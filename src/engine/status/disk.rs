//! What a sandbox costs on disk: a walk of the sandbox folder that never
//! follows a link and counts within a budget (ADR 0023).

use std::collections::HashMap;
use std::ffi::{CString, OsStr};
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use rustix::fs::{AtFlags, Dir, FileType, Mode, OFlags, Stat};
use rustix::io::Errno;
use serde::Serialize;

use super::{AgentList, Fact, printable};
use crate::runtime::home::{is_dot, wide};
use crate::runtime::{DiskPart, RuntimeAdapter, RuntimeAgentName};

/// The most entries the walker reads in one sandbox before it stops and
/// says its sizes are lower bounds.
const MAX_ENTRIES: usize = 1_000_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Disk {
    /// Why the walk did not see everything: then every size here is a
    /// lower bound.
    pub incomplete: Option<String>,
    /// The whole sandbox folder.
    pub total: u64,
    /// Of `total`, hard-linked files that also have links outside the
    /// sandbox folder: removing it does not free them. APFS clones are not
    /// told apart and count in full.
    pub shared: u64,
    /// The parts the adapter names; `None` when it names none.
    pub runtime: Option<u64>,
    pub caches: Option<u64>,
    pub agents: Option<u64>,
    pub other: u64,
}

impl Disk {
    /// What `enclos sandbox rm` frees.
    pub fn frees(&self) -> u64 {
        self.total - self.shared
    }

    /// The field for `part`: every part has one, or this does not compile.
    fn part_mut(&mut self, part: DiskPart) -> &mut Option<u64> {
        match part {
            DiskPart::Runtime => &mut self.runtime,
            DiskPart::Cache => &mut self.caches,
        }
    }
}

/// The sandbox folder's usage, and each agent's own, by the parts and
/// folders the adapter names.
pub(super) fn disk_usage(
    dir: &Path,
    home: &Path,
    runtime: Option<&dyn RuntimeAdapter>,
    agents: Option<&AgentList>,
) -> (Disk, HashMap<RuntimeAgentName, Fact<u64>>) {
    // Paths as the walker sees them, from the sandbox folder.
    let home_rel = home.strip_prefix(dir).unwrap_or(Path::new("home"));
    let named_parts = runtime.map(|rt| rt.disk_parts()).unwrap_or_default();
    let mut parts: Vec<(PathBuf, Slot)> = named_parts
        .iter()
        .map(|(part, path)| (home_rel.join(path.as_path()), Slot::Part(*part)))
        .collect();
    let mut folders = Vec::new();
    if let (Some(rt), Some(list)) = (runtime, agents) {
        for a in &list.agents {
            if let Some(folder) = rt.agent_facts(&a.name).folder {
                let path = home_rel.join(folder.as_path());
                // A folder that is also a named part counts as that part.
                if !parts.iter().any(|(p, _)| *p == path) {
                    parts.push((path, Slot::Agent(a.name.clone())));
                    folders.push(a.name.clone());
                }
            }
        }
    }
    let usage = walk(dir, &parts, MAX_ENTRIES);
    let named = |slot: &Slot| usage.by_slot.get(slot).copied();
    let mut disk = Disk {
        incomplete: usage.incomplete.clone(),
        total: usage.total,
        shared: usage.shared,
        runtime: None,
        caches: None,
        agents: (!folders.is_empty()).then(|| {
            folders
                .iter()
                .filter_map(|n| named(&Slot::Agent(n.clone())))
                .sum()
        }),
        other: named(&Slot::Other).unwrap_or(0),
    };
    for (part, _) in &named_parts {
        *disk.part_mut(*part) = Some(named(&Slot::Part(*part)).unwrap_or(0));
    }
    let agent_bytes = folders
        .into_iter()
        .map(|n| {
            let bytes = match (named(&Slot::Agent(n.clone())), &usage.incomplete) {
                (Some(b), _) => Fact::Known(b),
                (None, None) => Fact::Absent,
                (None, Some(why)) => Fact::CannotTell(why.clone()),
            };
            (n, bytes)
        })
        .collect();
    (disk, agent_bytes)
}

/// Bytes in decimal units, as Finder shows them.
pub fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1000.0 && unit < UNITS.len() - 1 {
        value /= 1000.0;
        unit += 1;
    }
    match unit {
        0 => format!("{bytes} B"),
        _ if value < 10.0 => format!("{value:.1} {}", UNITS[unit]),
        _ => format!("{value:.0} {}", UNITS[unit]),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum Slot {
    Part(DiskPart),
    Agent(RuntimeAgentName),
    Other,
}

struct Usage {
    total: u64,
    shared: u64,
    incomplete: Option<String>,
    by_slot: HashMap<Slot, u64>,
}

/// A folder found and not read yet: opened through its parent when its
/// turn comes, so only the folders on the way down stay open.
struct Pending {
    parent: Rc<OwnedFd>,
    name: CString,
    rel: PathBuf,
    slot: Slot,
}

/// A hard-linked file: its link count, the links seen, and its size.
struct Linked {
    nlink: i128,
    seen: i128,
    bytes: u64,
}

const FOLDER: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);

/// What `root` holds, as removing it would free: allocated blocks, each
/// entry `lstat`ed through its folder's descriptor (a link counts as
/// itself, and a folder swapped for a link is not entered), each
/// hard-linked file once, and at most `budget` entries, counted as they are
/// read. Everything under one of `parts` (paths from `root`) counts toward
/// it. A read that fails, other than for an entry gone meanwhile, or the
/// budget running out, makes every size a lower bound and says why. A file
/// with hard links in several parts counts toward the first one reached.
fn walk(root: &Path, parts: &[(PathBuf, Slot)], budget: usize) -> Usage {
    let mut usage = Usage {
        total: 0,
        shared: 0,
        incomplete: None,
        by_slot: HashMap::new(),
    };
    let mut linked: HashMap<(i128, i128), Linked> = HashMap::new();
    // `rel` holds names the sandbox chose: escaped before it is shown.
    let fail = |usage: &mut Usage, rel: &Path, e: Errno| {
        usage
            .incomplete
            .get_or_insert_with(|| match rel.as_os_str().is_empty() {
                true => format!("{}: {e}", root.display()),
                false => format!(
                    "{}/{}: {e}",
                    root.display(),
                    printable(&rel.to_string_lossy())
                ),
            });
    };
    let root_fd = match rustix::fs::open(
        root,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        // No folder: removing it frees nothing.
        Err(Errno::NOENT) => return usage,
        Err(e) => {
            fail(&mut usage, Path::new(""), e);
            return usage;
        }
    };
    match rustix::fs::fstat(&root_fd) {
        Ok(stat) => count(&mut usage, &mut linked, &Slot::Other, &stat),
        Err(e) => fail(&mut usage, Path::new(""), e),
    }
    let mut entries = 1;
    let mut folders = vec![(Rc::new(root_fd), PathBuf::new(), Slot::Other)];
    let mut pending: Vec<Pending> = Vec::new();
    'walk: loop {
        while let Some((fd, rel, slot)) = folders.pop() {
            let dir = match Dir::read_from(&*fd) {
                Ok(dir) => dir,
                Err(e) => {
                    fail(&mut usage, &rel, e);
                    continue;
                }
            };
            for entry in dir {
                let entry = match entry {
                    Ok(entry) => entry,
                    Err(e) => {
                        fail(&mut usage, &rel, e);
                        break;
                    }
                };
                let name = entry.file_name();
                if is_dot(name) {
                    continue;
                }
                entries += 1;
                if entries > budget {
                    usage.incomplete = Some(format!("stopped after {budget} entries"));
                    break 'walk;
                }
                let child = rel.join(OsStr::from_bytes(name.to_bytes()));
                let slot = parts
                    .iter()
                    .find(|(p, _)| *p == child)
                    .map_or_else(|| slot.clone(), |(_, s)| s.clone());
                match rustix::fs::statat(&*fd, name, AtFlags::SYMLINK_NOFOLLOW) {
                    Ok(stat) => {
                        count(&mut usage, &mut linked, &slot, &stat);
                        if FileType::from_raw_mode(stat.st_mode).is_dir() {
                            pending.push(Pending {
                                parent: Rc::clone(&fd),
                                name: name.to_owned(),
                                rel: child,
                                slot,
                            });
                        }
                    }
                    // Gone meanwhile: it frees nothing.
                    Err(Errno::NOENT) => {}
                    Err(e) => fail(&mut usage, &child, e),
                }
            }
        }
        let Some(next) = pending.pop() else {
            break;
        };
        match rustix::fs::openat(&*next.parent, next.name.as_c_str(), FOLDER, Mode::empty()) {
            Ok(fd) => folders.push((Rc::new(fd), next.rel, next.slot)),
            Err(Errno::NOENT) => {}
            // Swapped for a link, or unreadable: not entered.
            Err(e) => fail(&mut usage, &next.rel, e),
        }
    }
    usage.shared = linked
        .values()
        .filter(|l| l.seen < l.nlink)
        .map(|l| l.bytes)
        .sum();
    usage
}

/// Adds one entry's allocated blocks, a hard-linked file only the first
/// time it is seen.
fn count(usage: &mut Usage, linked: &mut HashMap<(i128, i128), Linked>, slot: &Slot, stat: &Stat) {
    let bytes = u64::try_from(wide(stat.st_blocks)).unwrap_or(0) * 512;
    let nlink = wide(stat.st_nlink);
    if nlink > 1 && !FileType::from_raw_mode(stat.st_mode).is_dir() {
        let key = (wide(stat.st_dev), wide(stat.st_ino));
        let entry = linked.entry(key).or_insert(Linked {
            nlink,
            seen: 0,
            bytes,
        });
        entry.seen += 1;
        if entry.seen > 1 {
            return;
        }
    }
    usage.total += bytes;
    *usage.by_slot.entry(slot.clone()).or_default() += bytes;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(path: &Path, bytes: usize) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, vec![b'x'; bytes]).unwrap();
    }

    #[test]
    fn the_walker_counts_parts_and_never_follows_a_link() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        file(&outside.path().join("big"), 2_000_000);
        file(&root.path().join("home/rt/lib"), 100_000);
        file(&root.path().join("home/other"), 10_000);
        std::os::unix::fs::symlink(outside.path(), root.path().join("home/rt/link")).unwrap();
        // A part that is itself a link counts as the link alone.
        std::os::unix::fs::symlink(outside.path(), root.path().join("home/cache")).unwrap();
        let parts = [
            (PathBuf::from("home/rt"), Slot::Part(DiskPart::Runtime)),
            (PathBuf::from("home/cache"), Slot::Part(DiskPart::Cache)),
        ];
        let usage = walk(root.path(), &parts, 1000);
        assert_eq!(usage.incomplete, None);
        let runtime = usage.by_slot[&Slot::Part(DiskPart::Runtime)];
        assert!((100_000..200_000).contains(&runtime), "{runtime}");
        assert!(usage.by_slot[&Slot::Part(DiskPart::Cache)] < 100_000);
        assert!(usage.total < 1_000_000, "a link's target was counted");
    }

    #[test]
    fn a_hard_linked_file_counts_once_and_one_linked_from_outside_is_shared() {
        let root = tempfile::tempdir().unwrap();
        file(&root.path().join("a"), 500_000);
        std::fs::hard_link(root.path().join("a"), root.path().join("b")).unwrap();
        let usage = walk(root.path(), &[], 1000);
        assert!(
            (500_000..1_000_000).contains(&usage.total),
            "{}",
            usage.total
        );
        assert_eq!(usage.shared, 0);
        // A third link outside the folder: removing it frees none of this.
        let outside = tempfile::tempdir_in(root.path().parent().unwrap()).unwrap();
        std::fs::hard_link(root.path().join("a"), outside.path().join("c")).unwrap();
        let usage = walk(root.path(), &[], 1000);
        assert!(usage.shared >= 500_000, "{}", usage.shared);
    }

    #[test]
    fn the_budget_counts_entries_as_they_are_read_and_says_when_it_stops() {
        let root = tempfile::tempdir().unwrap();
        for i in 0..9 {
            file(&root.path().join(format!("d/{i}")), 10);
        }
        // The root, `d` and its nine files.
        let all = 11;
        assert_eq!(walk(root.path(), &[], all).incomplete, None);
        let capped = walk(root.path(), &[], all - 1);
        assert_eq!(
            capped.incomplete.as_deref(),
            Some("stopped after 10 entries")
        );
        let full = walk(root.path(), &[], all).total;
        assert!(capped.total > 0 && capped.total <= full);
    }

    #[test]
    fn an_unreadable_folder_makes_every_size_a_lower_bound() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        file(&root.path().join("locked/inside"), 100_000);
        let locked = root.path().join("locked");
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
        if std::fs::read_dir(&locked).is_ok() {
            // Run as root, which reads everything.
            std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700)).unwrap();
            return;
        }
        let usage = walk(root.path(), &[], 1000);
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700)).unwrap();
        let why = usage.incomplete.unwrap();
        assert!(why.contains("locked"), "{why}");
        // A name the sandbox chose is escaped before it is shown.
        let forged = root.path().join("\u{1b}[2J\u{1b}[HFORGED\nline");
        std::fs::create_dir(&forged).unwrap();
        std::fs::set_permissions(&forged, std::fs::Permissions::from_mode(0o000)).unwrap();
        let usage = walk(root.path(), &[], 1000);
        std::fs::set_permissions(&forged, std::fs::Permissions::from_mode(0o700)).unwrap();
        let why = usage.incomplete.unwrap();
        assert!(!why.contains('\u{1b}') && !why.contains('\n'), "{why:?}");
        assert!(why.contains("\\u{1b}[2J\\u{1b}[HFORGED\\nline"), "{why}");
        // A missing folder is not a failure: it frees nothing.
        let gone = walk(&root.path().join("gone"), &[], 1000);
        assert_eq!((gone.total, gone.incomplete), (0, None));
    }

    #[test]
    fn sizes_read_like_finder() {
        assert_eq!(human_bytes(512), "512 B");
        assert_eq!(human_bytes(4_700_000), "4.7 MB");
        assert_eq!(human_bytes(2_400_000_000), "2.4 GB");
        assert_eq!(human_bytes(330_000_000), "330 MB");
    }
}
