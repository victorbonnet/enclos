//! Markers: evidence that a process is a session's, also after a double
//! fork (ADR 0030), with no `unsafe` code (ADR 0012).
//!
//! enclos starts each sandboxed program holding an open descriptor to a
//! marker file of its own, which every process the program starts inherits,
//! one that leaves its group or loses its parent included. The file is made
//! with no permissions in enclos's folder, where a sandbox cannot write, so
//! no sandboxed process can open it or change its mode, and enclos keeps no
//! copy open: the processes holding it are the program and what it started,
//! unless one closed it or passed it on, or a process outside the sandbox
//! changed its mode and opened it. `lsof` names them on macOS, and
//! `/proc/<pid>/fd` on Linux (see `descriptors`).
//!
//! A marker is made in the sandbox's `members/` folder before the program
//! starts, and named after the session's root process (its pid and start
//! time) once the program runs, before the session is recorded.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::io;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
#[cfg(test)]
use std::process::Stdio;
use std::process::{Child, Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

use super::descriptors;
use crate::model::session::ProcessRef;

/// Which processes hold the markers could not be told.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MarkerError {
    /// The sandbox's markers' folder could not be looked at.
    #[error("cannot look at the sandbox's markers in {0}")]
    Folder(String),
    /// `lsof` could not run or answer: for every sandbox alike.
    #[error("cannot look at the sandbox's markers with /usr/sbin/lsof: {0}")]
    Lsof(String),
    /// `/proc` could not be read: for every sandbox alike.
    #[error("cannot look at the sandbox's markers in /proc: {0}")]
    Proc(String),
}

/// A marker made for a program about to start, not yet held by it.
pub struct Marker {
    file: File,
    path: PathBuf,
}

impl Marker {
    /// Makes a new marker in `dir`, with no permissions.
    pub fn new(dir: &Path) -> io::Result<Marker> {
        std::fs::create_dir_all(dir)?;
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let path = dir.join(format!("starting-{}-{nanos}", std::process::id()));
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o000)
            .open(&path)?;
        Ok(Marker { file, path })
    }

    /// Starts `command` holding the marker. The descriptor it inherits is a
    /// copy made without close-on-exec just before, and enclos closes both
    /// its copies once the program runs. Another thread of enclos starting
    /// a program at that moment would inherit it too: the CLI starts nothing
    /// else meanwhile; tests running in parallel threads may.
    pub fn spawn(self, command: &mut Command) -> io::Result<(Child, Started)> {
        let started = Started {
            path: Some(self.path),
        };
        let inherited = rustix::io::dup(&self.file)?;
        let child = command.spawn();
        drop(inherited);
        drop(self.file);
        Ok((child?, started))
    }
}

/// The marker of a program that started, before its session is recorded.
/// Dropped unnamed, as when the program did not start or its session could
/// not be recorded, it is removed.
pub struct Started {
    path: Option<PathBuf>,
}

impl Started {
    /// Names the marker after the session's root process, so that its
    /// holders are found as the session's. On failure the marker is removed.
    pub fn name(mut self, root: &ProcessRef) -> io::Result<()> {
        let Some(path) = self.path.take() else {
            return Ok(());
        };
        let dir = path.parent().unwrap_or(Path::new("."));
        let named = std::fs::rename(&path, dir.join(name_of(root)));
        if named.is_err() {
            let _ = std::fs::remove_file(&path);
        }
        named
    }
}

impl Drop for Started {
    fn drop(&mut self) {
        if let Some(path) = self.path.take() {
            let _ = std::fs::remove_file(path);
        }
    }
}

/// The file name of the marker of the session whose root is `root`.
pub fn name_of(root: &ProcessRef) -> String {
    let started: String = root
        .started
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    format!("root-{}-{started}", root.pid)
}

/// Removes the marker of the session whose root is `root`, once it ended.
/// Gone already is not an error.
pub fn remove(dir: &Path, root: &ProcessRef) -> io::Result<()> {
    match std::fs::remove_file(dir.join(name_of(root))) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

/// The processes holding each named marker in `dir`, by file name, of those
/// `lsof` or `/proc` can show (the user's; root's are not listed).
pub fn holders(dir: &Path) -> Result<BTreeMap<String, BTreeSet<u32>>, MarkerError> {
    // No folder yet is no marker; a folder that cannot be read is not: read
    // here, since `lsof -w` hides its own failure to open the folder and
    // answers as for one with nothing held.
    let entries = match std::fs::read_dir(dir) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(BTreeMap::new()),
        Err(e) => return Err(MarkerError::Folder(format!("{}: {e}", dir.display()))),
        Ok(entries) => entries,
    };
    if !cfg!(target_os = "macos") {
        return holders_in_proc(Path::new(descriptors::PROC), dir, entries);
    }
    // `-w`: a warning about another file system (an unreachable network
    // mount) is not a failure to look at this folder.
    let out = super::bounded::output_within(
        Command::new("/usr/sbin/lsof")
            .env("LC_ALL", "C")
            .args(["-nP", "-w", "-Fpn", "+d"])
            .arg(dir),
        super::bounded::LIMIT,
    )
    .map_err(|e| MarkerError::Lsof(e.to_string()))?;
    parse(&out)
}

/// The processes under `proc` holding each named marker in `dir`, whose
/// `entries` are what the folder shows now: as with `lsof +d`, a file already
/// removed from it is not listed, and a process working in it holds nothing.
fn holders_in_proc(
    proc: &Path,
    dir: &Path,
    entries: std::fs::ReadDir,
) -> Result<BTreeMap<String, BTreeSet<u32>>, MarkerError> {
    let folder_error = |e: io::Error| MarkerError::Folder(format!("{}: {e}", dir.display()));
    let mut markers = BTreeSet::new();
    for entry in entries {
        if let Some(name) = entry.map_err(folder_error)?.file_name().to_str()
            && name.starts_with("root-")
        {
            markers.insert(name.to_owned());
        }
    }
    let mut held: BTreeMap<String, BTreeSet<u32>> = BTreeMap::new();
    if markers.is_empty() {
        return Ok(held);
    }
    // `/proc` writes real paths, and `dir` may not be one.
    let real = dir.canonicalize().map_err(folder_error)?;
    let processes =
        descriptors::every_process(proc).map_err(|e| MarkerError::Proc(e.to_string()))?;
    for (pid, open) in processes {
        for target in open {
            if target.parent() == Some(real.as_path())
                && let Some(name) = target.file_name().and_then(|n| n.to_str())
                && markers.contains(name)
            {
                held.entry(name.to_owned()).or_default().insert(pid);
            }
        }
    }
    Ok(held)
}

/// What `lsof -Fpn +d` answered: a `p<pid>` line for each process, then an
/// `n<path>` line for each file of the folder it holds, the folder itself
/// for a process working in it. With nothing held it prints nothing and
/// exits 1, as for listeners (`listeners.rs`).
fn parse(out: &Output) -> Result<BTreeMap<String, BTreeSet<u32>>, MarkerError> {
    let text = String::from_utf8_lossy(&out.stdout);
    let why = String::from_utf8_lossy(&out.stderr).trim().to_owned();
    match (out.status.code(), text.trim().is_empty(), why.is_empty()) {
        (Some(1), true, true) => return Ok(BTreeMap::new()),
        (Some(0), false, _) | (Some(1), false, true) => {}
        _ => return Err(MarkerError::Lsof(format!("{}: {why}", out.status))),
    }
    let mut held: BTreeMap<String, BTreeSet<u32>> = BTreeMap::new();
    let mut pid = None;
    for line in text.lines() {
        if let Some(p) = line.strip_prefix('p') {
            pid = Some(
                p.parse::<u32>()
                    .map_err(|_| MarkerError::Lsof(format!("unexpected process `{p}`")))?,
            );
        } else if let Some(name) = line.strip_prefix('n') {
            let file = Path::new(name)
                .file_name()
                .and_then(|n| n.to_str())
                .filter(|n| n.starts_with("root-"));
            if let (Some(file), Some(pid)) = (file, pid) {
                held.entry(file.to_owned()).or_default().insert(pid);
            }
        }
    }
    Ok(held)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt;
    use std::process::ExitStatus;

    fn output(code: i32, stdout: &str, stderr: &str) -> Output {
        Output {
            status: ExitStatus::from_raw(code << 8),
            stdout: stdout.as_bytes().to_vec(),
            stderr: stderr.as_bytes().to_vec(),
        }
    }

    #[test]
    fn lsof_output_gives_each_sessions_holders() {
        let held = parse(&output(
            0,
            "p100\nf3\nn/e/sandboxes/home/members/root-7-a\np200\nfcwd\nn/e/sandboxes/home/members\nf4\nn/e/sandboxes/home/members/root-7-a\nf5\nn/e/sandboxes/home/members/root-9-b\np300\nf3\nn/e/sandboxes/home/members/starting-1-2\n",
            "",
        ))
        .unwrap();
        assert_eq!(held["root-7-a"], BTreeSet::from([100, 200]));
        assert_eq!(held["root-9-b"], BTreeSet::from([200]));
        assert_eq!(held.len(), 2, "{held:?}");
    }

    /// The folder's markers held under a `/proc` of the test's own: each
    /// process's descriptors, whatever they name, sorted out by marker.
    #[test]
    fn proc_gives_each_sessions_holders() {
        let dir = tempfile::tempdir().unwrap();
        let members = dir.path().canonicalize().unwrap().join("members");
        std::fs::create_dir(&members).unwrap();
        for file in ["root-7-a", "root-9-b", "root-8-unheld", "starting-1-2"] {
            std::fs::write(members.join(file), "").unwrap();
        }
        let path = |file: &str| members.join(file).to_str().unwrap().to_owned();
        let proc = dir.path().join("proc");
        descriptors::fake_process(&proc, std::process::id(), &[]);
        descriptors::fake_process(&proc, 100, &[&path("root-7-a"), "socket:[5]"]);
        descriptors::fake_process(&proc, 200, &[&path("root-7-a"), &path("root-9-b")]);
        descriptors::fake_process(
            &proc,
            300,
            &[
                &path("starting-1-2"),
                &path("root-3-removed (deleted)"),
                &path("root-3-removed"),
                members.to_str().unwrap(),
                "/elsewhere/root-7-a",
            ],
        );
        let held = holders_in_proc(&proc, &members, std::fs::read_dir(&members).unwrap()).unwrap();
        assert_eq!(held["root-7-a"], BTreeSet::from([100, 200]));
        assert_eq!(held["root-9-b"], BTreeSet::from([200]));
        assert_eq!(held.len(), 2, "{held:?}");
    }

    #[test]
    fn a_proc_that_cannot_be_read_is_an_error() {
        let members = tempfile::tempdir().unwrap();
        std::fs::write(members.path().join("root-7-a"), "").unwrap();
        let entries = std::fs::read_dir(members.path()).unwrap();
        let err = holders_in_proc(Path::new("/nonexistent"), members.path(), entries).unwrap_err();
        assert!(matches!(err, MarkerError::Proc(_)), "{err}");
    }

    #[test]
    fn a_reused_pid_gets_another_marker() {
        let at = |started: &str| ProcessRef {
            pid: 42,
            started: started.to_owned(),
        };
        assert_ne!(
            name_of(&at("Wed Oct 22 12:00:00 2026")),
            name_of(&at("Wed Oct 22 12:00:01 2026"))
        );
    }

    #[test]
    fn a_program_that_does_not_start_leaves_no_marker() {
        let dir = tempfile::tempdir().unwrap();
        let marker = Marker::new(dir.path()).unwrap();
        let mut command = Command::new("/nonexistent/program");
        assert!(marker.spawn(&mut command).is_err());
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    #[test]
    fn nothing_held_is_no_holder_and_a_failure_is_an_error() {
        assert!(parse(&output(1, "", "")).unwrap().is_empty());
        assert!(parse(&output(1, "", "lsof: status error")).is_err());
        assert!(parse(&output(0, "pnope\n", "")).is_err());
    }

    /// The marker's whole life with real processes: no one can open it, a
    /// double-forked process still holds it, and enclos holds none.
    #[test]
    fn a_double_forked_process_holds_its_sessions_marker() {
        let dir = tempfile::tempdir().unwrap();
        let members = dir.path().join("members");
        let marker = Marker::new(&members).unwrap();
        let pid_file = dir.path().join("pid");
        let mut command = Command::new("/bin/sh");
        command
            .args(["-c", "(sleep 30 & echo $! > \"$0\") ; exit 0"])
            .arg(&pid_file)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let (mut child, started) = marker.spawn(&mut command).unwrap();
        child.wait().unwrap();
        let root = ProcessRef {
            pid: child.id(),
            started: "Wed Oct 22 12:00:00 2026".to_owned(),
        };
        started.name(&root).unwrap();
        let path = members.join(name_of(&root));
        assert_eq!(
            name_of(&root),
            format!("root-{}-Wed_Oct_22_12_00_00_2026", child.id())
        );
        assert!(File::open(&path).is_err(), "the marker can be opened again");
        let sleep: u32 = std::fs::read_to_string(&pid_file)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        let held = holders(&members).unwrap();
        let pids = held.get(&name_of(&root)).cloned().unwrap_or_default();
        // Other tests' programs started meanwhile may hold it too (see
        // `Marker::spawn`): the sleep must, enclos must not.
        let found = pids.contains(&sleep);
        let _ = Command::new("/bin/kill").arg(sleep.to_string()).status();
        assert!(found, "{held:?}");
        assert!(!pids.contains(&std::process::id()), "enclos holds it");
        remove(&members, &root).unwrap();
        assert!(!path.exists());
    }
}
