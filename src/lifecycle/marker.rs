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
//! changed its mode and opened it. The host names them (`lsof` on macOS,
//! `/proc/<pid>/fd` on Linux; see `host`). On Linux, `O_PATH` takes no
//! permission on the file, so any process that reaches the folder can name a
//! marker with a descriptor; such a descriptor opens nothing and holds nothing.
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
use std::process::{Child, Command};
use std::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};

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
    /// A process holds the marker of the session whose root had this pid,
    /// and the listing made before does not show it.
    #[error("a process that started a moment ago holds the marker of the session of pid {0}")]
    Unlisted(u32),
    /// `/proc` could not be read: for every sandbox alike.
    #[error("cannot look at the sandbox's markers in /proc: {0}")]
    Proc(String),
}

/// Taken by [`Marker::spawn`] alone, and by [`spawn_unmarked`] together:
/// the copy of a marker a program starts with reaches any program started
/// at the same moment, by another thread, as tests running in parallel do.
static STARTS: RwLock<()> = RwLock::new(());

/// Starts `command` as [`Command::spawn`] does, never while a program
/// starts holding a marker, so that it inherits none: a process holding a
/// session's marker is one of its members, and ends with it.
pub fn spawn_unmarked(command: &mut Command) -> io::Result<Child> {
    let _turn = STARTS.read().unwrap_or_else(|e| e.into_inner());
    command.spawn()
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
    /// a program at that moment would inherit it too, unless it starts it
    /// through [`spawn_unmarked`]: the CLI starts nothing else meanwhile;
    /// tests running in parallel threads may.
    pub fn spawn(self, command: &mut Command) -> io::Result<(Child, Started)> {
        let started = Started {
            path: Some(self.path),
        };
        let _turn = STARTS.write().unwrap_or_else(|e| e.into_inner());
        let inherited = rustix::io::dup(&self.file)?;
        let child = command.spawn();
        drop(inherited);
        drop(self.file);
        Ok((child?, started))
    }
}

/// The marker of a program that started, before its session is recorded.
/// Dropped unnamed, as when the program did not start or failed before it
/// was named, it is removed. Once named, it stays until the session's end.
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

/// The processes holding each marker of a sandbox, by marker file name.
pub type Held = BTreeMap<String, BTreeSet<u32>>;

/// Whether a process in `held` holds the marker of the session whose root
/// is `root`.
pub fn is_held(held: &Held, root: &ProcessRef) -> bool {
    held.get(&name_of(root)).is_some_and(|p| !p.is_empty())
}

/// The processes holding each named marker in `dir`, by file name, of those
/// `lsof` or `/proc` can show (the user's; root's are not listed).
pub fn holders(dir: &Path) -> Result<Held, MarkerError> {
    // No folder yet is no marker; a folder that cannot be read is not: read
    // here, since `lsof -w` hides its own failure to open the folder and
    // answers as for one with nothing held.
    let entries = match std::fs::read_dir(dir) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Held::new()),
        Err(e) => return Err(MarkerError::Folder(format!("{}: {e}", dir.display()))),
        Ok(entries) => entries,
    };
    super::host::marker_holders(dir, entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The same with the kernel's own `/proc`: the program holds its marker,
    /// and this process, which opened it `O_PATH` as any process of the user
    /// can whatever its mode, does not.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_real_o_path_descriptor_holds_no_marker() {
        use rustix::fs::{Mode, OFlags};
        let dir = tempfile::tempdir().unwrap();
        let members = dir.path().join("members");
        let marker = Marker::new(&members).unwrap();
        let mut command = Command::new("/bin/sleep");
        command.arg("30").stdin(Stdio::null());
        let (mut child, started) = marker.spawn(&mut command).unwrap();
        let root = ProcessRef {
            pid: child.id(),
            started: "Wed Oct 22 12:00:00 2026".to_owned(),
        };
        started.name(&root).unwrap();
        let path = members.join(name_of(&root));
        let named = rustix::fs::open(&path, OFlags::PATH, Mode::empty()).unwrap();
        let held = holders(&members);
        drop(named);
        let _ = child.kill();
        let _ = child.wait();
        let pids = held.unwrap().remove(&name_of(&root)).unwrap_or_default();
        assert!(pids.contains(&child.id()), "{pids:?}");
        assert!(!pids.contains(&std::process::id()), "{pids:?}");
    }

    /// A process whose main thread exited still holds what it held, and
    /// its session is not over.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_process_whose_main_thread_exited_holds_its_marker() {
        use crate::lifecycle::process::{headless, headless_port};
        let dir = tempfile::tempdir().unwrap();
        let members = dir.path().join("members");
        let marker = Marker::new(&members).unwrap();
        let mut python = Command::new("/usr/bin/python3");
        let (mut child, started) = marker.spawn(headless(&mut python)).unwrap();
        headless_port(&mut child);
        let root = ProcessRef {
            pid: child.id(),
            started: "Wed Oct 22 12:00:00 2026".to_owned(),
        };
        started.name(&root).unwrap();
        let held = holders(&members);
        let _ = child.kill();
        let _ = child.wait();
        let held = held.unwrap();
        assert!(held[&name_of(&root)].contains(&child.id()), "{held:?}");
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

    /// A program started through `spawn_unmarked` while another thread
    /// starts programs holding markers holds none of them, so that ending
    /// their sessions never signals it.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_program_started_unmarked_holds_no_marker_starting_meanwhile() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};
        let dir = tempfile::tempdir().unwrap();
        // `/proc` writes real paths.
        let members = dir.path().canonicalize().unwrap().join("members");
        let done = Arc::new(AtomicBool::new(false));
        let marking = {
            let (done, members) = (done.clone(), members.clone());
            std::thread::spawn(move || {
                while !done.load(Ordering::Relaxed) {
                    let mut command = Command::new("/bin/true");
                    let marker = Marker::new(&members).unwrap();
                    let (mut child, _started) = marker.spawn(&mut command).unwrap();
                    child.wait().unwrap();
                }
            })
        };
        let mut held = Vec::new();
        for _ in 0..200 {
            let mut command = Command::new("/bin/sh");
            command
                .args(["-c", "echo ready; read x"])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped());
            let mut child = spawn_unmarked(&mut command).unwrap();
            // Past its start: until then it may still show the descriptors
            // close-on-exec closes as its program starts.
            let mut ready = String::new();
            std::io::BufRead::read_line(
                &mut std::io::BufReader::new(child.stdout.take().unwrap()),
                &mut ready,
            )
            .unwrap();
            assert_eq!(ready, "ready\n");
            let fds = std::fs::read_dir(format!("/proc/{}/fd", child.id())).unwrap();
            for fd in fds {
                let target = std::fs::read_link(fd.unwrap().path()).unwrap_or_default();
                if target.starts_with(&members) {
                    held.push(target);
                }
            }
            drop(child.stdin.take());
            child.wait().unwrap();
        }
        done.store(true, Ordering::Relaxed);
        marking.join().unwrap();
        assert!(held.is_empty(), "{held:?}");
    }
}
