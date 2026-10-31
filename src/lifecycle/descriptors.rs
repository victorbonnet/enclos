//! What each process holds open, from `/proc/<pid>/fd`, with no `unsafe`
//! code (ADR 0012): where `lsof` is not at `/usr/sbin/lsof`, on Linux.
//!
//! Each look is a `readlink`, which `/proc` answers without reaching the file
//! system the descriptor is on, so unlike `lsof` it needs no time limit.
//!
//! Only the user's own processes can be read, as with `lsof`, and among
//! those not one that is exiting (a zombie's folder is root's) or that made
//! itself not dumpable. So what such a process holds is not seen.

use std::io;
use std::path::{Path, PathBuf};

/// Where the kernel shows its processes.
pub const PROC: &str = "/proc";

/// What a look at one process's descriptors found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Descriptors {
    /// The target of each open descriptor, as `/proc` writes it: a real
    /// path, ` (deleted)` after one removed, `socket:[<inode>]` for a socket.
    Open(Vec<PathBuf>),
    /// No such process.
    Gone,
    /// The process exists, but this user cannot read its descriptors.
    Unreadable,
}

/// Whether `e` says that the process, or the descriptor, no longer exists:
/// `ESRCH` when it exited during the read, `ENOENT` otherwise.
pub fn is_gone(e: &io::Error) -> bool {
    e.kind() == io::ErrorKind::NotFound
        || e.raw_os_error() == Some(rustix::io::Errno::SRCH.raw_os_error())
}

/// The descriptors `pid` holds, under `proc`.
pub fn of(proc: &Path, pid: u32) -> io::Result<Descriptors> {
    let entries = match std::fs::read_dir(proc.join(pid.to_string()).join("fd")) {
        Err(e) if is_gone(&e) => return Ok(Descriptors::Gone),
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
            return Ok(Descriptors::Unreadable);
        }
        entries => entries?,
    };
    let mut open = Vec::new();
    for entry in entries {
        let entry = match entry {
            Err(e) if is_gone(&e) => return Ok(Descriptors::Gone),
            entry => entry?,
        };
        match std::fs::read_link(entry.path()) {
            Ok(target) => open.push(target),
            // Closed since the folder was read.
            Err(e) if is_gone(&e) => {}
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                return Ok(Descriptors::Unreadable);
            }
            Err(e) => return Err(e),
        }
    }
    Ok(Descriptors::Open(open))
}

/// The descriptors of every process this user can read, by pid. A listing
/// where this process itself cannot be read shows nothing it can be trusted
/// for, so it is an error, as `process::processes` treats its own.
pub fn every_process(proc: &Path) -> io::Result<Vec<(u32, Vec<PathBuf>)>> {
    let me = std::process::id();
    let mut found = Vec::new();
    for entry in std::fs::read_dir(proc)? {
        let Some(pid) = entry?.file_name().to_str().and_then(|n| n.parse().ok()) else {
            continue;
        };
        if let Descriptors::Open(open) = of(proc, pid)? {
            found.push((pid, open));
        }
    }
    match found.iter().any(|(pid, _)| *pid == me) {
        true => Ok(found),
        false => Err(io::Error::other(format!(
            "{} does not show pid {me}, the caller",
            proc.display()
        ))),
    }
}

/// A `/proc` of a test's own: a process with these descriptor targets.
#[cfg(test)]
pub fn fake_process(proc: &Path, pid: u32, targets: &[&str]) {
    let fd = proc.join(pid.to_string()).join("fd");
    std::fs::create_dir_all(&fd).unwrap();
    for (n, target) in targets.iter().enumerate() {
        std::os::unix::fs::symlink(target, fd.join(n.to_string())).unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn me() -> u32 {
        std::process::id()
    }

    #[test]
    fn every_process_is_listed_with_what_it_holds_and_other_entries_are_not() {
        let proc = tempfile::tempdir().unwrap();
        fake_process(proc.path(), me(), &[]);
        fake_process(proc.path(), 7, &["/a", "socket:[12]"]);
        // Listed, but exited before its descriptors were read.
        std::fs::create_dir(proc.path().join("8")).unwrap();
        std::fs::create_dir(proc.path().join("sys")).unwrap();
        let found = every_process(proc.path()).unwrap();
        let held = found.iter().find(|(pid, _)| *pid == 7).unwrap();
        assert_eq!(held.1.len(), 2, "{found:?}");
        assert!(held.1.contains(&PathBuf::from("socket:[12]")), "{found:?}");
        assert_eq!(found.len(), 2, "{found:?}");
    }

    #[test]
    fn a_listing_that_does_not_show_the_caller_is_an_error() {
        let proc = tempfile::tempdir().unwrap();
        fake_process(proc.path(), me().wrapping_add(1), &[]);
        let err = every_process(proc.path()).unwrap_err();
        assert!(err.to_string().contains("the caller"), "{err}");
        assert!(every_process(&proc.path().join("none")).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_zombie_is_unreadable_and_a_reaped_process_is_gone() {
        let proc = Path::new(PROC);
        let mut child = std::process::Command::new("/usr/bin/true").spawn().unwrap();
        let pid = child.id();
        let start = std::time::Instant::now();
        while of(proc, pid).unwrap() != Descriptors::Unreadable {
            assert!(start.elapsed() < std::time::Duration::from_secs(5));
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        child.wait().unwrap();
        assert_eq!(of(proc, pid).unwrap(), Descriptors::Gone);
    }
}
