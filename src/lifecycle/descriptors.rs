//! What each process holds open, from `/proc/<pid>/fd`, with no `unsafe`
//! code (ADR 0012): how enclos looks on Linux, where macOS uses `lsof`.
//!
//! Each look is a `readlink`, which `/proc` answers without reaching the file
//! system the descriptor is on, so unlike `lsof` it needs no time limit.
//!
//! Only the user's own processes can be read, as with `lsof`, and among
//! those neither a zombie, whose folder is root's, nor a process that is not
//! dumpable, so what those hold is not seen. A process whose main thread
//! exited has a folder like a zombie's, and is read through a thread that
//! runs on.

use std::io;
use std::path::{Path, PathBuf};

/// Where the kernel shows its processes.
pub const PROC: &str = "/proc";

/// `O_PATH` as `fdinfo` writes it, on x86-64 and arm64.
const O_PATH: u32 = 0o10000000;

/// One open descriptor of a process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Descriptor {
    /// What it names, as `/proc` writes it: a real path, ` (deleted)` after
    /// one removed, `socket:[<inode>]` for a socket.
    pub target: PathBuf,
    /// Where `/proc` gives its flags.
    info: PathBuf,
}

impl Descriptor {
    /// Whether it opens what it names. An `O_PATH` descriptor does not, and
    /// it takes no permission on the file, so it proves nothing about who
    /// holds it. One closed since, or of a process that can no longer be
    /// read, opens nothing that can be seen.
    pub fn opens(&self) -> io::Result<bool> {
        let text = match std::fs::read_to_string(&self.info) {
            Err(e) if is_gone(&e) || e.kind() == io::ErrorKind::PermissionDenied => {
                return Ok(false);
            }
            text => text?,
        };
        let flags = text
            .lines()
            .find_map(|line| line.strip_prefix("flags:"))
            .and_then(|flags| u32::from_str_radix(flags.trim(), 8).ok());
        match flags {
            Some(flags) => Ok(flags & O_PATH == 0),
            None => Err(io::Error::other(format!(
                "{} shows no flags",
                self.info.display()
            ))),
        }
    }
}

/// What a look at one process's descriptors found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Descriptors {
    /// Each open descriptor.
    Open(Vec<Descriptor>),
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

/// The descriptors `pid` holds, under `proc`: through its own folder, or, when
/// that is refused, through a thread that runs on. Threads share their memory,
/// so one that is not dumpable is refused through each of them.
pub fn of(proc: &Path, pid: u32) -> io::Result<Descriptors> {
    match in_folder(&proc.join(pid.to_string()))? {
        Descriptors::Unreadable => {}
        found => return Ok(found),
    }
    for thread in other_threads(proc, pid)? {
        if let found @ Descriptors::Open(_) = in_folder(&thread)? {
            return Ok(found);
        }
    }
    Ok(Descriptors::Unreadable)
}

/// The folder of each thread of `pid`, under `proc`, but for its main thread.
pub fn other_threads(proc: &Path, pid: u32) -> io::Result<Vec<PathBuf>> {
    let main = pid.to_string();
    let entries = match std::fs::read_dir(proc.join(&main).join("task")) {
        Err(e) if is_gone(&e) => return Ok(Vec::new()),
        entries => entries?,
    };
    let mut threads = Vec::new();
    for entry in entries {
        let entry = match entry {
            Err(e) if is_gone(&e) => break,
            entry => entry?,
        };
        if entry.file_name() != main.as_str() {
            threads.push(entry.path());
        }
    }
    Ok(threads)
}

/// The descriptors in `folder`, a process's or a thread's.
fn in_folder(folder: &Path) -> io::Result<Descriptors> {
    let entries = match std::fs::read_dir(folder.join("fd")) {
        Err(e) if is_gone(&e) => return Ok(Descriptors::Gone),
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
            return Ok(Descriptors::Unreadable);
        }
        entries => entries?,
    };
    let info = folder.join("fdinfo");
    let mut open = Vec::new();
    for entry in entries {
        let entry = match entry {
            Err(e) if is_gone(&e) => return Ok(Descriptors::Gone),
            entry => entry?,
        };
        match std::fs::read_link(entry.path()) {
            Ok(target) => open.push(Descriptor {
                target,
                info: info.join(entry.file_name()),
            }),
            // Closed since the folder was read.
            Err(e) if is_gone(&e) => {}
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                return Ok(Descriptors::Unreadable);
            }
            // Deeper than `/proc` can write: anyone can make such a path, and
            // no marker or socket has one.
            Err(e) if e.raw_os_error() == Some(rustix::io::Errno::NAMETOOLONG.raw_os_error()) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(Descriptors::Open(open))
}

/// The descriptors of every process this user can read, by pid. A listing
/// where this process itself cannot be read shows nothing it can be trusted
/// for, so it is an error, as `process::processes` treats its own.
pub fn every_process(proc: &Path) -> io::Result<Vec<(u32, Vec<Descriptor>)>> {
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

/// A `/proc` of a test's own: a process with these descriptor targets, each
/// open for reading and writing.
#[cfg(test)]
pub fn fake_process(proc: &Path, pid: u32, targets: &[&str]) {
    let fd = proc.join(pid.to_string()).join("fd");
    let info = proc.join(pid.to_string()).join("fdinfo");
    std::fs::create_dir_all(&fd).unwrap();
    std::fs::create_dir_all(&info).unwrap();
    for (n, target) in targets.iter().enumerate() {
        std::os::unix::fs::symlink(target, fd.join(n.to_string())).unwrap();
        fake_flags(&info.join(n.to_string()), "0100002");
    }
}

/// A folder of a test's `/proc` that refuses this user until restored.
#[cfg(test)]
pub struct Refused(PathBuf);

#[cfg(test)]
impl Refused {
    pub fn restore(self) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
}

/// Has `folder` refuse this user.
#[cfg(test)]
pub fn refuse(folder: &Path) -> Refused {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(folder, std::fs::Permissions::from_mode(0o000)).unwrap();
    Refused(folder.to_owned())
}

/// `flags`, in octal, as the `fdinfo` file at `info` writes them.
#[cfg(test)]
pub fn fake_flags(info: &Path, flags: &str) {
    std::fs::write(info, format!("pos:\t0\nflags:\t{flags}\nmnt_id:\t1\n")).unwrap();
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
        assert!(
            held.1.iter().any(|d| d.target == Path::new("socket:[12]")),
            "{found:?}"
        );
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

    /// A process whose main thread exited: its own folder is root's, and
    /// the thread left on it reads what they all hold.
    #[test]
    fn a_process_is_read_through_a_thread_when_its_own_folder_is_refused() {
        let proc = tempfile::tempdir().unwrap();
        let task = proc.path().join("7/task");
        fake_process(proc.path(), 7, &[]);
        fake_process(&task, 7, &[]);
        fake_process(&task, 8, &["/a"]);
        std::fs::remove_dir(task.join("7/fd")).unwrap();
        let fd = refuse(&proc.path().join("7/fd"));
        let read = of(proc.path(), 7);
        fd.restore();
        let Descriptors::Open(open) = read.unwrap() else {
            panic!("the thread was not read");
        };
        assert_eq!(open[0].target, Path::new("/a"));
        assert!(open[0].opens().unwrap());
    }

    /// With no other thread, or none that reads, it stays unreadable.
    #[test]
    fn a_process_no_thread_of_which_reads_is_unreadable() {
        let proc = tempfile::tempdir().unwrap();
        let task = proc.path().join("7/task");
        fake_process(proc.path(), 7, &[]);
        fake_process(&task, 7, &[]);
        let fd = refuse(&proc.path().join("7/fd"));
        assert_eq!(of(proc.path(), 7).unwrap(), Descriptors::Unreadable);
        fake_process(&task, 8, &[]);
        let thread = refuse(&task.join("8/fd"));
        let read = of(proc.path(), 7);
        fd.restore();
        thread.restore();
        assert_eq!(read.unwrap(), Descriptors::Unreadable);
    }

    /// `fdinfo`'s flags say what a descriptor opens, and one that shows none
    /// is a look that failed.
    #[test]
    fn a_descriptor_opens_its_target_unless_it_is_o_path_or_closed() {
        let proc = tempfile::tempdir().unwrap();
        fake_process(proc.path(), 7, &["/a", "/b", "/c", "/d"]);
        let info = proc.path().join("7/fdinfo");
        fake_flags(&info.join("1"), "012000000");
        std::fs::remove_file(info.join("2")).unwrap();
        std::fs::write(info.join("3"), "pos:\t0\n").unwrap();
        let Descriptors::Open(mut open) = of(proc.path(), 7).unwrap() else {
            panic!("the process cannot be read");
        };
        open.sort_by(|a, b| a.target.cmp(&b.target));
        assert!(open[0].opens().unwrap());
        assert!(!open[1].opens().unwrap());
        assert!(!open[2].opens().unwrap());
        assert!(open[3].opens().is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn o_path_is_the_kernels() {
        assert_eq!(O_PATH, rustix::fs::OFlags::PATH.bits());
    }

    /// A descriptor on a folder deeper than `/proc` can write, past any page
    /// a kernel may use: one such descriptor anywhere must not fail the look
    /// at every process.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_descriptor_too_deep_to_name_is_left_out() {
        use rustix::fs::{Mode, OFlags, mkdirat, open, openat};
        use std::os::fd::AsRawFd;
        let dir = tempfile::tempdir().unwrap();
        let name = "d".repeat(255);
        let read = OFlags::RDONLY | OFlags::DIRECTORY;
        let mut deep = open(dir.path(), read, Mode::empty()).unwrap();
        for _ in 0..300 {
            mkdirat(&deep, &name, Mode::RWXU).unwrap();
            deep = openat(&deep, &name, read, Mode::empty()).unwrap();
        }
        let proc = Path::new(PROC);
        let link = proc.join("self/fd").join(deep.as_raw_fd().to_string());
        let err = std::fs::read_link(&link).unwrap_err();
        assert_eq!(
            err.raw_os_error(),
            Some(rustix::io::Errno::NAMETOOLONG.raw_os_error())
        );
        let found = every_process(proc).unwrap();
        assert!(found.iter().any(|(pid, _)| *pid == me()));
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
