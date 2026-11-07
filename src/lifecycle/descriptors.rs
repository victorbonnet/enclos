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
mod tests;
