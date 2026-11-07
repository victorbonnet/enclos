//! bubblewrap started again when its setup meets a mount that changed
//! (design §5, What `wrap` does at each launch).
//!
//! bubblewrap before 0.13 makes the host's `/` read-only in steps: it binds
//! the whole tree, reads the mount table, then remounts each mount it read.
//! A mount the host takes away in between, as systemd does with a
//! service's credentials under `/run/credentials`, fails its remount, and
//! bubblewrap exits 1 before it runs anything (its `bind-mount.c`):
//!
//! ```text
//! bwrap: Can't bind mount /oldroot/ on /newroot/: Unable to apply mount flags: remount "/newroot/run/credentials/…": No such file or directory
//! ```
//!
//! Every bubblewrap enclos starts goes through here: [`run`] for a
//! session's and the namespace holder's, [`again`] for the backend's probe.
//! [`run`] gives bubblewrap a pipe for its stderr, and the stderr it was
//! given at the descriptor [`STDERR`] names. The program bubblewrap runs
//! first calls [`done`] before anything else: it says so on the pipe, then
//! takes that stderr back, so what it and its command write never passes
//! through the pipe. A bubblewrap that exits 1 with that message, its
//! program never having said it runs, ran nothing, and is started again
//! after a pause; any other end, and the last, is passed on with what
//! bubblewrap said.

use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::process::{Command, ExitStatus, Stdio};
use std::time::Duration;

/// The variable naming the descriptor of the stderr that the program
/// bubblewrap runs first takes back. Not passed on to its command.
pub const STDERR: &str = "ENCLOS_BUBBLEWRAP_STDERR";

/// The pauses before each start again: four starts in all, within a second.
pub const PAUSES: [Duration; 3] = [
    Duration::from_millis(100),
    Duration::from_millis(200),
    Duration::from_millis(400),
];

/// What the program bubblewrap runs first writes on the pipe as it starts.
/// No message of bubblewrap's holds a NUL byte.
const RUNS: &[u8] = b"\0enclos: bubblewrap set up\n";

/// What bubblewrap says when a mount it read was gone when it remounted it.
const MOUNT_CHANGED: &str = "Unable to apply mount flags: remount \"";

/// At most this much of what bubblewrap says before its program runs is
/// held. Past it, all is passed on as it comes, and nothing is started
/// again.
const HELD: usize = 64 * 1024;

/// Whether bubblewrap, which ended with `code` after saying `said` and
/// before its program ran, met a mount that changed while it set up: it ran
/// nothing, so starting it again runs its program once.
pub(crate) fn mount_changed(code: Option<i32>, said: &[u8]) -> bool {
    code == Some(1)
        && String::from_utf8_lossy(said)
            .lines()
            .any(|line| line.starts_with("bwrap: ") && line.contains(MOUNT_CHANGED))
}

/// Calls `start` until what it gives did not meet a mount that changed, as
/// `changed` tells, or the `pauses` run out, waiting each pause between two
/// starts: what the last start gave.
pub(crate) fn again<T>(
    pauses: &[Duration],
    mut start: impl FnMut() -> io::Result<T>,
    changed: impl Fn(&T) -> bool,
) -> io::Result<T> {
    let mut pauses = pauses.iter();
    loop {
        let ended = start()?;
        match pauses.next() {
            Some(pause) if changed(&ended) => std::thread::sleep(*pause),
            _ => return Ok(ended),
        }
    }
}

/// Runs bubblewrap, as `command` makes it at each start, to its end, and
/// starts it again while its setup meets a mount that changed, pausing
/// `pauses` between starts. `stderr` is its program's stderr, and gets what
/// bubblewrap says: at once once its program runs, and else at its end, of
/// the last start alone. Started again, it is said once on `stderr`, before
/// anything of the program's. Returns how the last start ended.
pub fn run(
    mut command: impl FnMut() -> io::Result<Command>,
    stderr: &File,
    pauses: &[Duration],
) -> io::Result<ExitStatus> {
    let given = inheritable(stderr)?;
    let mut starts = 0;
    let ended = again(
        pauses,
        || {
            starts += 1;
            start(command()?, &given, stderr, starts)
        },
        Start::met_a_changed_mount,
    )?;
    if let Some(said) = &ended.unset {
        // With stderr gone, there is no one to tell.
        let mut stderr = stderr;
        if ended.met_a_changed_mount() {
            let _ = writeln!(
                stderr,
                "enclos: bubblewrap was started {starts} times, and each time a mount of the host changed while it set up:"
            );
        }
        let _ = stderr.write_all(said);
    }
    Ok(ended.status)
}

/// How one start of bubblewrap ended.
struct Start {
    status: ExitStatus,
    /// What bubblewrap said, when its program never ran; none once it ran,
    /// or once what bubblewrap said was passed on.
    unset: Option<Vec<u8>>,
}

impl Start {
    fn met_a_changed_mount(&self) -> bool {
        self.unset
            .as_deref()
            .is_some_and(|said| mount_changed(self.status.code(), said))
    }
}

/// A copy of `stderr` that the programs this process starts inherit.
fn inheritable(stderr: &File) -> io::Result<OwnedFd> {
    let copy = stderr.as_fd().try_clone_to_owned()?;
    rustix::io::fcntl_setfd(&copy, rustix::io::FdFlags::empty())?;
    Ok(copy)
}

/// Starts `command` once, the `nth` start, its stderr a pipe and `given`
/// named in [`STDERR`], and reads the pipe to its end: what came before its
/// program ran is held, the rest goes to `stderr` as it comes.
fn start(mut command: Command, given: &OwnedFd, stderr: &File, nth: usize) -> io::Result<Start> {
    let (mut pipe, writer) = io::pipe()?;
    command
        .env(STDERR, given.as_raw_fd().to_string())
        .stderr(Stdio::from(writer));
    let mut child = command.spawn()?;
    // Its copy of the pipe's end: the pipe ends once bubblewrap's do.
    drop(command);
    let mut said = Vec::new();
    let unset = match read_until_set_up(&mut pipe, &mut said) {
        Ok(true) => {
            if nth > 1 {
                let _ = writeln!(
                    &*stderr,
                    "enclos: bubblewrap was started {nth} times, as a mount of the host changed while it set up"
                );
            }
            pass_on(&mut pipe, &said, stderr);
            None
        }
        Ok(false) if said.len() < HELD => Some(said),
        // Too much to hold, or the pipe lost: the program may run, so it is
        // never started again.
        Ok(false) | Err(_) => {
            pass_on(&mut pipe, &said, stderr);
            None
        }
    };
    let status = child.wait()?;
    Ok(Start { status, unset })
}

/// Reads `pipe` into `said` until the program bubblewrap runs says it runs,
/// whose words are taken out (true), the pipe ends, or [`HELD`] bytes came
/// (false).
fn read_until_set_up(pipe: &mut impl Read, said: &mut Vec<u8>) -> io::Result<bool> {
    let mut chunk = [0u8; 4096];
    while said.len() < HELD {
        let read = match pipe.read(&mut chunk) {
            Ok(0) => return Ok(false),
            Ok(read) => read,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        // The words may have come split over two reads.
        let from = said.len().saturating_sub(RUNS.len() - 1);
        said.extend_from_slice(&chunk[..read]);
        if let Some(at) = said[from..].windows(RUNS.len()).position(|w| w == RUNS) {
            said.drain(from + at..from + at + RUNS.len());
            return Ok(true);
        }
    }
    Ok(false)
}

/// Writes `said`, then what else comes on `pipe` until it ends, to
/// `stderr`. One gone is no reason to stop reading: bubblewrap would block
/// on a full pipe.
fn pass_on(pipe: &mut impl Read, said: &[u8], stderr: &File) {
    let mut stderr = stderr;
    let mut open = stderr.write_all(said).is_ok();
    let mut chunk = [0u8; 4096];
    loop {
        match pipe.read(&mut chunk) {
            Ok(0) => return,
            Ok(read) => open = open && stderr.write_all(&chunk[..read]).is_ok(),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return,
        }
    }
}

/// Called first by the program bubblewrap runs first: says on its stderr,
/// the pipe [`run`] reads, that bubblewrap's setup is done and this program
/// runs, then takes back the stderr [`run`] was given, which the programs
/// it starts get, with no second copy. Does nothing where [`STDERR`] is not
/// set, as for `enclos inside` run outside bubblewrap.
#[cfg(target_os = "linux")]
pub fn done() -> io::Result<()> {
    use rustix::process::{PidfdFlags, PidfdGetfdFlags, getpid, pidfd_getfd, pidfd_open};
    let Some(named) = std::env::var_os(STDERR) else {
        return Ok(());
    };
    let fd: i32 = named
        .to_str()
        .and_then(|n| n.parse().ok())
        .filter(|fd| *fd > 2)
        .ok_or_else(|| io::Error::other(format!("{STDERR} names no descriptor: {named:?}")))?;
    io::stderr().write_all(RUNS)?;
    // The descriptor by its number, with no `unsafe`: this process may
    // always take its own.
    let me = pidfd_open(getpid(), PidfdFlags::empty())?;
    let given = pidfd_getfd(&me, fd, PidfdGetfdFlags::empty())?;
    rustix::stdio::dup2_stderr(&given)?;
    let others: Vec<i32> = close_fds::iter_open_fds(fd + 1).collect();
    close_fds::set_fds_cloexec(fd, &others);
    Ok(())
}

#[cfg(test)]
mod tests;
