//! The turn tests take to start proxies on this host's ports. Shared, by
//! path, between the library's tests and `tests/cli.rs`, so that both take
//! the same turn.
//!
//! Proxy ports are the host's. Every test's enclos folder reserves them from
//! the same range, and so does every other `cargo test` of enclos running on
//! this host at the same time (another worktree, another target folder): two
//! of them reserve the same free port, and the second proxy to start cannot
//! listen. So tests that start proxies take turns through a lock on a file,
//! which, unlike a mutex, other processes see too. The file is in `$TMPDIR`,
//! which macOS sets per user: runs of one user take turns, but a run given
//! another `$TMPDIR` takes its turns apart.

use std::fs::{File, OpenOptions, TryLockError};
use std::io::Write;
use std::sync::LockResult;
use std::time::{Duration, Instant};

/// The file lock tests take turns through; each test file keeps one as its
/// `HOST_PORTS` static.
pub struct HostPorts;

/// The turn, held until dropped. Closing the file, also when the test
/// panics or its process dies, passes the turn on. Std opens it
/// close-on-exec, so the programs a test starts never hold the turn.
pub struct Turn {
    _file: File,
}

impl HostPorts {
    /// Waits for the turn, saying so when another run holds it. Panics when
    /// the file cannot be opened or locked.
    ///
    /// It has the shape of [`std::sync::Mutex::lock`], which these tests
    /// took before the turn was a file, so every test, written before or
    /// after, takes it the same way: `HOST_PORTS.lock().unwrap_or_else(|e|
    /// e.into_inner())`. The result is never an error: a test that failed
    /// already passed the turn on.
    pub fn lock(&self) -> LockResult<Turn> {
        let path = path();
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&path)
            .unwrap_or_else(|e| {
                panic!(
                    "cannot open {}: {e}; no test run holds the turn once it is removed, so remove it and run again",
                    path.display()
                )
            });
        // Tests of one run wait for each other briefly; a long wait means a
        // test, maybe of another run, is stuck holding the turn.
        let started = Instant::now();
        let locked = loop {
            match file.try_lock() {
                Ok(()) => break Ok(()),
                Err(TryLockError::Error(e)) => break Err(e),
                Err(TryLockError::WouldBlock) if started.elapsed() < SAY_AFTER => {
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(TryLockError::WouldBlock) => {
                    // Straight to stderr: libtest captures only `eprintln!`.
                    let _ = writeln!(
                        std::io::stderr(),
                        "still waiting for the turn on {0}: a test holds it, maybe in another run; `lsof {0}` names its process",
                        path.display()
                    );
                    break file.lock();
                }
            }
        };
        locked.unwrap_or_else(|e| panic!("cannot lock {}: {e}", path.display()));
        Ok(Turn { _file: file })
    }
}

/// How long a test waits for the turn before saying what it waits for.
const SAY_AFTER: Duration = Duration::from_secs(60);

/// The same file for every run of the same user, whatever its worktree or
/// target folder.
fn path() -> std::path::PathBuf {
    std::env::temp_dir().join("enclos-tests-host-ports.lock")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_second_open_of_the_file_cannot_take_the_turn() {
        let _turn = HostPorts.lock().unwrap();
        // `flock` locks each open of a file apart, even within one process,
        // so this open stands in for another `cargo test`'s.
        let other = File::open(path()).unwrap();
        assert!(matches!(other.try_lock(), Err(TryLockError::WouldBlock)));
    }
}
