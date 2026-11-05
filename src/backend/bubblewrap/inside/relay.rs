//! The relay a session starts of itself: started by the session before it
//! is confined, then confined on its own, and serving until its session
//! ends.

use std::fs::OpenOptions;
use std::io::{self, BufRead, BufReader, Write};
use std::net::TcpListener;
use std::os::fd::OwnedFd;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::{CommandExt, parent_id};
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

use super::{InsideError, Prepared, RelaySteps, Running};

/// What the relay says once it is confined and serving is all that is left.
const READY: &str = "ready";

/// This program, wherever it was installed and whatever the mounts show of
/// that path.
const THIS_PROGRAM: &str = "/proc/self/exe";

/// How often a relay looks whether its session is still there.
const PARENT_LOOK: Duration = Duration::from_secs(1);

impl Prepared {
    /// The port is held before the relay starts, so the command never races
    /// it, and passed as the relay's stdin, the one descriptor `Command`
    /// hands on without `unsafe`.
    pub(super) fn start_relay(&self) -> Result<(), InsideError> {
        let relay = &self.compiled.relay;
        let listener = crate::relay::listen(relay.port, Path::new(&relay.socket))
            .map_err(|e| InsideError::RelayListen(Box::new(e)))?;
        let log = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(&relay.log)
            .map_err(|source| InsideError::RelayLog {
                path: relay.log.clone(),
                source,
            })?;
        // In a group of its own: in a terminal the session's is the foreground
        // one, whose Ctrl-C is the program's to hear, and would end the relay.
        let child = Command::new(THIS_PROGRAM)
            .args(["inside", "--relay", "--compiled"])
            .arg(&self.path)
            .process_group(0)
            .stdin(Stdio::from(OwnedFd::from(listener)))
            .stdout(Stdio::piped())
            .stderr(Stdio::from(log))
            .spawn()
            .map_err(InsideError::RelayStart)?;
        let mut said = String::new();
        // Read now: the log is in the session's `/tmp`, which goes when the
        // session ends.
        let not_ready = || InsideError::RelayNotReady {
            why: last_line(Path::new(&relay.log)),
        };
        let stdout = child.stdout.ok_or_else(not_ready)?;
        BufReader::new(stdout)
            .read_line(&mut said)
            .map_err(|_| not_ready())?;
        match said.trim() == READY {
            true => Ok(()),
            false => Err(not_ready()),
        }
    }
}

/// What a relay's log ends with, which is what stopped it.
pub(super) fn last_line(log: &Path) -> String {
    let text = std::fs::read(log).unwrap_or_default();
    let text = String::from_utf8_lossy(&text);
    match text.lines().rfind(|line| !line.trim().is_empty()) {
        Some(line) => line.trim_start_matches("error: ").to_owned(),
        None => "it left no word in its log".to_owned(),
    }
}

/// Returns once `now` gives another parent than `parent`.
pub(super) fn wait_for_new_parent(parent: u32, now: impl Fn() -> u32, every: Duration) {
    while now() == parent {
        thread::sleep(every);
    }
}

/// The port a relay serves, and the session that started it.
pub(super) struct Serving {
    pub(super) listener: TcpListener,
    pub(super) session: u32,
}

impl RelaySteps for Running<Serving> {
    fn say_ready(&mut self) -> Result<(), InsideError> {
        writeln!(io::stdout(), "{READY}").map_err(InsideError::RelayStart)
    }

    /// Looks after its session from here: a parent-death signal is checked
    /// as one the dying session sends, so where Landlock's scopes apply the
    /// relay's own domain refuses it, and a PID namespace is not relied on.
    fn serve(&mut self) -> InsideError {
        let session = self.then.session;
        let watching = thread::Builder::new().spawn(move || {
            wait_for_new_parent(session, parent_id, PARENT_LOOK);
            std::process::exit(0);
        });
        if let Err(e) = watching {
            return InsideError::RelayStart(e);
        }
        match self.then.listener.try_clone() {
            Ok(listener) => {
                crate::relay::serve(listener, Path::new(&self.prepared.compiled.relay.socket))
            }
            Err(e) => InsideError::RelayPort(e),
        }
    }
}
