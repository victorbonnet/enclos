//! What bubblewrap runs first in a session (design §5, What a session runs
//! first): the compiled Landlock rules and seccomp filter, applied to this
//! process, the relay, then the command. It reads the compiled file and
//! works out nothing of its own.
//!
//! What is applied cannot be undone, so all that can be refused is looked at
//! first, by [`Prepared::read`], and the order is [`in_session`]'s. The relay
//! starts first because it is a new program: Landlock's execute rules do not
//! cover an enclos installed under the user's home, and `fork` with no `exec`
//! takes `unsafe`, so the relay is a copy of this program, run while nothing
//! refuses it, that applies the same rules to itself before it serves. A
//! session's command runs only once its relay said so.

mod filter;
mod rules;

use std::ffi::OsString;
use std::fs::OpenOptions;
use std::io::{self, BufRead, BufReader, Write};
use std::net::TcpListener;
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use seccompiler::{BpfProgram, TargetArch};

use super::compile::CompiledSandbox;
use super::proposed::Landlock;

/// What the relay says once it is confined and serving is all that is left.
const READY: &str = "ready";

/// This program, wherever it was installed and whatever the mounts show of
/// that path.
const THIS_PROGRAM: &str = "/proc/self/exe";

#[derive(Debug, thiserror::Error)]
pub enum InsideError {
    #[error("cannot read the compiled file {}: {source}", path.display())]
    Read { path: PathBuf, source: io::Error },
    #[error("the compiled file {} does not read: {source}", path.display())]
    Parse {
        path: PathBuf,
        source: serde_json::Error,
    },
    #[error("seccomp filter for {0}: no such architecture is supported")]
    Architecture(String),
    #[error("the compiled filter names {0}, an errno enclos does not know")]
    Errno(String),
    #[error("the compiled filter does not build: {0}")]
    Filter(String),
    #[error("the compiled rules name {0}, a Landlock scope enclos does not know")]
    Scope(String),
    #[error("Landlock: {0}")]
    Landlock(String),
    #[error("seccomp: {0}")]
    Seccomp(String),
    #[error("the relay cannot listen: {0}")]
    RelayListen(#[source] Box<crate::error::Error>),
    #[error("cannot open the relay's log {path}: {source}")]
    RelayLog { path: String, source: io::Error },
    #[error("cannot start the relay: {0}")]
    RelayStart(#[source] io::Error),
    #[error("the relay did not start: see {log}")]
    RelayNotReady { log: String },
    #[error("the relay's port is not on its stdin: {0}")]
    RelayPort(#[source] io::Error),
    #[error("no command to run")]
    NoCommand,
    #[error("cannot run {command}: {source}")]
    Command { command: String, source: io::Error },
}

/// What a session and its relay both do.
trait Confine {
    fn apply_landlock(&mut self) -> Result<Landlock, InsideError>;
    fn apply_seccomp(&mut self) -> Result<(), InsideError>;
    fn say(&mut self, line: &str);
}

/// What a session does besides, each step returning what stops it.
trait SessionSteps: Confine {
    fn start_relay(&mut self) -> Result<(), InsideError>;
    fn run_command(&mut self) -> InsideError;
}

/// What the relay does besides.
trait RelaySteps: Confine {
    fn say_ready(&mut self) -> Result<(), InsideError>;
    fn serve(&mut self) -> InsideError;
}

/// Landlock, then seccomp, as the prototype applied them.
fn confine(steps: &mut impl Confine) -> Result<(), InsideError> {
    let landlock = steps.apply_landlock()?;
    if let Some(line) = landlock.notice() {
        steps.say(&line);
    }
    steps.apply_seccomp()
}

fn in_session(steps: &mut impl SessionSteps) -> InsideError {
    let confined = steps.start_relay().and_then(|()| confine(steps));
    match confined {
        Ok(()) => steps.run_command(),
        Err(e) => e,
    }
}

fn as_relay(steps: &mut impl RelaySteps) -> InsideError {
    match confine(steps).and_then(|()| steps.say_ready()) {
        Ok(()) => steps.serve(),
        Err(e) => e,
    }
}

/// What the compiled file gives, all of it looked at before anything is
/// applied.
struct Prepared {
    path: PathBuf,
    compiled: CompiledSandbox,
    grants: Vec<rules::Grant>,
    scopes: landlock::BitFlags<landlock::Scope>,
    programs: Vec<BpfProgram>,
}

impl Prepared {
    fn read(path: &Path) -> Result<Self, InsideError> {
        let text = std::fs::read_to_string(path).map_err(|source| InsideError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        let compiled: CompiledSandbox =
            serde_json::from_str(&text).map_err(|source| InsideError::Parse {
                path: path.to_path_buf(),
                source,
            })?;
        let arch = TargetArch::try_from(std::env::consts::ARCH)
            .map_err(|_| InsideError::Architecture(std::env::consts::ARCH.to_owned()))?;
        Ok(Self {
            path: path.to_path_buf(),
            grants: rules::grants(&compiled.landlock),
            scopes: rules::scopes(&compiled.landlock)?,
            programs: filter::programs(&compiled.seccomp, arch)?,
            compiled,
        })
    }

    /// The port is held before the relay starts, so the command never races
    /// it, and passed as the relay's stdin, the one descriptor `Command`
    /// hands on without `unsafe`.
    fn start_relay(&self) -> Result<(), InsideError> {
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
        let child = Command::new(THIS_PROGRAM)
            .args(["inside", "--relay", "--compiled"])
            .arg(&self.path)
            .stdin(Stdio::from(OwnedFd::from(listener)))
            .stdout(Stdio::piped())
            .stderr(Stdio::from(log))
            .spawn()
            .map_err(InsideError::RelayStart)?;
        let mut said = String::new();
        let not_ready = || InsideError::RelayNotReady {
            log: relay.log.clone(),
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

/// The compiled file, and the session's command or the relay's port.
struct Running<T> {
    prepared: Prepared,
    then: T,
}

impl<T> Confine for Running<T> {
    fn apply_landlock(&mut self) -> Result<Landlock, InsideError> {
        rules::apply(&self.prepared.grants, self.prepared.scopes)
    }

    /// Binds this thread and what it starts. No other thread exists yet.
    fn apply_seccomp(&mut self) -> Result<(), InsideError> {
        self.prepared.programs.iter().try_for_each(|program| {
            seccompiler::apply_filter(program).map_err(|e| InsideError::Seccomp(e.to_string()))
        })
    }

    /// The session's stderr, and the relay's log for the relay.
    fn say(&mut self, line: &str) {
        let _ = writeln!(io::stderr(), "{line}");
    }
}

impl SessionSteps for Running<&[OsString]> {
    fn start_relay(&mut self) -> Result<(), InsideError> {
        self.prepared.start_relay()
    }

    fn run_command(&mut self) -> InsideError {
        let Some((program, args)) = self.then.split_first() else {
            return InsideError::NoCommand;
        };
        let source = Command::new(program).args(args).exec();
        InsideError::Command {
            command: program.to_string_lossy().into_owned(),
            source,
        }
    }
}

impl RelaySteps for Running<TcpListener> {
    fn say_ready(&mut self) -> Result<(), InsideError> {
        writeln!(io::stdout(), "{READY}").map_err(InsideError::RelayStart)
    }

    fn serve(&mut self) -> InsideError {
        match self.then.try_clone() {
            Ok(listener) => {
                crate::relay::serve(listener, Path::new(&self.prepared.compiled.relay.socket))
            }
            Err(e) => InsideError::RelayPort(e),
        }
    }
}

/// Brings a session up on `path`'s file and becomes `command`. Returns only
/// what stopped it: no command has run then.
pub fn session(path: &Path, command: &[OsString]) -> InsideError {
    match Prepared::read(path) {
        Ok(prepared) => in_session(&mut Running {
            prepared,
            then: command,
        }),
        Err(e) => e,
    }
}

/// Serves as the session's relay. Returns only what stopped it.
pub fn relay(path: &Path) -> InsideError {
    // The session it serves is the process that started it, and the command
    // that process became; a PID namespace is not relied on to end it.
    let parent_gone = rustix::process::Signal::KILL;
    if let Err(e) = rustix::process::set_parent_process_death_signal(Some(parent_gone)) {
        return InsideError::RelayStart(e.into());
    }
    let listener = io::stdin()
        .as_fd()
        .try_clone_to_owned()
        .map(TcpListener::from)
        .map_err(InsideError::RelayPort);
    match (Prepared::read(path), listener) {
        (Ok(prepared), Ok(then)) => as_relay(&mut Running { prepared, then }),
        (Err(e), _) | (_, Err(e)) => e,
    }
}

#[cfg(test)]
mod tests;
