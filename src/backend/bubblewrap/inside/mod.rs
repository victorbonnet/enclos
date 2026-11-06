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

mod command;
mod filter;
mod relay;
mod rules;

use std::ffi::OsString;
use std::io::{self, Write};
use std::net::TcpListener;
use std::os::fd::AsFd;
use std::os::unix::process::parent_id;
use std::path::{Path, PathBuf};

use seccompiler::{BpfProgram, TargetArch};

use super::compile::CompiledSandbox;
use super::proposed::Landlock;
use command::Session;
#[cfg(test)]
use command::{Ended, reap_until};
use relay::Serving;
#[cfg(test)]
use relay::{last_line, wait_for_new_parent};

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
    #[error("the relay did not start: {why}")]
    RelayNotReady { why: String },
    #[error("the relay's port is not on its stdin: {0}")]
    RelayPort(#[source] io::Error),
    #[error("no command to run")]
    NoCommand,
    #[error("cannot run {command}: {source}")]
    Command { command: String, source: io::Error },
    #[error("cannot keep the session's processes off this one: {0}")]
    NotDumpable(io::Error),
    #[error("lost the session's command: {0}")]
    Reap(io::Error),
    #[error("cannot hand Ctrl-C back to the command: {0}")]
    Interrupts(io::Error),
}

/// What a session and its relay both do.
trait Confine {
    fn apply_landlock(&mut self) -> Result<Landlock, InsideError>;
    fn apply_seccomp(&mut self) -> Result<(), InsideError>;
    fn say(&mut self, line: &str);
}

/// The steps only a session takes, after [`Confine`]'s, each returning what
/// stops it.
trait SessionSteps: Confine {
    fn start_relay(&mut self) -> Result<(), InsideError>;
    /// Runs the command to its end: its exit code, as a shell gives it.
    fn run_command(&mut self) -> Result<u8, InsideError>;
}

/// The steps only a relay takes.
trait RelaySteps: Confine {
    fn say_ready(&mut self) -> Result<(), InsideError>;
    fn serve(&mut self) -> InsideError;
}

/// Landlock, then seccomp: the rules are made while no filter applies to
/// the calls that make them.
fn confine(steps: &mut impl Confine) -> Result<(), InsideError> {
    let landlock = steps.apply_landlock()?;
    if let Some(line) = landlock.notice() {
        steps.say(&line);
    }
    steps.apply_seccomp()
}

fn in_session(steps: &mut impl SessionSteps) -> Result<u8, InsideError> {
    steps.start_relay()?;
    confine(steps)?;
    steps.run_command()
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

/// Brings a session up on `path`'s file and runs `command` to its end: its
/// exit code, or what stopped it, when no command has run. With
/// `restore_interrupts`, the command gets Ctrl-C and Ctrl-\, which
/// bubblewrap's outer process was started ignoring.
pub fn session(
    path: &Path,
    command: &[OsString],
    restore_interrupts: bool,
) -> Result<u8, InsideError> {
    in_session(&mut Running {
        prepared: Prepared::read(path)?,
        then: Session {
            command,
            restore_interrupts,
        },
    })
}

/// The kernel's Landlock ABI, up to the one the rules need, if it has
/// Landlock (ADR 0037). Restricts nothing.
pub fn landlock_abi() -> Option<u32> {
    rules::host_abi()
}

/// Serves as the session's relay. Returns only what stopped it.
pub fn relay(path: &Path) -> InsideError {
    // The session it serves is the `enclos inside` that started it. Read
    // first: a session gone before this line leaves nobody to read `ready`,
    // and saying it fails.
    let session = parent_id();
    let listener = io::stdin()
        .as_fd()
        .try_clone_to_owned()
        .map(TcpListener::from)
        .map_err(InsideError::RelayPort);
    match (Prepared::read(path), listener) {
        (Ok(prepared), Ok(listener)) => as_relay(&mut Running {
            prepared,
            then: Serving { listener, session },
        }),
        (Err(e), _) | (_, Err(e)) => e,
    }
}

#[cfg(test)]
mod tests;
