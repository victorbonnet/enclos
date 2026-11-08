//! What bubblewrap runs first in a session (design §5, What a session runs
//! first): the compiled Landlock rules and seccomp filter, applied to this
//! process, then the command. It reads the compiled file and works out
//! nothing of its own. The relay to the proxy is not the session's: the
//! sandbox's namespace holder serves it in the network namespace the session
//! joined (ADR 0039).
//!
//! What is applied cannot be undone, so all that can be refused is looked at
//! first, by [`Prepared::read`], and the order is [`in_session`]'s.

mod command;
mod filter;
mod rules;

use std::ffi::OsString;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use seccompiler::{BpfProgram, TargetArch};

use super::compile::CompiledSandbox;
use super::proposed::Landlock;
use command::Session;
#[cfg(test)]
use command::{Ended, reap_until};

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
    #[error("cannot take the session's stderr back from bubblewrap: {0}")]
    Stderr(io::Error),
}

/// What confines a session, each step returning what stops it.
trait Confine {
    fn apply_landlock(&mut self) -> Result<Landlock, InsideError>;
    fn apply_seccomp(&mut self) -> Result<(), InsideError>;
    fn say(&mut self, line: &str);
}

/// The step a session takes once confined.
trait SessionSteps: Confine {
    /// Runs the command to its end: its exit code, as a shell gives it.
    fn run_command(&mut self) -> Result<u8, InsideError>;
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
    confine(steps)?;
    steps.run_command()
}

/// What the compiled file gives, all of it looked at before anything is
/// applied.
struct Prepared {
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
            grants: rules::grants(&compiled.landlock),
            scopes: rules::scopes(&compiled.landlock)?,
            programs: filter::programs(&compiled.seccomp, arch)?,
        })
    }
}

/// The compiled file, and the session's command.
struct Running<'a> {
    prepared: Prepared,
    session: Session<'a>,
}

impl Confine for Running<'_> {
    fn apply_landlock(&mut self) -> Result<Landlock, InsideError> {
        rules::apply(&self.prepared.grants, self.prepared.scopes)
    }

    /// Binds this thread and what it starts. No other thread exists yet.
    fn apply_seccomp(&mut self) -> Result<(), InsideError> {
        self.prepared.programs.iter().try_for_each(|program| {
            seccompiler::apply_filter(program).map_err(|e| InsideError::Seccomp(e.to_string()))
        })
    }

    /// The session's stderr.
    fn say(&mut self, line: &str) {
        let _ = writeln!(io::stderr(), "{line}");
    }
}

/// Brings a session up on `path`'s file and runs `command` to its end: its
/// exit code, or what stopped it, when no command has run. With
/// `restore_interrupts`, the command gets Ctrl-C and Ctrl-\, which
/// bubblewrap's outer process was started ignoring. First of all, says that
/// bubblewrap's setup is done and takes back the session's stderr (`setup`).
pub fn session(
    path: &Path,
    command: &[OsString],
    restore_interrupts: bool,
) -> Result<u8, InsideError> {
    super::setup::done().map_err(InsideError::Stderr)?;
    in_session(&mut Running {
        prepared: Prepared::read(path)?,
        session: Session {
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

#[cfg(test)]
mod tests;
