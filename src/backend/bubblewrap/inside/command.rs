//! How `enclos inside` runs a session's command: as a child, with Ctrl-C
//! handed back to it, while this process stays PID 1 and reaps.

use std::ffi::OsString;
use std::io;
use std::process::Command;

use super::{InsideError, Running, SessionSteps};

/// The signals bubblewrap's outer process ignores in a terminal's session
/// (`wrap`).
const INTERRUPTS: [i32; 2] = [signal_hook::consts::SIGINT, signal_hook::consts::SIGQUIT];

/// SIGINT and SIGQUIT arrive here ignored, and an ignored signal stays
/// ignored across `exec`. A caught one does not: catching both (the flag is
/// never read) gives the command their default action, while this process,
/// which only reaps, ignores them.
fn hand_back_interrupts() -> Result<(), InsideError> {
    let heard = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    for signal in INTERRUPTS {
        signal_hook::flag::register(signal, heard.clone()).map_err(InsideError::Interrupts)?;
    }
    Ok(())
}

/// How a child ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Ended {
    Exited(i32),
    Killed(i32),
}

impl Ended {
    /// None for a child that was stopped or continued, which `wait` reports
    /// only when asked to.
    pub(super) fn of(status: rustix::process::WaitStatus) -> Option<Ended> {
        match (status.exit_status(), status.terminating_signal()) {
            (Some(code), _) => Some(Ended::Exited(code)),
            (None, Some(signal)) => Some(Ended::Killed(signal)),
            (None, None) => None,
        }
    }
}

/// Reaps what `next` finds ended, every orphan of the session included, until
/// `command` ends, then gives its exit code as a shell does: 128 and the
/// signal for one a signal ended. A child that did not end is passed over,
/// and a call a signal cut short is made again.
pub(super) fn reap_until(
    command: u32,
    mut next: impl FnMut() -> io::Result<Option<(u32, Option<Ended>)>>,
) -> Result<u8, InsideError> {
    loop {
        match next() {
            Ok(Some((pid, Some(ended)))) if pid == command => {
                return Ok(match ended {
                    Ended::Exited(code) => code.clamp(0, 255) as u8,
                    Ended::Killed(signal) => (128 + signal).clamp(0, 255) as u8,
                });
            }
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(InsideError::Reap(e)),
        }
    }
}

/// The session's command, and whether to hand Ctrl-C and Ctrl-\ back to it.
pub(super) struct Session<'a> {
    pub(super) command: &'a [OsString],
    pub(super) restore_interrupts: bool,
}

impl SessionSteps for Running<Session<'_>> {
    fn start_relay(&mut self) -> Result<(), InsideError> {
        self.prepared.start_relay()
    }

    /// Runs the command as a child, not by `exec`: as PID 1 it would ignore
    /// every signal it has no handler for, Ctrl-C included. First makes this
    /// process not dumpable, so no member can attach to it, then reaps every
    /// orphan until the command ends.
    fn run_command(&mut self) -> Result<u8, InsideError> {
        let Some((program, args)) = self.then.command.split_first() else {
            return Err(InsideError::NoCommand);
        };
        rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable)
            .map_err(|e| InsideError::NotDumpable(e.into()))?;
        if self.then.restore_interrupts {
            hand_back_interrupts()?;
        }
        let child =
            Command::new(program)
                .args(args)
                .spawn()
                .map_err(|source| InsideError::Command {
                    command: program.to_string_lossy().into_owned(),
                    source,
                })?;
        reap_until(child.id(), || {
            rustix::process::wait(rustix::process::WaitOptions::empty())
                .map(|found| {
                    found.map(|(pid, status)| {
                        (pid.as_raw_nonzero().get().unsigned_abs(), Ended::of(status))
                    })
                })
                .map_err(io::Error::from)
        })
    }
}
