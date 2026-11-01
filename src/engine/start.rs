//! Starting a recorded session (design §8 steps 2-4): one way, for
//! `connect`, `exec`, the installers and agent commands, and `enclos
//! launch`. What differs between them is [`Starting`].
//!
//! The order is load-bearing. Nothing starts until the policy compiles and
//! the secrets are read. The program starts holding a marker, which is named
//! after it before the session is recorded, so that a session on record
//! always has its marker. A failure once the program runs ends it: no
//! session is left open for a program that is ended, and no program runs
//! where no `stop` finds it.

use std::ffi::OsString;
use std::os::unix::process::CommandExt;
use std::process::Child;

use super::Engine;
use super::proxy::abandon;
use crate::backend::Launch;
use crate::error::{Error, Result};
use crate::layout::LayoutError;
use crate::lifecycle::process::reference_of_child;
use crate::model::now;
use crate::model::runtime::RuntimeKind;
use crate::model::sandbox::{SandboxName, SandboxState};
use crate::model::session::{SessionId, SessionKind, SessionRecord};
use crate::state::StateLock;

/// Which process group a session's program starts in (design §8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Group {
    /// A group made for it, which it leads.
    Own,
    /// The group this process leads, as a terminal's job does: the program
    /// keeps the terminal, and this process is not a member.
    ThisProcess,
    /// The caller's group, which is not the session's: the session then has
    /// no group, only the processes the program starts.
    Caller,
}

impl Group {
    /// The group a session records, with `program` the program's pid and
    /// `me` this process's.
    fn pgid(self, program: u32, me: u32) -> Option<u32> {
        match self {
            Group::Own => Some(program),
            Group::ThisProcess => Some(me),
            Group::Caller => None,
        }
    }
}

/// What a session is started for.
#[derive(Debug, Clone, Copy)]
pub(super) enum Starting<'a> {
    /// A command run from the CLI, in this terminal if there is one: it
    /// starts the sandbox's proxy if need be, reaches the runtime's service,
    /// and gets the sandbox's secrets as variables.
    Command { kind: SessionKind, group: Group },
    /// `name`, a service of `runtime`, for the service manager, in a group
    /// of its own. Its proxy already runs, and its secrets are as
    /// `service_secrets` says.
    Service { runtime: RuntimeKind, name: &'a str },
}

/// A session that started.
pub(super) struct Started<T> {
    pub session: SessionRecord,
    pub child: Child,
    /// Why the session cannot reach its runtime's service (ADR 0028).
    pub unreachable: Option<String>,
    /// What `before_recording` gave.
    pub ready: T,
}

impl Engine {
    /// Starts `command` in the sandbox and records it as a session, under
    /// the state lock. `before_recording` runs once the program does, before
    /// the session is recorded, so that a failure there ends the program and
    /// leaves no session open.
    pub(super) fn start_session<T>(
        &self,
        lock: &StateLock,
        name: &SandboxName,
        command: &[OsString],
        starting: Starting,
        before_recording: impl FnOnce() -> Result<T>,
    ) -> Result<Started<T>> {
        let mut record = self.record(name)?;
        let compiled = self.compile_policy(name, record.proxy_port)?;
        if matches!(starting, Starting::Command { .. }) {
            self.ensure_proxy(lock, &record)?;
        }
        let (version, snapshot) = self.active_policy(name)?;
        let (program, args) = command.split_first().ok_or_else(|| Error::Session {
            what: "no command to run".into(),
        })?;
        let (service_port, unreachable, env) = match starting {
            Starting::Command { .. } => {
                // The runtime's clients reach its service on the port it
                // holds now (ADR 0028), or the session says why it cannot.
                let (port, unreachable) = match self.service_port(&record) {
                    Ok(port) => (port, None),
                    Err(why) => (None, Some(why)),
                };
                // Read on the host, now: the sandbox reaches no secret store.
                (port, unreachable, self.secret_env(&snapshot.policy)?)
            }
            // Read on the host, as the service starts, never written to the
            // service manager's file (ADR 0022).
            Starting::Service { runtime, name: of } => (
                None,
                None,
                self.service_secrets(name, runtime, of, &snapshot.policy)?,
            ),
        };
        let launch = Launch {
            program: program.clone(),
            args: args.to_vec(),
            env,
            // A service outlives even an `enclos launch` run by hand in a
            // terminal.
            in_terminal: matches!(starting, Starting::Command { .. }),
            service_port,
            limits: self.launch_limits(&record, &snapshot.policy)?,
        };
        let ctx = self.sandbox_context(name, record.proxy_port);
        // TMPDIR inside the sandbox (the policy denies /tmp). The sandbox
        // may have removed it.
        let tmp = ctx.home.join("tmp");
        std::fs::create_dir_all(&tmp).map_err(|source| LayoutError::Io { path: tmp, source })?;
        let mut wrapped = self.backend_of(name)?.wrap(&compiled, &ctx, &launch);
        let group = match starting {
            Starting::Command { group, .. } => group,
            Starting::Service { .. } => Group::Own,
        };
        if group == Group::Own {
            wrapped.process_group(0);
        }
        let marker = self.new_marker(name)?;
        let (child, marked) = marker.spawn(&mut wrapped).map_err(|e| Error::Session {
            what: match starting {
                Starting::Command { .. } => format!(
                    "could not start {} in {name}: {e}",
                    launch.program.to_string_lossy()
                ),
                Starting::Service { runtime, name: of } => {
                    format!("could not start the {runtime} {of} service: {e}")
                }
            },
        })?;
        let recorded = (|| -> Result<(SessionRecord, T)> {
            let ready = before_recording()?;
            // Read even if the program already exited: it is still a
            // session, with an exit status to report.
            let root = reference_of_child(&child)?;
            self.name_marker(name, marked, &root)?;
            let (kind, service) = match starting {
                Starting::Command { kind, .. } => (kind, None),
                Starting::Service { name, .. } => (SessionKind::Service, Some(name.to_owned())),
            };
            let mut session = SessionRecord {
                id: SessionId(0),
                sandbox: name.clone(),
                kind,
                service,
                version: version.version,
                snapshot: snapshot.id,
                compiled: Some(compiled.display().to_string()),
                root,
                pgid: group.pgid(child.id(), std::process::id()),
                tracked: Vec::new(),
                started_at: now(),
                ended_at: None,
            };
            // Running again, also after a `launch` that failed and that the
            // service manager starts again.
            record.state = SandboxState::Running;
            session.id = self.state.start_session(lock, &session, &record)?;
            Ok((session, ready))
        })();
        match recorded {
            Ok((session, ready)) => Ok(Started {
                session,
                child,
                unreachable,
                ready,
            }),
            Err(e) => Err(abandon(
                child,
                e,
                match starting {
                    Starting::Command { .. } => "the program",
                    Starting::Service { .. } => "the service",
                },
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_session_records_the_group_it_can_answer_for() {
        assert_eq!(Group::Own.pgid(7, 3), Some(7));
        assert_eq!(Group::ThisProcess.pgid(7, 3), Some(3));
        assert_eq!(Group::Caller.pgid(7, 3), None);
    }
}
