//! Starting a recorded session (design §8 steps 2-5): one way, for
//! `connect`, `exec`, the installers and agent commands, and `enclos
//! launch`. What differs between them is [`Starting`] and what they do
//! once the program runs and before it is recorded.
//!
//! The order is load-bearing. On a host whose systemd is too old for a scope
//! nothing starts, so the check comes first. The program does not start until the policy
//! compiles and the secrets are read; the proxy a command needs starts
//! between the two, and stays if a later step fails. The program starts
//! holding a marker, which is named after it before the session is
//! recorded, so that a session started here has its marker. A failure
//! before the session is recorded kills the program, so that no session
//! stays open for a program that is ended; a kill that fails is reported.
//! In a scope (design §8) its cgroup is ended too, with what the program
//! started meanwhile; with none, only the program is killed.

use std::ffi::OsString;
use std::io;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command};
use std::time::Duration;

use super::Engine;
use super::proxy::abandon;
use crate::backend::Launch;
use crate::error::{Error, Result};
use crate::layout::LayoutError;
use crate::lifecycle::cgroup::{Hierarchy, Scope, Systemd};
use crate::lifecycle::process::{PsError, reference_of_child};
use crate::model::now;
use crate::model::sandbox::{SandboxName, SandboxState};
use crate::model::session::{SessionId, SessionKind, SessionRecord};
use crate::state::StateLock;

/// How long what a failed start left in its cgroup has to die of the kill.
const SCOPE_END_WAIT: Duration = Duration::from_secs(5);

/// Which process group a session's program starts in (design §8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Group {
    /// A group made for it, which it leads, and to which this process
    /// passes every signal it catches.
    Own,
    /// The group this process leads, as a terminal's job does: the program
    /// keeps the terminal, and this process is not a member.
    ThisProcess,
    /// The caller's group, which is not the session's: the session then has
    /// no group, only the processes the program starts.
    Caller,
}

impl Group {
    /// The group of a program this process starts. Without a terminal (a
    /// script, CI, a supervisor, whether or not this process leads its
    /// group), one made for it. In a terminal, when this process leads its
    /// group, as a terminal's job does, that group. Otherwise (a terminal,
    /// but not a job of its own, as in a shell's pipeline) the caller's. A
    /// terminal on any of the standard streams counts: with input piped in,
    /// the output still goes to the terminal, whose Ctrl-C must reach the
    /// program.
    pub(super) fn of(in_terminal: bool, leads_group: bool) -> Group {
        match (in_terminal, leads_group) {
            (false, _) => Group::Own,
            (true, true) => Group::ThisProcess,
            (true, false) => Group::Caller,
        }
    }

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

/// The kinds of session a command run from the CLI can be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CommandKind {
    Interactive,
    Exec,
}

impl From<CommandKind> for SessionKind {
    fn from(kind: CommandKind) -> SessionKind {
        match kind {
            CommandKind::Interactive => SessionKind::Interactive,
            CommandKind::Exec => SessionKind::Exec,
        }
    }
}

/// What a session is started for.
#[derive(Debug, Clone, Copy)]
pub(super) enum Starting<'a> {
    /// A command run from the CLI: it starts the sandbox's proxy if need be,
    /// reaches the runtime's service, and gets the sandbox's secrets as
    /// variables.
    Command { kind: CommandKind, group: Group },
    /// A service of the sandbox's runtime, for the service manager. Its
    /// proxy already runs, and its secrets are as `service_secrets` says.
    Service { service: &'a str },
}

impl Starting<'_> {
    /// Whether the program may use this process's terminal, if it has one.
    /// A service never does, even under an `enclos launch` run by hand in
    /// one.
    fn in_terminal(self) -> bool {
        matches!(self, Starting::Command { .. })
    }

    fn group(self) -> Group {
        match self {
            Starting::Command { group, .. } => group,
            Starting::Service { .. } => Group::Own,
        }
    }

    /// The session's kind, and its service if it is one.
    fn recorded_as(self) -> (SessionKind, Option<String>) {
        match self {
            Starting::Command { kind, .. } => (kind.into(), None),
            Starting::Service { service } => (SessionKind::Service, Some(service.to_owned())),
        }
    }

    /// What a program left running would be called.
    fn program(self) -> &'static str {
        match self {
            Starting::Command { .. } => "the program",
            Starting::Service { .. } => "the service",
        }
    }
}

/// A session that started.
pub(super) struct Started<T> {
    pub session: SessionRecord,
    pub child: Child,
    /// Why the session cannot reach its runtime's service (ADR 0028).
    pub unreachable: Option<String>,
    /// What `before_recording` prepared.
    pub prepared: T,
}

/// Makes `tmp`, the folder `TMPDIR` names (the policy denies /tmp), a folder.
/// The sandbox owns its home and may have removed it, or left something else
/// in its place: that is replaced, never followed, so that what a sandbox
/// does to its own cache cannot keep its next session from starting.
fn fresh_tmp(tmp: &Path) -> io::Result<()> {
    match std::fs::symlink_metadata(tmp) {
        Ok(found) if found.is_dir() => return Ok(()),
        Ok(_) => std::fs::remove_file(tmp)?,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    match std::fs::create_dir(tmp) {
        // A process of the sandbox made one meanwhile.
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(()),
        made => made,
    }
}

/// Ends `child`, whose session was not recorded, then what the cgroup `left`
/// says it left: the cgroup holds what it started, whatever its group and
/// parent. The program goes first, so that nothing joins the scope after,
/// and it goes whether or not the cgroup can be told; what cannot be ended,
/// or looked for, is reported with the failure.
fn end_unrecorded(
    cgroups: &Hierarchy,
    child: Child,
    left: impl FnOnce() -> std::result::Result<Option<String>, PsError>,
    error: Error,
    what: &str,
) -> Error {
    let error = abandon(child, error, what);
    match left().and_then(|cgroup| match cgroup {
        Some(cgroup) => cgroups.end(&cgroup, SCOPE_END_WAIT),
        None => Ok(()),
    }) {
        Ok(()) => error,
        Err(e) => Error::CleanupFailed {
            error: Box::new(error),
            left: format!("what {what} started ({e})"),
        },
    }
}

impl Engine {
    /// `wrapped` as the program of a new scope in sandbox `name`'s slice,
    /// and that scope, when this engine runs programs in scopes (design §8).
    /// `Scope::wrap` keeps only the program, its arguments, environment and
    /// folder, so anything else is set on what this returns.
    fn in_scope(&self, name: &SandboxName, wrapped: Command) -> Result<(Command, Option<Scope>)> {
        if !self.scopes {
            return Ok((wrapped, None));
        }
        let scope = Scope::new(&self.layout.install_id()?, name.as_str());
        Ok((scope.wrap(&wrapped), Some(scope)))
    }

    /// Starts `command` in the sandbox and records it as a session, under
    /// the state lock. `before_recording` runs once the program does, before
    /// the session is recorded, so that a failure there ends the program and
    /// leaves no session open. It runs no earlier because what it prepares
    /// may change how this process answers signals, as `KeepWaiting` does,
    /// which must not apply through the wait for the proxy and the secrets.
    pub(super) fn start_session<T>(
        &self,
        lock: &StateLock,
        name: &SandboxName,
        command: &[OsString],
        starting: Starting,
        before_recording: impl FnOnce() -> Result<T>,
    ) -> Result<Started<T>> {
        if self.scopes
            && let Some(what) = Systemd::at(&self.systemd_run).refusal()
        {
            return Err(Error::Session { what });
        }
        let mut record = self.record(name)?;
        let compiled = self.compile_policy(name, record.proxy_port)?;
        if matches!(starting, Starting::Command { .. }) {
            self.ensure_proxy(lock, &record)?;
        }
        let (version, snapshot) = self.active_policy(name)?;
        let (program, args) = command.split_first().ok_or_else(|| Error::Session {
            what: "no command to run".into(),
        })?;
        let ctx = self.sandbox_context(name, record.proxy_port);
        // Before the secrets, which a service's start writes to files.
        let tmp = ctx.home.join("tmp");
        fresh_tmp(&tmp).map_err(|source| LayoutError::Io { path: tmp, source })?;
        let (service_port, unreachable, env, named) = match starting {
            Starting::Command { .. } => {
                // The runtime's clients reach its service on the port it
                // holds now (ADR 0028), or the session says why it cannot.
                let (port, unreachable) = match self.service_port(&record) {
                    Ok(port) => (port, None),
                    Err(why) => (None, Some(why)),
                };
                // Read on the host, now: the sandbox reaches no secret store.
                let env = self.secret_env(&snapshot.policy)?;
                let named = format!("{} in {name}", program.to_string_lossy());
                (port, unreachable, env, named)
            }
            Starting::Service { service } => {
                let runtime = self.runtime_of(name)?;
                // Read on the host, as the service starts, never written to
                // the service manager's file (ADR 0022).
                let env = self.service_secrets(name, runtime, service, &snapshot.policy)?;
                let named = format!("the {runtime} {service} service");
                (None, None, env, named)
            }
        };
        let launch = Launch {
            program: program.clone(),
            args: args.to_vec(),
            env,
            in_terminal: starting.in_terminal(),
            service_port,
            limits: self.launch_limits(&record, &snapshot.policy)?,
        };
        let wrapped = self.backend_of(name)?.wrap(&compiled, &ctx, &launch);
        let (mut wrapped, scope) = self.in_scope(name, wrapped)?;
        let group = starting.group();
        if group == Group::Own {
            wrapped.process_group(0);
        }
        let marker = self.new_marker(name)?;
        let (child, marked) = marker.spawn(&mut wrapped).map_err(|e| Error::Session {
            what: format!("could not start {named}: {e}"),
        })?;
        // Known from here on, for a failure to end it.
        let mut cgroup = None;
        let recorded = (|| -> Result<(SessionRecord, T)> {
            let prepared = before_recording()?;
            // Read even if the program already exited: it is still a
            // session, with an exit status to report.
            let root = reference_of_child(&child)?;
            self.name_marker(name, marked, &root)?;
            // An error ends the program, as any failure to record it does.
            if let Some(scope) = &scope {
                cgroup = Some(scope.cgroup_of(child.id())?);
            }
            let (kind, service) = starting.recorded_as();
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
                cgroup: cgroup.clone(),
                tracked: Vec::new(),
                started_at: now(),
                ended_at: None,
            };
            // Running again, also after a `launch` that failed and that the
            // service manager starts again.
            record.state = SandboxState::Running;
            session.id = self.state.start_session(lock, &session, &record)?;
            Ok((session, prepared))
        })();
        match recorded {
            Ok((session, prepared)) => Ok(Started {
                session,
                child,
                unreachable,
                prepared,
            }),
            Err(e) => Err(match &scope {
                Some(scope) => end_unrecorded(
                    &self.cgroups,
                    child,
                    || cgroup.map_or_else(|| scope.control_group(), |c| Ok(Some(c))),
                    e,
                    starting.program(),
                ),
                None => abandon(child, e, starting.program()),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const COMMAND: Starting = Starting::Command {
        kind: CommandKind::Exec,
        group: Group::Caller,
    };
    const SERVICE: Starting = Starting::Service { service: "gateway" };

    /// A stand-in for the hierarchy with a cgroup holding `text`, and a
    /// program for a failed start to end.
    fn started_in_cgroup(text: &str) -> (tempfile::TempDir, Hierarchy, Child) {
        let dir = tempfile::tempdir().unwrap();
        let folder = dir.path().join("s.scope");
        std::fs::create_dir(&folder).unwrap();
        std::fs::write(folder.join("cgroup.procs"), text).unwrap();
        let cgroups = Hierarchy::at(dir.path());
        let child = Command::new("/bin/sleep").arg("30").spawn().unwrap();
        (dir, cgroups, child)
    }

    fn failed() -> Error {
        Error::Session {
            what: "the start failed".into(),
        }
    }

    #[test]
    fn a_failed_start_ends_the_program_and_its_cgroup() {
        let (dir, cgroups, child) = started_in_cgroup("");
        let pid = child.id();
        let cgroup = || Ok(Some("/s.scope".to_owned()));
        let e = end_unrecorded(&cgroups, child, cgroup, failed(), "the program");
        assert!(matches!(e, Error::Session { .. }), "{e}");
        assert_eq!(crate::lifecycle::process::reference(pid).unwrap(), None);
        let asked = std::fs::read_to_string(dir.path().join("s.scope/cgroup.kill"));
        assert_eq!(asked.unwrap(), "1");
    }

    #[test]
    fn a_failed_start_with_nothing_left_of_its_scope_is_only_that_failure() {
        let (_dir, cgroups, child) = started_in_cgroup("");
        let e = end_unrecorded(&cgroups, child, || Ok(None), failed(), "the program");
        assert!(matches!(e, Error::Session { .. }), "{e}");
    }

    /// With the failure, and the program is ended all the same.
    #[test]
    fn a_failed_start_says_when_its_cgroup_could_not_be_told() {
        let (_dir, cgroups, child) = started_in_cgroup("");
        let no_answer = || Err(PsError::Cgroup("no systemctl".into()));
        let e = end_unrecorded(&cgroups, child, no_answer, failed(), "the program");
        let Error::CleanupFailed { error, left } = e else {
            panic!("{e}");
        };
        assert!(matches!(*error, Error::Session { .. }));
        assert!(left.contains("what the program started"), "{left}");
    }

    #[test]
    fn a_terminal_and_who_leads_the_group_choose_where_a_program_starts() {
        assert_eq!(Group::of(false, false), Group::Own);
        assert_eq!(Group::of(false, true), Group::Own);
        assert_eq!(Group::of(true, true), Group::ThisProcess);
        assert_eq!(Group::of(true, false), Group::Caller);
    }

    #[test]
    fn a_session_records_the_group_it_can_answer_for() {
        assert_eq!(Group::Own.pgid(7, 3), Some(7));
        assert_eq!(Group::ThisProcess.pgid(7, 3), Some(3));
        assert_eq!(Group::Caller.pgid(7, 3), None);
    }

    #[test]
    fn a_command_may_use_the_terminal_and_a_service_never_does() {
        assert!(COMMAND.in_terminal());
        assert!(!SERVICE.in_terminal());
    }

    #[test]
    fn a_service_leads_a_group_of_its_own_and_a_command_where_it_was_told() {
        assert_eq!(COMMAND.group(), Group::Caller);
        assert_eq!(SERVICE.group(), Group::Own);
    }

    #[test]
    fn a_session_is_recorded_as_what_it_was_started_for() {
        assert_eq!(COMMAND.recorded_as(), (SessionKind::Exec, None));
        let interactive = Starting::Command {
            kind: CommandKind::Interactive,
            group: Group::Own,
        };
        assert_eq!(interactive.recorded_as(), (SessionKind::Interactive, None));
        assert_eq!(
            SERVICE.recorded_as(),
            (SessionKind::Service, Some("gateway".to_owned()))
        );
    }

    #[test]
    fn a_tmp_folder_is_kept_with_what_it_holds() {
        let dir = tempfile::tempdir().unwrap();
        let tmp = dir.path().join("tmp");
        std::fs::create_dir(&tmp).unwrap();
        std::fs::write(tmp.join("kept"), "").unwrap();
        fresh_tmp(&tmp).unwrap();
        assert!(tmp.join("kept").exists());
    }

    #[test]
    fn a_missing_tmp_folder_is_made() {
        let dir = tempfile::tempdir().unwrap();
        let tmp = dir.path().join("tmp");
        fresh_tmp(&tmp).unwrap();
        assert!(tmp.is_dir());
    }

    /// Whatever a sandbox left there, a file, a link that leads nowhere or
    /// a link to a folder, becomes a folder of its own, and what a link
    /// led to is left alone.
    #[test]
    fn what_a_sandbox_left_in_place_of_tmp_is_replaced_and_never_followed() {
        let dir = tempfile::tempdir().unwrap();
        let tmp = dir.path().join("tmp");
        let elsewhere = dir.path().join("elsewhere");
        std::fs::create_dir(&elsewhere).unwrap();
        std::fs::write(elsewhere.join("kept"), "").unwrap();

        std::fs::write(&tmp, "a file").unwrap();
        fresh_tmp(&tmp).unwrap();
        assert!(tmp.symlink_metadata().unwrap().is_dir());

        for target in [dir.path().join("nowhere"), elsewhere.clone()] {
            std::fs::remove_dir(&tmp).unwrap();
            std::os::unix::fs::symlink(&target, &tmp).unwrap();
            fresh_tmp(&tmp).unwrap();
            assert!(tmp.symlink_metadata().unwrap().is_dir());
        }
        assert!(elsewhere.join("kept").exists());
        assert!(!dir.path().join("nowhere").exists());
    }
}
