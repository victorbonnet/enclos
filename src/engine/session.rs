//! Interactive sessions: `enclos connect` (design §8, "Starting a session").

use std::ffi::OsString;
use std::fs::OpenOptions;
use std::io::IsTerminal;
use std::net::{Ipv6Addr, SocketAddr, TcpStream};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use signal_hook::consts::{SIGHUP, SIGINT, SIGQUIT};

use super::Engine;
use super::listener::ConnectStep;
use super::service::{PROXY_WAIT, STOP_GRACE};
use crate::backend::Launch;
use crate::error::{Error, Result};
use crate::layout::LayoutError;
use crate::lifecycle::marker::{self, Marker};
use crate::lifecycle::members::{Found, find};
use crate::lifecycle::process::{Proc, group_of, is_same, processes, reference_of_child};
use crate::lifecycle::stop::{GRACE, Stopped, describe_survivors, stop};
use crate::model::audit::Actor;
use crate::model::now;
use crate::model::plan::{Confirm, Plan, Planned};
use crate::model::sandbox::{SandboxName, SandboxRecord, SandboxState};
use crate::model::session::{Member, ProcessRef, SessionId, SessionKind, SessionRecord};
use crate::runtime::SandboxCommand;
use crate::state::{StateError, StateLock};

/// How a session ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionEnd {
    pub session: SessionId,
    /// The program's exit status, or, as a shell reports it, 128 plus the
    /// signal that ended it.
    pub exit: i32,
    /// The signal that ended the program, if one did.
    pub signal: Option<i32>,
    pub left: Left,
    /// Problems met while recording the session's members, each said once.
    pub notes: Vec<String>,
}

/// What the program left running when it exited.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Left {
    /// Nothing: the session ended.
    Nothing,
    /// Members that still run. The session stays open, so `show` lists them
    /// and `rm` refuses, until `enclos sandbox stop` finds them gone.
    Running(Vec<Member>),
    /// enclos could not look, with why. The session stays open, as above.
    Unknown(String),
}

/// A session's program, waited for.
pub(super) struct Waited {
    pub status: ExitStatus,
    /// The members it left running, or why they could not be listed (its
    /// processes, or who holds its marker).
    pub left: Result<Vec<Found>>,
    /// The sure members last seen, recorded when `left` could not be listed.
    pub known: Vec<ProcessRef>,
    pub notes: Vec<String>,
}

/// How long the proxy has to start listening.
const PROXY_START: Duration = Duration::from_secs(5);
/// How often a running session's processes are looked at, to record the
/// members it starts.
const WATCH: Duration = Duration::from_millis(500);
/// How often the wait for a session's program checks that it exited.
const EXIT_POLL: Duration = Duration::from_millis(20);
/// How long the session's end waits for other commands holding the state
/// lock, such as a `sandbox stop` ending other sessions one by one.
pub(super) const END_WAIT: Duration = Duration::from_secs(120);

impl Engine {
    /// Runs `command` (a login shell by default) in the sandbox, in this
    /// terminal, and returns when it exits.
    pub fn connect(
        &self,
        by: &Actor,
        name: &SandboxName,
        command: Vec<OsString>,
        confirm: Confirm,
    ) -> Result<Planned<SessionEnd>> {
        let command = if command.is_empty() {
            vec![OsString::from("/bin/zsh"), OsString::from("-l")]
        } else {
            command
        };
        if confirm == Confirm::DryRun {
            return self.plan_connect(name, &command).map(Planned::DryRun);
        }
        self.run_in_sandbox(by, name, SandboxCommand::new(command), "connect")
            .map(Planned::Done)
    }

    /// Runs `command` in the sandbox, in this terminal, as a recorded
    /// session (design §8 steps 1-6), and returns when it exits.
    pub(super) fn run_in_sandbox(
        &self,
        by: &Actor,
        name: &SandboxName,
        command: SandboxCommand,
        audit_name: &str,
    ) -> Result<SessionEnd> {
        let command = command.into_words();
        let summary = |(session, ..): &(SessionRecord, _, _, _)| format!("session {}", session.id);
        // Which process group the program starts in (design §8). When this
        // command leads its group, as a terminal's job does, that group:
        // the program keeps the terminal, and this process, which leads the
        // group, is not a member. Run by something else without a terminal
        // (a script, CI), a group made for the program. Otherwise (a
        // terminal, but not a job of its own) the caller's group, which is
        // not the session's: the session then has no group, only the
        // processes the program starts.
        let me = std::process::id();
        let leads_group = group_of(me)? == Some(me);
        let own_group = !leads_group && !std::io::stdin().is_terminal();
        self.wait_service_proxy(name)?;
        let (session, mut child, _keep_waiting, unreachable) =
            self.write(by, audit_name, Some(name.to_string()), summary, |lock| {
                let started = self.start_in_sandbox(lock, name, &command, own_group, leads_group);
                self.failed_on_error(lock, name, audit_name, started)
            })?;

        let waited = self.wait_session(&session, &mut child, None)?;
        let mut end = self.finish_session(by, "session end", &session, waited)?;
        // Why the session could not reach its runtime's service (ADR 0028),
        // which explains a runtime's own "connection failed".
        end.notes.extend(unreachable);
        Ok(end)
    }

    /// Starts `command` in the sandbox and records it as a session (design
    /// §8 steps 2-4), under the state lock.
    fn start_in_sandbox(
        &self,
        lock: &StateLock,
        name: &SandboxName,
        command: &[OsString],
        own_group: bool,
        leads_group: bool,
    ) -> Result<(SessionRecord, Child, KeepWaiting, Option<String>)> {
        let mut record = self.state.get(name)?.ok_or_else(|| Error::NoSuchSandbox {
            name: name.to_string(),
        })?;
        let compiled = self.compile_policy(name, record.proxy_port)?;
        self.ensure_proxy(lock, &record)?;
        let (version, snapshot) = self.active_policy(name)?;
        let (program, args) = command.split_first().ok_or_else(|| Error::Session {
            what: "no command to run".into(),
        })?;
        // The runtime's clients reach its service on the port it holds now
        // (ADR 0028), or the session says why it cannot.
        let (service_port, unreachable) = match self.service_port(&record) {
            Ok(port) => (port, None),
            Err(why) => (None, Some(why)),
        };
        let launch = Launch {
            program: program.clone(),
            args: args.to_vec(),
            env: Vec::new(),
            in_terminal: true,
            service_port,
        };
        let ctx = self.sandbox_context(name, record.proxy_port);
        // TMPDIR inside the sandbox (the policy denies /tmp).
        let tmp = ctx.home.join("tmp");
        std::fs::create_dir_all(&tmp).map_err(|source| LayoutError::Io { path: tmp, source })?;
        let backend = self.backend_of(name)?;
        let mut wrapped = backend.wrap(&compiled, &ctx, &launch);
        if own_group {
            wrapped.process_group(0);
        }
        let marker = self.new_marker(name)?;
        let (child, marked) = marker.spawn(&mut wrapped).map_err(|e| Error::Session {
            what: format!(
                "could not start {} in {name}: {e}",
                launch.program.to_string_lossy()
            ),
        })?;
        let recorded = (|| -> Result<(SessionRecord, KeepWaiting)> {
            // Before the session is recorded, so that a failure here leaves
            // no session open for a program that is ended.
            let keep_waiting = KeepWaiting::new()?;
            let root = reference_of_child(&child)?;
            self.name_marker(name, marked, &root)?;
            let me = std::process::id();
            let mut session = SessionRecord {
                id: SessionId(0),
                sandbox: name.clone(),
                kind: SessionKind::Interactive,
                service: None,
                version: version.version,
                snapshot: snapshot.id,
                compiled: Some(compiled.display().to_string()),
                // Read even if the program already exited: it is still a
                // session, with an exit status to report.
                root,
                pgid: match (own_group, leads_group) {
                    (true, _) => Some(child.id()),
                    (false, true) => Some(me),
                    (false, false) => None,
                },
                tracked: Vec::new(),
                started_at: now(),
                ended_at: None,
            };
            record.state = SandboxState::Running;
            session.id = self.state.start_session(lock, &session, &record)?;
            Ok((session, keep_waiting))
        })();
        match recorded {
            Ok((session, keep_waiting)) => Ok((session, child, keep_waiting, unreachable)),
            Err(e) => Err(abandon(child, e, "the program")),
        }
    }

    /// Saves `Failed { reason: "<what> failed: …" }` on the sandbox when
    /// `done`, the work of the audited command `what`, failed (design §8
    /// step 7): in the same write, whose audit entry then closes as failed.
    /// The program the work started and could not record, it ended already;
    /// a proxy it started stays recorded and running, as after a `connect`
    /// that succeeds, for `sandbox stop` to end.
    pub(super) fn failed_on_error<T>(
        &self,
        lock: &StateLock,
        name: &SandboxName,
        what: &str,
        done: Result<T>,
    ) -> Result<T> {
        let error = match done {
            Ok(value) => return Ok(value),
            Err(error) => error,
        };
        let marked = self.state.get(name).and_then(|record| match record {
            // No record, no state to mark: the sandbox does not exist.
            None => Ok(()),
            Some(mut record) => {
                record.state = SandboxState::Failed {
                    reason: format!("{what} failed: {error}"),
                };
                self.state.put(lock, &record)
            }
        });
        Err(match marked {
            Ok(()) => error,
            Err(e) => Error::CleanupFailed {
                error: Box::new(error),
                left: format!("sandbox {name} not marked failed ({e})"),
            },
        })
    }

    /// Records how a session's program ended (design §8 step 6), as
    /// `audit_name`: the session ends, or stays open while it left members.
    pub(super) fn finish_session(
        &self,
        by: &Actor,
        audit_name: &str,
        session: &SessionRecord,
        waited: Waited,
    ) -> Result<SessionEnd> {
        let signal = waited.status.signal();
        let exit = waited
            .status
            .code()
            .unwrap_or_else(|| 128 + signal.unwrap_or(0));
        let summary = |_: &()| match &waited.left {
            Ok(left) if left.is_empty() => format!("exit {exit}"),
            Ok(left) => format!("exit {exit}, {} processes still running", left.len()),
            Err(_) => format!("exit {exit}, could not look at what it left running"),
        };
        self.write_session_end(by, audit_name, session, summary, |lock| {
            self.end_or_track(lock, session, &waited)
        })?;
        let left = match waited.left {
            Ok(left) if left.is_empty() => Left::Nothing,
            Ok(left) => Left::Running(left.into_iter().map(|f| f.member).collect()),
            Err(e) => Left::Unknown(e.to_string()),
        };
        Ok(SessionEnd {
            session: session.id,
            exit,
            signal,
            left,
            notes: waited.notes,
        })
    }

    /// Records, as `audit_name`, a failed end for a session whose program
    /// `wait_session` did not see exit: one that survived TERM and KILL, or
    /// one enclos could not stop, as `error` says. The session stays open,
    /// so `sandbox show` lists it, and `sandbox stop` or the service's next
    /// `launch` tries again. Returns the entry's error, or `CleanupFailed`
    /// around `error` when the entry could not be written.
    pub(super) fn record_unended(
        &self,
        by: &Actor,
        audit_name: &str,
        session: &SessionRecord,
        error: Error,
    ) -> Error {
        let why = format!(
            "{error}; session {} stays open, and `enclos sandbox show {}` lists what still runs",
            session.id, session.sandbox
        );
        let opened = std::cell::Cell::new(false);
        let recorded = self.write_session_end(
            by,
            audit_name,
            session,
            // Never called: the work always fails.
            |_: &()| String::new(),
            |_| {
                opened.set(true);
                Err(Error::Session { what: why.clone() })
            },
        );
        match recorded {
            Err(unrecorded) if !opened.get() => Error::CleanupFailed {
                error: Box::new(error),
                left: format!("the session's end unrecorded ({unrecorded})"),
            },
            _ => Error::Session { what: why },
        }
    }

    /// `write` for a session's end, as `audit_name`. It waits even while
    /// another command holds the lock for long, such as a `sandbox stop`
    /// ending other sessions one by one, up to `END_WAIT`.
    fn write_session_end<T>(
        &self,
        by: &Actor,
        audit_name: &str,
        session: &SessionRecord,
        summary: impl Fn(&T) -> String,
        work: impl Fn(&StateLock) -> Result<T>,
    ) -> Result<T> {
        let waiting = Instant::now();
        loop {
            match self.write(
                by,
                audit_name,
                Some(format!("{} session {}", session.sandbox, session.id)),
                &summary,
                &work,
            ) {
                Err(Error::State(StateError::Locked { .. })) if waiting.elapsed() < END_WAIT => {}
                done => break done,
            }
        }
    }

    /// Waits for the session's program to exit, recording the members it
    /// starts as they appear (design §8), and returns its exit status and
    /// the members it left running. Once `ended` is set, it stops every
    /// member, TERM then KILL after `STOP_GRACE` each, as `sandbox stop`
    /// does with `GRACE`; a program that survives both is an error.
    pub(super) fn wait_session(
        &self,
        session: &SessionRecord,
        child: &mut Child,
        ended: Option<&AtomicBool>,
    ) -> Result<Waited> {
        let lost = |e: std::io::Error| Error::Session {
            what: format!("lost the session's program: {e}"),
        };
        let mut known = session.tracked.clone();
        let mut saved = known.clone();
        let mut notes = Vec::new();
        let mut looked: Option<Instant> = None;
        let mut stopping = None;
        let status = loop {
            if let Some(status) = child.try_wait().map_err(lost)? {
                break status;
            }
            if stopping.is_none() && ended.is_some_and(|e| e.load(Ordering::Relaxed)) {
                // On another thread, so this one reaps the program as it
                // exits: a program not reaped would still be listed.
                let mut members = session.clone();
                members.tracked = known.clone();
                let stop_members = self.stop_members;
                stopping = Some(std::thread::spawn(move || {
                    stop_members(&members, STOP_GRACE)
                }));
            }
            if stopping
                .as_ref()
                .is_some_and(std::thread::JoinHandle::is_finished)
            {
                // Done signalling, and the program had not exited: it
                // survived TERM and KILL, or enclos could not stop it, so
                // waiting more would not end.
                let failed = match stopping.take().map(std::thread::JoinHandle::join) {
                    Some(Ok(Ok(Stopped::Clean | Stopped::Gone))) | None => None,
                    Some(Ok(Ok(Stopped::Survivors(left)))) => Some(format!(
                        "the program of session {} survived TERM and KILL ({})",
                        session.id,
                        describe_survivors(&left)
                    )),
                    Some(Ok(Err(e))) => Some(format!(
                        "could not stop the members of session {}: {e}",
                        session.id
                    )),
                    Some(Err(_)) => Some(format!(
                        "stopping the members of session {} failed",
                        session.id
                    )),
                };
                if let Some(what) = failed {
                    // Unless it exited since the last look.
                    if let Some(status) = child.try_wait().map_err(lost)? {
                        break status;
                    }
                    return Err(Error::Session { what });
                }
            }
            if looked.is_none_or(|at| at.elapsed() >= WATCH) {
                looked = Some(Instant::now());
                match processes() {
                    Ok(procs) => {
                        known = find(&procs, session, &known)
                            .iter()
                            .filter_map(Found::sure_ref)
                            .collect();
                    }
                    Err(e) => note(&mut notes, format!("could not look at its processes: {e}")),
                }
                // Recorded for `show`, `stop` and `rm`. This never waits for
                // the lock: while another command holds it, a later look
                // records them, and the program's exit is still seen at once.
                if known != saved {
                    let tracked = self.state.try_lock().and_then(|lock| match lock {
                        Some(lock) => self.state.track(&lock, session.id, &known).map(Some),
                        None => Ok(None),
                    });
                    match tracked {
                        Ok(Some(())) => saved = known.clone(),
                        Ok(None) => {}
                        Err(e) => note(&mut notes, format!("could not record its members: {e}")),
                    }
                }
            }
            std::thread::sleep(EXIT_POLL);
        };
        // The program exited while its members were being stopped: what
        // survived is listed below, as `left`.
        match stopping.map(std::thread::JoinHandle::join) {
            None | Some(Ok(Ok(_))) => {}
            Some(Ok(Err(e))) => note(&mut notes, format!("could not stop its members: {e}")),
            Some(Err(_)) => note(&mut notes, "stopping its members failed".to_owned()),
        }
        // The program's exit is not the session's end: what it left running
        // keeps the session open, so `show`, `stop` and `rm` still see it,
        // what holds its marker included (ADR 0030).
        let left = (|| -> Result<Vec<Found>> {
            let procs = processes()?;
            // After the listing (see `Engine::marked`). Without the marker,
            // what is left cannot be told, so the session stays open.
            let held = self.held(&session.sandbox)?;
            known = marked_in(session, &known, &procs, &held);
            Ok(find(&procs, session, &known))
        })();
        Ok(Waited {
            status,
            left,
            known,
            notes,
        })
    }

    /// Stops what the session's program left running, TERM then KILL, and
    /// looks again at what is left.
    pub(super) fn stop_left(&self, session: &SessionRecord, waited: &mut Waited) {
        let sure: Vec<ProcessRef> = match &waited.left {
            Ok(left) if !left.is_empty() => left.iter().filter_map(Found::sure_ref).collect(),
            _ => return,
        };
        let mut members = session.clone();
        members.tracked = waited.known.clone();
        members.tracked.extend(sure);
        if let Err(e) = stop(&members, STOP_GRACE) {
            note(
                &mut waited.notes,
                format!("could not stop what it left running: {e}"),
            );
        }
        waited.left = processes()
            .map(|procs| find(&procs, session, &waited.known))
            .map_err(Error::from);
    }

    /// Ends the session, or, while it left members running or enclos could
    /// not look, records the members last seen.
    pub(super) fn end_or_track(
        &self,
        lock: &StateLock,
        session: &SessionRecord,
        waited: &Waited,
    ) -> Result<()> {
        match &waited.left {
            Ok(left) if left.is_empty() => {
                self.state.end_session(lock, session.id)?;
                self.forget_marker(session);
            }
            Ok(left) => {
                let sure: Vec<ProcessRef> = left.iter().filter_map(Found::sure_ref).collect();
                self.state.track(lock, session.id, &sure)?;
            }
            Err(_) => self.state.track(lock, session.id, &waited.known)?,
        }
        Ok(())
    }

    /// Stops the sandbox's open sessions that `which` selects, so that
    /// something new can take their place, and ends each as it stops,
    /// adding it to `ended`. A member that survives refuses: its session
    /// stays open, and the error names each survivor, then `refused`, which
    /// says what was not done and what to do once they are ended.
    pub(super) fn stop_sessions(
        &self,
        lock: &StateLock,
        name: &SandboxName,
        which: impl Fn(&SessionRecord) -> bool,
        refused: &str,
        ended: &mut Vec<SessionId>,
    ) -> Result<()> {
        for session in self.state.sessions(name, true)?.into_iter().filter(&which) {
            let label = match &session.service {
                Some(service) => format!("the {service} service session {}", session.id),
                None => format!("the {} session {}", session.kind.as_str(), session.id),
            };
            let stopped = self
                .stop_marked(&session, GRACE, self.stop_members)
                .map_err(|e| Error::Session {
                    what: format!("could not stop {label} of sandbox {name}: {e}"),
                })?;
            match stopped {
                Stopped::Clean | Stopped::Gone => {
                    self.state.end_session(lock, session.id)?;
                    self.forget_marker(&session);
                    ended.push(session.id);
                }
                Stopped::Survivors(left) => {
                    return Err(Error::Session {
                        what: format!(
                            "{label} of sandbox {name} did not stop ({}), so {refused}",
                            describe_survivors(&left)
                        ),
                    });
                }
            }
        }
        Ok(())
    }

    /// The folder of the sandbox's markers (ADR 0030).
    pub(super) fn markers(&self, name: &SandboxName) -> std::path::PathBuf {
        self.layout.sandbox_dir(name.as_str()).join("members")
    }

    /// A new marker for a program about to start in sandbox `name`.
    pub(super) fn new_marker(&self, name: &SandboxName) -> Result<Marker> {
        let dir = self.markers(name);
        Marker::new(&dir).map_err(|source| LayoutError::Io { path: dir, source }.into())
    }

    /// Names a started program's marker after its session's `root`, before
    /// the session is recorded.
    pub(super) fn name_marker(
        &self,
        name: &SandboxName,
        marked: marker::Started,
        root: &ProcessRef,
    ) -> Result<()> {
        marked.name(root).map_err(|source| {
            LayoutError::Io {
                path: self.markers(name),
                source,
            }
            .into()
        })
    }

    /// Removes an ended session's marker, once a fresh look shows nothing
    /// holds it: removed, a marker a member still holds would hide that
    /// member for good. One left behind is an empty file, which a later
    /// session cannot take for its own (its name has the root's start time).
    pub(super) fn forget_marker(&self, session: &SessionRecord) {
        let dir = self.markers(&session.sandbox);
        if let Ok(held) = marker::holders(&dir)
            && !held.contains_key(&marker::name_of(&session.root))
        {
            let _ = marker::remove(&dir, &session.root);
        }
    }

    /// The processes holding each marker of sandbox `name`, by marker.
    pub(super) fn held(&self, name: &SandboxName) -> Result<Held> {
        Ok(marker::holders(&self.markers(name))?)
    }

    /// `session`, with the processes holding its marker added to those it
    /// tracked (ADR 0030). The processes are listed before `lsof` looks: a
    /// holder that exits in between, its pid reused, is then listed with
    /// its own start time and fails the same-process check before a signal,
    /// where the other order would name the process that reused the pid.
    pub(super) fn marked(&self, session: &SessionRecord) -> Result<SessionRecord> {
        let procs = processes()?;
        let held = self.held(&session.sandbox)?;
        let mut marked = session.clone();
        marked.tracked = marked_in(session, &session.tracked, &procs, &held);
        Ok(marked)
    }

    /// Stops `session`'s members, with what holds its marker (ADR 0030),
    /// then looks at the marker again: a process that gained it meanwhile,
    /// such as one a member detached during the grace period, is stopped
    /// too, and one that survives is a survivor, so the session stays open.
    pub(super) fn stop_marked(
        &self,
        session: &SessionRecord,
        grace: Duration,
        stop: super::StopMembers,
    ) -> Result<Stopped> {
        let first = stop(&self.marked(session)?, grace)?;
        if matches!(first, Stopped::Survivors(_)) {
            return Ok(first);
        }
        let again = self.marked(session)?;
        if again.tracked.len() == session.tracked.len() {
            return Ok(first);
        }
        Ok(match stop(&again, grace)? {
            Stopped::Gone => first,
            other => other,
        })
    }

    /// What `connect` would start, without starting anything.
    fn plan_connect(&self, name: &SandboxName, command: &[OsString]) -> Result<Plan> {
        let record = self.state.get(name)?.ok_or_else(|| Error::NoSuchSandbox {
            name: name.to_string(),
        })?;
        let (version, _) = self.active_policy(name)?;
        let mut changes = Vec::new();
        let mut starts_services = false;
        if let Some((listener, step)) = self.connect_step(&record)? {
            let service = listener.service.as_str();
            match step {
                ConnectStep::Nothing => {}
                ConnectStep::Unreadable(why) => changes.push(format!(
                    "leave the {service} of sandbox {name} as it is, since {why}"
                )),
                ConnectStep::Wait => changes.push(format!(
                    "wait for the {service} of sandbox {name} to listen"
                )),
                ConnectStep::Start => {
                    starts_services = true;
                    changes.push(format!(
                        "start the services of sandbox {name}, since its runtime's clients need its {service} (ADR 0028); they start again at each login until `enclos sandbox stop {name}`"
                    ));
                    if self.proxy_runs(name)? {
                        changes.push(format!(
                            "start the running proxy of sandbox {name} again as a service, which cuts the connections of its open sessions"
                        ));
                    }
                    changes.push(format!("wait for the {service} to listen"));
                }
            }
        }
        // With services installed, or about to be, the proxy is theirs to
        // start.
        if !starts_services && !self.has_services(name)? && !self.proxy_runs(name)? {
            changes.push(format!(
                "start the proxy of sandbox {name} on port {}",
                record.proxy_port
            ));
        }
        let shown = command
            .iter()
            .map(|w| w.to_string_lossy())
            .collect::<Vec<_>>()
            .join(" ");
        changes.push(format!(
            "run `{shown}` in sandbox {name} under policy v{}",
            version.version
        ));
        Ok(Plan {
            changes,
            ..Plan::default()
        })
    }

    /// Whether the sandbox's recorded proxy still runs.
    pub(super) fn proxy_runs(&self, name: &SandboxName) -> Result<bool> {
        for s in self.state.sessions(name, true)? {
            if s.kind == SessionKind::Proxy && is_same(&s.root)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Gives the sandbox's proxy service, when one is installed, time to
    /// record itself: a proxy this command would start instead would take
    /// its port, and the service would fail at every restart. Outside the
    /// lock, which the service needs to record itself.
    pub(super) fn wait_service_proxy(&self, name: &SandboxName) -> Result<()> {
        if self.has_services(name)? {
            self.proxy_started(name, PROXY_WAIT)?;
        }
        Ok(())
    }

    /// Starts the sandbox's proxy unless it runs already, and records it as
    /// a session, so that `sandbox stop` ends it too.
    pub(super) fn ensure_proxy(&self, lock: &StateLock, record: &SandboxRecord) -> Result<()> {
        if self.proxy_runs(&record.name)? {
            return Ok(());
        }
        // With services installed, the proxy is the service's to start.
        if self.has_services(&record.name)? {
            return Err(Error::Session {
                what: format!(
                    "the proxy service of sandbox {} has not started; see `enclos logs {}`, or run `enclos sandbox stop {}`, then connect again, to run it without services",
                    record.name, record.name, record.name
                ),
            });
        }
        // A recorded proxy that exited, or was killed, is replaced: its
        // session ends here.
        for dead in self
            .state
            .sessions(&record.name, true)?
            .into_iter()
            .filter(|s| s.kind == SessionKind::Proxy)
        {
            self.state.end_session(lock, dead.id)?;
        }
        let failed = |what: String| Error::Session { what };
        let exe = self
            .exe
            .clone()
            .ok_or_else(|| failed("cannot find the enclos program to start the proxy".into()))?;
        let log_path = self.proxy_log(&record.name);
        if let Some(dir) = log_path.parent() {
            std::fs::create_dir_all(dir)
                .map_err(|e| failed(format!("cannot create {}: {e}", dir.display())))?;
        }
        let log = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(&log_path)
            .map_err(|e| failed(format!("cannot open {}: {e}", log_path.display())))?;
        let addr = SocketAddr::from(([127, 0, 0, 1], record.proxy_port));
        // Anything else on this port, on either loopback, would receive the
        // sandbox's traffic.
        let v6 = SocketAddr::from((Ipv6Addr::LOCALHOST, record.proxy_port));
        if let Some(taken) = [addr, v6]
            .into_iter()
            .find(|a| TcpStream::connect_timeout(a, Duration::from_millis(200)).is_ok())
        {
            return Err(Error::proxy_port_taken(record.name.as_str(), taken));
        }
        let child = Command::new(exe)
            .args([
                "proxy",
                "run",
                record.name.as_str(),
                "--port",
                &record.proxy_port.to_string(),
            ])
            .process_group(0)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(log)
            .spawn()
            .map_err(|e| failed(format!("could not start the proxy: {e}")))?;
        let mut child = child;
        match self.record_started_proxy(lock, record, &mut child, addr, &log_path) {
            Ok(()) => Ok(()),
            Err(e) => Err(abandon(child, e, "the proxy")),
        }
    }

    /// Waits for the proxy this command started to listen, and records it.
    fn record_started_proxy(
        &self,
        lock: &StateLock,
        record: &SandboxRecord,
        child: &mut Child,
        addr: SocketAddr,
        log_path: &std::path::Path,
    ) -> Result<()> {
        let failed = |what: String| Error::Session { what };
        let start = Instant::now();
        loop {
            // Listening is not enough: it must be this proxy, still running.
            let exited = |child: &mut Child| -> Result<()> {
                let status = child.try_wait().map_err(|e| {
                    failed(format!("lost the proxy of sandbox {}: {e}", record.name))
                })?;
                match status {
                    None => Ok(()),
                    Some(status) => Err(failed(format!(
                        "the proxy of sandbox {} exited ({status}): {}; see {}",
                        record.name,
                        last_log_line(log_path),
                        log_path.display()
                    ))),
                }
            };
            exited(child)?;
            // It binds 127.0.0.1 after `[::1]`, so once 127.0.0.1 answers and
            // the proxy is still running, it holds the port on every loopback
            // it could. The answer itself could come from another program
            // that took 127.0.0.1 just before the proxy did; the proxy then
            // exits, which the second look usually catches.
            if TcpStream::connect_timeout(&addr, Duration::from_millis(200)).is_ok() {
                std::thread::sleep(Duration::from_millis(50));
                exited(child)?;
                break;
            }
            if start.elapsed() > PROXY_START {
                return Err(failed(format!(
                    "the proxy of sandbox {} did not start listening on {addr}; see {}",
                    record.name,
                    log_path.display()
                )));
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let (version, snapshot) = self.active_policy(&record.name)?;
        let session = SessionRecord {
            id: SessionId(0),
            sandbox: record.name.clone(),
            kind: SessionKind::Proxy,
            service: None,
            version: version.version,
            snapshot: snapshot.id,
            compiled: None,
            root: reference_of_child(child)?,
            pgid: Some(child.id()),
            tracked: Vec::new(),
            started_at: now(),
            ended_at: None,
        };
        self.state.put_session(lock, &session)?;
        Ok(())
    }
}

/// Ends `child`, which this command started but could not record, so that
/// it does not run where no `stop` finds it; `error` stays the reason.
pub(super) fn abandon(mut child: Child, error: Error, what: &str) -> Error {
    match child.kill().and_then(|()| child.wait()) {
        Ok(_) => error,
        Err(e) => Error::CleanupFailed {
            error: Box::new(error),
            left: format!("{what} running as pid {} ({e})", child.id()),
        },
    }
}

/// The last line the proxy wrote to its log, which says why it exited: at
/// most its last 4 KiB are read.
fn last_log_line(path: &std::path::Path) -> String {
    use std::io::{Read, Seek, SeekFrom};
    let tail = || -> std::io::Result<String> {
        let mut file = std::fs::File::open(path)?;
        let len = file.metadata()?.len();
        file.seek(SeekFrom::Start(len.saturating_sub(4096)))?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    };
    match tail() {
        Ok(text) => match text.lines().rev().find(|l| !l.trim().is_empty()) {
            Some(line) => line.trim().to_owned(),
            None => "it wrote nothing to its log".to_owned(),
        },
        Err(e) => format!("cannot read its log: {e}"),
    }
}

fn note(notes: &mut Vec<String>, note: String) {
    if !notes.contains(&note) {
        notes.push(note);
    }
}

/// Keeps this process waiting for the program through Ctrl-C, Ctrl-\ and a
/// hangup, as `system(3)` does. In a terminal they reach this process along
/// with the program, which may handle them and go on; this process must
/// outlive it to record the session's end. The program itself was started
/// before, with the default handling, and keeps it.
struct KeepWaiting(Vec<signal_hook::SigId>);

impl KeepWaiting {
    fn new() -> Result<Self> {
        let mut ids = Vec::new();
        for signal in [SIGINT, SIGQUIT, SIGHUP] {
            let id = signal_hook::flag::register(signal, Arc::new(AtomicBool::new(false)))
                .map_err(|e| Error::Session {
                    what: format!("cannot keep waiting through signal {signal}: {e}"),
                })?;
            ids.push(id);
        }
        Ok(KeepWaiting(ids))
    }
}

impl Drop for KeepWaiting {
    fn drop(&mut self) {
        for id in self.0.drain(..) {
            signal_hook::low_level::unregister(id);
        }
    }
}

/// The processes holding each marker of a sandbox, by marker file name.
pub(super) type Held = std::collections::BTreeMap<String, std::collections::BTreeSet<u32>>;

/// `tracked`, with the processes in `procs` that hold `session`'s marker
/// (ADR 0030).
pub(super) fn marked_in(
    session: &SessionRecord,
    tracked: &[ProcessRef],
    procs: &[Proc],
    held: &Held,
) -> Vec<ProcessRef> {
    let mut tracked = tracked.to_vec();
    if let Some(pids) = held.get(&marker::name_of(&session.root)) {
        for p in procs.iter().filter(|p| pids.contains(&p.pid)) {
            let holder = ProcessRef {
                pid: p.pid,
                started: p.started.clone(),
            };
            if !tracked.contains(&holder) {
                tracked.push(holder);
            }
        }
    }
    tracked
}
