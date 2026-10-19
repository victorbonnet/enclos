//! Interactive sessions: `enclos connect` (design §8, "Starting a session").

use std::ffi::OsString;
use std::fs::OpenOptions;
use std::io::IsTerminal;
use std::net::{SocketAddr, TcpStream};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

use signal_hook::consts::{SIGHUP, SIGINT, SIGQUIT};

use super::Engine;
use crate::backend::Launch;
use crate::error::{Error, Result};
use crate::layout::LayoutError;
use crate::lifecycle::members::{Found, find};
use crate::lifecycle::process::{PsError, group_of, is_same, processes, reference, reference_of_child};
use crate::lifecycle::stop::{GRACE, stop};
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
    /// The members it left running, or why they could not be listed.
    pub left: std::result::Result<Vec<Found>, PsError>,
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
const END_WAIT: Duration = Duration::from_secs(120);

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
        let target = name.to_string();
        let summary = |(session, ..): &(SessionRecord, _, _)| format!("session {}", session.id);
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
        let (session, mut child, _keep_waiting) =
            self.write(by, audit_name, Some(target.clone()), summary, |lock| {
                let mut record = self.state.get(name)?.ok_or_else(|| Error::NoSuchSandbox {
                    name: name.to_string(),
                })?;
                let compiled = self.compile_policy(name, record.proxy_port)?;
                self.ensure_proxy(lock, &record)?;
                let (version, snapshot) =
                    self.state
                        .active_policy(name)?
                        .ok_or_else(|| Error::NoPolicy {
                            sandbox: name.to_string(),
                        })?;
                let (program, args) = command.split_first().ok_or_else(|| Error::Session {
                    what: "no command to run".into(),
                })?;
                let launch = Launch {
                    program: program.clone(),
                    args: args.to_vec(),
                    env: Vec::new(),
                };
                let ctx = self.sandbox_context(name, record.proxy_port);
                // TMPDIR inside the sandbox (the policy denies /tmp).
                let tmp = ctx.home.join("tmp");
                std::fs::create_dir_all(&tmp)
                    .map_err(|source| LayoutError::Io { path: tmp, source })?;
                let backend = self.backend_of(name)?;
                let mut wrapped = backend.wrap(&compiled, &ctx, &launch);
                if own_group {
                    wrapped.process_group(0);
                }
                let child = wrapped.spawn().map_err(|e| Error::Session {
                    what: format!(
                        "could not start {} in {target}: {e}",
                        launch.program.to_string_lossy()
                    ),
                })?;
                let recorded = (|| -> Result<(SessionRecord, KeepWaiting)> {
                    let mut session = SessionRecord {
                        id: SessionId(0),
                        sandbox: name.clone(),
                        kind: SessionKind::Interactive,
                        version: version.version,
                        snapshot: snapshot.id,
                        compiled: Some(compiled.display().to_string()),
                        // Read even if the program already exited: it is
                        // still a session, with an exit status to report.
                        root: reference_of_child(&child)?,
                        pgid: match (own_group, leads_group) {
                            (true, _) => Some(child.id()),
                            (false, true) => Some(me),
                            (false, false) => None,
                        },
                        tracked: Vec::new(),
                        started_at: now(),
                        ended_at: None,
                    };
                    session.id = self.state.put_session(lock, &session)?;
                    record.state = SandboxState::Running;
                    self.state.put(lock, &record)?;
                    Ok((session, KeepWaiting::new()?))
                })();
                match recorded {
                    Ok((session, keep_waiting)) => Ok((session, child, keep_waiting)),
                    Err(e) => Err(abandon(child, e, "the program")),
                }
            })?;

        let waited = self.wait_session(&session, &mut child)?;
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
        // The end is recorded even while another command holds the lock
        // for long, such as a `sandbox stop` ending other sessions.
        let waiting = Instant::now();
        loop {
            match self.write(
                by,
                "session end",
                Some(format!("{target} session {}", session.id)),
                summary,
                |lock| self.end_or_track(lock, &session, &waited),
            ) {
                Err(Error::State(StateError::Locked { .. })) if waiting.elapsed() < END_WAIT => {}
                done => break done?,
            }
        }
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

    /// Waits for the session's program to exit, recording the members it
    /// starts as they appear (design §8), and returns its exit status and
    /// the members it left running.
    pub(super) fn wait_session(
        &self,
        session: &SessionRecord,
        child: &mut Child,
    ) -> Result<Waited> {
        let lost = |e: std::io::Error| Error::Session {
            what: format!("lost the session's program: {e}"),
        };
        let mut known = session.tracked.clone();
        let mut saved = known.clone();
        let mut notes = Vec::new();
        let mut looked: Option<Instant> = None;
        let status = loop {
            if let Some(status) = child.try_wait().map_err(lost)? {
                break status;
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
        // The program's exit is not the session's end: what it left running
        // keeps the session open, so `show`, `stop` and `rm` still see it.
        let left = processes().map(|procs| find(&procs, session, &known));
        Ok(Waited {
            status,
            left,
            known,
            notes,
        })
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
            Ok(left) if left.is_empty() => self.state.end_session(lock, session.id)?,
            Ok(left) => {
                let sure: Vec<ProcessRef> = left.iter().filter_map(Found::sure_ref).collect();
                self.state.track(lock, session.id, &sure)?;
            }
            Err(_) => self.state.track(lock, session.id, &waited.known)?,
        }
        Ok(())
    }

    /// Stops the sandbox's proxy session, so that a service can take its
    /// port.
    pub(super) fn stop_proxy(&self, lock: &StateLock, name: &SandboxName) -> Result<()> {
        for session in self
            .state
            .sessions(name, true)?
            .into_iter()
            .filter(|s| s.kind == SessionKind::Proxy)
        {
            stop(&session, GRACE);
            self.state.end_session(lock, session.id)?;
        }
        Ok(())
    }

    /// What `connect` would start, without starting anything.
    fn plan_connect(&self, name: &SandboxName, command: &[OsString]) -> Result<Plan> {
        let record = self.state.get(name)?.ok_or_else(|| Error::NoSuchSandbox {
            name: name.to_string(),
        })?;
        let (version, _) = self
            .state
            .active_policy(name)?
            .ok_or_else(|| Error::NoPolicy {
                sandbox: name.to_string(),
            })?;
        let mut changes = Vec::new();
        if !self.proxy_runs(name)? {
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

    /// Starts the sandbox's proxy unless it runs already, and records it as
    /// a session, so that `sandbox stop` ends it too.
    pub(super) fn ensure_proxy(&self, lock: &StateLock, record: &SandboxRecord) -> Result<()> {
        if self.proxy_runs(&record.name)? {
            return Ok(());
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
        let log_path = self
            .layout
            .sandbox_dir(record.name.as_str())
            .join("proxy.log");
        let log = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(&log_path)
            .map_err(|e| failed(format!("cannot open {}: {e}", log_path.display())))?;
        let addr = SocketAddr::from(([127, 0, 0, 1], record.proxy_port));
        // Anything else on this port would receive the sandbox's traffic.
        if TcpStream::connect_timeout(&addr, Duration::from_millis(200)).is_ok() {
            return Err(failed(format!(
                "port {} of sandbox {} is in use by another program; stop it, or recreate the sandbox to get another port",
                record.proxy_port, record.name
            )));
        }
        let child = Command::new(exe)
            .args([
                "proxy",
                "run",
                record.name.as_str(),
                "--listen",
                &addr.to_string(),
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
            let exited = child
                .try_wait()
                .map_err(|e| failed(format!("lost the proxy of sandbox {}: {e}", record.name)))?;
            if let Some(status) = exited {
                return Err(failed(format!(
                    "the proxy of sandbox {} exited ({status}); see {}",
                    record.name,
                    log_path.display()
                )));
            }
            if TcpStream::connect_timeout(&addr, Duration::from_millis(200)).is_ok() {
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
        let (version, snapshot) =
            self.state
                .active_policy(&record.name)?
                .ok_or_else(|| Error::NoPolicy {
                    sandbox: record.name.to_string(),
                })?;
        let session = SessionRecord {
            id: SessionId(0),
            sandbox: record.name.clone(),
            kind: SessionKind::Proxy,
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
fn abandon(mut child: Child, error: Error, what: &str) -> Error {
    match child.kill().and_then(|()| child.wait()) {
        Ok(_) => error,
        Err(e) => Error::CleanupFailed {
            error: Box::new(error),
            left: format!("{what} running as pid {} ({e})", child.id()),
        },
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
