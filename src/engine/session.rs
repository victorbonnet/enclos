//! Interactive sessions: `enclos connect` (design §8, "Starting a session").

use std::ffi::OsString;
use std::fs::OpenOptions;
use std::io::IsTerminal;
use std::net::{SocketAddr, TcpStream};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use super::Engine;
use crate::backend::Launch;
use crate::error::{Error, Result};
use crate::lifecycle::members::{Found, find};
use crate::lifecycle::process::{group_of, is_same, processes, reference};
use crate::model::audit::Actor;
use crate::model::now;
use crate::model::plan::{Confirm, Plan, Planned};
use crate::model::sandbox::{SandboxName, SandboxRecord, SandboxState};
use crate::model::session::{Member, ProcessRef, SessionId, SessionKind, SessionRecord};
use crate::state::StateLock;

/// How a session ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionEnd {
    pub session: SessionId,
    /// The program's exit status; 1 when a signal ended it.
    pub exit: i32,
    /// Processes the program left running in the session's group. While
    /// there are any, the session stays open.
    pub left: Vec<Member>,
}

/// How long the proxy has to start listening.
const PROXY_START: Duration = Duration::from_secs(5);
/// How often a running session's processes are looked at, to record the
/// members it starts.
const WATCH: Duration = Duration::from_millis(500);
/// How often the wait for a session's program checks that it exited.
const EXIT_POLL: Duration = Duration::from_millis(20);

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
        if confirm == Confirm::DryRun {
            return self.plan_connect(name, &command).map(Planned::DryRun);
        }
        let summary = |(session, _): &(SessionRecord, _)| format!("session {}", session.id);
        // Which process group the program starts in (design §8). In a
        // terminal where this command leads its job, the job's group: the
        // program keeps the terminal, and this process, which leads the
        // group, is not a member. Run by something else without a terminal
        // (a script, CI), a group made for the program. Otherwise (a
        // terminal, but not a job of its own) the caller's group, which is
        // not the session's: the session then has no group, only the
        // processes the program starts.
        let me = std::process::id();
        let leads_group = group_of(me) == Some(me);
        let own_group = !leads_group && !std::io::stdin().is_terminal();
        let (session, mut child) =
            self.write(by, "connect", Some(name.to_string()), summary, |lock| {
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

                let (program, args) = match command.split_first() {
                    Some((program, args)) => (program.clone(), args.to_vec()),
                    None => (OsString::from("/bin/zsh"), vec![OsString::from("-l")]),
                };
                let launch = Launch {
                    program,
                    args,
                    env: Vec::new(),
                };
                let ctx = self.sandbox_context(name, record.proxy_port);
                std::fs::create_dir_all(ctx.home.join("tmp")).ok();
                let backend = self.backend_of(name)?;
                let mut wrapped = backend.wrap(&compiled, &ctx, &launch);
                if own_group {
                    wrapped.process_group(0);
                }
                let child = wrapped.spawn().map_err(|e| Error::Session {
                    what: format!(
                        "could not start {} in sandbox {name}: {e}",
                        launch.program.to_string_lossy()
                    ),
                })?;
                let mut session = SessionRecord {
                    id: SessionId(0),
                    sandbox: name.clone(),
                    kind: SessionKind::Interactive,
                    version: version.version,
                    snapshot: snapshot.id,
                    compiled: Some(compiled.display().to_string()),
                    root: reference(child.id()).ok_or_else(|| Error::Session {
                        what: "cannot read the session's start time".into(),
                    })?,
                    pgid: match (own_group, leads_group) {
                        (true, _) => child.id(),
                        (false, true) => me,
                        (false, false) => 0,
                    },
                    tracked: Vec::new(),
                    started_at: now(),
                    ended_at: None,
                };
                session.id = self.state.put_session(lock, &session)?;
                record.state = SandboxState::Running;
                self.state.put(lock, &record)?;
                Ok((session, child))
            })?;

        let (status, left) = self.wait_session(&session, &mut child)?;
        let exit = status.code().unwrap_or(1);
        let summary = |_: &()| match left.len() {
            0 => format!("exit {exit}"),
            n => format!("exit {exit}, {n} processes still running"),
        };
        self.write(
            by,
            "session end",
            Some(format!("{name} session {}", session.id)),
            summary,
            |lock| self.end_or_track(lock, &session, &left),
        )?;
        Ok(Planned::Done(SessionEnd {
            session: session.id,
            exit,
            left: left.into_iter().map(|f| f.member).collect(),
        }))
    }

    /// Waits for the session's program to exit, recording the members it
    /// starts as they appear (design §8), and returns its exit status and
    /// the members it left running.
    pub(super) fn wait_session(
        &self,
        session: &SessionRecord,
        child: &mut Child,
    ) -> Result<(ExitStatus, Vec<Found>)> {
        let lost = |e: std::io::Error| Error::Session {
            what: format!("lost the session's program: {e}"),
        };
        let mut known = session.tracked.clone();
        let mut saved = known.clone();
        let mut looked: Option<Instant> = None;
        let status = loop {
            if let Some(status) = child.try_wait().map_err(lost)? {
                break status;
            }
            if looked.is_none_or(|at| at.elapsed() >= WATCH) {
                looked = Some(Instant::now());
                known = find(&processes(), session, &known)
                    .iter()
                    .filter(|f| f.sure)
                    .map(Found::process)
                    .collect();
                // Recorded for `show`, `stop` and `rm`; a busy lock only
                // delays it to a later look.
                if known != saved
                    && let Ok(lock) = self.state.lock()
                    && self.state.track(&lock, session.id, &known).is_ok()
                {
                    saved = known.clone();
                }
            }
            std::thread::sleep(EXIT_POLL);
        };
        // The program's exit is not the session's end: what it left running
        // keeps the session open, so `show`, `stop` and `rm` still see it.
        Ok((status, find(&processes(), session, &known)))
    }

    /// Ends the session, or, while it left members running, records them.
    pub(super) fn end_or_track(
        &self,
        lock: &StateLock,
        session: &SessionRecord,
        left: &[Found],
    ) -> Result<()> {
        if left.is_empty() {
            self.state.end_session(lock, session.id)?;
        } else {
            let sure: Vec<ProcessRef> =
                left.iter().filter(|f| f.sure).map(Found::process).collect();
            self.state.track(lock, session.id, &sure)?;
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
        let shown = match command {
            [] => "/bin/zsh -l".to_owned(),
            words => words
                .iter()
                .map(|w| w.to_string_lossy())
                .collect::<Vec<_>>()
                .join(" "),
        };
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
    fn proxy_runs(&self, name: &SandboxName) -> Result<bool> {
        Ok(self
            .state
            .sessions(name, true)?
            .into_iter()
            .any(|s| s.kind == SessionKind::Proxy && is_same(&s.root)))
    }

    /// Starts the sandbox's proxy unless it runs already, and records it as
    /// a session, so that `sandbox stop` ends it too.
    fn ensure_proxy(&self, lock: &StateLock, record: &SandboxRecord) -> Result<()> {
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
        let mut child = Command::new(exe)
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
        let pid = child.id();
        let start = Instant::now();
        loop {
            // Listening is not enough: it must be this proxy, still running.
            if let Ok(Some(status)) = child.try_wait() {
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
            root: reference(pid).ok_or_else(|| failed("the proxy exited at once".into()))?,
            pgid: pid,
            tracked: Vec::new(),
            started_at: now(),
            ended_at: None,
        };
        self.state.put_session(lock, &session)?;
        Ok(())
    }
}
