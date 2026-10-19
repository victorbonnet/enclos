//! Interactive sessions: `enclos connect` (design §8, "Starting a session").

use std::ffi::OsString;
use std::fs::OpenOptions;
use std::io::IsTerminal;
use std::net::{SocketAddr, TcpStream};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use super::Engine;
use crate::backend::Launch;
use crate::error::{Error, Result};
use crate::lifecycle::process::{group_members, group_of, is_same, reference};
use crate::model::audit::Actor;
use crate::model::now;
use crate::model::sandbox::{SandboxName, SandboxRecord, SandboxState};
use crate::model::session::{Member, SessionId, SessionKind, SessionRecord};
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

impl Engine {
    /// Runs `command` (a login shell by default) in the sandbox, in this
    /// terminal, and returns when it exits.
    pub fn connect(
        &self,
        by: &Actor,
        name: &SandboxName,
        command: Vec<OsString>,
    ) -> Result<SessionEnd> {
        let command = if command.is_empty() {
            vec![OsString::from("/bin/zsh"), OsString::from("-l")]
        } else {
            command
        };
        self.run_in_sandbox(by, name, command, "connect")
    }

    /// Runs `command` in the sandbox, in this terminal, as a recorded
    /// session (design §8 steps 1-6), and returns when it exits.
    pub(super) fn run_in_sandbox(
        &self,
        by: &Actor,
        name: &SandboxName,
        command: Vec<OsString>,
        audit_name: &str,
    ) -> Result<SessionEnd> {
        let target = name.to_string();
        let summary = |(id, _, _): &(SessionId, _, _)| format!("session {id}");
        // Which process group is the session's (design §8). In a terminal
        // where this command leads its job, the job's group: the program
        // keeps the terminal. Run by something else without a terminal (a
        // script, CI), a new group for the program, so the session's group
        // holds only its processes. Otherwise (a terminal, but not a job of
        // its own) the group is the caller's, which is not the session's to
        // signal or count.
        let me = std::process::id();
        let leads_group = group_of(me) == Some(me);
        let own_group = !leads_group && !std::io::stdin().is_terminal();
        let (session, mut child, pgid) =
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
                std::fs::create_dir_all(ctx.home.join("tmp")).ok();
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
                let leader = if own_group { child.id() } else { me };
                let session = SessionRecord {
                    id: SessionId(0),
                    sandbox: name.clone(),
                    kind: SessionKind::Interactive,
                    version: version.version,
                    snapshot: snapshot.id,
                    compiled: Some(compiled.display().to_string()),
                    root: reference(leader).ok_or_else(|| Error::Session {
                        what: "cannot read the session's start time".into(),
                    })?,
                    pgid: if own_group {
                        leader
                    } else {
                        group_of(me).unwrap_or(me)
                    },
                    started_at: now(),
                    ended_at: None,
                };
                let id = self.state.put_session(lock, &session)?;
                record.state = SandboxState::Running;
                self.state.put(lock, &record)?;
                Ok((id, child, session.pgid))
            })?;

        let status = child.wait().map_err(|e| Error::Session {
            what: format!("lost the session's program: {e}"),
        })?;
        let exit = status.code().unwrap_or(1);
        // The program's exit is not the session's end: what it left running
        // in the session's group keeps the session open, so `show`, `stop`
        // and `rm` still see it. This process is not a member.
        let left: Vec<Member> = if leads_group || own_group {
            group_members(pgid)
                .into_iter()
                .filter(|m| m.pid != me)
                .collect()
        } else {
            Vec::new()
        };
        let summary = |_: &()| match left.len() {
            0 => format!("exit {exit}"),
            n => format!("exit {exit}, {n} processes still running"),
        };
        self.write(
            by,
            "session end",
            Some(format!("{target} session {session}")),
            summary,
            |lock| {
                if left.is_empty() {
                    self.state.end_session(lock, session)?;
                }
                Ok(())
            },
        )?;
        Ok(SessionEnd {
            session,
            exit,
            left,
        })
    }

    /// Starts the sandbox's proxy unless it runs already, and records it as
    /// a session, so that `sandbox stop` ends it too.
    pub(super) fn ensure_proxy(&self, lock: &StateLock, record: &SandboxRecord) -> Result<()> {
        let running = self
            .state
            .sessions(&record.name, true)?
            .into_iter()
            .any(|s| s.kind == SessionKind::Proxy && is_same(&s.root));
        if running {
            return Ok(());
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
            started_at: now(),
            ended_at: None,
        };
        self.state.put_session(lock, &session)?;
        Ok(())
    }
}
