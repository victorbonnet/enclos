//! Interactive sessions: `enclos connect` (design §8, "Starting a session").

use std::ffi::OsString;
use std::fs::OpenOptions;
use std::net::{SocketAddr, TcpStream};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use super::Engine;
use crate::backend::Launch;
use crate::error::{Error, Result};
use crate::lifecycle::process::{group_of, is_same, reference};
use crate::model::audit::Actor;
use crate::model::now;
use crate::model::sandbox::{SandboxName, SandboxRecord, SandboxState};
use crate::model::session::{SessionId, SessionKind, SessionRecord};
use crate::state::StateLock;

/// How a session ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionEnd {
    pub session: SessionId,
    /// The program's exit status; 1 when a signal ended it.
    pub exit: i32,
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
        profile: Option<&str>,
        command: Vec<OsString>,
    ) -> Result<SessionEnd> {
        if let Some(profile) = profile {
            return Err(Error::Session {
                what: format!(
                    "profiles come with the agent: `{name}/{profile}` needs `enclos agent install` first"
                ),
            });
        }
        let summary = |(id, _): &(SessionId, _)| format!("session {id}");
        let (session, mut child) =
            self.write(by, "connect", Some(name.to_string()), summary, |lock| {
                let mut record = self.state.get(name)?.ok_or_else(|| Error::NoSuchSandbox {
                    name: name.to_string(),
                })?;
                let ports = [record.port_base];
                let compiled = self.compile_policy(name, &ports)?;
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
                    proxy_port: record.port_base,
                    env: Vec::new(),
                };
                let ctx = self.sandbox_context(name, &ports);
                std::fs::create_dir_all(ctx.home.join("tmp")).ok();
                let backend = self.backend_of(name)?;
                let child = backend
                    .wrap(&compiled, &ctx, &launch)
                    .spawn()
                    .map_err(|e| Error::Session {
                        what: format!(
                            "could not start {} in sandbox {name}: {e}",
                            launch.program.to_string_lossy()
                        ),
                    })?;

                // The session's group is this command's own: the terminal's job
                // for `enclos connect`, which `sandbox stop` may end as a whole.
                let me = std::process::id();
                let session = SessionRecord {
                    id: SessionId(0),
                    sandbox: name.clone(),
                    profile: None,
                    kind: SessionKind::Interactive,
                    version: version.version,
                    snapshot: snapshot.id,
                    compiled: Some(compiled.display().to_string()),
                    root: reference(me).ok_or_else(|| Error::Session {
                        what: "cannot read this process's start time".into(),
                    })?,
                    pgid: group_of(me).unwrap_or(me),
                    started_at: now(),
                    ended_at: None,
                };
                let id = self.state.put_session(lock, &session)?;
                record.state = SandboxState::Running;
                self.state.put(lock, &record)?;
                Ok((id, child))
            })?;

        let status = child.wait().map_err(|e| Error::Session {
            what: format!("lost the session's program: {e}"),
        })?;
        let exit = status.code().unwrap_or(1);
        self.write(
            by,
            "session end",
            Some(format!("{name} session {session}")),
            |_| format!("exit {exit}"),
            |lock| {
                self.state.end_session(lock, session)?;
                Ok(())
            },
        )?;
        Ok(SessionEnd { session, exit })
    }

    /// Starts the sandbox's proxy unless it runs already, and records it as
    /// a session, so that `sandbox stop` ends it too.
    fn ensure_proxy(&self, lock: &StateLock, record: &SandboxRecord) -> Result<()> {
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
        let addr = SocketAddr::from(([127, 0, 0, 1], record.port_base));
        // Anything else on this port would receive the sandbox's traffic.
        if TcpStream::connect_timeout(&addr, Duration::from_millis(200)).is_ok() {
            return Err(failed(format!(
                "port {} of sandbox {} is in use by another program; stop it, or recreate the sandbox to get other ports",
                record.port_base, record.name
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
            profile: None,
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
