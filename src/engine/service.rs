//! A sandbox's background services (design §4, ADRs 0002, 0021): its proxy
//! and, when its runtime has one, the runtime's gateway, run by launchd while
//! the user is logged in. `sandbox start` installs them, so they come back
//! at each login; `sandbox stop` removes them.

use std::ffi::OsString;
use std::net::{SocketAddr, TcpStream};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use super::Engine;
use super::session::SessionEnd;
use crate::backend::Launch;
use crate::error::{Error, Result};
use crate::lifecycle::process::{group_of, reference};
use crate::model::audit::Actor;
use crate::model::now;
use crate::model::sandbox::{SandboxName, SandboxState};
use crate::model::session::{SessionId, SessionKind, SessionRecord};
use crate::runtime::adapter;
use crate::service::{ServiceStatus, ServiceUnit};

/// The units a sandbox may have.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unit {
    Proxy,
    Gateway,
}

impl Unit {
    pub const ALL: [Unit; 2] = [Unit::Proxy, Unit::Gateway];

    pub fn as_str(self) -> &'static str {
        match self {
            Unit::Proxy => "proxy",
            Unit::Gateway => "gateway",
        }
    }
}

pub fn label(name: &SandboxName, unit: Unit) -> String {
    format!("enclos.{name}.{}", unit.as_str())
}

/// How long the gateway waits for the proxy service to listen.
const PROXY_WAIT: Duration = Duration::from_secs(15);

impl Engine {
    fn log_file(&self, name: &SandboxName, unit: Unit) -> PathBuf {
        self.layout
            .sandbox_dir(name.as_str())
            .join("logs")
            .join(format!("{}.log", unit.as_str()))
    }

    /// What every service of this enclos runs with: where enclos keeps its
    /// files, when that is one folder.
    fn service_env(&self) -> Vec<(String, String)> {
        if self.layout.data() == self.layout.config() {
            vec![(
                "ENCLOS_HOME".to_owned(),
                self.layout.data().display().to_string(),
            )]
        } else {
            Vec::new()
        }
    }

    /// Starts the sandbox's proxy and its runtime's gateway as services.
    pub fn start_sandbox(&self, by: &Actor, name: &SandboxName) -> Result<Vec<String>> {
        let summary = |labels: &Vec<String>| labels.join(", ");
        self.write(
            by,
            "sandbox start",
            Some(name.to_string()),
            summary,
            |lock| {
                let mut record = self.state.get(name)?.ok_or_else(|| Error::NoSuchSandbox {
                    name: name.to_string(),
                })?;
                self.backend_of(name)?;
                let exe = self.exe.clone().ok_or_else(|| Error::Session {
                    what: "cannot find the enclos program".into(),
                })?;
                std::fs::create_dir_all(self.layout.sandbox_dir(name.as_str()).join("logs")).ok();
                // A proxy `connect` started would hold the ports the service needs.
                self.stop_proxy(lock, name)?;

                let mut args: Vec<OsString> = vec![
                    "proxy".into(),
                    "run".into(),
                    name.to_string().into(),
                    "--record".into(),
                ];
                args.extend([
                    "--listen".into(),
                    format!("127.0.0.1:{}", record.port_base).into(),
                ]);
                for p in self.state.agents(name)? {
                    args.extend([
                        "--listen".into(),
                        format!("127.0.0.1:{}={}", p.port, p.name).into(),
                    ]);
                }
                let mut units = vec![ServiceUnit {
                    label: label(name, Unit::Proxy),
                    program: exe.clone(),
                    args,
                    log: self.log_file(name, Unit::Proxy),
                    env: self.service_env(),
                }];
                if record
                    .runtime
                    .is_some_and(|kind| adapter(kind).service().is_some())
                {
                    units.push(ServiceUnit {
                        label: label(name, Unit::Gateway),
                        program: exe,
                        args: vec!["launch".into(), name.to_string().into()],
                        log: self.log_file(name, Unit::Gateway),
                        env: self.service_env(),
                    });
                }
                for unit in &units {
                    self.services.start(unit).map_err(|e| Error::Session {
                        what: e.to_string(),
                    })?;
                }
                record.state = SandboxState::Running;
                self.state.put(lock, &record)?;
                Ok(units.into_iter().map(|u| u.label).collect())
            },
        )
    }

    /// Removes the sandbox's services; `stop_sandbox` calls this first.
    pub(super) fn stop_services(&self, name: &SandboxName) -> Result<()> {
        for unit in [Unit::Gateway, Unit::Proxy] {
            self.services
                .stop(&label(name, unit))
                .map_err(|e| Error::Session {
                    what: e.to_string(),
                })?;
        }
        Ok(())
    }

    /// Each unit of the sandbox and whether it runs.
    pub fn service_status(&self, name: &SandboxName) -> Vec<(String, ServiceStatus)> {
        Unit::ALL
            .iter()
            .map(|u| label(name, *u))
            .map(|l| {
                let status = self.services.status(&l);
                (l, status)
            })
            .filter(|(_, s)| *s != ServiceStatus::NotLoaded)
            .collect()
    }

    /// The gateway service's process: runs the runtime's background command
    /// in the sandbox, in a process group of its own, recorded as a session.
    pub fn launch(&self, by: &Actor, name: &SandboxName) -> Result<SessionEnd> {
        let kind = self.runtime_of(name)?;
        let command = adapter(kind).service().ok_or_else(|| Error::Session {
            what: format!("{kind} has no background service"),
        })?;
        let record = self.state.get(name)?.ok_or_else(|| Error::NoSuchSandbox {
            name: name.to_string(),
        })?;
        let addr = SocketAddr::from(([127, 0, 0, 1], record.port_base));
        let start = Instant::now();
        while TcpStream::connect_timeout(&addr, Duration::from_millis(200)).is_err() {
            if start.elapsed() > PROXY_WAIT {
                return Err(Error::Session {
                    what: format!("the proxy of sandbox {name} is not listening on {addr}"),
                });
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        let summary = |(id, _): &(SessionId, _)| format!("session {id}");
        let (session, mut child) =
            self.write(by, "launch", Some(name.to_string()), summary, |lock| {
                let ports = self.ports_of(&record)?;
                let compiled = self.compile_policy(name, &ports)?;
                let (version, snapshot) =
                    self.state
                        .active_policy(name)?
                        .ok_or_else(|| Error::NoPolicy {
                            sandbox: name.to_string(),
                        })?;
                let (program, args) = command
                    .split_first()
                    .expect("a service command has a program");
                let launch = Launch {
                    program: program.clone(),
                    args: args.to_vec(),
                    proxy_port: record.port_base,
                    env: Vec::new(),
                };
                let ctx = self.sandbox_context(name, &ports);
                let mut wrapped = self.backend_of(name)?.wrap(&compiled, &ctx, &launch);
                let child = wrapped
                    .process_group(0)
                    .spawn()
                    .map_err(|e| Error::Session {
                        what: format!("could not start the {kind} service: {e}"),
                    })?;
                let root = reference(child.id()).ok_or_else(|| Error::Session {
                    what: "the service exited at once".into(),
                })?;
                let session = SessionRecord {
                    id: SessionId(0),
                    sandbox: name.clone(),
                    agent: None,
                    kind: SessionKind::Service,
                    version: version.version,
                    snapshot: snapshot.id,
                    compiled: Some(compiled.display().to_string()),
                    pgid: group_of(child.id()).unwrap_or(child.id()),
                    root,
                    started_at: now(),
                    ended_at: None,
                };
                let id = self.state.put_session(lock, &session)?;
                Ok((id, child))
            })?;
        let status = child.wait().map_err(|e| Error::Session {
            what: format!("lost the service: {e}"),
        })?;
        let exit = status.code().unwrap_or(1);
        self.write(
            by,
            "service end",
            Some(format!("{name} session {session}")),
            |_| format!("exit {exit}"),
            |lock| Ok(self.state.end_session(lock, session)?),
        )?;
        Ok(SessionEnd { session, exit })
    }

    /// Records a proxy that a service started, so `connect` knows it runs.
    pub fn record_proxy(&self, by: &Actor, name: &SandboxName) -> Result<SessionId> {
        let me = std::process::id();
        self.write(
            by,
            "proxy start",
            Some(name.to_string()),
            |id| format!("session {id}"),
            |lock| {
                let (version, snapshot) =
                    self.state
                        .active_policy(name)?
                        .ok_or_else(|| Error::NoPolicy {
                            sandbox: name.to_string(),
                        })?;
                let session = SessionRecord {
                    id: SessionId(0),
                    sandbox: name.clone(),
                    agent: None,
                    kind: SessionKind::Proxy,
                    version: version.version,
                    snapshot: snapshot.id,
                    compiled: None,
                    root: reference(me).ok_or_else(|| Error::Session {
                        what: "cannot read this process's start time".into(),
                    })?,
                    pgid: group_of(me).unwrap_or(me),
                    started_at: now(),
                    ended_at: None,
                };
                Ok(self.state.put_session(lock, &session)?)
            },
        )
    }

    /// The service logs of a sandbox, oldest unit first.
    pub fn log_files(&self, name: &SandboxName) -> Result<Vec<PathBuf>> {
        self.require_sandbox(name)?;
        Ok(Unit::ALL
            .iter()
            .map(|u| self.log_file(name, *u))
            .filter(|p| p.exists())
            .collect())
    }
}
