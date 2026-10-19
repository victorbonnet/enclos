//! The engine's sandbox calls: create, list, show, remove and stop
//! (design §8, §10).

use super::Engine;
use crate::error::{Error, Result};
use crate::layout::LayoutError;
use crate::lifecycle::process::group_members;
use crate::lifecycle::stop::{GRACE, Stopped, stop};
use crate::model::audit::Actor;
use crate::model::now;
use crate::model::plan::{Confirm, Plan, Planned};
use crate::model::policy::{PolicyVersion, TemplateName};
use crate::model::sandbox::{
    BackendKind, PORT_FIRST, PORT_LAST, SandboxName, SandboxRecord, SandboxState,
};
use crate::model::session::{Member, SessionId, SessionRecord};

/// What `enclos sandbox create` takes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxSpec {
    pub name: SandboxName,
    pub backend: BackendKind,
    pub template: TemplateName,
}

/// A sandbox as `list` and `show` print it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxView {
    pub record: SandboxRecord,
    pub policy: Option<PolicyVersion>,
    /// Running sessions, each with the members found in its group now.
    pub sessions: Vec<(SessionRecord, Vec<Member>)>,
}

/// What stopping a sandbox did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StopReport {
    pub stopped: Vec<SessionId>,
    pub survivors: Vec<(SessionId, Vec<Member>)>,
}

impl Engine {
    /// Creates a sandbox: its record, a proxy port, its folder and
    /// home, and version 1 of its policy from the template.
    pub fn create_sandbox(
        &self,
        by: &Actor,
        spec: SandboxSpec,
        confirm: Confirm,
    ) -> Result<Planned<SandboxRecord>> {
        if self.state.get(&spec.name)?.is_some() {
            return Err(Error::SandboxExists {
                name: spec.name.to_string(),
            });
        }
        if confirm == Confirm::DryRun {
            return Ok(Planned::DryRun(Plan {
                create: vec![self.layout.sandbox_home(spec.name.as_str())],
                changes: vec![format!(
                    "create sandbox {} ({}, template {})",
                    spec.name, spec.backend, spec.template
                )],
            }));
        }
        let summary = |r: &SandboxRecord| format!("{} on port {}", r.backend, r.proxy_port);
        let record = self.write(
            by,
            "sandbox create",
            Some(spec.name.to_string()),
            summary,
            |lock| {
                let record = SandboxRecord {
                    name: spec.name.clone(),
                    backend: spec.backend,
                    template: spec.template.clone(),
                    state: SandboxState::Created,
                    proxy_port: self.free_port()?,
                    runtime: None,
                    created_at: now(),
                };
                // The backend must run here before anything is created (ADR 0009).
                self.state.put(lock, &record)?;
                if let Err(e) = self.backend_of(&record.name) {
                    self.state.remove(lock, &record.name)?;
                    return Err(e);
                }
                self.create_policy(lock, by, &record.name, &record.template)?;
                Ok(record)
            },
        )?;
        Ok(Planned::Done(record))
    }

    /// The first port no sandbox here uses and nothing on this host listens
    /// on (other enclos installs or users included).
    fn free_port(&self) -> Result<u16> {
        let used: Vec<u16> = self.state.list()?.iter().map(|r| r.proxy_port).collect();
        let listening = |port: u16| {
            let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
            std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_millis(100))
                .is_ok()
        };
        (PORT_FIRST..=PORT_LAST)
            .find(|port| !used.contains(port) && !listening(*port))
            .ok_or(Error::NoFreePorts)
    }

    pub fn list_sandboxes(&self) -> Result<Vec<SandboxView>> {
        self.state
            .list()?
            .into_iter()
            .map(|r| self.view(r))
            .collect()
    }

    pub fn show_sandbox(&self, name: &SandboxName) -> Result<SandboxView> {
        let record = self.state.get(name)?.ok_or_else(|| Error::NoSuchSandbox {
            name: name.to_string(),
        })?;
        self.view(record)
    }

    fn view(&self, record: SandboxRecord) -> Result<SandboxView> {
        let policy = self.state.active_policy(&record.name)?.map(|(v, _)| v);
        let sessions = self
            .state
            .sessions(&record.name, true)?
            .into_iter()
            .map(|s| {
                let members = group_members(s.pgid);
                (s, members)
            })
            .collect();
        Ok(SandboxView {
            record,
            policy,
            sessions,
        })
    }

    /// Stops every session of the sandbox. Members that survive are
    /// reported, and the sandbox is marked failed rather than stopped.
    pub fn stop_sandbox(&self, by: &Actor, name: &SandboxName) -> Result<StopReport> {
        let summary = |r: &StopReport| match r.survivors.is_empty() {
            true => format!("stopped {} sessions", r.stopped.len()),
            false => format!("{} sessions left members running", r.survivors.len()),
        };
        // The services first, so launchd does not restart what is stopped.
        self.stop_services(name)?;
        self.write(
            by,
            "sandbox stop",
            Some(name.to_string()),
            summary,
            |lock| {
                let mut record = self.state.get(name)?.ok_or_else(|| Error::NoSuchSandbox {
                    name: name.to_string(),
                })?;
                let mut report = StopReport {
                    stopped: Vec::new(),
                    survivors: Vec::new(),
                };
                for session in self.state.sessions(name, true)? {
                    match stop(&session, GRACE) {
                        Stopped::Clean => {
                            self.state.end_session(lock, session.id)?;
                            report.stopped.push(session.id);
                        }
                        Stopped::Survivors(left) => report.survivors.push((session.id, left)),
                    }
                }
                record.state = if report.survivors.is_empty() {
                    SandboxState::Stopped
                } else {
                    SandboxState::Failed {
                        reason: "members survived stop".to_owned(),
                    }
                };
                self.state.put(lock, &record)?;
                Ok(report)
            },
        )
    }

    /// Removes a stopped sandbox: its record and history, and its folder
    /// unless `keep_data`. Deleting data asks for confirmation first.
    pub fn remove_sandbox(
        &self,
        by: &Actor,
        name: &SandboxName,
        keep_data: bool,
        confirm: Confirm,
    ) -> Result<Planned<()>> {
        self.require_sandbox(name)?;
        if !self.state.sessions(name, true)?.is_empty() {
            return Err(Error::SandboxRunning {
                name: name.to_string(),
            });
        }
        let dir = self.layout.sandbox_dir(name.as_str());
        let what = if keep_data {
            "remove its record"
        } else {
            "delete its folder and home"
        };
        match confirm {
            Confirm::DryRun => {
                return Ok(Planned::DryRun(Plan {
                    changes: vec![format!("remove sandbox {name}: {what} ({})", dir.display())],
                    ..Plan::default()
                }));
            }
            Confirm::Ask if !keep_data => {
                return Err(Error::NeedsConfirmation {
                    what: format!("deleting sandbox {name} and its home"),
                });
            }
            _ => {}
        }
        self.write(
            by,
            "sandbox rm",
            Some(name.to_string()),
            |_| what.to_owned(),
            |lock| {
                self.state.remove(lock, name)?;
                if !keep_data && dir.exists() {
                    std::fs::remove_dir_all(&dir).map_err(|source| LayoutError::Io {
                        path: dir.clone(),
                        source,
                    })?;
                }
                Ok(())
            },
        )?;
        Ok(Planned::Done(()))
    }
}
