//! The engine's sandbox calls: create, list, show, remove and stop
//! (design §8, §10).

use super::Engine;
use crate::error::{Error, Result};
use crate::layout::LayoutError;
use crate::lifecycle::members::members;
use crate::lifecycle::stop::{GRACE, Stopped, Survivor, stop};
use crate::model::audit::Actor;
use crate::model::now;
use crate::model::plan::{Confirm, Plan, Planned};
use crate::model::policy::{PolicyVersion, TemplateName};
use crate::model::sandbox::{
    BackendKind, PORT_FIRST, PORT_LAST, SandboxName, SandboxRecord, SandboxState,
};
use crate::model::session::{Member, SessionId, SessionRecord};
use crate::service::ServiceLabel;
use std::path::{Path, PathBuf};

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
    /// Sessions not ended yet, and the sandbox's proxy, which is recorded
    /// beside them.
    pub sessions: Vec<SessionView>,
}

/// A session not ended yet, as `show` prints it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionView {
    pub session: SessionRecord,
    /// The members found now.
    pub members: Vec<Member>,
    /// Whether its file and program rules differ from the active
    /// snapshot's, so that only a restart applies them (design §8).
    pub needs_restart: bool,
}

/// What stopping a sandbox did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StopReport {
    /// The services removed, so they do not start again.
    pub services: Vec<ServiceLabel>,
    pub stopped: Vec<SessionId>,
    pub survivors: Vec<(SessionId, Vec<Survivor>)>,
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
                // Checked again under the lock: another create may have
                // taken the name while this one waited for it.
                if self.state.get(&spec.name)?.is_some() {
                    return Err(Error::SandboxExists {
                        name: spec.name.to_string(),
                    });
                }
                let record = SandboxRecord {
                    name: spec.name.clone(),
                    backend: spec.backend,
                    template: spec.template.clone(),
                    state: SandboxState::Created,
                    proxy_port: self.free_port()?,
                    runtime: None,
                    created_at: now(),
                };
                let dir = self.layout.sandbox_dir(spec.name.as_str());
                let existed = dir.exists();
                self.state.put(lock, &record)?;
                // The backend must run here (ADR 0009), and the template
                // must resolve. If either fails, nothing is left but what was
                // there before, such as a folder kept by `sandbox rm
                // --keep-data`.
                let made = self
                    .backend_of(&record.name)
                    .and_then(|_| self.create_policy(lock, by, &record.name, &record.template));
                if let Err(error) = made {
                    let mut left = Vec::new();
                    if let Err(e) = self.state.remove(lock, &record.name) {
                        left.push(format!("the record of sandbox {} ({e})", record.name));
                    }
                    if !existed
                        && let Err(e) = std::fs::remove_dir_all(&dir)
                        && e.kind() != std::io::ErrorKind::NotFound
                    {
                        left.push(format!("{} ({e})", dir.display()));
                    }
                    return Err(match left.is_empty() {
                        true => error,
                        false => Error::CleanupFailed {
                            error: Box::new(error),
                            left: left.join(" and "),
                        },
                    });
                }
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

    /// The file the active policy compiles to: a session started under
    /// another one runs file and program rules the active policy no longer
    /// has. A sandbox this host cannot compile for runs nothing. Compiled in
    /// memory only: nothing is written.
    pub(super) fn active_compiled(&self, record: &SandboxRecord) -> Option<PathBuf> {
        self.compiled_file(&record.name, record.proxy_port)
            .ok()
            .map(|(file, _)| file)
    }

    fn view(&self, record: SandboxRecord) -> Result<SandboxView> {
        let policy = self.state.active_policy(&record.name)?.map(|(v, _)| v);
        let active = self.active_compiled(&record);
        let sessions = self
            .state
            .sessions(&record.name, true)?
            .into_iter()
            .map(|session| {
                let members = members(&session)?;
                let needs_restart = needs_restart(&session, active.as_deref());
                Ok(SessionView {
                    session,
                    members,
                    needs_restart,
                })
            })
            .collect::<Result<_>>()?;
        Ok(SandboxView {
            record,
            policy,
            sessions,
        })
    }

    /// Stops every session of the sandbox. Members that survive are
    /// reported, and the sandbox is marked failed rather than stopped.
    pub fn stop_sandbox(
        &self,
        by: &Actor,
        name: &SandboxName,
        confirm: Confirm,
    ) -> Result<Planned<StopReport>> {
        if confirm == Confirm::DryRun {
            let view = self.show_sandbox(name)?;
            let mut changes: Vec<String> = view
                .sessions
                .iter()
                .map(|v| {
                    format!(
                        "stop session {} ({}, {} processes)",
                        v.session.id,
                        v.session.kind.as_str(),
                        v.members.len()
                    )
                })
                .collect();
            changes.splice(
                0..0,
                self.service_status(name)?
                    .into_iter()
                    .map(|(label, _)| format!("stop service {label}")),
            );
            changes.push(format!("mark sandbox {name} stopped"));
            return Ok(Planned::DryRun(Plan {
                changes,
                ..Plan::default()
            }));
        }
        let summary = |r: &StopReport| match r.survivors.is_empty() {
            true => format!(
                "removed {} services, stopped {} sessions",
                r.services.len(),
                r.stopped.len()
            ),
            false => format!(
                "removed {} services; {} sessions left members running",
                r.services.len(),
                r.survivors.len()
            ),
        };
        // The services first, so the service manager does not restart what
        // is stopped; outside the lock, which a service told to end needs to
        // record its end.
        let services = self.stop_services(name)?;
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
                    services: services.clone(),
                    stopped: Vec::new(),
                    survivors: Vec::new(),
                };
                for session in self.state.sessions(name, true)? {
                    match stop(&session, GRACE) {
                        Ok(Stopped::Clean) => {
                            self.state.end_session(lock, session.id)?;
                            report.stopped.push(session.id);
                        }
                        Ok(Stopped::Survivors(left)) => report.survivors.push((session.id, left)),
                        // Without a listing, nothing shows the members are
                        // gone: the session stays open.
                        Err(e) => {
                            record.state = SandboxState::Failed {
                                reason: format!("stop could not look at processes: {e}"),
                            };
                            self.state.put(lock, &record)?;
                            return Err(e.into());
                        }
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
        .map(Planned::Done)
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
        self.require_stopped(name)?;
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
                // Checked again under the lock: a `connect` may have started
                // while this command waited for it.
                self.require_stopped(name)?;
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

    /// Refuses a sandbox with services installed or sessions open, saying
    /// how to end them.
    fn require_stopped(&self, name: &SandboxName) -> Result<()> {
        let record = self.state.get(name)?.ok_or_else(|| Error::NoSuchSandbox {
            name: name.to_string(),
        })?;
        // Installed, a service comes back on its own, even with no session
        // recorded: one whose proxy could not take its port has none.
        if self.has_services(name)? {
            return Err(Error::SandboxHasServices {
                name: name.to_string(),
            });
        }
        if self.state.sessions(name, true)?.is_empty() {
            return Ok(());
        }
        let name = name.to_string();
        Err(match record.state {
            SandboxState::Failed { .. } => Error::SandboxNotStopped { name },
            _ => Error::SandboxRunning { name },
        })
    }
}

/// Whether a running session needs a restart to run under the active
/// policy: it started under another compiled file. The proxy has none and
/// applies network rules live, so it never does.
pub(super) fn needs_restart(session: &SessionRecord, active: Option<&Path>) -> bool {
    match (&session.compiled, active) {
        (Some(at_launch), Some(active)) => Path::new(at_launch) != active,
        _ => false,
    }
}
