//! A runtime's services stopped around one of the runtime's own commands
//! that a running service would get in the way of, then installed again:
//! Hermes's gateway serves every agent and holds its files, so its delete
//! of one runs while the gateway is stopped (design §10). It also serves
//! only the agents that existed when it started, so `agent add` restarts it
//! once the agent exists (design §9).

use super::Engine;
use super::service::{IfUnrecorded, Unit};
use crate::error::{Error, Result};
use crate::model::audit::Actor;
use crate::model::sandbox::SandboxName;
use crate::runtime::adapter;
use crate::service::ServiceLabel;

/// The runtime services [`Engine::pause_runtime`] stopped, for
/// [`Engine::resume_runtime`] to install again.
#[must_use = "what was stopped is to be installed again"]
pub(super) struct Paused {
    units: Vec<Unit>,
    /// The sandbox's other services, which kept running: one of them gone
    /// by the resume means the sandbox was stopped meanwhile.
    others: Vec<ServiceLabel>,
}

impl Paused {
    /// The services stopped, by the names their runtime gives them.
    pub(super) fn names(&self) -> Vec<&'static str> {
        self.units.iter().map(|u| u.as_str()).collect()
    }
}

impl Engine {
    /// The sandbox's runtime services installed now, running or not: what
    /// [`Engine::pause_runtime`] would stop.
    pub(super) fn installed_runtime_services(
        &self,
        name: &SandboxName,
    ) -> Result<Vec<(Unit, ServiceLabel)>> {
        let record = self.record(name)?;
        let installed = self.installed_labels(name)?;
        let services = record
            .runtime
            .map(|kind| adapter(kind).services())
            .unwrap_or_default();
        let mut found = Vec::new();
        for service in services {
            let unit = Unit::Runtime(service.name);
            let label = self.label(name, unit)?;
            if installed.contains(&label) {
                found.push((unit, label));
            }
        }
        Ok(found)
    }

    /// Stops the sandbox's runtime services that are installed, `why`
    /// saying what for in the audit log, and keeps the others (the proxy,
    /// the namespace holder) and every open session running. Outside the
    /// lock, which a runtime service told to end needs to record its end.
    pub(super) fn pause_runtime(
        &self,
        by: &Actor,
        name: &SandboxName,
        why: &str,
    ) -> Result<Paused> {
        let stopping = self.installed_runtime_services(name)?;
        if stopping.is_empty() {
            return Ok(Paused {
                units: Vec::new(),
                others: Vec::new(),
            });
        }
        let labels: Vec<&ServiceLabel> = stopping.iter().map(|(_, l)| l).collect();
        let others: Vec<ServiceLabel> = self
            .installed_labels(name)?
            .into_iter()
            .filter(|l| !labels.contains(&l))
            .collect();
        self.audit.check()?;
        self.remove_services(by, name, why, IfUnrecorded::Stop, &others)?
            .into_result()?;
        Ok(Paused {
            units: stopping.into_iter().map(|(u, _)| u).collect(),
            others,
        })
    }

    /// Installs again the services `paused` names, as `sandbox start`
    /// installs them, unless the sandbox's other services were removed
    /// meanwhile, as by `sandbox stop`: then they stay removed.
    pub(super) fn resume_runtime(
        &self,
        by: &Actor,
        name: &SandboxName,
        paused: Paused,
    ) -> Result<()> {
        if paused.units.is_empty() {
            return Ok(());
        }
        let restarted = self.write(
            by,
            "services start",
            Some(name.to_string()),
            |labels: &Option<Vec<ServiceLabel>>| match labels {
                Some(labels) => format!(
                    "installed {} again",
                    labels
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
                None => "the sandbox was stopped meanwhile: nothing installed again".to_owned(),
            },
            |_lock| {
                let installed = self.installed_labels(name)?;
                if paused.others.iter().any(|l| !installed.contains(l)) {
                    return Ok(None);
                }
                let record = self.record(name)?;
                let store_env = self.service_store_env(&self.policy(name)?.snapshot.policy)?;
                self.create_logs_dir(name)?;
                let mut labels = Vec::new();
                for unit in &paused.units {
                    let unit = self.service_unit(&record, *unit, &store_env)?;
                    self.services.start(&unit)?;
                    labels.push(unit.label);
                }
                Ok(Some(labels))
            },
        );
        restarted.map(|_| ()).map_err(|error| Error::WithContext {
            what: format!(
                "its {} could not start again: {error}. `enclos sandbox start {name}` starts its services again",
                paused.names().join(" and ")
            ),
            error: Box::new(error),
        })
    }
}

/// The runtime services `agent add` restarts once the agent exists, read
/// when it plans: Hermes's gateway serves only the agents that existed when
/// it started (design §9).
pub(super) struct Restart {
    installed: Vec<(Unit, ServiceLabel)>,
}

impl Restart {
    /// What the restart adds to the plan of adding `agent`: nothing when
    /// no runtime service is installed.
    pub(super) fn plan(&self, agent: &str) -> Vec<String> {
        let stop = self
            .installed
            .iter()
            .map(|(_, l)| format!("stop service {l}, which ends a chat in progress"));
        let start = self
            .installed
            .iter()
            .map(|(_, l)| format!("install service {l} again, so that it serves agent {agent}"));
        stop.chain(start).collect()
    }

    /// The confirmation `agent add` asks for while it would restart a
    /// service, `adding` naming what it does; `Ok` when it restarts none.
    pub(super) fn confirm(&self, adding: &str) -> Result<()> {
        if self.installed.is_empty() {
            return Ok(());
        }
        Err(Error::NeedsConfirmation {
            what: format!(
                "{adding}, which restarts the sandbox's service {} and so ends a chat in progress,",
                self.installed
                    .iter()
                    .map(|(u, _)| u.as_str())
                    .collect::<Vec<_>>()
                    .join(" and ")
            ),
        })
    }
}

impl Engine {
    /// The runtime services installed now, which `agent add` restarts once
    /// the agent exists; none while the sandbox is stopped.
    pub(super) fn plan_restart(&self, name: &SandboxName) -> Result<Restart> {
        Ok(Restart {
            installed: self.installed_runtime_services(name)?,
        })
    }

    /// Stops the runtime services `restart` names, and installs them again,
    /// as `sandbox start` does, so that they start after what `why` made;
    /// unless `sandbox stop` stopped the sandbox meanwhile. An error says
    /// how to start them.
    pub(super) fn restart_runtime(
        &self,
        by: &Actor,
        name: &SandboxName,
        restart: Restart,
        why: &str,
    ) -> Result<()> {
        if restart.installed.is_empty() {
            return Ok(());
        }
        let paused = self
            .pause_runtime(by, name, why)
            .map_err(|error| Error::WithContext {
                what: format!(
                    "its services could not be stopped to start again: {error}. `enclos sandbox start {name}` starts them again"
                ),
                error: Box::new(error),
            })?;
        self.resume_runtime(by, name, paused)
    }
}
