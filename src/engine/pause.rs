//! A runtime's services stopped around one of the runtime's own commands
//! that a running service would get in the way of, then installed again:
//! Hermes's gateway serves every agent and holds its files, so its delete
//! of one runs while the gateway is stopped (design §10).

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
