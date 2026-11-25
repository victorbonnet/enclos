//! A runtime's services stopped around one of the runtime's own commands
//! that a running service would get in the way of, then installed again:
//! Hermes's gateway serves every agent and holds its files, so its delete
//! of one runs while the gateway is stopped (design §10). It also serves
//! only the agents that existed when it started, so `agent add` restarts it
//! once the agent exists (design §9).

use std::collections::BTreeMap;

use serde::Serialize;

use super::Engine;
use super::pause_state::{
    HostPauseRead, HostPauseView, SandboxPauseInput, SandboxPauseView, derive_host, derive_sandbox,
};
use super::service::{IfUnrecorded, Unit};
use crate::error::{Error, Result};
use crate::model::audit::{Actor, Intent, Outcome};
use crate::model::now;
use crate::model::pause::{HostPauseRecord, SandboxPauseRecord};
use crate::model::sandbox::{SandboxName, SandboxState};
use crate::runtime::adapter;
use crate::service::ServiceLabel;

/// Which sandboxes a host pause or resume targets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PauseScope {
    All,
    Names(Vec<SandboxName>),
}

impl PauseScope {
    fn subject(&self) -> String {
        match self {
            PauseScope::All => "all".to_owned(),
            PauseScope::Names(names) => names
                .iter()
                .map(SandboxName::as_str)
                .collect::<Vec<_>>()
                .join(", "),
        }
    }
}

/// Closed set of per-sandbox outcomes for `enclos sandbox pause`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PauseOutcome {
    Paused,
    NothingToPause,
    WouldNotStop,
}

/// Closed set of per-sandbox outcomes for `enclos sandbox resume`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResumeOutcome {
    Resumed,
    NothingToResume,
    LeftAsItWas,
    WouldNotStart,
}

/// Per-sandbox result of `Engine::pause_sandboxes`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxPauseResult {
    pub sandbox: SandboxName,
    pub outcome: PauseOutcome,
    /// Runtime service labels stopped (or already held by the pause).
    pub services: Vec<String>,
    /// Tracked agents this sandbox serves (read from state records only).
    pub agents: Vec<String>,
    /// Why stopping failed, present iff `outcome == PauseOutcome::WouldNotStop`.
    pub error: Option<String>,
}

/// Result of `Engine::pause_sandboxes`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PauseReport {
    pub sandboxes: Vec<SandboxPauseResult>,
    pub host: HostPauseView,
}

impl PauseReport {
    pub fn any_failed(&self) -> bool {
        self.sandboxes
            .iter()
            .any(|s| s.outcome == PauseOutcome::WouldNotStop)
    }
}

/// Per-sandbox result of `Engine::resume_sandboxes`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxResumeResult {
    pub sandbox: SandboxName,
    pub outcome: ResumeOutcome,
    /// Runtime service labels installed again.
    pub services: Vec<String>,
    /// Tracked agents this sandbox serves (read from state records only).
    pub agents: Vec<String>,
    /// Why starting failed, present iff `outcome == ResumeOutcome::WouldNotStart`.
    pub error: Option<String>,
}

/// Result of `Engine::resume_sandboxes`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResumeReport {
    /// `true` when no pause record was in force when resume ran.
    pub no_record: bool,
    pub sandboxes: Vec<SandboxResumeResult>,
    pub host: HostPauseView,
}

impl ResumeReport {
    pub fn any_failed(&self) -> bool {
        self.sandboxes
            .iter()
            .any(|s| s.outcome == ResumeOutcome::WouldNotStart)
    }
}

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
        self.resume_runtime_inner(by, name, &paused)
            .map(|_| ())
            .map_err(|error| Error::WithContext {
                what: format!(
                    "its {} could not start again: {error}. `enclos sandbox start {name}` starts its services again",
                    paused.names().join(" and ")
                ),
                error: Box::new(error),
            })
    }

    /// Core of [`Engine::resume_runtime`]: returns `Ok(Some(labels))` when the
    /// services were installed again, or `Ok(None)` when the sandbox was
    /// stopped meanwhile (its state is no longer `Running` or one of its kept
    /// services was removed).
    pub(super) fn resume_runtime_inner(
        &self,
        by: &Actor,
        name: &SandboxName,
        paused: &Paused,
    ) -> Result<Option<Vec<ServiceLabel>>> {
        if paused.units.is_empty() {
            return Ok(Some(Vec::new()));
        }
        self.write(
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
                let record = self.record(name)?;
                if !matches!(record.state, SandboxState::Running) {
                    return Ok(None);
                }
                let installed = self.installed_labels(name)?;
                if paused.others.iter().any(|l| !installed.contains(l)) {
                    return Ok(None);
                }
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
        )
    }

    /// Pauses runtime services for `scope` (whole host or named sandboxes).
    ///
    /// Never runs a runtime command, never writes into a sandbox home, and
    /// never touches policy or secrets (H5). Checks every named sandbox and
    /// `expected_revision` before writing anything.
    pub fn pause_sandboxes(
        &self,
        by: &Actor,
        scope: PauseScope,
        expected_revision: Option<u64>,
    ) -> Result<PauseReport> {
        let lock = self.state.lock()?;
        let (is_all, targets) = self.resolve_pause_targets(&scope)?;
        let current_host = self.state.host_pause()?;
        let current_rev = current_host.as_ref().map_or(0, |h| h.revision);
        if let Some(expected) = expected_revision
            && expected != current_rev
        {
            return Err(Error::PauseConflict {
                expected,
                found: current_rev,
            });
        }

        // Plan per-target work under the lock before opening the audit entry
        // or writing any row.
        enum TargetPlan {
            Stop {
                labels: Vec<String>,
                kept: Vec<String>,
            },
            RePauseOwed {
                row: SandboxPauseRecord,
            },
            AlreadyPaused {
                labels: Vec<String>,
            },
            NoServices {
                needs_empty_row: bool,
            },
        }

        let mut planned: Vec<(SandboxName, TargetPlan)> = Vec::with_capacity(targets.len());
        let mut any_to_stop = false;
        let mut any_repause_owed = false;

        for name in &targets {
            let record = self.record(name)?;
            let installed_rt = self.installed_runtime_services(name)?;
            let existing = self.state.sandbox_pause(name)?;
            if !installed_rt.is_empty() {
                let rt_labels: Vec<ServiceLabel> =
                    installed_rt.iter().map(|(_, l)| l.clone()).collect();
                let kept: Vec<String> = self
                    .installed_labels(name)?
                    .into_iter()
                    .filter(|l| !rt_labels.contains(l))
                    .map(|l| l.to_string())
                    .collect();
                let labels: Vec<String> = rt_labels.iter().map(ToString::to_string).collect();
                any_to_stop = true;
                planned.push((name.clone(), TargetPlan::Stop { labels, kept }));
            } else if let Some(ref row) = existing
                && !row.labels.is_empty()
                && matches!(record.state, SandboxState::Running)
            {
                if row.released.is_some() {
                    any_repause_owed = true;
                    planned.push((name.clone(), TargetPlan::RePauseOwed { row: row.clone() }));
                } else {
                    planned.push((
                        name.clone(),
                        TargetPlan::AlreadyPaused {
                            labels: row.labels.clone(),
                        },
                    ));
                }
            } else {
                let needs_empty_row = existing.as_ref().is_none_or(|r| r.released.is_some());
                planned.push((name.clone(), TargetPlan::NoServices { needs_empty_row }));
            }
        }

        let write_record = is_all || any_to_stop || any_repause_owed;

        // Open one audit entry BEFORE the first row is written.
        let subject = match &scope {
            PauseScope::All => "all".to_owned(),
            PauseScope::Names(_) => targets
                .iter()
                .map(SandboxName::as_str)
                .collect::<Vec<_>>()
                .join(", "),
        };
        let ticket = self.audit.begin(
            &lock,
            Intent {
                by: by.clone(),
                command: "sandbox pause".to_owned(),
                target: Some(subject),
            },
        )?;
        let entry = ticket.into_entry();

        let at = now();
        let mut to_stop: Vec<(SandboxName, Vec<String>)> = Vec::new();
        let mut results: Vec<SandboxPauseResult> = Vec::with_capacity(planned.len());

        if write_record {
            if let Err(e) = self.state.ensure_host_pause(&lock, is_all, by, at) {
                let _ = self
                    .audit
                    .finish_entry(&lock, entry, Outcome::failed(e.to_string()));
                return Err(e.into());
            }
            for (name, plan) in planned {
                let agents = self.tracked_agent_names(&name);
                match plan {
                    TargetPlan::Stop { labels, kept } => {
                        let rec = SandboxPauseRecord {
                            sandbox: name.clone(),
                            labels: labels.clone(),
                            kept,
                            released: None,
                            at,
                            by: by.clone(),
                        };
                        if let Err(e) = self.state.put_sandbox_pause(&lock, &rec, now()) {
                            let _ = self.audit.finish_entry(
                                &lock,
                                entry,
                                Outcome::failed(e.to_string()),
                            );
                            return Err(e.into());
                        }
                        to_stop.push((name.clone(), labels));
                        // Placeholder updated after pause_runtime runs outside the lock.
                        results.push(SandboxPauseResult {
                            sandbox: name,
                            outcome: PauseOutcome::Paused,
                            services: Vec::new(),
                            agents,
                            error: None,
                        });
                    }
                    TargetPlan::RePauseOwed { mut row } => {
                        row.released = None;
                        row.at = at;
                        row.by = by.clone();
                        let labels = row.labels.clone();
                        if let Err(e) = self.state.put_sandbox_pause(&lock, &row, now()) {
                            let _ = self.audit.finish_entry(
                                &lock,
                                entry,
                                Outcome::failed(e.to_string()),
                            );
                            return Err(e.into());
                        }
                        results.push(SandboxPauseResult {
                            sandbox: name,
                            outcome: PauseOutcome::Paused,
                            services: labels,
                            agents,
                            error: None,
                        });
                    }
                    TargetPlan::AlreadyPaused { labels } => {
                        results.push(SandboxPauseResult {
                            sandbox: name,
                            outcome: PauseOutcome::Paused,
                            services: labels,
                            agents,
                            error: None,
                        });
                    }
                    TargetPlan::NoServices { needs_empty_row } => {
                        if needs_empty_row {
                            let rec = SandboxPauseRecord {
                                sandbox: name.clone(),
                                labels: Vec::new(),
                                kept: Vec::new(),
                                released: None,
                                at,
                                by: by.clone(),
                            };
                            if let Err(e) = self.state.put_sandbox_pause(&lock, &rec, now()) {
                                let _ = self.audit.finish_entry(
                                    &lock,
                                    entry,
                                    Outcome::failed(e.to_string()),
                                );
                                return Err(e.into());
                            }
                        }
                        results.push(SandboxPauseResult {
                            sandbox: name,
                            outcome: PauseOutcome::NothingToPause,
                            services: Vec::new(),
                            agents,
                            error: None,
                        });
                    }
                }
            }
        } else {
            // Subset with no services to stop (I13): write nothing at all.
            for (name, plan) in planned {
                let agents = self.tracked_agent_names(&name);
                match plan {
                    TargetPlan::AlreadyPaused { labels } => results.push(SandboxPauseResult {
                        sandbox: name,
                        outcome: PauseOutcome::Paused,
                        services: labels,
                        agents,
                        error: None,
                    }),
                    _ => results.push(SandboxPauseResult {
                        sandbox: name,
                        outcome: PauseOutcome::NothingToPause,
                        services: Vec::new(),
                        agents,
                        error: None,
                    }),
                }
            }
        }

        // Release the state lock before stopping services so services told to
        // end can record their session end and remove_services can audit.
        drop(lock);

        for (name, labels) in to_stop {
            let Some(slot) = results.iter_mut().find(|r| r.sandbox == name) else {
                continue;
            };
            match self.pause_runtime(by, &name, "for host pause") {
                Ok(_) => {
                    slot.outcome = PauseOutcome::Paused;
                    slot.services = labels;
                }
                Err(e) => {
                    slot.outcome = PauseOutcome::WouldNotStop;
                    slot.error = Some(e.to_string());
                }
            }
        }

        let lock = self.state.lock()?;
        let outcome = pause_audit_outcome(&results);
        self.audit.finish_entry(&lock, entry, outcome)?;
        drop(lock);

        let host = self.derive_host_pause()?;
        Ok(PauseReport {
            sandboxes: results,
            host,
        })
    }

    /// Resumes runtime services for `scope` (whole host or named sandboxes).
    ///
    /// Never runs a runtime command, never writes into a sandbox home, and
    /// never applies pending policies (installs under the active snapshot).
    pub fn resume_sandboxes(
        &self,
        by: &Actor,
        scope: PauseScope,
        expected_revision: Option<u64>,
    ) -> Result<ResumeReport> {
        let lock = self.state.lock()?;
        if let PauseScope::Names(ref names) = scope {
            for name in dedup_names(names) {
                self.require_sandbox(&name)?;
            }
        }
        let current_host = self.state.host_pause()?;
        let current_rev = current_host.as_ref().map_or(0, |h| h.revision);
        if let Some(expected) = expected_revision
            && expected != current_rev
        {
            return Err(Error::PauseConflict {
                expected,
                found: current_rev,
            });
        }

        let subject = scope.subject();
        let ticket = self.audit.begin(
            &lock,
            Intent {
                by: by.clone(),
                command: "sandbox resume".to_owned(),
                target: Some(subject),
            },
        )?;
        let entry = ticket.into_entry();

        let Some(host_rec) = current_host else {
            self.audit.finish_entry(
                &lock,
                entry,
                Outcome::ok("no pause in force: nothing to resume"),
            )?;
            drop(lock);
            let host = self.derive_host_pause()?;
            return Ok(ResumeReport {
                no_record: true,
                sandboxes: Vec::new(),
                host,
            });
        };

        let targets: Vec<SandboxName> = match &scope {
            PauseScope::All => self
                .state
                .sandbox_pauses()?
                .into_iter()
                .map(|r| r.sandbox)
                .collect(),
            PauseScope::Names(names) => dedup_names(names),
        };

        enum ResumeAction {
            Install { paused: Paused, labels: Vec<String> },
            Done(ResumeOutcome),
        }

        let mut actions: Vec<(SandboxName, ResumeAction)> = Vec::with_capacity(targets.len());
        let mut results: Vec<SandboxResumeResult> = Vec::with_capacity(targets.len());

        for name in targets {
            let agents = self.tracked_agent_names(&name);
            let record = match self.state.get(&name)? {
                Some(r) => r,
                None => {
                    results.push(SandboxResumeResult {
                        sandbox: name,
                        outcome: ResumeOutcome::NothingToResume,
                        services: Vec::new(),
                        agents,
                        error: None,
                    });
                    continue;
                }
            };
            let row = self.state.sandbox_pause(&name)?;
            let installed_rt = self.installed_runtime_services(&name)?;
            let action = match row {
                None => {
                    if host_rec.pause_all {
                        // Named sandbox created while pause_all = 1: write a
                        // released empty row so it leaves coverage.
                        let t = now();
                        let rec = SandboxPauseRecord {
                            sandbox: name.clone(),
                            labels: Vec::new(),
                            kept: Vec::new(),
                            released: Some(t),
                            at: t,
                            by: by.clone(),
                        };
                        if let Err(e) = self.state.put_sandbox_pause(&lock, &rec, t) {
                            let _ = self.audit.finish_entry(
                                &lock,
                                entry,
                                Outcome::failed(e.to_string()),
                            );
                            return Err(e.into());
                        }
                    }
                    ResumeAction::Done(ResumeOutcome::NothingToResume)
                }
                Some(r) if r.released.is_some() => {
                    let owed = !r.labels.is_empty()
                        && matches!(record.state, SandboxState::Running)
                        && installed_rt.is_empty();
                    if !owed {
                        ResumeAction::Done(ResumeOutcome::NothingToResume)
                    } else {
                        if let Err(e) = self.state.release_sandbox_pause(&lock, &name, by, now()) {
                            let _ = self.audit.finish_entry(
                                &lock,
                                entry,
                                Outcome::failed(e.to_string()),
                            );
                            return Err(e.into());
                        }
                        match self.rebuild_paused(&record, &r) {
                            Ok(paused) => ResumeAction::Install {
                                paused,
                                labels: r.labels,
                            },
                            Err(e) => {
                                results.push(SandboxResumeResult {
                                    sandbox: name,
                                    outcome: ResumeOutcome::WouldNotStart,
                                    services: Vec::new(),
                                    agents,
                                    error: Some(format!(
                                        "{e}. Run `enclos sandbox resume` to try again"
                                    )),
                                });
                                continue;
                            }
                        }
                    }
                }
                Some(r) => {
                    // Intent-first: mark released BEFORE installing services.
                    if let Err(e) = self.state.release_sandbox_pause(&lock, &name, by, now()) {
                        let _ =
                            self.audit
                                .finish_entry(&lock, entry, Outcome::failed(e.to_string()));
                        return Err(e.into());
                    }
                    if r.labels.is_empty() {
                        ResumeAction::Done(ResumeOutcome::LeftAsItWas)
                    } else if !installed_rt.is_empty() {
                        ResumeAction::Done(ResumeOutcome::NothingToResume)
                    } else if !matches!(record.state, SandboxState::Running) {
                        ResumeAction::Done(ResumeOutcome::LeftAsItWas)
                    } else {
                        match self.rebuild_paused(&record, &r) {
                            Ok(paused) => ResumeAction::Install {
                                paused,
                                labels: r.labels,
                            },
                            Err(e) => {
                                results.push(SandboxResumeResult {
                                    sandbox: name,
                                    outcome: ResumeOutcome::WouldNotStart,
                                    services: Vec::new(),
                                    agents,
                                    error: Some(format!(
                                        "{e}. Run `enclos sandbox resume` to try again"
                                    )),
                                });
                                continue;
                            }
                        }
                    }
                }
            };

            match action {
                ResumeAction::Done(outcome) => results.push(SandboxResumeResult {
                    sandbox: name,
                    outcome,
                    services: Vec::new(),
                    agents,
                    error: None,
                }),
                install @ ResumeAction::Install { .. } => {
                    results.push(SandboxResumeResult {
                        sandbox: name.clone(),
                        outcome: ResumeOutcome::Resumed,
                        services: Vec::new(),
                        agents,
                        error: None,
                    });
                    actions.push((name, install));
                }
            }
        }

        // Release lock before calling resume_runtime_inner (which takes the lock
        // for `services start`).
        drop(lock);

        for (name, action) in actions {
            let ResumeAction::Install { paused, labels } = action else {
                continue;
            };
            let Some(slot) = results.iter_mut().find(|r| r.sandbox == name) else {
                continue;
            };
            match self.resume_runtime_inner(by, &name, &paused) {
                Ok(Some(_)) => {
                    slot.outcome = ResumeOutcome::Resumed;
                    slot.services = labels;
                }
                Ok(None) => {
                    slot.outcome = ResumeOutcome::LeftAsItWas;
                    slot.services = Vec::new();
                }
                Err(e) => {
                    slot.outcome = ResumeOutcome::WouldNotStart;
                    slot.error = Some(format!(
                        "its {} could not start again: {e}. Run `enclos sandbox resume {name}` to try again",
                        paused.names().join(" and ")
                    ));
                }
            }
        }

        let lock = self.state.lock()?;
        // Delete the whole record when no covered sandbox remains held or owed
        // AND (scope was All, or pause_all = 0). With pause_all = 1 a
        // `resume <name>` never deletes the record.
        let latest_host = self.state.host_pause()?;
        if let Some(latest_host) = latest_host {
            let all_rows = self.state.sandbox_pauses()?;
            let mut any_held_or_owed = false;
            for row in &all_rows {
                if row.released.is_none() {
                    any_held_or_owed = true;
                    break;
                }
                if !row.labels.is_empty()
                    && let Some(rec) = self.state.get(&row.sandbox)?
                {
                    let has_rt = !self.installed_runtime_services(&row.sandbox)?.is_empty();
                    let derived = derive_sandbox(
                        Some(&latest_host),
                        SandboxPauseInput {
                            name: &row.sandbox,
                            state: &rec.state,
                            has_runtime_services: has_rt,
                            row: Some(row),
                        },
                    );
                    if derived.owed {
                        any_held_or_owed = true;
                        break;
                    }
                }
            }
            if !any_held_or_owed && (matches!(scope, PauseScope::All) || !latest_host.pause_all) {
                self.state.clear_host_pause(&lock)?;
            }
        }

        let outcome = resume_audit_outcome(&results);
        self.audit.finish_entry(&lock, entry, outcome)?;
        drop(lock);

        let host = self.derive_host_pause()?;
        Ok(ResumeReport {
            no_record: false,
            sandboxes: results,
            host,
        })
    }

    /// Reads the host pause state for display without failing on an unreadable
    /// record: returns [`HostPauseRead::Unreadable`] instead of guessing `Running`.
    pub fn read_host_pause(&self) -> HostPauseRead {
        match self.derive_host_pause() {
            Ok(view) => HostPauseRead::Readable(view),
            Err(e) => HostPauseRead::Unreadable(e.to_string()),
        }
    }

    /// Reads the host pause record and derives the host-level pause view across
    /// every sandbox.
    pub fn derive_host_pause(&self) -> Result<HostPauseView> {
        let host = self.state.host_pause()?;
        let rows = self.state.sandbox_pauses()?;
        let row_map: BTreeMap<&SandboxName, &SandboxPauseRecord> =
            rows.iter().map(|r| (&r.sandbox, r)).collect();
        let records = self.state.list()?;
        let mut has_rt = Vec::with_capacity(records.len());
        for rec in &records {
            has_rt.push(!self.installed_runtime_services(&rec.name)?.is_empty());
        }
        let inputs: Vec<SandboxPauseInput<'_>> = records
            .iter()
            .zip(has_rt.iter())
            .map(|(rec, &rt)| SandboxPauseInput {
                name: &rec.name,
                state: &rec.state,
                has_runtime_services: rt,
                row: row_map.get(&rec.name).copied(),
            })
            .collect();
        Ok(derive_host(host.as_ref(), &inputs))
    }

    /// Derives the pause view for one sandbox given already-read pause records
    /// (or reads them if not provided).
    pub(super) fn derive_sandbox_pause(
        &self,
        record: &crate::model::sandbox::SandboxRecord,
        host: Option<&HostPauseRecord>,
        row: Option<&SandboxPauseRecord>,
    ) -> Result<SandboxPauseView> {
        let has_rt = !self.installed_runtime_services(&record.name)?.is_empty();
        Ok(derive_sandbox(
            host,
            SandboxPauseInput {
                name: &record.name,
                state: &record.state,
                has_runtime_services: has_rt,
                row,
            },
        ))
    }

    fn resolve_pause_targets(&self, scope: &PauseScope) -> Result<(bool, Vec<SandboxName>)> {
        match scope {
            PauseScope::All => {
                let names = self.state.list()?.into_iter().map(|r| r.name).collect();
                Ok((true, names))
            }
            PauseScope::Names(names) => {
                let dedup = dedup_names(names);
                for name in &dedup {
                    self.require_sandbox(name)?;
                }
                Ok((false, dedup))
            }
        }
    }

    fn tracked_agent_names(&self, sandbox: &SandboxName) -> Vec<String> {
        self.state
            .agents(sandbox)
            .map(|list| list.into_iter().map(|a| a.name.to_string()).collect())
            .unwrap_or_default()
    }

    fn rebuild_paused(
        &self,
        record: &crate::model::sandbox::SandboxRecord,
        row: &SandboxPauseRecord,
    ) -> Result<Paused> {
        let services = record
            .runtime
            .map(|kind| adapter(kind).services())
            .unwrap_or_default();
        let mut units = Vec::new();
        for label_str in &row.labels {
            let mut matched = None;
            for service in &services {
                let unit = Unit::Runtime(service.name);
                let expected = self.label(&record.name, unit)?;
                if expected.as_str() == label_str {
                    matched = Some(unit);
                    break;
                }
            }
            let unit = matched.ok_or_else(|| Error::Session {
                what: format!(
                    "sandbox `{}` has no runtime service `{label_str}` to start again",
                    record.name
                ),
            })?;
            units.push(unit);
        }
        let mut others = Vec::with_capacity(row.kept.len());
        for kept_str in &row.kept {
            let label = ServiceLabel::parse(kept_str).ok_or_else(|| Error::Session {
                what: format!("invalid kept service label `{kept_str}`"),
            })?;
            others.push(label);
        }
        Ok(Paused { units, others })
    }
}

fn dedup_names(names: &[SandboxName]) -> Vec<SandboxName> {
    let mut seen = Vec::with_capacity(names.len());
    for name in names {
        if !seen.contains(name) {
            seen.push(name.clone());
        }
    }
    seen
}

fn pause_audit_outcome(results: &[SandboxPauseResult]) -> Outcome {
    let failed: Vec<&str> = results
        .iter()
        .filter(|r| r.outcome == PauseOutcome::WouldNotStop)
        .map(|r| r.sandbox.as_str())
        .collect();
    let paused: Vec<&str> = results
        .iter()
        .filter(|r| r.outcome == PauseOutcome::Paused)
        .map(|r| r.sandbox.as_str())
        .collect();
    if !failed.is_empty() {
        return Outcome::failed(format!(
            "paused [{}]; would not stop: {}",
            paused.join(", "),
            failed.join(", ")
        ));
    }
    if paused.is_empty() {
        Outcome::ok("nothing to pause")
    } else {
        Outcome::ok(format!("paused {}", paused.join(", ")))
    }
}

fn resume_audit_outcome(results: &[SandboxResumeResult]) -> Outcome {
    let failed: Vec<&str> = results
        .iter()
        .filter(|r| r.outcome == ResumeOutcome::WouldNotStart)
        .map(|r| r.sandbox.as_str())
        .collect();
    let resumed: Vec<&str> = results
        .iter()
        .filter(|r| r.outcome == ResumeOutcome::Resumed)
        .map(|r| r.sandbox.as_str())
        .collect();
    if !failed.is_empty() {
        return Outcome::failed(format!(
            "resumed [{}]; would not start: {}",
            resumed.join(", "),
            failed.join(", ")
        ));
    }
    if resumed.is_empty() {
        Outcome::ok("nothing to resume")
    } else {
        Outcome::ok(format!("resumed {}", resumed.join(", ")))
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
