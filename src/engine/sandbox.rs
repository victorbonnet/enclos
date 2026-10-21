//! The engine's sandbox calls: create, list, show, remove and stop
//! (design §8, §10).

use super::Engine;
use super::service::IfUnrecorded;
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
use crate::policy;
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

/// What a sandbox's folder held before `sandbox create` wrote to it, so
/// that a failed create can put it back.
enum Before {
    /// No folder: the create makes it.
    Nothing,
    /// A folder without `policy.toml`, such as one left by a create that
    /// stopped before writing it.
    Folder,
    /// A folder and the `policy.toml` it held, such as one kept by
    /// `sandbox rm --keep-data`.
    Kept(String),
}

impl Engine {
    /// Creates a sandbox: its folder and home, its `policy.toml` from the
    /// template, then its record, with a proxy port, and version 1 of its
    /// policy in one transaction.
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
                // The backend must run here (ADR 0009), and the template
                // must resolve, before any file or record is written. A new
                // sandbox has no runtime, so no adapter layer.
                let name = spec.name.as_str();
                self.backend_for(&spec.name, spec.backend)?;
                let overrides = policy::initial_overrides(name, &spec.template);
                let snapshot = self.checked_policy_with(&spec.name, &overrides, None)?;
                let record = SandboxRecord {
                    name: spec.name.clone(),
                    backend: spec.backend,
                    template: spec.template.clone(),
                    state: SandboxState::Created,
                    proxy_port: self.free_port()?,
                    runtime: None,
                    created_at: now(),
                };
                // The folder first, then the record and version 1 of its
                // policy in one transaction. A crash in between leaves only
                // the folder, which the next create of this name reuses as it
                // does one kept by `sandbox rm --keep-data`: its home is kept
                // and its `policy.toml` written again from the template
                // (design §11).
                let before = self.before_create(name)?;
                let made = (|| -> Result<()> {
                    self.layout.create_sandbox_dirs(name)?;
                    self.layout.write_policy(name, &overrides)?;
                    self.state.create_sandbox(lock, &record, &snapshot, by)?;
                    Ok(())
                })();
                if let Err(error) = made {
                    return Err(match self.undo_create(name, before) {
                        Ok(()) => error,
                        Err(left) => Error::CleanupFailed {
                            error: Box::new(error),
                            left,
                        },
                    });
                }
                Ok(record)
            },
        )?;
        Ok(Planned::Done(record))
    }

    /// What the sandbox's folder holds before `sandbox create` writes to
    /// it. Only a missing `policy.toml` counts as none: one that cannot be
    /// read stops the create before anything is written, since its undo
    /// could not put it back.
    fn before_create(&self, name: &str) -> Result<Before> {
        match self.layout.read_policy(name) {
            Ok(policy) => Ok(Before::Kept(policy)),
            Err(LayoutError::Io { source, .. })
                if source.kind() == std::io::ErrorKind::NotFound =>
            {
                let dir = self.layout.sandbox_dir(name);
                match dir.try_exists() {
                    Ok(true) => Ok(Before::Folder),
                    Ok(false) => Ok(Before::Nothing),
                    Err(source) => Err(LayoutError::Io { path: dir, source }.into()),
                }
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Takes back what a failed create wrote: the folder it made, or the
    /// `policy.toml` it wrote into a folder that was there before. A kept
    /// home stays as it is, with any `home/tmp` the create added. Returns
    /// what it could not take back.
    fn undo_create(&self, name: &str, before: Before) -> std::result::Result<(), String> {
        let gone = |path: &Path, removed: std::io::Result<()>| match removed {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                Err(format!("{} ({e})", path.display()))
            }
            _ => Ok(()),
        };
        match before {
            Before::Nothing => {
                let dir = self.layout.sandbox_dir(name);
                gone(&dir, std::fs::remove_dir_all(&dir))
            }
            Before::Folder => {
                let file = self.layout.policy_file(name);
                gone(&file, std::fs::remove_file(&file))
            }
            Before::Kept(policy) => self.layout.write_policy(name, &policy).map_err(|e| {
                format!(
                    "{} with the template's policy in place of the kept one ({e})",
                    self.layout.policy_file(name).display()
                )
            }),
        }
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
        // record its end, and audited on its own. A damaged audit log would
        // refuse the audited stop after the removal, so it is checked before.
        self.audit.check()?;
        let services = self
            .remove_services(by, name, "for sandbox stop", IfUnrecorded::Stop)?
            .into_result()?;
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
