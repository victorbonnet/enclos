//! The engine's sandbox calls: create, list, show, remove and stop
//! (design §8, §10).

use super::Engine;
use super::service::IfUnrecorded;
use super::session::{Held, marked_in};
use crate::error::{Error, Result};
use crate::layout::LayoutError;
use crate::lifecycle::members::{is_gone, members};
use crate::lifecycle::process::processes;
use crate::lifecycle::stop::{GRACE, Stopped, Survivor, stop};
use crate::model::audit::Actor;
use crate::model::now;
use crate::model::plan::{Confirm, Plan, Planned};
use crate::model::policy::{PendingPolicy, PolicyVersion, TemplateName};
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
    /// The change waiting for a restart, if any (design §7).
    pub pending: Option<PendingPolicy>,
    /// Why enclos now refuses to compile the active policy, if it does: see
    /// [`compile_refused`].
    pub policy_refused: Option<String>,
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

impl StopReport {
    /// The sessions whose end the stop records.
    fn ended(&self) -> Vec<SessionId> {
        self.stopped.iter().chain(&self.gone).copied().collect()
    }
}

impl SessionView {
    /// Nothing of the session runs any more, as after a crash or a restart
    /// of the Mac, but its end is not recorded: `show` reads and changes
    /// nothing, and `sandbox stop` or `sandbox rm` records it.
    pub fn gone(&self) -> bool {
        self.members.is_empty()
    }
}

/// What stopping a sandbox did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StopReport {
    /// The services removed, so they do not start again.
    pub services: Vec<ServiceLabel>,
    /// Sessions whose members it stopped.
    pub stopped: Vec<SessionId>,
    /// Sessions of which nothing ran any more, whose end it recorded.
    pub gone: Vec<SessionId>,
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
    pub(super) fn active_compiled(&self, record: &SandboxRecord) -> Result<PathBuf> {
        self.compiled_file(&record.name, record.proxy_port)
            .map(|(file, _)| file)
    }

    fn view(&self, record: SandboxRecord) -> Result<SandboxView> {
        let policy = self.state.active_policy(&record.name)?.map(|(v, _)| v);
        let pending = self.state.pending_policy(&record.name)?.map(|(p, _)| p);
        let compiled = self.active_compiled(&record);
        let active = compiled.as_ref().ok().map(PathBuf::as_path);
        let sessions = self
            .state
            .sessions(&record.name, true)?
            .into_iter()
            .map(|session| {
                let members = members(&self.marked(&session)?)?;
                let needs_restart = needs_restart(&session, active);
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
            pending,
            policy_refused: compile_refused(&compiled),
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
                .map(|v| match v.gone() {
                    true => format!(
                        "record the end of session {} ({}), whose processes are gone",
                        v.session.id,
                        v.session.kind.as_str()
                    ),
                    false => format!(
                        "stop session {} ({}, {} processes)",
                        v.session.id,
                        v.session.kind.as_str(),
                        v.members.len()
                    ),
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
        let summary = |r: &StopReport| {
            let done = match r.survivors.is_empty() {
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
            format!("{done}{}", ended_gone(&r.gone))
        };
        // Which sessions still run, looked at before the services are
        // removed: a session a service ran (the proxy service's always)
        // ends with its service, and is stopped, not found gone. A listing
        // that fails tells none apart, so none is said to be gone; the stop
        // below looks again, and fails on its own if it still cannot.
        let open = self.state.sessions(name, true)?;
        // What holds a marker is a member too (ADR 0030), looked at after
        // the listing (see `Engine::marked`); a failed look at either is as
        // a failed listing.
        let looked = (|| -> Result<Vec<SessionId>> {
            let procs = processes()?;
            let held = match open.is_empty() {
                true => Held::new(),
                false => self.held(name)?,
            };
            Ok(open
                .iter()
                .filter(|s| {
                    let mut marked = (*s).clone();
                    marked.tracked = marked_in(s, &s.tracked, &procs, &held);
                    !is_gone(&procs, &marked)
                })
                .map(|s| s.id)
                .collect())
        })();
        let ran: Vec<SessionId> = match looked {
            Ok(ran) => ran,
            Err(_) => open.iter().map(|s| s.id).collect(),
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
                    gone: Vec::new(),
                    survivors: Vec::new(),
                };
                let mut cannot_look: Option<Error> = None;
                let sessions = self.state.sessions(name, true)?;
                for session in &sessions {
                    // Its marker looked at here, after the services are
                    // removed, and again once it stopped.
                    match self.stop_marked(session, GRACE, stop) {
                        // Nothing of it ran before this stop either: it ended
                        // with nothing to record its end (a crash, a restart
                        // of the Mac, `enclos` killed), which the audit entry
                        // tells apart.
                        Ok(Stopped::Gone) if !ran.contains(&session.id) => {
                            report.gone.push(session.id)
                        }
                        Ok(Stopped::Gone | Stopped::Clean) => report.stopped.push(session.id),
                        Ok(Stopped::Survivors(left)) => report.survivors.push((session.id, left)),
                        // Without a listing, nothing shows the members are
                        // gone: this session and those after it stay open.
                        Err(e) => {
                            cannot_look = Some(e);
                            break;
                        }
                    }
                }
                record.state = match (&cannot_look, report.survivors.is_empty()) {
                    (Some(e), _) => SandboxState::Failed {
                        reason: format!("stop could not look at processes: {e}"),
                    },
                    (None, true) => SandboxState::Stopped,
                    (None, false) => SandboxState::Failed {
                        reason: "members survived stop".to_owned(),
                    },
                };
                // The ends and the state in one transaction, so that a crash
                // or a failed write never leaves every session ended and the
                // sandbox still running.
                let saved = self.state.end_sessions(lock, &report.ended(), &record);
                match (cannot_look, saved) {
                    (None, saved) => {
                        saved?;
                        let ended = report.ended();
                        for session in sessions.iter().filter(|s| ended.contains(&s.id)) {
                            self.forget_marker(session);
                        }
                        Ok(report)
                    }
                    (Some(e), Ok(())) => Err(e),
                    (Some(e), Err(saved)) => Err(Error::CleanupFailed {
                        error: Box::new(e),
                        left: format!(
                            "sandbox {name} not marked failed, and the end of sessions {} not recorded ({saved})",
                            join_ids(&report.ended())
                        ),
                    }),
                }
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
    ) -> Result<Planned<Vec<String>>> {
        let gone = self.require_stopped(name)?;
        let dir = self.layout.sandbox_dir(name.as_str());
        let what = if keep_data {
            "remove its record"
        } else {
            "delete its folder and home"
        };
        match confirm {
            Confirm::DryRun => {
                let mut changes: Vec<String> = gone
                    .iter()
                    .map(|id| format!("record the end of session {id}, whose processes are gone"))
                    .collect();
                changes.push(format!("remove sandbox {name}: {what} ({})", dir.display()));
                return Ok(Planned::DryRun(Plan {
                    changes,
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
        let (_, secrets_left) = self.write(
            by,
            "sandbox rm",
            Some(name.to_string()),
            |(gone, left): &(Vec<SessionId>, Vec<String>)| {
                let left = match left.as_slice() {
                    [] => String::new(),
                    left => format!(
                        "; could not remove from the secret store: {}",
                        left.join(", ")
                    ),
                };
                format!("{what}{}{left}", ended_gone(gone))
            },
            |lock| {
                // Checked again under the lock: a `connect` may have started
                // while this command waited for it.
                let gone = self.require_stopped(name)?;
                // Its secrets go with it, kept data or not: their record goes
                // with the sandbox's.
                let secrets = self.state.secrets(name)?;
                // The sessions' rows go with the record: only the audit
                // entry keeps their ends.
                self.state.remove(lock, name)?;
                let left = self.forget_secrets(&secrets);
                if !keep_data && dir.exists() {
                    std::fs::remove_dir_all(&dir).map_err(|source| LayoutError::Io {
                        path: dir.clone(),
                        source,
                    })?;
                }
                Ok((gone, left))
            },
        )?;
        Ok(Planned::Done(secrets_left))
    }

    /// Refuses a sandbox with services installed or sessions running, saying
    /// how to end them. Returns the open sessions of which nothing runs any
    /// more, whose end is left to record.
    fn require_stopped(&self, name: &SandboxName) -> Result<Vec<SessionId>> {
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
        let open = self.state.sessions(name, true)?;
        if open.is_empty() {
            return Ok(Vec::new());
        }
        let procs = processes()?;
        let held = self.held(name)?;
        if open.iter().all(|s| {
            let mut marked = s.clone();
            marked.tracked = marked_in(s, &s.tracked, &procs, &held);
            is_gone(&procs, &marked)
        }) {
            return Ok(open.iter().map(|s| s.id).collect());
        }
        let name = name.to_string();
        Err(match record.state {
            SandboxState::Failed { reason } => Error::SandboxNotStopped { name, reason },
            _ => Error::SandboxRunning { name },
        })
    }
}

/// What an audit summary adds for the sessions of which nothing ran any
/// more, whose end the command recorded.
fn ended_gone(gone: &[SessionId]) -> String {
    match gone {
        [] => String::new(),
        ids => format!(
            "; recorded the end of sessions {}, whose processes were gone",
            join_ids(ids)
        ),
    }
}

fn join_ids(ids: &[SessionId]) -> String {
    ids.iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

/// Why enclos refuses to compile the active policy because a path changed
/// since it was stored (design §5): nothing new starts in the sandbox until
/// the user fixes it, while what already runs keeps the policy it started
/// with. Other failures, such as a backend this host cannot run, are told
/// where the sandbox is started.
pub(super) fn compile_refused(compiled: &Result<PathBuf>) -> Option<String> {
    match compiled {
        Err(e @ (Error::HomeNotAFolder { .. } | Error::ActivePolicyInvalid { .. })) => {
            Some(e.to_string())
        }
        _ => None,
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
