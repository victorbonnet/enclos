//! The engine's runtime calls: install a runtime in a sandbox (design §9
//! "Runtime adapter"). What the install puts beside the home is in
//! `staging.rs`, and a runtime's agents are in `agents.rs`. Logging it in is
//! the runtime's own command, through `enclos connect` (ADR 0024).

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use super::Engine;
use super::policy::{adapter_layer, differences, listen_change};
use super::releases::{LatestRelease, Releases};
use super::service::STOP_GRACE;
use super::session::{END_WAIT, SessionEnd, UpdateLog, spoken};
use super::status::{Fact, bridge_activity};
use super::usage::{Removed, read_report};
use crate::bridge::ids::new_id;
use crate::error::{Error, Result};
use crate::model::audit::{Actor, Outcome};
use crate::model::count;
use crate::model::now;
use crate::model::plan::{Confirm, Plan, Planned};
use crate::model::policy::PolicyVersion;
use crate::model::runtime::{RuntimeKind, RuntimeVersion};
use crate::model::sandbox::{BackendKind, SandboxName, SandboxState};
use crate::policy::file::PolicyFile;
use crate::runtime::{RuntimeAdapter, adapter};

/// How `runtime install` ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallEnd {
    pub kind: RuntimeKind,
    /// How the installer's session ended.
    pub end: SessionEnd,
    /// Whether this install succeeded: its installer exited 0, and the
    /// runtime is recorded because of it.
    pub installed: bool,
    /// The runtime the sandbox records afterwards. After a failed install it
    /// is the one it had before, and the active policy allows that runtime's
    /// destinations only: none after a failed first install, this runtime
    /// after a failed reinstall.
    pub recorded: Option<RuntimeKind>,
    /// The sandbox's active policy version afterwards.
    pub policy: u32,
    /// What a person runs in the sandbox to log `kind` in and set it up,
    /// even after a failed install.
    pub login: String,
    /// The install's time limit, when its installer was still running then
    /// and was stopped: the install failed.
    pub stopped_after: Option<Duration>,
    /// After an install, the version the runtime reported and enclos
    /// recorded, for a runtime whose home holds none enclos reads (ADR
    /// 0074, proposed); or why it was not recorded. None when not asked.
    pub version: Option<std::result::Result<RuntimeVersion, String>>,
}

/// How long an install whose installer runs past its time limit
/// ([`Engine::install_runtime_within`]) may take after it to stop it and
/// record that: TERM then KILL, `STOP_GRACE` each, to the session's
/// members, the same to what they left running, the session's end, which
/// waits for the state lock up to `END_WAIT`, then the undo, with a minute
/// to spare.
pub const INSTALL_STOP_TIME: Duration =
    Duration::from_secs(4 * STOP_GRACE.as_secs() + END_WAIT.as_secs() + 60);

/// How long a runtime's version command may run after an install: it
/// answers at once, or something is wrong. Within an install's time limit,
/// it is stopped at that limit too, so the install still ends within
/// [`INSTALL_STOP_TIME`] of it.
pub const VERSION_TIME: Duration = Duration::from_secs(30);

impl InstallEnd {
    /// How the installer ended, as a person reads it after "the installer".
    pub fn ended(&self) -> String {
        match (self.stopped_after, self.end.signal) {
            (Some(limit), _) => {
                format!("did not finish within {} and was stopped", spoken(limit))
            }
            (None, Some(signal)) => format!("was ended by signal {signal}"),
            (None, None) => format!("exited with {}", self.end.exit),
        }
    }
}

/// The state of the sandbox's services after `enclos runtime update` (ADR 0074).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServicesAfter {
    /// The sandbox had services installed before the update, and they were
    /// started again afterwards.
    StartedAgain,
    /// The sandbox was running with no services installed — the state after
    /// `enclos runtime install`, or a `connect`, without a `sandbox start` —
    /// so the update ended its sessions and left it running with none.
    NotInstalledRunning,
    /// The sandbox was stopped with no services installed, and stays so.
    NotInstalled,
}

impl ServicesAfter {
    /// How the JSON output describes the services after the update (A12).
    pub fn as_str(self) -> &'static str {
        match self {
            ServicesAfter::StartedAgain => "started again",
            ServicesAfter::NotInstalledRunning => {
                "not installed (the sandbox runs without services)"
            }
            ServicesAfter::NotInstalled => "not installed (the sandbox was stopped)",
        }
    }
}

/// What running work the bridge's activity store reports for a sandbox
/// before `enclos runtime update` stops its services (ADR 0074).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunningWork {
    /// The bridge's activity store was read (or no bridge runs), and these
    /// `<sandbox>/<agent>` entries were reported active.
    Count { count: usize, agents: Vec<String> },
    /// The activity store could not be read; never reported as 0.
    Unknown(String),
}

/// What `enclos runtime update` tells the person in text mode before the
/// updater runs (ADR 0074).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdatePreflight {
    pub kind: RuntimeKind,
    /// Adapter destinations the active policy cannot reach on port 443.
    pub policy_missing: Vec<String>,
    /// The latest release kept for this runtime (`Releases::kept()`), if any.
    pub release: Option<LatestRelease>,
    /// Running work reported by the bridge's activity store.
    pub running_work: RunningWork,
}

/// How `enclos runtime update` ended (ADR 0074).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateEnd {
    pub kind: RuntimeKind,
    /// Whether the updater succeeded and the version read back differs from
    /// the one before.
    pub updated: bool,
    /// Whether the updater exited 0 and was not stopped at its time limit.
    pub succeeded: bool,
    /// The version read before the update, when readable.
    pub before: Option<RuntimeVersion>,
    /// The version read after a successful update, or why it could not be
    /// read; `None` when the updater failed or the runtime provides none.
    pub after: Option<std::result::Result<RuntimeVersion, String>>,
    /// How the updater's session ended (the last one when the runtime runs
    /// more than one command).
    pub session: SessionEnd,
    /// The latest release kept for this runtime (`Releases::kept()`), if any.
    pub release: Option<LatestRelease>,
    /// The sandbox's active policy version, unchanged by the update.
    pub policy: u32,
    /// Adapter destinations the active policy cannot reach on port 443.
    pub policy_missing: Vec<String>,
    /// The sandbox's services afterwards.
    pub services: ServicesAfter,
    /// Running work reported by the bridge's activity store before the update.
    pub running_work: RunningWork,
    /// The update's time limit, when the updater was still running then and
    /// was stopped.
    pub stopped_after: Option<Duration>,
    /// The host path of the updater's log (`<logs>/update.log`).
    pub log: PathBuf,
}

impl UpdateEnd {
    /// How the updater ended, as a person reads it after "the <runtime> updater".
    pub fn ended(&self) -> String {
        ended_text(self.stopped_after, &self.session)
    }
}

/// Formats how an updater session ended, matching `InstallEnd::ended` and
/// spelling whole hours as `1 hour` / `N hours` (spec §3.3).
fn ended_text(stopped_after: Option<Duration>, end: &SessionEnd) -> String {
    match (stopped_after, end.signal) {
        (Some(limit), _) => {
            let secs = limit.as_secs();
            let span = if secs > 0 && secs.is_multiple_of(3600) {
                count((secs / 3600) as usize, "hour", "hours")
            } else {
                spoken(limit)
            };
            format!("did not finish within {span} and was stopped")
        }
        (None, Some(signal)) => format!("was ended by signal {signal}"),
        (None, None) => format!("exited with {}", end.exit),
    }
}

/// What an install would change, worked out without changing anything.
struct InstallPlan {
    /// The sandbox's `policy.toml`.
    overrides: String,
    active: u32,
    /// The runtime's destinations the active policy does not allow yet.
    added: Vec<String>,
    /// Whether the runtime's layer turns listening on, and the new policy
    /// listens where the active one does not (ADR 0028).
    listens: bool,
    /// Whether the runtime's layer turns listening on and `policy.toml`
    /// keeps it off, so the runtime's service cannot start.
    listen_kept_off: bool,
    /// What else the new version changes: edits to `policy.toml` not
    /// applied yet, or a newer template or built-in defaults.
    also: Vec<String>,
    proxy_runs: bool,
    /// The sandbox's backend: its host, as the plan names it, where the
    /// installer is downloaded, and who reaches what the sandbox listens on.
    backend: BackendKind,
}

impl Engine {
    /// The runtime installed in the sandbox.
    pub(super) fn runtime_of(&self, name: &SandboxName) -> Result<RuntimeKind> {
        let record = self.state.get(name)?.ok_or_else(|| Error::NoSuchSandbox {
            name: name.to_string(),
        })?;
        record.runtime.ok_or_else(|| Error::Session {
            what: format!("sandbox {name} has no runtime yet. Install one with `enclos runtime install hermes --sandbox {name}`"),
        })
    }

    /// The runtime installed in the sandbox, if any.
    pub fn runtime(&self, name: &SandboxName) -> Result<Option<RuntimeKind>> {
        let record = self.state.get(name)?.ok_or_else(|| Error::NoSuchSandbox {
            name: name.to_string(),
        })?;
        Ok(record.runtime)
    }

    /// Installs `kind` in the sandbox (ADR 0020): its destinations join the
    /// policy, its installer is downloaded on the host, as the runtime serves
    /// it then (ADR 0029), and run inside the sandbox, through the proxy, in
    /// this terminal. The audit entry names the installer's SHA-256. The runtime is recorded as installed only when the
    /// installer exits 0; otherwise the record keeps the runtime it had and
    /// the policy is resolved again from `policy.toml` with that runtime's
    /// destinations. Files written in the home stay either way.
    pub fn install_runtime(
        &self,
        by: &Actor,
        name: &SandboxName,
        kind: RuntimeKind,
        confirm: Confirm,
    ) -> Result<Planned<InstallEnd>> {
        self.install_runtime_with(by, name, adapter(kind).as_ref(), confirm)
    }

    /// [`Engine::install_runtime`], for a caller nobody watches, such as
    /// the mobile app's bridge: an installer still running `limit` after
    /// the install began, its download included, is stopped, with every process it started whatever its process
    /// group, its session's end is recorded, and the install fails, undone
    /// as when the installer exits non-zero. This takes up to
    /// [`INSTALL_STOP_TIME`] more.
    pub fn install_runtime_within(
        &self,
        by: &Actor,
        name: &SandboxName,
        kind: RuntimeKind,
        confirm: Confirm,
        limit: Duration,
    ) -> Result<Planned<InstallEnd>> {
        let runtime = adapter(kind);
        self.install_runtime_limited(by, name, runtime.as_ref(), confirm, Some(limit))
    }

    /// `install_runtime` with the adapter given, so tests can install from
    /// a file of their own.
    pub(crate) fn install_runtime_with(
        &self,
        by: &Actor,
        name: &SandboxName,
        runtime: &dyn RuntimeAdapter,
        confirm: Confirm,
    ) -> Result<Planned<InstallEnd>> {
        self.install_runtime_limited(by, name, runtime, confirm, None)
    }

    /// `install_runtime_with`, stopping the installer `limit` after now.
    pub(crate) fn install_runtime_limited(
        &self,
        by: &Actor,
        name: &SandboxName,
        runtime: &dyn RuntimeAdapter,
        confirm: Confirm,
        limit: Option<Duration>,
    ) -> Result<Planned<InstallEnd>> {
        let deadline = limit.map(|limit| Instant::now() + limit);
        let kind = runtime.kind();
        let plan = self.plan_install(name, runtime)?;
        match confirm {
            Confirm::DryRun => return Ok(Planned::DryRun(plan.describe(name, runtime))),
            Confirm::Ask if !plan.also.is_empty() => {
                return Err(needs_confirmation(kind, name, &plan.also));
            }
            _ => {}
        }
        // Outside the lock: a download takes long and changes no state. The
        // installer lands beside the home, where the sandbox cannot write.
        let (command, sha256) = self.stage_install(name, runtime)?;
        let target = format!("{name} {kind}");
        let version = self.write(
            by,
            "runtime install",
            Some(target.clone()),
            |v: &PolicyVersion| format!("policy v{}, installer sha256 {sha256}", v.version),
            |lock| {
                // Checked again under the lock: the policy may have changed.
                let plan = self.plan_install(name, runtime)?;
                if confirm == Confirm::Ask && !plan.also.is_empty() {
                    return Err(needs_confirmation(kind, name, &plan.also));
                }
                self.save_policy_for_runtime(lock, by, name, &plan.overrides, Some(kind))
            },
        )?;
        let ran = match deadline {
            None => self
                .run_in_sandbox(by, name, command, "runtime installer")
                .map(|end| (end, false)),
            Some(deadline) => {
                self.run_in_sandbox_within(by, name, command, "runtime installer", deadline)
            }
        };
        let (end, timed_out) = match ran {
            Ok(ran) => ran,
            Err(e) => {
                self.undo_install(by, name, kind, &e.to_string())?;
                return Err(e);
            }
        };
        // Told to end, it failed, even if it then exited 0: it may have
        // trapped TERM and stopped halfway.
        let stopped_after = limit.filter(|_| timed_out);
        if end.exit != 0 || stopped_after.is_some() {
            let mut failed = InstallEnd {
                kind,
                end,
                installed: false,
                recorded: None,
                policy: 0,
                login: runtime.login(),
                stopped_after,
                version: None,
            };
            let why = format!("the installer {}", failed.ended());
            (failed.policy, failed.recorded) = self.undo_install(by, name, kind, &why)?;
            return Ok(Planned::Done(failed));
        }
        self.write(
            by,
            "runtime installed",
            Some(target),
            |_| "recorded".to_owned(),
            |lock| {
                let mut record = self.state.get(name)?.ok_or_else(|| Error::NoSuchSandbox {
                    name: name.to_string(),
                })?;
                record.runtime = Some(kind);
                self.state.put(lock, &record)?;
                // A change made while the installer ran was resolved without
                // the runtime's destinations, as it was not recorded yet.
                self.resolve_with_runtime(lock, by, name)
                    .map_err(|error| Error::FailedAfter {
                        error: Box::new(error),
                        done: format!(
                            "recording {kind} as installed in sandbox {name}; a policy change made while its installer ran was not resolved again with {kind}'s destinations, which the next change of the policy, such as `enclos policy edit {name}`, does"
                        ),
                    })
            },
        )?;
        let reported = self
            .record_reported_version(by, name, runtime, deadline)
            .transpose();
        Ok(Planned::Done(InstallEnd {
            kind,
            end,
            installed: true,
            recorded: Some(kind),
            policy: version.version,
            login: runtime.login(),
            stopped_after: None,
            version: reported,
        }))
    }

    /// Read-only preflight for `enclos runtime update` (ADR 0074): checks the
    /// same preconditions as [`Engine::update_runtime`] and returns what text
    /// mode prints before the updater starts.
    pub fn update_preflight(&self, name: &SandboxName) -> Result<UpdatePreflight> {
        let kind = self.runtime_of(name)?;
        let active = self.policy(name)?;
        // The update writes no policy and its session runs under the active
        // snapshot from `state.db`, so nothing is "resolved" by it; it refuses
        // because the person's waiting change must not be overrun by a
        // lifecycle action.
        if active.pending.is_some() {
            return Err(Error::PolicyPending {
                sandbox: name.to_string(),
            });
        }
        self.check_start_limits(name)?;
        let runtime = adapter(kind);
        let policy_missing = self.unreachable_destinations(name, runtime.as_ref())?;
        let release = match Releases::kept().of(self, runtime.as_ref(), now()) {
            Fact::Known(r) => Some(r),
            _ => None,
        };
        let running_work = self.running_work(name);
        Ok(UpdatePreflight {
            kind,
            policy_missing,
            release,
            running_work,
        })
    }

    /// Updates the sandbox's runtime with its own updater, stopping its
    /// services and sessions first and starting its services again afterwards
    /// when they were installed (ADR 0074).
    pub fn update_runtime(
        &self,
        by: &Actor,
        name: &SandboxName,
        confirm: Confirm,
    ) -> Result<Planned<UpdateEnd>> {
        let kind = self.runtime_of(name)?;
        self.update_runtime_with(by, name, adapter(kind).as_ref(), confirm)
    }

    /// [`Engine::update_runtime`], stopping the updater and every process it
    /// started after `limit`, for a caller with nobody watching such as the
    /// mobile app's bridge (ADR 0074).
    pub fn update_runtime_within(
        &self,
        by: &Actor,
        name: &SandboxName,
        confirm: Confirm,
        limit: Duration,
    ) -> Result<Planned<UpdateEnd>> {
        let kind = self.runtime_of(name)?;
        self.update_runtime_limited(by, name, adapter(kind).as_ref(), confirm, Some(limit))
    }

    /// `update_runtime` against `runtime`, so tests can substitute an adapter
    /// whose updater is a stand-in.
    pub(crate) fn update_runtime_with(
        &self,
        by: &Actor,
        name: &SandboxName,
        runtime: &dyn RuntimeAdapter,
        confirm: Confirm,
    ) -> Result<Planned<UpdateEnd>> {
        self.update_runtime_limited(by, name, runtime, confirm, None)
    }

    /// `update_runtime_with`, stopping the updater `limit` after now.
    pub(crate) fn update_runtime_limited(
        &self,
        by: &Actor,
        name: &SandboxName,
        runtime: &dyn RuntimeAdapter,
        confirm: Confirm,
        limit: Option<Duration>,
    ) -> Result<Planned<UpdateEnd>> {
        let kind = self.runtime_of(name)?;
        let active = self.policy(name)?;
        // The update writes no policy and its session runs under the active
        // snapshot from `state.db`, so nothing is "resolved" by it; it refuses
        // because the person's waiting change must not be overrun by a
        // lifecycle action.
        if active.pending.is_some() {
            return Err(Error::PolicyPending {
                sandbox: name.to_string(),
            });
        }
        self.check_start_limits(name)?;
        // What the sandbox was doing when the update began. Step 9 puts it
        // back to this, and the dry run says what it would do with it. The
        // state read again after the updater ran cannot say what the sandbox
        // was: the update's own steps leave their mark on it (F1 — a session
        // that cannot start recorded it `Failed`, and reading that as "stopped
        // by the person" left a running sandbox failed with no services).
        let was_running = self.record(name)?.state == SandboxState::Running;
        let installed = self.has_services(name)?;
        if confirm == Confirm::DryRun {
            return Ok(Planned::DryRun(plan_update(
                name,
                kind,
                active.version.version,
                installed,
                was_running,
            )));
        }

        let before = match self.current_version(name, runtime) {
            Fact::Known(v) => RuntimeVersion::new(&v),
            _ => None,
        };
        let policy_missing = self.unreachable_destinations(name, runtime)?;
        let release = match Releases::kept().of(self, runtime, now()) {
            Fact::Known(r) => Some(r),
            _ => None,
        };
        let running_work = self.running_work(name);

        let update = runtime.update();
        let mut commands = Vec::new();
        let mut installer_sha256 = None;
        if update.installer {
            // Outside the lock and before stopping services: a download takes
            // long and changes no state.
            let (cmd, sha256) = self.stage_install(name, runtime)?;
            installer_sha256 = Some(sha256);
            commands.push(cmd);
        }
        commands.extend(update.commands);
        if commands.is_empty() {
            return Err(Error::Session {
                what: format!("{kind} has no updater"),
            });
        }

        let log_path = self.update_log(name);
        let mut update_log = UpdateLog::new(log_path.clone())?;
        let deadline = limit.map(|l| Instant::now() + l);

        // Step 6: stop the sandbox's services and end its sessions.
        self.stop_services_and_sessions(by, name)?;

        // Step 7: run the updater command(s) in order. On any error, still
        // start the services again when they were installed.
        let mut last_end: Option<SessionEnd> = None;
        let mut succeeded = true;
        let mut stopped_after = None;
        for cmd in commands {
            let ran = self.run_update_in_sandbox(
                by,
                name,
                cmd,
                "runtime updater",
                deadline,
                &mut update_log,
            );
            let (end, timed_out) = match ran {
                Ok(ran) => ran,
                Err(error) => {
                    // The sandbox goes back to what it was before the update
                    // began: the services start again on what the updater
                    // left, as `sandbox start` starts them, unless it was
                    // stopped, or was stopped meanwhile — then it stays
                    // stopped and what the run left open is ended (ADR 0074).
                    // Whether it was running is the state from before step 6;
                    // the state read here only answers "was it stopped
                    // meanwhile", because this failure may itself have
                    // recorded `Failed` (F1: a session that cannot start is
                    // not the sandbox failing).
                    let stopped = self
                        .record(name)
                        .map(|r| stopped_since(&r.state, was_running))
                        .unwrap_or(!was_running);
                    let mut note = None;
                    if installed && was_running && !stopped {
                        if let Err(e) = self.start_sandbox(by, name) {
                            note = Some(format!("its services were not started again ({e})"));
                        }
                    } else if !was_running || stopped {
                        if let Err(e) = self.stop_services_and_sessions(by, name) {
                            note = Some(format!("its sessions were not ended ({e})"));
                        }
                    }
                    // A6: the run is in the audit log as failed, with the
                    // reason the person sees, even though it never reaches
                    // step 10 — no version was recorded and there is no
                    // session to report.
                    let reason = match &note {
                        Some(note) => format!("{error}; {note}"),
                        None => error.to_string(),
                    };
                    let target = Some(format!("{name} {kind}"));
                    let _ = self.write_with_outcome(
                        by,
                        "runtime update",
                        target,
                        |_| Outcome::failed(reason),
                        |_| Ok(()),
                    );
                    return Err(error);
                }
            };
            let stopped = limit.filter(|_| timed_out);
            let failed = end.exit != 0 || stopped.is_some();
            last_end = Some(end);
            if failed {
                succeeded = false;
                stopped_after = stopped;
                break;
            }
        }
        let session = last_end.expect("updater commands was non-empty");

        // Step 8: record the version the runtime then reports, only when the
        // updater succeeded. Never forget the previously recorded version on
        // failure (A3, A5, Q2).
        let after = if succeeded {
            if runtime.version_command(Path::new("")).is_some() {
                match self.record_reported_version_with(
                    by,
                    name,
                    runtime,
                    deadline,
                    true,
                    "update",
                    Some(&mut update_log),
                ) {
                    Ok(Some(v)) => Some(Ok(v)),
                    Ok(None) => None,
                    Err(why) => Some(Err(why)),
                }
            } else {
                match self.current_version(name, runtime) {
                    Fact::Known(v) => match RuntimeVersion::new(&v) {
                        Some(version) => Some(Ok(version)),
                        None => Some(Err(format!("it reported no version enclos reads ({v})"))),
                    },
                    Fact::CannotTell(why) => Some(Err(why)),
                    Fact::Absent => Some(Err("its version file is absent".to_owned())),
                    Fact::NotProvided => None,
                }
            }
        } else {
            None
        };

        let updated = succeeded
            && match (&before, &after) {
                (Some(b), Some(Ok(a))) => a != b,
                (None, Some(Ok(_))) => true,
                _ => false,
            };

        // What the run's audit entry says, built before step 9 so that a
        // failure there still leaves the run accounted for: the version is
        // recorded by then, and the `runtime update` entry would otherwise be
        // missing altogether (the verdict's audit-row residual).
        let target = Some(format!("{name} {kind}"));
        let sha_note = installer_sha256
            .as_deref()
            .map(|sha| format!(", installer sha256 {sha}"))
            .unwrap_or_default();
        let outcome = |lost: Option<String>| -> Outcome {
            let text = if succeeded {
                match (&before, &after) {
                    (Some(b), Some(Ok(a))) if a != b => {
                        format!("updated from {b} to {a}{sha_note}")
                    }
                    (Some(_), Some(Ok(a))) => format!("unchanged at {a}{sha_note}"),
                    (None, Some(Ok(a))) => format!("updated to {a}{sha_note}"),
                    (_, Some(Err(why))) => {
                        format!("updater finished; version unreadable ({why}){sha_note}")
                    }
                    (_, None) => format!("updater finished{sha_note}"),
                }
            } else {
                let ended = ended_text(stopped_after, &session);
                let stays = before
                    .as_ref()
                    .map(|b| format!("; {b} stays"))
                    .unwrap_or_default();
                format!("the updater {ended}{stays}{sha_note}")
            };
            match lost {
                // The updater ran, but the sandbox's own services could not be
                // put back: the run failed, whatever it did to the version.
                Some(lost) => Outcome::failed(format!("{text}; {lost}")),
                None if succeeded => Outcome::ok(text),
                None => Outcome::failed(text),
            }
        };

        // Step 9: start the services again when they were installed and the
        // sandbox was running when the update began and has not been stopped
        // since. The state is read here for the "stopped since" part only: a
        // `sandbox stop` meanwhile removes the services itself and records
        // `Stopped`, and installing them again would leave a stopped sandbox
        // with services (ADR 0074: one that was stopped stays stopped with
        // none installed). A `Failed` state is not a stop of a sandbox that
        // was running (see `stopped_since`).
        let state_now = match self.record(name) {
            Ok(record) => record.state,
            Err(error) => {
                let _ = self.write_with_outcome(
                    by,
                    "runtime update",
                    target.clone(),
                    |_| outcome(Some("its services were left as they were".into())),
                    |_| Ok(()),
                );
                return Err(error);
            }
        };
        let stopped = stopped_since(&state_now, was_running);
        let services = if installed && was_running && !stopped {
            if let Err(error) = self.start_sandbox(by, name) {
                let lost = format!("its services were not started again ({error})");
                let _ = self.write_with_outcome(
                    by,
                    "runtime update",
                    target.clone(),
                    |_| outcome(Some(lost)),
                    |_| Ok(()),
                );
                return Err(error);
            }
            ServicesAfter::StartedAgain
        } else {
            if stopped {
                // Nothing is installed again, so end what the updater's own
                // session left open — the proxy it started for itself — as
                // `sandbox stop` ends sessions; its result is the update's,
                // not a second failure.
                if let Err(error) = self.stop_services_and_sessions(by, name) {
                    let lost = format!("its sessions were not ended ({error})");
                    let _ = self.write_with_outcome(
                        by,
                        "runtime update",
                        target.clone(),
                        |_| outcome(Some(lost)),
                        |_| Ok(()),
                    );
                    return Err(error);
                }
            }
            if stopped {
                ServicesAfter::NotInstalled
            } else {
                // Running with no services installed, before and after.
                ServicesAfter::NotInstalledRunning
            }
        };

        // Step 10: one `runtime update` audit entry for the run, after the
        // services are started again so it never sits between stop and start.
        self.write_with_outcome(by, "runtime update", target, |_| outcome(None), |_| Ok(()))?;

        Ok(Planned::Done(UpdateEnd {
            kind,
            updated,
            succeeded,
            before,
            after,
            session,
            release,
            policy: active.version.version,
            policy_missing,
            services,
            running_work,
            stopped_after,
            log: log_path,
        }))
    }

    /// Running work reported by the bridge's activity store for sandbox `name`.
    fn running_work(&self, name: &SandboxName) -> RunningWork {
        let (activity, unreadable) = bridge_activity(&self.layout.app_store());
        if let Some(why) = unreadable {
            return RunningWork::Unknown(why);
        }
        let prefix = format!("{name}/");
        let mut agents: Vec<String> = activity
            .into_iter()
            .filter(|(k, a)| k.starts_with(&prefix) && !a.kinds().is_empty())
            .map(|(k, _)| k)
            .collect();
        agents.sort();
        RunningWork::Count {
            count: agents.len(),
            agents,
        }
    }

    /// Asks the runtime its version, with its own command in the sandbox,
    /// and records it (ADR 0074, proposed), for a runtime whose home holds
    /// none enclos reads: none for another. The command is stopped after
    /// [`VERSION_TIME`], or at `deadline`, the install's, if sooner. When
    /// it cannot tell, the version recorded before is forgotten, as it may
    /// be the one this install replaced; and why is given.
    pub(super) fn record_reported_version(
        &self,
        by: &Actor,
        name: &SandboxName,
        runtime: &dyn RuntimeAdapter,
        deadline: Option<Instant>,
    ) -> std::result::Result<Option<RuntimeVersion>, String> {
        self.record_reported_version_with(by, name, runtime, deadline, false, "install", None)
    }

    /// Shared version-recording path for install and update. When
    /// `keep_on_failure` is true (update semantics, ADR 0074), a version
    /// that cannot be read keeps the version previously recorded in
    /// `state.db` instead of forgetting it.
    #[allow(clippy::too_many_arguments)]
    fn record_reported_version_with(
        &self,
        by: &Actor,
        name: &SandboxName,
        runtime: &dyn RuntimeAdapter,
        deadline: Option<Instant>,
        keep_on_failure: bool,
        what: &str,
        update_log: Option<&mut UpdateLog>,
    ) -> std::result::Result<Option<RuntimeVersion>, String> {
        let kind = runtime.kind();
        let target = Some(format!("{name} {kind}"));
        let version = match self.ask_version(by, name, runtime, deadline, what, update_log) {
            Ok(None) => return Ok(None),
            Ok(Some(version)) => version,
            Err(why) => {
                if keep_on_failure {
                    let _ = self.write(
                        by,
                        "runtime version",
                        target,
                        |_| format!("not reported: {why}; previous version kept"),
                        |_| Ok(()),
                    );
                    return Err(why);
                }
                let forgot = self.write(
                    by,
                    "runtime version",
                    target,
                    |_| format!("not reported: {why}"),
                    |lock| {
                        self.state
                            .forget_runtime_version(lock, name)
                            .map_err(Into::into)
                    },
                );
                return Err(match forgot {
                    Ok(_) => why,
                    Err(e) => format!(
                        "{why}; and the version recorded before could not be forgotten, so `enclos status` may show it: {e}"
                    ),
                });
            }
        };
        self.write(
            by,
            "runtime version",
            target,
            |_| format!("reported {version}"),
            |lock| {
                self.state
                    .put_runtime_version(lock, name, kind, &version, now())?;
                Ok(())
            },
        )
        .map_err(|e| e.to_string())?;
        Ok(Some(version))
    }

    /// What the runtime's version command reports, read from its report
    /// in the home, which it writes, as a usage report is read.
    fn ask_version(
        &self,
        by: &Actor,
        name: &SandboxName,
        runtime: &dyn RuntimeAdapter,
        deadline: Option<Instant>,
        what: &str,
        update_log: Option<&mut UpdateLog>,
    ) -> std::result::Result<Option<RuntimeVersion>, String> {
        let home = self.sandbox_home(name);
        let id = new_id().map_err(|e| format!("cannot name its version report: {e}"))?;
        let report = home.join(format!(".enclos-version-{id}"));
        let Some(command) = runtime.version_command(&report) else {
            return Ok(None);
        };
        let now = Instant::now();
        let stop = deadline.map_or(now + VERSION_TIME, |d| d.min(now + VERSION_TIME));
        if stop <= now {
            return Err(format!(
                "the {what}'s time limit left no time to ask its version"
            ));
        }
        let _remove = Removed(report.clone());
        let (ended, stopped) = match update_log {
            // During a runtime update, run as `Starting::Update` so asking
            // the version does not flip a stopped sandbox back to `Running`
            // (ADR 0074).
            Some(log) => {
                self.run_update_in_sandbox(by, name, command, "runtime version", Some(stop), log)
            }
            None => self.run_exec_in_sandbox_within(by, name, command, "runtime version", stop),
        }
        .map_err(|e| e.to_string())?;
        match (stopped, ended.signal) {
            (true, _) => {
                return Err(format!(
                    "its version command did not answer within {} and was stopped",
                    spoken(stop - now)
                ));
            }
            (false, Some(signal)) => {
                return Err(format!("its version command was ended by signal {signal}"));
            }
            (false, None) if ended.exit != 0 => {
                return Err(format!("its version command exited with {}", ended.exit));
            }
            (false, None) => {}
        }
        let text =
            read_report(&report, &home).map_err(|why| format!("its version report {why}"))?;
        let version = runtime.reported_version(&text).and_then(|v| {
            RuntimeVersion::new(&v).ok_or_else(|| "it reported no version enclos reads".to_owned())
        })?;
        Ok(Some(version))
    }

    fn plan_install(
        &self,
        name: &SandboxName,
        runtime: &dyn RuntimeAdapter,
    ) -> Result<InstallPlan> {
        let kind = runtime.kind();
        let active = self.policy(name)?;
        // The install resolves `policy.toml`, which holds the pending
        // change: it would be in force without the restart it needs.
        if active.pending.is_some() {
            return Err(Error::PolicyPending {
                sandbox: name.to_string(),
            });
        }
        let record = self.state.get(name)?.ok_or_else(|| Error::NoSuchSandbox {
            name: name.to_string(),
        })?;
        if let Some(other) = record.runtime.filter(|a| *a != kind) {
            return Err(Error::Session {
                what: format!(
                    "sandbox {name} already has {other}; one runtime per sandbox (ADR 0003)"
                ),
            });
        }
        let overrides = self.layout.read_policy(name.as_str())?;
        let snapshot = self.checked_policy_with(
            name,
            &overrides,
            Some(adapter_layer(kind)),
            self.recorded_backend(name)?,
        )?;
        let layer = PolicyFile::parse(&format!("{kind} adapter"), runtime.endpoints())?;
        let expected: Vec<&str> = layer.network.allow_add.iter().map(String::as_str).collect();
        let added = layer
            .network
            .allow_add
            .iter()
            .filter(|d| !active.snapshot.policy.net.allow.contains(d))
            .cloned()
            .collect();
        let mut also = differences(&active.snapshot.policy, &snapshot.policy, &expected);
        // Listening the adapter's layer turns on is what the runtime brings,
        // like its destinations (ADR 0028); any other change of it is an edit
        // of `policy.toml`, which stays an "also" change. Kept off by
        // `policy.toml`, the runtime's service cannot start, which the plan
        // says.
        let asks = layer.network.listen == Some(true);
        let listening = snapshot.policy.net.listen;
        if asks && listening {
            also.retain(|c| *c != listen_change(true));
        }
        Ok(InstallPlan {
            overrides,
            active: active.version.version,
            added,
            listens: asks && listening && !active.snapshot.policy.net.listen,
            listen_kept_off: asks && !listening,
            also,
            proxy_runs: self.proxy_runs(name)?,
            backend: record.backend,
        })
    }

    /// After a failed install, the policy is resolved again with the
    /// runtime the record has: an install records its runtime only on
    /// success, so that is the one the sandbox had before, none or the same
    /// one, unless another install succeeded meanwhile. Returns the
    /// active version and that runtime.
    fn undo_install(
        &self,
        by: &Actor,
        name: &SandboxName,
        kind: RuntimeKind,
        why: &str,
    ) -> Result<(u32, Option<RuntimeKind>)> {
        let (version, recorded) = self.write(
            by,
            "runtime install failed",
            Some(format!("{name} {kind}")),
            |(v, recorded): &(PolicyVersion, Option<RuntimeKind>)| match recorded {
                Some(kept) => format!(
                    "{why}; {kept} still recorded as installed, under policy v{}",
                    v.version
                ),
                None => format!("{why}; policy v{} without {kind}'s destinations", v.version),
            },
            |lock| {
                let record = self.state.get(name)?.ok_or_else(|| Error::NoSuchSandbox {
                    name: name.to_string(),
                })?;
                // A change saved as pending while the installer ran stays
                // pending.
                Ok((self.resolve_again(lock, by, name)?, record.runtime))
            },
        )?;
        Ok((version.version, recorded))
    }

    /// The sandbox's home folder, which is `~` for everything that runs in it.
    pub fn sandbox_home(&self, name: &SandboxName) -> PathBuf {
        self.layout.sandbox_home(name.as_str())
    }
}

impl InstallPlan {
    fn describe(&self, name: &SandboxName, runtime: &dyn RuntimeAdapter) -> Plan {
        let kind = runtime.kind();
        let mut changes = Vec::new();
        match self.added.len() {
            0 if self.also.is_empty() && !self.listens && !self.listen_kept_off => {
                changes.push(format!(
                    "keep the policy of sandbox {name} at v{}: it already allows what {kind} needs",
                    self.active
                ))
            }
            0 if self.also.is_empty() && !self.listens => changes.push(format!(
                "keep the policy of sandbox {name} at v{}",
                self.active
            )),
            0 => changes.push(format!(
                "change the policy of sandbox {name} for {kind}, as a new policy version"
            )),
            n => changes.push(format!(
                "allow the {n} destinations {kind} needs in sandbox {name}, as a new policy version: {}",
                self.added.join(", ")
            )),
        }
        if self.listens {
            changes.push(format!(
                "let sandbox {name} listen for {kind} (ADR 0028), {}",
                self.backend.listening()
            ));
        }
        if self.listen_kept_off {
            changes.push(format!(
                "keep sandbox {name} from listening, as its policy.toml sets `listen = false`: {kind}'s service cannot start without it (ADR 0028)"
            ));
        }
        changes.extend(self.also.iter().map(|c| format!("also {c}")));
        changes.push(format!(
            "download the {kind} installer from {} on {}, as it is served now (ADR 0029), and record its SHA-256",
            runtime.installer().url,
            self.backend.host()
        ));
        if !self.proxy_runs {
            changes.push(format!("start the proxy of sandbox {name}"));
        }
        changes.push(format!(
            "run the installer in sandbox {name} under that policy, in this terminal, and record {kind} as its runtime if the installer exits 0"
        ));
        if runtime.version_command(Path::new("")).is_some() {
            changes.push(format!(
                "then ask {kind} its version in sandbox {name}, and record it for `enclos status`"
            ));
        }
        Plan {
            changes,
            ..Plan::default()
        }
    }
}

/// Whether the sandbox is stopped after the update began. A sandbox that was
/// running and is now `Stopped` was stopped meanwhile: it stays stopped, with
/// none installed (ADR 0074). A sandbox that was not running and is not
/// running now is stopped, `Failed` included. A `Failed` recorded on a
/// sandbox that was running is not a stop: `stop_services_and_sessions`
/// records it when session members survive the stop, and before F1's fix the
/// update's own session failing to start did too.
fn stopped_since(state: &SandboxState, was_running: bool) -> bool {
    match state {
        SandboxState::Stopped => true,
        SandboxState::Running => false,
        _ => !was_running,
    }
}

fn plan_update(
    name: &SandboxName,
    kind: RuntimeKind,
    policy: u32,
    installed: bool,
    running: bool,
) -> Plan {
    let mut changes = Vec::new();
    if installed {
        changes.push(format!(
            "stop the services of sandbox {name} (its proxy, its namespace holder where the backend has one, and its runtime's services) and end its sessions"
        ));
    } else if running {
        // Recorded running with nothing installed: what `runtime install` or a
        // `connect` leaves. Calling that sandbox stopped (the wording before
        // F2) is wrong, and it is not left stopped either.
        changes.push(format!(
            "end the sessions of sandbox {name} and stop no service: it runs with none installed"
        ));
    } else {
        changes.push(format!(
            "stop no service of sandbox {name}: it is stopped already"
        ));
    }
    changes.push(format!(
        "run the {kind} updater in sandbox {name} under its active policy (v{policy})"
    ));
    changes.push(format!("record the version {kind} then reports"));
    if installed {
        changes.push(format!("start the services of sandbox {name} again"));
    } else if running {
        changes.push(format!(
            "leave sandbox {name} running with no service installed"
        ));
    } else {
        changes.push(format!(
            "keep sandbox {name} stopped with no service installed"
        ));
    }
    Plan {
        changes,
        ..Plan::default()
    }
}

fn needs_confirmation(kind: RuntimeKind, name: &SandboxName, also: &[String]) -> Error {
    Error::NeedsConfirmation {
        what: format!(
            "installing {kind} in sandbox {name} together with {} other changes to its policy ({})",
            also.len(),
            also.join("; ")
        ),
    }
}
