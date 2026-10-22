//! The pending policy (design §7): a change to the rules a running session
//! keeps from its start waits until `policy apply`, or the change made with
//! `--yes`, restarts the sandbox into it. `policy allow` and `policy edit`
//! record their change through `propose`, and `policy discard` drops what
//! waits.

use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use toml_edit::{DocumentMut, Item, Table};

use super::Engine;
use super::policy::{ChangeOutcome, PolicyApplied, differences, with_allowed};
use super::sandbox::StopReport;
use crate::error::{Error, Result};
use crate::layout::LayoutError;
use crate::lifecycle::members::members;
use crate::model::audit::Actor;
use crate::model::plan::{Confirm, Plan, Planned};
use crate::model::policy::{NetPolicy, PendingPolicy, PolicySnapshot, PolicyVersion};
use crate::model::sandbox::SandboxName;
use crate::model::session::SessionRecord;
use crate::policy::PolicyError;
use crate::service::ServiceLabel;
use crate::state::StateLock;

/// A change to record with `propose`.
pub(super) struct Change<'a> {
    /// The `policy.toml` it was resolved from.
    pub overrides: &'a str,
    pub snapshot: &'a PolicySnapshot,
    /// The destination `policy allow` adds, which applies at once.
    pub entry: Option<&'a str>,
    /// The version a rollback restores.
    pub restores: Option<u32>,
}

impl<'a> Change<'a> {
    /// `policy.toml` as a whole, as `policy edit` makes it.
    pub fn edit(overrides: &'a str, snapshot: &'a PolicySnapshot) -> Self {
        Change {
            overrides,
            snapshot,
            entry: None,
            restores: None,
        }
    }
}

/// A change once recorded, and whether it brought rules a running session
/// keeps from its start: with `--yes`, only such a change restarts the
/// sandbox, not one that was pending before it.
pub(super) struct Recorded {
    pub applied: PolicyApplied,
    pub restarts: bool,
}

/// How a pending policy was applied: the sandbox stopped, the policy made
/// active, and its services started again. Never holds survivors: a stop
/// that leaves any fails the restart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Restarted {
    pub version: PolicyVersion,
    /// What stopping the sandbox did; none when nothing of it ran or was
    /// installed.
    pub stopped: Option<StopReport>,
    /// The services `sandbox start` installed, when the sandbox had
    /// services installed before the restart.
    pub started: Vec<ServiceLabel>,
}

/// What `policy discard` dropped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Discarded {
    /// The pending policy dropped, if there was one.
    pub pending: Option<PendingPolicy>,
    /// Where the `policy.toml` replaced by the active policy's is kept,
    /// when it held anything else.
    pub kept: Option<PathBuf>,
    /// Where an edit `policy edit` kept is moved, if there was one.
    pub edit: Option<PathBuf>,
    /// The active version `policy.toml` holds again.
    pub version: PolicyVersion,
}

/// The files of an edit `policy edit` keeps, beside `policy.toml`: the copy
/// being edited, and the `policy.toml` it started from, so that an edit
/// opened again is refused once the file changed since.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EditFiles {
    pub copy: PathBuf,
    pub base: PathBuf,
}

impl Engine {
    /// The sandbox's open sessions that run under a compiled policy and
    /// still have members: those a change to the rules kept from a
    /// session's start does not reach until they restart. The proxy has no
    /// compiled policy, and applies its rules live.
    pub(super) fn sessions_under_rules(&self, name: &SandboxName) -> Result<Vec<SessionRecord>> {
        let mut running = Vec::new();
        for session in self.state.sessions(name, true)? {
            if session.compiled.is_none() {
                continue;
            }
            if !members(&self.marked(&session)?)?.is_empty() {
                running.push(session);
            }
        }
        Ok(running)
    }

    /// Where `policy edit` keeps an edit of the sandbox's `policy.toml`.
    pub fn edit_files(&self, name: &SandboxName) -> EditFiles {
        let file = self.layout.policy_file(name.as_str());
        EditFiles {
            copy: file.with_file_name("policy.toml.edit"),
            base: file.with_file_name("policy.toml.edit.base"),
        }
    }

    /// Records `snapshot`, resolved from `overrides`, as the sandbox's
    /// policy, under the lock (design §7):
    /// - active at once when it keeps every rule running sessions kept from
    ///   their start, or when none runs;
    /// - otherwise pending. When the change itself touches only network
    ///   rules (`entry`, a destination `policy allow` adds, or an edit made
    ///   while a change waits), that part also goes on the active policy at
    ///   once, provided the active policy's `policy.toml` is known and the
    ///   result differs from it by exactly that change.
    ///
    /// `policy.toml` holds `overrides` either way.
    pub(super) fn propose(
        &self,
        lock: &StateLock,
        by: &Actor,
        name: &SandboxName,
        change: Change<'_>,
    ) -> Result<Recorded> {
        let Change {
            overrides,
            snapshot,
            entry,
            restores,
        } = change;
        let (active_version, active) = self.active_policy(name)?;
        let before = self.state.pending_policy(name)?;
        let in_force = |version: PolicyVersion, changed: bool| Recorded {
            applied: PolicyApplied {
                version,
                changed,
                also: Vec::new(),
                outcome: ChangeOutcome::InForce {
                    dropped: before.as_ref().map(|(p, _)| p.clone()),
                },
            },
            restarts: false,
        };
        if snapshot.id == active.id {
            // Back to the policy in force: nothing waits any more.
            let previous = self.layout.read_policy(name.as_str())?;
            self.layout.write_policy(name.as_str(), overrides)?;
            if before.is_some()
                && let Err(e) = self.state.discard_pending(lock, name)
            {
                return Err(self.restore_policy(name, &previous, e.into()));
            }
            return Ok(in_force(active_version, false));
        }
        if snapshot.policy.same_at_launch(&active.policy)
            || self.sessions_under_rules(name)?.is_empty()
        {
            let version = self.store_policy(lock, by, name, overrides, snapshot, restores)?;
            return Ok(in_force(version, true));
        }
        let base = before.as_ref().map_or(&active, |(_, s)| s);
        let restarts = !snapshot.policy.same_at_launch(&base.policy);
        let live = match entry {
            Some(entry) => self.live_entry(name, &active, entry)?,
            // An edit that also changes rules sessions keep waits as a whole.
            None if restarts => None,
            None => self.live_network(name, &active, base, overrides, snapshot)?,
        };
        let pending = |version: PolicyVersion, p: PendingPolicy, changed: bool| Recorded {
            applied: PolicyApplied {
                version,
                changed,
                also: Vec::new(),
                outcome: ChangeOutcome::Pending(p),
            },
            restarts,
        };
        let previous = self.layout.read_policy(name.as_str())?;
        self.layout.write_policy(name.as_str(), overrides)?;
        if live.is_none()
            && let Some((p, s)) = &before
            && s.id == snapshot.id
        {
            return Ok(pending(active_version, p.clone(), false));
        }
        match self
            .state
            .save_pending(lock, name, snapshot, live.as_ref(), by, restores)
        {
            Ok((Some(version), p)) => Ok(pending(version, p, true)),
            Ok((None, p)) => Ok(pending(active_version, p, false)),
            Err(e) => Err(self.restore_policy(name, &previous, e.into())),
        }
    }

    /// Puts `previous` back as the sandbox's `policy.toml` after `error`, so
    /// that the file never holds a change the state does not record: the
    /// next command that resolves it would put that change in force.
    pub(super) fn restore_policy(&self, name: &SandboxName, previous: &str, error: Error) -> Error {
        match self.layout.write_policy(name.as_str(), previous) {
            Ok(()) => error,
            Err(e) => Error::CleanupFailed {
                error: Box::new(error),
                left: format!(
                    "{} holding a change enclos did not record ({e}); `enclos policy discard {name}` puts back the active policy's",
                    self.layout.policy_file(name.as_str()).display()
                ),
            },
        }
    }

    /// The active policy with `entry` allowed, when that is all it changes.
    fn live_entry(
        &self,
        name: &SandboxName,
        active: &PolicySnapshot,
        entry: &str,
    ) -> Result<Option<PolicySnapshot>> {
        if active.policy.net.allow.iter().any(|a| a == entry) {
            return Ok(None);
        }
        let Some(text) = active.overrides_text() else {
            return Ok(None);
        };
        let text = with_allowed(text, entry)?.unwrap_or_else(|| text.to_owned());
        let live = self.checked_policy(name, &text)?;
        let mut expected = active.policy.net.clone();
        expected.allow.push(entry.to_owned());
        expected.allow.sort();
        expected.allow.dedup();
        Ok(only_network(&live, active, &expected).then_some(live))
    }

    /// The active policy with the network rules of `overrides`, when the
    /// change from `base` (the pending policy) touches only those, and the
    /// pending policy waits with no network change of its own: what would
    /// go in force is then exactly the edit.
    fn live_network(
        &self,
        name: &SandboxName,
        active: &PolicySnapshot,
        base: &PolicySnapshot,
        overrides: &str,
        snapshot: &PolicySnapshot,
    ) -> Result<Option<PolicySnapshot>> {
        if !same_network(&base.policy.net, &active.policy.net) {
            return Ok(None);
        }
        let Some(text) = active.overrides_text() else {
            return Ok(None);
        };
        let live = self.checked_policy(name, &with_network_of(text, overrides)?)?;
        let mut expected = snapshot.policy.net.clone();
        expected.listen = active.policy.net.listen;
        Ok(only_network(&live, active, &expected).then_some(live))
    }

    /// Makes `after` the sandbox's `policy.toml`, as `policy edit` does once
    /// the editor closes: in force at once, or pending when sessions run
    /// under rules it changes. With `--yes`, a change that brings such rules
    /// restarts the sandbox into it. `before` is the file the edit started
    /// from: one changed since is refused, so no other change is lost.
    pub fn policy_edit(
        &self,
        by: &Actor,
        name: &SandboxName,
        before: &str,
        after: &str,
        confirm: Confirm,
    ) -> Result<Planned<PolicyApplied>> {
        let snapshot = self.checked_policy(name, after)?;
        let view = self.policy(name)?;
        let changes = differences(&view.snapshot.policy, &snapshot.policy, &[]);
        if confirm == Confirm::DryRun {
            let running = !self.sessions_under_rules(name)?.is_empty();
            let waits = !snapshot.policy.same_at_launch(&view.snapshot.policy) && running;
            let brings = !snapshot.policy.same_at_launch(&view.latest().policy);
            let what = match (snapshot.id == view.snapshot.id, waits, brings) {
                (true, ..) => match view.pending {
                    Some(_) => format!(
                        "drop the pending change of sandbox {name}: the file is back to policy v{}",
                        view.version.version
                    ),
                    None => format!("change nothing in the policy of sandbox {name}"),
                },
                (false, false, _) => {
                    format!("apply the edit to sandbox {name} at once, as a new policy version")
                }
                (false, true, true) => format!(
                    "save the edit as the pending policy of sandbox {name}, since sessions run under rules it changes; with --yes, restart the sandbox to apply it"
                ),
                (false, true, false) => format!(
                    "keep the change of sandbox {name} pending, with this edit; a network-only edit also applies at once"
                ),
            };
            return Ok(Planned::DryRun(Plan {
                changes: std::iter::once(what)
                    .chain(changes.iter().map(|c| format!("  {c}")))
                    .collect(),
                ..Plan::default()
            }));
        }
        let recorded = self.write(
            by,
            "policy edit",
            Some(name.to_string()),
            |r: &Recorded| edit_summary(&r.applied),
            |lock| {
                if self.layout.read_policy(name.as_str())? != before {
                    return Err(Error::PolicyFileChanged {
                        sandbox: name.to_string(),
                        file: self.layout.policy_file(name.as_str()),
                    });
                }
                let snapshot = self.checked_policy(name, after)?;
                let mut recorded = self.propose(lock, by, name, Change::edit(after, &snapshot))?;
                recorded.applied.also = changes;
                Ok(recorded)
            },
        )?;
        Ok(Planned::Done(
            self.restart_if_asked(by, name, confirm, recorded)?,
        ))
    }

    /// With `--yes`, restarts the sandbox into a change that brought rules
    /// running sessions keep from their start; one pending before stays
    /// pending, for `policy apply`. A restart that fails says the change
    /// was saved as pending, so it is not taken for one never made.
    pub(super) fn restart_if_asked(
        &self,
        by: &Actor,
        name: &SandboxName,
        confirm: Confirm,
        recorded: Recorded,
    ) -> Result<PolicyApplied> {
        let mut applied = recorded.applied;
        let ChangeOutcome::Pending(pending) = &applied.outcome else {
            return Ok(applied);
        };
        if confirm != Confirm::Yes || !recorded.restarts {
            return Ok(applied);
        }
        let restarted = self.restart_into(by, name, pending).map_err(|error| {
            // Said only while the change still waits: a restart can fail
            // after the change went in force, when its services start.
            let waits = matches!(
                self.state.pending_policy(name),
                Ok(Some((p, _))) if p.snapshot == pending.snapshot
            );
            match waits {
                true => Error::FailedAfter {
                    error: Box::new(error),
                    done: format!(
                        "saving the change as the pending policy of sandbox {name} (snapshot {}), with policy v{} in force",
                        pending.snapshot.short(),
                        applied.version.version
                    ),
                },
                false => error,
            }
        })?;
        applied.version = restarted.version.clone();
        applied.changed = true;
        applied.outcome = ChangeOutcome::Restarted(restarted);
        Ok(applied)
    }

    /// Restarts the sandbox into its pending policy: stops what runs, makes
    /// the pending policy active, then starts the services again when it
    /// had services installed. Asks first when sessions would end.
    pub fn policy_apply(
        &self,
        by: &Actor,
        name: &SandboxName,
        confirm: Confirm,
    ) -> Result<Planned<Restarted>> {
        let view = self.policy(name)?;
        let Some((pending, snapshot)) = &view.pending else {
            return Err(Error::NoPendingPolicy {
                sandbox: name.to_string(),
            });
        };
        let running = self.sessions_under_rules(name)?;
        let services = self.has_services(name)?;
        match confirm {
            Confirm::DryRun => {
                let mut changes = Vec::new();
                if self.stops_to_restart(name)? {
                    changes.push(format!(
                        "stop sandbox {name}: its services and sessions end ({} under a compiled policy)",
                        sessions(running.len())
                    ));
                }
                changes.push(format!(
                    "make the pending policy of sandbox {name} (snapshot {}) active, as a new version",
                    pending.snapshot.short()
                ));
                changes.extend(
                    differences(&view.snapshot.policy, &snapshot.policy, &[])
                        .into_iter()
                        .map(|c| format!("  {c}")),
                );
                if services {
                    changes.push(format!("start the services of sandbox {name} again"));
                }
                return Ok(Planned::DryRun(Plan {
                    changes,
                    ..Plan::default()
                }));
            }
            Confirm::Ask if !running.is_empty() => {
                return Err(Error::NeedsConfirmation {
                    what: format!(
                        "restarting sandbox {name} to apply its pending policy, which ends {} (an interactive one ends too: connect again after)",
                        sessions(running.len())
                    ),
                });
            }
            _ => {}
        }
        Ok(Planned::Done(self.restart_into(by, name, pending)?))
    }

    /// Stops the sandbox when anything of it runs or is installed, makes
    /// `pending` active, then starts its services when it had any. A step
    /// that fails says what the steps before it did: the stop removes the
    /// services, which only `sandbox start` brings back.
    pub(super) fn restart_into(
        &self,
        by: &Actor,
        name: &SandboxName,
        pending: &PendingPolicy,
    ) -> Result<Restarted> {
        let services = self.has_services(name)?;
        let stopped = match self.stops_to_restart(name)? {
            true => match self.stop_sandbox(by, name, Confirm::Yes) {
                Ok(Planned::Done(report)) => Some(report),
                Ok(Planned::DryRun(_)) => unreachable!("a stop with --yes runs"),
                Err(error) => {
                    return Err(Error::WithContext {
                        what: format!(
                            "{error}. The pending policy of sandbox {name} stays pending; its services may be removed already: `enclos sandbox show {name}` says what runs, and `enclos sandbox start {name}` starts them again"
                        ),
                        error: Box::new(error),
                    });
                }
            },
            false => None,
        };
        let stop_done = |report: &StopReport| match report.services.as_slice() {
            [] => format!("stopping sandbox {name}"),
            labels => format!(
                "stopping sandbox {name}, which removed its services ({}); `enclos sandbox start {name}` installs them again",
                labels
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        };
        if let Some(report) = &stopped
            && !report.survivors.is_empty()
        {
            let left: Vec<String> = report
                .survivors
                .iter()
                .flat_map(|(_, survivors)| survivors)
                .map(|s| format!("{} ({})", s.member.pid, s.member.command))
                .collect();
            return Err(Error::FailedAfter {
                error: Box::new(Error::Session {
                    what: format!(
                        "sandbox {name} is marked failed: processes survived the stop ({}), so its pending policy stays pending. End them, then run `enclos policy apply {name}` again",
                        left.join(", ")
                    ),
                }),
                done: stop_done(report),
            });
        }
        let version = self
            .write(
                by,
                "policy apply",
                Some(name.to_string()),
                |v: &PolicyVersion| format!("policy v{}", v.version),
                |lock| {
                    self.state
                        .apply_pending(lock, name, &pending.snapshot, by)?
                        .ok_or_else(|| Error::PendingChanged {
                            sandbox: name.to_string(),
                        })
                },
            )
            .map_err(|error| match &stopped {
                Some(report) => Error::FailedAfter {
                    error: Box::new(error),
                    done: stop_done(report),
                },
                None => error,
            })?;
        let started = match services {
            true => self
                .start_sandbox(by, name)
                .map_err(|error| Error::FailedAfter {
                    error: Box::new(error),
                    done: format!(
                        "stopping sandbox {name} and making policy v{} active; `enclos sandbox start {name}` starts its services again",
                        version.version
                    ),
                })?,
            false => Vec::new(),
        };
        Ok(Restarted {
            version,
            stopped,
            started,
        })
    }

    /// Whether a restart stops the sandbox first: it has services installed,
    /// which run under the policy they started with, or sessions open.
    fn stops_to_restart(&self, name: &SandboxName) -> Result<bool> {
        Ok(self.has_services(name)? || !self.state.sessions(name, true)?.is_empty())
    }

    /// After a failed `runtime install`, resolves the sandbox's policy again
    /// with the runtime its record has, keeping a change that became pending
    /// while the installer ran pending: the active policy is resolved from
    /// its own `policy.toml`, and the pending one from the file.
    pub(super) fn resolve_again(
        &self,
        lock: &StateLock,
        by: &Actor,
        name: &SandboxName,
    ) -> Result<PolicyVersion> {
        let overrides = self.layout.read_policy(name.as_str())?;
        if self.state.pending_policy(name)?.is_none() {
            return self.save_policy(lock, by, name, &overrides);
        }
        let (version, active) = self.active_policy(name)?;
        let text = active
            .overrides_text()
            .ok_or_else(|| Error::PolicyTextUnknown {
                sandbox: name.to_string(),
                version: version.version,
                file: self.layout.policy_file(name.as_str()),
            })?;
        let now = self.checked_policy(name, text)?;
        let pending = self.checked_policy(name, &overrides)?;
        let active = (now.id != active.id).then_some(&now);
        let (made, _) = self
            .state
            .save_pending(lock, name, &pending, active, by, None)?;
        Ok(made.unwrap_or(version))
    }

    /// Once a runtime is recorded as installed, resolves again what a change
    /// made while its installer ran resolved without its destinations: the
    /// active policy from its own `policy.toml`, and a pending one from the
    /// file. Nothing else changes: the file is not resolved on its own.
    pub(super) fn resolve_with_runtime(
        &self,
        lock: &StateLock,
        by: &Actor,
        name: &SandboxName,
    ) -> Result<()> {
        let (_, active) = self.active_policy(name)?;
        let now = match active.overrides_text() {
            Some(text) => Some(self.checked_policy(name, text)?),
            None => None,
        }
        .filter(|now| now.id != active.id && now.policy != active.policy);
        match self.state.pending_policy(name)? {
            Some((p, pending)) => {
                let overrides = self.layout.read_policy(name.as_str())?;
                let again = self.checked_policy(name, &overrides)?;
                if again.id != pending.id || now.is_some() {
                    self.state
                        .save_pending(lock, name, &again, now.as_ref(), by, p.restores)?;
                }
            }
            None => {
                if let Some(now) = &now {
                    self.state.save_policy(lock, name, now, by, None)?;
                }
            }
        }
        Ok(())
    }

    /// Drops the pending policy, and any edit of `policy.toml` not applied:
    /// the file goes back to the one the active policy was resolved from,
    /// what it held is kept beside it in `policy.toml.discarded`, and an
    /// edit `policy edit` kept is moved to `policy.toml.edit.discarded`.
    /// Each replaces the one an earlier discard kept.
    pub fn policy_discard(
        &self,
        by: &Actor,
        name: &SandboxName,
        confirm: Confirm,
    ) -> Result<Planned<Discarded>> {
        let plan = self.plan_discard(name)?;
        if confirm == Confirm::DryRun {
            let mut changes = Vec::new();
            if let Some(p) = &plan.pending {
                changes.push(format!(
                    "drop the pending policy of sandbox {name} (snapshot {})",
                    p.snapshot.short()
                ));
            }
            if plan.edited {
                changes.push(format!(
                    "put back the policy.toml of policy v{}, keeping the current one as {}",
                    plan.version.version,
                    self.discarded_file(name).display()
                ));
            }
            if plan.kept_edit {
                changes.push(format!(
                    "drop the edit kept by `policy edit`, moving it to {}",
                    discarded(&self.edit_files(name).copy).display()
                ));
            }
            if changes.is_empty() {
                changes.push(format!(
                    "change nothing: sandbox {name} has nothing pending"
                ));
            }
            return Ok(Planned::DryRun(Plan {
                changes,
                ..Plan::default()
            }));
        }
        if plan.pending.is_none() && !plan.edited && !plan.kept_edit {
            return Ok(Planned::Done(Discarded {
                pending: None,
                kept: None,
                edit: None,
                version: plan.version,
            }));
        }
        let discarded = self.write(
            by,
            "policy discard",
            Some(name.to_string()),
            |d: &Discarded| match &d.pending {
                Some(p) => format!(
                    "dropped pending snapshot {}; policy.toml back to v{}",
                    p.snapshot.short(),
                    d.version.version
                ),
                None => format!(
                    "policy.toml back to v{}, dropping edits not applied",
                    d.version.version
                ),
            },
            |lock| {
                let plan = self.plan_discard(name)?;
                let file = self.layout.policy_file(name.as_str());
                let kept = match plan.edited {
                    true => {
                        let kept = self.discarded_file(name);
                        let current = std::fs::read(&file).map_err(io(&file))?;
                        write_private(&kept, &current)?;
                        self.layout.write_policy(name.as_str(), &plan.text)?;
                        Some(kept)
                    }
                    false => None,
                };
                let edit = match plan.kept_edit {
                    true => {
                        let files = self.edit_files(name);
                        let to = discarded(&files.copy);
                        std::fs::rename(&files.copy, &to).map_err(io(&files.copy))?;
                        remove_if_there(&files.base)?;
                        Some(to)
                    }
                    false => None,
                };
                if plan.pending.is_some() {
                    self.state
                        .discard_pending(lock, name)
                        .map_err(|e| Error::FailedAfter {
                            error: Box::new(e.into()),
                            done: format!(
                                "putting back the policy.toml of policy v{}",
                                plan.version.version
                            ),
                        })?;
                }
                Ok(Discarded {
                    pending: plan.pending,
                    kept,
                    edit,
                    version: plan.version,
                })
            },
        )?;
        Ok(Planned::Done(discarded))
    }

    fn plan_discard(&self, name: &SandboxName) -> Result<DiscardPlan> {
        let view = self.policy(name)?;
        let text = view
            .snapshot
            .overrides_text()
            .ok_or_else(|| Error::PolicyTextUnknown {
                sandbox: name.to_string(),
                version: view.version.version,
                file: view.file.clone(),
            })?
            .to_owned();
        let edited = match std::fs::read(&view.file) {
            Ok(current) => current != text.as_bytes(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => true,
            Err(source) => return Err(io(&view.file)(source)),
        };
        let copy = self.edit_files(name).copy;
        let kept_edit = copy.try_exists().map_err(io(&copy))?;
        Ok(DiscardPlan {
            edited,
            kept_edit,
            text,
            pending: view.pending.map(|(p, _)| p),
            version: view.version,
        })
    }

    /// Where `policy discard` keeps the `policy.toml` it replaces.
    fn discarded_file(&self, name: &SandboxName) -> PathBuf {
        discarded(&self.layout.policy_file(name.as_str()))
    }
}

/// What `policy discard` works out before it changes anything.
struct DiscardPlan {
    /// The `policy.toml` the active policy was resolved from.
    text: String,
    /// Whether the file holds anything else.
    edited: bool,
    /// Whether `policy edit` kept an edit.
    kept_edit: bool,
    pending: Option<PendingPolicy>,
    version: PolicyVersion,
}

/// Whether `live` differs from `active` by its network rules alone, and has
/// exactly `expected`, the network rules the change asked for: a newer
/// template or defaults would show as a difference, and keep the change
/// waiting rather than put something unlisted in force.
fn only_network(live: &PolicySnapshot, active: &PolicySnapshot, expected: &NetPolicy) -> bool {
    live.id != active.id
        && live.policy.same_at_launch(&active.policy)
        && live.policy.net == *expected
}

/// Whether two policies reach the same destinations, listening aside.
fn same_network(a: &NetPolicy, b: &NetPolicy) -> bool {
    NetPolicy {
        listen: b.listen,
        ..a.clone()
    } == *b
}

/// `text` with the `[network]` table of `from`, keeping `text`'s own
/// `listen`, which sessions keep from their start.
fn with_network_of(text: &str, from: &str) -> Result<String> {
    let parse = |t: &str| {
        t.parse::<DocumentMut>()
            .map_err(|e: toml_edit::TomlError| PolicyError::Parse {
                layer: "policy.toml".to_owned(),
                reason: e.to_string().trim().to_owned(),
            })
    };
    let mut doc = parse(text)?;
    let from = parse(from)?;
    let listen = doc.get("network").and_then(|n| n.get("listen")).cloned();
    match from.get("network") {
        Some(network) => {
            doc.insert("network", network.clone());
        }
        None => {
            doc.remove("network");
        }
    }
    let network = doc
        .entry("network")
        .or_insert(Item::Table(Table::new()))
        .as_table_like_mut()
        .ok_or_else(|| PolicyError::Parse {
            layer: "policy.toml".to_owned(),
            reason: "`network` must be a table".to_owned(),
        })?;
    network.remove("listen");
    if let Some(listen) = listen {
        network.insert("listen", listen);
    }
    Ok(doc.to_string())
}

/// `path` with `.discarded` added, where `policy discard` keeps it.
fn discarded(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_owned();
    name.push(".discarded");
    path.with_file_name(name)
}

fn io(path: &Path) -> impl FnOnce(std::io::Error) -> Error {
    let path = path.to_owned();
    move |source| Error::Layout(LayoutError::Io { path, source })
}

/// Writes `contents` to `path`, readable by its owner only, replacing it.
fn write_private(path: &Path, contents: &[u8]) -> Result<()> {
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .and_then(|mut f| f.write_all(contents))
        .map_err(io(path))
}

fn remove_if_there(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(io(path)(e)),
        _ => Ok(()),
    }
}

/// `n` sessions, in words: "1 session", "2 sessions".
fn sessions(n: usize) -> String {
    match n {
        1 => "1 session".to_owned(),
        n => format!("{n} sessions"),
    }
}

fn edit_summary(applied: &PolicyApplied) -> String {
    let changes = match applied.also.len() {
        0 => String::new(),
        _ => format!(": {}", applied.also.join("; ")),
    };
    match (&applied.outcome, applied.changed) {
        (ChangeOutcome::Pending(p), true) => format!(
            "pending snapshot {}, with policy v{} in force{changes}",
            p.snapshot.short(),
            applied.version.version
        ),
        (ChangeOutcome::Pending(p), false) => format!(
            "pending snapshot {}, as sessions run under rules it changes{changes}",
            p.snapshot.short()
        ),
        (ChangeOutcome::InForce { dropped: Some(p) }, false) => format!(
            "back to policy v{}, dropping pending snapshot {}",
            applied.version.version,
            p.snapshot.short()
        ),
        (_, false) => "nothing changed".to_owned(),
        (_, true) => format!("policy v{}{changes}", applied.version.version),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_network_table_is_taken_whole_and_listening_kept() {
        let text = "extends = \"assistant\"\n[filesystem]\nwrite_add = [\"~/a\"]\n[network]\nlisten = false\nallow_add = [\"a.example.com\"]\n";
        let from =
            "[network]\nmode = \"allowlist\"\nallow_add = [\"b.example.com\"]\nlisten = true\n";
        let joined = with_network_of(text, from).unwrap();
        let parsed: toml::Table = toml::from_str(&joined).unwrap();
        let network = parsed["network"].as_table().unwrap();
        assert_eq!(network["allow_add"].as_array().unwrap().len(), 1);
        assert_eq!(network["allow_add"][0].as_str(), Some("b.example.com"));
        assert_eq!(network["mode"].as_str(), Some("allowlist"));
        assert_eq!(network["listen"].as_bool(), Some(false));
        assert!(joined.contains("~/a"), "{joined}");
        // A file with no network table drops it, and no listen is added.
        let bare =
            with_network_of("extends = \"assistant\"\n", "extends = \"assistant\"\n").unwrap();
        assert!(!bare.contains("listen"), "{bare}");
    }

    #[test]
    fn a_discarded_file_keeps_its_name() {
        assert_eq!(
            discarded(Path::new("/s/policy.toml")),
            Path::new("/s/policy.toml.discarded")
        );
    }
}
