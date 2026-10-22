//! The pending policy (design §7): a change to rules a running session
//! keeps from its start waits until a restart applies it. `policy edit`
//! changes `policy.toml` as a whole, `policy apply` restarts the sandbox
//! into the pending policy, and `policy discard` drops it.

use std::path::PathBuf;

use super::Engine;
use super::policy::{PolicyApplied, applied, differences, with_allowed};
use super::sandbox::StopReport;
use crate::error::{Error, Result};
use crate::lifecycle::members::members;
use crate::model::audit::Actor;
use crate::model::plan::{Confirm, Plan, Planned};
use crate::model::policy::{PendingPolicy, PolicySnapshot, PolicyVersion};
use crate::model::sandbox::SandboxName;
use crate::model::session::SessionRecord;
use crate::service::ServiceLabel;
use crate::state::StateLock;

/// What became of a change once recorded.
pub(super) enum Proposed {
    /// In force at once, as `version`; `changed` is false when it already
    /// was the active policy and there was nothing pending to drop.
    Active {
        version: PolicyVersion,
        changed: bool,
    },
    /// Saved as the pending policy. `version` is the active one, which a
    /// network part of the change made anew; `fresh` says the change itself
    /// brought rules sessions keep, rather than one pending before.
    Pending {
        version: PolicyVersion,
        pending: PendingPolicy,
        changed: bool,
        fresh: bool,
    },
}

/// How a pending policy was applied: the sandbox stopped, the policy made
/// active, and its services started again.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Restarted {
    pub version: PolicyVersion,
    /// What stopping the sandbox did; none when nothing ran.
    pub stopped: Option<StopReport>,
    /// The services started again: those installed before.
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
    /// The active version `policy.toml` holds again.
    pub version: PolicyVersion,
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

    /// Records `snapshot`, resolved from `overrides`, as the sandbox's
    /// policy, under the lock: active at once when it keeps every rule
    /// running sessions kept from their start, or when none runs; pending
    /// otherwise, with `live`, a destination the change allows, in force at
    /// once all the same (design §7). `policy.toml` holds `overrides`
    /// either way.
    pub(super) fn propose(
        &self,
        lock: &StateLock,
        by: &Actor,
        name: &SandboxName,
        overrides: &str,
        snapshot: &PolicySnapshot,
        live: Option<&str>,
    ) -> Result<Proposed> {
        let (active_version, active) = self.active_policy(name)?;
        let before = self.state.pending_policy(name)?;
        if snapshot.id == active.id {
            // Back to the policy in force: nothing waits any more.
            self.layout.write_policy(name.as_str(), overrides)?;
            let dropped = before.is_some() && self.state.discard_pending(lock, name)?;
            return Ok(Proposed::Active {
                version: active_version,
                changed: dropped,
            });
        }
        if snapshot.policy.same_at_launch(&active.policy)
            || self.sessions_under_rules(name)?.is_empty()
        {
            let version = self.store_policy(lock, by, name, overrides, snapshot)?;
            return Ok(Proposed::Active {
                version,
                changed: true,
            });
        }
        let base = before.as_ref().map_or(&active, |(_, s)| s);
        let fresh = !snapshot.policy.same_at_launch(&base.policy);
        // The destination asked for applies at once, on top of the active
        // policy as it was resolved; without that policy's text, it waits
        // with the rest.
        let live = match (live, active.overrides_text()) {
            (Some(entry), Some(text)) if !active.policy.net.allow.iter().any(|a| a == entry) => {
                let text = with_allowed(text, entry)?.unwrap_or_else(|| text.to_owned());
                Some(self.checked_policy(name, &text)?)
            }
            _ => None,
        };
        let unchanged = live.is_none()
            && before
                .as_ref()
                .is_some_and(|(_, pending)| pending.id == snapshot.id);
        let previous = self.layout.read_policy(name.as_str()).ok();
        self.layout.write_policy(name.as_str(), overrides)?;
        if unchanged {
            let (pending, _) = before.expect("checked above");
            return Ok(Proposed::Pending {
                version: active_version,
                pending,
                changed: false,
                fresh,
            });
        }
        match self
            .state
            .save_pending(lock, name, snapshot, live.as_ref(), by)
        {
            Ok((version, pending)) => Ok(Proposed::Pending {
                version: version.unwrap_or(active_version),
                pending,
                changed: true,
                fresh,
            }),
            Err(e) => {
                if let Some(previous) = previous {
                    let _ = self.layout.write_policy(name.as_str(), &previous);
                }
                Err(e.into())
            }
        }
    }

    /// Makes `after` the sandbox's `policy.toml`, as `policy edit` does once
    /// the editor closes: in force at once, or pending when sessions run
    /// under rules it changes, and with `--yes` the sandbox restarts to
    /// apply it. `before` is the file the edit started from: one changed
    /// since is refused, so no other change is lost.
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
            let restart = !snapshot.policy.same_at_launch(&view.snapshot.policy)
                && !self.sessions_under_rules(name)?.is_empty();
            let what = match (snapshot.id == view.snapshot.id, restart) {
                (true, _) => match view.pending {
                    Some(_) => format!(
                        "drop the pending change of sandbox {name}: the file is back to policy v{}",
                        view.version.version
                    ),
                    None => format!("change nothing in the policy of sandbox {name}"),
                },
                (false, false) => {
                    format!("apply the edit to sandbox {name} at once, as a new policy version")
                }
                (false, true) => format!(
                    "save the edit as the pending policy of sandbox {name}, since sessions run under rules it changes; with --yes, restart the sandbox to apply it"
                ),
            };
            return Ok(Planned::DryRun(Plan {
                changes: std::iter::once(what)
                    .chain(changes.iter().map(|c| format!("  {c}")))
                    .collect(),
                ..Plan::default()
            }));
        }
        let applied = self.write(
            by,
            "policy edit",
            Some(name.to_string()),
            |(applied, _): &(PolicyApplied, bool)| edit_summary(applied),
            |lock| {
                let file = self.layout.policy_file(name.as_str());
                if self.layout.read_policy(name.as_str()).ok().as_deref() != Some(before) {
                    return Err(Error::PolicyFileChanged { file });
                }
                let snapshot = self.checked_policy(name, after)?;
                let proposed = self.propose(lock, by, name, after, &snapshot, None)?;
                Ok(applied(proposed, changes))
            },
        )?;
        Ok(Planned::Done(
            self.restart_if_asked(by, name, confirm, applied)?,
        ))
    }

    /// Restarts the sandbox into its pending policy: stops what runs, makes
    /// the pending policy active, then starts the services that were
    /// installed again. Asks first when sessions would end.
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
                        "stop sandbox {name}, ending {} that run under its rules",
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
    /// `pending` active, then starts the services installed before again.
    pub(super) fn restart_into(
        &self,
        by: &Actor,
        name: &SandboxName,
        pending: &PendingPolicy,
    ) -> Result<Restarted> {
        let services = self.has_services(name)?;
        let stopped = match self.stops_to_restart(name)? {
            true => match self.stop_sandbox(by, name, Confirm::Yes)? {
                Planned::Done(report) => Some(report),
                Planned::DryRun(_) => unreachable!("a stop with --yes runs"),
            },
            false => None,
        };
        if let Some(report) = &stopped
            && !report.survivors.is_empty()
        {
            return Err(Error::Session {
                what: format!(
                    "sandbox {name} is marked failed: some of its processes survived the stop, so its pending policy stays pending. `enclos sandbox show {name}` lists them; end them, then run `enclos policy apply {name}` again"
                ),
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
                Some(_) => Error::FailedAfter {
                    error: Box::new(error),
                    done: format!(
                        "stopping sandbox {name}; `enclos sandbox start {name}` starts it again"
                    ),
                },
                None => error,
            })?;
        let started = match services {
            true => self
                .start_sandbox(by, name)
                .map_err(|error| Error::FailedAfter {
                    error: Box::new(error),
                    done: format!(
                        "making policy v{} of sandbox {name} active",
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

    /// Drops the pending policy, and any edit of `policy.toml` not applied:
    /// the file goes back to the one the active policy was resolved from,
    /// and what it held is kept beside it, in `policy.toml.discarded`.
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
        if plan.pending.is_none() && !plan.edited {
            return Ok(Planned::Done(Discarded {
                pending: None,
                kept: None,
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
                let kept = match plan.edited {
                    true => {
                        let kept = self.discarded_file(name);
                        let current = self.layout.read_policy(name.as_str()).unwrap_or_default();
                        std::fs::write(&kept, current).map_err(|source| {
                            crate::layout::LayoutError::Io {
                                path: kept.clone(),
                                source,
                            }
                        })?;
                        self.layout.write_policy(name.as_str(), &plan.text)?;
                        Some(kept)
                    }
                    false => None,
                };
                if plan.pending.is_some() {
                    self.state.discard_pending(lock, name)?;
                }
                Ok(Discarded {
                    pending: plan.pending,
                    kept,
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
        let current = self.layout.read_policy(name.as_str()).ok();
        Ok(DiscardPlan {
            edited: current.as_deref() != Some(text.as_str()),
            text,
            pending: view.pending.map(|(p, _)| p),
            version: view.version,
        })
    }

    /// Where `policy discard` keeps the `policy.toml` it replaces.
    fn discarded_file(&self, name: &SandboxName) -> PathBuf {
        self.layout
            .policy_file(name.as_str())
            .with_file_name("policy.toml.discarded")
    }
}

/// What `policy discard` works out before it changes anything.
struct DiscardPlan {
    /// The `policy.toml` the active policy was resolved from.
    text: String,
    /// Whether the file holds anything else.
    edited: bool,
    pending: Option<PendingPolicy>,
    version: PolicyVersion,
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
    match (&applied.pending, applied.changed) {
        (None, false) => "nothing changed".to_owned(),
        (None, true) => format!("policy v{}{changes}", applied.version.version),
        (Some(p), _) => format!(
            "pending snapshot {}, as sessions run under rules it changes{changes}",
            p.snapshot.short()
        ),
    }
}
