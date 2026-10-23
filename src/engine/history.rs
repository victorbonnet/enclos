//! A sandbox's policy history (design §7, ADR 0018): the versions, what one
//! changes from another, a rollback to an earlier one, and a refresh
//! against the current templates and adapters.

use super::Engine;
use super::pending::{Change, Recorded, change_summary};
use super::policy::{ChangeOutcome, PolicyApplied, differences};
use crate::error::{Error, Result};
use crate::model::audit::Actor;
use crate::model::plan::{Confirm, Plan, Planned};
use crate::model::policy::{PendingPolicy, PolicyInputs, PolicySnapshot, PolicyVersion};
use crate::model::sandbox::SandboxName;

/// Every version of a sandbox's policy, and what waits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyHistory {
    pub sandbox: SandboxName,
    /// Oldest first. The last one is in force: every new active version,
    /// a rollback's included, is appended.
    pub versions: Vec<PolicyVersion>,
    pub pending: Option<PendingPolicy>,
}

impl PolicyHistory {
    /// The version in force.
    pub fn active(&self) -> Option<&PolicyVersion> {
        self.versions.last()
    }
}

/// What a `policy diff` compares a version to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    Version(u32),
    Pending,
}

impl std::fmt::Display for Side {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Side::Version(n) => write!(f, "v{n}"),
            Side::Pending => f.write_str("the pending policy"),
        }
    }
}

/// What a policy changes from a version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyDiff {
    /// The version compared from.
    pub from: u32,
    pub to: Side,
    /// What `to` grants differently, one sentence each.
    pub changes: Vec<String>,
    /// How what they were resolved from differs: template, built-in
    /// defaults, adapter, enclos version.
    pub inputs: Vec<String>,
}

impl Engine {
    /// Every version of the sandbox's policy, oldest first.
    pub fn policy_history(&self, name: &SandboxName) -> Result<PolicyHistory> {
        let view = self.policy(name)?;
        Ok(PolicyHistory {
            sandbox: name.clone(),
            versions: self.state.policy_history(name)?,
            pending: view.pending.map(|(p, _)| p),
        })
    }

    /// What `to` changes from `from`. Without `to`: the pending policy,
    /// when there is one and `from` is not given or is the active version;
    /// else the active version. Without `from`: the active version when
    /// `to` is the pending policy, else the version before `to` (v1 for
    /// v1).
    pub fn policy_diff(
        &self,
        name: &SandboxName,
        from: Option<u32>,
        to: Option<u32>,
    ) -> Result<PolicyDiff> {
        let view = self.policy(name)?;
        let active = view.version.version;
        let (to, new) = match (to, view.pending) {
            (Some(n), _) => (Side::Version(n), self.version_snapshot(name, n)?),
            (None, Some((_, pending))) if from.is_none_or(|n| n == active) => {
                (Side::Pending, pending)
            }
            (None, _) => (Side::Version(active), view.snapshot),
        };
        let from = match (from, to) {
            (Some(n), _) => n,
            (None, Side::Pending) => active,
            (None, Side::Version(n)) => n.saturating_sub(1).max(1),
        };
        let old = self.version_snapshot(name, from)?;
        Ok(PolicyDiff {
            from,
            to,
            changes: differences(&old.policy, &new.policy, &[]),
            inputs: input_differences(&old.inputs, &new.inputs),
        })
    }

    /// Makes version `to`'s policy the sandbox's policy again, as a new
    /// version recording what it restores (none when it is the policy in
    /// force), and puts back its `policy.toml` so later edits start from it.
    /// It follows the restart rules of any change; a change pending is
    /// replaced, after asking (design §7).
    pub fn policy_rollback(
        &self,
        by: &Actor,
        name: &SandboxName,
        to: u32,
        confirm: Confirm,
    ) -> Result<Planned<PolicyApplied>> {
        self.require_sandbox(name)?;
        let target = self.version_snapshot(name, to)?;
        let text = target
            .overrides_text()
            .ok_or_else(|| Error::PolicyTextUnknown {
                sandbox: name.to_string(),
                version: to,
                file: self.layout.policy_file(name.as_str()),
            })?
            .to_owned();
        // Checked again as any policy stored: its paths as they are now, and
        // the secrets it grants, one of which may have been removed since.
        self.check_policy(name, &target.policy)
            .map_err(|error| Error::WithContext {
                what: format!(
                    "v{to} of sandbox {name} cannot be restored as things are now: {error}"
                ),
                error: Box::new(error),
            })?;
        let replacement = Replacement {
            command: "policy rollback",
            target_name: format!("{name} v{to}"),
            what: format!("roll sandbox {name} back to v{to}"),
            text: &text,
            snapshot: &target,
            restores: Some(to),
            asks: false,
        };
        self.replace_policy(by, name, replacement, confirm)
    }

    /// Resolves the active policy's `policy.toml` again against this enclos's
    /// templates, built-in defaults and the runtime's adapter, and turns any
    /// difference in what it resolves to into a change, asked first: a new
    /// enclos version never changes the policy on its own (design §7).
    pub fn policy_refresh(
        &self,
        by: &Actor,
        name: &SandboxName,
        confirm: Confirm,
    ) -> Result<Planned<PolicyApplied>> {
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
        let fresh = self.checked_policy(name, &text).map_err(|error| Error::WithContext {
            what: format!(
                "policy v{} of sandbox {name}, resolved against this enclos's templates and the runtime's adapter, is not accepted: {error}",
                view.version.version
            ),
            error: Box::new(error),
        })?;
        if fresh.policy == view.snapshot.policy && view.pending.is_none() {
            return Ok(Planned::Done(PolicyApplied {
                version: view.version,
                changed: false,
                also: Vec::new(),
                outcome: ChangeOutcome::InForce { dropped: None },
            }));
        }
        // The same policy resolved from newer inputs is no change: the
        // active snapshot stays, and with it what it was resolved from.
        let target = match fresh.policy == view.snapshot.policy {
            true => view.snapshot.clone(),
            false => fresh,
        };
        let replacement = Replacement {
            command: "policy refresh",
            target_name: name.to_string(),
            what: format!("refresh the policy of sandbox {name}"),
            text: &text,
            snapshot: &target,
            restores: None,
            asks: true,
        };
        self.replace_policy(by, name, replacement, confirm)
    }

    /// The snapshot of version `number`, or an error naming the versions.
    fn version_snapshot(&self, name: &SandboxName, number: u32) -> Result<PolicySnapshot> {
        match self.state.policy_version(name, number)? {
            Some((_, snapshot)) => Ok(snapshot),
            None => Err(Error::NoSuchPolicyVersion {
                sandbox: name.to_string(),
                version: number,
                last: self
                    .state
                    .policy_history(name)?
                    .last()
                    .map_or(0, |v| v.version),
            }),
        }
    }

    /// Makes the replacement's snapshot the sandbox's policy, as rollback
    /// and refresh do: listing what it changes, asking first as the command
    /// does, and replacing a change pending. `policy.toml` holding an edit
    /// not applied is refused rather than overwritten, and so is a policy
    /// that changed between this plan and the lock.
    fn replace_policy(
        &self,
        by: &Actor,
        name: &SandboxName,
        r: Replacement<'_>,
        confirm: Confirm,
    ) -> Result<Planned<PolicyApplied>> {
        let Replacement {
            command,
            target_name,
            what,
            text,
            snapshot: target,
            restores,
            asks,
        } = r;
        let view = self.policy(name)?;
        let changes = differences(&view.snapshot.policy, &target.policy, &[]);
        let dropped: Vec<String> = match &view.pending {
            Some((p, pending)) if pending.id != target.id => std::iter::once(format!(
                "drop the pending policy (snapshot {}), which would {}",
                p.snapshot.short(),
                summarize(&differences(&view.snapshot.policy, &pending.policy, &[]))
            ))
            .collect(),
            _ => Vec::new(),
        };
        self.refuse_unapplied_edit(name, view.latest(), command)?;
        match confirm {
            Confirm::DryRun => {
                let running = !self.sessions_under_rules(name)?.is_empty();
                let waits = running && !target.policy.same_at_launch(&view.snapshot.policy);
                let first = match (target.id == view.snapshot.id, waits) {
                    (true, _) => format!(
                        "{what}: it is the policy in force, v{}",
                        view.version.version
                    ),
                    (false, false) => format!("{what}, as a new policy version in force at once"),
                    (false, true) => format!(
                        "{what} as the pending policy, since sessions run under rules it changes; with --yes, restart the sandbox to apply it"
                    ),
                };
                let mut plan = vec![first];
                plan.extend(changes.iter().map(|c| format!("  {c}")));
                plan.extend(dropped);
                return Ok(Planned::DryRun(Plan {
                    changes: plan,
                    ..Plan::default()
                }));
            }
            Confirm::Ask if (asks && !changes.is_empty()) || !dropped.is_empty() => {
                let mut list = changes.clone();
                list.extend(dropped);
                return Err(Error::NeedsConfirmation {
                    what: format!("{what} ({})", list.join("; ")),
                });
            }
            _ => {}
        }
        let planned_with = (
            view.version.version,
            view.pending.as_ref().map(|(p, _)| p.snapshot.clone()),
        );
        let recorded = self.write(
            by,
            command,
            Some(target_name),
            |r: &Recorded| change_summary(&r.applied),
            |lock| {
                // Again under the lock: what was listed and asked must still
                // be what changes.
                let latest = self.policy(name)?;
                let now = (
                    latest.version.version,
                    latest.pending.as_ref().map(|(p, _)| p.snapshot.clone()),
                );
                if now != planned_with {
                    return Err(Error::PolicyChangedMeanwhile {
                        sandbox: name.to_string(),
                    });
                }
                self.refuse_unapplied_edit(name, latest.latest(), command)?;
                // `secret rm` may have removed a secret it grants meanwhile.
                self.check_secrets_set(name, &target.policy)?;
                let mut recorded = self.propose(
                    lock,
                    by,
                    name,
                    Change {
                        restores,
                        ..Change::edit(text, target)
                    },
                )?;
                recorded.applied.also = changes;
                Ok(recorded)
            },
        )?;
        Ok(Planned::Done(
            self.restart_if_asked(by, name, confirm, recorded)?,
        ))
    }

    /// Refuses when `policy.toml` holds anything but the text `latest`, the
    /// pending or else the active policy, was resolved from: an edit not
    /// applied, which putting back another file would lose. Without that
    /// text (a snapshot stored before snapshots kept it), nothing tells an
    /// edit apart, and nothing is refused.
    fn refuse_unapplied_edit(
        &self,
        name: &SandboxName,
        latest: &PolicySnapshot,
        command: &str,
    ) -> Result<()> {
        let Some(expected) = latest.overrides_text() else {
            return Ok(());
        };
        if self.layout.read_policy(name.as_str())? == expected {
            return Ok(());
        }
        Err(Error::PolicyFileEdited {
            sandbox: name.to_string(),
            file: self.layout.policy_file(name.as_str()),
            command: command.to_owned(),
        })
    }
}

/// A policy that rollback or refresh puts in place of the sandbox's.
struct Replacement<'a> {
    /// The audited command.
    command: &'static str,
    /// The audited target.
    target_name: String,
    /// The change, as plans and questions say it.
    what: String,
    /// The `policy.toml` it was resolved from.
    text: &'a str,
    snapshot: &'a PolicySnapshot,
    restores: Option<u32>,
    /// Whether the change itself is asked before it is made, as a
    /// refresh is; a rollback names what it does, as an edit does, and
    /// asks only before it drops a change pending.
    asks: bool,
}

/// How what two snapshots were resolved from differs, one sentence each.
fn input_differences(old: &PolicyInputs, new: &PolicyInputs) -> Vec<String> {
    let mut found = Vec::new();
    if old.template != new.template {
        found.push(format!(
            "built on the `{}` template instead of `{}`",
            new.template, old.template
        ));
    } else if old.template_hash != new.template_hash {
        found.push(format!(
            "built on another version of the `{}` template",
            new.template
        ));
    }
    if old.defaults != new.defaults {
        found.push("built on other built-in defaults".to_owned());
    }
    match (&old.adapter, &new.adapter) {
        (None, Some(a)) => found.push(format!("with the {} adapter's destinations", a.runtime)),
        (Some(a), None) => found.push(format!("without the {} adapter's destinations", a.runtime)),
        (Some(a), Some(b)) if (&a.runtime, &a.version) != (&b.runtime, &b.version) => {
            found.push(format!(
                "with the {} adapter {} instead of {} {}",
                b.runtime, b.version, a.runtime, a.version
            ))
        }
        (Some(a), Some(b)) if a.hash != b.hash => found.push(format!(
            "with other destinations from the {} adapter {}",
            b.runtime, b.version
        )),
        _ => {}
    }
    if old.enclos_version != new.enclos_version {
        found.push(format!(
            "resolved by enclos {} instead of {}",
            new.enclos_version, old.enclos_version
        ));
    }
    found
}

/// Changes said as one phrase: "let it write ~/work; allow a.example.com".
fn summarize(changes: &[String]) -> String {
    match changes {
        [] => "change nothing".to_owned(),
        changes => changes.join("; "),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::policy::AdapterInput;

    fn inputs() -> PolicyInputs {
        PolicyInputs {
            enclos_version: "0.1.0".into(),
            defaults: "d".into(),
            template: "assistant".parse().unwrap(),
            template_hash: "t".into(),
            adapter: None,
            overrides: "o".into(),
        }
    }

    fn adapter(version: &str, hash: &str) -> Option<AdapterInput> {
        Some(AdapterInput {
            runtime: "hermes".into(),
            version: version.into(),
            hash: hash.into(),
        })
    }

    #[test]
    fn inputs_that_differ_are_each_named() {
        let old = inputs();
        assert!(input_differences(&old, &old).is_empty());
        let mut new = old.clone();
        new.template_hash = "t2".into();
        new.adapter = adapter("2", "h");
        new.enclos_version = "0.2.0".into();
        assert_eq!(
            input_differences(&old, &new),
            [
                "built on another version of the `assistant` template",
                "with the hermes adapter's destinations",
                "resolved by enclos 0.2.0 instead of 0.1.0",
            ]
        );
        let mut other = old.clone();
        other.template = "minimal".parse().unwrap();
        other.defaults = "d2".into();
        assert_eq!(
            input_differences(&old, &other),
            [
                "built on the `minimal` template instead of `assistant`",
                "built on other built-in defaults",
            ]
        );
    }

    #[test]
    fn an_adapter_change_names_its_version_or_its_destinations() {
        let (mut a, mut b) = (inputs(), inputs());
        a.adapter = adapter("1", "h");
        b.adapter = adapter("2", "h");
        assert_eq!(
            input_differences(&a, &b),
            ["with the hermes adapter 2 instead of hermes 1"]
        );
        b.adapter = adapter("1", "h2");
        assert_eq!(
            input_differences(&a, &b),
            ["with other destinations from the hermes adapter 1"]
        );
        assert_eq!(
            input_differences(&a, &inputs()),
            ["without the hermes adapter's destinations"]
        );
    }
}
