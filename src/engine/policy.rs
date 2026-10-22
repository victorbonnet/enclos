//! The engine's policy calls: show the active and pending policies and
//! allow a destination (design §7, ADR 0018). Changes that may need a
//! restart go through `pending.rs`.

use std::path::PathBuf;

use toml_edit::{Array, DocumentMut, Item, Table};

use super::Engine;
use super::pending::{Recorded, Restarted};
use crate::error::{Error, Result};
use crate::model::audit::Actor;
use crate::model::plan::{Confirm, Plan, Planned};
use crate::model::policy::{NetMode, PendingPolicy, Policy, PolicySnapshot, PolicyVersion};
use crate::model::runtime::RuntimeKind;
use crate::model::sandbox::SandboxName;
use crate::net::host::AllowEntry;
use crate::policy::paths::PathContext;
use crate::policy::validate::{ValidationContext, validate};
use crate::policy::{self, AdapterLayer, PolicyError, Problem};
use crate::state::StateLock;

/// A sandbox's active policy, and its pending one, as `enclos policy show`
/// prints them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyView {
    pub sandbox: SandboxName,
    pub version: PolicyVersion,
    pub snapshot: PolicySnapshot,
    /// A change saved while sessions ran under rules it changes, waiting
    /// for `policy apply`.
    pub pending: Option<(PendingPolicy, PolicySnapshot)>,
    /// The sandbox's `policy.toml`.
    pub file: PathBuf,
}

impl PolicyView {
    /// The policy the next change normally starts from: the pending one if
    /// there is one, since `policy.toml` holds it, else the active one.
    pub fn latest(&self) -> &PolicySnapshot {
        self.pending.as_ref().map_or(&self.snapshot, |(_, s)| s)
    }
}

/// What a policy change did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyApplied {
    /// The active version after the change.
    pub version: PolicyVersion,
    /// Whether the active policy changed: a new version is in force.
    pub changed: bool,
    /// What the change does besides the entry asked for, one sentence each:
    /// edits to `policy.toml` not applied yet, or a newer template or
    /// built-in defaults. For `policy edit`, everything it changes from the
    /// active policy.
    pub also: Vec<String>,
    pub outcome: ChangeOutcome,
}

/// Where a change ended up (design §7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChangeOutcome {
    /// In force for new sessions, and live for the network; `dropped` is
    /// the pending policy it replaced, if one waited.
    InForce { dropped: Option<PendingPolicy> },
    /// A change waits as the pending policy: this one, or one saved before
    /// it that this change left waiting.
    Pending(PendingPolicy),
    /// With `--yes`, the sandbox restarted into it.
    Restarted(Restarted),
}

/// What `policy allow` would do, worked out without changing anything.
struct AllowPlan {
    view: PolicyView,
    /// The file to write and what it resolves to; `None` when the policy
    /// already allows the entry.
    change: Option<(String, PolicySnapshot)>,
    also: Vec<String>,
}

impl Engine {
    /// The sandbox's active policy, and its pending one.
    pub fn policy(&self, name: &SandboxName) -> Result<PolicyView> {
        let (version, snapshot) = self.active_policy(name)?;
        Ok(PolicyView {
            sandbox: name.clone(),
            version,
            snapshot,
            pending: self.state.pending_policy(name)?,
            file: self.layout.policy_file(name.as_str()),
        })
    }

    /// Allows the sandbox to reach `destination` (`host`, `host:port` or
    /// `*.domain`). A network change applies at once: the proxy enforces it,
    /// so nothing restarts, and a change pending gets it too. The new
    /// version is what `policy.toml` resolves to, so when it changes more
    /// than this entry (edits not applied yet, a newer template or built-in
    /// defaults), it asks first; with `--yes`, a part that needs a restart
    /// restarts the sandbox (design §7).
    pub fn policy_allow(
        &self,
        by: &Actor,
        name: &SandboxName,
        destination: &str,
        confirm: Confirm,
    ) -> Result<Planned<PolicyApplied>> {
        let entry = AllowEntry::parse(destination)
            .map_err(|e| PolicyError::Invalid {
                problems: vec![Problem::entry(format!("`{destination}`"), e)],
            })?
            .to_string();
        let plan = self.plan_allow(name, &entry)?;
        match confirm {
            Confirm::DryRun => {
                let changes = match plan.change {
                    None => vec![format!(
                        "change nothing: sandbox {name} already allows {entry}"
                    )],
                    Some((_, ref snapshot)) => {
                        let mut changes: Vec<String> = std::iter::once(format!(
                            "allow {entry} in sandbox {name}; applies at once"
                        ))
                        .chain(plan.also.iter().map(|c| format!("also {c}")))
                        .collect();
                        let latest = &plan.view.latest().policy;
                        if !snapshot.policy.same_at_launch(&plan.view.snapshot.policy)
                            && !self.sessions_under_rules(name)?.is_empty()
                        {
                            changes.push(match snapshot.policy.same_at_launch(latest) {
                                true => format!(
                                    "keep the rest of the change pending in sandbox {name} until `enclos policy apply {name}`"
                                ),
                                false => format!(
                                    "save the rest as the pending policy of sandbox {name}, since sessions run under rules it changes; with --yes, restart the sandbox to apply it"
                                ),
                            });
                        }
                        changes
                    }
                };
                return Ok(Planned::DryRun(Plan {
                    changes,
                    ..Plan::default()
                }));
            }
            Confirm::Ask if !plan.also.is_empty() => {
                return Err(needs_confirmation(&entry, &plan.also));
            }
            _ => {}
        }
        let recorded = self.write(
            by,
            "policy allow",
            Some(format!("{name} {entry}")),
            |r: &Recorded| allow_summary(&r.applied),
            |lock| {
                // Again under the lock: the policy may have changed since.
                let plan = self.plan_allow(name, &entry)?;
                let Some((overrides, snapshot)) = plan.change else {
                    return Ok(Recorded {
                        applied: PolicyApplied {
                            version: plan.view.version,
                            changed: false,
                            also: Vec::new(),
                            outcome: match plan.view.pending {
                                Some((p, _)) => ChangeOutcome::Pending(p),
                                None => ChangeOutcome::InForce { dropped: None },
                            },
                        },
                        restarts: false,
                    });
                };
                if confirm == Confirm::Ask && !plan.also.is_empty() {
                    return Err(needs_confirmation(&entry, &plan.also));
                }
                let mut recorded =
                    self.propose(lock, by, name, &overrides, &snapshot, Some(&entry))?;
                recorded.applied.also = plan.also;
                Ok(recorded)
            },
        )?;
        Ok(Planned::Done(
            self.restart_if_asked(by, name, confirm, recorded)?,
        ))
    }

    fn plan_allow(&self, name: &SandboxName, entry: &str) -> Result<AllowPlan> {
        let view = self.policy(name)?;
        let allows = |s: &PolicySnapshot| s.policy.net.allow.iter().any(|a| a == entry);
        if allows(&view.snapshot) && allows(view.latest()) {
            return Ok(AllowPlan {
                view,
                change: None,
                also: Vec::new(),
            });
        }
        // The file may already list the entry, edited by hand but not applied
        // yet: only the active snapshot says what the proxy enforces.
        let current = self.layout.read_policy(name.as_str())?;
        let overrides = with_allowed(&current, entry)?.unwrap_or(current);
        let snapshot = self.checked_policy(name, &overrides)?;
        // What else goes in force with it is told against the active
        // policy; while sessions keep a change waiting, against that change,
        // which stays pending with this one.
        // The same test `propose` makes.
        let waits = !snapshot.policy.same_at_launch(&view.snapshot.policy)
            && !self.sessions_under_rules(name)?.is_empty();
        let base = match waits {
            true => view.latest(),
            false => &view.snapshot,
        };
        let also = differences(&base.policy, &snapshot.policy, &[entry]);
        Ok(AllowPlan {
            view,
            change: Some((overrides, snapshot)),
            also,
        })
    }

    /// Resolves and checks `overrides`, writes them to `policy.toml`, then
    /// records the snapshot as the active version.
    pub(super) fn save_policy(
        &self,
        lock: &StateLock,
        by: &Actor,
        name: &SandboxName,
        overrides: &str,
    ) -> Result<PolicyVersion> {
        let snapshot = self.checked_policy(name, overrides)?;
        self.store_policy(lock, by, name, overrides, &snapshot)
    }

    /// Resolves and checks `overrides` with `runtime`'s endpoints instead of
    /// the installed runtime's, writes them to `policy.toml`, then records
    /// the snapshot as the active version: while a runtime installs, before
    /// it is recorded.
    pub(super) fn save_policy_for_runtime(
        &self,
        lock: &StateLock,
        by: &Actor,
        name: &SandboxName,
        overrides: &str,
        runtime: Option<RuntimeKind>,
    ) -> Result<PolicyVersion> {
        let snapshot = self.checked_policy_with(name, overrides, runtime.map(adapter_layer))?;
        self.store_policy(lock, by, name, overrides, &snapshot)
    }

    /// `overrides` resolved and validated for this sandbox.
    pub(super) fn checked_policy(
        &self,
        name: &SandboxName,
        overrides: &str,
    ) -> Result<PolicySnapshot> {
        self.checked_policy_with(name, overrides, self.adapter_layer(name)?)
    }

    pub(super) fn checked_policy_with(
        &self,
        name: &SandboxName,
        overrides: &str,
        adapter: Option<AdapterLayer>,
    ) -> Result<PolicySnapshot> {
        let snapshot = policy::resolve(overrides, adapter.as_ref())?;
        validate(&snapshot.policy, &self.validation_context(name))?;
        Ok(snapshot)
    }

    /// Writes the file first, so the active version never runs ahead of it:
    /// if recording the version fails, the file goes back to what it was,
    /// and an error says so if that fails too.
    pub(super) fn store_policy(
        &self,
        lock: &StateLock,
        by: &Actor,
        name: &SandboxName,
        overrides: &str,
        snapshot: &PolicySnapshot,
    ) -> Result<PolicyVersion> {
        // A sandbox being created has no file yet: nothing to put back.
        let previous = match self.layout.read_policy(name.as_str()) {
            Ok(text) => Some(text),
            Err(crate::layout::LayoutError::Io { source, .. })
                if source.kind() == std::io::ErrorKind::NotFound =>
            {
                None
            }
            Err(e) => return Err(e.into()),
        };
        self.layout.write_policy(name.as_str(), overrides)?;
        // The same policy as the active one is not a new version.
        if let Some((active, current)) = self.state.active_policy(name)?
            && current.id == snapshot.id
        {
            return Ok(active);
        }
        match self.state.save_policy(lock, name, snapshot, by, None) {
            Ok(version) => Ok(version),
            Err(e) => Err(match previous {
                Some(previous) => self.restore_policy(name, &previous, e.into()),
                None => e.into(),
            }),
        }
    }

    pub(super) fn validation_context(&self, name: &SandboxName) -> ValidationContext {
        ValidationContext {
            paths: PathContext {
                user_home: self.layout.user_home().to_owned(),
                sandbox_home: self.layout.sandbox_home(name.as_str()),
            },
            protected: self.layout.protected(),
        }
    }

    /// The installed runtime's endpoints, as a policy layer (design §7). A
    /// state that cannot be read is an error: resolving without the layer
    /// would record a policy that lacks them.
    fn adapter_layer(&self, name: &SandboxName) -> Result<Option<AdapterLayer>> {
        let record = self.state.get(name)?.ok_or_else(|| Error::NoSuchSandbox {
            name: name.to_string(),
        })?;
        Ok(record.runtime.map(adapter_layer))
    }
}

/// `kind`'s endpoints as a policy layer.
pub(super) fn adapter_layer(kind: RuntimeKind) -> AdapterLayer {
    let runtime = crate::runtime::adapter(kind);
    AdapterLayer {
        runtime: kind.to_string(),
        version: runtime.version().to_owned(),
        text: runtime.endpoints().to_owned(),
    }
}

fn allow_summary(applied: &PolicyApplied) -> String {
    let version = applied.version.version;
    let others = match applied.also.len() {
        0 => String::new(),
        n => format!(", with {n} other changes: {}", applied.also.join("; ")),
    };
    match (&applied.outcome, applied.changed) {
        (ChangeOutcome::Pending(p), true) => format!(
            "policy v{version} in force; pending snapshot {}{others}",
            p.snapshot.short()
        ),
        (ChangeOutcome::Pending(p), false) => format!(
            "waits with pending snapshot {}; policy v{version} stays in force{others}",
            p.snapshot.short()
        ),
        (_, false) => "already allowed; nothing changed".to_owned(),
        (_, true) => format!("policy v{version}{others}"),
    }
}

fn needs_confirmation(entry: &str, also: &[String]) -> Error {
    Error::NeedsConfirmation {
        what: format!(
            "allowing {entry} together with {} other changes to the policy ({})",
            also.len(),
            also.join("; ")
        ),
    }
}

/// What `new` grants differently from `old`, one sentence each.
pub fn policy_differences(old: &Policy, new: &Policy) -> Vec<String> {
    differences(old, new, &[])
}

/// What `new` grants differently from `old`, besides allowing `expected`.
pub(super) fn differences(old: &Policy, new: &Policy, expected: &[&str]) -> Vec<String> {
    let mut found = Vec::new();
    let mut compare = |old: &[String], new: &[String], added: &str, removed: &str| {
        for e in new
            .iter()
            .filter(|e| !old.contains(e) && !expected.contains(&e.as_str()))
        {
            found.push(added.replace("{}", e));
        }
        for e in old.iter().filter(|e| !new.contains(e)) {
            found.push(removed.replace("{}", e));
        }
    };
    compare(
        &old.fs.write,
        &new.fs.write,
        "let it write {} (sessions started from now on)",
        "stop it writing {} (sessions started from now on)",
    );
    compare(
        &old.fs.read_deny,
        &new.fs.read_deny,
        "hide {} from it (sessions started from now on)",
        "let it read {} (sessions started from now on)",
    );
    compare(
        &old.net.allow,
        &new.net.allow,
        "allow {}",
        "stop allowing {}",
    );
    compare(
        &old.net.private,
        &new.net.private,
        "let {} reach private addresses",
        "stop {} reaching private addresses",
    );
    if old.net.mode != new.net.mode {
        found.push(match new.net.mode {
            NetMode::Public => {
                "open the public web to it: any public address on ports 80 and 443".to_owned()
            }
            NetMode::Allowlist => "limit its network to the allowlist".to_owned(),
        });
    }
    if old.net.listen != new.net.listen {
        found.push(listen_change(new.net.listen));
    }
    found
}

/// How a change of [`NetPolicy::listen`](crate::model::policy::NetPolicy)
/// to `listen` is worded (ADR 0028).
pub(super) fn listen_change(listen: bool) -> String {
    match listen {
        true => "let it listen on TCP, on any port but enclos's proxy ports, on every address (sessions started from now on)".to_owned(),
        false => "stop it listening on TCP (sessions started from now on)".to_owned(),
    }
}

/// `policy.toml` with `entry` added to `[network] allow_add`, keeping the
/// user's comments and layout; `None` when the file already allows it.
pub(super) fn with_allowed(text: &str, entry: &str) -> Result<Option<String>> {
    let mut doc: DocumentMut =
        text.parse()
            .map_err(|e: toml_edit::TomlError| PolicyError::Parse {
                layer: "policy.toml".to_owned(),
                reason: e.to_string().trim().to_owned(),
            })?;
    let listed = |key: &str| {
        doc.get("network")
            .and_then(|n| n.get(key))
            .and_then(Item::as_array)
            .is_some_and(|list| {
                list.iter()
                    .filter_map(|v| v.as_str())
                    .any(|v| AllowEntry::parse(v).is_ok_and(|e| e.to_string() == entry))
            })
    };
    if listed("allow") || listed("allow_add") {
        return Ok(None);
    }
    let not_a_table = || PolicyError::Parse {
        layer: "policy.toml".to_owned(),
        reason: "`network` must be a table and `network.allow_add` a list".to_owned(),
    };
    let network = doc
        .entry("network")
        .or_insert(Item::Table(Table::new()))
        .as_table_like_mut()
        .ok_or_else(not_a_table)?;
    let list = network
        .entry("allow_add")
        .or_insert(toml_edit::value(Array::new()))
        .as_array_mut()
        .ok_or_else(not_a_table)?;
    list.push(entry);
    Ok(Some(doc.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowing_keeps_comments_and_skips_what_is_already_allowed() {
        let text = "# mine\nextends = \"assistant\"\n\n[network]\n# trusted APIs\nallow_add = [\"api.example.com\"]\n";
        let updated = with_allowed(text, "weather.example.com").unwrap().unwrap();
        assert!(
            updated.contains("# mine") && updated.contains("# trusted APIs"),
            "{updated}"
        );
        assert!(updated.contains("\"weather.example.com\""), "{updated}");
        assert_eq!(with_allowed(text, "api.example.com").unwrap(), None);
        // An inline or dotted network table is edited where it is.
        for text in [
            "network = { allow_add = [\"a.example.com\"] }\n",
            "network.allow_add = [\"a.example.com\"]\n",
        ] {
            let updated = with_allowed(text, "b.example.com").unwrap().unwrap();
            let parsed = policy::resolve(&updated, None).unwrap();
            assert_eq!(
                parsed.policy.net.allow,
                ["a.example.com", "b.example.com"],
                "{updated}"
            );
        }
        // A file without a [network] table gets one.
        let bare = with_allowed("extends = \"assistant\"\n", "a.example.com")
            .unwrap()
            .unwrap();
        assert!(
            bare.contains("[network]") && bare.contains("allow_add = [\"a.example.com\"]"),
            "{bare}"
        );
    }

    #[test]
    fn differences_leave_out_the_entry_asked_for() {
        let mut old = Policy::default();
        old.fs.read_deny = vec!["~/.ssh".into(), "~/dev/work".into()];
        let mut new = old.clone();
        new.net.allow = vec!["a.example.com".into(), "b.example.com".into()];
        new.fs.write = vec!["~/work".into()];
        new.fs.read_deny.pop();
        assert_eq!(
            differences(&old, &new, &["a.example.com"]),
            [
                "let it write ~/work (sessions started from now on)",
                "let it read ~/dev/work (sessions started from now on)",
                "allow b.example.com",
            ]
        );
        assert!(differences(&old, &old, &["a.example.com"]).is_empty());
        let mut public = old.clone();
        public.net.mode = NetMode::Public;
        assert_eq!(
            differences(&old, &public, &["a.example.com"]),
            ["open the public web to it: any public address on ports 80 and 443"]
        );
        assert_eq!(
            differences(&public, &old, &["a.example.com"]),
            ["limit its network to the allowlist"]
        );
        let mut listens = old.clone();
        listens.net.listen = true;
        assert_eq!(
            differences(&old, &listens, &[]),
            [
                "let it listen on TCP, on any port but enclos's proxy ports, on every address (sessions started from now on)"
            ]
        );
        assert_eq!(
            differences(&listens, &old, &[]),
            ["stop it listening on TCP (sessions started from now on)"]
        );
    }
}
