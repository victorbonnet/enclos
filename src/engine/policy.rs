//! The engine's policy calls: show the active policy, allow a destination,
//! and write a new sandbox's first policy (design §7, ADR 0018).

use std::path::PathBuf;

use toml_edit::{Array, DocumentMut, Item, Table};

use super::Engine;
use crate::error::{Error, Result};
use crate::model::audit::Actor;
use crate::model::plan::{Confirm, Plan, Planned};
use crate::model::policy::{PolicySnapshot, PolicyVersion, TemplateName};
use crate::model::sandbox::SandboxName;
use crate::net::host::AllowEntry;
use crate::policy::paths::PathContext;
use crate::policy::validate::{ValidationContext, validate};
use crate::policy::{self, AdapterLayer, PolicyError};
use crate::state::StateLock;

/// A sandbox's active policy, as `enclos policy show` prints it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyView {
    pub sandbox: SandboxName,
    pub version: PolicyVersion,
    pub snapshot: PolicySnapshot,
    /// The sandbox's `policy.toml`.
    pub file: PathBuf,
}

/// What a policy change did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyApplied {
    /// The active version after the change.
    pub version: PolicyVersion,
    /// False when the policy already allowed it.
    pub changed: bool,
}

impl Engine {
    /// The sandbox's active policy.
    pub fn policy(&self, name: &SandboxName) -> Result<PolicyView> {
        self.require_sandbox(name)?;
        let (version, snapshot) =
            self.state
                .active_policy(name)?
                .ok_or_else(|| Error::NoPolicy {
                    sandbox: name.to_string(),
                })?;
        Ok(PolicyView {
            sandbox: name.clone(),
            version,
            snapshot,
            file: self.layout.policy_file(name.as_str()),
        })
    }

    /// Allows the sandbox to reach `destination` (`host`, `host:port` or
    /// `*.domain`). A network change applies at once: the proxy enforces it,
    /// so nothing restarts.
    pub fn policy_allow(
        &self,
        by: &Actor,
        name: &SandboxName,
        destination: &str,
        confirm: Confirm,
    ) -> Result<Planned<PolicyApplied>> {
        let entry = AllowEntry::parse(destination)
            .map_err(|e| PolicyError::Invalid {
                problems: vec![format!("`{destination}`: {e}")],
            })?
            .to_string();
        if confirm == Confirm::DryRun {
            self.require_sandbox(name)?;
            return Ok(Planned::DryRun(Plan {
                changes: vec![format!("allow {entry} in sandbox {name}; applies at once")],
                ..Plan::default()
            }));
        }
        let summary = |applied: &PolicyApplied| match applied.changed {
            true => format!("policy v{}", applied.version.version),
            false => "already allowed; nothing changed".to_owned(),
        };
        let applied = self.write(
            by,
            "policy allow",
            Some(format!("{name} {entry}")),
            summary,
            |lock| {
                self.require_sandbox(name)?;
                let current = self.layout.read_policy(name.as_str())?;
                let Some(updated) = with_allowed(&current, &entry)? else {
                    let version = self.policy(name)?.version;
                    return Ok(PolicyApplied {
                        version,
                        changed: false,
                    });
                };
                let version = self.save_policy(lock, by, name, &updated)?;
                Ok(PolicyApplied {
                    version,
                    changed: true,
                })
            },
        )?;
        Ok(Planned::Done(applied))
    }

    /// Writes a new sandbox's `policy.toml` from `template` and makes its
    /// resolution the sandbox's first policy version. The sandbox record must
    /// exist; the caller holds the lock and the audit entry.
    pub fn create_policy(
        &self,
        lock: &StateLock,
        by: &Actor,
        name: &SandboxName,
        template: &TemplateName,
    ) -> Result<PolicyVersion> {
        self.layout.create_sandbox_dirs(name.as_str())?;
        let overrides = policy::initial_overrides(name.as_str(), template);
        self.save_policy(lock, by, name, &overrides)
    }

    /// Resolves and checks `overrides`, records the snapshot as the active
    /// version, then writes the file it came from.
    fn save_policy(
        &self,
        lock: &StateLock,
        by: &Actor,
        name: &SandboxName,
        overrides: &str,
    ) -> Result<PolicyVersion> {
        let snapshot = policy::resolve(overrides, self.adapter_layer(name).as_ref())?;
        validate(&snapshot.policy, &self.validation_context(name))?;
        let version = self.state.save_policy(lock, name, &snapshot, by, None)?;
        self.layout.write_policy(name.as_str(), overrides)?;
        Ok(version)
    }

    fn validation_context(&self, name: &SandboxName) -> ValidationContext {
        ValidationContext {
            paths: PathContext {
                user_home: self.layout.user_home().to_owned(),
                sandbox_home: self.layout.sandbox_home(name.as_str()),
            },
            protected: self.layout.protected(),
        }
    }

    /// The installed runtime's endpoints. Agents arrive with the adapter issue.
    fn adapter_layer(&self, _name: &SandboxName) -> Option<AdapterLayer> {
        None
    }

    fn require_sandbox(&self, name: &SandboxName) -> Result<()> {
        match self.state.get(name)? {
            Some(_) => Ok(()),
            None => Err(Error::NoSuchSandbox {
                name: name.to_string(),
            }),
        }
    }
}

/// `policy.toml` with `entry` added to `[network] allow_add`, keeping the
/// user's comments and layout; `None` when the file already allows it.
fn with_allowed(text: &str, entry: &str) -> Result<Option<String>> {
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
        .as_table_mut()
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
        // A file without a [network] table gets one.
        let bare = with_allowed("extends = \"assistant\"\n", "a.example.com")
            .unwrap()
            .unwrap();
        assert!(
            bare.contains("[network]") && bare.contains("allow_add = [\"a.example.com\"]"),
            "{bare}"
        );
    }
}
