//! Bounded, single-field edits of the active policy, reviewed before application.
use super::pending::{Change, Recorded};
use super::{Engine, PolicyApplied};
use crate::error::{Error, Result};
use crate::model::{audit::Actor, plan::Confirm, sandbox::SandboxName};
use crate::policy::{file::PolicyFile, sha256_hex};
use enclos_protocol::policy::{PolicyChange, PolicyField, PolicyPreview, PolicyState, PolicyValue};
use toml_edit::{Array, DocumentMut};

fn refused(message: impl Into<String>) -> Error {
    Error::Session {
        what: message.into(),
    }
}
fn location(key: &str) -> Result<(&'static str, &'static str, bool)> {
    Ok(match key {
        "write" => ("filesystem", "write", true),
        "read_deny" => ("filesystem", "read_deny", true),
        "allow" => ("network", "allow", true),
        "private" => ("network", "private", true),
        "mode" => ("network", "mode", false),
        "listen" => ("network", "listen", false),
        "open_files" => ("resources", "open_files", false),
        "file_size" => ("resources", "file_size", false),
        "cpu_seconds" => ("resources", "cpu_seconds", false),
        "memory" => ("resources", "memory", false),
        "cpu" => ("resources", "cpu", false),
        _ => return Err(refused("This policy field cannot be edited from the app.")),
    })
}
impl Engine {
    pub fn mobile_policy(&self, name: &SandboxName) -> Result<PolicyState> {
        let view = self.policy(name)?;
        let before = self.layout.read_policy(name.as_str())?;
        let editable = view.pending.is_none()
            && self
                .checked_policy(name, &before)
                .is_ok_and(|resolved| resolved.policy == view.snapshot.policy);
        let reason = (!editable).then(|| "A policy change is pending or the file has unapplied edits. Apply or discard it on the host first.".into());
        let base = sha256_hex(
            format!(
                "{}:{}:{:?}",
                view.snapshot.id,
                sha256_hex(before.as_bytes()),
                view.pending
            )
            .as_bytes(),
        );
        let layer = PolicyFile::parse("policy.toml", &before).unwrap_or_default();
        let defaults = PolicyFile::parse("built-in defaults", crate::policy::DEFAULTS)?;
        let p = &view.snapshot.policy;
        let mut fields = Vec::new();
        for (key, label, values, replace, additions, locked) in [
            (
                "allow",
                "Allowed destinations",
                p.net.allow.clone(),
                layer.network.allow.is_some(),
                layer.network.allow_add.clone(),
                Vec::new(),
            ),
            (
                "private",
                "Private network access",
                p.net.private.clone(),
                layer.network.private.is_some(),
                layer.network.private_add.clone(),
                Vec::new(),
            ),
            (
                "write",
                "Writable paths",
                p.fs.write.clone(),
                layer.filesystem.write.is_some(),
                layer.filesystem.write_add.clone(),
                Vec::new(),
            ),
            (
                "read_deny",
                "Protected read paths",
                p.fs.read_deny.clone(),
                layer.filesystem.read_deny.is_some(),
                layer.filesystem.read_deny_add.clone(),
                defaults.filesystem.read_deny.unwrap_or_default(),
            ),
        ] {
            // Lists replaced by this sandbox are local overrides; the others inherit their defaults.
            fields.push(PolicyField {
                key: key.into(),
                label: label.into(),
                multiple: true,
                editable: true,
                choices: vec![],
                values: values
                    .into_iter()
                    .map(|value| PolicyValue {
                        locked: locked.contains(&value),
                        source: if replace || additions.contains(&value) {
                            "Sandbox policy"
                        } else {
                            "Default / runtime"
                        }
                        .into(),
                        value,
                    })
                    .collect(),
            });
        }
        for (key, label, value, choices) in [
            (
                "mode",
                "Network mode",
                p.net.mode.to_string(),
                vec!["allowlist", "public"],
            ),
            (
                "listen",
                "Accept incoming connections",
                p.net.listen.to_string(),
                vec!["false", "true"],
            ),
            (
                "open_files",
                "Open file limit",
                p.resources
                    .open_files
                    .map(|n| n.to_string())
                    .unwrap_or_default(),
                vec![],
            ),
            (
                "file_size",
                "File size limit",
                p.resources
                    .file_size
                    .map(|n| n.to_string())
                    .unwrap_or_default(),
                vec![],
            ),
            (
                "cpu_seconds",
                "CPU time limit",
                p.resources
                    .cpu_seconds
                    .map(|n| n.to_string())
                    .unwrap_or_default(),
                vec![],
            ),
            (
                "memory",
                "Memory limit",
                p.resources.memory.clone().unwrap_or_default(),
                vec![],
            ),
            (
                "cpu",
                "CPU share",
                p.resources.cpu.clone().unwrap_or_default(),
                vec![],
            ),
        ] {
            fields.push(PolicyField {
                key: key.into(),
                label: label.into(),
                multiple: false,
                editable: true,
                choices: choices.into_iter().map(str::to_owned).collect(),
                values: if value.is_empty() {
                    vec![]
                } else {
                    vec![PolicyValue {
                        value,
                        source: "Active policy".into(),
                        locked: false,
                    }]
                },
            });
        }
        fields.push(PolicyField {
            key: "log".into(),
            label: "Network logging".into(),
            multiple: false,
            editable: false,
            choices: vec![],
            values: vec![PolicyValue {
                value: "Connection metadata only".into(),
                source: "Default".into(),
                locked: true,
            }],
        });
        let mut secrets: Vec<_> = p.secrets.iter().map(|(k, v)| format!("{k}: {v}")).collect();
        for (agent, grants) in &p.agent_secrets {
            secrets.extend(grants.iter().map(|(k, v)| format!("{agent} · {k}: {v}")));
        }
        fields.push(PolicyField {
            key: "secrets".into(),
            label: "Secret grants".into(),
            multiple: true,
            editable: false,
            choices: vec![],
            values: secrets
                .into_iter()
                .map(|value| PolicyValue {
                    value,
                    source: "Manage secrets on the host".into(),
                    locked: true,
                })
                .collect(),
        });
        Ok(PolicyState {
            sandbox: name.to_string(),
            version: view.version.version,
            base,
            editable,
            reason,
            fields,
            of: String::new(),
        })
    }

    fn mobile_edit(
        &self,
        name: &SandboxName,
        base: &str,
        edit: &PolicyChange,
    ) -> Result<(String, String, PolicyPreview)> {
        let state = self.mobile_policy(name)?;
        if !state.editable || state.base != base {
            return Err(refused(
                "The policy changed or has unapplied edits. Refresh and review it again.",
            ));
        }
        let field = state
            .fields
            .iter()
            .find(|f| f.key == edit.field)
            .ok_or_else(|| refused("Unknown policy field"))?;
        for text in [edit.before.as_deref(), edit.after.as_deref()]
            .into_iter()
            .flatten()
        {
            if text.is_empty() || text.len() > 4096 || text.chars().any(char::is_control) {
                return Err(refused(
                    "Name one path, destination or setting without control characters.",
                ));
            }
        }
        if edit.before == edit.after {
            return Err(refused("This edit changes nothing."));
        }
        if let Some(old) = &edit.before {
            let value = field
                .values
                .iter()
                .find(|v| &v.value == old)
                .ok_or_else(|| refused("This entry changed. Refresh the policy."))?;
            if value.locked {
                return Err(refused(
                    "This is a protected built-in policy entry and cannot be removed or changed.",
                ));
            }
        }
        let (section, key, multiple) = location(&edit.field)?;
        if !multiple && edit.after.is_none() {
            return Err(refused("Choose a replacement for this setting."));
        }
        if !multiple && edit.before.is_none() && !field.values.is_empty() {
            return Err(refused("Review the existing setting before replacing it."));
        }
        let before = self.layout.read_policy(name.as_str())?;
        let current = self.policy(name)?;
        let current_base = sha256_hex(
            format!(
                "{}:{}:{:?}",
                current.snapshot.id,
                sha256_hex(before.as_bytes()),
                current.pending
            )
            .as_bytes(),
        );
        if current_base != base
            || self.checked_policy(name, &before)?.policy != current.snapshot.policy
        {
            return Err(refused(
                "The policy changed while the edit was being prepared. Refresh and review it again.",
            ));
        }
        let mut doc = before
            .parse::<DocumentMut>()
            .map_err(|e| refused(e.to_string()))?;
        if doc.get(section).is_none() {
            doc[section] = toml_edit::Item::Table(toml_edit::Table::new());
        }
        if multiple {
            let mut values: Vec<_> = field.values.iter().map(|v| v.value.clone()).collect();
            if let Some(old) = &edit.before {
                values.retain(|v| v != old);
            }
            if let Some(new) = &edit.after {
                let value = if edit.field == "write" {
                    let expanded = self
                        .validation_context(name, self.recorded_backend(name)?)
                        .paths
                        .expand(new)
                        .map_err(|e| refused(e.to_string()))?;
                    crate::policy::paths::real_path(&expanded)
                        .display()
                        .to_string()
                } else {
                    new.clone()
                };
                if values.contains(&value) {
                    return Err(refused("This entry already exists."));
                }
                values.push(value);
            }
            values.sort();
            values.dedup();
            let mut array = Array::new();
            for value in values {
                array.push(value);
            }
            doc[section][key] = toml_edit::value(array);
            doc[section]
                .as_table_mut()
                .expect("existing policy section")
                .remove(&format!("{key}_add"));
        } else {
            let value = edit.after.as_deref().expect("checked replacement");
            doc[section][key] = match edit.field.as_str() {
                "listen" => toml_edit::value(
                    value
                        .parse::<bool>()
                        .map_err(|_| refused("Choose true or false."))?,
                ),
                "open_files" | "cpu_seconds" => toml_edit::value(
                    value
                        .parse::<i64>()
                        .ok()
                        .filter(|v| *v >= 0)
                        .ok_or_else(|| refused("Use a non-negative whole number."))?,
                ),
                _ => toml_edit::value(value),
            };
        }
        if edit.field == "allow"
            && let Some(old) = &edit.before
            && let Ok(removed) = crate::net::host::AllowEntry::parse(old)
        {
            let candidate = PolicyFile::parse("policy.toml", &doc.to_string())?;
            let mut policy = self.policy(name)?.snapshot.policy;
            candidate.apply(&mut policy);
            let host = removed.host_text();
            if policy.net.private.contains(&host)
                && !policy
                    .net
                    .allow
                    .iter()
                    .filter_map(|v| crate::net::host::AllowEntry::parse(v).ok())
                    .any(|e| e.matches(&host, e.port))
            {
                let mut remaining = Array::new();
                for value in policy.net.private.iter().filter(|v| *v != &host) {
                    remaining.push(value.as_str());
                }
                doc["network"]["private"] = toml_edit::value(remaining);
                doc["network"]
                    .as_table_mut()
                    .expect("network section")
                    .remove("private_add");
            }
        }
        let after = doc.to_string();
        let snapshot = self.checked_policy(name, &after)?;
        let current = self.policy(name)?;
        let mut changes =
            super::policy::policy_differences(&current.snapshot.policy, &snapshot.policy);
        if changes.is_empty() {
            return Err(refused("This edit changes nothing."));
        }
        if snapshot.policy.net.mode == crate::model::policy::NetMode::Public
            && edit.field == "allow"
        {
            changes.push("Public mode still allows public websites on ports 80 and 443, even without an explicit destination entry.".into());
        }
        let restart = !snapshot.policy.same_at_launch(&current.snapshot.policy)
            && !self.sessions_under_rules(name)?.is_empty();
        let revision = sha256_hex(format!("{base}:{}:{restart}", snapshot.id).as_bytes());
        Ok((
            before,
            after,
            PolicyPreview {
                sandbox: name.to_string(),
                base: base.into(),
                revision,
                change: edit.clone(),
                changes,
                restart,
                of: String::new(),
            },
        ))
    }
    pub fn mobile_policy_preview(
        &self,
        name: &SandboxName,
        base: &str,
        edit: &PolicyChange,
    ) -> Result<PolicyPreview> {
        self.mobile_edit(name, base, edit).map(|(_, _, p)| p)
    }
    pub fn mobile_policy_apply(
        &self,
        by: &Actor,
        name: &SandboxName,
        base: &str,
        revision: &str,
        edit: &PolicyChange,
    ) -> Result<PolicyApplied> {
        let recorded = self.write(
            by,
            "app policy edit",
            Some(name.to_string()),
            |_: &Recorded| "applied the reviewed policy edit".into(),
            |lock| {
                let (_, after, preview) = self.mobile_edit(name, base, edit)?;
                if preview.revision != revision {
                    return Err(refused(
                        "The policy changed. Review a fresh preview before saving.",
                    ));
                }
                let snapshot = self.checked_policy(name, &after)?;
                self.propose(lock, by, name, Change::edit(&after, &snapshot))
            },
        )?;
        self.restart_if_asked(by, name, Confirm::Yes, recorded)
    }
}
