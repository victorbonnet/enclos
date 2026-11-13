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
        checked_text(edit)?;
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
            let values: Vec<_> = field.values.iter().map(|v| v.value.clone()).collect();
            let mut added = None;
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
                if values.contains(&value) && edit.before.as_ref() != Some(&value) {
                    return Err(refused("This entry already exists."));
                }
                added = Some(value);
            }
            edit_list(
                &mut doc,
                section,
                key,
                edit.before.as_deref(),
                added.as_deref(),
            )?;
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
            // Resolved as stored, before validation, which refuses the
            // opt-in this edit leaves unused.
            let policy =
                crate::policy::resolve(&doc.to_string(), self.adapter_layer(name)?.as_ref())?
                    .policy;
            let host = removed.host_text();
            if policy.net.private.contains(&host)
                && !policy
                    .net
                    .allow
                    .iter()
                    .filter_map(|v| crate::net::host::AllowEntry::parse(v).ok())
                    .any(|e| e.matches(&host, e.port))
            {
                edit_list(&mut doc, "network", "private", Some(&host), None)?;
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
        // Before the audit entry, which names the edit: the device's text
        // is bounded and readable there too
        checked_text(edit)?;
        location(&edit.field)?;
        let recorded = self.write(
            by,
            "app policy edit",
            // The edit itself, so the audit says what changed, not only where.
            Some(format!(
                "{name} {}: {} -> {}",
                edit.field,
                edit.before.as_deref().unwrap_or("(none)"),
                edit.after.as_deref().unwrap_or("(none)")
            )),
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

/// A phone edit's values: bounded, on one line, and, for what it adds,
/// with nothing hidden, since the policy page, the audit log and the
/// agents' context show it later. An entry already in the file is named as
/// it is, to be removed.
fn checked_text(edit: &PolicyChange) -> Result<()> {
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
    if edit
        .after
        .as_deref()
        .is_some_and(|text| enclos_protocol::visible::has_hidden(text, false))
    {
        return Err(refused(
            "This value contains hidden characters, which would change how it reads.",
        ));
    }
    Ok(())
}

/// Edits one list of the sandbox's own layer and leaves what it inherits
/// inherited: never a copy of the resolved list, which would freeze the
/// template's, the runtime adapter's and the built-in defaults' entries in
/// this file, so a later enclos or runtime that changes them would not reach
/// this sandbox (and a frozen `read_deny` would miss a new default denial).
/// `old` comes out of the list that holds it, or, inherited, goes to
/// `<key>_remove`; `new` goes back from `<key>_remove`, or into the list
/// this file replaces, or to `<key>_add`.
fn edit_list(
    doc: &mut DocumentMut,
    section: &str,
    key: &str,
    old: Option<&str>,
    new: Option<&str>,
) -> Result<()> {
    let read = |doc: &DocumentMut, name: &str| -> Result<Option<Vec<String>>> {
        match doc.get(section).and_then(|s| s.get(name)) {
            None => Ok(None),
            Some(item) => item
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(str::to_owned))
                        .collect()
                })
                .map(Some)
                .ok_or_else(|| refused(format!("{section}.{name} is not a list."))),
        }
    };
    let (add_key, remove_key) = (format!("{key}_add"), format!("{key}_remove"));
    let mut replace = read(doc, key)?;
    let mut adds = read(doc, &add_key)?;
    let mut removes = read(doc, &remove_key)?.unwrap_or_default();
    if let Some(old) = old {
        if let Some(list) = replace.as_mut().filter(|l| l.iter().any(|v| v == old)) {
            list.retain(|v| v != old);
        } else if let Some(list) = adds.as_mut().filter(|l| l.iter().any(|v| v == old)) {
            list.retain(|v| v != old);
        } else if !removes.iter().any(|v| v == old) {
            removes.push(old.to_owned());
        }
    }
    if let Some(new) = new {
        if removes.iter().any(|v| v == new) {
            removes.retain(|v| v != new);
        } else if let Some(list) = replace.as_mut() {
            list.push(new.to_owned());
        } else {
            adds.get_or_insert_with(Vec::new).push(new.to_owned());
        }
    }
    let array = |values: Vec<String>| {
        let mut array = Array::new();
        for value in values {
            array.push(value);
        }
        toml_edit::value(array)
    };
    if let Some(list) = replace {
        doc[section][key] = array(list);
    }
    if let Some(list) = adds {
        doc[section][add_key.as_str()] = array(list);
    }
    if removes.is_empty() {
        if let Some(table) = doc[section].as_table_like_mut() {
            table.remove(&remove_key);
        }
    } else {
        doc[section][remove_key.as_str()] = array(removes);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn edited(text: &str, old: Option<&str>, new: Option<&str>) -> PolicyFile {
        let mut doc = text.parse::<DocumentMut>().unwrap();
        edit_list(&mut doc, "network", "allow", old, new).unwrap();
        PolicyFile::parse("policy.toml", &doc.to_string()).unwrap()
    }

    #[test]
    fn an_inherited_entry_is_removed_by_name_and_comes_back_by_name() {
        let layer = edited(
            "[network]\nallow_add = [\"mine.com\"]\n",
            Some("inherited.com"),
            None,
        );
        assert_eq!(layer.network.allow, None);
        assert_eq!(layer.network.allow_remove, ["inherited.com"]);
        assert_eq!(layer.network.allow_add, ["mine.com"]);
        let layer = edited(
            "[network]\nallow_remove = [\"inherited.com\"]\n",
            None,
            Some("inherited.com"),
        );
        assert!(layer.network.allow_remove.is_empty());
        assert!(layer.network.allow_add.is_empty());
    }

    #[test]
    fn the_files_own_entries_are_edited_where_they_are() {
        let layer = edited(
            "[network]\nallow_add = [\"a.com\"]\n",
            Some("a.com"),
            Some("b.com"),
        );
        assert_eq!(layer.network.allow_add, ["b.com"]);
        assert!(layer.network.allow_remove.is_empty());
        // A list this file already replaces stays its replacement.
        let layer = edited(
            "[network]\nallow = [\"a.com\"]\n",
            Some("a.com"),
            Some("b.com"),
        );
        assert_eq!(layer.network.allow, Some(vec!["b.com".to_owned()]));
        assert!(layer.network.allow_add.is_empty());
        // A first entry goes to `allow_add`, never a copy of the resolved list.
        let layer = edited("[network]\n", None, Some("c.com"));
        assert_eq!(layer.network.allow, None);
        assert_eq!(layer.network.allow_add, ["c.com"]);
    }
}
