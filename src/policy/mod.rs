//! Policy resolution: built-in defaults, a template, a runtime adapter's
//! endpoints and a sandbox's `policy.toml`, resolved into an immutable
//! snapshot (design §7, ADRs 0008, 0018). Pure functions, no I/O.

pub mod file;
pub mod paths;
pub mod validate;

use sha2::{Digest, Sha256};

use crate::model::policy::{
    AdapterInput, Policy, PolicyInputs, PolicySnapshot, SnapshotId, TemplateName,
};
use crate::net::host::{AllowEntry, canonical_private};
use file::PolicyFile;

/// The built-in defaults every template builds on.
pub const DEFAULTS: &str = include_str!("templates/defaults.toml");

/// The templates this build of enclos ships (design §7). Milestone 1 has the
/// one Hermes uses.
const TEMPLATES: &[(&str, &str)] = &[("assistant", include_str!("templates/assistant.toml"))];

/// The template a new sandbox gets unless told otherwise.
pub const DEFAULT_TEMPLATE: &str = "assistant";

#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("cannot read the {layer} policy: {reason}")]
    Parse { layer: String, reason: String },
    #[error("unknown template `{0}`: this enclos has {names}", names = template_names().join(", "))]
    UnknownTemplate(String),
    #[error("a template cannot extend another; `{0}` names `extends`")]
    NestedTemplate(String),
    #[error("the policy is not valid:\n  - {}", problems.join("\n  - "))]
    Invalid { problems: Vec<String> },
}

pub fn template_names() -> Vec<&'static str> {
    TEMPLATES.iter().map(|(name, _)| *name).collect()
}

pub fn template(name: &TemplateName) -> Option<&'static str> {
    TEMPLATES
        .iter()
        .find(|(n, _)| *n == name.as_str())
        .map(|(_, text)| *text)
}

/// The endpoints a runtime adapter adds, as one policy layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdapterLayer {
    pub runtime: String,
    pub version: String,
    pub text: String,
}

/// The `policy.toml` a new sandbox starts with: the template, nothing more.
pub fn initial_overrides(sandbox: &str, template: &TemplateName) -> String {
    format!(
        "# Policy of sandbox `{sandbox}`: what it may do beyond the `{template}` template.\n\
         # Lists written `name = [...]` replace the template's; `name_add = [...]` extend them.\n\
         extends = \"{template}\"\n\
         \n\
         [filesystem]\n\
         write_add = []\n\
         read_deny_add = []\n\
         \n\
         [network]\n\
         allow_add = []\n"
    )
}

/// Resolves every layer under a sandbox's `policy.toml` into a snapshot.
pub fn resolve(
    overrides: &str,
    adapter: Option<&AdapterLayer>,
) -> Result<PolicySnapshot, PolicyError> {
    let sandbox = PolicyFile::parse("policy.toml", overrides)?;
    let template_name = match &sandbox.extends {
        Some(name) => name.clone(),
        None => DEFAULT_TEMPLATE
            .parse()
            .expect("the default template name is valid"),
    };
    let template_text = template(&template_name)
        .ok_or_else(|| PolicyError::UnknownTemplate(template_name.to_string()))?;
    let template_layer = PolicyFile::parse(&format!("`{template_name}` template"), template_text)?;
    if template_layer.extends.is_some() {
        return Err(PolicyError::NestedTemplate(template_name.to_string()));
    }

    let mut policy = Policy::default();
    PolicyFile::parse("built-in defaults", DEFAULTS)?.apply(&mut policy);
    template_layer.apply(&mut policy);
    if let Some(adapter) = adapter {
        let layer = PolicyFile::parse(&format!("{} adapter", adapter.runtime), &adapter.text)?;
        if layer.extends.is_some() {
            return Err(PolicyError::NestedTemplate(adapter.runtime.clone()));
        }
        layer.apply(&mut policy);
    }
    sandbox.apply(&mut policy);
    normalize(&mut policy);

    let inputs = PolicyInputs {
        enclos_version: env!("CARGO_PKG_VERSION").to_owned(),
        defaults: sha256_hex(DEFAULTS.as_bytes()),
        template: template_name,
        template_hash: sha256_hex(template_text.as_bytes()),
        adapter: adapter.map(|a| AdapterInput {
            runtime: a.runtime.clone(),
            version: a.version.clone(),
            hash: sha256_hex(a.text.as_bytes()),
        }),
        overrides: sha256_hex(overrides.as_bytes()),
    };
    Ok(PolicySnapshot {
        id: snapshot_id(&inputs, &policy),
        inputs,
        policy,
    })
}

/// The SHA-256 of a policy and its inputs, over their JSON form.
pub fn snapshot_id(inputs: &PolicyInputs, policy: &Policy) -> SnapshotId {
    let json = serde_json::to_string(&(inputs, policy)).expect("policies serialize");
    SnapshotId(sha256_hex(json.as_bytes()))
}

/// Puts lists in one canonical form, so the same grants give the same
/// snapshot whatever order or spelling the layers used.
fn normalize(policy: &mut Policy) {
    for entry in &mut policy.net.allow {
        if let Ok(parsed) = AllowEntry::parse(entry) {
            *entry = parsed.to_string();
        }
    }
    // The same canonical form validation and the proxy compare against.
    for entry in &mut policy.net.private {
        *entry = canonical_private(entry)
            .unwrap_or_else(|_| entry.trim().trim_end_matches('.').to_ascii_lowercase());
    }
    for list in [
        &mut policy.fs.write,
        &mut policy.fs.read_deny,
        &mut policy.net.allow,
        &mut policy.net.private,
    ] {
        list.sort();
        list.dedup();
    }
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A new sandbox's `policy.toml` with `allow_add` set to `allow`.
    fn overrides(allow: &str) -> String {
        initial_overrides("home", &"assistant".parse().unwrap())
            .replace("allow_add = []", &format!("allow_add = [{allow}]"))
    }

    #[test]
    fn private_entries_take_the_canonical_form_allow_entries_take() {
        let text = overrides("\"[fd00:0:0::1]:8443\", \"Printer.LAN.\"").replace(
            "[network]",
            "[network]\nprivate = [\"fd00:0:0::1\", \"Printer.LAN.\"]",
        );
        let snap = resolve(&text, None).unwrap();
        assert_eq!(snap.policy.net.private, ["fd00::1", "printer.lan"]);
        assert!(snap.policy.net.allow.contains(&"[fd00::1]:8443".to_owned()));
    }

    #[test]
    fn a_new_sandbox_resolves_to_the_defaults_and_its_template() {
        let snap = resolve(&overrides(""), None).unwrap();
        assert_eq!(snap.inputs.template.as_str(), "assistant");
        assert_eq!(snap.policy.fs.write, ["{home}"]);
        assert!(snap.policy.fs.read_deny.contains(&"~/.ssh".to_owned()));
        assert!(snap.policy.net.allow.is_empty());
        assert_eq!(snap.id.0.len(), 64);
    }

    #[test]
    fn resolution_is_deterministic_and_order_insensitive() {
        let a = resolve(&overrides("\"b.example.com\", \"A.example.com\""), None).unwrap();
        // The same file twice gives the same snapshot.
        assert_eq!(
            a.id,
            resolve(&overrides("\"b.example.com\", \"A.example.com\""), None)
                .unwrap()
                .id
        );
        assert_eq!(a.policy.net.allow, ["a.example.com", "b.example.com"]);
    }

    #[test]
    fn the_adapter_layer_adds_endpoints_and_is_recorded() {
        let adapter = AdapterLayer {
            runtime: "hermes".into(),
            version: "1.2.3".into(),
            text: "[network]\nallow_add = [\"chatgpt.com\"]\n".into(),
        };
        let with = resolve(&overrides(""), Some(&adapter)).unwrap();
        let without = resolve(&overrides(""), None).unwrap();
        assert_eq!(with.policy.net.allow, ["chatgpt.com"]);
        assert_eq!(with.inputs.adapter.as_ref().unwrap().version, "1.2.3");
        assert_ne!(with.id, without.id);
    }

    #[test]
    fn an_unknown_template_is_refused() {
        let err = resolve("extends = \"coding\"\n", None).unwrap_err();
        assert!(
            err.to_string().contains("unknown template `coding`"),
            "{err}"
        );
    }
}
