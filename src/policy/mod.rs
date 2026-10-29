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
use crate::net::host::{AllowEntry, EntryError, canonical_private};
use file::PolicyFile;

/// The built-in defaults every template builds on.
pub const DEFAULTS: &str = include_str!("templates/defaults.toml");

/// The templates this build of enclos ships (design §7). `coding` comes
/// with the runtimes it is for.
const TEMPLATES: &[(&str, &str)] = &[
    ("minimal", include_str!("templates/minimal.toml")),
    ("mcp-only", include_str!("templates/mcp-only.toml")),
    ("assistant", include_str!("templates/assistant.toml")),
];

#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("cannot read the {layer} policy: {reason}")]
    Parse { layer: String, reason: String },
    #[error("unknown template `{0}`: this enclos has {names}", names = template_names().join(", "))]
    UnknownTemplate(String),
    // Never a default: a sandbox made from `minimal` whose line is dropped
    // would otherwise reach the public web without anyone saying so.
    #[error("`policy.toml` names no template: add `extends = \"<template>\"`, where this enclos has {names}", names = template_names().join(", "))]
    NoTemplate,
    #[error("a template cannot extend another; `{0}` names `extends`")]
    NestedTemplate(String),
    #[error(
        "the {runtime} adapter's layer may only add network destinations (`[network] allow_add`) and set `listen`; it sets {}",
        sets.join(", ")
    )]
    AdapterLayer { runtime: String, sets: Vec<String> },
    #[error("{}:\n  - {}", heading(problems), list(problems))]
    Invalid { problems: Vec<Problem> },
}

impl PolicyError {
    /// Whether the policy's own checks refused it (exit 2, design §10),
    /// rather than it being written wrong. A list with a malformed entry is
    /// an error: what it means is not known until it is fixed.
    pub fn is_refused(&self) -> bool {
        matches!(self, PolicyError::Invalid { problems } if all_refused(problems))
    }
}

/// One reason a policy is not accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Problem {
    /// The policy is written wrong: an entry that is not a path or a
    /// destination, or one that contradicts another (an opt-in for a host
    /// not in `network.allow`). Fixing it changes what the policy means.
    Malformed(String),
    /// What enclos does not accept as written: a destination a sandbox never
    /// reaches, a private address without its opt-in, every destination or
    /// a wildcard over a public suffix, a write to enclos's own files, a
    /// dropped built-in read-deny entry, or a path the compiled policy
    /// cannot hold (ADR 0009).
    Refused(String),
}

impl Problem {
    /// An allowlist entry's problem, worded `{context}: {error}`, refused or
    /// malformed as `error` is.
    pub fn entry(context: impl std::fmt::Display, error: EntryError) -> Problem {
        match error {
            EntryError::Refused(why) => Problem::Refused(format!("{context}: {why}")),
            EntryError::Malformed(why) => Problem::Malformed(format!("{context}: {why}")),
        }
    }

    pub fn is_refused(&self) -> bool {
        matches!(self, Problem::Refused(_))
    }
}

impl std::fmt::Display for Problem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Problem::Malformed(text) | Problem::Refused(text) => f.write_str(text),
        }
    }
}

fn all_refused(problems: &[Problem]) -> bool {
    !problems.is_empty() && problems.iter().all(Problem::is_refused)
}

fn heading(problems: &[Problem]) -> &'static str {
    if all_refused(problems) {
        "refused by policy"
    } else {
        "the policy is not valid"
    }
}

fn list(problems: &[Problem]) -> String {
    problems
        .iter()
        .map(Problem::to_string)
        .collect::<Vec<_>>()
        .join("\n  - ")
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
    let template_name = sandbox.extends.clone().ok_or(PolicyError::NoTemplate)?;
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
        // An adapter adds the destinations its runtime needs, and may let it
        // listen (ADR 0028), nothing else: it never widens writes, narrows
        // the deny list or replaces a list.
        let beyond = layer.beyond_destinations();
        if !beyond.is_empty() {
            return Err(PolicyError::AdapterLayer {
                runtime: adapter.runtime.clone(),
                sets: beyond.iter().map(|s| s.to_string()).collect(),
            });
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
    Ok(PolicySnapshot::new(
        snapshot_id(&inputs, &policy),
        inputs,
        policy,
        overrides.to_owned(),
    )
    .expect("the inputs name the text's own hash"))
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
    fn minimal_and_mcp_only_reach_only_what_is_listed() {
        for name in ["minimal", "mcp-only"] {
            let template: TemplateName = name.parse().unwrap();
            let snap = resolve(&initial_overrides("lab", &template), None).unwrap();
            assert_eq!(snap.inputs.template.as_str(), name);
            assert_eq!(
                snap.policy.net.mode,
                crate::model::policy::NetMode::Allowlist
            );
            assert!(snap.policy.net.allow.is_empty(), "{name}");
            assert_eq!(snap.policy.fs.write, ["{home}"]);
            // The defaults' deny list holds under every template.
            assert!(snap.policy.fs.read_deny.contains(&"~/.ssh".to_owned()));
        }
        assert_eq!(template_names(), ["minimal", "mcp-only", "assistant"]);
    }

    /// `minimal` and `mcp-only` are `assistant` with the public web closed:
    /// the same writes, deny list and listening, and nothing else apart.
    #[test]
    fn minimal_and_mcp_only_differ_from_assistant_only_in_the_network_mode() {
        let assistant = resolve(&overrides(""), None).unwrap().policy;
        assert_eq!(assistant.net.mode, crate::model::policy::NetMode::Public);
        for name in ["minimal", "mcp-only"] {
            let template: TemplateName = name.parse().unwrap();
            let mut closed = resolve(&initial_overrides("home", &template), None)
                .unwrap()
                .policy;
            closed.net.mode = crate::model::policy::NetMode::Public;
            assert_eq!(closed, assistant, "{name}");
        }
    }

    /// Under `minimal`, a Hermes sandbox reaches the hosts Hermes needs to
    /// install, log in and run, and may listen, as the Hermes adapter's
    /// layer sets.
    #[test]
    fn minimal_with_hermes_reaches_the_adapter_endpoints() {
        use crate::runtime::RuntimeAdapter;
        let hermes = AdapterLayer {
            runtime: "hermes".into(),
            version: "2".into(),
            text: crate::runtime::hermes::Hermes.endpoints().into(),
        };
        let template: TemplateName = "minimal".parse().unwrap();
        let snap = resolve(&initial_overrides("lab", &template), Some(&hermes)).unwrap();
        assert_eq!(
            snap.policy.net.mode,
            crate::model::policy::NetMode::Allowlist
        );
        for host in ["chatgpt.com", "auth.openai.com", "github.com"] {
            assert!(snap.policy.net.allow.contains(&host.to_owned()), "{host}");
        }
        assert!(snap.policy.net.listen);
    }

    /// A `policy.toml` that names no template is refused, never resolved
    /// over a default the file does not say.
    #[test]
    fn a_policy_naming_no_template_is_refused() {
        let text = overrides("").replace("extends = \"assistant\"\n", "");
        assert!(!text.contains("extends"));
        let err = resolve(&text, None).unwrap_err();
        assert!(matches!(err, PolicyError::NoTemplate), "{err}");
        assert!(!err.is_refused());
        let said = err.to_string();
        assert!(said.contains("minimal, mcp-only, assistant"), "{said}");
    }

    // The list repeats entries of `defaults.toml` on purpose: it guards against
    // one being dropped from the file, which `check_default_denies` cannot
    // catch since it compares against that same file.
    #[test]
    fn the_defaults_hide_logins_history_browsers_password_managers_assistant_tools_and_apple_data()
    {
        let snap = resolve(&overrides(""), None).unwrap();
        for entry in [
            // Credentials and keys
            "~/.cargo/credentials.toml",
            "~/.cargo/credentials",
            "~/.gem/credentials",
            "~/.pgpass",
            "~/.my.cnf",
            "~/.mylogin.cnf",
            "~/.vault-token",
            "~/.terraform.d/credentials.tfrc.json",
            "~/Library/Application Support/com.vercel.cli",
            "~/.config/hub",
            "~/.config/glab-cli",
            "~/.config/rclone",
            "~/.rclone.conf",
            "~/.cache/huggingface/token",
            "~/.cache/huggingface/stored_tokens",
            // History
            "~/.sh_history",
            "~/.zhistory",
            "~/.histfile",
            "~/.lesshst",
            "~/.local/share/atuin",
            // Browsers
            "~/Library/Application Support/Google/Chrome Beta",
            "~/Library/Application Support/Google/Chrome Canary",
            "~/Library/Application Support/Google/Chrome Dev",
            "~/Library/Application Support/Vivaldi",
            "~/Library/Application Support/com.operasoftware.Opera",
            "~/Library/Application Support/Orion",
            "~/Library/Containers/com.apple.Safari",
            "~/Library/HTTPStorages",
            "~/Library/WebKit",
            // Password managers
            "~/Library/Application Support/KeePassXC",
            "~/.password-store",
            "~/.config/op",
            "~/Library/Application Support/Bitwarden CLI",
            // Other assistant tools
            "~/Library/Application Support/Claude",
            "~/.gemini",
            "~/.cursor",
            "~/Library/Application Support/Cursor",
            "~/.config/opencode",
            "~/.local/share/opencode",
            // Mail and Apple apps' data
            "~/Library/Containers/com.apple.mail",
            "~/Library/Group Containers/group.com.apple.notes",
            "~/Library/Application Support/AddressBook",
            "~/Library/Calendars",
            "~/Library/Group Containers/group.com.apple.calendar",
            "~/Pictures/Photos Library.photoslibrary",
        ] {
            assert!(
                snap.policy.fs.read_deny.contains(&entry.to_owned()),
                "{entry} is not denied"
            );
        }
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

    fn layer(text: &str) -> AdapterLayer {
        AdapterLayer {
            runtime: "hermes".into(),
            version: "2".into(),
            text: text.into(),
        }
    }

    #[test]
    fn an_adapter_layer_may_set_listen_and_add_destinations_and_nothing_else() {
        let listens = resolve(&overrides(""), Some(&layer("[network]\nlisten = true\n"))).unwrap();
        assert!(listens.policy.net.listen);
        for (text, sets) in [
            (
                "[network]\nlisten = true\nlog = \"metadata\"\n",
                "network.log",
            ),
            ("[network]\nmode = \"public\"\n", "network.mode"),
            ("[filesystem]\nwrite_add = [\"~/x\"]\n", "filesystem"),
        ] {
            let err = resolve(&overrides(""), Some(&layer(text))).unwrap_err();
            let PolicyError::AdapterLayer { sets: found, .. } = err else {
                panic!("{text}: {err}");
            };
            assert_eq!(found, [sets], "{text}");
        }
    }

    #[test]
    fn policy_toml_turning_listening_off_wins_over_the_adapter() {
        let off = overrides("").replace("[network]", "[network]\nlisten = false");
        let snap = resolve(&off, Some(&layer("[network]\nlisten = true\n"))).unwrap();
        assert!(!snap.policy.net.listen);
    }

    #[test]
    fn a_policy_stored_before_listening_existed_does_not_listen() {
        let json = r#"{"fs":{"write":[],"read_deny":[]},"net":{"mode":"allowlist","allow":[],"private":[],"log":"metadata"}}"#;
        let policy: Policy = serde_json::from_str(json).unwrap();
        assert!(!policy.net.listen);
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
