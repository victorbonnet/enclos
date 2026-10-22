//! One layer of policy as written in TOML: the built-in defaults, a template,
//! an adapter's endpoints, or a sandbox's `policy.toml` (design §7).
//!
//! A list written `name = [...]` replaces what the layers below set, and
//! `name_add = [...]` extends it.

use serde::Deserialize;

use super::PolicyError;
use crate::model::policy::{NetLog, NetMode, Policy, TemplateName};
use crate::model::secret::SecretGrant;

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyFile {
    /// The template this policy builds on; only a sandbox's `policy.toml`
    /// names one.
    pub extends: Option<TemplateName>,
    #[serde(default)]
    pub filesystem: FsLayer,
    #[serde(default)]
    pub network: NetLayer,
    #[serde(default)]
    pub secrets: SecretsLayer,
}

/// The secrets a layer grants, by environment variable: `env` replaces what
/// the layers below grant, and `env_add` adds to it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct SecretsLayer {
    pub env: Option<std::collections::BTreeMap<String, SecretGrant>>,
    pub env_add: std::collections::BTreeMap<String, SecretGrant>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct FsLayer {
    pub write: Option<Vec<String>>,
    pub write_add: Vec<String>,
    pub read_deny: Option<Vec<String>>,
    pub read_deny_add: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct NetLayer {
    pub mode: Option<NetMode>,
    pub allow: Option<Vec<String>>,
    pub allow_add: Vec<String>,
    pub private: Option<Vec<String>>,
    pub private_add: Vec<String>,
    pub log: Option<NetLog>,
    pub listen: Option<bool>,
}

impl PolicyFile {
    /// What this layer sets besides adding network destinations and
    /// listening: a runtime adapter's layer may do nothing else (design §7,
    /// ADR 0028).
    pub fn beyond_destinations(&self) -> Vec<&'static str> {
        let mut found = Vec::new();
        if self.extends.is_some() {
            found.push("extends");
        }
        if self.filesystem != FsLayer::default() {
            found.push("filesystem");
        }
        if self.network.mode.is_some() {
            found.push("network.mode");
        }
        if self.network.allow.is_some() {
            found.push("network.allow");
        }
        if self.network.private.is_some() || !self.network.private_add.is_empty() {
            found.push("network.private");
        }
        if self.network.log.is_some() {
            found.push("network.log");
        }
        if self.secrets != SecretsLayer::default() {
            found.push("secrets");
        }
        found
    }

    /// Parses one layer; `name` says which in errors, such as `policy.toml`.
    pub fn parse(name: &str, text: &str) -> Result<PolicyFile, PolicyError> {
        toml::from_str(text).map_err(|e| PolicyError::Parse {
            layer: name.to_owned(),
            // toml's message names the line and what it expected.
            reason: e.to_string().trim().to_owned(),
        })
    }

    /// Applies this layer on top of `policy`.
    pub fn apply(&self, policy: &mut Policy) {
        layer(
            &mut policy.fs.write,
            &self.filesystem.write,
            &self.filesystem.write_add,
        );
        layer(
            &mut policy.fs.read_deny,
            &self.filesystem.read_deny,
            &self.filesystem.read_deny_add,
        );
        layer(
            &mut policy.net.allow,
            &self.network.allow,
            &self.network.allow_add,
        );
        layer(
            &mut policy.net.private,
            &self.network.private,
            &self.network.private_add,
        );
        if let Some(mode) = self.network.mode {
            policy.net.mode = mode;
        }
        if let Some(log) = self.network.log {
            policy.net.log = log;
        }
        if let Some(listen) = self.network.listen {
            policy.net.listen = listen;
        }
        if let Some(env) = &self.secrets.env {
            policy.secrets.clone_from(env);
        }
        policy.secrets.extend(
            self.secrets
                .env_add
                .iter()
                .map(|(k, v)| (k.clone(), v.clone())),
        );
    }
}

fn layer(list: &mut Vec<String>, replace: &Option<Vec<String>>, add: &[String]) {
    if let Some(replace) = replace {
        list.clone_from(replace);
    }
    list.extend(add.iter().cloned());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_list_replaces_and_an_add_list_extends() {
        let mut policy = Policy::default();
        PolicyFile::parse("a", "[network]\nallow = [\"a.com\", \"b.com\"]")
            .unwrap()
            .apply(&mut policy);
        PolicyFile::parse("b", "[network]\nallow_add = [\"c.com\"]")
            .unwrap()
            .apply(&mut policy);
        assert_eq!(policy.net.allow, ["a.com", "b.com", "c.com"]);
        PolicyFile::parse("c", "[network]\nallow = [\"d.com\"]")
            .unwrap()
            .apply(&mut policy);
        assert_eq!(policy.net.allow, ["d.com"]);
    }

    #[test]
    fn the_last_layer_naming_a_mode_sets_it() {
        let mut policy = Policy::default();
        assert_eq!(policy.net.mode, NetMode::Allowlist);
        PolicyFile::parse("a", "[network]\nmode = \"public\"")
            .unwrap()
            .apply(&mut policy);
        PolicyFile::parse("b", "[network]\nallow_add = [\"c.com\"]")
            .unwrap()
            .apply(&mut policy);
        assert_eq!(policy.net.mode, NetMode::Public);
        PolicyFile::parse("c", "[network]\nmode = \"allowlist\"")
            .unwrap()
            .apply(&mut policy);
        assert_eq!(policy.net.mode, NetMode::Allowlist);
        let err = PolicyFile::parse("d", "[network]\nmode = \"open\"").unwrap_err();
        assert!(err.to_string().contains("open"), "{err}");
    }

    #[test]
    fn the_last_layer_naming_listen_sets_it() {
        let mut policy = Policy::default();
        assert!(!policy.net.listen);
        PolicyFile::parse("adapter", "[network]\nlisten = true")
            .unwrap()
            .apply(&mut policy);
        PolicyFile::parse("b", "[network]\nallow_add = [\"c.com\"]")
            .unwrap()
            .apply(&mut policy);
        assert!(policy.net.listen);
        PolicyFile::parse("policy.toml", "[network]\nlisten = false")
            .unwrap()
            .apply(&mut policy);
        assert!(!policy.net.listen);
    }

    #[test]
    fn listening_is_not_beyond_what_an_adapter_layer_may_set() {
        let layer = PolicyFile::parse(
            "adapter",
            "[network]\nlisten = true\nallow_add = [\"a.com\"]",
        )
        .unwrap();
        assert!(layer.beyond_destinations().is_empty());
    }

    #[test]
    fn secrets_are_granted_by_variable_and_an_adapter_grants_none() {
        let mut policy = Policy::default();
        PolicyFile::parse(
            "a",
            "[secrets]\nenv = { A = \"secret:home/aa\", B = \"secret:home/bb\" }",
        )
        .unwrap()
        .apply(&mut policy);
        PolicyFile::parse("b", "[secrets]\nenv_add = { B = \"secret:home/cc\" }")
            .unwrap()
            .apply(&mut policy);
        assert_eq!(policy.secrets["A"].to_string(), "secret:home/aa");
        assert_eq!(policy.secrets["B"].to_string(), "secret:home/cc");
        PolicyFile::parse("c", "[secrets]\nenv = {}")
            .unwrap()
            .apply(&mut policy);
        assert!(policy.secrets.is_empty());
        let layer = PolicyFile::parse("adapter", "[secrets]\nenv_add = { X = \"secret:home/xx\" }")
            .unwrap();
        assert_eq!(layer.beyond_destinations(), ["secrets"]);
        // A grant that names no secret is refused as the file is read.
        let err = PolicyFile::parse("d", "[secrets]\nenv = { X = \"home/x\" }").unwrap_err();
        assert!(err.to_string().contains("secret:<sandbox>/<name>"), "{err}");
    }

    #[test]
    fn sections_milestone_1_does_not_enforce_are_refused() {
        let err = PolicyFile::parse("policy.toml", "[exec]\nshell = false").unwrap_err();
        assert!(err.to_string().contains("policy.toml"), "{err}");
        assert!(err.to_string().contains("exec"), "{err}");
    }

    #[test]
    fn a_misspelled_field_is_refused() {
        let err = PolicyFile::parse("policy.toml", "[network]\nalow = []").unwrap_err();
        assert!(err.to_string().contains("alow"), "{err}");
    }

    #[test]
    fn the_built_in_layers_parse() {
        for (name, text) in [
            ("defaults", include_str!("templates/defaults.toml")),
            ("assistant", include_str!("templates/assistant.toml")),
        ] {
            PolicyFile::parse(name, text).unwrap();
        }
    }
}
