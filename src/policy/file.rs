//! One layer of policy as written in TOML: the built-in defaults, a template,
//! an adapter's endpoints, or a sandbox's `policy.toml` (design §7).
//!
//! A list written `name = [...]` replaces what the layers below set, and
//! `name_add = [...]` extends it.

use serde::Deserialize;

use super::PolicyError;
use crate::model::policy::{ByteSize, NetLog, NetMode, Policy, TemplateName};
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
    #[serde(default)]
    pub resources: ResourcesLayer,
}

/// The limits a layer sets, each replacing the one the layers below set.
/// `memory` and `cpu` are read as text, whatever their form: kept as
/// written, for the validation to refuse them where they cannot be
/// enforced, and for a backend that enforces them.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ResourcesLayer {
    pub open_files: Option<u64>,
    pub file_size: Option<ByteSize>,
    pub cpu_seconds: Option<u64>,
    #[serde(deserialize_with = "as_text")]
    pub memory: Option<String>,
    #[serde(deserialize_with = "as_text")]
    pub cpu: Option<String>,
}

/// A value of any form, as text.
fn as_text<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    Ok(Option::<toml::Value>::deserialize(d)?.map(|v| match v {
        toml::Value::String(s) => s,
        other => other.to_string(),
    }))
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
        if self.resources != ResourcesLayer::default() {
            found.push("resources");
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
        // Every field named, so one added to the layer is not dropped here.
        let ResourcesLayer {
            open_files,
            file_size,
            cpu_seconds,
            memory,
            cpu,
        } = &self.resources;
        let limits = &mut policy.resources;
        if open_files.is_some() {
            limits.open_files = *open_files;
        }
        if file_size.is_some() {
            limits.file_size = *file_size;
        }
        if cpu_seconds.is_some() {
            limits.cpu_seconds = *cpu_seconds;
        }
        if memory.is_some() {
            limits.memory.clone_from(memory);
        }
        if cpu.is_some() {
            limits.cpu.clone_from(cpu);
        }
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

    /// A limit written as the wrong kind of value is refused with what is
    /// expected, never an internal type's name.
    #[test]
    fn a_limit_of_the_wrong_kind_says_what_is_expected() {
        for bad in ["file_size = -1", "file_size = 1.5", "file_size = true"] {
            let err = PolicyFile::parse("policy.toml", &format!("[resources]\n{bad}\n"))
                .unwrap_err()
                .to_string();
            assert!(err.contains("a size"), "{bad}: {err}");
            assert!(!err.contains("SizeText"), "{bad}: {err}");
        }
        assert!(PolicyFile::parse("policy.toml", "[resources]\nopen_files = -1\n").is_err());
        assert!(PolicyFile::parse("policy.toml", "[resources]\nopen_files = \"64\"\n").is_err());
    }

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
    fn limits_are_set_by_the_last_layer_that_names_each() {
        let mut policy = Policy::default();
        PolicyFile::parse(
            "a",
            "[resources]\nopen_files = 256\nfile_size = \"1G\"\ncpu = 2.0\nmemory = \"2G\"",
        )
        .unwrap()
        .apply(&mut policy);
        PolicyFile::parse("b", "[resources]\nopen_files = 512\ncpu_seconds = 60")
            .unwrap()
            .apply(&mut policy);
        let r = &policy.resources;
        assert_eq!(r.open_files, Some(512));
        assert_eq!(r.file_size, Some(ByteSize(1 << 30)));
        assert_eq!(r.cpu_seconds, Some(60));
        assert_eq!(
            (r.cpu.as_deref(), r.memory.as_deref()),
            (Some("2.0"), Some("2G"))
        );
        let layer = PolicyFile::parse("adapter", "[resources]\nopen_files = 1").unwrap();
        assert_eq!(layer.beyond_destinations(), ["resources"]);
        assert!(PolicyFile::parse("c", "[resources]\nfile_size = \"1T\"").is_err());
        // A size may be a number of bytes, as well as text.
        let mut bytes = Policy::default();
        PolicyFile::parse("d", "[resources]\nfile_size = 1048576")
            .unwrap()
            .apply(&mut bytes);
        assert_eq!(bytes.resources.file_size, Some(ByteSize(1 << 20)));
        assert!(PolicyFile::parse("c", "[resources]\nthreads = 4").is_err());
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
