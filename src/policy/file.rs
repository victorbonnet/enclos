//! One layer of policy as written in TOML: the built-in defaults, a template,
//! an adapter's endpoints, or a sandbox's `policy.toml` (design §7).
//!
//! A list written `name = [...]` replaces what the layers below set, and
//! `name_add = [...]` extends it.

use serde::Deserialize;

use super::PolicyError;
use crate::model::policy::{NetLog, Policy, TemplateName};

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
    pub allow: Option<Vec<String>>,
    pub allow_add: Vec<String>,
    pub private: Option<Vec<String>>,
    pub private_add: Vec<String>,
    pub log: Option<NetLog>,
}

impl PolicyFile {
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
        if let Some(log) = self.network.log {
            policy.net.log = log;
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
