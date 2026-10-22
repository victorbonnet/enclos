//! Secrets (design §12, ADR 0022): values such as a bot token, kept on the
//! host and granted to a whole sandbox through its policy.

use std::fmt;
use std::str::FromStr;

use super::Timestamp;
use super::sandbox::{SandboxName, is_short_name};

/// A secret's name within its sandbox: the naming rule sandboxes follow.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SecretName(String);

impl SecretName {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SecretName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(&self.0)
    }
}

impl FromStr for SecretName {
    type Err = InvalidSecretRef;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match is_short_name(s) {
            true => Ok(SecretName(s.to_owned())),
            false => Err(InvalidSecretRef(s.to_owned())),
        }
    }
}

/// A secret a sandbox has: enclos's record of it, never its value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretRecord {
    pub secret: SecretRef,
    pub created_at: Timestamp,
    /// When its value was last set.
    pub updated_at: Timestamp,
}

/// A secret of one sandbox, written `<sandbox>/<name>` on the command line
/// and `secret:<sandbox>/<name>` in a policy.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SecretRef {
    pub sandbox: SandboxName,
    pub name: SecretName,
}

/// How a policy names a secret it grants.
pub const POLICY_PREFIX: &str = "secret:";

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error(
    "`{0}` is not a secret: write `<sandbox>/<name>`, such as `home/telegram`, each a lowercase letter then lowercase letters, digits or hyphens"
)]
pub struct InvalidSecretRef(pub String);

impl SecretRef {
    /// `secret:<sandbox>/<name>`, as a policy writes it.
    pub fn parse_policy(text: &str) -> Result<SecretRef, InvalidSecretRef> {
        text.strip_prefix(POLICY_PREFIX)
            .ok_or_else(|| InvalidSecretRef(text.to_owned()))?
            .parse()
            .map_err(|_| InvalidSecretRef(text.to_owned()))
    }

    /// How a policy writes it.
    pub fn in_policy(&self) -> String {
        format!("{POLICY_PREFIX}{self}")
    }
}

impl FromStr for SecretRef {
    type Err = InvalidSecretRef;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let invalid = || InvalidSecretRef(s.to_owned());
        let (sandbox, name) = s.split_once('/').ok_or_else(invalid)?;
        Ok(SecretRef {
            sandbox: sandbox.parse().map_err(|_| invalid())?,
            name: name.parse().map_err(|_| invalid())?,
        })
    }
}

impl fmt::Display for SecretRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(&format!("{}/{}", self.sandbox, self.name))
    }
}

/// Environment variables a session may not be given as a secret: the ones
/// enclos sets itself, or that would change how the sandbox runs.
pub fn reserved_variable(name: &str) -> bool {
    const RESERVED: &[&str] = &[
        "HOME",
        "PATH",
        "TMPDIR",
        "USER",
        "LOGNAME",
        "SHELL",
        "TERM",
        "PWD",
        "LANG",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "no_proxy",
    ];
    RESERVED.contains(&name)
        || name.starts_with("LC_")
        || name.starts_with("ENCLOS_")
        || name.starts_with("DYLD_")
}

/// Whether `name` is a variable name a shell reads: a letter or `_`, then
/// letters, digits or `_`.
pub fn is_variable_name(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_secret_is_named_by_its_sandbox_and_its_name() {
        let r: SecretRef = "home/telegram-main".parse().unwrap();
        assert_eq!(r.sandbox.as_str(), "home");
        assert_eq!(r.name.as_str(), "telegram-main");
        assert_eq!(r.to_string(), "home/telegram-main");
        assert_eq!(r.in_policy(), "secret:home/telegram-main");
        assert_eq!(SecretRef::parse_policy("secret:home/telegram-main"), Ok(r));
        for bad in [
            "home",
            "home/",
            "/x",
            "home/X",
            "home/a b",
            "a/b/c",
            "home/../x",
        ] {
            assert!(bad.parse::<SecretRef>().is_err(), "{bad}");
        }
        assert!(SecretRef::parse_policy("home/telegram").is_err());
    }

    #[test]
    fn only_plain_variables_enclos_does_not_set_may_hold_a_secret() {
        for ok in ["TELEGRAM_BOT_TOKEN", "_X", "api_key"] {
            assert!(is_variable_name(ok) && !reserved_variable(ok), "{ok}");
        }
        for bad in ["", "1X", "A-B", "A B"] {
            assert!(!is_variable_name(bad), "{bad}");
        }
        for reserved in [
            "HOME",
            "PATH",
            "HTTPS_PROXY",
            "LC_ALL",
            "ENCLOS_HOME",
            "DYLD_INSERT_LIBRARIES",
        ] {
            assert!(reserved_variable(reserved), "{reserved}");
        }
    }
}
