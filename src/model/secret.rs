//! Secrets (design §12, ADR 0022): values such as a bot token, kept on the
//! host and granted to a whole sandbox through its policy.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

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

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error(
    "`{0}` is not a secret's name: a lowercase letter, then lowercase letters, digits or hyphens, 2 to 41 characters in all"
)]
pub struct InvalidSecretName(pub String);

impl FromStr for SecretName {
    type Err = InvalidSecretName;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match is_short_name(s) {
            true => Ok(SecretName(s.to_owned())),
            false => Err(InvalidSecretName(s.to_owned())),
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
    "`{0}` is not a secret: write `<sandbox>/<name>`, such as `home/telegram`, each a lowercase letter then lowercase letters, digits or hyphens, 2 to 41 characters in all"
)]
pub struct InvalidSecretRef(pub String);

impl SecretRef {
    /// How a policy grants it.
    pub fn in_policy(&self) -> SecretGrant {
        SecretGrant(self.clone())
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

/// A secret as a policy grants it, written `secret:<sandbox>/<name>`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct SecretGrant(pub SecretRef);

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error(
    "`{0}` is not a secret: write `secret:<sandbox>/<name>`, such as `secret:home/telegram`, each a lowercase letter then lowercase letters, digits or hyphens, 2 to 41 characters in all"
)]
pub struct InvalidSecretGrant(pub String);

impl FromStr for SecretGrant {
    type Err = InvalidSecretGrant;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.strip_prefix(POLICY_PREFIX)
            .and_then(|r| r.parse().ok())
            .map(SecretGrant)
            .ok_or_else(|| InvalidSecretGrant(s.to_owned()))
    }
}

impl TryFrom<String> for SecretGrant {
    type Error = InvalidSecretGrant;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl From<SecretGrant> for String {
    fn from(grant: SecretGrant) -> String {
        grant.to_string()
    }
}

impl fmt::Display for SecretGrant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(&format!("{POLICY_PREFIX}{}", self.0))
    }
}

/// A secret's value: text an environment variable can hold, never empty.
/// Nothing prints it: its `Debug` shows only that there is one.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretValue(String);

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum InvalidSecretValue {
    #[error("the value is empty")]
    Empty,
    #[error("the value holds a NUL byte, which no environment variable can")]
    Nul,
}

impl SecretValue {
    pub fn new(value: String) -> Result<SecretValue, InvalidSecretValue> {
        if value.is_empty() {
            Err(InvalidSecretValue::Empty)
        } else if value.contains('\0') {
            Err(InvalidSecretValue::Nul)
        } else {
            Ok(SecretValue(value))
        }
    }

    /// The value itself, for the store and a session's environment only.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretValue(…)")
    }
}

/// Environment variables a session may not be given as a secret: the ones
/// enclos sets itself or passes on from the host (a test of the Seatbelt
/// backend holds this list to its environment), or that would change how
/// the sandbox runs.
pub fn reserved_variable(name: &str) -> bool {
    const RESERVED: &[&str] = &[
        "HOME",
        "PATH",
        "TMPDIR",
        "USER",
        "LOGNAME",
        "SHELL",
        "TERM",
        "TERMINFO",
        "TERMINFO_DIRS",
        "COLORTERM",
        "TZ",
        "PWD",
        "LANG",
        "UV_CACHE_DIR",
        "npm_config_cache",
        "NODE_USE_ENV_PROXY",
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
        || name.starts_with("XDG_")
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
        assert_eq!(r.in_policy().to_string(), "secret:home/telegram-main");
        assert_eq!(
            "secret:home/telegram-main".parse::<SecretGrant>(),
            Ok(SecretGrant(r))
        );
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
        for bad in ["home/telegram", "secret:", "secret:home/X", "secret:home"] {
            assert!(bad.parse::<SecretGrant>().is_err(), "{bad}");
        }
        assert!("home/x".parse::<SecretRef>().is_err());
        let err = "x".parse::<SecretName>().unwrap_err();
        assert!(err.to_string().contains("secret's name"), "{err}");
    }

    #[test]
    fn a_grant_is_stored_as_policy_text() {
        let grant: SecretGrant = "secret:home/telegram".parse().unwrap();
        assert_eq!(
            serde_json::to_string(&grant).unwrap(),
            "\"secret:home/telegram\""
        );
        let back: SecretGrant = serde_json::from_str("\"secret:home/telegram\"").unwrap();
        assert_eq!(back, grant);
        assert!(serde_json::from_str::<SecretGrant>("\"home/telegram\"").is_err());
    }

    #[test]
    fn a_value_is_text_without_nul_and_never_printed() {
        assert_eq!(
            SecretValue::new(String::new()),
            Err(InvalidSecretValue::Empty)
        );
        assert_eq!(
            SecretValue::new("a\0b".into()),
            Err(InvalidSecretValue::Nul)
        );
        let value = SecretValue::new("tok-123".into()).unwrap();
        assert_eq!(value.expose(), "tok-123");
        assert!(!format!("{value:?}").contains("tok"));
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
            "XDG_CONFIG_HOME",
            "NODE_USE_ENV_PROXY",
            "TZ",
        ] {
            assert!(reserved_variable(reserved), "{reserved}");
        }
    }
}
