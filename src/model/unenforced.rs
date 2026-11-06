//! A policy field whose enforcement depends on the host, not on the backend
//! alone (ADR 0038): where the host lacks what holds it, a sandbox runs with
//! the field not enforced only once the user accepted that, and the
//! acceptance is audited and kept with the sandbox.

use std::fmt;
use std::str::FromStr;

use super::Timestamp;

/// A field a host may not enforce. `[exec]` joins it once a policy can hold
/// one (ADR 0037).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum UnenforcedField {
    /// `resources.memory`, held by a session's cgroup where the host's
    /// memory controller is there and delegated to the user's manager.
    Memory,
}

impl UnenforcedField {
    pub const ALL: [UnenforcedField; 1] = [UnenforcedField::Memory];

    /// How `--accept-unenforced` names it.
    pub fn as_str(self) -> &'static str {
        match self {
            UnenforcedField::Memory => "memory",
        }
    }

    /// Where it is in a policy.
    pub fn policy_path(self) -> &'static str {
        match self {
            UnenforcedField::Memory => "resources.memory",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("`{0}` is not a field a host may leave unenforced: use memory")]
pub struct UnknownField(pub String);

impl FromStr for UnenforcedField {
    type Err = UnknownField;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        UnenforcedField::ALL
            .into_iter()
            .find(|f| f.as_str() == s)
            .ok_or_else(|| UnknownField(s.to_owned()))
    }
}

impl fmt::Display for UnenforcedField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(self.as_str())
    }
}

/// A field a policy sets that this host does not enforce, as the policy
/// writes it, and why the host does not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotEnforcedHere {
    pub field: UnenforcedField,
    pub value: String,
    pub why: String,
}

impl NotEnforcedHere {
    /// The line each start prints while it applies.
    pub fn said_at_start(&self, sandbox: &str) -> String {
        format!(
            "sandbox {sandbox}: {} = {} is not applied: {} (enclos doctor)",
            self.field.policy_path(),
            self.value,
            self.why
        )
    }

    /// Why a policy setting it is refused without an acceptance, with what
    /// to do: `command` given `--accept-unenforced`, or, with none, the
    /// command that was refused.
    pub fn refusal(&self, command: Option<&str>) -> String {
        let accept = match command {
            Some(command) => format!("Run `{command} --accept-unenforced {}`", self.field),
            None => format!("Pass `--accept-unenforced {}`", self.field),
        };
        format!(
            "{} = {} would not be applied on this host: {}. {accept} to run with it not applied, recorded in the audit log, or leave it out (enclos doctor)",
            self.field.policy_path(),
            self.value,
            self.why,
        )
    }
}

/// The user's acceptance that a sandbox runs with a field not enforced, at
/// this value: kept until the value changes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Acceptance {
    pub field: UnenforcedField,
    pub value: String,
    /// Why the host did not enforce it when it was accepted.
    pub why: String,
    pub at: Timestamp,
}

impl Acceptance {
    /// Whether it covers `gap`: the same field at the same value.
    pub fn covers(&self, gap: &NotEnforcedHere) -> bool {
        self.field == gap.field && self.value == gap.value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gap(value: &str) -> NotEnforcedHere {
        NotEnforcedHere {
            field: UnenforcedField::Memory,
            value: value.to_owned(),
            why: "this host's memory controller is not delegated to the user's manager".to_owned(),
        }
    }

    #[test]
    fn a_field_is_named_as_the_flag_names_it() {
        for field in UnenforcedField::ALL {
            assert_eq!(field.as_str().parse::<UnenforcedField>().unwrap(), field);
        }
        assert!("exec".parse::<UnenforcedField>().is_err());
    }

    #[test]
    fn an_acceptance_covers_its_field_at_its_value_only() {
        let accepted = Acceptance {
            field: UnenforcedField::Memory,
            value: "1G".to_owned(),
            why: String::new(),
            at: crate::model::now(),
        };
        assert!(accepted.covers(&gap("1G")));
        assert!(!accepted.covers(&gap("2G")));
    }

    #[test]
    fn a_refusal_names_the_field_why_and_the_flag() {
        let said = gap("1G").refusal(Some("enclos sandbox start lab"));
        assert!(said.contains("resources.memory = 1G"), "{said}");
        assert!(said.contains("not delegated"), "{said}");
        assert!(
            said.contains("`enclos sandbox start lab --accept-unenforced memory`"),
            "{said}"
        );
        let said = gap("1G").refusal(None);
        assert!(said.contains("Pass `--accept-unenforced memory`"), "{said}");
        let line = gap("1G").said_at_start("lab");
        assert!(line.starts_with("sandbox lab: resources.memory = 1G is not applied"));
    }
}
