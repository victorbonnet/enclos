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
    /// `resources.memory`, held by the sandbox's slice where the host's
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

/// Whether a field a sandbox runs with not enforced is accepted, as enclos
/// finds it for one command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Accepted {
    /// Kept with the sandbox at the field's value.
    Kept(Acceptance),
    /// By this command's `--accept-unenforced`, which records it.
    Given,
    /// Kept with the sandbox at another value: it no longer covers this one.
    Stale(Acceptance),
    /// Never given.
    Missing,
}

/// A field a sandbox's policy sets that this host does not enforce, with
/// whether it is accepted: the one assessment that each start, `policy
/// test` and `doctor` report from (ADR 0038).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotEnforced {
    pub gap: NotEnforcedHere,
    pub accepted: Accepted,
}

impl NotEnforced {
    /// `gap`, accepted by what is `kept` with the sandbox or `given` by
    /// this command, or not.
    pub fn assess(gap: NotEnforcedHere, kept: &[Acceptance], given: &[UnenforcedField]) -> Self {
        let kept = kept.iter().find(|a| a.field == gap.field);
        let accepted = match kept {
            Some(a) if a.covers(&gap) => Accepted::Kept(a.clone()),
            _ if given.contains(&gap.field) => Accepted::Given,
            Some(a) => Accepted::Stale(a.clone()),
            None => Accepted::Missing,
        };
        NotEnforced { gap, accepted }
    }

    /// Whether the sandbox may run with it not enforced.
    pub fn is_accepted(&self) -> bool {
        matches!(self.accepted, Accepted::Kept(_) | Accepted::Given)
    }

    /// Why a command is refused while it is not accepted, with what to do
    /// ([`NotEnforcedHere::refusal`]), and the value an acceptance kept is
    /// for when it is another.
    pub fn refusal(&self, command: Option<&str>) -> String {
        let refused = self.gap.refusal(command);
        match &self.accepted {
            Accepted::Stale(kept) => format!(
                "{refused}. The acceptance kept is for {} = {}",
                kept.field.policy_path(),
                kept.value
            ),
            _ => refused,
        }
    }

    /// The field and its acceptance in a few words, as a verdict names it:
    /// `memory (accepted)`, `memory (not accepted)`, or `memory (accepted
    /// at 512M, not at 1G)`.
    pub fn named(&self) -> String {
        let field = self.gap.field;
        match &self.accepted {
            Accepted::Kept(_) | Accepted::Given => format!("{field} (accepted)"),
            Accepted::Missing => format!("{field} (not accepted)"),
            Accepted::Stale(kept) => format!(
                "{field} (accepted at {}, not at {})",
                kept.value, self.gap.value
            ),
        }
    }

    /// The field, its value, why the host does not enforce it and its
    /// acceptance, in a sentence: what `policy test` and `doctor` list.
    pub fn said(&self) -> String {
        let gap = &self.gap;
        let accepted = match &self.accepted {
            Accepted::Kept(a) => format!("accepted {}", a.at.strftime("%Y-%m-%d %H:%M UTC")),
            Accepted::Given => "accepted by this command".to_owned(),
            Accepted::Stale(a) => format!("accepted at {} only, not at this value", a.value),
            Accepted::Missing => "not accepted".to_owned(),
        };
        format!(
            "{} = {} is not applied on this host: {}; {accepted}",
            gap.field.policy_path(),
            gap.value,
            gap.why
        )
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
    fn an_assessment_tells_kept_given_stale_and_missing_apart() {
        let kept = |value: &str| Acceptance {
            field: UnenforcedField::Memory,
            value: value.to_owned(),
            why: String::new(),
            at: crate::model::now(),
        };
        let memory = [UnenforcedField::Memory];
        let accepted = NotEnforced::assess(gap("1G"), &[kept("1G")], &[]);
        assert!(matches!(accepted.accepted, Accepted::Kept(_)));
        assert!(accepted.is_accepted());
        assert_eq!(accepted.named(), "memory (accepted)");
        // The flag accepts what nothing kept covers, a stale one included.
        for kept in [vec![], vec![kept("512M")]] {
            let given = NotEnforced::assess(gap("1G"), &kept, &memory);
            assert_eq!(given.accepted, Accepted::Given);
            assert!(given.is_accepted());
        }
        let stale = NotEnforced::assess(gap("1G"), &[kept("512M")], &[]);
        assert!(matches!(stale.accepted, Accepted::Stale(_)));
        assert!(!stale.is_accepted());
        assert_eq!(stale.named(), "memory (accepted at 512M, not at 1G)");
        let missing = NotEnforced::assess(gap("1G"), &[], &[]);
        assert_eq!(missing.accepted, Accepted::Missing);
        assert!(!missing.is_accepted());
        assert_eq!(missing.named(), "memory (not accepted)");
        let said = missing.said();
        assert!(
            said.starts_with("resources.memory = 1G is not applied on this host: "),
            "{said}"
        );
        assert!(said.ends_with("; not accepted"), "{said}");
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
