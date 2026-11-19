//! Runtimes (design §3): the software installed in a sandbox to run its
//! agents, such as Hermes. A sandbox holds at most one.

use std::fmt;
use std::str::FromStr;

/// The runtimes enclos knows. Milestone 1 has Hermes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RuntimeKind {
    Hermes,
    OpenClaw,
}

impl RuntimeKind {
    pub const ALL: [RuntimeKind; 2] = [RuntimeKind::Hermes, RuntimeKind::OpenClaw];

    pub fn as_str(self) -> &'static str {
        match self {
            RuntimeKind::Hermes => "hermes",
            RuntimeKind::OpenClaw => "openclaw",
        }
    }

    /// Its name as people write it.
    pub fn display_name(self) -> &'static str {
        match self {
            RuntimeKind::Hermes => "Hermes",
            RuntimeKind::OpenClaw => "OpenClaw",
        }
    }
}

impl fmt::Display for RuntimeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unknown runtime `{0}`: this enclos knows {known}", known = known())]
pub struct UnknownRuntime(pub String);

fn known() -> String {
    RuntimeKind::ALL
        .iter()
        .map(|k| k.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

impl FromStr for RuntimeKind {
    type Err = UnknownRuntime;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        RuntimeKind::ALL
            .into_iter()
            .find(|k| k.as_str() == s)
            .ok_or_else(|| UnknownRuntime(s.to_owned()))
    }
}

/// A runtime's version as the runtime names it, such as `0.23.2` or
/// `2026.11.5` (ADR 0074, proposed): letters, digits, dots, hyphens and
/// plus signs, at most 64 of them, starting with a digit, without the `v`
/// of a release tag. What a runtime reports or a release lookup says is
/// checked against this before enclos records, keeps or compares it; a
/// version read from a home file is shown as other home facts are.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RuntimeVersion(String);

impl RuntimeVersion {
    const MAX: usize = 64;

    /// `text` as a version, a leading `v` dropped; none when it is not one.
    pub fn new(text: &str) -> Option<RuntimeVersion> {
        let text = text.trim();
        let text = text.strip_prefix('v').unwrap_or(text);
        let allowed = |c: char| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '+');
        let starts = text.chars().next().is_some_and(|c| c.is_ascii_digit());
        (starts && text.len() <= Self::MAX && text.chars().all(allowed))
            .then(|| RuntimeVersion(text.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether this version is newer than `other`, compared number by
    /// number between the dots, a missing number counting as 0. Not newer
    /// when they are the same. None when they differ and either has a part
    /// that is not a number, such as `2026.11.5-beta.1`: enclos does not
    /// guess how a runtime orders those.
    pub fn newer_than(&self, other: &RuntimeVersion) -> Option<bool> {
        if self == other {
            return Some(false);
        }
        let numbers = |v: &RuntimeVersion| -> Option<Vec<u64>> {
            v.0.split('.').map(|part| part.parse().ok()).collect()
        };
        let (mine, theirs) = (numbers(self)?, numbers(other)?);
        let at = |v: &[u64], i: usize| v.get(i).copied().unwrap_or(0);
        let order = (0..mine.len().max(theirs.len()))
            .map(|i| at(&mine, i).cmp(&at(&theirs, i)))
            .find(|o| o.is_ne())
            .unwrap_or(std::cmp::Ordering::Equal);
        Some(order.is_gt())
    }
}

impl fmt::Display for RuntimeVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(text: &str) -> RuntimeVersion {
        RuntimeVersion::new(text).unwrap()
    }

    #[test]
    fn versions_drop_a_tags_v_and_refuse_what_is_not_a_version() {
        assert_eq!(v("v0.23.2").as_str(), "0.23.2");
        assert_eq!(v(" 2026.11.5\n").as_str(), "2026.11.5");
        assert_eq!(v("2026.11.5-beta.1").as_str(), "2026.11.5-beta.1");
        let long = "9".repeat(65);
        for bad in [
            "",
            "v",
            "latest",
            "0.23.2; rm -rf ~",
            "1.2\u{1b}[31m",
            &long,
        ] {
            assert_eq!(RuntimeVersion::new(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn versions_compare_number_by_number() {
        assert_eq!(v("0.23.2").newer_than(&v("0.23.1")), Some(true));
        assert_eq!(v("0.23.10").newer_than(&v("0.23.9")), Some(true));
        assert_eq!(v("0.23.1").newer_than(&v("0.23.2")), Some(false));
        assert_eq!(v("0.23.2").newer_than(&v("0.23.2")), Some(false));
        assert_eq!(v("2026.11.5").newer_than(&v("2026.11")), Some(true));
        assert_eq!(v("2026.11.0").newer_than(&v("2026.11")), Some(false));
        assert_eq!(v("2026.11.5-beta.1").newer_than(&v("2026.11.4")), None);
        let beta = v("2026.11.5-beta.1");
        assert_eq!(beta.newer_than(&beta.clone()), Some(false));
    }

    #[test]
    fn kinds_parse() {
        assert_eq!("hermes".parse::<RuntimeKind>(), Ok(RuntimeKind::Hermes));
        assert_eq!("openclaw".parse::<RuntimeKind>(), Ok(RuntimeKind::OpenClaw));
        let err = "claude".parse::<RuntimeKind>().unwrap_err();
        assert_eq!(
            err.to_string(),
            "unknown runtime `claude`: this enclos knows hermes, openclaw"
        );
    }
}
