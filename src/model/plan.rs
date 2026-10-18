//! How a state-changing command is confirmed, and what it returns.

use std::path::PathBuf;

/// What the user said about a change, from `--yes` and `--dry-run`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confirm {
    /// Ask before a change that needs confirmation.
    Ask,
    /// `--yes`: make the change without asking.
    Yes,
    /// `--dry-run`: only return the plan; change nothing.
    DryRun,
}

impl Confirm {
    /// Builds the confirmation from the global CLI flags; `--dry-run` wins.
    pub fn from_flags(yes: bool, dry_run: bool) -> Self {
        match (yes, dry_run) {
            (_, true) => Confirm::DryRun,
            (true, false) => Confirm::Yes,
            (false, false) => Confirm::Ask,
        }
    }
}

/// The result of a state-changing engine call: done, or only planned.
#[derive(Debug, PartialEq, Eq)]
pub enum Planned<T> {
    Done(T),
    DryRun(Plan),
}

/// What a command would change.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Plan {
    pub create: Vec<PathBuf>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dry_run_wins_over_yes() {
        assert_eq!(Confirm::from_flags(true, true), Confirm::DryRun);
        assert_eq!(Confirm::from_flags(true, false), Confirm::Yes);
        assert_eq!(Confirm::from_flags(false, false), Confirm::Ask);
    }
}
