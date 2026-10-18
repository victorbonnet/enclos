//! The errors an engine call returns, and the exit code each maps to.

use crate::audit::AuditError;
use crate::layout::LayoutError;
use crate::state::StateError;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Layout(#[from] LayoutError),
    #[error(transparent)]
    State(#[from] StateError),
    #[error(transparent)]
    Audit(#[from] AuditError),
    /// The policy does not allow the command; see design principle 6.
    #[error("refused by policy: {reason}")]
    Refused { reason: String },
    /// The command changes something the user must confirm first.
    #[error(
        "{what} needs confirmation: run it again with --yes, or with --dry-run to see the plan"
    )]
    NeedsConfirmation { what: String },
}

pub type Result<T> = std::result::Result<T, Error>;

/// Exit codes (design §10).
pub mod exit {
    pub const OK: u8 = 0;
    pub const ERROR: u8 = 1;
    pub const REFUSED: u8 = 2;
    pub const NEEDS_CONFIRMATION: u8 = 3;
}

impl Error {
    pub fn exit_code(&self) -> u8 {
        match self {
            Error::Refused { .. } => exit::REFUSED,
            Error::NeedsConfirmation { .. } => exit::NEEDS_CONFIRMATION,
            Error::Layout(_) | Error::State(_) | Error::Audit(_) => exit::ERROR,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_errors_to_exit_codes() {
        let refused = Error::Refused { reason: "x".into() };
        let confirm = Error::NeedsConfirmation { what: "x".into() };
        let error = Error::Layout(LayoutError::NoHome);
        assert_eq!(refused.exit_code(), 2);
        assert_eq!(confirm.exit_code(), 3);
        assert_eq!(error.exit_code(), 1);
    }
}
