//! The errors an engine call returns, and the exit code each maps to.

use crate::audit::AuditError;
use crate::layout::LayoutError;
use crate::policy::PolicyError;
use crate::state::StateError;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Layout(#[from] LayoutError),
    #[error(transparent)]
    State(#[from] StateError),
    #[error(transparent)]
    Audit(#[from] AuditError),
    #[error(transparent)]
    Policy(#[from] PolicyError),
    #[error("there is no sandbox named `{name}`. Run `enclos sandbox list` to see them")]
    NoSuchSandbox { name: String },
    #[error(
        "a sandbox named `{name}` already exists. Pick another name, or remove it with `enclos sandbox rm {name}`"
    )]
    SandboxExists { name: String },
    #[error("sandbox `{name}` is running. Stop it first with `enclos sandbox stop {name}`")]
    SandboxRunning { name: String },
    #[error(
        "no free proxy port is left between 41000 and 48999. Remove a sandbox you no longer use"
    )]
    NoFreePorts,
    #[error("{what}")]
    Session { what: String },
    #[error("sandbox `{sandbox}` has no policy yet. Run `enclos state check {sandbox}`")]
    NoPolicy { sandbox: String },
    /// A backend this host cannot run; never overridden (ADR 0009).
    #[error("sandbox `{sandbox}` uses the {backend} backend, which this host cannot run: {reason}")]
    BackendUnavailable {
        sandbox: String,
        backend: String,
        reason: String,
    },
    #[error(transparent)]
    Compile(#[from] crate::backend::CompileError),
    #[error("the proxy of sandbox `{sandbox}` cannot listen on {addr}: {source}")]
    ProxyListen {
        sandbox: String,
        addr: String,
        source: std::io::Error,
    },
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
            Error::Layout(_)
            | Error::State(_)
            | Error::Audit(_)
            | Error::Policy(_)
            | Error::NoSuchSandbox { .. }
            | Error::NoPolicy { .. }
            | Error::ProxyListen { .. }
            | Error::Compile(_)
            | Error::SandboxExists { .. }
            | Error::SandboxRunning { .. }
            | Error::NoFreePorts
            | Error::Session { .. } => exit::ERROR,
            Error::BackendUnavailable { .. } => exit::REFUSED,
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
