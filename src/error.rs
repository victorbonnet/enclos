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
    #[error("sandbox `{name}` has sessions open. End them first with `enclos sandbox stop {name}`")]
    SandboxRunning { name: String },
    #[error(transparent)]
    Service(#[from] crate::service::ServiceError),
    #[error(
        "sandbox `{name}` has background services installed, which come back on their own. Remove them first with `enclos sandbox stop {name}`"
    )]
    SandboxHasServices { name: String },
    /// A stop left members running; `rm` waits until they are gone.
    #[error(
        "sandbox `{name}` still has processes `enclos sandbox stop` could not end; `enclos sandbox show {name}` lists them. End them, then run `enclos sandbox stop {name}` again"
    )]
    SandboxNotStopped { name: String },
    #[error(
        "no free proxy port is left between {} and {}. Remove a sandbox you no longer use",
        crate::model::sandbox::PORT_FIRST,
        crate::model::sandbox::PORT_LAST
    )]
    NoFreePorts,
    #[error("{what}")]
    Session { what: String },
    /// Guidance for a failed operation, preserving its cause and exit code.
    #[error("{what}")]
    WithContext {
        #[source]
        error: Box<Error>,
        what: String,
    },
    #[error(transparent)]
    Processes(#[from] crate::lifecycle::process::PsError),
    /// A failed command whose cleanup failed too.
    #[error("{error}; cleaning up after it failed too, and left {left}")]
    CleanupFailed { error: Box<Error>, left: String },
    /// A failed command whose cleanup worked but could not be recorded in
    /// the audit log.
    #[error(
        "{error}; cleaning up after it {done}, but the audit log could not record that: {audit}"
    )]
    CleanupUnrecorded {
        error: Box<Error>,
        done: String,
        audit: Box<Error>,
    },
    /// A change made outside the state lock, or one that failed, whose
    /// audit entry could not be written.
    #[error("{what}, but the audit log could not record it: {audit}")]
    Unrecorded { what: String, audit: Box<Error> },
    /// A record without an active policy, which `sandbox create` never
    /// leaves: it records both in one transaction. The steps make it again
    /// from the backend and template it was recorded with.
    #[error(
        "sandbox `{sandbox}` has no active policy, so its record is incomplete. Remove the record with `enclos sandbox rm {sandbox} --keep-data`, then run `enclos sandbox create {sandbox} --backend {backend} --template {template}` again: its home is kept"
    )]
    NoPolicy {
        sandbox: String,
        backend: String,
        template: String,
    },
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
    #[error("the proxy of sandbox `{sandbox}` stopped serving: {source}")]
    ProxyStopped {
        sandbox: String,
        source: std::io::Error,
    },
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
    /// A policy whose problems are all refusals, or a backend this host
    /// cannot run (ADR 0009).
    pub const REFUSED: u8 = 2;
    pub const NEEDS_CONFIRMATION: u8 = 3;
}

impl Error {
    /// The exit code for this error (design §10). A policy exits 2 only when
    /// `PolicyError::is_refused` holds. `Compile` stays 1: validation refuses
    /// a path the compiled policy cannot hold when the policy is stored, and
    /// a compile failure at start is an error. A failed cleanup keeps the
    /// code of the error it followed.
    pub fn exit_code(&self) -> u8 {
        match self {
            Error::Policy(e) if e.is_refused() => exit::REFUSED,
            Error::BackendUnavailable { .. } => exit::REFUSED,
            Error::NeedsConfirmation { .. } => exit::NEEDS_CONFIRMATION,
            Error::Layout(_)
            | Error::State(_)
            | Error::Audit(_)
            | Error::Policy(_)
            | Error::NoSuchSandbox { .. }
            | Error::NoPolicy { .. }
            | Error::ProxyListen { .. }
            | Error::ProxyStopped { .. }
            | Error::Compile(_)
            | Error::SandboxExists { .. }
            | Error::SandboxRunning { .. }
            | Error::SandboxHasServices { .. }
            | Error::SandboxNotStopped { .. }
            | Error::NoFreePorts
            | Error::Session { .. }
            | Error::Service(_)
            | Error::Processes(_)
            | Error::Unrecorded { .. } => exit::ERROR,
            Error::CleanupFailed { error, .. }
            | Error::CleanupUnrecorded { error, .. }
            | Error::WithContext { error, .. } => error.exit_code(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::Problem;

    fn invalid(problems: Vec<Problem>) -> Error {
        Error::Policy(PolicyError::Invalid { problems })
    }

    #[test]
    fn context_and_cleanup_preserve_the_original_exit_code() {
        for (error, code) in [
            (Error::Session { what: "x".into() }, 1),
            (invalid(vec![Problem::Refused("x".into())]), 2),
            (
                Error::BackendUnavailable {
                    sandbox: "home".into(),
                    backend: "seatbelt".into(),
                    reason: "not available".into(),
                },
                2,
            ),
            (Error::NeedsConfirmation { what: "x".into() }, 3),
        ] {
            let error = Error::WithContext {
                error: Box::new(error),
                what: "the operation did not finish".into(),
            };
            assert_eq!(error.exit_code(), code);
            assert!(std::error::Error::source(&error).is_some());
            let error = Error::CleanupFailed {
                error: Box::new(error),
                left: "the staged archive".into(),
            };
            assert_eq!(error.exit_code(), code);
        }
    }

    #[test]
    fn maps_errors_to_exit_codes() {
        let backend = Error::BackendUnavailable {
            sandbox: "home".into(),
            backend: "bubblewrap".into(),
            reason: "not Linux".into(),
        };
        let confirm = Error::NeedsConfirmation { what: "x".into() };
        let error = Error::Layout(LayoutError::NoHome);
        assert_eq!(backend.exit_code(), 2);
        assert_eq!(confirm.exit_code(), 3);
        assert_eq!(error.exit_code(), 1);
    }

    #[test]
    fn a_policy_refusal_exits_2_and_a_policy_written_wrong_exits_1() {
        let refused = || Problem::Refused("127.0.0.1 is a loopback address".into());
        let malformed = || Problem::Malformed("`exa mple.com` is not a host name".into());
        assert_eq!(invalid(vec![refused()]).exit_code(), 2);
        assert_eq!(invalid(vec![refused(), refused()]).exit_code(), 2);
        assert_eq!(invalid(vec![malformed()]).exit_code(), 1);
        assert_eq!(invalid(vec![refused(), malformed()]).exit_code(), 1);
        let syntax = Error::Policy(PolicyError::Parse {
            layer: "policy.toml".into(),
            reason: "expected `=`".into(),
        });
        assert_eq!(syntax.exit_code(), 1);
        // A refusal keeps its exit code when cleaning up after it fails too.
        let cleanup = Error::CleanupFailed {
            error: Box::new(invalid(vec![refused()])),
            left: "x".into(),
        };
        assert_eq!(cleanup.exit_code(), 2);
    }
}
