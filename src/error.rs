//! The errors an engine call returns, and the exit code each maps to.

use crate::audit::AuditError;
use crate::layout::LayoutError;
use crate::policy::PolicyError;
use crate::state::StateError;
use std::path::PathBuf;

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
    /// A sandbox marked failed, by a stop that left members running or by
    /// a command that failed, still has sessions running; `rm` waits until
    /// they are gone.
    #[error(
        "sandbox `{name}` is marked failed ({reason}) and still has processes running; `enclos sandbox show {name}` lists them. Run `enclos sandbox stop {name}`, and end yourself what it cannot"
    )]
    SandboxNotStopped { name: String, reason: String },
    #[error(
        "no free proxy port is left between {} and {}. Remove a sandbox you no longer use, or stop what else listens on those ports",
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
    #[error(transparent)]
    Markers(#[from] crate::lifecycle::marker::MarkerError),
    /// A failed command whose cleanup failed too.
    #[error("{error}; cleaning up after it failed too, and left {left}")]
    CleanupFailed { error: Box<Error>, left: String },
    /// A failed command that had already changed something, which `done`
    /// names, so that its audit entry records it too.
    #[error("{error} (after {done})")]
    FailedAfter { error: Box<Error>, done: String },
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
    /// Its own proxy holds the port: there is nothing to stop or recreate.
    #[error("the proxy of sandbox `{sandbox}` already runs on port {port}")]
    ProxyRuns { sandbox: String, port: u16 },
    /// The sandbox's home is not a real folder (a link, a file, or missing),
    /// so its policy is not compiled: Seatbelt resolves the path when the
    /// policy is compiled, and a link would carry the grant elsewhere.
    #[error(
        "the home of sandbox `{sandbox}` is not a real folder: {} is {found}, so enclos will not compile its policy. If the folder was moved aside, put it back there; otherwise stop the sandbox with `enclos sandbox stop {sandbox}`, remove it with `enclos sandbox rm {sandbox}` (which deletes its home) and create it again",
        path.display()
    )]
    HomeNotAFolder {
        sandbox: String,
        path: PathBuf,
        found: HomeFound,
    },
    /// The active policy's write checks, run again on the paths as they are
    /// when it is compiled, no longer pass.
    #[error(
        "the active policy of sandbox `{sandbox}` no longer passes enclos's write checks on the paths as they are now, so enclos will not compile it. If a link on the way changed, point it back; or change {} with `enclos policy edit {sandbox}`. {source}",
        policy_file.display()
    )]
    ActivePolicyInvalid {
        sandbox: String,
        policy_file: PathBuf,
        source: PolicyError,
    },
    /// The proxy cannot hold its port on a loopback, for another reason
    /// than another program having it. It serves only once it holds the
    /// port on both, so it does not start.
    #[error(
        "the proxy of sandbox `{sandbox}` cannot listen on {addr}: {source}. It serves only once it holds its port on 127.0.0.1 and on [::1] (where `ifconfig lo0` lists ::1)"
    )]
    ProxyListen {
        sandbox: String,
        addr: String,
        source: std::io::Error,
    },
    /// Another program holds the sandbox's proxy port on `loopback`, and
    /// would receive its traffic. Ports are the host's, so it may be the
    /// proxy of another user's or another enclos install's sandbox, say.
    #[error(
        "port {port} of sandbox `{sandbox}` is in use on {loopback} by another program; stop it (`lsof -nP -iTCP:{port} -sTCP:LISTEN` names it), or recreate the sandbox to get another port"
    )]
    ProxyPortTaken {
        sandbox: String,
        port: u16,
        /// `127.0.0.1` or `[::1]`.
        loopback: String,
    },
    #[error("the proxy of sandbox `{sandbox}` stopped serving: {source}")]
    ProxyStopped {
        sandbox: String,
        source: std::io::Error,
    },
    #[error(
        "sandbox `{sandbox}` has no pending policy: changes that need no restart are in force already. `enclos policy show {sandbox}` shows its policy"
    )]
    NoPendingPolicy { sandbox: String },
    /// The pending policy changed between reading it and applying it.
    #[error(
        "the pending policy of sandbox `{sandbox}` changed or was dropped while it was being applied. `enclos policy show {sandbox}` shows what waits now"
    )]
    PendingChanged { sandbox: String },
    /// `policy.toml` changed since the edit of a copy of it began.
    #[error(
        "{} changed since your edit of sandbox `{sandbox}` began, so the edit was not applied: it would undo that change. Your edit stays in policy.toml.edit beside it: compare the two and put what you want in your edit, then copy policy.toml over policy.toml.edit.base and run `enclos policy edit {sandbox}`, which opens your edit again; or `enclos policy discard {sandbox}` drops it",
        file.display()
    )]
    PolicyFileChanged { sandbox: String, file: PathBuf },
    /// `policy.toml` no longer holds the text the pending policy was
    /// resolved from: put in force, it would be a policy the file does not
    /// describe, and the next change, which resolves the file, would drop
    /// what the file lacks.
    #[error(
        "{} no longer holds the pending policy of sandbox `{sandbox}`, so it was not applied. `enclos policy edit {sandbox}`, saved, makes what the file holds the pending change; `enclos policy discard {sandbox}` drops it and puts back the file of the policy in force",
        file.display()
    )]
    PendingFileDiffers { sandbox: String, file: PathBuf },
    #[error(
        "sandbox `{sandbox}` has no policy v{version}: its versions are v1 to v{last}. `enclos policy history {sandbox}` lists them"
    )]
    NoSuchPolicyVersion {
        sandbox: String,
        version: u32,
        last: u32,
    },
    /// `policy.toml` holds an edit not applied, which rollback or refresh
    /// would overwrite.
    #[error(
        "{} holds an edit not applied, which `{command}` would overwrite. Apply it with `enclos policy edit {sandbox}` (closing the editor applies the file as it is), or drop it with `enclos policy discard {sandbox}`, which also drops a pending change; then run `{command}` again",
        file.display()
    )]
    PolicyFileEdited {
        sandbox: String,
        file: PathBuf,
        command: String,
    },
    /// The policy changed between what a command listed and the lock it
    /// makes its change under.
    #[error(
        "the policy of sandbox `{sandbox}` changed while this command ran, so it changed nothing. Run it again: it lists what it would change from the policy as it is now"
    )]
    PolicyChangedMeanwhile { sandbox: String },
    /// A command that resolves `policy.toml` on its own, refused while a
    /// change waits: it would put the pending change in force without the
    /// restart it needs.
    #[error(
        "sandbox `{sandbox}` has a pending policy change, which needs a restart. Apply it first with `enclos policy apply {sandbox}`, or drop it with `enclos policy discard {sandbox}`"
    )]
    PolicyPending { sandbox: String },
    #[error(transparent)]
    Secret(#[from] crate::secrets::SecretError),
    /// A policy granting a secret the sandbox does not have.
    #[error(
        "sandbox `{}` has no secret `{}`: set it first with `enclos secret set {secret}`",
        secret.sandbox,
        secret.name
    )]
    NoSuchSecret {
        secret: crate::model::secret::SecretRef,
    },
    /// A secret to remove that the sandbox does not have.
    #[error(
        "sandbox `{}` has no secret `{}`: `enclos secret list {}` lists those it has",
        secret.sandbox,
        secret.name,
        secret.sandbox
    )]
    SecretUnknown {
        secret: crate::model::secret::SecretRef,
    },
    /// A secret the active or pending policy grants, which a session would
    /// then not find.
    #[error("secret {secret} is granted as {variables} by {by}; {advice}")]
    SecretGranted {
        secret: crate::model::secret::SecretRef,
        variables: String,
        by: String,
        advice: String,
    },
    /// A secret the policy grants, which the secret store does not hold.
    #[error(
        "the policy gives secret {secret} as ${variable}, but the Keychain has no value for it; set it with `enclos secret set {secret}`"
    )]
    SecretMissing {
        secret: crate::model::secret::SecretRef,
        variable: String,
    },
    /// A service's secrets cannot be read without a dialog nobody would
    /// see: the service is not started, and not started again.
    #[error(
        "{why}, so sandbox `{sandbox}`'s {service} service, which its policy gives secrets, was not started; unlock it (logging in to the Mac does), then run `enclos sandbox start {sandbox}`"
    )]
    SecretsLocked {
        sandbox: String,
        service: String,
        why: String,
    },
    /// What the secrets file of a runtime's services cannot hold, or where
    /// it cannot be written: the service is not started, and not started
    /// again, until the user acts.
    #[error(
        "{why}, so sandbox `{sandbox}`'s services, whose runtime reads its secrets from a file, were not started; then run `enclos sandbox start {sandbox}`"
    )]
    SecretsFileRefused { sandbox: String, why: String },
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
    /// `enclos exec` failed before, around or after its command, which
    /// would otherwise be told apart from the command's own 1, 2 or 3 only
    /// by what it printed; as `env` and `docker run` do.
    pub const EXEC_FAILED: u8 = 125;
}

/// What enclos found at a sandbox home's path instead of a real folder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HomeFound {
    /// A symbolic link, and where it points.
    Link {
        to: PathBuf,
    },
    NotAFolder,
    Missing,
}

impl std::fmt::Display for HomeFound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HomeFound::Link { to } => write!(f, "a symbolic link to {}", to.display()),
            HomeFound::NotAFolder => f.write_str("not a folder"),
            HomeFound::Missing => f.write_str("missing"),
        }
    }
}

impl Error {
    /// [`Error::ProxyPortTaken`] for `addr`, the address found taken.
    pub fn proxy_port_taken(sandbox: &str, addr: std::net::SocketAddr) -> Error {
        Error::ProxyPortTaken {
            sandbox: sandbox.to_owned(),
            port: addr.port(),
            loopback: match addr {
                std::net::SocketAddr::V4(a) => a.ip().to_string(),
                std::net::SocketAddr::V6(a) => format!("[{}]", a.ip()),
            },
        }
    }

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
            | Error::ProxyPortTaken { .. }
            | Error::ProxyRuns { .. }
            | Error::ProxyListen { .. }
            | Error::ProxyStopped { .. }
            | Error::Compile(_)
            | Error::HomeNotAFolder { .. }
            | Error::ActivePolicyInvalid { .. }
            | Error::SandboxExists { .. }
            | Error::SandboxRunning { .. }
            | Error::SandboxHasServices { .. }
            | Error::SandboxNotStopped { .. }
            | Error::NoFreePorts
            | Error::Session { .. }
            | Error::Service(_)
            | Error::Processes(_)
            | Error::Markers(_)
            | Error::NoPendingPolicy { .. }
            | Error::PendingChanged { .. }
            | Error::PolicyFileChanged { .. }
            | Error::PendingFileDiffers { .. }
            | Error::PolicyPending { .. }
            | Error::NoSuchPolicyVersion { .. }
            | Error::PolicyFileEdited { .. }
            | Error::PolicyChangedMeanwhile { .. }
            | Error::Secret(_)
            | Error::NoSuchSecret { .. }
            | Error::SecretUnknown { .. }
            | Error::SecretGranted { .. }
            | Error::SecretMissing { .. }
            | Error::SecretsLocked { .. }
            | Error::SecretsFileRefused { .. }
            | Error::Unrecorded { .. } => exit::ERROR,
            Error::CleanupFailed { error, .. }
            | Error::CleanupUnrecorded { error, .. }
            | Error::WithContext { error, .. }
            | Error::FailedAfter { error, .. } => error.exit_code(),
        }
    }

    /// The error under every context and cleanup wrapped around it.
    pub fn root(&self) -> &Error {
        match self {
            Error::CleanupFailed { error, .. }
            | Error::CleanupUnrecorded { error, .. }
            | Error::WithContext { error, .. }
            | Error::FailedAfter { error, .. } => error.root(),
            other => other,
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
        let after = Error::FailedAfter {
            error: Box::new(invalid(vec![Problem::Refused("x".into())])),
            done: "y".into(),
        };
        assert_eq!(after.exit_code(), 2);
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
