//! Backends: the isolation technologies sandboxes are built on (design §5).
//!
//! The trait holds what the commands built so far need; it grows toward the
//! full shape in design §9 (prepare, members, denials, ...) as the commands
//! that use it arrive.

#[cfg(test)]
pub mod fake;
pub mod seatbelt;

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::layout::Layout;
use crate::model::policy::Policy;
use crate::model::sandbox::{BackendKind, SandboxName};

/// Whether a backend can run on this host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Probe {
    Available,
    Unavailable { reason: String },
}

/// How well a backend enforces one area of the policy (ADR 0008).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Enforcement {
    Enforced,
    Partial { note: String },
    Unsupported,
}

/// What a backend enforces, per policy area.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capabilities {
    pub fs: Enforcement,
    pub network: Enforcement,
    pub exec: Enforcement,
    pub resources: Enforcement,
    /// Finding every process of a sandbox (ADR 0019).
    pub members: Enforcement,
}

/// Everything about a sandbox that compiling and wrapping need, with every
/// path already absolute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxContext {
    pub name: SandboxName,
    /// The sandbox's folder: its policy, compiled policies and home.
    pub dir: PathBuf,
    pub home: PathBuf,
    /// The user's own home, which `~` in policies means.
    pub user_home: PathBuf,
    /// The enclos data and config folders (ADR 0010).
    pub protected: Vec<PathBuf>,
    /// The folder holding every sandbox's folder.
    pub sandboxes: PathBuf,
    /// Files the sandbox may not read, each with every file whose name
    /// starts with it.
    pub hidden_files: Vec<PathBuf>,
    /// Folders the sandbox may not read.
    pub hidden_dirs: Vec<PathBuf>,
    /// The sandbox's proxy port, on 127.0.0.1 and [::1]: its only way out.
    pub proxy_port: u16,
}

impl SandboxContext {
    /// The sandbox `name` in `layout`, the one source of its paths.
    pub fn new(layout: &Layout, name: &SandboxName, proxy_port: u16) -> SandboxContext {
        SandboxContext {
            name: name.clone(),
            dir: layout.sandbox_dir(name.as_str()),
            home: layout.sandbox_home(name.as_str()),
            user_home: layout.user_home().to_owned(),
            protected: layout.protected(),
            sandboxes: layout.sandboxes_dir(),
            hidden_files: layout.hidden_files(),
            hidden_dirs: layout.hidden_dirs(),
            proxy_port,
        }
    }
}

/// A policy compiled for one backend, as the backend reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Compiled {
    pub text: String,
    /// The file extension it is stored under, such as `sb`.
    pub extension: &'static str,
}

/// A program to run inside a sandbox.
#[derive(Debug, PartialEq, Eq)]
pub struct Launch {
    pub program: OsString,
    pub args: Vec<OsString>,
    /// The secrets its policy grants, by variable, set before the
    /// sandbox's own environment, which they never replace.
    pub env: Vec<(String, crate::model::secret::SecretValue)>,
    /// Whether the program runs in the terminal enclos runs in, as a
    /// session does: the backend then lets it open that terminal by name. A
    /// service or a probe never does, whatever terminal enclos runs in.
    pub in_terminal: bool,
    /// The port at 127.0.0.1 where the sandbox's own runtime service listens,
    /// which the program may then connect to besides the proxy (ADR 0028).
    /// Set for the sessions `run_in_sandbox` starts while the service
    /// listens; none for the service itself, a probe, a sandbox whose
    /// runtime has no such service, or one whose service does not listen.
    pub service_port: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CompileError {
    #[error("cannot compile the policy for {backend}: {reason}")]
    Unsupported {
        backend: BackendKind,
        reason: String,
    },
}

/// One isolation technology. Prepares, wraps and finds members; never
/// supervises.
pub trait Backend {
    fn kind(&self) -> BackendKind;
    /// Checks, without side effects, whether this backend works on this host.
    fn probe(&self) -> Probe;
    fn capabilities(&self) -> Capabilities;
    /// Turns a policy into what the backend enforces. Pure.
    fn compile(&self, policy: &Policy, ctx: &SandboxContext) -> Result<Compiled, CompileError>;
    /// The command that runs `launch` inside the sandbox under `compiled`.
    fn wrap(&self, compiled: &Path, ctx: &SandboxContext, launch: &Launch) -> Command;
}

/// Every backend this build of enclos ships, in order of preference.
///
/// This is the one explicit list of implementations.
pub fn registered() -> Vec<Box<dyn Backend>> {
    vec![Box::new(seatbelt::Seatbelt)]
}
