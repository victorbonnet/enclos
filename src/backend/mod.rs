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
    /// The enclos data folder, where state.db and audit.jsonl live.
    pub data: PathBuf,
    /// `config.toml`.
    pub config_file: PathBuf,
    /// The sandbox's proxy port on localhost: its only way out.
    pub proxy_port: u16,
}

/// A policy compiled for one backend, as the backend reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Compiled {
    pub text: String,
    /// The file extension it is stored under, such as `sb`.
    pub extension: &'static str,
}

/// A program to run inside a sandbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Launch {
    pub program: OsString,
    pub args: Vec<OsString>,
    /// Variables set on top of the sandbox's environment.
    pub env: Vec<(String, String)>,
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
