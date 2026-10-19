//! Runtime adapters (design §9): what each runtime needs from enclos,
//! as data and commands. The engine runs every command inside the sandbox.

pub mod hermes;

use std::ffi::OsString;

use crate::model::agent::AgentName;
use crate::model::runtime::RuntimeKind;

/// An installer enclos downloads on the host and runs only if its content
/// is the one reviewed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Installer {
    pub url: &'static str,
    pub sha256: &'static str,
    /// The arguments it runs with, after the downloaded file.
    pub args: &'static [&'static str],
}

/// A file the adapter puts in the sandbox home, relative to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HomeFile {
    pub path: &'static str,
    pub contents: &'static str,
    pub executable: bool,
}

pub trait RuntimeAdapter {
    fn kind(&self) -> RuntimeKind;
    /// The adapter's version, recorded in policy snapshots (ADR 0018).
    fn version(&self) -> &'static str;
    /// The policy layer of endpoints the runtime needs to work at all.
    fn endpoints(&self) -> &'static str;
    fn installer(&self) -> Installer;
    fn home_files(&self) -> Vec<HomeFile>;
    /// The runtime's own login and model choice, run in the terminal.
    fn login(&self) -> Vec<OsString>;
    fn create_agent(&self, name: &AgentName) -> Vec<OsString>;
    /// An interactive session for an agent, or the default one.
    fn interactive(&self, agent: Option<&AgentName>) -> Vec<OsString>;
}

pub fn adapter(kind: RuntimeKind) -> Box<dyn RuntimeAdapter> {
    match kind {
        RuntimeKind::Hermes => Box::new(hermes::Hermes),
    }
}
