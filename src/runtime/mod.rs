//! Runtime adapters (design §9): what each runtime needs from enclos,
//! as data and commands. The engine runs every command inside the sandbox.

pub mod hermes;

use std::ffi::OsString;
use std::path::{Path, PathBuf};

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

/// A part of a sandbox home that `enclos status` counts on its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DiskPart {
    /// The runtime's own install: what reinstalling would put back.
    Runtime,
    /// Caches the runtime or its tools rebuild on their own.
    Cache,
}

/// A value in a YAML file of the sandbox home: the file, relative to the
/// home, and the dotted keys to try in order (`model.default`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValueAt {
    pub file: PathBuf,
    pub keys: Vec<&'static str>,
}

/// Where a runtime keeps the facts `enclos status` shows about it. Paths
/// only, relative to the sandbox home: the engine does every read, under
/// ADR 0023's rules.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuntimeFacts {
    /// Its version, when it writes one to a file.
    pub version: Option<ValueAt>,
    /// A file that exists once the runtime is logged in. Only its presence
    /// is read, never its content.
    pub login: Option<PathBuf>,
}

/// Where a runtime keeps one agent's data and the facts `status` shows.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AgentFacts {
    /// The folder holding the agent's own data.
    pub folder: Option<PathBuf>,
    pub model: Option<ValueAt>,
    /// Files that change when the agent is used: the newest gives its last
    /// activity.
    pub activity: Vec<PathBuf>,
}

pub trait RuntimeAdapter {
    fn kind(&self) -> RuntimeKind;
    /// The adapter's version, recorded in policy snapshots (ADR 0018).
    fn version(&self) -> &'static str;
    /// The policy layer of endpoints the runtime needs to work at all.
    fn endpoints(&self) -> &'static str;
    fn installer(&self) -> Installer;
    fn home_files(&self) -> Vec<HomeFile>;
    /// What a person runs in the sandbox to log the runtime in and set it
    /// up, for enclos's messages: `enclos connect <sandbox> -- <this>`.
    /// enclos shows it, never runs it (ADR 0024).
    fn login(&self) -> String;
    fn create_agent(&self, name: &AgentName) -> Vec<OsString>;
    /// What a person runs in the sandbox to talk to an agent, for enclos's
    /// messages: `enclos connect <sandbox> -- <this>` (ADR 0024).
    fn talk(&self, agent: &AgentName) -> String;
    /// The one background process serving every agent of the sandbox,
    /// if the runtime has one (ADR 0021).
    fn service(&self) -> Option<Vec<OsString>>;
    /// The names of the agents the runtime has in this sandbox home, as it
    /// would list them, read on the host without running anything. `None`
    /// when the runtime has no named agents, or when its listing cannot be
    /// read safely. The sandbox writes its home, so implementations never
    /// follow a link and read a bounded number of entries (ADR 0023).
    fn agents_in(&self, home: &Path) -> Option<Vec<String>>;
    /// The runtime's own command that deletes an agent and its data, run in
    /// the sandbox by `enclos agent rm`. `None`: the files stay.
    fn delete_agent(&self, _name: &AgentName) -> Option<Vec<OsString>> {
        None
    }

    // What `enclos status` shows (issue #29). Each answer may be "cannot
    // tell", and a runtime that names nothing still gets sizes.

    /// Parts of the home counted on their own, relative to it.
    fn disk_parts(&self) -> Vec<(DiskPart, PathBuf)> {
        Vec::new()
    }
    fn runtime_facts(&self) -> RuntimeFacts {
        RuntimeFacts::default()
    }
    fn agent_facts(&self, _agent: &str) -> AgentFacts {
        AgentFacts::default()
    }
}

pub fn adapter(kind: RuntimeKind) -> Box<dyn RuntimeAdapter> {
    match kind {
        RuntimeKind::Hermes => Box::new(hermes::Hermes),
    }
}
