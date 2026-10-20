//! Runtime adapters (design §9): what each runtime needs from enclos, as
//! data and commands. The commands enclos runs (the installer, creating an
//! agent) run inside the sandbox, never on the host: they are
//! [`SandboxCommand`]s, which only the engine's session code can start.
//! `login` and `talk` are text enclos shows, never runs (ADR 0024).

pub mod hermes;

use std::ffi::OsString;

use crate::model::agent::AgentName;
use crate::model::runtime::RuntimeKind;

/// An installer enclos downloads on the host and runs only if its content
/// is the one reviewed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Installer {
    pub url: String,
    pub sha256: String,
    /// The arguments it runs with, after the downloaded file.
    pub args: Vec<String>,
}

/// A file the adapter puts in the sandbox home, relative to it: a plain
/// relative path, no `..`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HomeFile {
    pub path: &'static str,
    pub contents: &'static str,
    pub executable: bool,
}

impl HomeFile {
    /// Whether `path` stays inside the home: relative, with no `..` and no
    /// empty component.
    pub fn path_is_inside_home(&self) -> bool {
        !self.path.is_empty()
            && !self.path.starts_with('/')
            && self
                .path
                .split('/')
                .all(|c| !c.is_empty() && c != "." && c != "..")
    }
}

/// A command that runs inside a sandbox, under its policy. Anyone can make
/// one; only the engine's session code can take its words out to start it,
/// so an adapter's command cannot be started on the host by mistake.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxCommand(Vec<OsString>);

impl SandboxCommand {
    pub fn new(words: Vec<OsString>) -> SandboxCommand {
        SandboxCommand(words)
    }

    pub fn from_words(words: &[&str]) -> SandboxCommand {
        SandboxCommand(words.iter().map(OsString::from).collect())
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The command as a person would type it.
    pub fn shown(&self) -> String {
        self.0
            .iter()
            .map(|w| w.to_string_lossy())
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// The words to start it with: the engine's session code only.
    pub(crate) fn into_words(self) -> Vec<OsString> {
        self.0
    }
}

pub trait RuntimeAdapter {
    fn kind(&self) -> RuntimeKind;
    /// The adapter's version, recorded in policy snapshots (ADR 0018).
    fn version(&self) -> &'static str;
    /// The policy layer of destinations the runtime needs to work at all:
    /// `[network] allow_add` and nothing else (design §7).
    fn endpoints(&self) -> &'static str;
    fn installer(&self) -> Installer;
    fn home_files(&self) -> Vec<HomeFile>;
    /// What a person runs in the sandbox to log the runtime in and set it
    /// up, for enclos's messages: `enclos connect <sandbox> -- <this>`.
    /// enclos shows it, never runs it (ADR 0024).
    fn login(&self) -> String;
    fn create_agent(&self, name: &AgentName) -> SandboxCommand;
    /// Where the runtime keeps an agent's files, relative to the sandbox
    /// home, for enclos's messages.
    fn agent_files(&self, name: &AgentName) -> String;
    /// What a person runs in the sandbox to talk to an agent, for enclos's
    /// messages: `enclos connect <sandbox> -- <this>` (ADR 0024).
    fn talk(&self, agent: &AgentName) -> String;
}

pub fn adapter(kind: RuntimeKind) -> Box<dyn RuntimeAdapter> {
    match kind {
        RuntimeKind::Hermes => Box::new(hermes::Hermes),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_home_file_stays_inside_the_home() {
        let file = |path| HomeFile {
            path,
            contents: "",
            executable: false,
        };
        assert!(file("bin/mktemp").path_is_inside_home());
        for bad in ["", "/etc/x", "../x", "bin/../../x", "bin//x", "./x"] {
            assert!(!file(bad).path_is_inside_home(), "{bad}");
        }
    }

    #[test]
    fn a_sandbox_command_is_shown_as_typed() {
        let command = SandboxCommand::from_words(&["hermes", "profile", "create", "main"]);
        assert_eq!(command.shown(), "hermes profile create main");
        assert!(!command.is_empty());
    }
}
