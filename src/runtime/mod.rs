//! Runtime adapters (design §9): what each runtime needs from enclos, as
//! data and commands. The commands enclos runs (the installer, creating an
//! agent) run inside the sandbox, never on the host: they are
//! [`SandboxCommand`]s, which only the engine's session code can start.
//! `login` and `talk` are text enclos shows, never runs (ADR 0024).

pub mod hermes;

use std::ffi::OsString;
use std::fmt;
use std::path::Path;

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
/// one; only the engine's code that starts programs in a sandbox can take
/// its words out, so an adapter's command cannot be started on the host by
/// mistake.
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

    /// The words to start it with: only the engine's code that starts a
    /// program in a sandbox (sessions, and the service runner).
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
    /// The background processes the runtime runs while its sandbox is
    /// started: none, one or several, each with a name of its own. Hermes
    /// has one gateway serving every agent (ADR 0021).
    fn services(&self) -> Vec<RuntimeService>;
    /// The names of the agents the runtime has in this sandbox home, as it
    /// would list them, sorted, read on the host without running anything.
    /// The sandbox writes its home, so implementations never follow a link,
    /// read a bounded number of entries, and answer [`Unreadable`], with
    /// the reason, rather than guess (ADR 0023).
    fn agents_in(&self, home: &Path) -> Result<Vec<RuntimeAgentName>, Unreadable>;
}

/// A name a runtime gives one of its agents, as the runtime writes it.
/// Wider than [`AgentName`] (Hermes allows `_` and a leading digit), but
/// still one printable ASCII word of at most 64 bytes, so it is safe in a
/// message. Adapters apply their runtime's own rule first; this one is the
/// trait's promise to whoever prints the name.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RuntimeAgentName(String);

impl RuntimeAgentName {
    /// `[a-z0-9][a-z0-9_.-]{0,63}`; `None` otherwise.
    pub fn new(name: &str) -> Option<RuntimeAgentName> {
        let mut chars = name.chars();
        let ok = chars
            .next()
            .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
            && chars.all(|c| {
                c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | '.' | '-')
            })
            && name.len() <= 64;
        ok.then(|| RuntimeAgentName(name.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Every agent name is a runtime agent name: the short-name rule is the
/// narrower one.
impl From<&AgentName> for RuntimeAgentName {
    fn from(name: &AgentName) -> RuntimeAgentName {
        RuntimeAgentName(name.as_str().to_owned())
    }
}

impl fmt::Display for RuntimeAgentName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Why an adapter could not read its runtime's agents in a sandbox home
/// (ADR 0023): what the sandbox wrote cannot be read safely, or at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unreadable {
    /// The path, as the sandbox sees it: `~/.hermes/profiles`.
    pub path: String,
    pub why: NotRead,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotRead {
    /// A link, which the sandbox may have pointed anywhere.
    Link,
    NotAFolder,
    Missing,
    /// More entries than an adapter reads.
    TooManyEntries(usize),
    /// A read failed; the OS's words.
    Io(String),
}

impl fmt::Display for Unreadable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let path = &self.path;
        match &self.why {
            NotRead::Link => write!(f, "{path} is a link"),
            NotRead::NotAFolder => write!(f, "{path} is not a folder"),
            NotRead::Missing => write!(f, "{path} is missing"),
            NotRead::TooManyEntries(max) => write!(f, "{path} has more than {max} entries"),
            NotRead::Io(e) => write!(f, "{path}: {e}"),
        }
    }
}

/// One background process of a runtime, run by the host's service manager
/// through `enclos launch <sandbox> <name>`.
#[derive(Debug, Clone)]
pub struct RuntimeService {
    pub name: ServiceName,
    pub command: SandboxCommand,
}

/// A runtime's name for one of its services, stable across versions, as it
/// names the service's label and log: the short-name rule, and never
/// `proxy`, the sandbox's own service. Made in code, as a constant, so a
/// name that breaks the rule does not compile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ServiceName(&'static str);

impl ServiceName {
    pub const fn new(name: &'static str) -> ServiceName {
        assert!(
            crate::model::sandbox::is_short_name(name),
            "a service name is a short name: a lowercase letter, then 1 to 40 lowercase letters, digits or hyphens"
        );
        // `const` has no string comparison; the bytes of "proxy".
        let b = name.as_bytes();
        assert!(
            !(b.len() == 5
                && b[0] == b'p'
                && b[1] == b'r'
                && b[2] == b'o'
                && b[3] == b'x'
                && b[4] == b'y'),
            "`proxy` is the sandbox's own service, not a runtime's"
        );
        ServiceName(name)
    }

    pub const fn as_str(self) -> &'static str {
        self.0
    }
}

impl fmt::Display for ServiceName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
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
    fn a_runtime_names_each_of_its_services_once() {
        for kind in crate::model::runtime::RuntimeKind::ALL {
            let names: Vec<ServiceName> = adapter(kind).services().iter().map(|s| s.name).collect();
            let mut unique = names.clone();
            unique.sort_unstable();
            unique.dedup();
            assert_eq!(unique.len(), names.len(), "{kind}: {names:?}");
        }
    }

    #[test]
    #[should_panic(expected = "short name")]
    fn a_service_name_that_is_not_a_short_name_is_refused() {
        ServiceName::new("Gateway");
    }

    #[test]
    #[should_panic(expected = "sandbox's own service")]
    fn a_service_named_proxy_is_refused() {
        ServiceName::new("proxy");
    }

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
    fn a_runtime_agent_name_is_one_printable_word_and_wider_than_an_agent_name() {
        for good in ["main", "my_bot", "0day", "a.b-c_d", &"x".repeat(64)] {
            assert_eq!(RuntimeAgentName::new(good).unwrap().as_str(), good);
        }
        for bad in [
            "",
            "Main",
            "-x",
            "_x",
            "a b",
            "a/b",
            "a\u{1b}[0m",
            "é",
            &"x".repeat(65),
        ] {
            assert!(RuntimeAgentName::new(bad).is_none(), "{bad:?}");
        }
        let main: AgentName = "main".parse().unwrap();
        assert_eq!(RuntimeAgentName::from(&main).as_str(), "main");
    }

    #[test]
    fn unreadable_says_the_path_and_the_reason() {
        let at = |why| Unreadable {
            path: "~/.hermes".to_owned(),
            why,
        };
        assert_eq!(at(NotRead::Link).to_string(), "~/.hermes is a link");
        assert_eq!(
            at(NotRead::TooManyEntries(512)).to_string(),
            "~/.hermes has more than 512 entries"
        );
        assert_eq!(
            at(NotRead::Io("permission denied".into())).to_string(),
            "~/.hermes: permission denied"
        );
    }

    #[test]
    fn a_sandbox_command_is_shown_as_typed() {
        let command = SandboxCommand::from_words(&["hermes", "profile", "create", "main"]);
        assert_eq!(command.shown(), "hermes profile create main");
        assert!(!command.is_empty());
    }
}
