//! Runtime adapters (design §9): what each runtime needs from enclos, as
//! data and commands. The commands enclos runs (the installer and the
//! agent commands) run inside the sandbox, never on the host: they are
//! [`SandboxCommand`]s, which only the engine's session code can start.
//! `login` and `talk` are text enclos shows, never runs (ADR 0024).

pub mod hermes;
pub mod home;

use std::ffi::OsString;
use std::fmt;
use std::path::Path;

pub use crate::lifecycle::process::Signal;
use crate::model::agent::AgentName;
use crate::model::channel::{Channel, ChannelUser};
use crate::model::runtime::RuntimeKind;
pub use home::HomePath;

/// An installer enclos downloads on the host and runs inside the sandbox,
/// whatever version the runtime serves (ADR 0029).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Installer {
    pub url: String,
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

/// `word` as a shell reads it back: quoted when it holds anything a shell
/// would read otherwise, such as `${VAR}`, which it would expand, or starts
/// with `=`, which zsh expands to a command's path.
fn shell_word(word: &str) -> String {
    let plain = !word.is_empty()
        && !word.starts_with('=')
        && word
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_./:=@%+,-".contains(&b));
    match plain {
        true => word.to_owned(),
        false => format!("'{}'", word.replace('\'', "'\\''")),
    }
}

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
            .map(|w| shell_word(&w.to_string_lossy()))
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// The words to start it with: only the engine's code that starts a
    /// program in a sandbox (sessions, and the service runner).
    pub(crate) fn into_words(self) -> Vec<OsString> {
        self.0
    }
}

/// A part of a sandbox home that `enclos status` counts on its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DiskPart {
    /// The runtime's own install: what reinstalling would put back.
    Runtime,
    /// Caches the runtime or its tools rebuild on their own.
    Cache,
}

/// A value in a YAML file of the sandbox home: the file, and the dotted
/// keys to try in order (`model.default`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValueAt {
    pub file: HomePath,
    pub keys: &'static [&'static str],
}

/// Where a runtime keeps the facts `enclos status` shows about it. Paths
/// only, inside the sandbox home: the engine does every read, under ADR
/// 0023's rules.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuntimeFacts {
    /// Its version, when it writes one to a file.
    pub version: Option<ValueAt>,
    /// A file that exists once the runtime is logged in. Only its presence
    /// is read, never its content.
    pub login: Option<HomePath>,
    /// A path that exists while the runtime is installed in the home: gone,
    /// the runtime needs installing again.
    pub install: Option<HomePath>,
}

/// Where a runtime keeps one agent's data and the facts `status` shows.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AgentFacts {
    /// The folder holding the agent's own data.
    pub folder: Option<HomePath>,
    pub model: Option<ValueAt>,
    /// Files that change when the agent is used: the newest gives its last
    /// activity.
    pub activity: Vec<HomePath>,
}

/// The agent a runtime always has once installed, such as Hermes's
/// `default`. Made in code, as a constant, so a name that is not a valid
/// agent name does not compile: enclos shows it, and names it in commands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BuiltinAgent(&'static str);

impl BuiltinAgent {
    pub const fn new(name: &'static str) -> BuiltinAgent {
        assert!(
            crate::model::sandbox::is_short_name(name),
            "a built-in agent's name is an agent name: a lowercase letter, then 1 to 40 lowercase letters, digits or hyphens"
        );
        BuiltinAgent(name)
    }

    pub const fn as_str(self) -> &'static str {
        self.0
    }

    pub fn agent_name(self) -> AgentName {
        self.0.parse().expect("checked when made")
    }

    pub fn runtime_name(self) -> RuntimeAgentName {
        RuntimeAgentName::from(&self.agent_name())
    }
}

impl fmt::Display for BuiltinAgent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(self.0)
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
    /// The runtime's own commands run in the sandbox right after
    /// [`create_agent`](Self::create_agent) made `name`, such as undoing
    /// what it copied from another agent that is that agent's alone. An
    /// empty list (the default): nothing to run.
    fn after_create_agent(&self, _name: &AgentName) -> Vec<SandboxCommand> {
        Vec::new()
    }
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
    /// The service that listens in the sandbox, whose port the sandbox's
    /// sessions then reach (ADR 0028). `None` (the default): the runtime has
    /// no service its sessions must reach.
    fn listener(&self) -> Option<RuntimeListener> {
        None
    }
    /// The variable naming a folder whose `.env` the runtime's services
    /// read into their own process: their secrets go there, not into their
    /// environment, which any process of the user can read (ADR 0034).
    /// `None` (the default): they get their secrets as variables.
    fn secrets_folder_var(&self) -> Option<&'static str> {
        None
    }
    /// Files in the home the services read only as they start, for the
    /// built-in agent and `agents` (ADR 0031).
    fn settings_files(&self, _agents: &[RuntimeAgentName]) -> Vec<HomePath> {
        Vec::new()
    }
    /// The names of the agents the runtime has in this sandbox home, as it
    /// would list them, sorted, read on the host without running anything.
    /// The sandbox writes its home, so implementations never follow a link,
    /// read a bounded number of entries, and answer [`Unreadable`], with
    /// the reason, rather than guess (ADR 0023).
    fn agents_in(&self, home: &Path) -> Result<Vec<RuntimeAgentName>, Unreadable>;
    /// The name of the agent the runtime always has once installed, such as
    /// Hermes's `default`: it exists as long as the runtime, so enclos lists
    /// it without a record and neither adds nor removes it. `None`: every
    /// agent is one enclos adds.
    fn builtin_agent(&self) -> Option<BuiltinAgent> {
        None
    }
    /// The runtime's own command that deletes an agent and its data, run in
    /// the sandbox by `enclos agent rm`. `None`: the runtime has none, so
    /// `agent rm` removes only the record and says the files stay.
    fn delete_agent(&self, _name: &AgentName) -> Option<SandboxCommand> {
        None
    }
    /// The runtime's own command that creates agent `name` from `archive`,
    /// an export made with the runtime's own command (for Hermes, `hermes
    /// profile export`), run in the sandbox by `enclos agent add --from`
    /// (issue #34). `archive` is a host path beside the sandbox home, which
    /// the sandbox reads and never writes; the runtime extracts it inside
    /// the sandbox, so the host never does. `None`: the runtime cannot
    /// import an agent.
    fn import_agent(&self, _name: &AgentName, _archive: &Path) -> Option<SandboxCommand> {
        None
    }
    /// The file in the home where the runtime's own setup keeps `agent`'s
    /// bot token for `channel` in plain text, as a `.env` line of the
    /// variable it names: `runtime configure` refuses while it holds one, so
    /// that a token the runtime's own setup wrote does not sit readable in
    /// the home (ADR 0022). `None`: no such file.
    fn channel_token_file(
        &self,
        _channel: Channel,
        _agent: &RuntimeAgentName,
    ) -> Option<(HomePath, &'static str)> {
        None
    }
    /// The runtime's own commands that make `agent` read the secrets the
    /// policy grants it from `secrets_file`, the file `enclos launch` writes
    /// them to while the services run (ADR 0036), run in the sandbox by
    /// `enclos runtime configure`. `None`: the runtime gives no agent
    /// secrets of its own.
    fn agent_secrets_source(
        &self,
        _agent: &RuntimeAgentName,
        _secrets_file: &Path,
    ) -> Option<Vec<SandboxCommand>> {
        None
    }
    /// The runtime's own command that sets `agent`'s setting `key` to
    /// `value`, as written: a secret there is a `${VAR}`, which the runtime
    /// resolves from the agent's secrets, so that enclos hands it a name,
    /// never a value (ADR 0022). `None`: the runtime has no such command.
    fn set_setting(
        &self,
        _agent: &RuntimeAgentName,
        _key: &str,
        _value: &str,
    ) -> Option<SandboxCommand> {
        None
    }
    /// The settings that set up a bot on `channel`, in order, for
    /// [`set_setting`](Self::set_setting): its token read from the variable
    /// `token` as `${token}`, and the people it answers. The people it
    /// answers come first and the channel is turned on last, so a run that
    /// fails turns no bot on. `None`: the runtime has no such channel.
    fn channel_settings(
        &self,
        _channel: Channel,
        _token: &str,
        _answers: &[ChannelUser],
    ) -> Option<Vec<(String, String)>> {
        None
    }

    // What `enclos status` shows (issue #29). Each answer may be "cannot
    // tell", and a runtime that names nothing still gets sizes.

    /// Parts of the home counted on their own.
    fn disk_parts(&self) -> Vec<(DiskPart, HomePath)> {
        Vec::new()
    }
    fn runtime_facts(&self) -> RuntimeFacts {
        RuntimeFacts::default()
    }
    fn agent_facts(&self, _agent: &RuntimeAgentName) -> AgentFacts {
        AgentFacts::default()
    }
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
        f.pad(&self.0)
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
    /// Something other than a plain file where a file was expected.
    NotAFile,
    /// A file larger than enclos reads.
    TooLarge(u64),
    /// A file that is not UTF-8 text.
    NotText,
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
            NotRead::NotAFile => write!(f, "{path} is not a plain file"),
            NotRead::TooLarge(max) => write!(f, "{path} is larger than {max} bytes"),
            NotRead::NotText => write!(f, "{path} is not text"),
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
    /// Sent once [`RuntimeAdapter::settings_files`] change (ADR 0031); `TERM`
    /// without a graceful restart, `None` to never restart.
    pub restart: Option<Signal>,
}

/// A runtime service that listens in its sandbox, on a loopback port it
/// picks when it starts, which the runtime's own clients dial (ADR 0028).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeListener {
    /// One of the runtime's [`RuntimeAdapter::services`].
    pub service: ServiceName,
    /// The path of the page the service serves on its listener for a
    /// browser on the host, such as `/` for Hermes's dashboard. `enclos
    /// status` shows it at the port sessions are given, while the service
    /// has one.
    pub page: Option<&'static str>,
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
        f.pad(self.0)
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
