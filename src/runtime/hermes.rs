//! The Hermes Agent adapter (Nous Research): installed per sandbox with
//! Hermes's own installer (ADR 0020), meant to be logged in with a ChatGPT
//! subscription through Hermes's device-code flow, each agent a Hermes
//! profile under `~/.hermes/profiles`, all sharing the sandbox's one Hermes
//! login (`~/.hermes/auth.json`) (design §14: to verify in this build).

mod facts;

use std::ffi::OsString;
use std::path::Path;

use rustix::fs::{Dir, FileType};

use super::home::{entry_stat, io, open_folder, open_home, unreadable};
use super::{
    AgentFacts, AppChannel, BuiltinAgent, DiskPart, HomeFile, HomePath, Installer, ListenerPorts,
    NotRead, ProviderAt, RuntimeAdapter, RuntimeAgentName, RuntimeDashboard, RuntimeFacts,
    RuntimeListener, RuntimeService, SandboxCommand, SecretFileFormat, SecretFiles, ServiceName,
    Signal, Unreadable, ValueAt,
};
use crate::model::agent::AgentName;
use crate::model::channel::{Channel, ChannelUser};
use crate::model::runtime::RuntimeKind;
use crate::model::sandbox::BackendKind;

pub struct Hermes;

/// The installer the official docs and README point to, as it is served at
/// install time, and the Hermes version it installs, whatever the stable
/// channel serves then (ADR 0029).
pub const INSTALLER_URL: &str = "https://hermes-agent.nousresearch.com/install.sh";

/// `hermes`, as the installer puts it on the sandbox's PATH.
const HERMES: &str = "hermes";

// The mobile app's channel plugin (`channels/hermes/enclos/`), carried by
// the binary so that nothing is downloaded to put it in a sandbox.
const APP_PLUGIN_YAML: &str = include_str!("../../channels/hermes/enclos/plugin.yaml");
const APP_PLUGIN_INIT: &str = include_str!("../../channels/hermes/enclos/__init__.py");
const APP_PLUGIN_ADAPTER: &str = include_str!("../../channels/hermes/enclos/adapter.py");
const APP_PLUGIN_PROTOCOL: &str = include_str!("../../channels/hermes/enclos/protocol.py");
const APP_PLUGIN_APPROVALS: &str = include_str!("../../channels/hermes/enclos/approvals.py");
const APP_PLUGIN_INTERRUPTS: &str = include_str!("../../channels/hermes/enclos/interrupts.py");
const APP_PLUGIN_OUTBOX: &str = include_str!("../../channels/hermes/enclos/outbox.py");
const APP_PLUGIN_ROUTINES: &str = include_str!("../../channels/hermes/enclos/routines.py");
const APP_PLUGIN_LINES: &str = include_str!("../../channels/hermes/enclos/lines.py");
const APP_PLUGIN_QUESTIONS: &str = include_str!("../../channels/hermes/enclos/questions.py");
const APP_PLUGIN_RUNTIME_APPROVALS: &str =
    include_str!("../../channels/hermes/enclos/runtime_approvals.py");
const APP_PLUGIN_QUESTIONS_SKILL: &str =
    include_str!("../../channels/hermes/enclos/skills/app-questions/SKILL.md");
const GATEWAY: ServiceName = ServiceName::new("gateway");
/// How long Hermes's `clarify` waits for the person's answer before the
/// agent goes on without one. Hermes's own default (90 s on main of
/// 2026-11-10, `tools/clarify_gateway.py`, `resolve_clarify_timeout`) frees
/// a turn quickly at a desk; a question on a phone is often seen later, so
/// the app's agents wait an hour, Hermes's earlier default. A reply typed
/// instead still cancels the question at once. The bridge's own backstop
/// for a channel that stays away is twice this (`bridge/questions.rs`).
pub const CLARIFY_TIMEOUT_SECONDS: u32 = 3600;

/// Hermes's built-in profile, the root of its home.
const DEFAULT_PROFILE: BuiltinAgent = BuiltinAgent::new("default");

/// The files that make a folder under `~/.hermes/profiles/` a profile, as
/// Hermes decides it: `_PROFILE_IDENTITY_MARKERS` in `hermes_constants.py`,
/// read in Hermes 0.22.2. A Hermes change here needs the adapter updated
/// (design §14).
const PROFILE_MARKERS: [&str; 6] = [
    "config.yaml",
    ".env",
    "SOUL.md",
    "profile.yaml",
    "auth.json",
    "state.db",
];

/// At most this many entries of `~/.hermes/profiles/` are read; more means
/// "cannot tell", never a partial list.
const MAX_ENTRIES: usize = 512;

const PROFILES: &str = "~/.hermes/profiles";
const DELETED: &str = "~/.hermes/profiles/.deleted";

/// Hermes's profile id rule, `PROFILE_ID_RE` in `hermes_cli/profiles.py`
/// (Hermes 0.22.2): `^[a-z0-9][a-z0-9_-]{0,63}$`.
fn hermes_id(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
        && name.len() <= 64
}

/// A path of the home Hermes writes; every one here is a literal.
fn at(path: &str) -> HomePath {
    HomePath::new(path).expect("a plain path inside the home")
}

/// The built-in agent's is all of `.hermes`.
fn agent_folder(agent: &RuntimeAgentName) -> HomePath {
    if agent.as_str() == DEFAULT_PROFILE.as_str() {
        at(".hermes")
    } else {
        at(".hermes/profiles").join(agent)
    }
}

/// Whether the entry is a link or a plain file, without following it.
fn file_or_link(dir: &rustix::fd::OwnedFd, name: &str, shown: &str) -> Result<bool, Unreadable> {
    Ok(entry_stat(dir, name, shown)?.is_some_and(|s| {
        let t = FileType::from_raw_mode(s.st_mode);
        t.is_file() || t.is_symlink()
    }))
}

impl RuntimeAdapter for Hermes {
    fn kind(&self) -> RuntimeKind {
        RuntimeKind::Hermes
    }

    fn version(&self) -> &'static str {
        // 2: the gateway listens (ADR 0028).
        "2"
    }

    fn endpoints(&self) -> &'static str {
        include_str!("hermes/endpoints.toml")
    }

    fn installer(&self) -> Installer {
        Installer {
            url: INSTALLER_URL.to_owned(),
            // No setup and no `gateway install` (no launchd job of its own),
            // and no computer-use driver.
            args: vec!["--non-interactive".into(), "--skip-computer-use".into()],
        }
    }

    fn home_files(&self, backend: BackendKind) -> Vec<HomeFile> {
        // The shim makes up for macOS's `mktemp`; on a Linux sandbox's PATH
        // it would only stand in front of a `mktemp` that needs no help.
        if !backend.mktemp_ignores_tmpdir() {
            return Vec::new();
        }
        vec![HomeFile {
            path: "bin/mktemp",
            contents: include_str!("hermes/mktemp"),
            executable: true,
        }]
    }

    fn login(&self) -> String {
        // Hermes's setup wizard: the provider and its login, the model, and
        // optional sections. `hermes model` covers only provider, login and
        // model, all a login needs (`setup` in the sandbox: to verify).
        // For the root profile, whose login every agent shares: without `-p`,
        // Hermes uses the profile `hermes profile use` last saved in
        // `~/.hermes/active_profile` (`hermes_cli/main.py`, Hermes 0.22.2).
        format!("{HERMES} -p {DEFAULT_PROFILE} setup")
    }

    fn create_agent(&self, name: &AgentName) -> SandboxCommand {
        // Hermes calls an agent a profile: each enclos agent is the Hermes
        // profile of the same name, created and selected with Hermes's
        // own `profile` command and `-p` flag. Cloned from the built-in
        // profile, so that it starts on the model and provider the
        // sandbox's login is for, not Hermes's own default, which that
        // login may not reach (shown with Hermes 0.22.5); Hermes leaves its
        // channels' settings behind (`--clone-from`, its
        // `strip_channel_settings`) and copies the rest of `config.yaml`.
        SandboxCommand::from_words(&[
            HERMES,
            "profile",
            "create",
            name.as_str(),
            "--clone-from",
            DEFAULT_PROFILE.as_str(),
        ])
    }

    fn after_create_agent(&self, name: &AgentName) -> Vec<SandboxCommand> {
        // The clone copies the built-in agent's `config.yaml`, and with it
        // any `secrets.command`, which may read that agent's secrets file
        // (ADR 0036): turned off, until `runtime configure` points it at
        // this agent's own. An imported agent gets the same.
        vec![SandboxCommand::from_words(&[
            HERMES,
            "-p",
            name.as_str(),
            "config",
            "set",
            "secrets.command.enabled",
            "false",
        ])]
    }

    fn agent_files(&self, name: &AgentName) -> String {
        format!("~/.hermes/profiles/{name}")
    }

    fn channel_token_files(
        &self,
        channel: Channel,
        agent: &RuntimeAgentName,
    ) -> Vec<(HomePath, &'static str)> {
        // Hermes's setup writes a profile's bot token to its `.env`
        // (`save_env_value` in `hermes_cli/setup_platforms.py`).
        let file = match agent.as_str() == DEFAULT_PROFILE.as_str() {
            true => ".hermes/.env".to_owned(),
            false => format!(".hermes/profiles/{agent}/.env"),
        };
        vec![(at(&file), channel.token_variable())]
    }

    fn agent_secrets_source(
        &self,
        agent: &RuntimeAgentName,
        secrets_file: &Path,
    ) -> Option<Vec<SandboxCommand>> {
        // Hermes's gateway serves every profile in one process, and the
        // sandbox's secrets file reaches them all alike; a profile's own
        // `secrets.command` gives what it prints to that profile alone
        // (`agent/secret_sources/command.py`, Hermes 0.22.5), read here from
        // the file `enclos launch` writes its grants to (ADR 0036). Hermes
        // runs it through `/bin/sh -c`, so this adapter quotes the path.
        let path = secrets_file.to_str()?;
        if path.contains(['\n', '\r']) {
            return None;
        }
        let read = format!("cat '{}'", path.replace('\'', "'\\''"));
        let set = |key: &str, value: &str| self.set_setting(agent, key, value);
        Some(vec![
            set("secrets.command.command", &read)?,
            // What the file holds wins over the profile's own `.env`.
            set("secrets.command.override_existing", "true")?,
            set("secrets.command.enabled", "true")?,
        ])
    }

    fn channel_token_is_plain(
        &self,
        _channel: Channel,
        _agent: &RuntimeAgentName,
        text: &str,
        field: &str,
    ) -> Result<bool, String> {
        Ok(super::settings::holds_variable(text, field))
    }

    fn inspect_settings(
        &self,
        files: &[super::settings::SettingsFile],
    ) -> Result<Vec<super::settings::SettingsFinding>, String> {
        Ok(super::settings::dotenv_yaml_findings(files))
    }

    fn set_setting(
        &self,
        agent: &RuntimeAgentName,
        key: &str,
        value: &str,
    ) -> Option<SandboxCommand> {
        // Hermes's own `config set`: a dotted key in the profile's
        // `config.yaml`, an upper-case one in its `.env`, where `${VAR}` is
        // resolved from the profile's secrets as the gateway loads its
        // settings (`hermes_cli/config.py`, `_expand_env_vars`).
        Some(SandboxCommand::from_words(&[
            HERMES,
            "-p",
            agent.as_str(),
            "config",
            "set",
            key,
            value,
        ]))
    }

    fn channel_settings(
        &self,
        _agent: &RuntimeAgentName,
        channel: Channel,
        token: &str,
        answers: &[ChannelUser],
    ) -> Option<Vec<(String, String)>> {
        let users: Vec<&str> = answers.iter().map(ChannelUser::as_str).collect();
        match channel {
            Channel::Telegram => Some(vec![
                // Not a secret: who may talk to the bot.
                ("TELEGRAM_ALLOWED_USERS".to_owned(), users.join(",")),
                // Only the variable's name.
                (
                    "platforms.telegram.token".to_owned(),
                    format!("${{{token}}}"),
                ),
                ("platforms.telegram.enabled".to_owned(), "true".to_owned()),
            ]),
            // Set up by `app_channel`: no bot, no people to answer.
            Channel::App => None,
        }
    }

    fn app_channel(
        &self,
        agent: &RuntimeAgentName,
        socket: &Path,
        _token_file: &Path,
        home: &str,
    ) -> Option<AppChannel> {
        // A plugin Hermes loads from the agent's own home, `plugins/` under
        // its `HERMES_HOME`, and only once `plugins enable` lists it in
        // that agent's settings (read in Hermes's source, main of
        // 2026-11-03: `plugins/plugin_loader.py`, `user_plugins_dir`, and
        // `hermes_cli/plugins_discovery.py`, `gate_manifest`; to verify,
        // design §14). It turns itself on for an agent whose secrets give
        // it a socket and a token (`channels/hermes/enclos/adapter.py`).
        let plugins = agent_folder(agent).child("plugins")?.child("enclos")?;
        let file = |name: &str, contents: &'static str| Some((plugins.child(name)?, contents));
        Some(AppChannel {
            files: vec![
                file("plugin.yaml", APP_PLUGIN_YAML)?,
                file("__init__.py", APP_PLUGIN_INIT)?,
                file("adapter.py", APP_PLUGIN_ADAPTER)?,
                file("interrupts.py", APP_PLUGIN_INTERRUPTS)?,
                file("protocol.py", APP_PLUGIN_PROTOCOL)?,
                file("outbox.py", APP_PLUGIN_OUTBOX)?,
                file("approvals.py", APP_PLUGIN_APPROVALS)?,
                file("routines.py", APP_PLUGIN_ROUTINES)?,
                file("lines.py", APP_PLUGIN_LINES)?,
                file("questions.py", APP_PLUGIN_QUESTIONS)?,
                file("runtime_approvals.py", APP_PLUGIN_RUNTIME_APPROVALS)?,
                file("skills/app-questions/SKILL.md", APP_PLUGIN_QUESTIONS_SKILL)?,
            ],
            commands: vec![SandboxCommand::from_words(&[
                HERMES,
                "-p",
                agent.as_str(),
                "plugins",
                "enable",
                "enclos",
            ])],
            settings: vec![
                // Not secrets: where to listen, and that the bridge, which
                // holds the agent's token, decides who talks to the agent.
                ("MOBILE_APP_SOCKET".to_owned(), socket.display().to_string()),
                ("MOBILE_APP_ALLOW_ALL".to_owned(), "true".to_owned()),
                // Hermes's home channel for the app is the agent's Home
                // conversation (ADR 0044): what `/sethome` would set, from
                // the start, so Hermes never asks for one. Overwrites what
                // a `/sethome` left.
                ("MOBILE_APP_HOME_CHANNEL".to_owned(), home.to_owned()),
                // A question asked in the app waits for a phone, not a desk.
                (
                    "agent.clarify_timeout".to_owned(),
                    CLARIFY_TIMEOUT_SECONDS.to_string(),
                ),
            ],
        })
    }

    fn delete_agent(&self, name: &AgentName) -> Option<SandboxCommand> {
        // Hermes's own delete, so whatever it keeps beside the profile
        // folder goes with it (what that is: to verify, design §14).
        Some(SandboxCommand::from_words(&[
            HERMES,
            "profile",
            "delete",
            name.as_str(),
            "--yes",
        ]))
    }

    fn finish_delete_agent(&self, name: &AgentName) -> Option<SandboxCommand> {
        // Hermes 0.23.0's delete removes the profile, then exits 1 when the
        // session and routing records under its name are not purged yet
        // ("its session/routing identity settlement is still pending"),
        // naming this command, which purges them, succeeds when they are
        // already gone, and refuses while a profile of that name exists
        // (`purge_profile_identity` in `hermes_cli/profile_identity.py`).
        Some(SandboxCommand::from_words(&[
            HERMES,
            "profile",
            "purge-identity",
            name.as_str(),
        ]))
    }

    fn import_agent(&self, name: &AgentName, archive: &Path) -> Option<SandboxCommand> {
        // Hermes's own import of an archive its `profile export` made, by
        // Hermes 0.22.2's code: it extracts without following links or
        // leaving the profile folder, refuses an existing profile and
        // `default`, removes the archive's `installs`, `tools` and `cache`
        // folders, and writes the profile's wrapper unless the name
        // collides with a command. Its export leaves out `auth.json`, `.env`
        // and the browser's data and scrubs secret-shaped strings. Neither
        // is shown yet (design §14).
        let mut words: Vec<OsString> = [HERMES, "profile", "import"].map(OsString::from).to_vec();
        words.push(archive.as_os_str().to_owned());
        words.extend(["--name", name.as_str()].map(OsString::from));
        Some(SandboxCommand::new(words))
    }

    fn disk_parts(&self) -> Vec<(DiskPart, HomePath)> {
        let runtime = [".hermes/hermes-agent", ".hermes/tools", ".hermes/installs"]
            .map(|p| (DiskPart::Runtime, at(p)));
        let caches = [".hermes/cache", ".npm", ".cache", "tmp"].map(|p| (DiskPart::Cache, at(p)));
        runtime.into_iter().chain(caches).collect()
    }

    fn fact_value(&self, at: &ValueAt, text: &str) -> Result<Option<String>, String> {
        facts::value(at, text)
    }

    fn runtime_facts(&self) -> RuntimeFacts {
        RuntimeFacts {
            // Not on disk where enclos can rely on it: `pyproject.toml` says
            // 0.0.0 (to verify, design §14).
            version: None,
            // Agents share the root login.
            login: Some(at(".hermes/auth.json")),
            // Where the installer puts Hermes itself.
            install: Some(at(".hermes/hermes-agent")),
        }
    }

    fn agent_facts(&self, agent: &RuntimeAgentName) -> AgentFacts {
        // The built-in agent's folder is the whole home of Hermes: the parts
        // counted on their own (runtime, caches, other profiles) leave it its
        // own data.
        let folder = agent_folder(agent);
        let file = |name: &str| folder.child(name).expect("a plain file name");
        AgentFacts {
            model: Some(ValueAt {
                file: file("config.yaml"),
                // Hermes reads either key.
                keys: vec!["model.default".into(), "model.model".into()],
            }),
            // Each profile keeps its own provider, which a new one copies
            // from `default` as it is then: `auto` before the sandbox's
            // login chose one, or after a setup that ended before the model.
            // With `auto`, a profile falls back on the `active_provider` of
            // its own `auth.json` only, not the root's, and says it is "not
            // connected to any AI provider" (`resolve_provider` in
            // `hermes_cli/auth.py`; seen with Hermes 0.23.0). Hermes's
            // `model` command chooses a provider and model for the profile.
            provider: Some(ProviderAt {
                at: ValueAt {
                    file: file("config.yaml"),
                    keys: vec!["model.provider".into()],
                },
                unchosen: &["auto", ""],
                choose: format!("{HERMES} -p {agent} model"),
            }),
            // What changed when an agent was used; `sessions/` did not (to
            // verify, design §14).
            activity: [".hermes_history", "state.db", "state.db-wal"]
                .map(file)
                .to_vec(),
            folder: Some(folder),
        }
    }

    fn talk(&self, agent: &AgentName) -> String {
        // Hermes also writes a wrapper named after the agent on the sandbox
        // PATH (`main` runs `hermes -p main`); enclos's messages use the
        // form that does not depend on it. The built-in agent is named too:
        // bare `hermes` follows the saved active profile, not always it.
        format!("{HERMES} -p {agent}")
    }

    fn builtin_agent(&self) -> Option<BuiltinAgent> {
        // Hermes's own `default` profile: the root of its home, which
        // `hermes` uses when no `-p` is given.
        Some(DEFAULT_PROFILE)
    }

    fn services(&self) -> Vec<RuntimeService> {
        // One gateway per Hermes home serves every agent: cron, housekeeping
        // and, later, messaging. The backend starts
        // programs from an empty environment, which clears the markers
        // Hermes reads to find its supervisor (`XPC_SERVICE_NAME` for
        // launchd, `INVOCATION_ID` for systemd), so the flag says that one
        // restarts it: on an in-chat restart or update it exits (75) for the
        // service manager to start it again, rather than starting a detached
        // replacement that no session would hold.
        vec![RuntimeService {
            name: GATEWAY,
            // As the built-in agent, whose home serves every agent: bare,
            // Hermes would follow the profile a sandbox shell last chose
            // with `hermes profile use` (`hermes_cli/main.py`), and serve
            // only that one.
            command: SandboxCommand::from_words(&[
                HERMES,
                "-p",
                DEFAULT_PROFILE.as_str(),
                "gateway",
                "run",
                "--external-supervisor",
            ]),
            // Hermes's graceful restart: running turns finish, then it exits
            // 75. Sent from outside the sandbox, which Seatbelt allows.
            restart: Some(Signal::Usr1),
        }]
    }

    fn agent_settings_files(&self, agent: &RuntimeAgentName) -> Vec<HomePath> {
        let folder = agent_folder(agent);
        ["config.yaml", ".env"]
            .map(|name| folder.child(name).expect("a plain file name"))
            .to_vec()
    }

    fn reads_agent_secrets(&self, text: &str, secrets_file: &Path) -> bool {
        // `secrets.command` as `agent_secrets_source` sets it, read line by
        // line: a clone or an import keeps the command and turns it off
        // (`after_create_agent`), and a line outside it says nothing. YAML
        // may fold the command over two lines, both inside the block.
        let secrets_file = secrets_file.to_string_lossy();
        let quoted_file = secrets_file.replace('\'', "'\\''");
        let (mut reads, mut on) = (false, false);
        let (mut in_secrets, mut block) = (false, None);
        for line in text.lines() {
            let content = line.trim_start();
            if content.is_empty() || content.starts_with('#') {
                continue;
            }
            let content = content.split(" #").next().unwrap_or(content).trim_end();
            let indent = line.len() - line.trim_start().len();
            if indent == 0 {
                in_secrets = content == "secrets:";
                block = None;
                continue;
            }
            match block {
                Some(at) if indent > at => {
                    reads |= content.contains(&*secrets_file) || content.contains(&quoted_file);
                    on |= content == "enabled: true";
                }
                _ => block = (in_secrets && content == "command:").then_some(indent),
            }
        }
        reads && on
    }

    fn secret_files(&self) -> Option<SecretFiles> {
        // Hermes loads `$HERMES_MANAGED_DIR/.env` into its own environment,
        // last and with override, when the folder exists
        // (`hermes_cli/managed_scope.py`, `env_loader._apply_managed_env`).
        Some(SecretFiles {
            folder_variable: Some("HERMES_MANAGED_DIR"),
            sandbox: SecretFileFormat::EscapedDotenv,
            agent: SecretFileFormat::QuotedDotenv,
        })
    }

    fn listener(&self) -> Option<RuntimeListener> {
        // Hermes 0.22.3's chat (CLI, TUI, stream-json) cannot run without the
        // gateway: it finds it, gets a ticket for its own agent (a Hermes
        // profile) over
        // `gateway.sock` in the home, and dials the WebSocket the gateway
        // serves on 127.0.0.1:0 (`gateway/run_api.py`,
        // `hermes_cli/gateway_client.py`).
        Some(RuntimeListener {
            service: GATEWAY,
            ports: ListenerPorts::Ephemeral,
            // Its web dashboard, on the same listener. Bound to loopback,
            // Hermes asks no login for it, by its code
            // (`listener_auth_required` in `gateway/run_api.py`).
            page: Some("/"),
        })
    }

    fn dashboard(&self) -> Option<RuntimeDashboard> {
        // `hermes dashboard` puts its session token in its page, which the
        // gateway's own port withholds, so the page works there alone.
        // `--isolated` and `--port 0` make its server its own: a plain one
        // reports a dashboard another session left open, or one on Hermes's
        // default port, and exits 0 (`_attach_to_host_backend`, read in
        // Hermes 0.22.5's source; ADR 0040).
        Some(RuntimeDashboard {
            command: SandboxCommand::from_words(&[
                HERMES,
                "dashboard",
                "--no-open",
                "--isolated",
                "--port",
                "0",
            ]),
            page: "/",
        })
    }

    fn agents_in(&self, home: &Path) -> Result<Vec<RuntimeAgentName>, Unreadable> {
        // Hermes lists a named profile when its folder under
        // `~/.hermes/profiles/` has a valid id, is not `default` (the Hermes
        // home itself), has one of its identity files, and has no marker
        // under `profiles/.deleted/`. Where Hermes follows links (a marker
        // that `is_file` or `is_symlink`, a tombstone that `exists`), enclos
        // looks without following: a link or a folder in a marker's place
        // counts as Hermes would count a link, and a dangling link counts as
        // a tombstone where Hermes would not. Every folder is opened by its
        // descriptor, so a link the sandbox plants, before or during the
        // read, is never followed: `.hermes`, `profiles` or `.deleted` as a
        // link means "cannot tell", and a linked profile folder is not
        // listed.
        let home = open_home(home)?;
        let Some(hermes) = open_folder(&home, ".hermes", "~/.hermes")? else {
            return Ok(Vec::new());
        };
        let Some(profiles) = open_folder(&hermes, "profiles", PROFILES)? else {
            return Ok(Vec::new());
        };
        let deleted = open_folder(&profiles, ".deleted", DELETED)?;
        let mut entries = Vec::new();
        for entry in Dir::read_from(&profiles).map_err(|e| io(PROFILES, e))? {
            let entry = entry.map_err(|e| io(PROFILES, e))?;
            // A name that is not text is not a Hermes id either.
            let Ok(name) = entry.file_name().to_str() else {
                continue;
            };
            if name == "." || name == ".." {
                continue;
            }
            if entries.len() == MAX_ENTRIES {
                return Err(unreadable(PROFILES, NotRead::TooManyEntries(MAX_ENTRIES)));
            }
            entries.push(name.to_owned());
        }
        let mut names = Vec::new();
        for name in entries {
            if name == DEFAULT_PROFILE.as_str() || !hermes_id(&name) {
                continue;
            }
            // Every Hermes id is a runtime agent name.
            let Some(agent) = RuntimeAgentName::new(&name) else {
                continue;
            };
            let shown = format!("{PROFILES}/{name}");
            let profile = match open_folder(&profiles, name.as_str(), &shown) {
                Ok(Some(fd)) => fd,
                Ok(None) => continue,
                Err(Unreadable {
                    why: NotRead::Link | NotRead::NotAFolder,
                    ..
                }) => continue,
                Err(e) => return Err(e),
            };
            let mut identity = false;
            for marker in PROFILE_MARKERS {
                if file_or_link(&profile, marker, &shown)? {
                    identity = true;
                    break;
                }
            }
            if !identity {
                continue;
            }
            if let Some(deleted) = &deleted
                && entry_stat(deleted, name.as_str(), DELETED)?.is_some()
            {
                continue;
            }
            names.push(agent);
        }
        names.sort();
        Ok(names)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_protected_source_path_with_a_quote_is_passed_literally_to_the_shell() {
        let home = tempfile::tempdir().unwrap();
        let file = home.path().join("one'quote.env");
        std::fs::write(&file, "harmless fixture").unwrap();
        let commands = Hermes
            .agent_secrets_source(&RuntimeAgentName::new("main").unwrap(), &file)
            .unwrap();
        let words = commands[0].clone().into_words();
        let read = words.last().unwrap();
        let output = std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg(read)
            .output()
            .unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout, b"harmless fixture");
    }
    use crate::policy::file::{FsLayer, PolicyFile};

    #[test]
    fn the_endpoints_add_exactly_the_model_login_and_install_hosts_and_nothing_else() {
        let layer = PolicyFile::parse("hermes adapter", Hermes.endpoints()).unwrap();
        assert!(layer.beyond_destinations().is_empty(), "{layer:?}");
        assert_eq!(layer.filesystem, FsLayer::default());
        let mut allow = layer.network.allow_add.clone();
        allow.sort();
        // Any new or broader host is a deliberate change here.
        assert_eq!(
            allow,
            [
                "api.github.com",
                "auth.openai.com",
                "cdn.playwright.dev",
                "chatgpt.com",
                "ffmpeg.martin-riedl.de",
                "files.pythonhosted.org",
                "github.com",
                "nodejs.org",
                "playwright.download.prss.microsoft.com",
                "pypi.org",
                "registry.npmjs.org",
                "release-assets.githubusercontent.com",
                "releases.astral.sh",
                "storage.googleapis.com",
            ]
        );
        for entry in &allow {
            crate::net::host::AllowEntry::parse(entry).unwrap();
            assert!(!entry.starts_with('*'), "no wildcard: {entry}");
        }
    }

    #[test]
    fn an_agent_reads_its_secrets_only_from_a_command_that_is_on() {
        let file = Path::new("/e/sandboxes/lab/secrets/main.env");
        let reads = |text: &str| Hermes.reads_agent_secrets(text, file);
        let on = "model: x\nsecrets:\n  command:\n    enabled: true\n    command: cat '/e/sandboxes/lab/secrets/main.env'\n    override_existing: true\nplatforms:\n  telegram:\n    enabled: false\n";
        assert!(reads(on));
        // YAML folds a long command.
        assert!(reads(
            "secrets:\n  command:\n    command: cat\n      '/e/sandboxes/lab/secrets/main.env'\n    enabled: true # on\n"
        ));
        // Turned off, as a clone or an import leaves it.
        assert!(!reads(&on.replace("enabled: true", "enabled: false")));
        // Another agent's file.
        assert!(!reads(&on.replace("main.env", "scout.env")));
        // In a comment, or in another block.
        assert!(!reads(
            "secrets:\n  command:\n    enabled: true\n    # command: cat '/e/sandboxes/lab/secrets/main.env'\n"
        ));
        assert!(!reads(
            "other:\n  command:\n    enabled: true\n    command: cat '/e/sandboxes/lab/secrets/main.env'\n"
        ));
        assert!(!reads(
            "secrets:\n  other:\n    enabled: true\n    command: cat '/e/sandboxes/lab/secrets/main.env'\n"
        ));
        assert!(!reads(""));
    }

    #[test]
    fn the_gateway_restarts_gracefully_for_the_settings_of_every_agent() {
        assert_eq!(Hermes.services()[0].restart, Some(Signal::Usr1));
        let main = RuntimeAgentName::new("main").unwrap();
        let files: Vec<String> = Hermes
            .settings_files(&[main])
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(
            files,
            [
                "~/.hermes/config.yaml",
                "~/.hermes/.env",
                "~/.hermes/profiles/main/config.yaml",
                "~/.hermes/profiles/main/.env",
            ]
        );
    }

    /// An agent reads its own secrets file through its own
    /// `secrets.command` (ADR 0036); a setting is Hermes's `config set`;
    /// a Telegram bot is the people it answers, its token by name, and the
    /// channel turned on last.
    #[test]
    fn an_agent_reads_its_own_secrets_and_its_settings_name_them() {
        let users = ["111".parse().unwrap(), "222".parse().unwrap()];
        let agent = RuntimeAgentName::new("main").unwrap();
        let file = Path::new("/Users/alice/.enclos/sandboxes/home/secrets/main.env");
        let shown: Vec<String> = Hermes
            .agent_secrets_source(&agent, file)
            .unwrap()
            .iter()
            .map(SandboxCommand::shown)
            .collect();
        assert_eq!(
            shown,
            [
                "hermes -p main config set secrets.command.command 'cat '\\''/Users/alice/.enclos/sandboxes/home/secrets/main.env'\\'''",
                "hermes -p main config set secrets.command.override_existing true",
                "hermes -p main config set secrets.command.enabled true",
            ]
        );
        assert_eq!(
            Hermes
                .set_setting(&agent, "platforms.discord.token", "${DISCORD_BOT_TOKEN}")
                .unwrap()
                .shown(),
            // Quoted, so a person who runs it as shown in a sandbox, where
            // the secret is set, does not write its value.
            "hermes -p main config set platforms.discord.token '${DISCORD_BOT_TOKEN}'"
        );
        assert_eq!(
            Hermes
                .channel_settings(
                    &RuntimeAgentName::new("main").unwrap(),
                    Channel::Telegram,
                    "TELEGRAM_BOT_TOKEN_MAIN",
                    &users
                )
                .unwrap(),
            [
                ("TELEGRAM_ALLOWED_USERS".to_owned(), "111,222".to_owned()),
                (
                    "platforms.telegram.token".to_owned(),
                    "${TELEGRAM_BOT_TOKEN_MAIN}".to_owned()
                ),
                ("platforms.telegram.enabled".to_owned(), "true".to_owned()),
            ]
        );
        // The built-in agent's plain-text token is in the home's `.env`,
        // another agent's in its own folder's.
        let default = RuntimeAgentName::new("default").unwrap();
        assert_eq!(
            Hermes.channel_token_files(Channel::Telegram, &default)[0].0,
            at(".hermes/.env")
        );
        assert_eq!(
            Hermes.channel_token_files(Channel::Telegram, &agent)[0].0,
            at(".hermes/profiles/main/.env")
        );
    }

    /// A new agent starts from the built-in agent's settings, its model
    /// among them, and does not keep reading that agent's secrets file.
    #[test]
    fn a_new_agent_is_cloned_from_the_built_in_one_without_its_secrets() {
        let main: AgentName = "main".parse().unwrap();
        assert_eq!(
            Hermes.create_agent(&main).shown(),
            "hermes profile create main --clone-from default"
        );
        let after: Vec<String> = Hermes
            .after_create_agent(&main)
            .iter()
            .map(SandboxCommand::shown)
            .collect();
        assert_eq!(
            after,
            ["hermes -p main config set secrets.command.enabled false"]
        );
    }

    #[test]
    fn the_gateway_may_listen() {
        // Hermes 0.22.3's gateway binds its own listener (ADR 0028).
        let layer = PolicyFile::parse("hermes adapter", Hermes.endpoints()).unwrap();
        assert_eq!(layer.network.listen, Some(true));
    }

    #[test]
    fn the_listening_service_is_one_of_its_services() {
        let listener = Hermes.listener().unwrap();
        assert_eq!(listener.service.as_str(), "gateway");
        assert_eq!(listener.ports, ListenerPorts::Ephemeral);
        assert!(Hermes.services().iter().any(|s| s.name == listener.service));
    }

    #[test]
    fn the_dashboard_is_a_server_of_its_own_on_a_port_the_kernel_picks() {
        let dashboard = Hermes.dashboard().unwrap();
        assert_eq!(
            dashboard.command.shown(),
            "hermes dashboard --no-open --isolated --port 0"
        );
        assert_eq!(dashboard.page, "/");
    }

    fn names(names: &[&str]) -> Vec<RuntimeAgentName> {
        names
            .iter()
            .map(|n| RuntimeAgentName::new(n).unwrap())
            .collect()
    }

    /// A home with a `.hermes/profiles` folder, and a way to make a profile
    /// in it with one identity marker.
    fn hermes_home() -> (
        tempfile::TempDir,
        std::path::PathBuf,
        impl Fn(&str, Option<&str>),
    ) {
        let home = tempfile::tempdir().unwrap();
        let profiles = home.path().join(".hermes/profiles");
        std::fs::create_dir_all(&profiles).unwrap();
        let at = profiles.clone();
        let profile = move |name: &str, marker: Option<&str>| {
            std::fs::create_dir_all(at.join(name)).unwrap();
            if let Some(m) = marker {
                std::fs::write(at.join(name).join(m), "").unwrap();
            }
        };
        (home, profiles, profile)
    }

    #[test]
    fn agents_are_listed_as_hermes_lists_its_named_profiles() {
        let (home, profiles, profile) = hermes_home();
        profile("main", Some("config.yaml"));
        profile("my_bot", Some("SOUL.md")); // a Hermes name enclos cannot use
        profile("default", Some("config.yaml")); // the Hermes home itself
        profile("ghost", None); // no identity file: not a profile
        profile("gone", Some(".env"));
        std::fs::create_dir_all(profiles.join(".deleted/gone")).unwrap();
        profile("Upper", Some(".env")); // not a Hermes id
        std::fs::write(profiles.join("file"), "").unwrap();
        // A marker that is a folder does not count; a link does, as for
        // Hermes, even a dangling one.
        profile("boxed", None);
        std::fs::create_dir(profiles.join("boxed/config.yaml")).unwrap();
        profile("linked-marker", None);
        std::os::unix::fs::symlink("/nonexistent", profiles.join("linked-marker/auth.json"))
            .unwrap();
        // A tombstone that is a dangling link counts (Hermes would not).
        profile("buried", Some("config.yaml"));
        std::os::unix::fs::symlink("/nonexistent", profiles.join(".deleted/buried")).unwrap();
        // A linked profile folder is not listed.
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("config.yaml"), "").unwrap();
        std::os::unix::fs::symlink(outside.path(), profiles.join("linked")).unwrap();
        assert_eq!(
            Hermes.agents_in(home.path()),
            Ok(names(&["linked-marker", "main", "my_bot"]))
        );
    }

    #[test]
    fn a_missing_hermes_or_profiles_folder_means_no_agents() {
        let home = tempfile::tempdir().unwrap();
        assert_eq!(Hermes.agents_in(home.path()), Ok(vec![]));
        std::fs::create_dir(home.path().join(".hermes")).unwrap();
        assert_eq!(Hermes.agents_in(home.path()), Ok(vec![]));
    }

    #[test]
    fn a_link_or_a_file_in_a_folders_place_cannot_be_read_and_says_which() {
        let at = |path: &str, why| Unreadable {
            path: path.to_owned(),
            why,
        };
        let outside = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(outside.path().join("profiles/main")).unwrap();
        std::fs::write(outside.path().join("profiles/main/config.yaml"), "").unwrap();

        let home = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path(), home.path().join(".hermes")).unwrap();
        assert_eq!(
            Hermes.agents_in(home.path()),
            Err(at("~/.hermes", NotRead::Link))
        );

        let home = tempfile::tempdir().unwrap();
        std::fs::write(home.path().join(".hermes"), "").unwrap();
        assert_eq!(
            Hermes.agents_in(home.path()),
            Err(at("~/.hermes", NotRead::NotAFolder))
        );

        let home = tempfile::tempdir().unwrap();
        std::fs::create_dir(home.path().join(".hermes")).unwrap();
        std::os::unix::fs::symlink(
            outside.path().join("profiles"),
            home.path().join(".hermes/profiles"),
        )
        .unwrap();
        assert_eq!(
            Hermes.agents_in(home.path()),
            Err(at("~/.hermes/profiles", NotRead::Link))
        );

        let (home, profiles, profile) = hermes_home();
        profile("main", Some("config.yaml"));
        std::os::unix::fs::symlink(outside.path(), profiles.join(".deleted")).unwrap();
        assert_eq!(
            Hermes.agents_in(home.path()),
            Err(at("~/.hermes/profiles/.deleted", NotRead::Link))
        );

        let gone = tempfile::tempdir().unwrap();
        let path = gone.path().to_owned();
        drop(gone);
        assert_eq!(Hermes.agents_in(&path), Err(at("~", NotRead::Missing)));
    }

    #[test]
    fn more_entries_than_the_cap_cannot_be_read() {
        let (home, profiles, profile) = hermes_home();
        for i in 0..MAX_ENTRIES {
            std::fs::write(profiles.join(format!("f{i}")), "").unwrap();
        }
        profile("main", Some("config.yaml"));
        assert_eq!(
            Hermes.agents_in(home.path()),
            Err(Unreadable {
                path: "~/.hermes/profiles".to_owned(),
                why: NotRead::TooManyEntries(MAX_ENTRIES),
            })
        );
        std::fs::remove_file(profiles.join("f0")).unwrap();
        assert_eq!(Hermes.agents_in(home.path()), Ok(names(&["main"])));
    }

    #[test]
    fn commands_name_the_agent_and_the_home_file_stays_inside_the_home() {
        let main: AgentName = "main".parse().unwrap();
        assert_eq!(Hermes.talk(&main), "hermes -p main");
        assert_eq!(Hermes.login(), "hermes -p default setup");
        assert_eq!(Hermes.agent_files(&main), "~/.hermes/profiles/main");
        assert_eq!(
            Hermes.delete_agent(&main),
            Some(SandboxCommand::from_words(&[
                "hermes", "profile", "delete", "main", "--yes"
            ]))
        );
        assert_eq!(
            Hermes.finish_delete_agent(&main).unwrap().shown(),
            "hermes profile purge-identity main"
        );
        let default: AgentName = "default".parse().unwrap();
        assert_eq!(Hermes.builtin_agent(), Some(DEFAULT_PROFILE));
        assert_eq!(Hermes.talk(&default), "hermes -p default");
        let facts = |n: &str| Hermes.agent_facts(&RuntimeAgentName::new(n).unwrap());
        assert_eq!(facts("default").folder, Some(at(".hermes")));
        let main_facts = facts("main");
        assert_eq!(main_facts.folder, Some(at(".hermes/profiles/main")));
        assert_eq!(
            main_facts.model,
            Some(ValueAt {
                file: at(".hermes/profiles/main/config.yaml"),
                keys: vec!["model.default".into(), "model.model".into()],
            })
        );
        assert_eq!(
            main_facts.activity,
            [".hermes_history", "state.db", "state.db-wal"]
                .map(|f| at(&format!(".hermes/profiles/main/{f}")))
        );
        // What `status` counts on its own; a rename here changes what it shows.
        let parts: Vec<(DiskPart, String)> = Hermes
            .disk_parts()
            .into_iter()
            .map(|(p, path)| (p, path.to_string()))
            .collect();
        assert_eq!(
            parts,
            [
                (DiskPart::Runtime, "~/.hermes/hermes-agent"),
                (DiskPart::Runtime, "~/.hermes/tools"),
                (DiskPart::Runtime, "~/.hermes/installs"),
                (DiskPart::Cache, "~/.hermes/cache"),
                (DiskPart::Cache, "~/.npm"),
                (DiskPart::Cache, "~/.cache"),
                (DiskPart::Cache, "~/tmp"),
            ]
            .map(|(p, s)| (p, s.to_owned()))
        );
        let rt = Hermes.runtime_facts();
        assert_eq!(
            (rt.version, rt.login, rt.install),
            (
                None,
                Some(at(".hermes/auth.json")),
                Some(at(".hermes/hermes-agent"))
            )
        );
        assert_eq!(
            Hermes.create_agent(&main),
            SandboxCommand::from_words(&[
                "hermes",
                "profile",
                "create",
                "main",
                "--clone-from",
                "default"
            ])
        );
        assert_eq!(
            Hermes.import_agent(&main, Path::new("/x/installers/agent-main.tar.gz")),
            Some(SandboxCommand::from_words(&[
                "hermes",
                "profile",
                "import",
                "/x/installers/agent-main.tar.gz",
                "--name",
                "main"
            ]))
        );
        for backend in BackendKind::ALL {
            assert!(
                Hermes
                    .home_files(backend)
                    .iter()
                    .all(HomeFile::path_is_inside_home)
            );
        }
    }

    /// The `mktemp` shim makes up for macOS's own, which ignores `TMPDIR`:
    /// a Seatbelt sandbox gets it, a Linux sandbox, whose GNU `mktemp`
    /// follows `TMPDIR`, does not.
    #[test]
    fn the_mktemp_shim_goes_only_where_mktemp_ignores_tmpdir() {
        let paths =
            |backend| -> Vec<&str> { Hermes.home_files(backend).iter().map(|f| f.path).collect() };
        assert_eq!(paths(BackendKind::Seatbelt), ["bin/mktemp"]);
        assert!(paths(BackendKind::Bubblewrap).is_empty());
        for backend in BackendKind::ALL {
            assert_eq!(
                paths(backend).contains(&"bin/mktemp"),
                backend.mktemp_ignores_tmpdir(),
                "{backend:?}"
            );
        }
    }

    #[test]
    fn the_app_channel_goes_in_the_agents_own_home_and_is_enabled_there() {
        let socket = Path::new("/h/.enclos-app/main.sock");
        let main = RuntimeAgentName::new("main").unwrap();
        let token_file = Path::new("/protected/secrets/main.env");
        let app = Hermes
            .app_channel(&main, socket, token_file, "home.lab.main")
            .unwrap();
        let places: Vec<String> = app
            .files
            .iter()
            .map(|(place, _)| place.as_path().display().to_string())
            .collect();
        assert_eq!(
            places,
            [
                ".hermes/profiles/main/plugins/enclos/plugin.yaml",
                ".hermes/profiles/main/plugins/enclos/__init__.py",
                ".hermes/profiles/main/plugins/enclos/adapter.py",
                ".hermes/profiles/main/plugins/enclos/interrupts.py",
                ".hermes/profiles/main/plugins/enclos/protocol.py",
                ".hermes/profiles/main/plugins/enclos/outbox.py",
                ".hermes/profiles/main/plugins/enclos/approvals.py",
                ".hermes/profiles/main/plugins/enclos/routines.py",
                ".hermes/profiles/main/plugins/enclos/lines.py",
                ".hermes/profiles/main/plugins/enclos/questions.py",
                ".hermes/profiles/main/plugins/enclos/runtime_approvals.py",
                ".hermes/profiles/main/plugins/enclos/skills/app-questions/SKILL.md",
            ]
        );
        assert!(app.files.iter().all(|(_, contents)| !contents.is_empty()));
        assert_eq!(
            app.commands
                .iter()
                .map(SandboxCommand::shown)
                .collect::<Vec<_>>(),
            ["hermes -p main plugins enable enclos"]
        );
        assert_eq!(
            app.settings,
            [
                (
                    "MOBILE_APP_SOCKET".to_owned(),
                    "/h/.enclos-app/main.sock".to_owned()
                ),
                ("MOBILE_APP_ALLOW_ALL".to_owned(), "true".to_owned()),
                (
                    "MOBILE_APP_HOME_CHANNEL".to_owned(),
                    "home.lab.main".to_owned()
                ),
                ("agent.clarify_timeout".to_owned(), "3600".to_owned()),
            ]
        );
        let default = RuntimeAgentName::new("default").unwrap();
        let app = Hermes
            .app_channel(&default, socket, token_file, "home.lab.default")
            .unwrap();
        assert_eq!(
            app.files[0].0.as_path(),
            Path::new(".hermes/plugins/enclos/plugin.yaml")
        );
    }

    #[test]
    fn one_gateway_serves_the_sandbox_and_says_launchd_restarts_it() {
        let services = Hermes.services();
        assert_eq!(services.len(), 1);
        assert_eq!(services[0].name.as_str(), "gateway");
        assert_eq!(
            services[0].command,
            SandboxCommand::from_words(&[
                "hermes",
                "-p",
                "default",
                "gateway",
                "run",
                "--external-supervisor"
            ])
        );
    }
}
