//! OpenClaw's native CLI, configuration and protected-file consumers.
//! Source contracts were checked against the installed 2026.11.2 package;
//! all native mutations remain SandboxCommands executed by the engine.

use std::path::Path;

use serde_json::{Value, json};

use super::home::{read_text, unreadable};
use super::settings::{Held, SettingsFile, SettingsFinding, dotenv_line, names_a_secret};
use super::{
    AgentDeleteMode, AgentFacts, AppChannel, DiskPart, HomeFile, HomePath, Installer,
    ListenerPorts, NotRead, RuntimeAdapter, RuntimeAgentName, RuntimeFacts, RuntimeListener,
    RuntimeService, SandboxCommand, SecretFileFormat, SecretFiles, SecretTarget, ServiceName,
    Unreadable, ValueAt,
};
use crate::model::agent::AgentName;
use crate::model::channel::{Channel, ChannelUser};
use crate::model::runtime::RuntimeKind;
use crate::model::sandbox::BackendKind;
use crate::model::secret::{is_variable_name, reserved_variable};

pub struct OpenClaw;
pub const INSTALLER_URL: &str = "https://openclaw.ai/install-cli.sh";
const CONFIG: &str = ".openclaw/openclaw.json";
const MAX_CONFIG: u64 = 256 * 1024;
const MAX_AGENTS: usize = 512;
const GATEWAY: ServiceName = ServiceName::new("gateway");
const APP_PLUGIN: &str = ".enclos-openclaw";
const INSTALL_APP: &str = "exec \"$HOME/bin/openclaw\" plugins install --link \"$HOME/.enclos-openclaw\" --force --no-enable --accept-capabilities";
const ENABLE_APP: &str = "set -eu\nagent=$1\n\"$HOME/bin/openclaw\" agents bind --agent \"$agent\" --bind \"enclos:$agent\" --json\n\"$HOME/bin/openclaw\" config set channels.enclos.enabled true\nexec \"$HOME/bin/openclaw\" config set \"channels.enclos.accounts.$agent.enabled\" true";

fn at(path: &str) -> HomePath {
    HomePath::new(path).expect("a literal home-relative path")
}

/// Provider aliases remain short even for a native id wider than AgentName.
pub(crate) fn agent_provider(agent: &RuntimeAgentName) -> String {
    format!(
        "enclos-{}",
        &crate::policy::sha256_hex(agent.as_str().as_bytes())[..16]
    )
}

fn setting(key: &str, value: &str) -> SandboxCommand {
    SandboxCommand::from_words(&["openclaw", "config", "set", key, value])
}

/// Bound nesting before recursive JSON5 decoding. Strings/comments cannot
/// manufacture nesting; parse errors never include source text or values.
pub(crate) fn parse(text: &str) -> Result<Value, String> {
    if text.len() > MAX_CONFIG as usize {
        return Err("OpenClaw settings exceed the observation limit".into());
    }
    let bytes = text.as_bytes();
    let (mut i, mut depth) = (0, 0usize);
    while i < bytes.len() {
        match bytes[i] {
            b'\'' | b'"' => {
                let quote = bytes[i];
                i += 1;
                while i < bytes.len() && bytes[i] != quote {
                    i += if bytes[i] == b'\\' { 2 } else { 1 };
                }
            }
            b'/' if bytes.get(i + 1) == Some(&b'/') => {
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
            }
            b'/' if bytes.get(i + 1) == Some(&b'*') => {
                i += 2;
                while i + 1 < bytes.len() && &bytes[i..i + 2] != b"*/" {
                    i += 1;
                }
                i += 1;
            }
            b'{' | b'[' => {
                depth += 1;
                if depth > 64 {
                    return Err("OpenClaw settings are nested too deeply".into());
                }
            }
            b'}' | b']' => depth = depth.saturating_sub(1),
            _ => {}
        }
        i += 1;
    }
    let value: Value = json5::from_str(text).map_err(|_| "invalid OpenClaw JSON5 settings")?;
    fn includes(value: &Value) -> bool {
        match value {
            Value::Object(map) => map.contains_key("$include") || map.values().any(includes),
            Value::Array(values) => values.iter().any(includes),
            _ => false,
        }
    }
    if includes(&value) {
        return Err("OpenClaw $include settings require native inspection; host observations do not follow them".into());
    }
    if !value.is_object() {
        return Err("OpenClaw settings must be an object".into());
    }
    Ok(value)
}

fn config(home: &Path) -> Result<Value, Unreadable> {
    let file = at(CONFIG);
    let text = read_text(home, &file, MAX_CONFIG)?;
    match text {
        None => Ok(json!({})),
        Some(text) => parse(&text).map_err(|why| unreadable(&file.to_string(), NotRead::Io(why))),
    }
}

fn names(config: &Value) -> Result<Vec<RuntimeAgentName>, String> {
    let raw: Vec<&str> = match config.pointer("/agents/entries") {
        Some(Value::Object(entries)) => entries.keys().map(String::as_str).collect(),
        Some(_) => return Err("OpenClaw agents.entries is not an object".into()),
        None => match config.pointer("/agents/list") {
            Some(Value::Array(entries)) => entries
                .iter()
                .map(|entry| {
                    entry
                        .get("id")
                        .and_then(Value::as_str)
                        .ok_or_else(|| "OpenClaw agent has no id".to_owned())
                })
                .collect::<Result<_, _>>()?,
            Some(_) => return Err("OpenClaw agents.list is not an array".into()),
            None if config.pointer("/agents/ownership").and_then(Value::as_str)
                == Some("explicit") =>
            {
                Vec::new()
            }
            None => vec!["main"],
        },
    };
    if raw.len() > MAX_AGENTS {
        return Err("OpenClaw has too many agents to observe".into());
    }
    let mut result = raw
        .into_iter()
        .map(|name| {
            RuntimeAgentName::new(name)
                .ok_or_else(|| "OpenClaw has an agent id enclos cannot represent".into())
        })
        .collect::<Result<Vec<_>, String>>()?;
    result.sort();
    if result.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err("OpenClaw has duplicate agent ids".into());
    }
    Ok(result)
}

fn reference_variable(value: &Value, agent: &RuntimeAgentName) -> Option<String> {
    let source = value.get("source")?.as_str()?;
    let id = value.get("id")?.as_str()?;
    match source {
        "env" if is_variable_name(id) => Some(id.to_owned()),
        "file"
            if value
                .get("provider")
                .and_then(Value::as_str)
                .is_some_and(|p| p == "enclos-sandbox" || p == agent_provider(agent)) =>
        {
            id.strip_prefix('/')
                .filter(|id| is_variable_name(id))
                .map(str::to_owned)
        }
        _ => None,
    }
}

fn is_reference(value: &Value) -> bool {
    value.as_object().is_some_and(|v| {
        v.len() == 3
            && v.get("source")
                .and_then(Value::as_str)
                .is_some_and(|s| matches!(s, "file" | "env" | "exec" | "store"))
            && ["provider", "id"].iter().all(|k| {
                v.get(*k)
                    .and_then(Value::as_str)
                    .is_some_and(|s| !s.is_empty())
            })
    })
}

/// The enclos channel consumes a protected JSON file, never a token value,
/// at this one native schema field. Other token-like fields stay guarded.
fn credential_file_field(path: &str, value: &Value) -> bool {
    let parts: Vec<_> = path.split('/').collect();
    parts.len() == 5
        && parts[..3] == ["channels", "enclos", "accounts"]
        && !parts[3].is_empty()
        && parts[4] == "tokenFile"
        && value.as_str().is_some_and(|path| {
            Path::new(path).is_absolute()
                && path.len() <= 4096
                && !path.chars().any(char::is_control)
        })
}

impl RuntimeAdapter for OpenClaw {
    fn kind(&self) -> RuntimeKind {
        RuntimeKind::OpenClaw
    }
    fn version(&self) -> &'static str {
        "1"
    }
    fn endpoints(&self) -> &'static str {
        include_str!("openclaw/endpoints.toml")
    }
    fn installer(&self) -> Installer {
        Installer {
            url: INSTALLER_URL.into(),
            args: [
                "--prefix",
                "~/.local/share/openclaw",
                "--npm",
                "--runtime-only",
                "--no-onboard",
            ]
            .map(str::to_owned)
            .to_vec(),
        }
    }
    fn home_files(&self, _backend: BackendKind) -> Vec<HomeFile> {
        vec![
            HomeFile {
                path: "bin/openclaw",
                contents: include_str!("openclaw/command"),
                executable: true,
            },
            HomeFile {
                path: "bin/enclos-openclaw-agent",
                contents: include_str!("openclaw/agent"),
                executable: true,
            },
            HomeFile {
                path: "bin/enclos-openclaw-delete.mjs",
                contents: include_str!("openclaw/delete.mjs"),
                executable: false,
            },
            HomeFile {
                path: "bin/enclos-openclaw-enable-telegram",
                contents: include_str!("openclaw/enable-telegram"),
                executable: true,
            },
        ]
    }
    fn login(&self) -> String {
        "openclaw models auth login --provider openai --device-code".into()
    }
    fn create_agent(&self, name: &AgentName) -> SandboxCommand {
        SandboxCommand::from_words(&["enclos-openclaw-agent", "add", name.as_str()])
    }
    fn agent_delete_mode(&self) -> AgentDeleteMode {
        AgentDeleteMode::RuntimeService
    }
    fn delete_agent(&self, name: &AgentName) -> Option<SandboxCommand> {
        Some(SandboxCommand::from_words(&[
            "enclos-openclaw-agent",
            "delete",
            name.as_str(),
        ]))
    }
    fn agent_files(&self, name: &AgentName) -> String {
        format!("~/.openclaw/agents/{name}")
    }
    fn talk(&self, agent: &AgentName) -> String {
        format!("openclaw tui --session agent:{agent}:main")
    }
    fn agents_in(&self, home: &Path) -> Result<Vec<RuntimeAgentName>, Unreadable> {
        names(&config(home)?)
            .map_err(|why| unreadable("~/.openclaw/openclaw.json", NotRead::Io(why)))
    }
    fn default_agent(&self, home: &Path) -> Result<Option<RuntimeAgentName>, Unreadable> {
        let value = config(home)?;
        let agents = names(&value)
            .map_err(|why| unreadable("~/.openclaw/openclaw.json", NotRead::Io(why)))?;
        if let Some(id) = value
            .pointer("/agents/defaults/systemAgent/agentId")
            .and_then(Value::as_str)
        {
            return agents
                .into_iter()
                .find(|a| a.as_str() == id)
                .map(Some)
                .ok_or_else(|| {
                    unreadable(
                        "~/.openclaw/openclaw.json",
                        NotRead::Io("the designated System Agent is absent".into()),
                    )
                });
        }
        if agents.len() == 1 {
            return Ok(agents.into_iter().next());
        }
        if value.pointer("/agents/ownership").and_then(Value::as_str) != Some("explicit") {
            let defaults: Vec<&str> = if let Some(entries) =
                value.pointer("/agents/entries").and_then(Value::as_object)
            {
                entries
                    .iter()
                    .filter(|(_, entry)| {
                        entry.get("default").and_then(Value::as_bool) == Some(true)
                    })
                    .map(|(id, _)| id.as_str())
                    .collect()
            } else {
                value
                    .pointer("/agents/list")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter(|entry| entry.get("default").and_then(Value::as_bool) == Some(true))
                    .filter_map(|entry| entry.get("id").and_then(Value::as_str))
                    .collect()
            };
            if defaults.len() == 1 {
                return Ok(RuntimeAgentName::new(defaults[0]));
            }
        }
        Ok(None)
    }
    fn services(&self) -> Vec<RuntimeService> {
        vec![RuntimeService {
            name: GATEWAY,
            command: SandboxCommand::from_words(&["openclaw", "gateway", "run"]),
            restart: None,
        }]
    }
    fn listener(&self) -> Option<RuntimeListener> {
        // The authenticated dashboard needs a native one-use handoff, never
        // an unauthenticated URL invented by status. Use native dashboard.
        Some(RuntimeListener {
            service: GATEWAY,
            ports: ListenerPorts::SingleLoopback,
            page: None,
        })
    }
    fn secret_files(&self) -> Option<SecretFiles> {
        Some(SecretFiles {
            folder_variable: None,
            sandbox: SecretFileFormat::Json,
            agent: SecretFileFormat::Json,
        })
    }
    fn agent_settings_files(&self, _agent: &RuntimeAgentName) -> Vec<HomePath> {
        vec![at(CONFIG), at(".openclaw/.env")]
    }
    fn settings_files(&self, _agents: &[RuntimeAgentName]) -> Vec<HomePath> {
        // Native hot reload owns these settings; no competing signal watcher.
        Vec::new()
    }
    fn agent_secrets_source(
        &self,
        agent: &RuntimeAgentName,
        file: &Path,
    ) -> Option<Vec<SandboxCommand>> {
        let folder = file.parent()?;
        [
            ("enclos-sandbox".to_owned(), folder.join(".env")),
            (agent_provider(agent), file.to_owned()),
        ]
        .into_iter()
        .map(|(provider, path)| {
            let value = json!({"source":"file", "path":path.to_str()?, "mode":"json"}).to_string();
            Some(setting(&format!("secrets.providers.{provider}"), &value))
        })
        .collect()
    }
    fn reads_agent_secrets(&self, text: &str, file: &Path) -> bool {
        parse(text)
            .ok()
            .and_then(|v| {
                v.pointer("/secrets/providers")
                    .and_then(Value::as_object)
                    .map(|p| {
                        p.values().any(|v| {
                            v.get("source").and_then(Value::as_str) == Some("file")
                                && v.get("path").and_then(Value::as_str) == file.to_str()
                        })
                    })
            })
            .unwrap_or(false)
    }
    fn set_setting(
        &self,
        agent: &RuntimeAgentName,
        key: &str,
        value: &str,
    ) -> Option<SandboxCommand> {
        // Native config set accepts JSON5 at a parent path. Reject nested
        // credentials and authored refs too: only the typed grant-checked
        // setter below may introduce a SecretRef.
        fn unsafe_value(value: &Value, path: &str) -> bool {
            match value {
                Value::Object(map) => {
                    (map.get("source")
                        .and_then(Value::as_str)
                        .is_some_and(|source| matches!(source, "env" | "file" | "exec" | "store"))
                        && map.get("id").and_then(Value::as_str).is_some())
                        || map.iter().any(|(key, value)| {
                            let path = format!("{path}/{key}");
                            (names_a_secret(key)
                                && !credential_file_field(&path, value)
                                && !value.is_null()
                                && value.as_str() != Some(""))
                                || unsafe_value(value, &path)
                        })
                }
                Value::Array(values) => values
                    .iter()
                    .enumerate()
                    .any(|(i, value)| unsafe_value(value, &format!("{path}/{i}"))),
                _ => false,
            }
        }
        if value.contains("${") || value.len() > MAX_CONFIG as usize {
            return None;
        }
        let trimmed = value.trim();
        // Wrapping also handles leading/trailing JSON5 comments. Native set
        // falls back to raw text when JSON5 fails; a structured-looking value
        // that exceeds our observation grammar is refused, never guessed raw.
        match parse(&format!("{{setting:\n{trimmed}\n}}")) {
            Ok(parsed) if unsafe_value(&parsed["setting"], &key.replace('.', "/")) => return None,
            Err(_) if trimmed.contains(['{', '[']) => return None,
            _ => {}
        }
        if key == format!("channels.telegram.accounts.{agent}.enabled") && value == "true" {
            return Some(SandboxCommand::from_words(&[
                "enclos-openclaw-enable-telegram",
                agent.as_str(),
            ]));
        }
        if key == format!("channels.enclos.accounts.{agent}.enabled") && value == "true" {
            // The canonical native binder preserves unrelated route entries,
            // reports another agent's conflicting claim and stops on failure.
            // Account activation follows both binding and channel enablement.
            return Some(SandboxCommand::from_words(&[
                "sh",
                "-c",
                ENABLE_APP,
                "enclos-enable-app",
                agent.as_str(),
            ]));
        }
        Some(setting(key, value))
    }
    fn app_channel(
        &self,
        agent: &RuntimeAgentName,
        socket: &Path,
        token_file: &Path,
        home: &str,
        _bridge_key: &str,
    ) -> Option<AppChannel> {
        if !socket.is_absolute() || !token_file.is_absolute() {
            return None;
        }
        let plugin = at(APP_PLUGIN);
        let state = socket.parent()?.join("openclaw-state").join(agent.as_str());
        let account = json!({"enabled":false, "agentId":agent.as_str(), "socket":socket.to_str()?,
            "tokenFile":token_file.to_str()?, "home":home, "stateDir":state.to_str()?})
        .to_string();
        Some(AppChannel {
            // One package per sandbox; every account has its own socket,
            // protected JSON credential consumer and durable state directory.
            files: vec![
                (
                    plugin.child("package.json")?,
                    include_str!("../../channels/openclaw/package.json"),
                ),
                (
                    plugin.child("index.js")?,
                    include_str!("../../channels/openclaw/index.js"),
                ),
                (
                    plugin.child("channel.js")?,
                    include_str!("../../channels/openclaw/channel.js"),
                ),
                (
                    plugin.child("transport.js")?,
                    include_str!("../../channels/openclaw/transport.js"),
                ),
                (
                    plugin.child("protocol.js")?,
                    include_str!("../../channels/openclaw/protocol.js"),
                ),
                (
                    plugin.child("features.js")?,
                    include_str!("../../channels/openclaw/features.js"),
                ),
                (
                    plugin.child("media.js")?,
                    include_str!("../../channels/openclaw/media.js"),
                ),
                (
                    plugin.child("routines.js")?,
                    include_str!("../../channels/openclaw/routines.js"),
                ),
                (
                    plugin.child("native-titles.js")?,
                    include_str!("../../channels/openclaw/native-titles.js"),
                ),
                (
                    plugin.child("native-approvals.js")?,
                    include_str!("../../channels/openclaw/native-approvals.js"),
                ),
                (
                    plugin.child("native-turns.js")?,
                    include_str!("../../channels/openclaw/native-turns.js"),
                ),
                (
                    plugin.child("openclaw.plugin.json")?,
                    include_str!("../../channels/openclaw/openclaw.plugin.json"),
                ),
            ],
            // Native install/link merges registration with existing plugin
            // paths; this plan never replaces the shared load-path list.
            commands: vec![SandboxCommand::from_words(&["sh", "-c", INSTALL_APP])],
            settings: vec![
                (format!("channels.enclos.accounts.{agent}"), account),
                ("plugins.entries.enclos.enabled".into(), "true".into()),
                (
                    format!("channels.enclos.accounts.{agent}.enabled"),
                    "true".into(),
                ),
            ],
        })
    }
    fn set_secret_setting(
        &self,
        agent: &RuntimeAgentName,
        key: &str,
        variable: &str,
        target: SecretTarget,
    ) -> Option<SandboxCommand> {
        if !is_variable_name(variable) {
            return None;
        }
        let provider = match target {
            SecretTarget::Sandbox => "enclos-sandbox".into(),
            SecretTarget::Agent => agent_provider(agent),
        };
        Some(SandboxCommand::from_words(&[
            "openclaw",
            "config",
            "set",
            key,
            "--ref-source",
            "file",
            "--ref-provider",
            &provider,
            "--ref-id",
            &format!("/{variable}"),
        ]))
    }
    fn channel_settings(
        &self,
        agent: &RuntimeAgentName,
        channel: Channel,
        token: &str,
        answers: &[ChannelUser],
    ) -> Option<Vec<(String, String)>> {
        if channel != Channel::Telegram {
            return None;
        }
        let prefix = format!("channels.telegram.accounts.{agent}");
        Some(vec![
            (format!("{prefix}.enabled"), "false".into()),
            (
                format!("{prefix}.allowFrom"),
                serde_json::to_string(&answers.iter().map(ChannelUser::as_str).collect::<Vec<_>>())
                    .ok()?,
            ),
            (format!("{prefix}.dmPolicy"), "allowlist".into()),
            (format!("{prefix}.groupPolicy"), "disabled".into()),
            (format!("{prefix}.botToken"), format!("${{{token}}}")),
            (format!("{prefix}.enabled"), "true".into()),
        ])
    }
    fn channel_token_files(
        &self,
        channel: Channel,
        _agent: &RuntimeAgentName,
    ) -> Vec<(HomePath, &'static str)> {
        if channel == Channel::Telegram {
            vec![
                (at(CONFIG), "botToken"),
                (at(".openclaw/.env"), "TELEGRAM_BOT_TOKEN"),
            ]
        } else {
            Vec::new()
        }
    }
    fn channel_token_is_plain(
        &self,
        _channel: Channel,
        agent: &RuntimeAgentName,
        text: &str,
        field: &str,
    ) -> Result<bool, String> {
        if field == "TELEGRAM_BOT_TOKEN" {
            return Ok(text
                .lines()
                .filter_map(dotenv_line)
                .any(|(name, value)| name == field && !matches!(value, "" | "\"\"" | "''")));
        }
        let value = parse(text)?;
        let accounts = [
            value.pointer(&format!("/channels/telegram/accounts/{agent}")),
            value.pointer("/channels/telegram"),
        ];
        Ok(accounts.into_iter().flatten().any(|account| {
            account
                .get("botToken")
                .is_some_and(|v| !v.is_null() && v.as_str() != Some("") && !is_reference(v))
                || account
                    .get("tokenFile")
                    .and_then(Value::as_str)
                    .is_some_and(|s| !s.is_empty())
        }))
    }
    fn inspect_settings(&self, files: &[SettingsFile]) -> Result<Vec<SettingsFinding>, String> {
        fn walk(value: &Value, path: &str, file: &SettingsFile, out: &mut Vec<SettingsFinding>) {
            if out.len() >= 2048 {
                return;
            }
            if let Some(variable) = reference_variable(value, &file.agent) {
                if !file.granted.contains(&variable) && !reserved_variable(&variable) {
                    out.push(SettingsFinding::NotGranted {
                        agent: file.agent.clone(),
                        file: file.path.clone(),
                        line: 1,
                        variable,
                    });
                }
                return;
            }
            match value {
                Value::Object(map) => {
                    for (key, value) in map {
                        let path = format!("{path}/{key}");
                        if names_a_secret(key)
                            && !credential_file_field(&path, value)
                            && value.as_str().is_some_and(|s| !s.is_empty())
                        {
                            out.push(SettingsFinding::Plain {
                                agent: file.agent.clone(),
                                file: file.path.clone(),
                                line: 1,
                                held: Held::Key(path),
                            });
                        } else {
                            walk(value, &path, file, out);
                        }
                    }
                }
                Value::Array(values) => {
                    for (i, value) in values.iter().enumerate() {
                        walk(value, &format!("{path}/{i}"), file, out);
                    }
                }
                _ => {}
            }
        }
        let mut result = Vec::new();
        for file in files {
            if file.path.as_path() == Path::new(".openclaw/.env") {
                for (n, line) in file.text.lines().enumerate() {
                    if let Some((name, value)) = dotenv_line(line) {
                        let granted = file.granted.contains(name);
                        if (granted || names_a_secret(name)) && !matches!(value, "" | "\"\"" | "''")
                        {
                            result.push(SettingsFinding::Plain {
                                agent: file.agent.clone(),
                                file: file.path.clone(),
                                line: n + 1,
                                held: Held::Variable {
                                    name: name.to_owned(),
                                    granted,
                                },
                            });
                        }
                    }
                }
                continue;
            }
            let config = parse(&file.text)?;
            for key in ["gateway", "models", "env"] {
                if let Some(value) = config.get(key) {
                    walk(value, key, file, &mut result);
                }
            }
            if let Some(value) = config.pointer(&format!("/agents/entries/{}", file.agent)) {
                walk(value, "agents", file, &mut result);
            }
            if let Some(channels) = config.get("channels").and_then(Value::as_object) {
                for (name, channel) in channels {
                    if let Some(account) = channel.pointer(&format!("/accounts/{}", file.agent)) {
                        walk(
                            account,
                            &format!("channels/{name}/accounts/{}", file.agent),
                            file,
                            &mut result,
                        );
                    }
                    if let Some(fields) = channel.as_object() {
                        for (key, value) in
                            fields.iter().filter(|(key, _)| key.as_str() != "accounts")
                        {
                            walk(
                                &json!({(key):value}),
                                &format!("channels/{name}"),
                                file,
                                &mut result,
                            );
                        }
                    }
                }
            }
        }
        if result.len() >= 2048 {
            return Err("too many OpenClaw settings findings to report safely".into());
        }
        Ok(result)
    }
    fn disk_parts(&self) -> Vec<(DiskPart, HomePath)> {
        vec![
            (DiskPart::Runtime, at(".local/share/openclaw")),
            (DiskPart::Cache, at(".npm")),
        ]
    }
    fn runtime_facts(&self) -> RuntimeFacts {
        RuntimeFacts {
            install: Some(at(".local/share/openclaw/bin/openclaw")),
            ..RuntimeFacts::default()
        }
    }
    fn agent_facts(&self, agent: &RuntimeAgentName) -> AgentFacts {
        AgentFacts {
            model: Some(ValueAt {
                file: at(CONFIG),
                keys: vec![format!("agent:{agent}")],
            }),
            ..AgentFacts::default()
        }
    }
    fn fact_value(&self, at: &ValueAt, text: &str) -> Result<Option<String>, String> {
        let value = parse(text)?;
        for key in &at.keys {
            if let Some(agent) = key.strip_prefix("agent:") {
                let model = value
                    .pointer(&format!("/agents/entries/{agent}/model"))
                    .or_else(|| {
                        value
                            .pointer("/agents/list")
                            .and_then(Value::as_array)
                            .and_then(|entries| {
                                entries.iter().find(|entry| {
                                    entry.get("id").and_then(Value::as_str) == Some(agent)
                                })
                            })
                            .and_then(|entry| entry.get("model"))
                    })
                    .or_else(|| value.pointer("/agents/defaults/model"));
                if let Some(model) = model {
                    return model
                        .as_str()
                        .or_else(|| model.get("primary").and_then(Value::as_str))
                        .map(str::to_owned)
                        .map(Some)
                        .ok_or_else(|| {
                            "OpenClaw model is not a string or primary model object".into()
                        });
                }
            }
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn agent(name: &str) -> RuntimeAgentName {
        RuntimeAgentName::new(name).unwrap()
    }
    fn save(home: &Path, text: &str) {
        std::fs::create_dir_all(home.join(".openclaw")).unwrap();
        std::fs::write(home.join(CONFIG), text).unwrap();
    }

    #[test]
    fn native_roster_and_default_do_not_invent_an_immortal_main() {
        let home = tempfile::tempdir().unwrap();
        assert!(OpenClaw.builtin_agent().is_none());
        assert_eq!(OpenClaw.agents_in(home.path()).unwrap(), [agent("main")]);
        assert_eq!(
            OpenClaw.default_agent(home.path()).unwrap(),
            Some(agent("main"))
        );
        save(
            home.path(),
            "{ agents: { ownership:'explicit', entries:{scout:{},writer:{}}, defaults:{systemAgent:{agentId:'writer'}} }, }",
        );
        assert_eq!(
            OpenClaw.agents_in(home.path()).unwrap(),
            [agent("scout"), agent("writer")]
        );
        assert_eq!(
            OpenClaw.default_agent(home.path()).unwrap(),
            Some(agent("writer"))
        );
        save(
            home.path(),
            "{agents:{ownership:'explicit',entries:{scout:{},writer:{}}}}",
        );
        assert_eq!(OpenClaw.default_agent(home.path()).unwrap(), None);
        save(
            home.path(),
            "{agents:{ownership:'explicit',entries:{scout:{}}}}",
        );
        assert_eq!(
            OpenClaw.default_agent(home.path()).unwrap(),
            Some(agent("scout"))
        );
        save(
            home.path(),
            "{agents:{entries:{scout:{default:true},writer:{}}}}",
        );
        assert_eq!(
            OpenClaw.default_agent(home.path()).unwrap(),
            Some(agent("scout"))
        );
        save(
            home.path(),
            "{agents:{list:[{id:'scout',default:true},{id:'writer'}]}}",
        );
        assert_eq!(
            OpenClaw.default_agent(home.path()).unwrap(),
            Some(agent("scout"))
        );
    }

    #[test]
    fn observations_refuse_links_includes_large_or_deep_settings_without_echoing_values() {
        let home = tempfile::tempdir().unwrap();
        save(home.path(), "{apiKey:'SENSITIVE_EXAMPLE', broken:}");
        assert!(
            !OpenClaw
                .agents_in(home.path())
                .unwrap_err()
                .to_string()
                .contains("SENSITIVE_EXAMPLE")
        );
        save(home.path(), "{$include:'/host/secret.json'}");
        assert!(OpenClaw.agents_in(home.path()).is_err());
        save(home.path(), &" ".repeat(MAX_CONFIG as usize + 1));
        assert!(matches!(
            OpenClaw.agents_in(home.path()).unwrap_err().why,
            NotRead::TooLarge(_)
        ));
        std::fs::remove_file(home.path().join(CONFIG)).unwrap();
        let target = home.path().join("other.json");
        std::fs::write(&target, "{}").unwrap();
        std::os::unix::fs::symlink(target, home.path().join(CONFIG)).unwrap();
        assert_eq!(
            OpenClaw.agents_in(home.path()).unwrap_err().why,
            NotRead::Link
        );
        assert!(parse(&format!("{}0{}", "[".repeat(65), "]".repeat(65))).is_err());
        parse("{value: '[{', /* [[[ */ agents: { entries: { scout: {} } } }").unwrap();
    }

    #[test]
    fn secret_consumers_keep_grant_ownership_and_never_place_values_in_commands() {
        let a = agent("scout");
        let file = Path::new("/private/host/secrets/scout.env");
        let plan = OpenClaw.agent_secrets_source(&a, file).unwrap();
        assert_eq!(plan.len(), 2);
        assert!(plan[0].shown().contains("/private/host/secrets/.env"));
        assert!(plan[1].shown().contains("/private/host/secrets/scout.env"));
        let shared = OpenClaw
            .set_secret_setting(
                &a,
                "models.providers.example.apiKey",
                "API_KEY",
                SecretTarget::Sandbox,
            )
            .unwrap()
            .shown();
        let own = OpenClaw
            .set_secret_setting(
                &a,
                "channels.telegram.accounts.scout.botToken",
                "BOT_TOKEN",
                SecretTarget::Agent,
            )
            .unwrap()
            .shown();
        assert!(shared.contains("--ref-provider enclos-sandbox"));
        assert!(own.contains(&agent_provider(&a)));
        assert!(
            OpenClaw
                .set_setting(&a, "apiKey", "prefix-${API_KEY}")
                .is_none()
        );
        assert_eq!(OpenClaw.secret_files().unwrap().folder_variable, None);
        assert!(
            OpenClaw
                .import_agent(&"scout".parse().unwrap(), Path::new("/tmp/export.tgz"))
                .is_none()
        );
    }

    #[test]
    fn parent_json5_settings_cannot_smuggle_literal_credentials_or_unchecked_refs() {
        let a = agent("scout");
        for value in [
            "{auth:{mode:'token',token:'SENSITIVE_EXAMPLE'}}",
            "/* JSON5 prefix */ {auth:{token:'SENSITIVE_EXAMPLE'}} // suffix",
            "{accounts:{scout:{botToken:'SENSITIVE_EXAMPLE'}}}",
            "[{apiKey:'SENSITIVE_EXAMPLE'}]",
            "{anything:{source:'file',provider:'enclos-sandbox',id:'/UNGRANTED'}}",
            "{anything:{source:'env',provider:'default',id:'UNGRANTED'}}",
            "{anything:{source:'env',id:'UNGRANTED'}}",
            "{$include:'elsewhere.json'}",
        ] {
            assert!(OpenClaw.set_setting(&a, "gateway", value).is_none());
        }
        assert!(
            OpenClaw
                .set_setting(
                    &a,
                    "models",
                    "{provider:{baseUrl:'https://example.test'}, max_tokens:123}"
                )
                .is_some()
        );
        assert!(
            OpenClaw
                .set_setting(&a, "gateway", "{auth:{token:null}}")
                .is_some()
        );
    }

    #[test]
    fn the_enclos_channel_credential_file_is_a_path_not_a_plaintext_token() {
        let a = agent("scout");
        let file = "/private/enclos/secrets/scout.env";
        let account = json!({"agentId":"scout", "tokenFile":file}).to_string();
        assert!(
            OpenClaw
                .set_setting(&a, "channels.enclos.accounts.scout", &account)
                .is_some()
        );
        for value in [
            "{tokenFile:'SENSITIVE_EXAMPLE'}",
            "{botToken:'/private/file'}",
            "{tokenFile:{source:'file',id:'/UNGRANTED'}}",
        ] {
            assert!(
                OpenClaw
                    .set_setting(&a, "channels.enclos.accounts.scout", value)
                    .is_none()
            );
        }
        assert!(OpenClaw.set_setting(&a, "gateway", &account).is_none());
        let text = json!({"channels":{"enclos":{"accounts":{"scout":{"agentId":"scout", "tokenFile":file}}}}}).to_string();
        let findings = OpenClaw
            .inspect_settings(&[SettingsFile {
                agent: a,
                path: at(CONFIG),
                text,
                granted: Default::default(),
            }])
            .unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn app_accounts_share_one_package_and_keep_explicit_credentials_and_state_separate() {
        let first = agent("main");
        let second = agent("scout");
        let socket = Path::new("/sandbox/home/.enclos-app/main.sock");
        // Deliberately unrelated to the socket's ancestors: the adapter must
        // consume the path supplied by the core rather than infer its layout.
        let token = Path::new("/protected/another-layout/main.env");
        let app = OpenClaw
            .app_channel(&first, socket, token, "home.lab.main", "key")
            .unwrap();
        let other = OpenClaw
            .app_channel(
                &second,
                Path::new("/sandbox/home/.enclos-app/scout.sock"),
                Path::new("/protected/another-layout/scout.env"),
                "home.lab.scout",
                "key",
            )
            .unwrap();
        assert_eq!(app.files, other.files);
        let package: Value = serde_json::from_str(
            app.files
                .iter()
                .find(|(path, _)| path.as_path().ends_with("package.json"))
                .unwrap()
                .1,
        )
        .unwrap();
        let mut declared: std::collections::BTreeSet<_> = package["files"]
            .as_array()
            .unwrap()
            .iter()
            .map(|file| Path::new(APP_PLUGIN).join(file.as_str().unwrap()))
            .collect();
        declared.insert(Path::new(APP_PLUGIN).join("package.json"));
        let embedded = app
            .files
            .iter()
            .map(|(path, _)| path.as_path().to_path_buf())
            .collect();
        assert_eq!(declared, embedded);
        assert!(
            app.files
                .iter()
                .all(|(path, text)| path.as_path().starts_with(APP_PLUGIN) && !text.is_empty())
        );
        let account: Value = serde_json::from_str(&app.settings[0].1).unwrap();
        let other_account: Value = serde_json::from_str(&other.settings[0].1).unwrap();
        assert_eq!(account["tokenFile"], token.to_str().unwrap());
        assert_eq!(account["socket"], socket.to_str().unwrap());
        assert_eq!(account["agentId"], "main");
        assert_eq!(account["home"], "home.lab.main");
        assert_eq!(account["enabled"], false);
        assert_ne!(account["stateDir"], other_account["stateDir"]);
        assert!(!app.settings[0].1.contains("MOBILE_APP_TOKEN"));
        assert!(
            app.settings
                .iter()
                .all(|(key, value)| OpenClaw.set_setting(&first, key, value).is_some())
        );
        let install = app.commands[0].shown();
        assert!(install.contains("plugins install --link"));
        assert!(install.contains("--no-enable --accept-capabilities"));
        assert!(
            !app.settings
                .iter()
                .any(|(key, _)| key == "bindings" || key == "plugins.load.paths")
        );
        assert_eq!(
            app.settings.last().unwrap(),
            &(
                "channels.enclos.accounts.main.enabled".into(),
                "true".into()
            )
        );
        let activate = OpenClaw
            .set_setting(&first, &app.settings.last().unwrap().0, "true")
            .unwrap()
            .shown();
        assert!(activate.contains("agents bind --agent"));
        assert!(activate.contains("enclos:$agent"));
        assert!(
            ENABLE_APP.find("agents bind").unwrap()
                < ENABLE_APP.find("channels.enclos.enabled true").unwrap()
        );
        assert!(ENABLE_APP.ends_with("\"channels.enclos.accounts.$agent.enabled\" true"));
        assert!(
            OpenClaw
                .app_channel(
                    &first,
                    Path::new("relative.sock"),
                    token,
                    "home.lab.main",
                    "key"
                )
                .is_none()
        );
    }

    #[test]
    fn telegram_is_agent_bound_with_access_before_token_and_activation_last() {
        let a = agent("scout");
        let users = ["123456".parse().unwrap()];
        let plan = OpenClaw
            .channel_settings(&a, Channel::Telegram, "BOT_TOKEN", &users)
            .unwrap();
        assert_eq!(
            plan.first().unwrap(),
            &(
                "channels.telegram.accounts.scout.enabled".into(),
                "false".into()
            )
        );
        assert!(
            plan.iter()
                .position(|(k, _)| k.ends_with("allowFrom"))
                .unwrap()
                < plan
                    .iter()
                    .position(|(k, _)| k.ends_with("botToken"))
                    .unwrap()
        );
        assert_eq!(
            plan.last().unwrap(),
            &(
                "channels.telegram.accounts.scout.enabled".into(),
                "true".into()
            )
        );
        assert_eq!(
            OpenClaw
                .set_setting(&a, &plan.last().unwrap().0, "true")
                .unwrap()
                .shown(),
            "enclos-openclaw-enable-telegram scout"
        );
        assert!(
            OpenClaw
                .channel_token_is_plain(
                    Channel::Telegram,
                    &a,
                    "{channels:{telegram:{accounts:{scout:{botToken:'literal'}}}}}",
                    "botToken"
                )
                .unwrap()
        );
        let config = json!({"channels":{"telegram":{"accounts":{"scout":{"botToken":{"source":"file","provider":agent_provider(&a),"id":"/BOT_TOKEN"}}}}}}).to_string();
        assert!(
            !OpenClaw
                .channel_token_is_plain(Channel::Telegram, &a, &config, "botToken")
                .unwrap()
        );
        assert!(
            OpenClaw
                .channel_token_is_plain(
                    Channel::Telegram,
                    &a,
                    "TELEGRAM_BOT_TOKEN='literal'\n",
                    "TELEGRAM_BOT_TOKEN"
                )
                .unwrap()
        );
        assert_eq!(OpenClaw.channel_token_files(Channel::Telegram, &a).len(), 2);
    }

    #[test]
    fn diagnostics_keep_only_locations_and_do_not_claim_other_agents_accounts() {
        let a = agent("scout");
        let file = SettingsFile { agent:a.clone(), path:at(CONFIG), granted:["BOT_TOKEN".to_owned()].into_iter().collect(), text:json!({"channels":{"telegram":{"accounts":{"scout":{"botToken":{"source":"file","provider":agent_provider(&a),"id":"/BOT_TOKEN"}},"writer":{"botToken":"OTHER_LITERAL"}}}}}).to_string() };
        assert!(OpenClaw.inspect_settings(&[file]).unwrap().is_empty());
        let file = SettingsFile {
            agent: a,
            path: at(CONFIG),
            granted: Default::default(),
            text: "{channels:{telegram:{accounts:{scout:{botToken:'DO_NOT_RETURN'}}}}}".into(),
        };
        let findings = OpenClaw.inspect_settings(&[file]).unwrap();
        assert_eq!(findings.len(), 1);
        assert!(!format!("{findings:?}").contains("DO_NOT_RETURN"));
        let env = SettingsFile {
            agent: agent("scout"),
            path: at(".openclaw/.env"),
            granted: Default::default(),
            text: "API_KEY=NOT_RETURNED_EITHER\n".into(),
        };
        let findings = OpenClaw.inspect_settings(&[env]).unwrap();
        assert!(
            matches!(&findings[..], [SettingsFinding::Plain { held:Held::Variable { name, .. }, .. }] if name == "API_KEY")
        );
        assert!(!format!("{findings:?}").contains("NOT_RETURNED_EITHER"));
    }

    #[test]
    fn wrapper_selects_only_private_state_and_a_disjoint_positive_gateway_port() {
        use std::os::unix::fs::PermissionsExt;
        let home = tempfile::tempdir().unwrap();
        let native = home.path().join(".local/share/openclaw/bin/openclaw");
        std::fs::create_dir_all(native.parent().unwrap()).unwrap();
        std::fs::write(&native, "#!/bin/sh\nprintf '%s\\n' \"$OPENCLAW_HOME\" \"$OPENCLAW_STATE_DIR\" \"$OPENCLAW_CONFIG_PATH\" \"$OPENCLAW_SUPERVISOR_MODE\" \"$OPENCLAW_GATEWAY_PORT\" \"$@\"\n").unwrap();
        std::fs::set_permissions(&native, std::fs::Permissions::from_mode(0o700)).unwrap();
        let out = std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg(include_str!("openclaw/command"))
            .arg("openclaw")
            .args(["gateway", "run"])
            .env_clear()
            .env("HOME", home.path())
            .env("HTTP_PROXY", "http://127.0.0.1:41007")
            .output()
            .unwrap();
        assert!(out.status.success());
        let stdout = String::from_utf8(out.stdout).unwrap();
        assert!(stdout.contains(&home.path().join(".openclaw").display().to_string()));
        assert!(
            stdout.contains("external\n43007\ngateway\nrun\n--bind\nloopback\n--port\n43007\n")
        );
    }
}
