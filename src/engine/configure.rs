//! The engine's runtime settings call (design §12): `runtime configure`
//! sets an agent up with the runtime's own commands. It points the agent's
//! secrets at the file `enclos launch` writes its grants to (ADR 0036), sets
//! the settings asked for, a secret named only as `${VAR}`, which the policy
//! grants, and sets up a channel's bot from the same settings.

use super::Engine;
use crate::error::{Error, Result};
use crate::model::agent::AgentName;
use crate::model::audit::Actor;
use crate::model::channel::{Channel, ChannelUser};
use crate::model::plan::{Confirm, Plan, Planned};
use crate::model::policy::Policy;
use crate::model::sandbox::SandboxName;
use crate::model::secret::{is_variable_name, reserved_variable};
use crate::proxy::decide::{Destination, allowed};
use crate::runtime::settings::names_a_secret;
use crate::runtime::{RuntimeAgentName, SandboxCommand, SecretTarget, adapter};
use std::path::PathBuf;

/// One setting `runtime configure` gives an agent, written `KEY=VALUE`: a
/// secret appears in the value only as `${VAR}`, which the agent reads from
/// its secrets, never as the secret itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Setting {
    pub key: String,
    pub value: String,
}

impl std::str::FromStr for Setting {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let (key, value) = s.split_once('=').ok_or_else(|| {
            format!("`{s}`: write KEY=VALUE, a secret as `${{VAR}}`, such as `platforms.discord.token=${{DISCORD_BOT_TOKEN}}`")
        })?;
        let key = key.trim();
        if key.is_empty() || key.chars().any(|c| c.is_whitespace() || c.is_control()) {
            return Err(format!("`{key}` is not a setting's name"));
        }
        if value.contains(['\n', '\r']) {
            return Err(format!("{key}: a value cannot hold a line break"));
        }
        Ok(Setting {
            key: key.to_owned(),
            value: value.to_owned(),
        })
    }
}

/// A channel's bot, set up from the settings the runtime names for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelRequest {
    pub channel: Channel,
    /// The variable its token is read from; the channel's usual one when
    /// `None`.
    pub token: Option<String>,
    /// The people it answers.
    pub answers: Vec<ChannelUser>,
}

/// What `runtime configure` did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Configured {
    /// The agent set up.
    pub agent: RuntimeAgentName,
    /// The settings set, by name, in order, those of a channel included.
    pub settings: Vec<String>,
    /// The bot set up, if one was asked for.
    pub channel: Option<ChannelSet>,
}

/// The channel `runtime configure --channel` set up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChannelSet {
    /// A messaging service's bot.
    Bot {
        channel: Channel,
        /// The variable the bot's token is read from.
        token: String,
        /// The people it answers, each once.
        answers: Vec<ChannelUser>,
        /// Whether the active policy lets the sandbox reach the channel's
        /// host.
        reachable: bool,
    },
    /// The mobile app's channel (ADR 0042, proposed), which answers whom
    /// the bridge lets in.
    App {
        /// The variable the agent's token is read from.
        token: String,
        /// Its socket, in the sandbox home, which the bridge connects to.
        socket: PathBuf,
    },
}

impl Engine {
    /// Sets `agent` up with the runtime's own commands, the runtime's
    /// built-in agent when `None`: its secrets read from the file `enclos
    /// launch` writes what the policy grants it to (ADR 0036), then each of
    /// `settings`, then, with `channel`, that channel's bot. A secret in a
    /// value is a `${VAR}` the active policy grants the agent, or the whole
    /// sandbox; one written as itself is refused where its setting's name
    /// says it is one. A running service restarts on its own once its
    /// settings change (ADR 0031).
    pub fn configure_agent(
        &self,
        by: &Actor,
        name: &SandboxName,
        agent: Option<&AgentName>,
        channel: Option<ChannelRequest>,
        settings: &[Setting],
        confirm: Confirm,
    ) -> Result<Planned<Configured>> {
        let kind = self.runtime_of(name)?;
        let runtime = adapter(kind);
        let shown = kind.display_name();
        let session = |what: String| Error::Session { what };
        let default = self.default_agent(name)?;
        let agent = match agent {
            Some(a) if default.as_ref().is_some_and(|b| b.as_str() == a.as_str()) => {
                RuntimeAgentName::from(a)
            }
            Some(a) => {
                if !self.agents(name)?.iter().any(|r| r.name == *a) {
                    return Err(session(format!(
                        "sandbox {name} has no agent {a} that enclos tracks: add it with `enclos agent add {name}/{a}` first"
                    )));
                }
                RuntimeAgentName::from(a)
            }
            None => match default {
                Some(b) => b,
                None => {
                    return Err(session(format!(
                        "{shown} has no selected default agent: name the agent to set up, as `{name}/<agent>`"
                    )));
                }
            },
        };
        let secrets_file = self
            .layout
            .agent_secrets_file(name.as_str(), agent.as_str());
        let source = runtime.agent_secrets_source(&agent, &secrets_file);
        let view = self.policy(name)?;
        let policy = &view.snapshot.policy;
        let mut commands = match source {
            Some(commands) => commands,
            None if policy
                .agent_secrets
                .get(agent.as_str())
                .is_some_and(|grants| !grants.is_empty()) =>
            {
                return Err(session(format!(
                    "{shown} cannot set up the protected secrets granted to agent {agent}, so enclos changes none of its settings"
                )));
            }
            None => Vec::new(),
        };
        let pending = view.pending.as_ref().map(|(_, p)| &p.policy);
        let set = |key: &str, value: &str| {
            let variable = value
                .strip_prefix("${")
                .and_then(|v| v.strip_suffix('}'))
                .filter(|v| is_variable_name(v));
            let command = match variable {
                Some(variable) => {
                    let target = if policy
                        .agent_secrets
                        .get(agent.as_str())
                        .is_some_and(|g| g.contains_key(variable))
                    {
                        SecretTarget::Agent
                    } else {
                        SecretTarget::Sandbox
                    };
                    runtime.set_secret_setting(&agent, key, variable, target)
                }
                None => runtime.set_setting(&agent, key, value),
            };
            command.ok_or_else(|| {
                session(format!(
                    "{shown} has no command that sets a setting, so enclos sets none"
                ))
            })
        };
        let mut keys = Vec::new();
        let mut staged = Vec::new();
        for setting in settings {
            self.check_setting(name, &agent, setting, policy, pending)?;
            commands.push(set(&setting.key, &setting.value)?);
            keys.push(setting.key.clone());
        }
        let channel = match channel {
            None => None,
            Some(request) if request.channel == Channel::App => {
                let plan = self.app_channel(name, &agent, &request, policy, pending, confirm)?;
                commands.extend(plan.commands);
                for (key, value) in &plan.settings {
                    commands.push(set(key, value)?);
                    keys.push(key.clone());
                }
                staged = plan.staged;
                Some(plan.set)
            }
            Some(request) => {
                let (bot, settings) =
                    self.channel_settings(name, &agent, request, &view.snapshot.policy, pending)?;
                for (key, value) in &settings {
                    commands.push(set(key, value)?);
                    keys.push(key.clone());
                }
                Some(bot)
            }
        };
        let done = Configured {
            agent: agent.clone(),
            settings: keys,
            channel,
        };
        if confirm == Confirm::DryRun {
            let mut changes: Vec<String> = commands
                .iter()
                .map(|c| {
                    format!(
                        "run `{}` in sandbox {name} under policy v{}",
                        c.shown(),
                        view.version.version
                    )
                })
                .collect();
            if let Some(ChannelSet::Bot {
                channel,
                reachable: false,
                ..
            }) = &done.channel
            {
                changes.push(unreachable(name, *channel));
            }
            return Ok(Planned::DryRun(Plan {
                changes,
                ..Plan::default()
            }));
        }
        let ran = self.run_all(by, name, commands);
        // The staged plugin is the binary's own, and the sandbox may not
        // write `installers/`: one left there when its removal fails does
        // no harm, so that failure does not undo what ran.
        for path in staged {
            let _ = std::fs::remove_file(path);
        }
        ran?;
        Ok(Planned::Done(done))
    }

    /// Refuses `setting` where it would put a secret in the agent's files:
    /// a `${VAR}` the policy in force grants neither the agent nor the whole
    /// sandbox (one the pending policy grants waits for `policy apply`), or
    /// a value holding no `${…}` where the setting's name says it is a
    /// secret (a guess from the name: TOKEN, SECRET, PASSWORD, KEY).
    fn check_setting(
        &self,
        name: &SandboxName,
        agent: &RuntimeAgentName,
        setting: &Setting,
        policy: &Policy,
        pending: Option<&Policy>,
    ) -> Result<()> {
        let session = |what: String| Error::Session { what };
        let key = &setting.key;
        let variables = referenced(&setting.value);
        if variables.is_empty() && names_a_secret(key) {
            return Err(session(format!(
                "{key} looks like a secret, and its value names none: store the secret with `enclos secret set {name}/<name>`, grant it to the agent under [secrets.agents.{agent}] with `enclos policy edit {name}`, and set `{key}=${{VAR}}`, so the value never sits in the agent's files"
            )));
        }
        let gives = |p: &Policy, v: &str| {
            p.secrets.contains_key(v)
                || p.agent_secrets
                    .get(agent.as_str())
                    .is_some_and(|g| g.contains_key(v))
        };
        for variable in variables {
            if gives(policy, variable) {
                continue;
            }
            return Err(session(match pending.is_some_and(|p| gives(p, variable)) {
                true => format!(
                    "{key}: the pending policy of sandbox {name} grants ${variable}, but it is not in force yet: `enclos policy apply {name}` first"
                ),
                false => format!(
                    "{key}: the policy of sandbox {name} grants agent {agent} no ${variable}: grant it under [secrets.agents.{agent}] with `enclos policy edit {name}` first"
                ),
            }));
        }
        Ok(())
    }

    /// The settings that set up `request`'s bot for `agent`, with what is
    /// refused first: a token variable enclos sets itself, no one to
    /// answer, a token the runtime's own setup left in plain text in the
    /// home, a token granted to the whole sandbox, or not to the agent, and
    /// the channel's usual variable granted beside another one, which the
    /// runtime would read first.
    fn channel_settings(
        &self,
        name: &SandboxName,
        agent: &RuntimeAgentName,
        request: ChannelRequest,
        policy: &Policy,
        pending: Option<&Policy>,
    ) -> Result<(ChannelSet, Vec<(String, String)>)> {
        let kind = self.runtime_of(name)?;
        let runtime = adapter(kind);
        let shown = kind.display_name();
        let session = |what: String| Error::Session { what };
        let ChannelRequest {
            channel,
            token,
            answers,
        } = request;
        let token = token.unwrap_or_else(|| channel.token_variable().to_owned());
        if !is_variable_name(&token) || reserved_variable(&token) {
            return Err(session(format!(
                "`{token}` cannot hold the bot's token: name a variable of letters, digits and `_`, not starting with a digit, that enclos neither sets nor passes on itself, as a policy's [secrets] does"
            )));
        }
        let mut answers = answers;
        answers.sort();
        answers.dedup();
        if answers.is_empty() {
            return Err(session(
                "name who the bot answers with `--allow-user <id>`: enclos sets up no bot that answers anyone".to_owned(),
            ));
        }
        let Some(settings) = runtime.channel_settings(agent, channel, &token, &answers) else {
            return Err(session(format!(
                "{shown} has no {} channel enclos can set up",
                channel.display_name()
            )));
        };
        // A token the runtime's own setup wrote in plain text in the home,
        // which any agent there reads: refused until it is removed.
        for (file, variable) in runtime.channel_token_files(channel, agent) {
            let home = self.layout.sandbox_home(name.as_str());
            let text = crate::runtime::home::read_text(&home, &file, 1 << 20).map_err(|e| {
                session(format!("cannot look for a plain bot token in {file}: {e}"))
            })?;
            let plain = match text {
                Some(text) => runtime
                    .channel_token_is_plain(channel, agent, &text, variable)
                    .map_err(|why| {
                        session(format!("cannot inspect a plain bot token in {file}: {why}"))
                    })?,
                None => false,
            };
            if plain {
                return Err(session(format!(
                    "{file} in sandbox {name} holds {variable} in plain text, as {shown}'s own setup writes it, where every agent of the sandbox reads it: remove that value ({}), then run `enclos runtime configure` again, which gives the token from the secret store",
                    home.join(file.as_path()).display()
                )));
            }
        }
        let section = format!("[secrets.agents.{agent}]");
        // Granted to the whole sandbox, the token would reach every agent,
        // and win over each one's own (ADR 0036).
        if policy.secrets.contains_key(&token) {
            return Err(session(format!(
                "the policy of sandbox {name} gives ${token} to the whole sandbox, under [secrets], which every agent receives and which wins over an agent's own: with `enclos policy edit {name}`, move it to {section} (ADR 0036)"
            )));
        }
        let granted = |p: &Policy, variable: &str| {
            p.agent_secrets
                .get(agent.as_str())
                .is_some_and(|g| g.contains_key(variable))
        };
        if !granted(policy, &token) {
            let builtin = runtime.builtin_agent();
            let secret = match agent.as_str() == builtin.map(|b| b.as_str()).unwrap_or_default() {
                true => format!("{name}/{channel}"),
                false => format!("{name}/{agent}-{channel}"),
            };
            return Err(session(match pending.is_some_and(|p| granted(p, &token)) {
                true => format!(
                    "the pending policy of sandbox {name} gives agent {agent} ${token}, the bot's token, but it is not in force yet: `enclos policy apply {name}` first"
                ),
                false => format!(
                    "the policy of sandbox {name} gives agent {agent} no ${token}, the bot's token: store the token with `enclos secret set {secret}`, then with `enclos policy edit {name}` add `{token} = \"secret:{secret}\"` to the `env` of its {section} section"
                ),
            }));
        }
        // The channel's usual variable, granted too, is the one the runtime
        // reads first: the bot would be that token's, not `token`'s.
        let usual = channel.token_variable();
        if token != usual && (granted(policy, usual) || policy.secrets.contains_key(usual)) {
            return Err(session(format!(
                "the policy of sandbox {name} also gives agent {agent} ${usual}, which {shown} reads for the bot before ${token}, so the bot would be the one ${usual} names: take ${usual} out of its {section}, or set the bot up with it (no --token-env)"
            )));
        }
        let reachable = channel.host().is_none_or(|host| {
            Destination::parse(host, 443).is_ok_and(|dest| allowed(policy, &dest))
        });
        Ok((
            ChannelSet::Bot {
                channel,
                token,
                answers,
                reachable,
            },
            settings,
        ))
    }

    /// What sets up the mobile app's channel for `agent` (ADR 0042,
    /// proposed): the runtime's plugin copied into the sandbox home from
    /// `installers/`, the runtime's commands that turn it on, and the
    /// settings that give it its socket. Refused first: people to answer
    /// or a token variable of another name, which the bridge decides
    /// instead, a runtime with no such channel, the agent's token,
    /// `MOBILE_APP_TOKEN`, not granted to the agent alone, and a socket
    /// path too long for a Unix socket.
    fn app_channel(
        &self,
        name: &SandboxName,
        agent: &RuntimeAgentName,
        request: &ChannelRequest,
        policy: &Policy,
        pending: Option<&Policy>,
        confirm: Confirm,
    ) -> Result<AppChannelPlan> {
        let session = |what: String| Error::Session { what };
        // The plugin answers whoever the bridge lets in, and the bridge
        // presents the agent's token under one name: an `--allow-user` or
        // a `--token-env` would be ignored, so both are refused.
        if !request.answers.is_empty() {
            return Err(session(
                "`--allow-user` does not apply to the app channel: enclos's bridge decides who talks to the agent, the people whose devices are paired with it".to_owned(),
            ));
        }
        if request.token.is_some() {
            return Err(session(format!(
                "`--token-env` does not apply to the app channel: its token is always ${}, the one the bridge presents to the agent",
                Channel::App.token_variable()
            )));
        }
        let kind = self.runtime_of(name)?;
        let runtime = adapter(kind);
        let shown = kind.display_name();
        let token = Channel::App.token_variable();
        let section = format!("[secrets.agents.{agent}]");
        let granted = |p: &Policy| {
            p.agent_secrets
                .get(agent.as_str())
                .is_some_and(|g| g.contains_key(token))
        };
        if policy.secrets.contains_key(token) {
            return Err(session(format!(
                "the policy of sandbox {name} gives ${token} to the whole sandbox, under [secrets], which every agent receives: with `enclos policy edit {name}`, move it to {section}, so each agent has a token of its own"
            )));
        }
        if !granted(policy) {
            let secret = format!("{name}/{agent}-app");
            return Err(session(match pending.is_some_and(granted) {
                true => format!(
                    "the pending policy of sandbox {name} gives agent {agent} ${token}, but it is not in force yet: `enclos policy apply {name}` first"
                ),
                false => format!(
                    "the policy of sandbox {name} gives agent {agent} no ${token}, the token the bridge presents to its app channel: store a new random one with `openssl rand -hex 32 | enclos secret set {secret}`, then with `enclos policy edit {name}` add `{token} = \"secret:{secret}\"` to the `env` of its {section} section"
                ),
            }));
        }
        let socket = self.layout.agent_app_socket(name.as_str(), agent.as_str());
        // A Unix socket's path holds at most 104 bytes on macOS (108 on
        // Linux), its last one a NUL.
        if socket.as_os_str().len() > 103 {
            return Err(session(format!(
                "the app channel's socket, {}, is longer than a Unix socket's path may be (103 bytes): set ENCLOS_HOME to a shorter folder",
                socket.display()
            )));
        }
        // The agent's Home conversation, as the bridge names it (ADR 0044).
        let home = crate::bridge::store::home_id(&format!("{name}/{agent}"));
        let token_file = self
            .layout
            .agent_secrets_file(name.as_str(), agent.as_str());
        let Some(app) = runtime.app_channel(agent, &socket, &token_file, &home) else {
            return Err(session(format!(
                "{shown} has no app channel enclos can set up"
            )));
        };
        // A dry run writes nothing, staged files included: it names them.
        let (copy, staged) = match confirm {
            Confirm::DryRun => {
                let mut words = vec!["cp".to_owned()];
                words.extend(
                    app.files
                        .iter()
                        .map(|(place, _)| format!("~/{}", place.as_path().display())),
                );
                let words = words.into_iter().map(Into::into).collect();
                (SandboxCommand::new(words), Vec::new())
            }
            _ => self.stage_home_copy(name, &app.files, &format!("app-{agent}"))?,
        };
        let mut commands = vec![copy];
        commands.extend(app.commands);
        Ok(AppChannelPlan {
            set: ChannelSet::App {
                token: token.to_owned(),
                socket,
            },
            commands,
            settings: app.settings,
            staged,
        })
    }

    /// Runs `commands` in the sandbox in order; one that fails stops the
    /// rest, and its error names those that ran before it.
    fn run_all(&self, by: &Actor, name: &SandboxName, commands: Vec<SandboxCommand>) -> Result<()> {
        let mut ran: Vec<String> = Vec::new();
        for command in commands {
            let this = command.shown();
            let end = self.run_in_sandbox(by, name, command, "runtime configure");
            let failed = match end {
                Ok(end) if end.exit == 0 => None,
                Ok(end) => Some(Error::Session {
                    what: format!(
                        "`{this}` exited with {} in sandbox {name}: its output above says why. Run `enclos runtime configure` again once it is fixed",
                        end.exit
                    ),
                }),
                Err(error) => Some(error),
            };
            if let Some(error) = failed {
                return Err(match ran.is_empty() {
                    true => error,
                    false => Error::FailedAfter {
                        error: Box::new(error),
                        done: format!("running {} in sandbox {name}", ran.join(", ")),
                    },
                });
            }
            ran.push(format!("`{this}`"));
        }
        Ok(())
    }
}

/// The variables `value` names as `${VAR}`.
fn referenced(value: &str) -> Vec<&str> {
    let mut found = Vec::new();
    let mut rest = value;
    while let Some(start) = rest.find("${") {
        let after = &rest[start + 2..];
        match after.find('}') {
            Some(end) => {
                found.push(&after[..end]);
                rest = &after[end + 1..];
            }
            None => break,
        }
    }
    found
}

/// What sets up an app channel.
struct AppChannelPlan {
    /// What `runtime configure` reports.
    set: ChannelSet,
    /// The commands that put the plugin in place and turn it on.
    commands: Vec<SandboxCommand>,
    /// Its settings, set after `commands`.
    settings: Vec<(String, String)>,
    /// The plugin's files staged in `installers/`, removed once the
    /// commands have run.
    staged: Vec<PathBuf>,
}

/// What a dry run says of a channel whose host the policy does not reach.
fn unreachable(name: &SandboxName, channel: Channel) -> String {
    format!(
        "find that the policy does not let the bot reach {host}: allow it with `enclos policy allow {name} {host}`",
        host = channel.host().unwrap_or_default()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_setting_is_key_equals_value_and_its_secrets_are_variables() {
        let s: Setting = "platforms.discord.token=${DISCORD_BOT_TOKEN}"
            .parse()
            .unwrap();
        assert_eq!(
            (s.key.as_str(), s.value.as_str()),
            ("platforms.discord.token", "${DISCORD_BOT_TOKEN}")
        );
        assert_eq!(referenced(&s.value), ["DISCORD_BOT_TOKEN"]);
        // `=` in the value is kept; a line break or no `=` is refused.
        let s: Setting = "a.b=x=y".parse().unwrap();
        assert_eq!(s.value, "x=y");
        assert!("no-equals".parse::<Setting>().is_err());
        assert!("a=b\nc".parse::<Setting>().is_err());
        assert!(" =b".parse::<Setting>().is_err());
        assert_eq!(referenced("${A}-${B} ${C"), ["A", "B"]);
        for secret in [
            "platforms.discord.token",
            "OPENAI_API_KEY",
            "x.password",
            "key",
        ] {
            assert!(names_a_secret(secret), "{secret}");
        }
        for plain in [
            "DISCORD_ALLOWED_USERS",
            "model.default",
            "model.max_tokens",
            "keyboard",
            "monkey",
        ] {
            assert!(!names_a_secret(plain), "{plain}");
        }
    }
}
