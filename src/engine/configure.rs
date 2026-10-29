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
use crate::runtime::{RuntimeAgentName, SandboxCommand, adapter};

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

/// The bot `runtime configure --channel` set up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelSet {
    pub channel: Channel,
    /// The variable the bot's token is read from.
    pub token: String,
    /// The people it answers, each once.
    pub answers: Vec<ChannelUser>,
    /// Whether the active policy lets the sandbox reach the channel's host.
    pub reachable: bool,
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
        let builtin = runtime.builtin_agent();
        let agent = match agent {
            Some(a) if builtin.is_some_and(|b| b.as_str() == a.as_str()) => {
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
            None => match builtin.and_then(|b| RuntimeAgentName::new(b.as_str())) {
                Some(b) => b,
                None => {
                    return Err(session(format!(
                        "{shown} has no built-in agent: name the agent to set up, as `{name}/<agent>`"
                    )));
                }
            },
        };
        let secrets_file = self
            .layout
            .agent_secrets_file(name.as_str(), agent.as_str());
        if secrets_file
            .to_str()
            .is_none_or(|p| p.contains(['\'', '\n', '\r']))
        {
            return Err(session(format!(
                "{} holds a quote or a line break, which the runtime's command that reads it cannot hold: set ENCLOS_HOME to a folder without them",
                secrets_file.display()
            )));
        }
        let Some(mut commands) = runtime.agent_secrets_source(&agent, &secrets_file) else {
            return Err(session(format!(
                "{shown} gives no agent secrets of its own, so enclos sets none of its settings"
            )));
        };
        let view = self.policy(name)?;
        let policy = &view.snapshot.policy;
        let pending = view.pending.as_ref().map(|(_, p)| &p.policy);
        let set = |key: &str, value: &str| {
            runtime.set_setting(&agent, key, value).ok_or_else(|| {
                session(format!(
                    "{shown} has no command that sets a setting, so enclos sets none"
                ))
            })
        };
        let mut keys = Vec::new();
        for setting in settings {
            self.check_setting(name, &agent, setting, policy, pending)?;
            commands.push(set(&setting.key, &setting.value)?);
            keys.push(setting.key.clone());
        }
        let channel = match channel {
            None => None,
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
            if let Some(bot) = done.channel.as_ref().filter(|b| !b.reachable) {
                changes.push(unreachable(name, bot.channel));
            }
            return Ok(Planned::DryRun(Plan {
                changes,
                ..Plan::default()
            }));
        }
        self.run_all(by, name, commands)?;
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
        let Some(settings) = runtime.channel_settings(channel, &token, &answers) else {
            return Err(session(format!(
                "{shown} has no {} channel enclos can set up",
                channel.display_name()
            )));
        };
        // A token the runtime's own setup wrote in plain text in the home,
        // which any agent there reads: refused until it is removed.
        if let Some((file, variable)) = runtime.channel_token_file(channel, agent) {
            let home = self.layout.sandbox_home(name.as_str());
            let text = crate::runtime::home::read_text(&home, &file, 1 << 20).map_err(|e| {
                session(format!("cannot look for a plain bot token in {file}: {e}"))
            })?;
            if text.is_some_and(|t| holds_variable(&t, variable)) {
                return Err(session(format!(
                    "{file} in sandbox {name} holds {variable} in plain text, as {shown}'s own setup writes it, where every agent of the sandbox reads it: remove that line ({}), then run `enclos runtime configure` again, which gives the token from the Keychain",
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
        let reachable =
            Destination::parse(channel.host(), 443).is_ok_and(|dest| allowed(policy, &dest));
        Ok((
            ChannelSet {
                channel,
                token,
                answers,
                reachable,
            },
            settings,
        ))
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

/// Whether a setting's name says it holds a secret: its last part, after
/// the last `.`, names a token, a secret, a password or a key.
fn names_a_secret(key: &str) -> bool {
    let last = key.rsplit('.').next().unwrap_or(key).to_ascii_uppercase();
    ["TOKEN", "SECRET", "PASSWORD", "PASSWD"]
        .iter()
        .any(|w| last.contains(w))
        || last == "KEY"
        || last.ends_with("_KEY")
}

/// What a dry run says of a channel whose host the policy does not reach.
fn unreachable(name: &SandboxName, channel: Channel) -> String {
    format!(
        "find that the policy does not let the bot reach {host}: allow it with `enclos policy allow {name} {host}`",
        host = channel.host()
    )
}

/// Whether the `.env` text `text` sets `variable` to something: a line
/// `variable=...` or `export variable=...`, with a value that is not empty.
fn holds_variable(text: &str, variable: &str) -> bool {
    text.lines().any(|line| {
        let line = line.trim_start();
        let line = line.strip_prefix("export ").unwrap_or(line).trim_start();
        line.strip_prefix(variable)
            .and_then(|rest| rest.trim_start().strip_prefix('='))
            .is_some_and(|value| {
                let value = value.trim();
                !value.is_empty() && value != "\"\"" && value != "''"
            })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_dotenv_line_setting_the_variable_is_found() {
        for set in ["T=abc", "  T = abc", "export T=\"abc\"", "a=1\nT='x'\n"] {
            assert!(holds_variable(set, "T"), "{set:?}");
        }
        for unset in ["", "T=", "T=\"\"", "# T=abc", "TT=abc", "AT=abc", "T_X=abc"] {
            assert!(!holds_variable(unset, "T"), "{unset:?}");
        }
    }

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
            "keyboard",
            "monkey",
        ] {
            assert!(!names_a_secret(plain), "{plain}");
        }
    }
}
