//! The engine's messaging call (design §12): set up an agent's bot on a
//! channel with the runtime's own commands, its token a secret the policy
//! grants that agent (ADR 0036).

use super::Engine;
use crate::error::{Error, Result};
use crate::model::agent::AgentName;
use crate::model::audit::Actor;
use crate::model::channel::{Channel, ChannelUser};
use crate::model::plan::{Confirm, Plan, Planned};
use crate::model::sandbox::SandboxName;
use crate::model::secret::{is_variable_name, reserved_variable};
use crate::proxy::decide::{Destination, allowed};
use crate::runtime::{RuntimeAgentName, adapter};

/// What `runtime configure --channel` did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelSet {
    pub channel: Channel,
    /// The agent whose bot it is.
    pub agent: RuntimeAgentName,
    /// The variable the bot's token is read from.
    pub token: String,
    /// The people it answers, each once.
    pub answers: Vec<ChannelUser>,
    /// Whether the active policy lets the sandbox reach the channel's host.
    pub reachable: bool,
}

impl Engine {
    /// Sets up `agent`'s bot on `channel` with the runtime's own commands,
    /// the runtime's built-in agent's when `None`: its token read from
    /// `token` (the channel's usual variable when none is named), which the
    /// active policy must grant that agent (ADR 0036), and the people it
    /// answers. A running service restarts on its own once its settings
    /// change (ADR 0031).
    #[allow(clippy::too_many_arguments)]
    pub fn configure_channel(
        &self,
        by: &Actor,
        name: &SandboxName,
        agent: Option<&AgentName>,
        channel: Channel,
        token: Option<String>,
        answers: &[ChannelUser],
        confirm: Confirm,
    ) -> Result<Planned<ChannelSet>> {
        let kind = self.runtime_of(name)?;
        let runtime = adapter(kind);
        let shown = kind.display_name();
        let token = token.unwrap_or_else(|| channel.token_variable().to_owned());
        if !is_variable_name(&token) || reserved_variable(&token) {
            return Err(Error::Session {
                what: format!(
                    "`{token}` cannot hold the bot's token: name a variable of letters, digits and `_`, not starting with a digit, that enclos neither sets nor passes on itself, as a policy's [secrets] does"
                ),
            });
        }
        let mut answers = answers.to_vec();
        answers.sort();
        answers.dedup();
        if answers.is_empty() {
            return Err(Error::Session {
                what: "name who the bot answers with `--allow-user <id>`: enclos sets up no bot that answers anyone".to_owned(),
            });
        }
        let builtin = runtime.builtin_agent();
        let agent = match agent {
            Some(a) if builtin.is_some_and(|b| b.as_str() == a.as_str()) => {
                RuntimeAgentName::from(a)
            }
            Some(a) => {
                if !self.agents(name)?.iter().any(|r| r.name == *a) {
                    return Err(Error::Session {
                        what: format!(
                            "sandbox {name} has no agent {a} that enclos tracks: add it with `enclos agent add {name}/{a}` first"
                        ),
                    });
                }
                RuntimeAgentName::from(a)
            }
            None => match builtin.and_then(|b| RuntimeAgentName::new(b.as_str())) {
                Some(b) => b,
                None => {
                    return Err(Error::Session {
                        what: format!(
                            "{shown} has no built-in agent: name the agent whose bot it is, as `{name}/<agent>`"
                        ),
                    });
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
            return Err(Error::Session {
                what: format!(
                    "{} holds a quote or a line break, which the runtime's command that reads it cannot hold: set ENCLOS_HOME to a folder without them",
                    secrets_file.display()
                ),
            });
        }
        let Some(commands) = runtime.channel(channel, &agent, &token, &answers, &secrets_file)
        else {
            return Err(Error::Session {
                what: format!(
                    "{shown} has no {} channel enclos can set up",
                    channel.display_name()
                ),
            });
        };
        // A token the runtime's own setup wrote in plain text in the home,
        // which any agent there reads: refused until it is removed.
        if let Some((file, variable)) = runtime.channel_token_file(channel, &agent) {
            let home = self.layout.sandbox_home(name.as_str());
            let text = crate::runtime::home::read_text(&home, &file, 1 << 20).map_err(|e| {
                Error::Session {
                    what: format!("cannot look for a plain bot token in {file}: {e}"),
                }
            })?;
            if text.is_some_and(|t| holds_variable(&t, variable)) {
                return Err(Error::Session {
                    what: format!(
                        "{file} in sandbox {name} holds {variable} in plain text, as {shown}'s own setup writes it, where every agent of the sandbox reads it: remove that line ({}), then run `enclos runtime configure` again, which gives the token from the Keychain",
                        home.join(file.as_path()).display()
                    ),
                });
            }
        }
        let view = self.policy(name)?;
        let policy = &view.snapshot.policy;
        let section = format!("[secrets.agents.{agent}]");
        // Granted to the whole sandbox, the token would reach every agent,
        // and win over each one's own (ADR 0036).
        if policy.secrets.contains_key(&token) {
            return Err(Error::Session {
                what: format!(
                    "the policy of sandbox {name} gives ${token} to the whole sandbox, under [secrets], which every agent receives and which wins over an agent's own: with `enclos policy edit {name}`, move it to {section} (ADR 0036)"
                ),
            });
        }
        let granted = |p: &crate::model::policy::Policy, variable: &str| {
            p.agent_secrets
                .get(agent.as_str())
                .is_some_and(|g| g.contains_key(variable))
        };
        if !granted(policy, &token) {
            let pending = view
                .pending
                .as_ref()
                .is_some_and(|(_, p)| granted(&p.policy, &token));
            let secret = match agent.as_str() == builtin.map(|b| b.as_str()).unwrap_or_default() {
                true => format!("{name}/{channel}"),
                false => format!("{name}/{agent}-{channel}"),
            };
            return Err(Error::Session {
                what: match pending {
                    true => format!(
                        "the pending policy of sandbox {name} gives agent {agent} ${token}, the bot's token, but it is not in force yet: `enclos policy apply {name}` first"
                    ),
                    false => format!(
                        "the policy of sandbox {name} gives agent {agent} no ${token}, the bot's token: store the token with `enclos secret set {secret}`, then with `enclos policy edit {name}` add `{token} = \"secret:{secret}\"` to the `env` of its {section} section"
                    ),
                },
            });
        }
        // The channel's usual variable, granted too, is the one the runtime
        // reads first: the bot would be that token's, not `token`'s.
        let usual = channel.token_variable();
        if token != usual && granted(policy, usual) {
            return Err(Error::Session {
                what: format!(
                    "the policy of sandbox {name} also gives agent {agent} ${usual}, which {shown} reads for the bot before ${token}, so the bot would be the one ${usual} names: take ${usual} out of its {section}, or set the bot up with it (no --token-env)"
                ),
            });
        }
        let reachable = Destination::parse(channel.host(), 443)
            .is_ok_and(|dest| allowed(&view.snapshot.policy, &dest));
        let set = ChannelSet {
            channel,
            agent: agent.clone(),
            token,
            answers,
            reachable,
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
            if !set.reachable {
                changes.push(unreachable(name, channel));
            }
            return Ok(Planned::DryRun(Plan {
                changes,
                ..Plan::default()
            }));
        }
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
        Ok(Planned::Done(set))
    }
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
    use super::holds_variable;

    #[test]
    fn a_dotenv_line_setting_the_variable_is_found() {
        for set in ["T=abc", "  T = abc", "export T=\"abc\"", "a=1\nT='x'\n"] {
            assert!(holds_variable(set, "T"), "{set:?}");
        }
        for unset in ["", "T=", "T=\"\"", "# T=abc", "TT=abc", "AT=abc", "T_X=abc"] {
            assert!(!holds_variable(unset, "T"), "{unset:?}");
        }
    }
}
