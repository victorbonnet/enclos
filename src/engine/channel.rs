//! The engine's messaging call (design §12): set up the sandbox's bot on a
//! channel with the runtime's own commands, its token one of the sandbox's
//! secrets.

use super::Engine;
use crate::error::{Error, Result};
use crate::model::audit::Actor;
use crate::model::channel::{Channel, ChannelUser};
use crate::model::plan::{Confirm, Plan, Planned};
use crate::model::sandbox::SandboxName;
use crate::proxy::decide::{Destination, allowed};
use crate::runtime::adapter;

/// What `runtime configure --channel` did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelSet {
    pub channel: Channel,
    /// The variable the bot's token is read from.
    pub token: String,
    /// Whether the active policy lets the sandbox reach the channel's host.
    pub reachable: bool,
}

impl Engine {
    /// Sets up the sandbox's bot on `channel` for the runtime's built-in
    /// agent: its token read from `token` (the channel's usual variable when
    /// none is named), which the active policy must grant, and the people
    /// it answers. The runtime's own commands write its settings; a running
    /// service restarts on its own once they change (ADR 0031).
    pub fn configure_channel(
        &self,
        by: &Actor,
        name: &SandboxName,
        channel: Channel,
        token: Option<String>,
        answers: &[ChannelUser],
        confirm: Confirm,
    ) -> Result<Planned<ChannelSet>> {
        let kind = self.runtime_of(name)?;
        let runtime = adapter(kind);
        let shown = kind.display_name();
        let token = token.unwrap_or_else(|| channel.token_variable().to_owned());
        if answers.is_empty() {
            return Err(Error::Session {
                what: format!(
                    "name who the bot answers with `--allow-user <id>`: {shown} answers only the {} users it is told, and enclos tells it none by default",
                    channel.display_name()
                ),
            });
        }
        let Some(commands) = runtime.channel(channel, &token, answers) else {
            return Err(Error::Session {
                what: format!(
                    "{shown} has no {} channel enclos can set up",
                    channel.display_name()
                ),
            });
        };
        let view = self.policy(name)?;
        if !view.snapshot.policy.secrets.contains_key(&token) {
            let pending = view
                .pending
                .as_ref()
                .is_some_and(|(_, p)| p.policy.secrets.contains_key(&token));
            return Err(Error::Session {
                what: match pending {
                    true => format!(
                        "the pending policy of sandbox {name} gives it ${token}, the bot's token, but it is not in force yet: `enclos policy apply {name}` first"
                    ),
                    false => format!(
                        "the policy of sandbox {name} gives it no ${token}, the bot's token: store the token with `enclos secret set {name}/{channel}`, then grant it with `enclos policy edit {name}`, under [secrets], as `env = {{ {token} = \"secret:{name}/{channel}\" }}`"
                    ),
                },
            });
        }
        let reachable = Destination::parse(channel.host(), 443)
            .is_ok_and(|dest| allowed(&view.snapshot.policy, &dest));
        let set = ChannelSet {
            channel,
            token,
            reachable,
        };
        if confirm == Confirm::DryRun {
            return Ok(Planned::DryRun(Plan {
                changes: commands
                    .iter()
                    .map(|c| {
                        format!(
                            "run `{}` in sandbox {name} under policy v{}",
                            c.shown(),
                            view.version.version
                        )
                    })
                    .collect(),
                ..Plan::default()
            }));
        }
        for command in commands {
            let ran = command.shown();
            let end = self.run_in_sandbox(by, name, command, "runtime configure")?;
            if end.exit != 0 {
                return Err(Error::Session {
                    what: format!(
                        "`{ran}` exited with {} in sandbox {name}: its output above says why. Run `enclos runtime configure` again once it is fixed",
                        end.exit
                    ),
                });
            }
        }
        Ok(Planned::Done(set))
    }
}
