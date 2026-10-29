//! `enclos runtime`: install a runtime in a sandbox, and set up its bot on
//! a messaging channel. Logging it in is the runtime's own command, through
//! `enclos connect` (ADR 0024).

use std::str::FromStr;

use clap::{Args, Subcommand};
use serde_json::json;

use super::output;
use enclos::engine::{ChannelRequest, Engine, Setting};
use enclos::error::{Result, exit};
use enclos::model::agent::AgentName;
use enclos::model::audit::Actor;
use enclos::model::channel::{Channel, ChannelUser};
use enclos::model::plan::{Confirm, Planned};
use enclos::model::runtime::RuntimeKind;
use enclos::model::sandbox::SandboxName;

#[derive(Args)]
pub struct RuntimeArgs {
    #[command(subcommand)]
    verb: RuntimeVerb,
}

#[derive(Subcommand)]
enum RuntimeVerb {
    /// Install a runtime in a sandbox with its own installer, run inside the sandbox.
    Install {
        runtime: RuntimeKind,
        #[arg(long)]
        sandbox: SandboxName,
    },
    /// Set an agent up with the runtime's own commands: it reads the
    /// secrets the policy grants it under [secrets.agents.<agent>], then
    /// each --set, then, with --channel, a bot (ADR 0036)
    Configure {
        /// The agent: a sandbox, such as `home`, for its built-in agent, or
        /// one of its agents, such as `home/main`.
        target: ChannelTarget,
        /// A setting of the agent, as the runtime names it, such as
        /// `platforms.discord.token=${DISCORD_BOT_TOKEN}`: a secret only as
        /// `${VAR}`, which the policy grants the agent or the sandbox;
        /// repeat it for each setting.
        #[arg(long = "set", value_name = "KEY=VALUE")]
        set: Vec<Setting>,
        /// A bot on this messaging channel, its token a secret the policy
        /// grants the agent.
        #[arg(long, requires = "allow_user")]
        channel: Option<Channel>,
        /// With --channel: the variable the policy grants the bot's token
        /// as; the channel's usual one (TELEGRAM_BOT_TOKEN) when left out.
        /// Hermes keeps only the usual one from the agents' commands.
        #[arg(long, value_name = "VAR", requires = "channel")]
        token_env: Option<String>,
        /// With --channel: someone the bot answers, a Telegram user's
        /// numeric id; repeat it for each person.
        #[arg(long = "allow-user", value_name = "ID", requires = "channel")]
        allow_user: Vec<ChannelUser>,
    },
}

pub fn run(engine: &Engine, by: &Actor, confirm: Confirm, args: RuntimeArgs) -> Result<u8> {
    let (runtime, sandbox) = match args.verb {
        RuntimeVerb::Install { runtime, sandbox } => (runtime, sandbox),
        RuntimeVerb::Configure {
            target,
            set,
            channel,
            token_env,
            allow_user,
        } => {
            let channel = channel.map(|channel| ChannelRequest {
                channel,
                token: token_env,
                answers: allow_user,
            });
            return configure(engine, by, confirm, target, channel, &set);
        }
    };
    let end = match engine.install_runtime(by, &sandbox, runtime, confirm)? {
        Planned::DryRun(plan) => {
            output::show_plan(&plan);
            return Ok(exit::OK);
        }
        Planned::Done(end) => end,
    };
    let shown = runtime.display_name();
    // How the installer ended, and what that leaves recorded: the same in
    // text and in JSON, since a policy left wider must be said.
    let ended = match end.end.signal {
        Some(signal) => format!("was ended by signal {signal}"),
        None => format!("exited with {}", end.end.exit),
    };
    let after = match end.recorded {
        Some(kept) => format!(
            "{} is still recorded as installed, and policy v{} still allows its destinations; its files may be incomplete",
            kept.display_name(),
            end.policy
        ),
        None => format!(
            "Nothing is recorded as installed, and policy v{} is without {shown}'s destinations",
            end.policy
        ),
    };
    if output::json() {
        let code = match end.installed {
            true => exit::OK,
            false => exit::ERROR,
        };
        return Ok(output::conclude(
            json!({
                "sandbox": sandbox.to_string(),
                "runtime": runtime.to_string(),
                "installed": end.installed,
                "session": output::session(&end.end),
                "recorded": end.recorded.map(|k| k.to_string()),
                "policy_version": end.policy,
                "login": format!("enclos connect {sandbox} -- {}", enclos::runtime::adapter(runtime).login()),
            }),
            code,
            || {
                format!(
                    "the {shown} installer {ended} in sandbox {sandbox}. {after}. Fix the cause, then run `enclos runtime install {runtime} --sandbox {sandbox}` again"
                )
            },
        ));
    }
    super::connect::report_end(&sandbox, &end.end);
    if !end.installed {
        eprintln!(
            "enclos: the {shown} installer {ended} in sandbox {sandbox}; its output above says why. {after}. Fix the cause, then run `enclos runtime install {runtime} --sandbox {sandbox}` again."
        );
        return Ok(exit::ERROR);
    }
    println!(
        "{shown} is installed in sandbox {sandbox} (policy v{}). Log it in and set it up with its own command: `enclos connect {sandbox} -- {}`.",
        end.policy,
        enclos::runtime::adapter(runtime).login()
    );
    Ok(exit::OK)
}

/// What `runtime configure` sets up: the bot of the sandbox's built-in
/// agent, or of the agent named (ADR 0036).
#[derive(Debug, Clone, PartialEq, Eq)]
struct ChannelTarget {
    sandbox: SandboxName,
    agent: Option<AgentName>,
}

impl FromStr for ChannelTarget {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let (sandbox, agent) = match s.split_once('/') {
            Some((sandbox, agent)) => (sandbox, Some(agent)),
            None => (s, None),
        };
        let sandbox = sandbox
            .parse()
            .map_err(|e| format!("{e}; name the sandbox, such as `home`"))?;
        let agent = agent
            .map(|a| a.parse().map_err(|e| format!("{e}")))
            .transpose()?;
        Ok(ChannelTarget { sandbox, agent })
    }
}

fn configure(
    engine: &Engine,
    by: &Actor,
    confirm: Confirm,
    target: ChannelTarget,
    channel: Option<ChannelRequest>,
    settings: &[Setting],
) -> Result<u8> {
    let ChannelTarget { sandbox, agent } = target;
    let done =
        match engine.configure_agent(by, &sandbox, agent.as_ref(), channel, settings, confirm)? {
            Planned::DryRun(plan) => {
                output::show_plan(&plan);
                return Ok(exit::OK);
            }
            Planned::Done(done) => done,
        };
    let agent = &done.agent;
    if output::json() {
        output::emit(&json!({
            "sandbox": sandbox.to_string(),
            "agent": agent.to_string(),
            "settings": done.settings,
            "channel": done.channel.as_ref().map(|bot| json!({
                "channel": bot.channel.to_string(),
                "token_variable": bot.token,
                "answers": bot.answers.iter().map(ToString::to_string).collect::<Vec<_>>(),
                "reachable": bot.reachable,
                "host": bot.channel.host(),
            })),
        }));
        return Ok(exit::OK);
    }
    println!(
        "Agent {sandbox}/{agent} reads the secrets the policy grants it under [secrets.agents.{agent}], from its services' next start."
    );
    if !done.settings.is_empty() {
        println!("Set: {}.", done.settings.join(", "));
    }
    if let Some(bot) = &done.channel {
        println!(
            "Its {} bot is set up: its token is read from ${}, and it answers {} user(s).",
            bot.channel.display_name(),
            bot.token,
            bot.answers.len()
        );
        if !bot.reachable {
            println!(
                "Its policy does not let it reach {host}: `enclos policy allow {sandbox} {host}`.",
                host = bot.channel.host(),
            );
        }
    }
    println!(
        "A running service restarts with it; if the sandbox is not started, start it with `enclos sandbox start {sandbox}`."
    );
    Ok(exit::OK)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_target_is_a_sandbox_or_one_of_its_agents() {
        let target: ChannelTarget = "home".parse().unwrap();
        assert_eq!((target.sandbox.as_str(), target.agent), ("home", None));
        let target: ChannelTarget = "home/main".parse().unwrap();
        assert_eq!(target.agent.unwrap().as_str(), "main");
        for bad in ["home/", "/main", "home/main/x", "Home"] {
            assert!(bad.parse::<ChannelTarget>().is_err(), "{bad}");
        }
    }
}
