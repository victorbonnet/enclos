//! `enclos runtime`: install a runtime in a sandbox, and set up its bot on
//! a messaging channel. Logging it in is the runtime's own command, through
//! `enclos connect` (ADR 0024).

use std::str::FromStr;

use clap::{Args, Subcommand};
use serde_json::json;

use super::output;
use enclos::engine::Engine;
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
    /// Set up the sandbox's bot on a messaging channel, its token one of
    /// the sandbox's secrets, which the policy grants.
    Configure {
        /// Whose bot it is: a sandbox, such as `home`, for its built-in
        /// agent's, or one of its agents, such as `home/main`, for that
        /// agent's own (ADR 0036).
        target: ChannelTarget,
        #[arg(long)]
        channel: Channel,
        /// The variable the policy grants the bot's token as; the
        /// channel's usual one (TELEGRAM_BOT_TOKEN) when left out. Hermes
        /// keeps only the usual one from the agents' commands.
        #[arg(long, value_name = "VAR")]
        token_env: Option<String>,
        /// Someone the bot answers: a Telegram user's numeric id; repeat it
        /// for each person.
        #[arg(long = "allow-user", value_name = "ID", required = true)]
        allow_user: Vec<ChannelUser>,
    },
}

pub fn run(engine: &Engine, by: &Actor, confirm: Confirm, args: RuntimeArgs) -> Result<u8> {
    let (runtime, sandbox) = match args.verb {
        RuntimeVerb::Install { runtime, sandbox } => (runtime, sandbox),
        RuntimeVerb::Configure {
            target,
            channel,
            token_env,
            allow_user,
        } => {
            return configure(engine, by, confirm, target, channel, token_env, &allow_user);
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
    channel: Channel,
    token: Option<String>,
    answers: &[ChannelUser],
) -> Result<u8> {
    let ChannelTarget { sandbox, agent } = target;
    let set = match engine.configure_channel(
        by,
        &sandbox,
        agent.as_ref(),
        channel,
        token,
        answers,
        confirm,
    )? {
        Planned::DryRun(plan) => {
            output::show_plan(&plan);
            return Ok(exit::OK);
        }
        Planned::Done(set) => set,
    };
    let shown = channel.display_name();
    if output::json() {
        output::emit(&json!({
            "sandbox": sandbox.to_string(),
            "agent": set.agent.to_string(),
            "channel": channel.to_string(),
            "token_variable": set.token.to_string(),
            "answers": set.answers.iter().map(ToString::to_string).collect::<Vec<_>>(),
            "reachable": set.reachable,
            "host": channel.host(),
        }));
        return Ok(exit::OK);
    }
    println!(
        "Agent {sandbox}/{}'s {shown} bot is set up: its token is read from ${}, which the policy grants that agent, as its service starts, and it answers {} user(s). A running service restarts with it.",
        set.agent,
        set.token,
        set.answers.len()
    );
    if !set.reachable {
        println!(
            "Its policy does not let it reach {host}: `enclos policy allow {sandbox} {host}`.",
            host = channel.host(),
        );
    }
    println!(
        "If the sandbox is not started, start it with `enclos sandbox start {sandbox}`; then send the bot a message."
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
