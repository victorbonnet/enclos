//! `enclos runtime`: install a runtime in a sandbox, and set up its bot on
//! a messaging channel. Logging it in is the runtime's own command, through
//! `enclos connect` (ADR 0024).

use clap::{Args, Subcommand};

use enclos::engine::Engine;
use enclos::error::{Error, Result, exit};
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
        /// The sandbox, such as `home`. A bot of one agent's own
        /// (`home/main`) is not possible with Hermes's gateway yet.
        target: String,
        #[arg(long)]
        channel: Channel,
        /// The variable the policy grants the bot's token as; the
        /// channel's usual one (TELEGRAM_BOT_TOKEN) when left out.
        #[arg(long, value_name = "VAR")]
        token_env: Option<String>,
        /// Someone the bot answers: a Telegram user's numeric id; give it
        /// once per person.
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
            return configure(
                engine,
                by,
                confirm,
                &target,
                channel,
                token_env,
                &allow_user,
            );
        }
    };
    let end = match engine.install_runtime(by, &sandbox, runtime, confirm)? {
        Planned::DryRun(plan) => {
            plan.changes.iter().for_each(|c| println!("Would {c}."));
            return Ok(exit::OK);
        }
        Planned::Done(end) => end,
    };
    super::connect::report_end(&sandbox, &end.end);
    let shown = runtime.display_name();
    if !end.installed {
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
        eprintln!(
            "enclos: the {shown} installer exited with {} in sandbox {sandbox}; its output above says why. {after}. Fix the cause, then run `enclos runtime install {runtime} --sandbox {sandbox}` again.",
            end.end.exit
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

fn configure(
    engine: &Engine,
    by: &Actor,
    confirm: Confirm,
    target: &str,
    channel: Channel,
    token: Option<String>,
    answers: &[ChannelUser],
) -> Result<u8> {
    let (sandbox, agent) = match target.split_once('/') {
        Some((sandbox, agent)) => (sandbox, Some(agent)),
        None => (target, None),
    };
    let sandbox: SandboxName = sandbox.parse().map_err(|e| Error::Session {
        what: format!("{e}"),
    })?;
    if let Some(agent) = agent {
        return Err(Error::Session {
            what: format!(
                "a bot of agent {agent}'s own is not possible yet: Hermes's gateway gives a named agent a token only from a file in its folder, and enclos keeps secrets out of the sandbox home (ADR 0022). Set up the sandbox's bot with `enclos runtime configure {sandbox} --channel {channel} ...`; see ADR 0032 (proposed)"
            ),
        });
    }
    let set = match engine.configure_channel(by, &sandbox, channel, token, answers, confirm)? {
        Planned::DryRun(plan) => {
            plan.changes.iter().for_each(|c| println!("Would {c}."));
            return Ok(exit::OK);
        }
        Planned::Done(set) => set,
    };
    let shown = channel.display_name();
    println!(
        "Sandbox {sandbox}'s {shown} bot is set up: its token is read from ${} as the gateway starts, and it answers {} user(s). A running gateway restarts with it.",
        set.token,
        answers.len()
    );
    if !set.reachable {
        println!(
            "Its policy does not let it reach {}: `enclos policy allow {sandbox} {}`.",
            channel.host(),
            channel.host()
        );
    }
    println!("Start it with `enclos sandbox start {sandbox}`, then send the bot a message.");
    Ok(exit::OK)
}
