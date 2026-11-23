//! `enclos runtime`: install a runtime in a sandbox, and set up its bot on
//! a messaging channel. Logging it in is the runtime's own command, through
//! `enclos connect` (ADR 0024).

use std::str::FromStr;
use std::time::Duration;

use clap::{Args, Subcommand};
use serde_json::json;

use super::output;
use enclos::engine::{ChannelRequest, ChannelSet, Engine, RunningWork, ServicesAfter, Setting};
use enclos::error::{Result, exit};
use enclos::model::agent::AgentName;
use enclos::model::audit::Actor;
use enclos::model::channel::{Channel, ChannelUser};
use enclos::model::count;
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
        /// Stop the installer, and every process it started, once it has
        /// run this many seconds, and fail the install: for the mobile
        /// app's bridge, which runs this command with nobody watching.
        #[arg(long, hide = true, value_name = "SECONDS")]
        time_limit: Option<u64>,
        /// Who asked for the install, as the audit log names them: the
        /// mobile app's bridge, which runs this command for a paired
        /// device, names its person and device.
        #[arg(long, hide = true, value_name = "WHO")]
        requested_by: Option<String>,
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
        /// grants the agent; or `app`, the enclos mobile app's channel,
        /// which enclos's bridge connects to.
        #[arg(long)]
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
    /// Update the sandbox's runtime with its own updater, restarting its services around it.
    Update {
        sandbox: SandboxName,
        /// Stop the updater, and every process it started, once it has
        /// run this many seconds, and fail the update: for the mobile
        /// app's bridge, which runs this command with nobody watching.
        #[arg(long, hide = true, value_name = "SECONDS")]
        time_limit: Option<u64>,
        /// Who asked for the update, as the audit log names them: the
        /// mobile app's bridge, which runs this command for a paired
        /// device, names its person and device.
        #[arg(long, hide = true, value_name = "WHO")]
        requested_by: Option<String>,
    },
}

pub fn run(engine: &Engine, by: &Actor, confirm: Confirm, args: RuntimeArgs) -> Result<u8> {
    let (runtime, sandbox, limit, requested_by) = match args.verb {
        RuntimeVerb::Install {
            runtime,
            sandbox,
            time_limit,
            requested_by,
        } => (
            runtime,
            sandbox,
            time_limit.map(Duration::from_secs),
            requested_by,
        ),
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
        RuntimeVerb::Update {
            sandbox,
            time_limit,
            requested_by,
        } => {
            let by = &requester(by, requested_by);
            let limit = time_limit.map(Duration::from_secs);
            return update(engine, by, confirm, sandbox, limit);
        }
    };
    let by = &requester(by, requested_by);
    let installed = match limit {
        None => engine.install_runtime(by, &sandbox, runtime, confirm)?,
        Some(limit) => engine.install_runtime_within(by, &sandbox, runtime, confirm, limit)?,
    };
    let end = match installed {
        Planned::DryRun(plan) => {
            output::show_plan(&plan);
            return Ok(exit::OK);
        }
        Planned::Done(end) => end,
    };
    let shown = runtime.display_name();
    // How the installer ended, and what that leaves recorded: the same in
    // text and in JSON, since a policy left wider must be said.
    let ended = end.ended();
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
                "runtime_version": end.version.as_ref().and_then(|v| v.as_ref().ok()).map(|v| v.to_string()),
                "runtime_version_unrecorded": end.version.as_ref().and_then(|v| v.as_ref().err()),
                "policy_version": end.policy,
                "login": format!("enclos connect {sandbox} -- {}", end.login),
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
    let installed = match &end.version {
        Some(Ok(version)) => format!("{shown} {version}"),
        _ => shown.to_owned(),
    };
    println!(
        "{installed} is installed in sandbox {sandbox} (policy v{}). Log it in and set it up with its own command: `enclos connect {sandbox} -- {}`.",
        end.policy, end.login
    );
    if let Some(Err(why)) = &end.version {
        eprintln!(
            "enclos: {shown}'s version is not recorded, so `enclos status` cannot say whether it is outdated until the next install records it: {why}."
        );
    }
    Ok(exit::OK)
}

/// Who the audit log names for an install: the user running enclos, or
/// the one `--requested-by` names, on this host.
fn requester(by: &Actor, requested_by: Option<String>) -> Actor {
    match requested_by {
        Some(user) => Actor {
            user,
            host: by.host.clone(),
        },
        None => by.clone(),
    }
}

/// What `runtime configure` sets up: the bot of the sandbox's built-in
/// agent, or of the agent named (ADR 0036).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ChannelTarget {
    pub(super) sandbox: SandboxName,
    pub(super) agent: Option<AgentName>,
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
            "channel": done.channel.as_ref().map(|set| match set {
                ChannelSet::Bot { channel, token, answers, reachable } => json!({
                    "channel": channel.to_string(),
                    "token_variable": token,
                    "answers": answers.iter().map(ToString::to_string).collect::<Vec<_>>(),
                    "reachable": reachable,
                    "host": channel.host(),
                    "socket": null,
                }),
                ChannelSet::App { token, socket } => json!({
                    "channel": Channel::App.to_string(),
                    "token_variable": token,
                    "answers": [],
                    "reachable": true,
                    "host": null,
                    "socket": socket.display().to_string(),
                }),
            }),
        }));
        return Ok(exit::OK);
    }
    println!(
        "Agent {sandbox}/{agent} reads the secrets the policy grants it under [secrets.agents.{agent}], from its services' next start."
    );
    if !done.settings.is_empty() {
        println!("Set: {}.", done.settings.join(", "));
    }
    match &done.channel {
        None => {}
        Some(ChannelSet::App { token, socket }) => println!(
            "Its app channel is set up: it listens at {}, for enclos's bridge, which presents ${token}. A running bridge serves it within seconds, with no restart.",
            socket.display()
        ),
        Some(ChannelSet::Bot {
            channel,
            token,
            answers,
            reachable,
        }) => {
            println!(
                "Its {} bot is set up: its token is read from ${token}, and it answers {} user(s).",
                channel.display_name(),
                answers.len()
            );
            if let (false, Some(host)) = (*reachable, channel.host()) {
                println!(
                    "Its policy does not let it reach {host}: `enclos policy allow {sandbox} {host}`."
                );
            }
        }
    }
    println!(
        "A running service restarts with it; if the sandbox is not started, start it with `enclos sandbox start {sandbox}`."
    );
    Ok(exit::OK)
}

fn update(
    engine: &Engine,
    by: &Actor,
    confirm: Confirm,
    sandbox: SandboxName,
    limit: Option<Duration>,
) -> Result<u8> {
    if !output::json() && confirm != Confirm::DryRun {
        let pre = engine.update_preflight(&sandbox)?;
        let shown = pre.kind.display_name();
        match &pre.running_work {
            RunningWork::Count { count: n, agents } if *n > 0 => {
                println!(
                    "This interrupts {} ({}).",
                    count(*n, "running task", "running tasks"),
                    agents.join(", ")
                );
            }
            RunningWork::Count { .. } => {}
            RunningWork::Unknown(why) => {
                println!("Cannot tell how many running tasks this interrupts: {why}.");
            }
        }
        if !pre.policy_missing.is_empty() {
            let allow_cmds: Vec<String> = pre
                .policy_missing
                .iter()
                .map(|d| format!("`enclos policy allow {sandbox} {d}`"))
                .collect();
            println!(
                "The policy of sandbox {sandbox} does not allow {}, which the {shown} updater may need: {}. The update goes ahead.",
                pre.policy_missing.join(", "),
                allow_cmds.join(", ")
            );
        }
        if let Some(rel) = &pre.release
            && !rel.checked
        {
            println!(
                "{shown} {} is out, not checked with this enclos yet; the update goes ahead.",
                rel.version
            );
        }
    }
    let updated = match limit {
        None => engine.update_runtime(by, &sandbox, confirm)?,
        Some(limit) => engine.update_runtime_within(by, &sandbox, confirm, limit)?,
    };
    let end = match updated {
        Planned::DryRun(plan) => {
            output::show_plan(&plan);
            return Ok(exit::OK);
        }
        Planned::Done(end) => end,
    };
    let shown = end.kind.display_name();
    let user_home = std::env::var("HOME").ok();
    let log_shown = super::status::tilde(&end.log, user_home.as_deref());
    let failure_message = || {
        let ended = end.ended();
        let services_clause = match end.services {
            ServicesAfter::StartedAgain => {
                "the sandbox's services are running again on what the updater left"
            }
            ServicesAfter::NotInstalled => "no service was installed (the sandbox was stopped)",
        };
        let state_sentence = match &end.before {
            Some(v) => format!("{shown} {v} stays recorded, and {services_clause}."),
            None => match end.services {
                ServicesAfter::StartedAgain => {
                    "The sandbox's services are running again on what the updater left.".to_owned()
                }
                ServicesAfter::NotInstalled => {
                    "No service was installed (the sandbox was stopped).".to_owned()
                }
            },
        };
        format!(
            "the {shown} updater {ended} in sandbox {sandbox}. Its log is {log_shown} (`enclos logs {sandbox}`). {state_sentence} There is no rollback: fix the cause, then run `enclos runtime update {sandbox}` again."
        )
    };
    if output::json() {
        let code = match end.succeeded {
            true => exit::OK,
            false => exit::ERROR,
        };
        let running_work = match &end.running_work {
            RunningWork::Count { count: n, agents } => json!({
                "count": n,
                "agents": agents,
            }),
            RunningWork::Unknown(why) => json!({
                "unknown": why,
            }),
        };
        return Ok(output::conclude(
            json!({
                "sandbox": sandbox.to_string(),
                "runtime": end.kind.to_string(),
                "updated": end.updated,
                "version_before": end.before.as_ref().map(|v| v.to_string()),
                "version_after": end.after.as_ref().and_then(|v| v.as_ref().ok()).map(|v| v.to_string()),
                "version_unreadable": end.after.as_ref().and_then(|v| v.as_ref().err()),
                "session": output::session(&end.session),
                "release": end.release.as_ref().map(|r| json!({
                    "version": r.version,
                    "checked": r.checked,
                })),
                "policy_version": end.policy,
                "policy_missing": end.policy_missing,
                "running_work": running_work,
                "stopped_after": end.stopped_after.map(|d| d.as_secs()),
                "log": end.log.display().to_string(),
                "services": end.services.as_str(),
            }),
            code,
            failure_message,
        ));
    }
    if !end.succeeded {
        // What the updater said about its own ending, and the path of its log,
        // are both values the engine hands back — and the `Engine` is the
        // object that holds the policy's secrets, so CodeQL's
        // cleartext-logging analysis takes every value derived from it as
        // secret-bearing when one reaches a log. Stderr therefore names
        // neither: the updater's own output, streamed above as A7 has it, says
        // why it stopped, `enclos logs` keeps and shows the log, and the JSON
        // document still carries the path (`log`) and how the session ended
        // (`session`, `stopped_after`) for the bridge and the phone.
        let services_clause = match end.services {
            ServicesAfter::StartedAgain => {
                "The sandbox's services are running again on what the updater left."
            }
            ServicesAfter::NotInstalled => "No service was installed (the sandbox was stopped).",
        };
        eprintln!(
            "enclos: the {shown} updater did not finish in sandbox {sandbox}; its output above says why, and `enclos logs {sandbox}` keeps it. {services_clause} There is no rollback: fix the cause, then run `enclos runtime update {sandbox}` again."
        );
        return Ok(exit::ERROR);
    }
    let services_semi = match end.services {
        ServicesAfter::StartedAgain => "its services are running again.",
        ServicesAfter::NotInstalled => "its services were not installed (the sandbox was stopped).",
    };
    let services_sentence = match end.services {
        ServicesAfter::StartedAgain => "Its services are running again.",
        ServicesAfter::NotInstalled => "Its services were not installed (the sandbox was stopped).",
    };
    if end.updated {
        match (&end.before, &end.after) {
            (Some(before), Some(Ok(after))) => println!(
                "{shown} {after} now runs in sandbox {sandbox} (was {before}); {services_semi}"
            ),
            (None, Some(Ok(after))) => {
                println!("{shown} {after} now runs in sandbox {sandbox}; {services_semi}")
            }
            _ => println!("{shown} updater finished in sandbox {sandbox}. {services_sentence}"),
        }
    } else if let Some(Ok(after)) = &end.after {
        println!(
            "{shown} is already at {after} in sandbox {sandbox}: its own update found no newer release. {services_sentence}"
        );
    } else {
        println!("{shown} updater finished in sandbox {sandbox}. {services_sentence}");
        if let Some(Err(why)) = &end.after {
            eprintln!(
                "enclos: {shown}'s version could not be read after the update, so `enclos status` cannot say whether it moved: {why}. The version recorded before is kept."
            );
        }
    }
    Ok(exit::OK)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_install_is_audited_as_who_asked_for_it_on_this_host() {
        let by = Actor {
            user: "victor".into(),
            host: "mac".into(),
        };
        assert_eq!(requester(&by, None), by);
        assert_eq!(
            requester(&by, Some("alice@example.com (device d-1)".into())),
            Actor {
                user: "alice@example.com (device d-1)".into(),
                host: "mac".into(),
            }
        );
    }

    #[test]
    fn who_asked_may_start_with_a_dash_when_given_with_an_equals_sign() {
        use clap::Parser;
        #[derive(Parser)]
        struct Cli {
            #[command(flatten)]
            args: RuntimeArgs,
        }
        let parsed = Cli::try_parse_from([
            "enclos",
            "install",
            "hermes",
            "--sandbox",
            "lab",
            "--requested-by=-alice (device d-1)",
        ])
        .unwrap();
        let RuntimeVerb::Install { requested_by, .. } = parsed.args.verb else {
            panic!("not an install");
        };
        assert_eq!(requested_by.as_deref(), Some("-alice (device d-1)"));
    }

    #[test]
    fn an_install_may_be_given_a_time_limit_in_seconds() {
        use clap::Parser;
        #[derive(Parser)]
        struct Cli {
            #[command(flatten)]
            args: RuntimeArgs,
        }
        let limit = |args: &[&str]| {
            let parsed = Cli::try_parse_from(
                ["enclos", "install", "hermes", "--sandbox", "lab"]
                    .iter()
                    .chain(args),
            )
            .unwrap();
            let RuntimeVerb::Install { time_limit, .. } = parsed.args.verb else {
                panic!("not an install");
            };
            time_limit
        };
        assert_eq!(limit(&[]), None);
        assert_eq!(limit(&["--time-limit=3600"]), Some(3600));
    }

    #[test]
    fn an_update_parses_sandbox_and_hidden_flags() {
        use clap::Parser;
        #[derive(Parser)]
        struct Cli {
            #[command(flatten)]
            args: RuntimeArgs,
        }
        let parsed = Cli::try_parse_from([
            "enclos",
            "update",
            "lab",
            "--requested-by=-alice (device d-1)",
            "--time-limit=3600",
        ])
        .unwrap();
        let RuntimeVerb::Update {
            sandbox,
            time_limit,
            requested_by,
        } = parsed.args.verb
        else {
            panic!("not an update");
        };
        assert_eq!(sandbox.as_str(), "lab");
        assert_eq!(time_limit, Some(3600));
        assert_eq!(requested_by.as_deref(), Some("-alice (device d-1)"));
        // One runtime per sandbox: no --runtime flag.
        assert!(Cli::try_parse_from(["enclos", "update", "lab", "--runtime", "hermes"]).is_err());
    }

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
