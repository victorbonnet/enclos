//! `enclos agent`: the runtime's agents in a sandbox.

use std::str::FromStr;

use clap::{Args, Subcommand};

use enclos::engine::{Added, AgentCheck, Engine};
use enclos::error::{Result, exit};
use enclos::model::agent::AgentName;
use enclos::model::audit::Actor;
use enclos::model::plan::{Confirm, Planned};
use enclos::model::sandbox::SandboxName;

#[derive(Args)]
pub struct AgentArgs {
    #[command(subcommand)]
    verb: AgentVerb,
}

#[derive(Subcommand)]
enum AgentVerb {
    /// Add an agent, such as `lab/main`: the runtime creates it in the
    /// sandbox, or enclos tracks one the runtime already has there.
    Add { agent: AgentTarget },
    /// List a sandbox's agents, and report the ones made inside it that
    /// enclos does not track.
    List { sandbox: SandboxName },
    /// Remove an agent's record; its files stay in the sandbox home.
    Rm { agent: AgentTarget },
}

/// An agent of a sandbox, as the agent commands name it: `lab/main`.
#[derive(Debug, Clone)]
struct AgentTarget {
    sandbox: SandboxName,
    agent: AgentName,
}

impl FromStr for AgentTarget {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let (sandbox, agent) = s.split_once('/').ok_or_else(|| {
            format!("`{s}`: name the agent as <sandbox>/<agent>, such as lab/main")
        })?;
        Ok(AgentTarget {
            sandbox: sandbox.parse().map_err(|e| format!("{e}"))?,
            agent: agent.parse().map_err(|e| format!("{e}"))?,
        })
    }
}

pub fn run(engine: &Engine, by: &Actor, confirm: Confirm, args: AgentArgs) -> Result<u8> {
    match args.verb {
        AgentVerb::Add { agent } => {
            let AgentTarget { sandbox, agent } = agent;
            let added = match engine.add_agent(by, &sandbox, agent, confirm)? {
                Planned::DryRun(plan) => {
                    plan.changes.iter().for_each(|c| println!("Would {c}."));
                    return Ok(exit::OK);
                }
                Planned::Done(added) => added,
            };
            let name = &added.agent.name;
            let runtime = enclos::runtime::adapter(added.kind);
            match &added.how {
                Added::Created(end) => super::connect::report_end(&sandbox, end),
                Added::Adopted => {
                    println!(
                        "Tracked agent {sandbox}/{name}, which {} already had. Talk to it with `enclos connect {sandbox} -- {}`.",
                        added.kind.display_name(),
                        runtime.talk(name)
                    );
                    return Ok(exit::OK);
                }
            }
            let shell = format!("enclos connect {sandbox}");
            let talk = format!("{shell} -- {}", runtime.talk(name));
            let w = talk.len() + 3;
            // The runtime's own output above suggests commands and `~` paths
            // that only work inside the sandbox.
            println!("\nAdded agent {sandbox}/{name}.\n");
            println!(
                "{}'s next steps above are commands to run inside the sandbox:",
                added.kind.display_name()
            );
            println!("  {talk:<w$}talk to the agent");
            println!(
                "  {shell:<w$}a shell in the sandbox, for {}'s own commands",
                added.kind.display_name()
            );
            println!(
                "There, ~ is the sandbox's home: {}",
                engine.sandbox_home(&sandbox).display()
            );
            println!(
                "The agent shares the sandbox's {} login, made with `enclos connect {sandbox} -- {}`; it needs no login of its own.",
                added.kind.display_name(),
                runtime.login()
            );
        }
        AgentVerb::List { sandbox } => {
            let agents = engine.agents(&sandbox)?;
            let notes = check_notes(engine, &sandbox, true)?;
            if agents.is_empty() && notes.is_empty() {
                println!(
                    "Sandbox {sandbox} has no agents yet. Add one with `enclos agent add {sandbox}/main`."
                );
            }
            for p in &agents {
                println!("{sandbox}/{}", p.name);
            }
            if !agents.is_empty() && !notes.is_empty() {
                println!();
            }
            notes.iter().for_each(|n| println!("{n}"));
        }
        AgentVerb::Rm { agent } => {
            let AgentTarget { sandbox, agent } = agent;
            match engine.remove_agent(by, &sandbox, &agent, confirm)? {
                Planned::DryRun(plan) => {
                    plan.changes.iter().for_each(|c| println!("Would {c}."));
                }
                Planned::Done(removed) => {
                    let runtime = removed.kind.display_name();
                    println!(
                        "Removed the record of agent {sandbox}/{agent}. Its files stay in the sandbox home ({}), so {runtime} still has the agent and enclos reports it as one it does not track; remove it with {runtime}'s own commands in `enclos connect {sandbox}`.",
                        removed.files
                    );
                }
            }
        }
    }
    Ok(exit::OK)
}

/// What differs between the agents the runtime has in the sandbox and the
/// ones enclos tracks, one line each, with what to do about it, or the one
/// line saying the runtime's list could not be read (ADR 0023). Empty for a
/// sandbox without a runtime. `show_untrackable` adds the agents enclos
/// cannot track by name, which only a rename inside the sandbox changes.
pub fn check_notes(
    engine: &Engine,
    sandbox: &SandboxName,
    show_untrackable: bool,
) -> Result<Vec<String>> {
    let Some(kind) = engine.runtime(sandbox)? else {
        return Ok(Vec::new());
    };
    let runtime = kind.display_name();
    let diff = match engine.check_agents(sandbox)? {
        AgentCheck::Compared(diff) => diff,
        AgentCheck::Unreadable(why) => {
            return Ok(vec![format!(
                "enclos cannot read {runtime}'s agents in sandbox {sandbox}: {why}. Agents made inside the sandbox are not reported."
            )]);
        }
    };
    let untracked = diff.untracked.iter().map(|a| {
        format!("{sandbox}/{a}: {runtime} has this agent; enclos does not track it. Track it with `enclos agent add {sandbox}/{a}`.")
    });
    let untrackable = diff
        .untrackable
        .iter()
        .filter(|_| show_untrackable)
        .map(|n| {
            let why = n
                .as_str()
                .parse::<AgentName>()
                .expect_err("untrackable: not an agent name");
            format!("{runtime} has an agent enclos cannot track: {why}.")
        });
    let missing = diff.missing.iter().map(|a| {
        format!("{sandbox}/{a}: {runtime} no longer has this agent. Remove its record with `enclos agent rm {sandbox}/{a}`.")
    });
    Ok(untracked.chain(untrackable).chain(missing).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_agent_is_named_sandbox_slash_agent_and_both_parts_follow_the_rule() {
        let target: AgentTarget = "lab/main".parse().unwrap();
        assert_eq!(
            (target.sandbox.as_str(), target.agent.as_str()),
            ("lab", "main")
        );
        for bad in [
            "main",
            "lab/",
            "/main",
            "lab/main/extra",
            "lab/../x",
            "lab/a;b",
            "lab/$(x)",
            "Lab/main",
            "lab/-x",
        ] {
            assert!(bad.parse::<AgentTarget>().is_err(), "{bad}");
        }
    }
}
