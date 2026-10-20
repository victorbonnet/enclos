//! `enclos agent`: the runtime's agents in a sandbox.

use std::str::FromStr;

use clap::{Args, Subcommand};

use enclos::engine::Engine;
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
    /// Add an agent, such as `lab/main`: the runtime creates it in the sandbox.
    Add { agent: AgentTarget },
    /// List a sandbox's agents.
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
            super::connect::report_end(&sandbox, &added.end);
            let name = &added.agent.name;
            let runtime = enclos::runtime::adapter(added.kind);
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
            if agents.is_empty() {
                println!(
                    "Sandbox {sandbox} has no agents yet. Add one with `enclos agent add {sandbox}/main`."
                );
            }
            for p in agents {
                println!("{sandbox}/{}", p.name);
            }
        }
        AgentVerb::Rm { agent } => {
            let AgentTarget { sandbox, agent } = agent;
            match engine.remove_agent(by, &sandbox, &agent, confirm)? {
                Planned::DryRun(plan) => {
                    plan.changes.iter().for_each(|c| println!("Would {c}."));
                }
                Planned::Done(removed) => {
                    println!(
                        "Removed the record of agent {sandbox}/{agent}. Its files stay in the sandbox home ({}); remove them with {}'s own commands in `enclos connect {sandbox}`.",
                        removed.files,
                        removed.kind.display_name()
                    );
                }
            }
        }
    }
    Ok(exit::OK)
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
