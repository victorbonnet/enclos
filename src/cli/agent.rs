//! `enclos agent`: the runtime's agents in a sandbox.

use std::str::FromStr;

use clap::{Args, Subcommand};

use enclos::engine::Engine;
use enclos::error::{Result, exit};
use enclos::model::agent::AgentName;
use enclos::model::audit::Actor;
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

pub fn run(engine: &Engine, by: &Actor, args: AgentArgs) -> Result<u8> {
    match args.verb {
        AgentVerb::Add { agent } => {
            let AgentTarget { sandbox, agent } = agent;
            let added = engine.add_agent(by, &sandbox, agent)?;
            let name = &added.name;
            let kind = engine.show_sandbox(&sandbox)?.record.runtime;
            let runtime = kind.map_or("The runtime", |r| r.display_name());
            let talk = kind.map_or(String::new(), |k| enclos::runtime::adapter(k).talk(name));
            let shell = format!("enclos connect {sandbox}");
            let talk = format!("{shell} -- {talk}");
            let w = talk.len() + 3;
            // The runtime's own output above suggests commands and `~` paths
            // that only work inside the sandbox.
            println!("\nAdded agent {sandbox}/{name}.\n");
            println!("{runtime}'s next steps above are commands to run inside the sandbox:");
            println!("  {talk:<w$}talk to the agent");
            println!("  {shell:<w$}a shell in the sandbox, for commands such as `{name} model`");
            println!(
                "There, ~ is the sandbox's home: {}",
                engine.sandbox_home(&sandbox).display()
            );
            println!(
                "`{name} setup` is optional: the agent already uses the sandbox's login (`enclos runtime login {sandbox}`)."
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
            engine.remove_agent(by, &agent.sandbox, &agent.agent)?;
            println!("Removed agent {}/{}.", agent.sandbox, agent.agent);
        }
    }
    Ok(exit::OK)
}
