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
    /// Remove an agent and its files, with the runtime's own command; `--keep-data` keeps the files.
    Rm {
        agent: AgentTarget,
        /// Keep the agent's files in the sandbox home; remove only the record.
        #[arg(long)]
        keep_data: bool,
    },
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
            let added = engine.add_agent(by, &sandbox, agent)?;
            let name = &added.record.name;
            let runtime = runtime_name(engine, &sandbox);
            let adapter = engine.runtime(&sandbox)?.map(enclos::runtime::adapter);
            let talk = adapter.as_ref().map_or(String::new(), |a| a.talk(name));
            let login = adapter.as_ref().map_or(String::new(), |a| a.login());
            if added.adopted {
                println!(
                    "Tracked agent {sandbox}/{name}, which {runtime} already had. Talk to it with `enclos connect {sandbox} -- {talk}`."
                );
                return Ok(exit::OK);
            }
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
                "`{name} setup` is optional: the agent already uses the sandbox's login (`enclos connect {sandbox} -- {}`).",
                login
            );
        }
        AgentVerb::List { sandbox } => {
            let agents = engine.agents(&sandbox)?;
            let notes = check_notes(engine, &sandbox, true);
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
        AgentVerb::Rm { agent, keep_data } => {
            let AgentTarget { sandbox, agent } = agent;
            match engine.remove_agent(by, &sandbox, &agent, keep_data, confirm)? {
                Planned::DryRun(plan) => plan.changes.iter().for_each(|c| println!("Would {c}.")),
                Planned::Done(()) => println!("Removed agent {sandbox}/{agent}."),
            }
        }
    }
    Ok(exit::OK)
}

/// The runtime's name as people write it, for messages.
pub fn runtime_name(engine: &Engine, sandbox: &SandboxName) -> &'static str {
    engine
        .runtime(sandbox)
        .ok()
        .flatten()
        .map_or("The runtime", |r| r.display_name())
}

/// What differs between the agents the runtime has in the sandbox and the
/// ones enclos tracks, one line each, with what to do about it (ADR 0023).
/// `unnamed` adds the agents enclos cannot track by name, which only a
/// rename inside the sandbox changes.
pub fn check_notes(engine: &Engine, sandbox: &SandboxName, unnamed: bool) -> Vec<String> {
    let Ok(check) = engine.check_agents(sandbox) else {
        return Vec::new();
    };
    let runtime = runtime_name(engine, sandbox);
    let untracked = check.untracked.iter().map(|a| {
        format!("{sandbox}/{a}: made inside the sandbox, not tracked by enclos. Track it with `enclos agent add {sandbox}/{a}`.")
    });
    let unnamed = check.unnamed.iter().filter(|_| unnamed).map(|n| {
        format!("{runtime} has an agent named `{n}`, which enclos cannot track: agent names are a lowercase letter, then 1 to 40 lowercase letters, digits or hyphens.")
    });
    let missing = check.missing.iter().map(|a| {
        format!("{sandbox}/{a}: {runtime} no longer has this agent. Remove it with `enclos agent rm {sandbox}/{a}`.")
    });
    untracked.chain(unnamed).chain(missing).collect()
}
