//! `enclos agent`: the runtime's agents in a sandbox.

use clap::{Args, Subcommand};

use enclos::engine::Engine;
use enclos::error::{Error, Result, exit};
use enclos::model::agent::AgentName;
use enclos::model::audit::Actor;
use enclos::model::sandbox::SandboxName;

use super::target::Target;

#[derive(Args)]
pub struct AgentArgs {
    #[command(subcommand)]
    verb: AgentVerb,
}

#[derive(Subcommand)]
enum AgentVerb {
    /// Add an agent, such as `home/main`: the runtime creates it, and it gets its own proxy port.
    Add { target: Target },
    /// List a sandbox's agents.
    List { sandbox: SandboxName },
    /// Remove an agent's record and port; its files stay in the sandbox home.
    Rm { target: Target },
}

fn agent_of(target: &Target) -> Result<AgentName> {
    let name = target.agent.as_deref().ok_or_else(|| Error::Session {
        what: format!(
            "name the agent: `{}/<agent>`, such as {}/main",
            target.sandbox, target.sandbox
        ),
    })?;
    name.parse().map_err(|e| Error::Session {
        what: format!("{e}"),
    })
}

pub fn run(engine: &Engine, by: &Actor, args: AgentArgs) -> Result<u8> {
    match args.verb {
        AgentVerb::Add { target } => {
            let sandbox = &target.sandbox;
            let added = engine.add_agent(by, sandbox, agent_of(&target)?)?;
            let runtime = engine.show_sandbox(sandbox)?.record.runtime;
            let runtime = runtime.map_or("The runtime".to_owned(), |r| r.display_name().to_owned());
            let name = &added.name;
            let shell = format!("enclos connect {sandbox}");
            let talk = format!("enclos connect {sandbox}/{name}");
            let w = talk.len() + 3;
            // The runtime's own output above suggests commands and `~` paths
            // that only work inside the sandbox.
            println!(
                "\nAdded agent {sandbox}/{name} (proxy port {}).\n",
                added.port
            );
            println!("{runtime}'s next steps above are commands to run inside the sandbox:");
            println!("  {shell:<w$}a shell in the sandbox, for commands such as `{name} chat`");
            println!("  {talk:<w$}talk to the agent directly");
            println!(
                "There, ~ is the sandbox's home: {}",
                engine.sandbox_home(sandbox).display()
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
                println!("{sandbox}/{}  port {}", p.name, p.port);
            }
        }
        AgentVerb::Rm { target } => {
            let name = agent_of(&target)?;
            engine.remove_agent(by, &target.sandbox, &name)?;
            println!("Removed agent {}/{name}.", target.sandbox);
        }
    }
    Ok(exit::OK)
}
