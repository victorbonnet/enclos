//! `enclos agent`: the runtime's agents in a sandbox.

use std::path::PathBuf;
use std::str::FromStr;

use clap::{Args, Subcommand};
use serde_json::json;

use super::output;

use enclos::engine::{Added, AgentCheck, AgentRemoved, Engine, FilesKept};
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
    /// sandbox, imports it with --from, or enclos tracks one the runtime
    /// already has there.
    Add {
        agent: AgentTarget,
        /// An export the runtime's own command made on the host (for Hermes, `hermes profile export`); the runtime imports it inside the sandbox.
        #[arg(long, value_name = "ARCHIVE")]
        from: Option<PathBuf>,
    },
    /// List a sandbox's agents, and report the ones made inside it that
    /// enclos does not track.
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
        AgentVerb::Add { agent, from } => {
            let AgentTarget { sandbox, agent } = agent;
            let planned = match &from {
                Some(archive) => engine.import_agent(by, &sandbox, agent, archive, confirm)?,
                None => engine.add_agent(by, &sandbox, agent, confirm)?,
            };
            let added = match planned {
                Planned::DryRun(plan) if output::json() => {
                    output::emit(&output::plan(&plan));
                    return Ok(exit::OK);
                }
                Planned::DryRun(plan) => {
                    plan.changes.iter().for_each(|c| println!("Would {c}."));
                    return Ok(exit::OK);
                }
                Planned::Done(added) => added,
            };
            let name = &added.agent.name;
            let runtime = enclos::runtime::adapter(added.kind);
            let kind = added.kind.display_name();
            if output::json() {
                let (how, session, archive, copy_left) = match &added.how {
                    Added::Adopted => ("adopted", None, None, None),
                    Added::Created(end) => ("created", Some(output::session(end)), None, None),
                    Added::Imported {
                        end,
                        archive,
                        copy_left,
                    } => (
                        "imported",
                        Some(output::session(end)),
                        Some(json!({
                            "path": output::path(&archive.path),
                            "sha256": archive.sha256,
                        })),
                        copy_left.as_ref().map(ToString::to_string),
                    ),
                };
                output::emit(&json!({
                    "agent": format!("{sandbox}/{name}"),
                    "runtime": added.kind.to_string(),
                    "how": how,
                    "session": session,
                    "archive": archive,
                    "copy_left": copy_left,
                    "talk": format!("enclos connect {sandbox} -- {}", runtime.talk(name)),
                    "home": output::path(&engine.sandbox_home(&sandbox)),
                }));
                return Ok(exit::OK);
            }
            match &added.how {
                Added::Adopted => {
                    println!(
                        "Tracked agent {sandbox}/{name}, which {kind} already had. Talk to it with `enclos connect {sandbox} -- {}`.",
                        runtime.talk(name)
                    );
                    return Ok(exit::OK);
                }
                Added::Created(end) => {
                    super::connect::report_end(&sandbox, end);
                    println!("\nAdded agent {sandbox}/{name}.\n");
                }
                Added::Imported {
                    end,
                    archive,
                    copy_left,
                } => {
                    super::connect::report_end(&sandbox, end);
                    println!(
                        "\nImported agent {sandbox}/{name} from {} (sha256 {}).\n",
                        archive.path.display(),
                        archive.sha256
                    );
                    if let Some(copy) = copy_left {
                        eprintln!("enclos: {copy}.\n");
                    }
                }
            }
            let imported = matches!(added.how, Added::Imported { .. });
            let shell = format!("enclos connect {sandbox}");
            let talk = format!("{shell} -- {}", runtime.talk(name));
            let w = talk.len() + 3;
            if imported {
                println!("Commands to run inside the sandbox:");
            } else {
                // The runtime's own output above, after creating an agent,
                // suggests commands and `~` paths that only work inside the
                // sandbox.
                println!("{kind}'s next steps above are commands to run inside the sandbox:");
            }
            println!("  {talk:<w$}talk to the agent");
            println!("  {shell:<w$}a shell in the sandbox, for {kind}'s own commands");
            println!(
                "There, ~ is the sandbox's home: {}",
                engine.sandbox_home(&sandbox).display()
            );
            let login = format!("`enclos connect {sandbox} -- {}`", runtime.login());
            if imported {
                // That an imported agent uses the sandbox's login is still
                // to verify (design §14).
                println!(
                    "enclos copied no login in: the agent should use the sandbox's {kind} login, made with {login}. If it asks for one of its own, its configuration names another provider: change it with {kind}'s own commands inside the sandbox."
                );
                println!(
                    "Until secrets are granted per sandbox (milestone 2), values such as a bot token go in the agent's files inside the sandbox."
                );
                println!(
                    "Nothing in the archive widened the sandbox's policy: what the agent reaches shows in `enclos net log {sandbox}`, and what was refused in `enclos net denied {sandbox}`."
                );
            } else {
                println!(
                    "The agent shares the sandbox's {kind} login, made with {login}; it needs no login of its own."
                );
            }
        }
        AgentVerb::List { sandbox } => {
            let agents = engine.agents(&sandbox)?;
            let notes = check_notes(engine, &sandbox, true)?;
            let builtin = engine.builtin_agent(&sandbox)?;
            if output::json() {
                output::emit(&json!({
                    "sandbox": sandbox.to_string(),
                    "builtin": builtin.map(|b| b.to_string()),
                    "agents": agents.iter().map(|a| a.name.to_string()).collect::<Vec<_>>(),
                    "notes": notes,
                }));
                return Ok(exit::OK);
            }
            if let Some(b) = builtin {
                println!("{sandbox}/{b}  built in");
            }
            if builtin.is_none() && agents.is_empty() && notes.is_empty() {
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
            let removed = match engine.remove_agent(by, &sandbox, &agent, keep_data, confirm)? {
                Planned::DryRun(plan) if output::json() => {
                    output::emit(&output::plan(&plan));
                    return Ok(exit::OK);
                }
                Planned::DryRun(plan) => {
                    plan.changes.iter().for_each(|c| println!("Would {c}."));
                    return Ok(exit::OK);
                }
                Planned::Done(removed) => removed,
            };
            if output::json() {
                let (files_removed, files, kept_because) = match &removed {
                    AgentRemoved::Deleted { .. } => (true, None, None),
                    AgentRemoved::RecordOnly { files, why, .. } => (
                        false,
                        Some(files.to_string()),
                        Some(match why {
                            FilesKept::Asked => "asked",
                            FilesKept::RuntimeLacksIt => "runtime_lacks_it",
                            FilesKept::NoDeleteCommand => "no_delete_command",
                        }),
                    ),
                };
                output::emit(&json!({
                    "agent": format!("{sandbox}/{agent}"),
                    "removed": true,
                    "files_removed": files_removed,
                    "files": files,
                    "files_kept_because": kept_because,
                }));
                return Ok(exit::OK);
            }
            match removed {
                AgentRemoved::Deleted { .. } => {
                    println!("Removed agent {sandbox}/{agent} and its files.")
                }
                AgentRemoved::RecordOnly { kind, files, why } => {
                    let runtime = kind.display_name();
                    match why {
                        FilesKept::Asked => println!(
                            "Removed the record of agent {sandbox}/{agent}. Its files stay in the sandbox home ({files}), so {runtime} still has the agent and enclos reports it as one it does not track; `enclos agent add {sandbox}/{agent}` tracks it again."
                        ),
                        FilesKept::RuntimeLacksIt => println!(
                            "Removed the record of agent {sandbox}/{agent}, which {runtime} no longer had."
                        ),
                        FilesKept::NoDeleteCommand => println!(
                            "Removed the record of agent {sandbox}/{agent}. {runtime} has no command enclos can run to delete an agent, so its files stay in the sandbox home ({files}); remove them with {runtime}'s own commands in `enclos connect {sandbox}`."
                        ),
                    }
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
