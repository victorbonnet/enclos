//! Removing an agent: its files with the runtime's own command, then its
//! record (design §10, ADR 0023).

use super::Engine;
use crate::error::{Error, Result};
use crate::model::agent::AgentName;
use crate::model::audit::Actor;
use crate::model::plan::{Confirm, Plan, Planned};
use crate::model::runtime::RuntimeKind;
use crate::model::sandbox::SandboxName;
use crate::runtime::{RuntimeAgentName, Unreadable, adapter};

/// What `agent rm` did. The record is gone either way.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentRemoved {
    /// The runtime's own command deleted the agent and its files.
    Deleted { kind: RuntimeKind },
    /// Only the record went.
    RecordOnly {
        kind: RuntimeKind,
        /// Where the agent's files are, relative to the sandbox home.
        files: String,
        why: FilesKept,
    },
}

/// Why `agent rm` removed only the record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilesKept {
    /// `--keep-data`: the runtime still has the agent.
    Asked,
    /// The runtime no longer listed the agent: nothing was left to delete.
    RuntimeLacksIt,
    /// The runtime has no command enclos can run to delete an agent: its
    /// files stay.
    NoDeleteCommand,
}

impl Engine {
    /// Removes an agent: its files, with the runtime's own command run in
    /// the sandbox (design §10), then its record. Only the record goes with
    /// `keep_data`, when the runtime no longer lists the agent, or when it
    /// has no command to delete one. Refuses the runtime's built-in agent,
    /// and refuses when the runtime's list cannot be read (ADR 0023), since
    /// enclos cannot tell whether files are left, unless `keep_data` asks
    /// for the record alone. Deleting files asks for confirmation first.
    pub fn remove_agent(
        &self,
        by: &Actor,
        name: &SandboxName,
        agent: &AgentName,
        keep_data: bool,
        confirm: Confirm,
    ) -> Result<Planned<AgentRemoved>> {
        self.agent_of(name, agent.as_str())?;
        let kind = self.runtime_of(name)?;
        let shown = kind.display_name();
        let runtime = adapter(kind);
        let home = self.sandbox_home(name);
        let listed = |found: &[RuntimeAgentName]| found.contains(&RuntimeAgentName::from(agent));
        let unreadable = |why: &Unreadable| Error::Session {
            what: format!(
                "enclos cannot read {shown}'s agents in sandbox {name} ({why}), so it cannot tell whether agent {agent} still has files to delete. `--keep-data` removes only the record"
            ),
        };
        let delete = match (keep_data, runtime.agents_in(&home)) {
            (true, _) => Err(FilesKept::Asked),
            (false, Ok(found)) if listed(&found) => runtime
                .delete_agent(agent)
                .ok_or(FilesKept::NoDeleteCommand),
            (false, Ok(_)) => Err(FilesKept::RuntimeLacksIt),
            (false, Err(why)) => return Err(unreadable(&why)),
        };
        let files = runtime.agent_files(agent);
        match confirm {
            Confirm::DryRun => {
                let what = match &delete {
                    Ok(_) => format!(
                        "delete agent {name}/{agent} and its files, with {shown}'s own command"
                    ),
                    Err(FilesKept::Asked) => {
                        format!(
                            "remove the record of agent {name}/{agent}; its files stay ({files})"
                        )
                    }
                    Err(FilesKept::RuntimeLacksIt) => format!(
                        "remove the record of agent {name}/{agent}, which {shown} no longer has"
                    ),
                    Err(FilesKept::NoDeleteCommand) => format!(
                        "remove the record of agent {name}/{agent}; {shown} has no command enclos can run to delete it, so its files stay ({files})"
                    ),
                };
                return Ok(Planned::DryRun(Plan {
                    changes: vec![what],
                    ..Plan::default()
                }));
            }
            Confirm::Ask if delete.is_ok() => {
                return Err(Error::NeedsConfirmation {
                    what: format!("deleting agent {name}/{agent} and its files"),
                });
            }
            _ => {}
        }
        let deleted = match delete {
            Ok(command) => {
                // The runtime's command runs as its own session, which takes
                // the lock itself; the record goes after it, below.
                let end = self.run_in_sandbox(by, name, command, "agent rm run")?;
                if end.exit != 0 {
                    let how = match end.signal {
                        Some(signal) => format!("was ended by signal {signal}"),
                        None => format!("exited with {}", end.exit),
                    };
                    return Err(Error::Session {
                        what: format!(
                            "{shown}'s command to delete agent {agent} {how}; its record stays. Look at what is left with {shown}'s own commands in `enclos connect {name}`; `--keep-data` removes only the record"
                        ),
                    });
                }
                match runtime.agents_in(&home) {
                    Ok(found) if listed(&found) => {
                        return Err(Error::Session {
                            what: format!(
                                "{shown}'s command to delete agent {agent} exited 0, but {shown} still lists it; its record stays"
                            ),
                        });
                    }
                    Ok(_) => {}
                    Err(why) => return Err(unreadable(&why)),
                }
                Ok(())
            }
            Err(why) => Err(why),
        };
        self.write(
            by,
            "agent rm",
            Some(format!("{name}/{agent}")),
            |_| {
                match deleted {
                    Ok(()) => "deleted",
                    Err(_) => "removed the record",
                }
                .to_owned()
            },
            |lock| {
                self.agent_of(name, agent.as_str())?;
                self.state
                    .remove_agent(lock, name, agent)
                    .map_err(Into::into)
            },
        )
        .map_err(|e| match deleted {
            // The files are gone already: say so, so a second try is not
            // read as a runtime that never had the agent.
            Ok(()) => Error::Session {
                what: format!(
                    "{shown} deleted agent {agent} and its files, but enclos could not remove its record: {e}. Run `enclos agent rm {name}/{agent}` again: it removes the record"
                ),
            },
            Err(_) => e,
        })?;
        Ok(Planned::Done(match deleted {
            Ok(()) => AgentRemoved::Deleted { kind },
            Err(why) => AgentRemoved::RecordOnly { kind, files, why },
        }))
    }
}
