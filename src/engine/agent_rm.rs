//! Removing an agent: its files with the runtime's own command, then its
//! record (design §10, ADR 0023).

use std::path::Path;

use super::Engine;
use super::removal::RemovalReview;
use crate::error::{Error, Result};
use crate::model::agent::AgentName;
use crate::model::audit::Actor;
use crate::model::plan::{Confirm, Plan, Planned};
use crate::model::runtime::RuntimeKind;
use crate::model::sandbox::SandboxName;
use crate::runtime::{RuntimeAdapter, RuntimeAgentName, SandboxCommand, Unreadable, adapter, home};

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
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilesKept {
    /// `--keep-data`, with what is left of the agent as enclos read it
    /// then, or why it could not.
    Asked {
        left: std::result::Result<Leftover, Unreadable>,
    },
    /// The runtime no longer listed the agent: nothing was left to delete.
    RuntimeLacksIt,
    /// The runtime has no command enclos can run to delete an agent: its
    /// files stay.
    NoDeleteCommand,
}

/// What is left of an agent in the sandbox home, as enclos reads it there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Leftover {
    /// The runtime lists the agent.
    Agent,
    /// The runtime no longer lists it, but its folder is still there, as a
    /// delete that stopped halfway leaves it: the runtime's delete finishes
    /// it.
    Folder,
    Nothing,
}

/// What is left of `agent` in `home`: whether the runtime lists it, then
/// whether its folder is there, looked at without following a link.
fn leftover(
    runtime: &dyn RuntimeAdapter,
    home: &Path,
    agent: &AgentName,
) -> std::result::Result<Leftover, Unreadable> {
    if runtime
        .agents_in(home)?
        .contains(&RuntimeAgentName::from(agent))
    {
        return Ok(Leftover::Agent);
    }
    let folder = runtime.agent_facts(&RuntimeAgentName::from(agent)).folder;
    Ok(match folder {
        Some(folder) if home::stat(home, &folder)?.is_some() => Leftover::Folder,
        _ => Leftover::Nothing,
    })
}

impl Engine {
    /// Removes an agent: its files, with the runtime's own command run in
    /// the sandbox (design §10), then its record. The delete runs while the
    /// runtime lists the agent, and also when only its folder is left, as a
    /// delete that stopped halfway leaves it. Only the record goes with
    /// `keep_data`, when nothing is left of the agent, or when the runtime
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
        self.remove_agent_with_review(by, name, agent, keep_data, confirm, None)
    }

    /// Removes the exact runtime profile reviewed for an explicit remote
    /// deletion. An untracked profile is deleted as it stands, never adopted
    /// or recreated. A tracked record whose files are already absent can be
    /// removed, with the distinct record-only outcome.
    pub(super) fn remove_existing_agent_reviewed(
        &self,
        by: &Actor,
        name: &SandboxName,
        agent: &AgentName,
        review: &RemovalReview,
    ) -> Result<Planned<AgentRemoved>> {
        if review.sandbox != *name || review.agent.as_ref() != Some(agent) {
            return Err(Error::Session {
                what: "The removal review names a different agent. Review this deletion again."
                    .to_owned(),
            });
        }
        self.remove_agent_with_review(by, name, agent, false, Confirm::Yes, Some(review))
    }

    fn remove_agent_with_review(
        &self,
        by: &Actor,
        name: &SandboxName,
        agent: &AgentName,
        keep_data: bool,
        confirm: Confirm,
        review: Option<&RemovalReview>,
    ) -> Result<Planned<AgentRemoved>> {
        match review {
            Some(review) => self.validate_agent_removal_start(review)?,
            None => {
                self.agent_of(name, agent.as_str())?;
            }
        }
        let kind = self.runtime_of(name)?;
        self.refuse_builtin(name, kind, agent.as_str())?;
        let shown = kind.display_name();
        let runtime = adapter(kind);
        let home = self.sandbox_home(name);
        let left = leftover(&*runtime, &home, agent);
        let delete = match (keep_data, &left) {
            (true, _) => Err(FilesKept::Asked { left: left.clone() }),
            (false, Err(why)) => return Err(cannot_tell_left(name, kind, agent, why)),
            (false, Ok(Leftover::Nothing)) => Err(FilesKept::RuntimeLacksIt),
            (false, Ok(_)) => runtime
                .delete_agent(agent)
                .ok_or(FilesKept::NoDeleteCommand),
        };
        if let Some(review) = review {
            match &delete {
                Err(FilesKept::RuntimeLacksIt) if review.tracked.is_none() => {
                    return Err(Error::Session {
                        what: format!(
                            "agent {name}/{agent} no longer has a runtime profile or an enclos record; nothing was adopted or deleted. Refresh before trying again"
                        ),
                    });
                }
                Err(FilesKept::NoDeleteCommand) => {
                    return Err(Error::Session {
                        what: format!(
                            "{shown} has no command enclos can run to delete agent {name}/{agent}; no files or records were removed"
                        ),
                    });
                }
                _ => {}
            }
        }
        let files = runtime.agent_files(agent);
        // The runtime's services may hold the agent's files (Hermes's
        // gateway serves every agent): they stop while the delete runs.
        let pausing = match &delete {
            Ok(_) => self.installed_runtime_services(name)?,
            Err(_) => Vec::new(),
        };
        let meanwhile = match pausing.as_slice() {
            [] => String::new(),
            units => format!(
                ", its service {} stopped meanwhile",
                units
                    .iter()
                    .map(|(u, _)| u.as_str())
                    .collect::<Vec<_>>()
                    .join(" and ")
            ),
        };
        match confirm {
            Confirm::DryRun => {
                let what = match &delete {
                    Ok(_) if left == Ok(Leftover::Folder) => format!(
                        "delete what is left of agent {name}/{agent} ({files}), which {shown} no longer lists, with {shown}'s own command"
                    ),
                    Ok(_) => format!(
                        "delete agent {name}/{agent} and its files, with {shown}'s own command"
                    ),
                    Err(FilesKept::Asked { left }) => match left {
                        Ok(Leftover::Agent) => format!(
                            "remove the record of agent {name}/{agent}; its files stay ({files})"
                        ),
                        Ok(Leftover::Folder) => format!(
                            "remove the record of agent {name}/{agent}; its folder stays ({files}), which {shown} no longer lists"
                        ),
                        Ok(Leftover::Nothing) => format!(
                            "remove the record of agent {name}/{agent}, which {shown} no longer has"
                        ),
                        Err(why) => format!(
                            "remove the record of agent {name}/{agent}; enclos cannot tell what is left of it: {why}"
                        ),
                    },
                    Err(FilesKept::RuntimeLacksIt) => format!(
                        "remove the record of agent {name}/{agent}, which {shown} no longer has"
                    ),
                    Err(FilesKept::NoDeleteCommand) => format!(
                        "remove the record of agent {name}/{agent}; {shown} has no command enclos can run to delete it, so its files stay ({files})"
                    ),
                };
                let stop = pausing.iter().map(|(_, l)| format!("stop service {l}"));
                let start = pausing
                    .iter()
                    .map(|(_, l)| format!("install service {l} again"));
                return Ok(Planned::DryRun(Plan {
                    changes: stop.chain([what]).chain(start).collect(),
                    ..Plan::default()
                }));
            }
            Confirm::Ask if delete.is_ok() => {
                return Err(Error::NeedsConfirmation {
                    what: format!("deleting agent {name}/{agent} and its files{meanwhile}"),
                });
            }
            _ => {}
        }
        // The runtime's commands run as sessions of their own, which take
        // the lock themselves; the record goes after them, below.
        let mut not_restarted = None;
        let deleted = match delete {
            Ok(command) => {
                let why = format!("for agent rm {name}/{agent}");
                if let Some(review) = review {
                    self.validate_agent_removal_start(review)?;
                }
                let paused = match review {
                    Some(review) => self.pause_runtime_checked(by, name, &why, || {
                        self.validate_agent_removal_start(review)
                    })?,
                    None => self.pause_runtime(by, name, &why)?,
                };
                let deleted = self.delete_files(by, name, agent, command, review);
                let resumed = match review {
                    Some(review) => self.resume_runtime_checked(by, name, paused, || {
                        self.validate_removal_sandbox_identity(review)
                    }),
                    None => self.resume_runtime(by, name, paused),
                };
                match (deleted, resumed) {
                    (Ok(()), resumed) => not_restarted = resumed.err(),
                    (Err(e), Ok(())) => return Err(e),
                    (Err(e), Err(r)) => {
                        return Err(Error::CleanupFailed {
                            error: Box::new(e),
                            left: r.to_string(),
                        });
                    }
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
                if let Some(review) = review {
                    self.validate_agent_removal_end(review, deleted.is_ok())?;
                    if review.tracked.is_none() {
                        return Ok(());
                    }
                } else {
                    self.agent_of(name, agent.as_str())?;
                }
                self.state.remove_agent(lock, name, agent).map_err(Into::into)
            },
        )
        .map_err(|e| match deleted {
            // The files are gone already: say so, so a second try is not
            // read as a runtime that never had the agent.
            Ok(()) if review.is_some_and(|review| review.tracked.is_none()) => Error::Session {
                what: format!(
                    "{shown} deleted the files of untracked agent {name}/{agent}, but enclos could not finalize the removal: {e}. Refresh the sandbox and check the remaining state on the host before trying again"
                ),
            },
            Ok(()) => Error::Session {
                what: format!(
                    "{shown} deleted agent {agent} and its files, but enclos could not remove its record: {e}. Run `enclos agent rm {name}/{agent}` again: it removes the record"
                ),
            },
            Err(_) => e,
        })?;
        if let Some(error) = not_restarted {
            return Err(Error::FailedAfter {
                error: Box::new(error),
                done: format!("deleting agent {name}/{agent} and its files, and its record"),
            });
        }
        Ok(Planned::Done(match deleted {
            Ok(()) => AgentRemoved::Deleted { kind },
            Err(why) => AgentRemoved::RecordOnly { kind, files, why },
        }))
    }

    /// Runs the runtime's `delete` of `agent` in the sandbox, then, when it
    /// failed after deleting the agent's files, the runtime's command that
    /// finishes such a delete, and checks that nothing of the agent is left.
    /// Each failure keeps the record and says what is left.
    fn delete_files(
        &self,
        by: &Actor,
        name: &SandboxName,
        agent: &AgentName,
        delete: SandboxCommand,
        review: Option<&RemovalReview>,
    ) -> Result<()> {
        let kind = self.runtime_of(name)?;
        let shown = kind.display_name();
        let runtime = adapter(kind);
        let home = self.sandbox_home(name);
        let files = runtime.agent_files(agent);
        let end = match review {
            Some(review) => self.run_in_sandbox_checked(by, name, delete, "agent rm run", || {
                self.validate_agent_removal_start(review)
            }),
            None => self.run_in_sandbox(by, name, delete, "agent rm run"),
        }?;
        let left = leftover(&*runtime, &home, agent)
            .map_err(|why| cannot_tell_left(name, kind, agent, &why))?;
        let how = |end: &super::SessionEnd| match end.signal {
            Some(signal) => format!("was ended by signal {signal}"),
            None => format!("exited with {}", end.exit),
        };
        let again = format!("`enclos agent rm {name}/{agent}` runs {shown}'s delete again");
        match (end.exit, left) {
            (0, Leftover::Nothing) => Ok(()),
            (_, Leftover::Nothing) => match runtime.finish_delete_agent(agent) {
                // The files are gone and the runtime says its delete is not
                // done: what it names finishes it.
                Some(finish) => {
                    let finish_shown = finish.shown();
                    let finished = match review {
                        Some(review) => {
                            self.run_in_sandbox_checked(by, name, finish, "agent rm run", || {
                                self.validate_agent_removal_finish(review)
                            })
                        }
                        None => self.run_in_sandbox(by, name, finish, "agent rm run"),
                    }?;
                    match finished.exit {
                        0 => Ok(()),
                        _ => Err(Error::Session {
                            what: format!(
                                "{shown} deleted the files of agent {agent}, but `{finish_shown}`, which finishes its delete, {}; its record stays. Run it with `enclos connect {name} -- {finish_shown}`, then `enclos agent rm {name}/{agent}` removes the record",
                                how(&finished)
                            ),
                        }),
                    }
                }
                None => Err(Error::Session {
                    what: format!(
                        "{shown}'s command to delete agent {agent} {}, though it no longer has the agent; its record stays. Its output above says why; `enclos agent rm {name}/{agent}` then removes the record",
                        how(&end)
                    ),
                }),
            },
            (0, Leftover::Agent) => Err(Error::Session {
                what: format!(
                    "{shown}'s command to delete agent {agent} exited 0, but {shown} still lists it; its record stays"
                ),
            }),
            (0, Leftover::Folder) => Err(Error::Session {
                what: format!(
                    "{shown}'s command to delete agent {agent} exited 0, but its folder ({files}) is still there; its record stays. {again}"
                ),
            }),
            (_, Leftover::Agent) => Err(Error::Session {
                what: format!(
                    "{shown}'s command to delete agent {agent} {}; its record stays. Look at what is left with {shown}'s own commands in `enclos connect {name}`; `--keep-data` removes only the record",
                    how(&end)
                ),
            }),
            (_, Leftover::Folder) => Err(Error::Session {
                what: format!(
                    "{shown}'s command to delete agent {agent} {} and left its folder ({files}), which {shown} no longer lists; its record stays. Its output above says why; {again}",
                    how(&end)
                ),
            }),
        }
    }
}

/// The error for an agent whose leftovers cannot be read.
fn cannot_tell_left(
    name: &SandboxName,
    kind: RuntimeKind,
    agent: &AgentName,
    why: &Unreadable,
) -> Error {
    Error::Session {
        what: format!(
            "enclos cannot read {}'s agents in sandbox {name} ({why}), so it cannot tell whether agent {agent} still has files to delete. `--keep-data` removes only the record",
            kind.display_name()
        ),
    }
}
