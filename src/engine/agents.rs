//! An agent of a sandbox: added, adopted, removed, and told apart from what
//! the runtime has (ADR 0023, ADR 0024); importing one from the host is in
//! `import.rs`.

use std::path::PathBuf;

use super::Engine;
use super::import::{Archive, LeftCopy};
use super::session::SessionEnd;
use crate::error::{Error, Result};
use crate::model::agent::{AgentName, AgentRecord};
use crate::model::audit::Actor;
use crate::model::now;
use crate::model::plan::{Confirm, Plan, Planned};
use crate::model::runtime::RuntimeKind;
use crate::model::sandbox::SandboxName;
use crate::runtime::{BuiltinAgent, RuntimeAgentName, SandboxCommand, Unreadable, adapter};

/// What `agent add` did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentAdded {
    pub agent: AgentRecord,
    pub kind: RuntimeKind,
    pub how: Added,
    /// What a person runs in the sandbox to talk to the agent.
    pub talk: String,
    /// What a person runs in the sandbox to log the runtime in and set it up.
    pub login: String,
}

/// How the record came to be: created, adopted (ADR 0023) or imported
/// (issue #34).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Added {
    /// The runtime created the agent; how its command ended.
    Created(SessionEnd),
    /// The runtime already had the agent, made inside the sandbox; only the
    /// record is new.
    Adopted,
    /// The runtime's own command imported it from an export made on the
    /// host, with `--from` (issue #34); how that command ended.
    Imported {
        end: SessionEnd,
        archive: Archive,
        /// enclos's copy of the archive beside the sandbox home, when it
        /// could not be removed: the sandbox can read it.
        copy_left: Option<LeftCopy>,
    },
}

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

/// The agents a runtime has in a sandbox, checked against the ones enclos
/// tracks (ADR 0023).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentCheck {
    Compared(AgentDiff),
    /// The runtime's list could not be read, so nothing was compared.
    Unreadable(Unreadable),
}

/// What differs between the runtime's agents and the records.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AgentDiff {
    /// Agents the runtime has that enclos does not track: usually made
    /// inside the sandbox with the runtime's own commands.
    pub untracked: Vec<AgentName>,
    /// Agents the runtime has under names that are not valid agent names,
    /// so enclos cannot track them.
    pub untrackable: Vec<RuntimeAgentName>,
    /// Agents enclos tracks that the runtime no longer has.
    pub missing: Vec<AgentName>,
}

/// What `agent add` does for the agent, decided from the runtime's list.
enum Adoption {
    /// The runtime already has it: record it only.
    Adopt,
    /// The runtime creates it with this command.
    Create(SandboxCommand),
}

impl Added {
    /// The `agent add` audit entry's outcome.
    fn outcome(&self) -> String {
        match self {
            Added::Created(_) => "added".to_owned(),
            Added::Adopted => "adopted".to_owned(),
            Added::Imported {
                archive, copy_left, ..
            } => {
                let mut outcome = format!(
                    "imported from {} (sha256 {})",
                    archive.path.display(),
                    archive.sha256
                );
                if let Some(copy) = copy_left {
                    outcome.push_str(&format!(
                        "; the copy at {} could not be removed: {}",
                        copy.path.display(),
                        copy.why
                    ));
                }
                outcome
            }
        }
    }
}

impl AgentDiff {
    /// `found` as the runtime lists them, against the records. `builtin` is
    /// the runtime's built-in agent: never untracked, since it needs no
    /// record.
    pub(crate) fn compare(
        found: &[RuntimeAgentName],
        tracked: &[AgentRecord],
        builtin: Option<BuiltinAgent>,
    ) -> AgentDiff {
        let mut diff = AgentDiff::default();
        let builtin = builtin.map(BuiltinAgent::runtime_name);
        for name in found.iter().filter(|n| Some(*n) != builtin.as_ref()) {
            match name.as_str().parse::<AgentName>() {
                Ok(agent) if tracked.iter().any(|t| t.name == agent) => {}
                Ok(agent) => diff.untracked.push(agent),
                Err(_) => diff.untrackable.push(name.clone()),
            }
        }
        diff.missing = tracked
            .iter()
            .filter(|t| !found.contains(&RuntimeAgentName::from(&t.name)))
            .map(|t| t.name.clone())
            .collect();
        diff
    }

    /// Nothing differs.
    pub fn is_clean(&self) -> bool {
        self.untracked.is_empty() && self.untrackable.is_empty() && self.missing.is_empty()
    }
}

impl Engine {
    pub(super) fn agent_of(&self, name: &SandboxName, agent: &str) -> Result<AgentRecord> {
        let kind = self.runtime_of(name)?;
        self.refuse_builtin(name, kind, agent)?;
        let tracked = self
            .state
            .agents(name)?
            .into_iter()
            .find(|p| p.name.as_str() == agent);
        tracked.ok_or_else(|| {
            let runtime = kind.display_name();
            let what = match adapter(kind).agents_in(&self.sandbox_home(name)) {
                Ok(found) if found.iter().any(|n| n.as_str() == agent) => format!(
                    "enclos does not track agent `{agent}`, which {runtime} has in sandbox {name}. Track it with `enclos agent add {name}/{agent}`, or remove it with {runtime}'s own commands in `enclos connect {name}`"
                ),
                Ok(_) => format!(
                    "sandbox {name} has no agent `{agent}`. Add it with `enclos agent add {name}/{agent}`"
                ),
                Err(why) => format!(
                    "sandbox {name} has no agent `{agent}`, and enclos cannot read {runtime}'s agents there to tell whether it was made inside the sandbox: {why}"
                ),
            };
            Error::Session { what }
        })
    }

    /// The runtime's built-in agent comes and goes with the runtime: enclos
    /// neither adds nor removes it.
    pub(super) fn refuse_builtin(
        &self,
        name: &SandboxName,
        kind: RuntimeKind,
        agent: &str,
    ) -> Result<()> {
        let runtime = adapter(kind);
        if let Some(builtin) = runtime.builtin_agent()
            && builtin.as_str() == agent
        {
            return Err(Error::Session {
                what: format!(
                    "agent `{agent}` is {}'s built-in agent: it exists as long as the runtime is installed in sandbox {name}, so enclos neither adds nor removes it. Talk to it with `enclos connect {name} -- {}`",
                    kind.display_name(),
                    runtime.talk(&builtin.agent_name())
                ),
            });
        }
        Ok(())
    }

    /// The runtime's built-in agent in this sandbox, if it has one.
    pub fn builtin_agent(&self, name: &SandboxName) -> Result<Option<BuiltinAgent>> {
        Ok(self
            .runtime(name)?
            .and_then(|kind| adapter(kind).builtin_agent()))
    }

    /// Compares the agents the runtime has in the sandbox with the ones
    /// enclos tracks (ADR 0023), or says why it could not read them.
    pub fn check_agents(&self, name: &SandboxName) -> Result<AgentCheck> {
        let kind = self.runtime_of(name)?;
        let tracked = self.state.agents(name)?;
        let runtime = adapter(kind);
        Ok(match runtime.agents_in(&self.sandbox_home(name)) {
            Ok(found) => AgentCheck::Compared(AgentDiff::compare(
                &found,
                &tracked,
                runtime.builtin_agent(),
            )),
            Err(why) => AgentCheck::Unreadable(why),
        })
    }

    /// Adds an agent: the runtime creates it inside the sandbox, and enclos
    /// records it. An agent the runtime already has, made inside the
    /// sandbox, is only recorded (ADR 0023). Nothing else changes: the
    /// policy and the proxy are the sandbox's (ADR 0024).
    pub fn add_agent(
        &self,
        by: &Actor,
        name: &SandboxName,
        agent: AgentName,
        confirm: Confirm,
    ) -> Result<Planned<AgentAdded>> {
        let kind = self.runtime_of(name)?;
        let runtime = adapter(kind);
        let shown = kind.display_name();
        self.refuse_builtin(name, kind, agent.as_str())?;
        self.refuse_known_agent(name, &agent)?;
        let home = self.sandbox_home(name);
        let runtime_has =
            |found: &[RuntimeAgentName]| found.contains(&RuntimeAgentName::from(&agent));
        // An agent made inside the sandbox with the runtime's own commands
        // is adopted as it is: creating it again would fail (ADR 0023).
        // When the list cannot be read, enclos cannot tell which, and says
        // so rather than run the runtime on a guess.
        let adoption = match runtime.agents_in(&home) {
            Ok(found) if runtime_has(&found) => Adoption::Adopt,
            Ok(_) => Adoption::Create(runtime.create_agent(&agent)),
            Err(why) => {
                return Err(Error::Session {
                    what: format!(
                        "enclos cannot read {shown}'s agents in sandbox {name} ({why}), so it cannot tell whether agent {agent} is already there. Look at the sandbox home with `enclos connect {name}` first"
                    ),
                });
            }
        };
        // A new agent's alias would collide with a command of that name; an
        // adopted one already has its alias there.
        if let Adoption::Create(_) = adoption
            && let Some(path) = self.command_named(name, &agent)?
        {
            return Err(Error::Session {
                what: format!(
                    "`{agent}` is a command on the sandbox's PATH ({}); {shown} would not give the agent its alias. Pick another name",
                    path.display()
                ),
            });
        }
        let files = runtime.agent_files(&agent);
        if confirm == Confirm::DryRun {
            let changes = match &adoption {
                Adoption::Adopt => vec![format!(
                    "record agent {name}/{agent}, which {shown} already has in the sandbox"
                )],
                Adoption::Create(command) => {
                    let version = self.policy(name)?.version.version;
                    std::iter::once(command)
                        .chain(&runtime.after_create_agent(&agent))
                        .map(|c| {
                            format!(
                                "run `{}` in sandbox {name} under policy v{version}",
                                c.shown()
                            )
                        })
                        .chain([format!("record agent {name}/{agent}")])
                        .collect()
                }
            };
            return Ok(Planned::DryRun(Plan {
                changes,
                ..Plan::default()
            }));
        }
        let how = match adoption {
            Adoption::Adopt => Added::Adopted,
            Adoption::Create(command) => {
                let created = self.run_in_sandbox(by, name, command, "agent create")?;
                if created.exit != 0 {
                    return Err(Error::Session {
                        what: format!(
                            "{shown} could not create agent {agent} (exit {}): its output above says why. If it says the agent already exists, its files are in the sandbox home at {files}: remove them with {shown}'s own commands (`enclos connect {name}`) and add the agent again",
                            created.exit
                        ),
                    });
                }
                for then in runtime.after_create_agent(&agent) {
                    let shown_then = then.shown();
                    let ended = self.run_in_sandbox(by, name, then, "agent create")?;
                    if ended.exit != 0 {
                        return Err(Error::FailedAfter {
                            error: Box::new(Error::Session {
                                what: format!(
                                    "`{shown_then}` exited with {} in sandbox {name}: its output above says why. Run it with `enclos connect {name} -- {shown_then}`, then `enclos agent add {name}/{agent}`, which tracks the agent as it is",
                                    ended.exit
                                ),
                            }),
                            done: format!("creating agent {agent} in sandbox {name}"),
                        });
                    }
                }
                Added::Created(created)
            }
        };
        let record = self.record_agent(by, name, &agent, kind, &how)?;
        Ok(Planned::Done(AgentAdded {
            agent: record,
            kind,
            how,
            talk: runtime.talk(&agent),
            login: runtime.login(),
        }))
    }

    /// Records an agent the runtime now has, as one `agent add` audit entry
    /// whose outcome says how it came to be. Under the lock it checks again
    /// that no other command recorded the agent meanwhile and, for an
    /// adopted one, that the runtime still has it. When the record fails,
    /// the runtime keeps the agent either way, so the error says what the
    /// state and the runtime show now.
    pub(super) fn record_agent(
        &self,
        by: &Actor,
        name: &SandboxName,
        agent: &AgentName,
        kind: RuntimeKind,
        how: &Added,
    ) -> Result<AgentRecord> {
        let runtime = adapter(kind);
        let shown = kind.display_name();
        let home = self.sandbox_home(name);
        let runtime_has =
            |found: &[RuntimeAgentName]| found.contains(&RuntimeAgentName::from(agent));
        self.write(
            by,
            "agent add",
            Some(format!("{name}/{agent}")),
            |_| how.outcome(),
            |lock| {
                // Checked again under the lock: another add may have
                // recorded it while the runtime worked, and a session in
                // the sandbox may have deleted what is being adopted.
                self.refuse_known_agent(name, agent)?;
                if *how == Added::Adopted {
                    match runtime.agents_in(&home) {
                        Ok(found) if runtime_has(&found) => {}
                        Ok(_) => {
                            return Err(Error::Session {
                                what: format!("{shown} no longer has agent {agent} in sandbox {name}"),
                            });
                        }
                        Err(why) => {
                            return Err(Error::Session {
                                what: format!("enclos cannot read {shown}'s agents in sandbox {name} any more: {why}"),
                            });
                        }
                    }
                }
                let added = AgentRecord {
                    name: agent.clone(),
                    created_at: now(),
                };
                self.state.insert_agent(lock, name, &added)?;
                Ok(added)
            },
        )
        .map_err(|e| {
            // Already failing: what the state and the runtime say now
            // only words what to do next.
            let recorded = self
                .state
                .agents(name)
                .is_ok_and(|agents| agents.iter().any(|p| p.name == *agent));
            let next = if recorded {
                "Another command recorded it meanwhile; there is nothing more to do".to_owned()
            } else {
                match runtime.agents_in(&home) {
                    Ok(found) if runtime_has(&found) => {
                        let mut next = format!(
                            "Run `enclos agent add {name}/{agent}` again: it adopts an agent {shown} already has"
                        );
                        if let Added::Imported { .. } = how {
                            next.push_str(" (without --from); the archive's SHA-256 is in the `agent import` audit entry");
                        }
                        next
                    }
                    Ok(_) => format!("{shown} does not list it any more either"),
                    Err(why) => format!("enclos cannot read {shown}'s agents there: {why}"),
                }
            };
            Error::Session {
                what: format!(
                    "{shown} has agent {agent} in sandbox {name}, but enclos could not record it: {e}. {next}"
                ),
            }
        })
    }

    /// A command named `agent` on the sandbox's PATH, if there is one: the
    /// runtime's alias for the agent would collide with it.
    pub(super) fn command_named(
        &self,
        name: &SandboxName,
        agent: &AgentName,
    ) -> Result<Option<PathBuf>> {
        let record = self.state.get(name)?.ok_or_else(|| Error::NoSuchSandbox {
            name: name.to_string(),
        })?;
        let ctx = self.sandbox_context(name, record.proxy_port);
        let loopback = crate::backend::environment::Loopback::Hosts;
        let path = crate::backend::environment::variables(&ctx, loopback)
            .into_iter()
            .find(|(k, _)| k == "PATH")
            .map(|(_, v)| v)
            .unwrap_or_default();
        Ok(std::env::split_paths(&path)
            .map(|dir| dir.join(agent.as_str()))
            .find(|file| file.exists()))
    }

    pub(super) fn refuse_known_agent(&self, name: &SandboxName, agent: &AgentName) -> Result<()> {
        if self.state.agents(name)?.iter().any(|p| p.name == *agent) {
            return Err(Error::Session {
                what: format!("sandbox {name} already has agent {agent}"),
            });
        }
        Ok(())
    }

    pub fn agents(&self, name: &SandboxName) -> Result<Vec<AgentRecord>> {
        self.runtime_of(name)?;
        Ok(self.state.agents(name)?)
    }

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
