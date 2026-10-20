//! The engine's runtime calls: install a runtime in a sandbox and manage
//! its agents (design §9 "Runtime adapter"). Logging it in is the runtime's
//! own command, through `enclos connect` (ADR 0024).

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use sha2::{Digest, Sha256};

use super::Engine;
use super::policy::{adapter_layer, differences};
use super::session::SessionEnd;
use crate::error::{Error, Result};
use crate::layout::LayoutError;
use crate::model::agent::{AgentName, AgentRecord};
use crate::model::audit::Actor;
use crate::model::now;
use crate::model::plan::{Confirm, Plan, Planned};
use crate::model::policy::PolicyVersion;
use crate::model::runtime::RuntimeKind;
use crate::model::sandbox::SandboxName;
use crate::policy::file::PolicyFile;
use crate::runtime::{
    BuiltinAgent, HomeFile, RuntimeAdapter, RuntimeAgentName, SandboxCommand, Unreadable, adapter,
};

/// How `runtime install` ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallEnd {
    pub kind: RuntimeKind,
    /// How the installer's session ended.
    pub end: SessionEnd,
    /// Whether the runtime is now recorded as installed: the installer
    /// exited 0. Otherwise the sandbox is as before, without the runtime's
    /// destinations.
    pub installed: bool,
    /// The sandbox's active policy version afterwards.
    pub policy: u32,
}

/// What `agent add` did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentAdded {
    pub agent: AgentRecord,
    pub kind: RuntimeKind,
    pub how: Added,
}

/// How the record came to be (ADR 0023).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Added {
    /// The runtime created the agent; how its command ended.
    Created(SessionEnd),
    /// The runtime already had the agent, made inside the sandbox; only the
    /// record is new.
    Adopted,
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

/// What an install would change, worked out without changing anything.
struct InstallPlan {
    /// The sandbox's `policy.toml`.
    overrides: String,
    active: u32,
    /// The runtime's destinations the active policy does not allow yet.
    added: Vec<String>,
    /// What else the new version changes: edits to `policy.toml` not
    /// applied yet, or a newer template or built-in defaults.
    also: Vec<String>,
    proxy_runs: bool,
}

/// An installer larger than this is not the script enclos reviewed.
const INSTALLER_MAX_BYTES: u64 = 20 * 1024 * 1024;

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

/// What `agent add` does for the agent, decided from the runtime's list.
enum Adoption {
    /// The runtime already has it: record it only.
    Adopt,
    /// The runtime creates it with this command.
    Create(SandboxCommand),
}

impl Engine {
    /// The runtime installed in the sandbox.
    pub(super) fn runtime_of(&self, name: &SandboxName) -> Result<RuntimeKind> {
        let record = self.state.get(name)?.ok_or_else(|| Error::NoSuchSandbox {
            name: name.to_string(),
        })?;
        record.runtime.ok_or_else(|| Error::Session {
            what: format!("sandbox {name} has no runtime yet. Install one with `enclos runtime install hermes --sandbox {name}`"),
        })
    }

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
    fn refuse_builtin(&self, name: &SandboxName, kind: RuntimeKind, agent: &str) -> Result<()> {
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

    /// The runtime installed in the sandbox, if any.
    pub fn runtime(&self, name: &SandboxName) -> Result<Option<RuntimeKind>> {
        let record = self.state.get(name)?.ok_or_else(|| Error::NoSuchSandbox {
            name: name.to_string(),
        })?;
        Ok(record.runtime)
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

    /// Installs `kind` in the sandbox (ADR 0020): its destinations join the
    /// policy, its installer is downloaded on the host and run only if it is
    /// the reviewed one, inside the sandbox, through the proxy, in this
    /// terminal. The runtime is recorded as installed only when the
    /// installer exits 0; otherwise its destinations are taken out again.
    pub fn install_runtime(
        &self,
        by: &Actor,
        name: &SandboxName,
        kind: RuntimeKind,
        confirm: Confirm,
    ) -> Result<Planned<InstallEnd>> {
        self.install_runtime_with(by, name, adapter(kind).as_ref(), confirm)
    }

    /// `install_runtime` with the adapter given, so tests can install from
    /// a file of their own.
    pub(crate) fn install_runtime_with(
        &self,
        by: &Actor,
        name: &SandboxName,
        runtime: &dyn RuntimeAdapter,
        confirm: Confirm,
    ) -> Result<Planned<InstallEnd>> {
        let kind = runtime.kind();
        let plan = self.plan_install(name, runtime)?;
        match confirm {
            Confirm::DryRun => return Ok(Planned::DryRun(plan.describe(name, runtime))),
            Confirm::Ask if !plan.also.is_empty() => {
                return Err(needs_confirmation(kind, name, &plan.also));
            }
            _ => {}
        }
        // Outside the lock: a download takes long and changes no state. The
        // installer lands beside the home, where the sandbox cannot write.
        let command = self.stage_install(name, runtime)?;
        let target = format!("{name} {kind}");
        let version = self.write(
            by,
            "runtime install",
            Some(target.clone()),
            |v: &PolicyVersion| format!("policy v{}", v.version),
            |lock| {
                // Checked again under the lock: the policy may have changed.
                let plan = self.plan_install(name, runtime)?;
                if confirm == Confirm::Ask && !plan.also.is_empty() {
                    return Err(needs_confirmation(kind, name, &plan.also));
                }
                self.save_policy_for_runtime(lock, by, name, &plan.overrides, Some(kind))
            },
        )?;
        let end = match self.run_in_sandbox(by, name, command, "runtime installer") {
            Ok(end) => end,
            Err(e) => {
                self.undo_install(by, name, kind, &e.to_string())?;
                return Err(e);
            }
        };
        if end.exit != 0 {
            let why = format!("the installer exited with {}", end.exit);
            let policy = self.undo_install(by, name, kind, &why)?;
            return Ok(Planned::Done(InstallEnd {
                kind,
                end,
                installed: false,
                policy,
            }));
        }
        self.write(
            by,
            "runtime installed",
            Some(target),
            |_| "recorded".to_owned(),
            |lock| {
                let mut record = self.state.get(name)?.ok_or_else(|| Error::NoSuchSandbox {
                    name: name.to_string(),
                })?;
                record.runtime = Some(kind);
                self.state.put(lock, &record)?;
                Ok(())
            },
        )?;
        Ok(Planned::Done(InstallEnd {
            kind,
            end,
            installed: true,
            policy: version.version,
        }))
    }

    fn plan_install(
        &self,
        name: &SandboxName,
        runtime: &dyn RuntimeAdapter,
    ) -> Result<InstallPlan> {
        let kind = runtime.kind();
        let active = self.policy(name)?;
        let record = self.state.get(name)?.ok_or_else(|| Error::NoSuchSandbox {
            name: name.to_string(),
        })?;
        if let Some(other) = record.runtime.filter(|a| *a != kind) {
            return Err(Error::Session {
                what: format!(
                    "sandbox {name} already has {other}; one runtime per sandbox (ADR 0003)"
                ),
            });
        }
        let overrides = self.layout.read_policy(name.as_str())?;
        let snapshot = self.checked_policy_with(name, &overrides, Some(adapter_layer(kind)))?;
        let layer = PolicyFile::parse(&format!("{kind} adapter"), runtime.endpoints())?;
        let expected: Vec<&str> = layer.network.allow_add.iter().map(String::as_str).collect();
        let added = layer
            .network
            .allow_add
            .iter()
            .filter(|d| !active.snapshot.policy.net.allow.contains(d))
            .cloned()
            .collect();
        let also = differences(&active.snapshot.policy, &snapshot.policy, &expected);
        Ok(InstallPlan {
            overrides,
            active: active.version.version,
            added,
            also,
            proxy_runs: self.proxy_runs(name)?,
        })
    }

    /// After a failed install, the sandbox is as before: no runtime, and a
    /// policy without the runtime's destinations.
    fn undo_install(
        &self,
        by: &Actor,
        name: &SandboxName,
        kind: RuntimeKind,
        why: &str,
    ) -> Result<u32> {
        let version = self.write(
            by,
            "runtime install failed",
            Some(format!("{name} {kind}")),
            |v: &PolicyVersion| format!("{why}; policy back to v{}", v.version),
            |lock| {
                let mut record = self.state.get(name)?.ok_or_else(|| Error::NoSuchSandbox {
                    name: name.to_string(),
                })?;
                record.runtime = None;
                self.state.put(lock, &record)?;
                let overrides = self.layout.read_policy(name.as_str())?;
                self.save_policy_for_runtime(lock, by, name, &overrides, None)
            },
        )?;
        Ok(version.version)
    }

    /// Stages what an install needs in the sandbox's `installers/` folder,
    /// beside its home: the compiled policy denies the sandbox writes there
    /// (Seatbelt tests), which is what keeps the host's plain writes from
    /// following a link the sandbox planted. Returns the command that
    /// installs: it copies the adapter's files into the home from inside the
    /// sandbox, under its policy, then runs the installer.
    fn stage_install(
        &self,
        name: &SandboxName,
        runtime: &dyn RuntimeAdapter,
    ) -> Result<SandboxCommand> {
        let dir = self.layout.sandbox_dir(name.as_str()).join("installers");
        let io = |path: &Path| {
            let path = path.to_owned();
            move |source| Error::Layout(LayoutError::Io { path, source })
        };
        std::fs::create_dir_all(&dir).map_err(io(&dir))?;
        let files = runtime.home_files();
        let mut staged = Vec::new();
        for (i, file) in files.iter().enumerate() {
            if !file.path_is_inside_home() {
                return Err(Error::Session {
                    what: format!(
                        "the {} adapter names a file outside the sandbox home: {}",
                        runtime.kind(),
                        file.path
                    ),
                });
            }
            let path = dir.join(format!("home-{i}"));
            std::fs::write(&path, file.contents).map_err(io(&path))?;
            staged.push((path, file));
        }
        let installer = self.download_installer(&dir, runtime)?;
        let mut script = home_files_script(&staged);
        script.push_str("exec /bin/bash \"$0\" \"$@\"\n");
        let mut words: Vec<std::ffi::OsString> = vec![
            "/bin/sh".into(),
            "-c".into(),
            script.into(),
            installer.into_os_string(),
        ];
        words.extend(runtime.installer().args.iter().map(Into::into));
        Ok(SandboxCommand::new(words))
    }

    /// Downloads the runtime's installer on the host into `dir`, outside the
    /// sandbox home, and keeps it only if its SHA-256 is the reviewed one. It
    /// is downloaded under a name of its own and moved into place once
    /// checked, so an install already reading the file keeps what it opened.
    fn download_installer(&self, dir: &Path, runtime: &dyn RuntimeAdapter) -> Result<PathBuf> {
        let installer = runtime.installer();
        let path = dir.join(format!("{}-install.sh", runtime.kind()));
        let part = dir.join(format!(
            "{}-install.{}.part",
            runtime.kind(),
            std::process::id()
        ));
        let failed = |what: String| Error::Session { what };
        let status = Command::new("/usr/bin/curl")
            .args(["-fsSL", "--max-time", "120", "--max-filesize"])
            .arg(INSTALLER_MAX_BYTES.to_string())
            .arg("-o")
            .arg(&part)
            .arg(&installer.url)
            .stdin(Stdio::null())
            .status()
            .map_err(|e| failed(format!("cannot run curl: {e}")))?;
        if !status.success() {
            let _ = std::fs::remove_file(&part);
            return Err(failed(format!(
                "could not download {} ({status})",
                installer.url
            )));
        }
        let bytes = std::fs::read(&part)
            .map_err(|e| failed(format!("cannot read {}: {e}", part.display())))?;
        let got: String = Sha256::digest(&bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        if got != installer.sha256 {
            let _ = std::fs::remove_file(&part);
            return Err(failed(format!(
                "the {} installer at {} changed (sha256 {got}); enclos runs only the version it was reviewed against ({}). Update enclos",
                runtime.kind(),
                installer.url,
                installer.sha256
            )));
        }
        std::fs::rename(&part, &path).map_err(|e| {
            failed(format!(
                "cannot move the installer into place at {}: {e}",
                path.display()
            ))
        })?;
        Ok(path)
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
        // A new agent's alias would shadow a command of that name; an
        // adopted one already has its alias there.
        if let Adoption::Create(_) = adoption
            && let Some(path) = self.command_named(name, &agent)?
        {
            return Err(Error::Session {
                what: format!(
                    "`{agent}` is a command on the sandbox's PATH ({}); {shown} would shadow it with the agent's alias. Pick another name",
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
                Adoption::Create(command) => vec![
                    format!(
                        "run `{}` in sandbox {name} under policy v{}",
                        command.shown(),
                        self.policy(name)?.version.version
                    ),
                    format!("record agent {name}/{agent}"),
                ],
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
                Added::Created(created)
            }
        };
        let summary = match how {
            Added::Adopted => "adopted",
            Added::Created(_) => "added",
        };
        let record = self
            .write(
                by,
                "agent add",
                Some(format!("{name}/{agent}")),
                |_| summary.to_owned(),
                |lock| {
                    // Checked again under the lock: another add may have
                    // recorded it while the runtime worked, and a session in
                    // the sandbox may have deleted what is being adopted.
                    self.refuse_known_agent(name, &agent)?;
                    if how == Added::Adopted {
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
                    .is_ok_and(|agents| agents.iter().any(|p| p.name == agent));
                let next = if recorded {
                    "Another command recorded it meanwhile; there is nothing more to do".to_owned()
                } else {
                    match runtime.agents_in(&home) {
                        Ok(found) if runtime_has(&found) => format!(
                            "Run `enclos agent add {name}/{agent}` again: it adopts an agent {shown} already has"
                        ),
                        Ok(_) => format!("{shown} does not list it any more either"),
                        Err(why) => format!("enclos cannot read {shown}'s agents there: {why}"),
                    }
                };
                Error::Session {
                    what: format!(
                        "{shown} has agent {agent} in sandbox {name}, but enclos could not record it: {e}. {next}"
                    ),
                }
            })?;
        Ok(Planned::Done(AgentAdded {
            agent: record,
            kind,
            how,
        }))
    }

    fn refuse_known_agent(&self, name: &SandboxName, agent: &AgentName) -> Result<()> {
        if self.state.agents(name)?.iter().any(|p| p.name == *agent) {
            return Err(Error::Session {
                what: format!("sandbox {name} already has agent {agent}"),
            });
        }
        Ok(())
    }

    /// A command named `agent` on the sandbox's PATH, if there is one: the
    /// runtime's alias for the agent would shadow it inside the sandbox.
    fn command_named(&self, name: &SandboxName, agent: &AgentName) -> Result<Option<PathBuf>> {
        let record = self.state.get(name)?.ok_or_else(|| Error::NoSuchSandbox {
            name: name.to_string(),
        })?;
        let ctx = self.sandbox_context(name, record.proxy_port);
        let path = crate::backend::seatbelt::environment(&ctx)
            .into_iter()
            .find(|(k, _)| k == "PATH")
            .map(|(_, v)| v)
            .unwrap_or_default();
        Ok(std::env::split_paths(&path)
            .map(|dir| dir.join(agent.as_str()))
            .find(|file| file.exists()))
    }

    /// The sandbox's home folder, which is `~` for everything that runs in it.
    pub fn sandbox_home(&self, name: &SandboxName) -> PathBuf {
        self.layout.sandbox_home(name.as_str())
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

impl InstallPlan {
    fn describe(&self, name: &SandboxName, runtime: &dyn RuntimeAdapter) -> Plan {
        let kind = runtime.kind();
        let mut changes = Vec::new();
        match self.added.len() {
            0 if self.also.is_empty() => changes.push(format!(
                "keep the policy of sandbox {name} at v{}: it already allows what {kind} needs",
                self.active
            )),
            n => changes.push(format!(
                "allow the {n} destinations {kind} needs in sandbox {name}, as a new policy version: {}",
                self.added.join(", ")
            )),
        }
        changes.extend(self.also.iter().map(|c| format!("also {c}")));
        changes.push(format!(
            "download the {kind} installer from {} on this Mac and check its SHA-256 against the reviewed one",
            runtime.installer().url
        ));
        if !self.proxy_runs {
            changes.push(format!("start the proxy of sandbox {name}"));
        }
        changes.push(format!(
            "run the installer in sandbox {name} under that policy, in this terminal, and record {kind} as its runtime if the installer exits 0"
        ));
        Plan {
            changes,
            ..Plan::default()
        }
    }
}

fn needs_confirmation(kind: RuntimeKind, name: &SandboxName, also: &[String]) -> Error {
    Error::NeedsConfirmation {
        what: format!(
            "installing {kind} in sandbox {name} together with {} other changes to its policy ({})",
            also.len(),
            also.join("; ")
        ),
    }
}

/// The `sh` lines that copy staged files into the sandbox home. They run
/// inside the sandbox, so a link the sandbox planted can only lead where
/// the sandbox may write anyway. Whatever is at the target first goes
/// (a link, a folder), and the copy must leave a plain file.
pub(crate) fn home_files_script(staged: &[(PathBuf, &HomeFile)]) -> String {
    let mut script = String::from("set -e\n");
    for (path, file) in staged {
        let target = format!("\"$HOME\"/{}", sh_word(file.path));
        let mode = if file.executable { "700" } else { "600" };
        script.push_str(&format!(
            "mkdir -p \"$(dirname {target})\"\n\
             rm -rf -- {target}\n\
             cp {} {target} && test -f {target} && ! test -L {target} || {{ echo {} >&2; exit 1; }}\n\
             chmod {mode} {target}\n",
            sh_word(&path.display().to_string()),
            sh_word(&format!(
                "enclos: cannot put {} in the sandbox home: something the sandbox may not replace is in the way",
                file.path
            )),
        ));
    }
    script
}

/// `s` as one `sh` word.
fn sh_word(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}
