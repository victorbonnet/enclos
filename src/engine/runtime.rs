//! The engine's runtime calls: install a runtime in a sandbox and manage
//! its agents (design §9 "Runtime adapter"). Logging it in is the runtime's
//! own command, through `enclos connect` (ADR 0024); importing an agent
//! from the host is in `import.rs`.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use sha2::{Digest, Sha256};

use super::Engine;
use super::import::{Archive, LeftCopy};
use super::policy::{adapter_layer, differences, listen_change};
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
    /// Whether this install succeeded: its installer exited 0, and the
    /// runtime is recorded because of it.
    pub installed: bool,
    /// The runtime the sandbox records afterwards. After a failed install it
    /// is the one it had before, and the active policy allows that runtime's
    /// destinations only: none after a failed first install, this runtime
    /// after a failed reinstall.
    pub recorded: Option<RuntimeKind>,
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
    /// Whether the runtime's layer turns listening on, and the new policy
    /// listens where the active one does not (ADR 0028).
    listens: bool,
    /// Whether the runtime's layer turns listening on and `policy.toml`
    /// keeps it off, so the runtime's service cannot start.
    listen_kept_off: bool,
    /// What else the new version changes: edits to `policy.toml` not
    /// applied yet, or a newer template or built-in defaults.
    also: Vec<String>,
    proxy_runs: bool,
}

/// An installer larger than this is not an install script: refused.
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
    /// policy, its installer is downloaded on the host, as the runtime serves
    /// it then (ADR 0029), and run inside the sandbox, through the proxy, in
    /// this terminal. The audit entry names the installer's SHA-256. The runtime is recorded as installed only when the
    /// installer exits 0; otherwise the record keeps the runtime it had and
    /// the policy is resolved again from `policy.toml` with that runtime's
    /// destinations. Files written in the home stay either way.
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
        let (command, sha256) = self.stage_install(name, runtime)?;
        let target = format!("{name} {kind}");
        let version = self.write(
            by,
            "runtime install",
            Some(target.clone()),
            |v: &PolicyVersion| format!("policy v{}, installer sha256 {sha256}", v.version),
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
            let (policy, recorded) = self.undo_install(by, name, kind, &why)?;
            return Ok(Planned::Done(InstallEnd {
                kind,
                end,
                installed: false,
                recorded,
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
                // A change made while the installer ran was resolved without
                // the runtime's destinations, as it was not recorded yet.
                self.resolve_with_runtime(lock, by, name)
                    .map_err(|error| Error::FailedAfter {
                        error: Box::new(error),
                        done: format!(
                            "recording {kind} as installed in sandbox {name}; a policy change made while its installer ran was not resolved again with {kind}'s destinations, which the next change of the policy, such as `enclos policy edit {name}`, does"
                        ),
                    })
            },
        )?;
        Ok(Planned::Done(InstallEnd {
            kind,
            end,
            installed: true,
            recorded: Some(kind),
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
        // The install resolves `policy.toml`, which holds the pending
        // change: it would be in force without the restart it needs.
        if active.pending.is_some() {
            return Err(Error::PolicyPending {
                sandbox: name.to_string(),
            });
        }
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
        let snapshot = self.checked_policy_with(
            name,
            &overrides,
            Some(adapter_layer(kind)),
            self.recorded_backend(name)?,
        )?;
        let layer = PolicyFile::parse(&format!("{kind} adapter"), runtime.endpoints())?;
        let expected: Vec<&str> = layer.network.allow_add.iter().map(String::as_str).collect();
        let added = layer
            .network
            .allow_add
            .iter()
            .filter(|d| !active.snapshot.policy.net.allow.contains(d))
            .cloned()
            .collect();
        let mut also = differences(&active.snapshot.policy, &snapshot.policy, &expected);
        // Listening the adapter's layer turns on is what the runtime brings,
        // like its destinations (ADR 0028); any other change of it is an edit
        // of `policy.toml`, which stays an "also" change. Kept off by
        // `policy.toml`, the runtime's service cannot start, which the plan
        // says.
        let asks = layer.network.listen == Some(true);
        let listening = snapshot.policy.net.listen;
        if asks && listening {
            also.retain(|c| *c != listen_change(true));
        }
        Ok(InstallPlan {
            overrides,
            active: active.version.version,
            added,
            listens: asks && listening && !active.snapshot.policy.net.listen,
            listen_kept_off: asks && !listening,
            also,
            proxy_runs: self.proxy_runs(name)?,
        })
    }

    /// After a failed install, the policy is resolved again with the
    /// runtime the record has: an install records its runtime only on
    /// success, so that is the one the sandbox had before, none or the same
    /// one, unless another install succeeded meanwhile. Returns the
    /// active version and that runtime.
    fn undo_install(
        &self,
        by: &Actor,
        name: &SandboxName,
        kind: RuntimeKind,
        why: &str,
    ) -> Result<(u32, Option<RuntimeKind>)> {
        let (version, recorded) = self.write(
            by,
            "runtime install failed",
            Some(format!("{name} {kind}")),
            |(v, recorded): &(PolicyVersion, Option<RuntimeKind>)| match recorded {
                Some(kept) => format!(
                    "{why}; {kept} still recorded as installed, under policy v{}",
                    v.version
                ),
                None => format!("{why}; policy v{} without {kind}'s destinations", v.version),
            },
            |lock| {
                let record = self.state.get(name)?.ok_or_else(|| Error::NoSuchSandbox {
                    name: name.to_string(),
                })?;
                // A change saved as pending while the installer ran stays
                // pending.
                Ok((self.resolve_again(lock, by, name)?, record.runtime))
            },
        )?;
        Ok((version.version, recorded))
    }

    /// Stages what an install needs in the sandbox's `installers/` folder,
    /// beside its home: the compiled policy denies the sandbox writes there
    /// (Seatbelt tests), which is what keeps the host's plain writes from
    /// following a link the sandbox planted. Returns the command that
    /// installs: it copies the adapter's files into the home from inside the
    /// sandbox, under its policy, then runs the installer, with the
    /// installer's SHA-256.
    fn stage_install(
        &self,
        name: &SandboxName,
        runtime: &dyn RuntimeAdapter,
    ) -> Result<(SandboxCommand, String)> {
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
        let (installer, sha256) = self.download_installer(&dir, runtime)?;
        let mut script = home_files_script(&staged);
        script.push_str("exec /bin/bash \"$0\" \"$@\"\n");
        let mut words: Vec<OsString> = vec![
            "/bin/sh".into(),
            "-c".into(),
            script.into(),
            installer.into_os_string(),
        ];
        words.extend(runtime.installer().args.iter().map(Into::into));
        Ok((SandboxCommand::new(words), sha256))
    }

    /// Downloads the runtime's installer on the host into `dir`, outside the
    /// sandbox home, with its SHA-256, which the audit entry names. Any
    /// version is run (ADR 0029), so the file is named after its hash: an
    /// install running at the same time that got another version moves its
    /// own to another path, and the bytes this install runs are the ones its
    /// entry names. It is downloaded under a name of its own and moved into
    /// place once read.
    fn download_installer(
        &self,
        dir: &Path,
        runtime: &dyn RuntimeAdapter,
    ) -> Result<(PathBuf, String)> {
        let installer = runtime.installer();
        let part = dir.join(format!(
            "{}-install.{}.part",
            runtime.kind(),
            std::process::id()
        ));
        let failed = |what: String| Error::Session { what };
        let status = Command::new("/usr/bin/curl")
            .args(download_args(&installer.url, &part, cfg!(test)))
            .stdin(Stdio::null())
            .status()
            .map_err(|e| failed(format!("cannot run curl: {e}")))?;
        if !status.success() {
            let _ = std::fs::remove_file(&part);
            // curl exits 1, unsupported protocol, when `--proto` or
            // `--proto-redir` refuses the URL or a redirect.
            return Err(failed(if status.code() == Some(1) {
                format!(
                    "could not download {}: it is not served over HTTPS, or redirects off HTTPS, and enclos downloads installers over HTTPS only. Update enclos, or report it if the {} installer moved",
                    installer.url,
                    runtime.kind()
                )
            } else {
                format!("could not download {} ({status})", installer.url)
            }));
        }
        let bytes = std::fs::read(&part)
            .map_err(|e| failed(format!("cannot read {}: {e}", part.display())))?;
        let sha256 = hex(&Sha256::digest(&bytes));
        let path = dir.join(format!("{}-install-{sha256}.sh", runtime.kind()));
        std::fs::rename(&part, &path).map_err(|e| {
            failed(format!(
                "cannot move the installer into place at {}: {e}",
                path.display()
            ))
        })?;
        Ok((path, sha256))
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

    pub(super) fn refuse_known_agent(&self, name: &SandboxName, agent: &AgentName) -> Result<()> {
        if self.state.agents(name)?.iter().any(|p| p.name == *agent) {
            return Err(Error::Session {
                what: format!("sandbox {name} already has agent {agent}"),
            });
        }
        Ok(())
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
            0 if self.also.is_empty() && !self.listens && !self.listen_kept_off => {
                changes.push(format!(
                    "keep the policy of sandbox {name} at v{}: it already allows what {kind} needs",
                    self.active
                ))
            }
            0 if self.also.is_empty() && !self.listens => changes.push(format!(
                "keep the policy of sandbox {name} at v{}",
                self.active
            )),
            0 => changes.push(format!(
                "change the policy of sandbox {name} for {kind}, as a new policy version"
            )),
            n => changes.push(format!(
                "allow the {n} destinations {kind} needs in sandbox {name}, as a new policy version: {}",
                self.added.join(", ")
            )),
        }
        if self.listens {
            changes.push(format!(
                "let sandbox {name} listen on TCP for {kind} (ADR 0028): any port but enclos's proxy ports, on every address, and anything in it can serve the network"
            ));
        }
        if self.listen_kept_off {
            changes.push(format!(
                "keep sandbox {name} from listening, as its policy.toml sets `listen = false`: {kind}'s service cannot start without it (ADR 0028)"
            ));
        }
        changes.extend(self.also.iter().map(|c| format!("also {c}")));
        changes.push(format!(
            "download the {kind} installer from {} on this Mac, as it is served now (ADR 0029), and record its SHA-256",
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

/// `bytes` as lowercase hex: how enclos writes a SHA-256.
pub(super) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
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

/// The arguments of the curl that downloads an installer from `url` to
/// `out`. `-q` comes first, the only place curl reads it, so no `.curlrc`
/// adds options; curl's environment variables, such as `https_proxy`, still
/// apply. The download and every redirect must stay on HTTPS, so curl
/// refuses any other URL, except a `file://` one when `allow_file` is set:
/// only this crate's tests set it, to install from a file. The SHA-256 check
/// after it is what decides whether the file is run.
fn download_args(url: &str, out: &Path, allow_file: bool) -> Vec<OsString> {
    let proto = if allow_file && url.starts_with("file://") {
        "=file"
    } else {
        "=https"
    };
    vec![
        "-q".into(),
        "--proto".into(),
        proto.into(),
        "--proto-redir".into(),
        "=https".into(),
        "-fsSL".into(),
        "--max-time".into(),
        "120".into(),
        "--max-filesize".into(),
        INSTALLER_MAX_BYTES.to_string().into(),
        "-o".into(),
        out.into(),
        url.into(),
    ]
}

/// `s` as one `sh` word.
fn sh_word(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_installer_download_reads_no_curlrc_and_stays_on_https() {
        for url in [
            "https://example.com/install.sh",
            "http://example.com/install.sh",
        ] {
            let args = download_args(url, Path::new("/tmp/x.part"), false);
            let args: Vec<&str> = args.iter().map(|a| a.to_str().unwrap()).collect();
            // curl reads `-q` only as its first argument.
            assert_eq!(args[0], "-q", "{args:?}");
            let pair = |flag: &str, value: &str| args.windows(2).any(|w| w == [flag, value]);
            assert!(pair("--proto", "=https"), "{args:?}");
            assert!(pair("--proto-redir", "=https"), "{args:?}");
            assert!(args.contains(&"-fsSL"), "{args:?}");
            assert!(
                pair("--max-filesize", &INSTALLER_MAX_BYTES.to_string()),
                "{args:?}"
            );
            assert!(pair("-o", "/tmp/x.part"), "{args:?}");
            assert_eq!(args.last(), Some(&url));
        }
    }

    #[test]
    fn a_release_build_refuses_an_installer_url_to_a_file() {
        let args = download_args("file:///etc/hosts", Path::new("/tmp/x.part"), false);
        let args: Vec<&str> = args.iter().map(|a| a.to_str().unwrap()).collect();
        assert!(
            args.windows(2).any(|w| w == ["--proto", "=https"]),
            "{args:?}"
        );
        assert!(!args.contains(&"=file"), "{args:?}");
        // Only a `file://` URL gets the tests' exception.
        let args = download_args("http://example.com/x", Path::new("/tmp/x.part"), true);
        assert!(!args.contains(&OsString::from("=file")), "{args:?}");
    }

    #[test]
    fn the_host_curl_reads_no_curlrc_for_an_installer_download() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(".curlrc"),
            "write-out = \"CURLRC-READ\\n\"\n",
        )
        .unwrap();
        let src = dir.path().join("install.sh");
        std::fs::write(&src, "echo hi\n").unwrap();
        let out = dir.path().join("install.part");
        let url = format!("file://{}", src.display());
        let curl = |args: &[OsString]| {
            let output = Command::new("/usr/bin/curl")
                .args(args)
                .env("CURL_HOME", dir.path())
                .env("HOME", dir.path())
                .env_remove("XDG_CONFIG_HOME")
                .stdin(Stdio::null())
                .output()
                .unwrap();
            assert!(output.status.success(), "{output:?}");
            String::from_utf8_lossy(&output.stdout).into_owned()
        };
        let args = download_args(&url, &out, true);
        assert!(!curl(&args).contains("CURLRC-READ"));
        assert_eq!(std::fs::read_to_string(&out).unwrap(), "echo hi\n");
        // Without `-q` the same curl reads it, so the check above can fail.
        assert!(curl(&args[1..]).contains("CURLRC-READ"));
    }
}
