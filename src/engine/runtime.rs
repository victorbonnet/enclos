//! The engine's runtime calls: install a runtime in a sandbox (design §9
//! "Runtime adapter"). What the install puts beside the home is in
//! `staging.rs`, and a runtime's agents are in `agents.rs`. Logging it in is
//! the runtime's own command, through `enclos connect` (ADR 0024).

use std::path::PathBuf;

use super::Engine;
use super::policy::{adapter_layer, differences, listen_change};
use super::session::SessionEnd;
use crate::error::{Error, Result};
use crate::model::agent::AgentName;
use crate::model::audit::Actor;
use crate::model::plan::{Confirm, Plan, Planned};
use crate::model::policy::PolicyVersion;
use crate::model::runtime::RuntimeKind;
use crate::model::sandbox::SandboxName;
use crate::policy::file::PolicyFile;
use crate::runtime::{RuntimeAdapter, adapter};

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
    /// What a person runs in the sandbox to log `kind` in and set it up,
    /// even after a failed install.
    pub login: String,
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

    /// The runtime installed in the sandbox, if any.
    pub fn runtime(&self, name: &SandboxName) -> Result<Option<RuntimeKind>> {
        let record = self.state.get(name)?.ok_or_else(|| Error::NoSuchSandbox {
            name: name.to_string(),
        })?;
        Ok(record.runtime)
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
                login: runtime.login(),
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
            login: runtime.login(),
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
