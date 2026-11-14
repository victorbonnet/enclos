//! What the mobile app's bridge needs of the engine (ADR 0042, proposed):
//! where an agent's app channel listens, and the token that opens it.

use std::path::PathBuf;

use super::Engine;
use crate::error::{Error, Result};
use crate::model::audit::Actor;
use crate::model::channel::Channel;
use crate::model::sandbox::SandboxName;
use crate::model::secret::SecretValue;

/// Where to reach one agent's app channel, and the token it asks for.
pub struct AppEndpoint {
    pub socket: PathBuf,
    pub token: SecretValue,
}

impl Engine {
    pub fn app_layout(&self) -> crate::layout::Layout {
        self.layout.clone()
    }

    /// The socket of `agent`'s app channel in sandbox `name`, and the
    /// agent's token, read from the secret store now as the active policy
    /// grants it (`runtime configure <sandbox>/<agent> --channel app`).
    pub fn app_endpoint(&self, name: &SandboxName, agent: &str) -> Result<AppEndpoint> {
        self.require_sandbox(name)?;
        let variable = Channel::App.token_variable();
        let view = self.policy(name)?;
        let grants = view
            .snapshot
            .policy
            .agent_secrets
            .get(agent)
            .map(|grants| {
                grants
                    .iter()
                    .filter(|(v, _)| v.as_str() == variable)
                    .map(|(v, g)| (v.clone(), g.clone()))
                    .collect::<crate::model::policy::SecretGrants>()
            })
            .unwrap_or_default();
        if grants.is_empty() {
            return Err(Error::Session {
                what: format!(
                    "agent {name}/{agent} has no app channel: set one up with `enclos runtime configure {name}/{agent} --channel app`"
                ),
            });
        }
        let mut values = self.granted_values(&grants)?;
        let (_, token) = values.pop().expect("one grant, one value");
        Ok(AppEndpoint {
            socket: self.layout.agent_app_socket(name.as_str(), agent),
            token,
        })
    }

    /// Whether a removed agent has neither a native identity nor remaining data.
    /// Retained profile data makes this return false, including after --keep-data.
    /// A sandbox removed with its folder holds nothing of the agent's: true.
    /// One removed with `sandbox rm --keep-data` no longer records its
    /// runtime, so every runtime looks for the agent in the home it left.
    /// An error when enclos cannot tell, never a guess either way.
    pub(crate) fn app_agent_data_absent(
        &self,
        name: &SandboxName,
        agent: &crate::model::agent::AgentName,
    ) -> Result<bool> {
        let kinds = if self.state.get(name)?.is_some() {
            vec![self.runtime_of(name)?]
        } else {
            let folder = self.layout.sandbox_dir(name.as_str());
            match std::fs::symlink_metadata(&folder) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(true),
                Err(e) => {
                    return Err(Error::Session {
                        what: format!("cannot read {}: {e}", folder.display()),
                    });
                }
                Ok(_) => crate::model::runtime::RuntimeKind::ALL.to_vec(),
            }
        };
        let home = self.sandbox_home(name);
        for kind in kinds {
            let runtime = crate::runtime::adapter(kind);
            let left =
                super::agent_rm::leftover(runtime.as_ref(), &home, agent).map_err(|error| {
                    Error::Session {
                        what: error.to_string(),
                    }
                })?;
            if left != super::agent_rm::Leftover::Nothing {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Every agent of every sandbox whose active policy grants it an app
    /// channel token, as `(sandbox, agent, runtime)`.
    pub fn app_agents(&self) -> Result<Vec<(SandboxName, String, String)>> {
        let variable = Channel::App.token_variable();
        let mut agents = Vec::new();
        for view in self.list_sandboxes()? {
            let name = view.record.name.clone();
            let Ok(policy) = self.policy(&name) else {
                continue;
            };
            let runtime = self
                .runtime_of(&name)
                .map(|k| k.to_string())
                .unwrap_or_default();
            for (agent, grants) in &policy.snapshot.policy.agent_secrets {
                if grants.contains_key(variable) {
                    agents.push((name.clone(), agent.as_str().to_owned(), runtime.clone()));
                }
            }
        }
        Ok(agents)
    }

    /// The bridge's static key pair's file.
    pub fn app_key_path(&self) -> PathBuf {
        self.layout.app_bridge_key()
    }

    /// The file of the key the bridge signs runtime-approval decisions
    /// with (ADR 0060, proposed).
    pub fn app_approval_key_path(&self) -> PathBuf {
        self.layout.app_approval_key()
    }

    /// The public key (SEC1, base64url) the bridge signs runtime-approval
    /// decisions with, which `runtime configure --channel app` gives the
    /// plugin (ADR 0060, proposed): made when the bridge has none yet. A
    /// dry run, which writes nothing, names it instead of making it.
    pub fn app_approval_public_key(&self, confirm: super::Confirm) -> Result<String> {
        let path = self.app_approval_key_path();
        let key = match confirm {
            super::Confirm::DryRun => crate::bridge::keys::existing_approval_key(&path),
            _ => crate::bridge::keys::approval_key(&path).map(Some),
        }
        .map_err(|e| Error::Session {
            what: format!(
                "cannot read or make the bridge's key for runtime approvals, {}: {e}",
                path.display()
            ),
        })?;
        Ok(key.map_or_else(
            || "<the bridge's key for runtime approvals, made when this runs>".to_owned(),
            |key| key.public_text(),
        ))
    }

    /// The bridge's own database: conversations and their messages.
    pub fn app_store_path(&self) -> PathBuf {
        self.layout.app_store()
    }

    /// Runs `work`, a change to which devices reach the bridge (`app pair`,
    /// `app unpair`), as an audited command: its intent is in the audit log
    /// before the work starts, and when the log cannot be written the work
    /// does not run (ADR 0010).
    pub fn app_access<T>(
        &self,
        by: &Actor,
        command: &str,
        target: String,
        summary: impl FnOnce(&T) -> String,
        work: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        self.write(by, command, Some(target), summary, |_| work())
    }
}
