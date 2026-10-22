//! The engine's secret calls (design §12, ADR 0022): store a sandbox's
//! secret, list and remove them, and give the secrets a policy grants to a
//! session as it starts.

use super::Engine;
use crate::error::{Error, Result};
use crate::model::audit::Actor;
use crate::model::plan::{Confirm, Plan, Planned};
use crate::model::policy::Policy;
use crate::model::sandbox::SandboxName;
use crate::model::secret::{SecretRecord, SecretRef};

/// What `secret set` did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretSet {
    /// False when it replaced the value of a secret already set.
    pub new: bool,
    /// The variables the active policy gives it as.
    pub granted_as: Vec<String>,
    /// How many sessions run with the value it had: they keep it until they
    /// restart.
    pub running: usize,
}

/// A secret of a sandbox, as `secret list` prints it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretView {
    pub record: SecretRecord,
    /// The variables the active policy gives it as.
    pub granted_as: Vec<String>,
    /// The variables the pending policy gives it as, when one waits.
    pub pending_as: Option<Vec<String>>,
}

impl Engine {
    /// Stores `value` as `secret`, in the secret store, and records that
    /// the sandbox has it; its value goes nowhere else. A session receives
    /// it only once its policy grants it, from its next start.
    pub fn secret_set(
        &self,
        by: &Actor,
        secret: &SecretRef,
        value: &str,
        confirm: Confirm,
    ) -> Result<Planned<SecretSet>> {
        self.require_sandbox(&secret.sandbox)?;
        if value.is_empty() || value.contains('\0') {
            return Err(Error::Session {
                what: format!(
                    "the value of secret {secret} is {}; a secret is set as an environment variable, which holds text without NUL",
                    if value.is_empty() {
                        "empty"
                    } else {
                        "not text without NUL"
                    }
                ),
            });
        }
        let known = self
            .state
            .secrets(&secret.sandbox)?
            .iter()
            .any(|s| s.secret == *secret);
        if confirm == Confirm::DryRun {
            let what = match known {
                true => format!("replace the value of secret {secret} in the Keychain"),
                false => format!("store secret {secret} in the Keychain"),
            };
            return Ok(Planned::DryRun(Plan {
                changes: vec![what],
                ..Plan::default()
            }));
        }
        let set = self.write(
            by,
            "secret set",
            Some(secret.to_string()),
            |s: &SecretSet| match s.new {
                true => "stored in the secret store".to_owned(),
                false => "value replaced in the secret store".to_owned(),
            },
            |lock| {
                self.secrets.set(secret, value)?;
                let new = self.state.put_secret(lock, secret)?;
                let (_, active) = self.active_policy(&secret.sandbox)?;
                let granted_as = granted_as(&active.policy, secret);
                let running = match granted_as.is_empty() {
                    true => 0,
                    false => self.sessions_under_rules(&secret.sandbox)?.len(),
                };
                Ok(SecretSet {
                    new,
                    granted_as,
                    running,
                })
            },
        )?;
        Ok(Planned::Done(set))
    }

    /// The sandbox's secrets, and the variables its policies give each as.
    pub fn secret_list(&self, sandbox: &SandboxName) -> Result<Vec<SecretView>> {
        let view = self.policy(sandbox)?;
        Ok(self
            .state
            .secrets(sandbox)?
            .into_iter()
            .map(|record| SecretView {
                granted_as: granted_as(&view.snapshot.policy, &record.secret),
                pending_as: view
                    .pending
                    .as_ref()
                    .map(|(_, p)| granted_as(&p.policy, &record.secret)),
                record,
            })
            .collect())
    }

    /// Removes `secret` from the secret store and from enclos's records.
    /// Refused while the active or the pending policy grants it: a session
    /// starting then would find it missing.
    pub fn secret_rm(
        &self,
        by: &Actor,
        secret: &SecretRef,
        confirm: Confirm,
    ) -> Result<Planned<()>> {
        self.refuse_granted(secret)?;
        let known = self
            .state
            .secrets(&secret.sandbox)?
            .iter()
            .any(|s| s.secret == *secret);
        if !known {
            return Err(Error::NoSuchSecret {
                secret: secret.to_string(),
            });
        }
        match confirm {
            Confirm::DryRun => {
                return Ok(Planned::DryRun(Plan {
                    changes: vec![format!("remove secret {secret} from the Keychain")],
                    ..Plan::default()
                }));
            }
            Confirm::Ask => {
                return Err(Error::NeedsConfirmation {
                    what: format!(
                        "removing secret {secret}, whose value is not kept anywhere else"
                    ),
                });
            }
            Confirm::Yes => {}
        }
        self.write(
            by,
            "secret rm",
            Some(secret.to_string()),
            |_| "removed from the secret store".to_owned(),
            |lock| {
                self.refuse_granted(secret)?;
                self.secrets.remove(secret)?;
                self.state.remove_secret(lock, secret)?;
                Ok(())
            },
        )?;
        Ok(Planned::Done(()))
    }

    fn refuse_granted(&self, secret: &SecretRef) -> Result<()> {
        let view = self.policy(&secret.sandbox)?;
        let mut variables = granted_as(&view.snapshot.policy, secret);
        if let Some((_, pending)) = &view.pending {
            variables.extend(granted_as(&pending.policy, secret));
        }
        variables.sort();
        variables.dedup();
        match variables.is_empty() {
            true => Ok(()),
            false => Err(Error::SecretGranted {
                secret: secret.to_string(),
                variables: variables.join(", "),
            }),
        }
    }

    /// Refuses a policy granting a secret the sandbox does not have: every
    /// session would then fail to start.
    pub(super) fn check_secrets_set(&self, name: &SandboxName, policy: &Policy) -> Result<()> {
        if policy.secrets.is_empty() {
            return Ok(());
        }
        let set = self.state.secrets(name)?;
        for grant in policy.secrets.values() {
            let Ok(secret) = SecretRef::parse_policy(grant) else {
                continue;
            };
            if !set.iter().any(|s| s.secret == secret) {
                return Err(Error::NoSuchSecret {
                    secret: secret.to_string(),
                });
            }
        }
        Ok(())
    }

    /// The variables a session of the sandbox starts with: each secret
    /// `policy` grants, read from the secret store now, on the host.
    pub(super) fn secret_env(&self, policy: &Policy) -> Result<Vec<(String, String)>> {
        let mut env = Vec::new();
        for (variable, grant) in &policy.secrets {
            let secret = SecretRef::parse_policy(grant).map_err(|e| Error::Session {
                what: format!("the policy grants ${variable} as {e}"),
            })?;
            match self.secrets.get(&secret)? {
                Some(value) => env.push((variable.clone(), value)),
                None => {
                    return Err(Error::SecretMissing {
                        secret: secret.to_string(),
                        variable: variable.clone(),
                    });
                }
            }
        }
        Ok(env)
    }

    /// Removes every secret of the sandbox from the secret store, as the
    /// sandbox's record goes; returns those it could not remove, with why.
    pub(super) fn forget_secrets(&self, records: &[SecretRecord]) -> Vec<String> {
        records
            .iter()
            .filter_map(|r| match self.secrets.remove(&r.secret) {
                Ok(_) => None,
                Err(e) => Some(format!("{} ({e})", r.secret)),
            })
            .collect()
    }
}

/// The variables `policy` gives `secret` as.
fn granted_as(policy: &Policy, secret: &SecretRef) -> Vec<String> {
    let grant = secret.in_policy();
    policy
        .secrets
        .iter()
        .filter(|(_, g)| **g == grant)
        .map(|(v, _)| v.clone())
        .collect()
}
