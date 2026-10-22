//! The engine's secret calls (design §12, ADR 0022): store a sandbox's
//! secret, list and remove them, and give the secrets a policy grants to a
//! session as it starts.

use super::Engine;
use crate::error::{Error, Result};
use crate::model::audit::Actor;
use crate::model::plan::{Confirm, Plan, Planned};
use crate::model::policy::Policy;
use crate::model::sandbox::SandboxName;
use crate::model::secret::{SecretRecord, SecretRef, SecretValue};

/// What `secret set` did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretSet {
    /// False when it replaced the value of a secret already set.
    pub new: bool,
    /// The variables the active policy gives it as.
    pub granted_as: Vec<String>,
    /// The variables the pending policy gives it as, if one waits.
    pub pending_as: Vec<String>,
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

/// A secret `sandbox rm` could not remove from the secret store, which no
/// enclos command reaches once the sandbox's record is gone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretLeft {
    pub secret: SecretRef,
    /// Why it could not be removed, where it is, and how to remove it.
    pub why: String,
}

impl Engine {
    /// Stores `value` as `secret`, in the secret store, and records that
    /// the sandbox has it; its value goes nowhere else. A session receives
    /// it only once its policy grants it, from its next start. A dry run
    /// needs no value: it stores nothing.
    pub fn secret_set(
        &self,
        by: &Actor,
        secret: &SecretRef,
        value: Option<&SecretValue>,
        confirm: Confirm,
    ) -> Result<Planned<SecretSet>> {
        self.require_sandbox(&secret.sandbox)?;
        let value = match (confirm, value) {
            (Confirm::DryRun, _) => {
                let what = match self.has_secret(secret)? {
                    true => format!("replace the value of secret {secret} in the secret store"),
                    false => format!("store secret {secret} in the secret store"),
                };
                return Ok(Planned::DryRun(Plan {
                    changes: vec![what],
                    ..Plan::default()
                }));
            }
            (_, Some(value)) => value,
            (_, None) => {
                return Err(Error::Session {
                    what: format!("no value was given for secret {secret}"),
                });
            }
        };
        let set = self.write(
            by,
            "secret set",
            Some(secret.to_string()),
            |s: &SecretSet| match s.new {
                true => "stored in the secret store".to_owned(),
                false => "value replaced in the secret store".to_owned(),
            },
            |lock| {
                // Again under the lock: a `sandbox rm` may have run meanwhile.
                self.require_sandbox(&secret.sandbox)?;
                let known = self.has_secret(secret)?;
                // What it reports is worked out first: once the value is
                // stored, only recording it may fail.
                let view = self.policy(&secret.sandbox)?;
                let pending_as = view
                    .pending
                    .as_ref()
                    .map(|(_, p)| granted_as(&p.policy, secret))
                    .unwrap_or_default();
                let granted_as = granted_as(&view.snapshot.policy, secret);
                let running = match granted_as.is_empty() {
                    true => 0,
                    false => self.sessions_under_rules(&secret.sandbox)?.len(),
                };
                if let Err(error) = self.secrets.set(secret, value) {
                    // A store can fail after it wrote, as when reading the
                    // value back does not answer: a new value it may have
                    // left goes again, as no record would lead to it.
                    return Err(match known {
                        true => error.into(),
                        false => self.unrecorded_value(secret, false, error.into()),
                    });
                }
                if let Err(error) = self.state.put_secret(lock, secret) {
                    return Err(self.unrecorded_value(secret, known, error.into()));
                }
                Ok(SecretSet {
                    new: !known,
                    granted_as,
                    pending_as,
                    running,
                })
            },
        )?;
        Ok(Planned::Done(set))
    }

    /// The error of a `secret set` whose value may be stored but is not
    /// recorded: a new value is removed again, since no enclos command
    /// would reach it without its record; a replaced one stays, recorded.
    fn unrecorded_value(&self, secret: &SecretRef, known: bool, error: Error) -> Error {
        if known {
            return Error::FailedAfter {
                error: Box::new(error),
                done: format!("replacing the value of secret {secret} in the secret store"),
            };
        }
        match self.secrets.remove(secret) {
            Ok(_) => error,
            Err(e) => Error::CleanupFailed {
                error: Box::new(error),
                left: format!(
                    "secret {secret}'s value in the secret store with no record of it ({e}): it is {}",
                    self.secrets.whereabouts(secret)
                ),
            },
        }
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
        self.require_secret(secret)?;
        match confirm {
            Confirm::DryRun => {
                return Ok(Planned::DryRun(Plan {
                    changes: vec![format!("remove secret {secret} from the secret store")],
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
                self.require_secret(secret)?;
                // The value first: should removing the record then fail, the
                // record is left with no value, which `secret rm` run again
                // removes. The other way round would leave a value with no
                // record, which no enclos command reaches.
                self.secrets.remove(secret)?;
                self.state.remove_secret(lock, secret)?;
                Ok(())
            },
        )?;
        Ok(Planned::Done(()))
    }

    fn has_secret(&self, secret: &SecretRef) -> Result<bool> {
        Ok(self
            .state
            .secrets(&secret.sandbox)?
            .iter()
            .any(|s| s.secret == *secret))
    }

    fn require_secret(&self, secret: &SecretRef) -> Result<()> {
        match self.has_secret(secret)? {
            true => Ok(()),
            false => Err(Error::SecretUnknown {
                secret: secret.clone(),
            }),
        }
    }

    fn refuse_granted(&self, secret: &SecretRef) -> Result<()> {
        let view = self.policy(&secret.sandbox)?;
        let active = granted_as(&view.snapshot.policy, secret);
        let pending = view
            .pending
            .as_ref()
            .map(|(_, p)| granted_as(&p.policy, secret))
            .unwrap_or_default();
        let sandbox = &secret.sandbox;
        let (by, advice) = match (active.is_empty(), pending.is_empty()) {
            (true, true) => return Ok(()),
            (false, true) => (
                "the policy in force",
                format!("take the grant out with `enclos policy edit {sandbox}` first"),
            ),
            (true, false) => (
                "the pending policy",
                format!(
                    "take the grant out with `enclos policy edit {sandbox}`, or drop that policy with `enclos policy discard {sandbox}`, first"
                ),
            ),
            (false, false) => (
                "the policy in force and the pending one",
                format!("take the grant out with `enclos policy edit {sandbox}` first"),
            ),
        };
        let mut variables: Vec<String> = active.into_iter().chain(pending).collect();
        variables.sort();
        variables.dedup();
        Err(Error::SecretGranted {
            secret: secret.clone(),
            variables: variables
                .iter()
                .map(|v| format!("${v}"))
                .collect::<Vec<_>>()
                .join(", "),
            by: by.to_owned(),
            advice,
        })
    }

    /// Refuses a policy granting a secret the sandbox does not have: every
    /// session would then fail to start.
    pub(super) fn check_secrets_set(&self, name: &SandboxName, policy: &Policy) -> Result<()> {
        if policy.secrets.is_empty() {
            return Ok(());
        }
        let set = self.state.secrets(name)?;
        for grant in policy.secrets.values() {
            if !set.iter().any(|s| s.secret == grant.0) {
                return Err(Error::NoSuchSecret {
                    secret: grant.0.clone(),
                });
            }
        }
        Ok(())
    }

    /// The variables a session of the sandbox starts with: each secret
    /// `policy` grants, read from the secret store now, on the host.
    pub(super) fn secret_env(&self, policy: &Policy) -> Result<Vec<(String, SecretValue)>> {
        let mut env = Vec::new();
        for (variable, grant) in &policy.secrets {
            match self.secrets.get(&grant.0)? {
                Some(value) => env.push((variable.clone(), value)),
                None => {
                    return Err(Error::SecretMissing {
                        secret: grant.0.clone(),
                        variable: variable.clone(),
                    });
                }
            }
        }
        Ok(env)
    }

    /// Removes every secret of the sandbox from the secret store, as the
    /// sandbox's record goes; returns those it could not remove.
    pub(super) fn forget_secrets(&self, records: &[SecretRecord]) -> Vec<SecretLeft> {
        records
            .iter()
            .filter_map(|r| match self.secrets.remove(&r.secret) {
                Ok(_) => None,
                Err(e) => Some(SecretLeft {
                    secret: r.secret.clone(),
                    why: format!("{e}; it is {}", self.secrets.whereabouts(&r.secret)),
                }),
            })
            .collect()
    }
}

/// The variables `policy` gives `secret` as.
fn granted_as(policy: &Policy, secret: &SecretRef) -> Vec<String> {
    policy
        .secrets
        .iter()
        .filter(|(_, g)| g.0 == *secret)
        .map(|(v, _)| v.clone())
        .collect()
}
