//! The engine's secret calls (design §12, ADR 0022): store a sandbox's
//! secret, list and remove them, and give the secrets a policy grants to a
//! session as it starts.

use std::path::Path;

use super::Engine;
use crate::error::{Error, Result};
use crate::layout::LayoutError;
use crate::model::audit::Actor;
use crate::model::plan::{Confirm, Plan, Planned};
use crate::model::policy::Policy;
use crate::model::runtime::RuntimeKind;
use crate::model::sandbox::SandboxName;
use crate::model::secret::{SecretRecord, SecretRef, SecretValue};
use crate::runtime::adapter;

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
                    return Err(match known || error.untouched {
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
        if policy.secrets.is_empty() && policy.agent_secrets.is_empty() {
            return Ok(());
        }
        let set = self.state.secrets(name)?;
        let grants = policy
            .secrets
            .values()
            .chain(policy.agent_secrets.values().flat_map(|g| g.values()));
        for grant in grants {
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
        self.granted_values(&policy.secrets)
    }

    /// The values of `grants`, by variable, read from the secret store now.
    fn granted_values(
        &self,
        grants: &crate::model::policy::AgentSecrets,
    ) -> Result<Vec<(String, SecretValue)>> {
        let mut env = Vec::new();
        for (variable, grant) in grants {
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

    /// What a service of `kind` gets of the secrets `policy` grants: for a
    /// runtime that reads them from a folder, the variable naming that
    /// folder, where they are written, so that they are never in the
    /// service's environment, which any process of the user can read (ADR
    /// 0034); else the secrets themselves, as variables. Each agent's own
    /// go to a file of its own in that folder (ADR 0036), and a runtime
    /// with no such folder refuses them. A store that could only be read
    /// through a dialog nobody sees refuses the start.
    pub(super) fn service_secrets(
        &self,
        name: &SandboxName,
        kind: RuntimeKind,
        service: &str,
        policy: &Policy,
    ) -> Result<Vec<(String, SecretValue)>> {
        if policy.secrets.is_empty() && policy.agent_secrets.is_empty() {
            self.remove_secrets_file(name)?;
            return Ok(Vec::new());
        }
        self.secrets.readable().map_err(|e| Error::SecretsLocked {
            sandbox: name.to_string(),
            service: service.to_owned(),
            why: e.what,
        })?;
        let values = self.secret_env(policy)?;
        let Some(var) = adapter(kind).secrets_folder_var() else {
            if !policy.agent_secrets.is_empty() {
                return Err(Error::SecretsFileRefused {
                    sandbox: name.to_string(),
                    why: format!(
                        "{} reads no secrets of one agent's own, which the policy grants under [secrets.agents]; grant them under [secrets] instead",
                        kind.display_name()
                    ),
                });
            }
            return Ok(values);
        };
        let folder = self.layout.sandbox_secrets_dir(name.as_str());
        write_secrets_file(name, &folder, SANDBOX_SECRETS_FILE, &values)?;
        let mut written = vec![SANDBOX_SECRETS_FILE.to_owned()];
        for (agent, grants) in &policy.agent_secrets {
            let file = format!("{agent}{}", crate::layout::AGENT_SECRETS_SUFFIX);
            write_secrets_file(name, &folder, &file, &self.granted_values(grants)?)?;
            written.push(file);
        }
        // What an earlier start wrote for an agent no longer granted any.
        remove_files_but(&folder, &written)?;
        // Not a secret, but where the secrets are.
        let named = SecretValue::new(folder.display().to_string())
            .expect("a folder's path is text with no NUL");
        Ok(vec![(var.to_owned(), named)])
    }

    /// Removes the file a runtime read its secrets from, as the sandbox
    /// stops or its services start with none.
    pub(super) fn remove_secrets_file(&self, name: &SandboxName) -> Result<()> {
        let folder = self.layout.sandbox_secrets_dir(name.as_str());
        match std::fs::remove_dir_all(&folder) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(source) => Err(LayoutError::Io {
                path: folder,
                source,
            }
            .into()),
        }
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

/// The file of the secrets folder holding what the sandbox's grants give
/// every agent (ADR 0034).
const SANDBOX_SECRETS_FILE: &str = ".env";

/// Removes the files of `folder` not named in `kept`.
fn remove_files_but(folder: &Path, kept: &[String]) -> Result<()> {
    let io = |path: &Path| {
        let path = path.to_owned();
        move |source| Error::from(LayoutError::Io { path, source })
    };
    for entry in std::fs::read_dir(folder).map_err(io(folder))? {
        let path = entry.map_err(io(folder))?.path();
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        if !kept.iter().any(|k| k == name) {
            std::fs::remove_file(&path).map_err(io(&path))?;
        }
    }
    Ok(())
}

/// The variables `policy` gives `secret` as: to the whole sandbox, then to
/// each agent, said `VAR for agent main` (ADR 0036).
fn granted_as(policy: &Policy, secret: &SecretRef) -> Vec<String> {
    let sandbox = policy
        .secrets
        .iter()
        .filter(|(_, g)| g.0 == *secret)
        .map(|(v, _)| v.clone());
    let agents = policy.agent_secrets.iter().flat_map(|(agent, grants)| {
        grants
            .iter()
            .filter(|(_, g)| g.0 == *secret)
            .map(move |(v, _)| format!("{v} for agent {agent}"))
    });
    sandbox.chain(agents).collect()
}

/// Writes `values` as `file` of `folder`, which only the user reads:
/// the folder 0700, the file 0600, written whole beside it and then renamed
/// over it. Each value is double-quoted with its `\` and `"` escaped, which
/// python-dotenv and Hermes's own reader (`agent.secret_scope.load_env_file`)
/// both read back as it was (checked against Hermes 0.22.4's). Refused,
/// before anything is written: a value holding a line break or `${`, since
/// Hermes's reader splits lines and python-dotenv expands `${…}` with no
/// escape for it, so the two would read different values; and a folder
/// that is a link, never followed.
fn write_secrets_file(
    name: &SandboxName,
    folder: &Path,
    file: &str,
    values: &[(String, SecretValue)],
) -> Result<()> {
    let refused = |why: String| Error::SecretsFileRefused {
        sandbox: name.to_string(),
        why,
    };
    let unreadable = |v: &SecretValue| {
        let v = v.expose();
        v.contains('\n') || v.contains('\r') || v.contains("${")
    };
    if let Some((variable, _)) = values.iter().find(|(_, v)| unreadable(v)) {
        return Err(refused(format!(
            "the secret given as ${variable} holds a line break or `${{`, which its secrets file cannot hold as it is; set a value without them with `enclos secret set`"
        )));
    }
    if std::fs::symlink_metadata(folder).is_ok_and(|m| m.file_type().is_symlink()) {
        return Err(refused(format!(
            "{} is a link, which secrets are never written through; remove it",
            folder.display()
        )));
    }
    use std::io::Write as _;
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
    let io = |path: &Path| {
        let path = path.to_owned();
        move |source| Error::from(LayoutError::Io { path, source })
    };
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(folder)
        .map_err(io(folder))?;
    std::fs::set_permissions(folder, std::fs::Permissions::from_mode(0o700)).map_err(io(folder))?;
    let mut text = zeroize::Zeroizing::new(String::new());
    for (variable, value) in values {
        text.push_str(variable);
        text.push_str("=\"");
        for c in value.expose().chars() {
            if c == '\\' || c == '"' {
                text.push('\\');
            }
            text.push(c);
        }
        text.push_str("\"\n");
    }
    let new = folder.join(format!("{file}.new"));
    let file = folder.join(file);
    match std::fs::remove_file(&new) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(source) => return Err(io(&new)(source)),
    }
    let mut out = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&new)
        .map_err(io(&new))?;
    out.write_all(text.as_bytes()).map_err(io(&new))?;
    out.sync_all().map_err(io(&new))?;
    std::fs::rename(&new, &file).map_err(io(&file))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn value(text: &str) -> SecretValue {
        SecretValue::new(text.to_owned()).unwrap()
    }

    fn home() -> SandboxName {
        "home".parse().unwrap()
    }

    /// Each value double-quoted, `\` and `"` escaped, as both of Hermes's
    /// readers read them back; written in place of the file there was.
    #[test]
    fn a_secrets_file_holds_each_value_escaped() {
        let dir = tempfile::tempdir().unwrap();
        let folder = dir.path().join("secrets");
        let values = vec![
            ("A".to_owned(), value("plain")),
            ("B".to_owned(), value("a'b\\c\"d$HOME #e")),
        ];
        write_secrets_file(&home(), &folder, SANDBOX_SECRETS_FILE, &values).unwrap();
        write_secrets_file(&home(), &folder, SANDBOX_SECRETS_FILE, &values).unwrap();
        let text = std::fs::read_to_string(folder.join(".env")).unwrap();
        assert_eq!(text, "A=\"plain\"\nB=\"a'b\\\\c\\\"d$HOME #e\"\n");
        assert!(!folder.join(".env.new").exists());
    }

    /// A line break or `${` would be read differently by Hermes's two
    /// readers: refused, and nothing written.
    #[test]
    fn a_value_the_runtime_would_read_otherwise_is_refused() {
        for bad in ["a${HOME}b", "line\nnext", "cr\rhere"] {
            let dir = tempfile::tempdir().unwrap();
            let folder = dir.path().join("secrets");
            let err = write_secrets_file(
                &home(),
                &folder,
                SANDBOX_SECRETS_FILE,
                &[("T".to_owned(), value(bad))],
            )
            .unwrap_err();
            assert!(matches!(err, Error::SecretsFileRefused { .. }), "{err}");
            assert!(
                err.to_string().contains("$T holds a line break or `${`"),
                "{err}"
            );
            assert!(!folder.exists());
        }
    }

    /// A folder that is a link is never written through.
    #[test]
    fn a_secrets_folder_that_is_a_link_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let elsewhere = dir.path().join("elsewhere");
        std::fs::create_dir(&elsewhere).unwrap();
        let folder = dir.path().join("secrets");
        std::os::unix::fs::symlink(&elsewhere, &folder).unwrap();
        let err = write_secrets_file(
            &home(),
            &folder,
            SANDBOX_SECRETS_FILE,
            &[("T".to_owned(), value("v"))],
        )
        .unwrap_err();
        assert!(matches!(err, Error::SecretsFileRefused { .. }), "{err}");
        assert!(!elsewhere.join(".env").exists());
    }
}
