//! Reviewed mobile removals. A short-lived bridge permit holds this
//! snapshot; the CLI checks its fingerprint before any destructive work.

use std::collections::BTreeSet;
use std::os::unix::fs::MetadataExt;

use super::{AgentRemoved, Engine, FilesKept};
use crate::error::{Error, Result};
use crate::model::agent::{AgentName, AgentRecord};
use crate::model::audit::Actor;
use crate::model::plan::Planned;
use crate::model::runtime::RuntimeKind;
use crate::model::sandbox::SandboxName;
use crate::model::session::SessionKind;
use crate::policy::sha256_hex;
use crate::runtime::{RuntimeAgentName, adapter, home};

#[derive(Debug, Clone)]
pub struct RemovalReview {
    pub sandbox: SandboxName,
    pub agent: Option<AgentName>,
    pub runtime: Option<RuntimeKind>,
    pub revision: String,
    pub identity: String,
    pub sandbox_identity: String,
    pub contents: String,
    pub agents: Vec<String>,
    pub secret_count: usize,
    pub session_count: usize,
    pub services: Vec<String>,
    pub effects: Vec<String>,
    pub(super) tracked: Option<AgentRecord>,
    had_files: bool,
}

#[derive(Debug, Clone)]
pub struct RemovalOutcome {
    pub removed: bool,
    pub files_removed: bool,
    pub secrets_left_count: usize,
    pub warnings: Vec<String>,
}

fn refused(message: impl Into<String>) -> Error {
    Error::Session {
        what: message.into(),
    }
}
fn stale() -> Error {
    refused(
        "This removal preview is stale: the target or its contents changed. Review it again before removing anything.",
    )
}
fn bounded(text: impl ToString) -> String {
    text.to_string().chars().take(1024).collect()
}

impl Engine {
    pub fn removal_review(
        &self,
        name: &SandboxName,
        agent: Option<&AgentName>,
    ) -> Result<RemovalReview> {
        let _lock = self.state.lock()?;
        let review = self.removal_snapshot(name, agent)?;
        if agent.is_some() {
            self.refuse_removal_cli_sessions(name)?;
        }
        Ok(review)
    }

    /// Identifies this creation of a sandbox even when its canonical name
    /// is reused later. Reading it changes no state or profile files.
    pub fn sandbox_generation(&self, name: &SandboxName) -> Result<String> {
        let record = self.record(name)?;
        let dir = self.layout.sandbox_dir(name.as_str());
        let meta = std::fs::symlink_metadata(&dir)
            .map_err(|error| refused(format!("cannot identify sandbox {name}: {error}")))?;
        if !meta.is_dir() || meta.file_type().is_symlink() {
            return Err(stale());
        }
        Ok(sha256_hex(
            format!(
                "{}:{name}:{}:{}:{}",
                self.layout.install_id()?,
                record.created_at,
                meta.dev(),
                meta.ino()
            )
            .as_bytes(),
        ))
    }

    pub fn sandbox_created_at(&self, name: &SandboxName) -> Result<crate::model::Timestamp> {
        Ok(self.record(name)?.created_at)
    }

    fn removal_sandbox_identity(&self, name: &SandboxName) -> Result<String> {
        let record = self.record(name)?;
        Ok(sha256_hex(
            format!(
                "{}:{:?}:{}",
                self.sandbox_generation(name)?,
                record.runtime,
                record.proxy_port
            )
            .as_bytes(),
        ))
    }

    fn removal_agent_folder(
        &self,
        name: &SandboxName,
        kind: RuntimeKind,
        agent: &AgentName,
    ) -> Result<Option<String>> {
        self.removal_runtime_folder(name, kind, &RuntimeAgentName::from(agent))
    }

    fn removal_runtime_folder(
        &self,
        name: &SandboxName,
        kind: RuntimeKind,
        agent: &RuntimeAgentName,
    ) -> Result<Option<String>> {
        let folder = adapter(kind).agent_facts(agent).folder.ok_or_else(|| {
            refused("This runtime does not identify the profile folder; remove it on the host.")
        })?;
        let stat = home::stat(&self.sandbox_home(name), &folder)
            .map_err(|error| refused(format!("cannot identify agent {name}/{agent}: {error}")))?;
        match stat {
            Some(stat) if rustix::fs::FileType::from_raw_mode(stat.st_mode).is_dir() => {
                Ok(Some(format!("{}:{}", stat.st_dev, stat.st_ino)))
            }
            Some(_) => Err(refused(
                "The profile path is not a plain directory. Review it on the host before removing anything.",
            )),
            None => Ok(None),
        }
    }

    fn removal_snapshot(
        &self,
        name: &SandboxName,
        agent: Option<&AgentName>,
    ) -> Result<RemovalReview> {
        let record = self.record(name)?;
        let sandbox_identity = self.removal_sandbox_identity(name)?;
        let tracked_all = self.state.agents(name)?;
        let tracked = agent.and_then(|agent| {
            tracked_all
                .iter()
                .find(|record| record.name == *agent)
                .cloned()
        });
        let mut profiles = BTreeSet::new();
        if let Some(kind) = record.runtime {
            let runtime = adapter(kind);
            for profile in runtime
                .agents_in(&self.sandbox_home(name))
                .map_err(|error| refused(format!("cannot review runtime profiles: {error}")))?
            {
                profiles.insert(profile.as_str().to_owned());
            }
            if let Some(builtin) = runtime.builtin_agent() {
                profiles.insert(builtin.as_str().to_owned());
            }
            for agent in &tracked_all {
                profiles.insert(agent.name.to_string());
            }
        }
        if profiles.len() > 512 {
            return Err(refused(
                "This sandbox has too many profiles for a mobile removal preview. Review and remove it on the host.",
            ));
        }
        let folder = match agent {
            Some(agent) => {
                let kind = record.runtime.ok_or_else(|| {
                    refused("This sandbox has no runtime or agent profile to remove.")
                })?;
                self.refuse_builtin(name, kind, agent.as_str()).map_err(|_| refused(format!("{agent} is the runtime's built-in agent. Remove sandbox {name} to remove its runtime and built-in agent.")))?;
                let folder = self.removal_agent_folder(name, kind, agent)?;
                if tracked.is_none() && folder.is_none() {
                    return Err(refused("This agent no longer exists. Refresh the sandbox."));
                }
                if tracked.is_none() && !profiles.contains(agent.as_str()) {
                    return Err(refused(
                        "The runtime does not list this untracked folder as a profile. Review its remaining files on the host before removing them.",
                    ));
                }
                if folder.is_some() && adapter(kind).delete_agent(agent).is_none() {
                    return Err(refused(
                        "This runtime cannot delete profile files through enclos. Remove the profile on the host.",
                    ));
                }
                folder
            }
            None => None,
        };
        let identity =
            sha256_hex(format!("{sandbox_identity}:{agent:?}:{tracked:?}:{folder:?}").as_bytes());
        let secrets = self.state.secrets(name)?;
        let policy = self.policy(name)?;
        let text = self.layout.read_policy(name.as_str())?;
        let mut profile_ids = Vec::new();
        if agent.is_none()
            && let Some(kind) = record.runtime
        {
            for profile in &profiles {
                if let Some(agent) = RuntimeAgentName::new(profile) {
                    profile_ids.push((profile, self.removal_runtime_folder(name, kind, &agent)?));
                }
            }
        }
        let contents = sha256_hex(
            format!(
                "{:?}:{:?}:{}:{secrets:?}:{:?}:{profile_ids:?}",
                policy.snapshot.id,
                policy.pending,
                sha256_hex(text.as_bytes()),
                if agent.is_none() {
                    Some(&profiles)
                } else {
                    None
                }
            )
            .as_bytes(),
        );
        let view = self.show_sandbox(name)?;
        let sessions: Vec<_> = view
            .sessions
            .iter()
            .filter(|session| !session.gone())
            .map(|session| (&session.session.id, &session.session.root))
            .collect();
        let mut services: Vec<_> = self
            .service_status(name)?
            .into_iter()
            .map(|(label, _)| label.to_string())
            .collect();
        services.sort();
        let revision = sha256_hex(
            format!(
                "{identity}:{contents}:{services:?}:{sessions:?}:{:?}",
                record.state
            )
            .as_bytes(),
        );
        let effects = if let Some(agent) = agent {
            vec![format!("Permanently delete agent {name}/{agent}, its profile configuration, SOUL, memory, skills and runtime session files."), "Pause and resume this sandbox's shared runtime services; running agent work in those services may be interrupted.".into(), "Any live CLI work in this sandbox must finish before an agent can be removed.".into(), "The sandbox, its other agents, policy grants and stored secrets remain. Saved app conversation history remains readable.".into()]
        } else {
            vec![format!("Stop all running work and services in sandbox {name}."), "Permanently delete the sandbox, its runtime, every agent profile, home files and stored secrets.".into(), "Saved app conversation history remains readable. Other sandboxes and the host pairing remain.".into()]
        };
        Ok(RemovalReview {
            sandbox: name.clone(),
            agent: agent.cloned(),
            runtime: record.runtime,
            revision,
            identity,
            sandbox_identity,
            contents,
            agents: agent
                .map(|agent| vec![agent.to_string()])
                .unwrap_or_else(|| profiles.into_iter().collect()),
            secret_count: if agent.is_none() { secrets.len() } else { 0 },
            session_count: sessions.len(),
            services,
            effects,
            tracked,
            had_files: folder.is_some(),
        })
    }

    fn refuse_removal_cli_sessions(&self, name: &SandboxName) -> Result<()> {
        if self.show_sandbox(name)?.sessions.iter().any(|view| {
            matches!(
                view.session.kind,
                SessionKind::Interactive | SessionKind::Exec
            ) && !view.gone()
        }) {
            return Err(refused(
                "Finish all live CLI work in this sandbox before removing an agent. The host cannot safely identify which profile a CLI session uses.",
            ));
        }
        Ok(())
    }

    pub(super) fn validate_removal_sandbox_identity(&self, review: &RemovalReview) -> Result<()> {
        if self.removal_sandbox_identity(&review.sandbox)? != review.sandbox_identity {
            return Err(stale());
        }
        Ok(())
    }

    pub(super) fn validate_removal_identity(&self, review: &RemovalReview) -> Result<()> {
        let current = self.removal_snapshot(&review.sandbox, review.agent.as_ref())?;
        if current.identity != review.identity || current.contents != review.contents {
            return Err(stale());
        }
        Ok(())
    }

    pub(super) fn validate_removal_revision(&self, review: &RemovalReview) -> Result<()> {
        if self
            .removal_snapshot(&review.sandbox, review.agent.as_ref())?
            .revision
            != review.revision
        {
            return Err(stale());
        }
        Ok(())
    }

    pub(super) fn validate_agent_removal_start(&self, review: &RemovalReview) -> Result<()> {
        self.validate_removal_identity(review)?;
        self.refuse_removal_cli_sessions(&review.sandbox)
    }

    pub(super) fn validate_agent_removal_end(
        &self,
        review: &RemovalReview,
        files_deleted: bool,
    ) -> Result<()> {
        self.validate_removal_sandbox_identity(review)?;
        let agent = review.agent.as_ref().ok_or_else(stale)?;
        let current = self
            .agents(&review.sandbox)?
            .into_iter()
            .find(|record| record.name == *agent);
        if current != review.tracked {
            return Err(stale());
        }
        if files_deleted {
            let kind = review.runtime.ok_or_else(stale)?;
            if self
                .removal_agent_folder(&review.sandbox, kind, agent)?
                .is_some()
                || adapter(kind)
                    .agents_in(&self.sandbox_home(&review.sandbox))
                    .map_err(|error| refused(error.to_string()))?
                    .contains(&RuntimeAgentName::from(agent))
            {
                return Err(stale());
            }
        } else {
            self.validate_removal_identity(review)?;
        }
        Ok(())
    }

    pub(super) fn validate_agent_removal_finish(&self, review: &RemovalReview) -> Result<()> {
        self.validate_agent_removal_end(review, true)?;
        self.refuse_removal_cli_sessions(&review.sandbox)
    }

    pub fn remove_reviewed(
        &self,
        by: &Actor,
        name: &SandboxName,
        agent: Option<&AgentName>,
        revision: &str,
    ) -> Result<RemovalOutcome> {
        let review = self.removal_review(name, agent)?;
        if review.revision != revision {
            return Err(stale());
        }
        if let Some(agent) = agent {
            match self.remove_existing_agent_reviewed(by, name, agent, &review) {
                Ok(Planned::Done(AgentRemoved::Deleted { .. })) => Ok(RemovalOutcome {
                    removed: true,
                    files_removed: true,
                    secrets_left_count: 0,
                    warnings: vec![],
                }),
                Ok(Planned::Done(AgentRemoved::RecordOnly { why, .. })) => {
                    let gone = matches!(why, FilesKept::RuntimeLacksIt);
                    Ok(RemovalOutcome {
                        removed: gone,
                        files_removed: false,
                        secrets_left_count: 0,
                        warnings: vec![if gone {
                            "Only the enclos record was removed; the runtime files were already absent.".into()
                        } else {
                            "Only the enclos record was removed. Profile files remain on the host."
                                .into()
                        }],
                    })
                }
                Ok(Planned::DryRun(_)) => unreachable!("reviewed removal is confirmed"),
                Err(error) => {
                    self.validate_removal_sandbox_identity(&review)?;
                    let files_gone = self
                        .removal_agent_folder(name, review.runtime.ok_or_else(stale)?, agent)?
                        .is_none();
                    if !files_gone {
                        return Err(error);
                    }
                    let record_gone = !self
                        .agents(name)?
                        .iter()
                        .any(|record| record.name == *agent);
                    Ok(RemovalOutcome {
                        removed: record_gone,
                        files_removed: review.had_files,
                        secrets_left_count: 0,
                        warnings: vec![bounded(error)],
                    })
                }
            }
        } else {
            let stopped = self.stop_sandbox_for_removal(by, name, &review)?;
            if !stopped.survivors.is_empty() {
                return Err(refused(
                    "Some processes survived the stop. No sandbox files were deleted. End those processes on the host, then review removal again.",
                ));
            }
            self.validate_removal_identity(&review)?;
            match self.remove_sandbox_after_review(by, name, &review) {
                Ok(Planned::Done(left)) => Ok(RemovalOutcome {
                    removed: true,
                    files_removed: !self.layout.sandbox_dir(name.as_str()).exists(),
                    secrets_left_count: left.len(),
                    warnings: if left.is_empty() {
                        vec![]
                    } else {
                        vec![format!(
                            "The sandbox is removed, but {} stored secrets could not be deleted. Clean them up on the host.",
                            left.len()
                        )]
                    },
                }),
                Ok(Planned::DryRun(_)) => unreachable!("reviewed removal is confirmed"),
                Err(error) => Err(error),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::jsonl::JsonlAuditLog;
    use crate::backend::fake::FakeBackend;
    use crate::engine::SandboxSpec;
    use crate::layout::Layout;
    use crate::model::plan::Confirm;
    use crate::model::sandbox::BackendKind;
    use crate::model::secret::{SecretRef, SecretValue};
    use crate::secrets::{InMemory, SecretStore, Unavailable};
    use crate::service::fake::FakeServices;
    use crate::state::sqlite::SqliteStateStore;
    use std::rc::Rc;

    fn actor() -> Actor {
        Actor {
            user: "tester".into(),
            host: "local".into(),
        }
    }
    fn fixture() -> (
        tempfile::TempDir,
        Engine,
        Rc<InMemory>,
        Rc<FakeServices>,
        SandboxName,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let layout = Layout::at(dir.path().join("enclos"));
        let store = Rc::new(InMemory::default());
        let services = Rc::new(FakeServices::default());
        let engine = Engine::new(
            layout.clone(),
            Box::new(SqliteStateStore::new(
                layout.state_db(),
                layout.state_lock(),
            )),
            Box::new(JsonlAuditLog::new(layout.audit_log())),
            vec![Box::new(FakeBackend::available(BackendKind::Seatbelt))],
        )
        .with_secrets(Box::new(Rc::clone(&store)))
        .with_services(Box::new(Rc::clone(&services)));
        engine.init(&actor(), Confirm::Yes).unwrap();
        for name in ["home", "other"] {
            engine
                .create_sandbox(
                    &actor(),
                    SandboxSpec {
                        name: name.parse().unwrap(),
                        backend: BackendKind::Seatbelt,
                        template: "assistant".parse().unwrap(),
                    },
                    Confirm::Yes,
                )
                .unwrap();
        }
        (dir, engine, store, services, "home".parse().unwrap())
    }

    #[test]
    fn reviewed_sandbox_removal_deletes_its_home_and_secrets_but_preserves_other_resources_and_history()
     {
        let (_dir, engine, store, services, name) = fixture();
        let lock = engine.state.lock().unwrap();
        let mut record = engine.state.get(&name).unwrap().unwrap();
        record.runtime = Some(RuntimeKind::Hermes);
        engine.state.put(&lock, &record).unwrap();
        drop(lock);
        engine
            .policy_refresh(&actor(), &name, Confirm::Yes)
            .unwrap();
        for profile in ["scout", "untracked_bot"] {
            let folder = engine
                .sandbox_home(&name)
                .join(".hermes/profiles")
                .join(profile);
            std::fs::create_dir_all(&folder).unwrap();
            std::fs::write(folder.join("config.yaml"), "").unwrap();
        }
        for sandbox in ["home", "other"] {
            std::fs::write(
                engine
                    .sandbox_home(&sandbox.parse().unwrap())
                    .join("keep-or-delete"),
                sandbox,
            )
            .unwrap();
            let secret: SecretRef = format!("{sandbox}/token").parse().unwrap();
            engine
                .secret_set(
                    &actor(),
                    &secret,
                    Some(&SecretValue::new(format!("value-{sandbox}")).unwrap()),
                    Confirm::Ask,
                )
                .unwrap();
        }
        let db = crate::bridge::store::Store::open(&engine.app_store_path()).unwrap();
        drop(db);
        let history = std::fs::read(engine.app_store_path()).unwrap();
        let labels = engine.label(&name, super::super::Unit::Proxy).unwrap();
        services.seed(labels.as_str());
        let review = engine.removal_review(&name, None).unwrap();
        assert_eq!(review.secret_count, 1);
        assert_eq!(review.agents, ["default", "scout", "untracked_bot"]);
        assert_eq!(review.services, [labels.to_string()]);
        let removed = engine
            .remove_reviewed(&actor(), &name, None, &review.revision)
            .unwrap();
        assert!(removed.removed && removed.files_removed && removed.warnings.is_empty());
        assert!(!engine.layout.sandbox_dir(name.as_str()).exists());
        assert!(store.get(&"home/token".parse().unwrap()).unwrap().is_none());
        assert!(
            store
                .get(&"other/token".parse().unwrap())
                .unwrap()
                .is_some()
        );
        assert!(
            engine
                .sandbox_home(&"other".parse().unwrap())
                .join("keep-or-delete")
                .exists()
        );
        assert_eq!(std::fs::read(engine.app_store_path()).unwrap(), history);
    }

    #[test]
    fn a_recreated_target_or_changed_policy_is_refused_before_services_stop() {
        for recreate in [false, true] {
            let (_dir, engine, _store, services, name) = fixture();
            let label = engine.label(&name, super::super::Unit::Proxy).unwrap();
            services.seed(label.as_str());
            let review = engine.removal_review(&name, None).unwrap();
            let dir = engine.layout.sandbox_dir(name.as_str());
            if recreate {
                let old = dir.with_extension("old");
                std::fs::rename(&dir, &old).unwrap();
                std::fs::create_dir_all(dir.join("home")).unwrap();
                std::fs::copy(old.join("policy.toml"), dir.join("policy.toml")).unwrap();
            } else {
                let file = engine.layout.policy_file(name.as_str());
                let before = std::fs::read_to_string(&file).unwrap();
                std::fs::write(file, format!("{before}\n# changed after review\n")).unwrap();
            }
            assert!(
                engine
                    .remove_reviewed(&actor(), &name, None, &review.revision)
                    .is_err()
            );
            assert!(services.stopped.borrow().is_empty());
            assert!(dir.exists());
        }
    }

    #[test]
    fn known_secret_cleanup_failures_are_explicit_partial_outcomes() {
        let (_dir, engine, _store, _services, name) = fixture();
        engine
            .secret_set(
                &actor(),
                &"home/token".parse().unwrap(),
                Some(&SecretValue::new("value".into()).unwrap()),
                Confirm::Ask,
            )
            .unwrap();
        let engine = engine.with_secrets(Box::new(Unavailable {
            why: "disposable test store unavailable".into(),
        }));
        let review = engine.removal_review(&name, None).unwrap();
        let outcome = engine
            .remove_reviewed(&actor(), &name, None, &review.revision)
            .unwrap();
        assert!(outcome.removed && outcome.files_removed);
        assert_eq!(outcome.secrets_left_count, 1);
        assert!(!outcome.warnings.is_empty());
    }

    #[test]
    fn untracked_nonprofiles_and_non_directory_profile_paths_are_refused() {
        let (_dir, engine, _store, services, name) = fixture();
        let lock = engine.state.lock().unwrap();
        let mut record = engine.state.get(&name).unwrap().unwrap();
        record.runtime = Some(RuntimeKind::Hermes);
        engine.state.put(&lock, &record).unwrap();
        drop(lock);
        let profile = engine.sandbox_home(&name).join(".hermes/profiles/scout");
        std::fs::create_dir_all(&profile).unwrap();
        let agent = "scout".parse().unwrap();
        assert!(engine.removal_review(&name, Some(&agent)).is_err());
        std::fs::remove_dir(&profile).unwrap();
        std::fs::write(&profile, "unasked data").unwrap();
        assert!(engine.removal_review(&name, Some(&agent)).is_err());
        assert_eq!(std::fs::read_to_string(&profile).unwrap(), "unasked data");
        assert!(services.stopped.borrow().is_empty());
    }
}
