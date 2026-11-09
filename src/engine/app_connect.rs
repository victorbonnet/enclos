//! Explicitly connecting an agent to the app: one private token grant and
//! a full restart of its sandbox, using the existing policy lifecycle.

use super::pending::{Change, Recorded};
use super::{ChannelRequest, Configured, Engine};
use crate::error::{Error, Result};
use crate::model::agent::AgentName;
use crate::model::audit::Actor;
use crate::model::channel::Channel;
use crate::model::plan::{Confirm, Plan, Planned};
use crate::model::policy::{PendingPolicy, Policy};
use crate::model::sandbox::SandboxName;
use crate::model::secret::SecretRef;
use crate::policy::sha256_hex;
use crate::runtime::{RuntimeAgentName, adapter};
use toml_edit::{DocumentMut, Item, Table, Value};

fn refused(message: impl Into<String>) -> Error {
    Error::Session {
        what: message.into(),
    }
}

#[derive(Debug, PartialEq, Eq)]
enum GrantPlan {
    Existing,
    Add { before: String, after: String },
    Resume(PendingPolicy),
}

#[derive(Debug, PartialEq, Eq)]
struct ConnectionPlan {
    secret: SecretRef,
    grant: GrantPlan,
    needs_tracking: bool,
}

impl Engine {
    /// Connects an existing runtime agent to the app, adopting it if needed. The caller must
    /// explicitly accept a full sandbox restart, including its sessions.
    pub fn connect_agent_to_app(
        &self,
        by: &Actor,
        name: &SandboxName,
        agent: &AgentName,
        confirm: Confirm,
    ) -> Result<Planned<Configured>> {
        let mut plan = self.app_connection_plan(name, agent)?;
        if confirm == Confirm::DryRun {
            return Ok(Planned::DryRun(Plan {
                changes: vec![
                    format!(
                        "give agent {name}/{agent} one private app channel token, reusing its existing token when present"
                    ),
                    format!(
                        "stop sandbox {name}, ending its running sessions; configure the app channel and start its services again"
                    ),
                ],
                ..Plan::default()
            }));
        }
        if confirm != Confirm::Yes {
            return Err(Error::NeedsConfirmation {
                what: format!(
                    "connecting agent {name}/{agent} to the app, which restarts sandbox {name} and ends its running sessions; use --restart after reviewing this effect"
                ),
            });
        }
        self.services.available()?;
        if plan.needs_tracking {
            self.adopt_agent(by, name, agent.clone(), Confirm::Ask)?;
            plan = self.app_connection_plan(name, agent)?;
        }
        self.ensure_app_channel_secret(
            by,
            &plan.secret,
            !matches!(plan.grant, GrantPlan::Add { .. }),
        )?;
        // Check again before stopping anything. Pending policy changes and
        // unrelated file edits remain refused, including on a retry.
        if self.app_connection_plan_with_secret(name, agent, Some(&plan.secret))? != plan {
            return Err(refused(
                "The app connection plan changed. Refresh it before restarting the sandbox.",
            ));
        }
        let stopped = match self.stop_sandbox(by, name, Confirm::Yes)? {
            Planned::Done(stopped) => stopped,
            Planned::DryRun(_) => unreachable!("an accepted stop is not a dry run"),
        };
        if !stopped.survivors.is_empty() {
            return Err(refused(format!(
                "Sandbox {name} still has processes that survived its stop. Its app channel was not changed; end those processes before retrying Connect to app."
            )));
        }
        let result = (|| {
            if self.app_connection_plan_with_secret(name, agent, Some(&plan.secret))? != plan {
                return Err(refused(
                    "The app connection plan changed while the sandbox stopped. Review it before connecting again.",
                ));
            }
            match plan.grant {
                GrantPlan::Existing => {}
                GrantPlan::Resume(pending) => {
                    self.restart_into(by, name, &pending)?;
                }
                GrantPlan::Add { before, after } => {
                    let recorded = self.write(
                        by,
                        "app channel grant",
                        Some(format!("{name}/{agent}")),
                        |_: &Recorded| "granted only this agent's app channel token".to_owned(),
                        |lock| {
                            if self.layout.read_policy(name.as_str())? != before {
                                return Err(refused("The policy changed. Review it before connecting this agent again."));
                            }
                            let fresh = self.app_connection_plan_with_secret(name, agent, Some(&plan.secret))?;
                            if fresh.secret != plan.secret || !matches!(fresh.grant, GrantPlan::Add { .. }) {
                                return Err(refused("The app channel grant changed. Refresh before connecting again."));
                            }
                            let snapshot = self.checked_policy(name, &after)?;
                            self.propose(lock, by, name, Change::edit(&after, &snapshot))
                        },
                    )?;
                    self.restart_if_asked(by, name, Confirm::Yes, recorded)?;
                }
            }
            let configured = match self.configure_agent(
                by,
                name,
                Some(agent),
                Some(ChannelRequest {
                    channel: Channel::App,
                    token: None,
                    answers: Vec::new(),
                }),
                &[],
                Confirm::Ask,
            )? {
                Planned::Done(configured) => configured,
                Planned::DryRun(_) => unreachable!("configuration is not a dry run"),
            };
            self.start_sandbox(by, name)?;
            Ok(Planned::Done(configured))
        })();
        result.map_err(|error| Error::WithContext {
            what: format!("{error}. Agent {name}/{agent} remains in the sandbox. Connecting it stopped the sandbox; retry Connect to app after fixing the cause, or run `enclos sandbox start {name}` on the host."),
            error: Box::new(error),
        })
    }

    fn app_connection_plan(&self, name: &SandboxName, agent: &AgentName) -> Result<ConnectionPlan> {
        self.app_connection_plan_with_secret(name, agent, None)
    }

    fn app_connection_plan_with_secret(
        &self,
        name: &SandboxName,
        agent: &AgentName,
        chosen: Option<&SecretRef>,
    ) -> Result<ConnectionPlan> {
        let kind = self.runtime_of(name)?;
        let runtime = adapter(kind);
        let builtin = runtime
            .builtin_agent()
            .is_some_and(|b| b.as_str() == agent.as_str());
        let needs_tracking = !builtin
            && !self
                .agents(name)?
                .iter()
                .any(|record| record.name == *agent);
        let found = runtime.agents_in(&self.sandbox_home(name)).map_err(|why| {
            refused(format!(
                "cannot read the runtime's agents in sandbox {name}: {why}"
            ))
        })?;
        if !builtin && !found.contains(&RuntimeAgentName::from(agent)) {
            return Err(refused(format!(
                "agent {agent} is missing from sandbox {name}; restore its runtime files before connecting it"
            )));
        }
        let socket = self.layout.agent_app_socket(name.as_str(), agent.as_str());
        if socket.as_os_str().len() > 103 {
            return Err(refused(
                "The app channel socket path is too long; use a shorter enclos data directory.",
            ));
        }
        if runtime
            .app_channel(
                &RuntimeAgentName::from(agent),
                &socket,
                "app-connection-plan",
            )
            .is_none()
        {
            return Err(refused(format!(
                "{} has no app channel enclos can configure",
                kind.display_name()
            )));
        }
        let view = self.policy(name)?;
        let before = self.layout.read_policy(name.as_str())?;
        let token = Channel::App.token_variable();
        if view.snapshot.policy.secrets.contains_key(token) {
            return Err(refused(
                "The app token is granted to the whole sandbox. Give each agent its own token on the host before connecting it.",
            ));
        }
        let current_grant = view
            .snapshot
            .policy
            .agent_secrets
            .get(agent)
            .and_then(|grants| grants.get(token));
        if let Some((pending, snapshot)) = &view.pending {
            let grant = snapshot
                .policy
                .agent_secrets
                .get(agent)
                .and_then(|grants| grants.get(token))
                .ok_or_else(|| {
                    refused("A policy change is pending. Apply or discard it on the host first.")
                })?;
            let mut expected = view.snapshot.policy.clone();
            expected
                .agent_secrets
                .entry(agent.clone())
                .or_default()
                .insert(token.to_owned(), grant.clone());
            if current_grant.is_some()
                || snapshot.policy != expected
                || sha256_hex(before.as_bytes()) != snapshot.inputs.overrides
            {
                return Err(refused(
                    "A different policy change is pending or the file has unapplied edits. Review it on the host first.",
                ));
            }
            unique_token(&expected, name, agent, &grant.0)?;
            return Ok(ConnectionPlan {
                secret: grant.0.clone(),
                grant: GrantPlan::Resume(pending.clone()),
                needs_tracking,
            });
        }
        if sha256_hex(before.as_bytes()) != view.snapshot.inputs.overrides {
            return Err(refused(
                "The policy file has unapplied edits. Review them on the host first.",
            ));
        }
        let current = self.checked_policy(name, &before)?;
        if current.policy != view.snapshot.policy {
            return Err(refused(
                "The active policy no longer matches the host's current rules. Review it on the host first.",
            ));
        }
        if let Some(grant) = current_grant {
            unique_token(&view.snapshot.policy, name, agent, &grant.0)?;
            return Ok(ConnectionPlan {
                secret: grant.0.clone(),
                grant: GrantPlan::Existing,
                needs_tracking,
            });
        }
        // A first connection never adopts an ungranted secret. Once the
        // exact grant is active or pending, retries reuse its reference.
        let secret = match chosen {
            Some(secret) => secret.clone(),
            None => loop {
                let bytes = crate::bridge::ids::random_bytes(16)
                    .map_err(|error| refused(format!("cannot name an app token: {error}")))?;
                let suffix = bytes
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>();
                let secret: SecretRef = format!("{name}/app-{suffix}")
                    .parse()
                    .map_err(|error| refused(format!("cannot name an app token: {error}")))?;
                if !self
                    .state
                    .secrets(name)?
                    .iter()
                    .any(|record| record.secret == secret)
                {
                    break secret;
                }
            },
        };
        unique_token(&view.snapshot.policy, name, agent, &secret)?;
        let mut doc = before
            .parse::<DocumentMut>()
            .map_err(|error| refused(error.to_string()))?;
        let mut place = doc.as_item_mut();
        for key in ["secrets", "agents", agent.as_str(), "env"] {
            table(place)?;
            place = &mut place[key];
        }
        table(place)?;
        place[token] = toml_edit::value(secret.in_policy().to_string());
        let after = doc.to_string();
        let mut expected = view.snapshot.policy.clone();
        expected
            .agent_secrets
            .entry(agent.clone())
            .or_default()
            .insert(token.to_owned(), secret.in_policy());
        let layer = super::policy::adapter_layer(kind);
        let resolved = crate::policy::resolve(&after, Some(&layer))?;
        if resolved.policy != expected {
            return Err(refused(
                "Connecting this agent would change more than its app token grant. Review the policy on the host.",
            ));
        }
        Ok(ConnectionPlan {
            secret,
            grant: GrantPlan::Add { before, after },
            needs_tracking,
        })
    }
}

fn unique_token(
    policy: &Policy,
    name: &SandboxName,
    agent: &AgentName,
    secret: &SecretRef,
) -> Result<()> {
    if secret.sandbox != *name
        || policy.secrets.values().any(|grant| grant.0 == *secret)
        || policy.agent_secrets.iter().any(|(other, grants)| {
            other != agent && grants.values().any(|grant| grant.0 == *secret)
        })
    {
        return Err(refused(
            "This app token is shared with another agent or sandbox. Give the agent its own token on the host first.",
        ));
    }
    Ok(())
}

fn table(item: &mut Item) -> Result<()> {
    let old = std::mem::take(item);
    *item = match old {
        Item::None => Item::Table(Table::new()),
        Item::Table(table) => Item::Table(table),
        Item::Value(Value::InlineTable(table)) => Item::Table(table.into_table()),
        other => {
            *item = other;
            return Err(refused("The policy's agent secrets must be tables."));
        }
    };
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::fake::FakeBackend;
    use crate::engine::SandboxSpec;
    use crate::layout::Layout;
    use crate::model::sandbox::BackendKind;
    use crate::model::secret::SecretValue;
    use crate::secrets::{InMemory, SecretStore};
    use crate::service::fake::FakeServices;
    use std::rc::Rc;

    fn actor() -> Actor {
        Actor {
            user: "test".into(),
            host: "test".into(),
        }
    }

    fn fixture() -> (
        tempfile::TempDir,
        Engine,
        Rc<InMemory>,
        Rc<FakeServices>,
        SandboxName,
        AgentName,
    ) {
        // Unix socket limits apply to the full path, including the test root.
        let dir = tempfile::Builder::new()
            .prefix("ea-")
            .tempdir_in("/tmp")
            .unwrap();
        let store = Rc::new(InMemory::default());
        let services = Rc::new(FakeServices::default());
        let layout = Layout::at(dir.path().join("e"));
        let state =
            crate::state::sqlite::SqliteStateStore::new(layout.state_db(), layout.state_lock());
        let audit = crate::audit::jsonl::JsonlAuditLog::new(layout.audit_log());
        let proxy = dir.path().join("proxy.sh");
        crate::test_scripts::write_script(&proxy, "exec /usr/bin/nc -lk 127.0.0.1 \"$5\"");
        let engine = Engine::new(
            layout,
            Box::new(state),
            Box::new(audit),
            vec![Box::new(FakeBackend::available(BackendKind::Seatbelt))],
        )
        .with_secrets(Box::new(Rc::clone(&store)))
        .with_services(Box::new(Rc::clone(&services)))
        .with_exe(proxy);
        engine.init(&actor(), Confirm::Yes).unwrap();
        let name: SandboxName = "home".parse().unwrap();
        engine
            .create_sandbox(
                &actor(),
                SandboxSpec {
                    name: name.clone(),
                    backend: BackendKind::Seatbelt,
                    template: "assistant".parse().unwrap(),
                },
                Confirm::Yes,
            )
            .unwrap();
        let lock = engine.state.lock().unwrap();
        let mut record = engine.state.get(&name).unwrap().unwrap();
        record.runtime = Some(crate::model::runtime::RuntimeKind::Hermes);
        engine.state.put(&lock, &record).unwrap();
        drop(lock);
        engine
            .policy_refresh(&actor(), &name, Confirm::Yes)
            .unwrap();
        let agent: AgentName = "scout".parse().unwrap();
        let profile = engine.sandbox_home(&name).join(".hermes/profiles/scout");
        std::fs::create_dir_all(&profile).unwrap();
        std::fs::write(profile.join("config.yaml"), "").unwrap();
        let hermes = engine.sandbox_home(&name).join(".local/bin/hermes");
        std::fs::create_dir_all(hermes.parent().unwrap()).unwrap();
        crate::test_scripts::write_script(
            &hermes,
            "[ ! -f \"$HOME/fail-configure\" ] || exit 1\nprintf '%s\\n' \"$*\" >> \"$HOME/hermes-calls\"",
        );
        (dir, engine, store, services, name, agent)
    }

    fn store_token(engine: &Engine, secret: &SecretRef) {
        engine
            .secret_set(
                &actor(),
                secret,
                Some(&SecretValue::new("test-private-token".into()).unwrap()),
                Confirm::Ask,
            )
            .unwrap();
    }

    fn pending(engine: &Engine, name: &SandboxName, after: &str) {
        let snapshot = engine.checked_policy(name, after).unwrap();
        let lock = engine.state.lock().unwrap();
        engine
            .state
            .save_pending(&lock, name, &snapshot, None, &actor(), None)
            .unwrap();
        std::fs::write(engine.layout.policy_file(name.as_str()), after).unwrap();
    }

    #[test]
    fn connection_requires_explicit_restart_and_never_creates_a_missing_profile() {
        let _turn = crate::host_ports::HostPorts
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let (_dir, engine, store, services, name, agent) = fixture();
        let error = engine
            .connect_agent_to_app(&actor(), &name, &agent, Confirm::Ask)
            .unwrap_err();
        assert!(matches!(error, Error::NeedsConfirmation { .. }));
        assert!(engine.agents(&name).unwrap().is_empty());
        assert!(store.0.borrow().is_empty());
        assert!(services.stopped.borrow().is_empty());
        assert!(matches!(
            engine
                .connect_agent_to_app(&actor(), &name, &agent, Confirm::DryRun)
                .unwrap(),
            Planned::DryRun(_)
        ));
        std::fs::remove_dir_all(engine.sandbox_home(&name).join(".hermes/profiles/scout")).unwrap();
        let error = engine
            .connect_agent_to_app(&actor(), &name, &agent, Confirm::Yes)
            .unwrap_err();
        assert!(error.to_string().contains("missing"), "{error}");
        assert!(engine.agents(&name).unwrap().is_empty());
        assert!(store.0.borrow().is_empty());
        assert!(services.stopped.borrow().is_empty());
    }

    #[test]
    fn a_first_connection_changes_only_its_one_grant_and_chooses_fresh_refs() {
        let _turn = crate::host_ports::HostPorts
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let (_dir, engine, _store, _services, name, agent) = fixture();
        let before = engine.policy(&name).unwrap().snapshot.policy;
        let first = engine.app_connection_plan(&name, &agent).unwrap();
        let second = engine.app_connection_plan(&name, &agent).unwrap();
        assert_ne!(first.secret, second.secret);
        assert!(first.needs_tracking);
        let GrantPlan::Add { after, .. } = &first.grant else {
            panic!("not a new grant")
        };
        let mut expected = before;
        expected
            .agent_secrets
            .entry(agent.clone())
            .or_default()
            .insert("MOBILE_APP_TOKEN".into(), first.secret.in_policy());
        let resolved = crate::policy::resolve(
            after,
            Some(&super::super::policy::adapter_layer(
                crate::model::runtime::RuntimeKind::Hermes,
            )),
        )
        .unwrap();
        assert_eq!(resolved.policy, expected);
        store_token(&engine, &first.secret);
        assert_ne!(
            engine.app_connection_plan(&name, &agent).unwrap().secret,
            first.secret
        );
    }

    #[test]
    fn an_ungranted_secret_is_never_reused_overwritten_or_granted() {
        let _turn = crate::host_ports::HostPorts
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let (_dir, engine, store, _services, name, _agent) = fixture();
        let secret: SecretRef = format!("{name}/unrelated-api-key").parse().unwrap();
        store_token(&engine, &secret);
        let original = store.get(&secret).unwrap();
        let error = engine
            .ensure_app_channel_secret(&actor(), &secret, false)
            .unwrap_err();
        assert!(error.to_string().contains("already used"), "{error}");
        assert_eq!(store.get(&secret).unwrap(), original);
        assert!(
            engine
                .policy(&name)
                .unwrap()
                .snapshot
                .policy
                .agent_secrets
                .is_empty()
        );
        // Even our own abandoned ungranted token is not reused on retry.
        let fresh: SecretRef = format!("{name}/fresh-app-token").parse().unwrap();
        engine
            .ensure_app_channel_secret(&actor(), &fresh, false)
            .unwrap();
        assert!(
            engine
                .ensure_app_channel_secret(&actor(), &fresh, false)
                .is_err()
        );
        let missing: SecretRef = format!("{name}/missing-app-token").parse().unwrap();
        assert!(
            engine
                .ensure_app_channel_secret(&actor(), &missing, true)
                .is_err()
        );
        assert!(store.get(&missing).unwrap().is_none());
        let unrecorded: SecretRef = format!("{name}/unrecorded-app-token").parse().unwrap();
        let existing = SecretValue::new("unrecorded-private-value".into()).unwrap();
        store.set(&unrecorded, &existing).unwrap();
        assert!(
            engine
                .ensure_app_channel_secret(&actor(), &unrecorded, false)
                .is_err()
        );
        assert_eq!(store.get(&unrecorded).unwrap(), Some(existing));
    }

    #[test]
    fn exact_pending_agent_grant_can_resume_but_broader_or_other_agent_changes_cannot() {
        let _turn = crate::host_ports::HostPorts
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        for change in ["exact", "broader", "other-agent", "edited-file"] {
            let (_dir, engine, _store, _services, name, agent) = fixture();
            let plan = engine.app_connection_plan(&name, &agent).unwrap();
            store_token(&engine, &plan.secret);
            let GrantPlan::Add { mut after, .. } = plan.grant else {
                panic!("not new")
            };
            match change {
                "broader" => {
                    after = after.replace("allow_add = []", "allow_add = [\"example.com\"]");
                }
                "other-agent" => {
                    after = after.replace("secrets.agents.scout", "secrets.agents.other");
                }
                _ => {}
            }
            pending(&engine, &name, &after);
            if change == "edited-file" {
                std::fs::write(
                    engine.layout.policy_file(name.as_str()),
                    format!("{after}\n# unapplied edit\n"),
                )
                .unwrap();
            }
            let result = engine.app_connection_plan(&name, &agent);
            if change == "exact" {
                let resumed = result.unwrap();
                assert_eq!(resumed.secret, plan.secret);
                assert!(matches!(resumed.grant, GrantPlan::Resume(_)));
            } else {
                assert!(result.is_err(), "accepted {change}");
            }
        }
    }

    #[test]
    fn untracked_profile_can_be_explicitly_adopted_and_existing_grant_reuses_token() {
        let _turn = crate::host_ports::HostPorts
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let (_dir, engine, store, _services, name, agent) = fixture();
        let plan = engine.app_connection_plan(&name, &agent).unwrap();
        assert!(plan.needs_tracking);
        engine
            .adopt_agent(&actor(), &name, agent.clone(), Confirm::Ask)
            .unwrap();
        let GrantPlan::Add { before, after } = plan.grant else {
            panic!("not new")
        };
        store_token(&engine, &plan.secret);
        engine
            .policy_edit(&actor(), &name, &before, &after, Confirm::Ask)
            .unwrap();
        let current = engine.app_connection_plan(&name, &agent).unwrap();
        assert!(!current.needs_tracking);
        assert_eq!(current.secret, plan.secret);
        assert_eq!(current.grant, GrantPlan::Existing);
        let original = store.get(&plan.secret).unwrap();
        engine
            .ensure_app_channel_secret(&actor(), &plan.secret, true)
            .unwrap();
        assert_eq!(store.get(&plan.secret).unwrap(), original);
    }

    #[test]
    fn connecting_an_existing_untracked_profile_configures_and_reuses_its_private_token() {
        let _turn = crate::host_ports::HostPorts
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let (_dir, engine, store, services, name, agent) = fixture();
        let fail = engine.sandbox_home(&name).join("fail-configure");
        std::fs::write(&fail, "").unwrap();
        let failed = engine.connect_agent_to_app(&actor(), &name, &agent, Confirm::Yes);
        assert!(failed.is_err());
        let secret = engine.app_connection_plan(&name, &agent).unwrap().secret;
        let original = store.get(&secret).unwrap();
        assert!(original.is_some());
        assert!(
            engine
                .agents(&name)
                .unwrap()
                .iter()
                .any(|record| record.name == agent)
        );
        std::fs::remove_file(fail).unwrap();
        let result = engine.connect_agent_to_app(&actor(), &name, &agent, Confirm::Yes);
        if let Err(error) = result {
            let _ = engine.stop_sandbox(&actor(), &name, Confirm::Yes);
            panic!("{error}");
        }
        assert_eq!(store.get(&secret).unwrap(), original);
        assert_eq!(engine.app_agents().unwrap().len(), 1);
        assert!(
            engine
                .agents(&name)
                .unwrap()
                .iter()
                .any(|record| record.name == agent)
        );
        assert!(!services.started.borrow().is_empty());
        let result = engine.connect_agent_to_app(&actor(), &name, &agent, Confirm::Yes);
        let _ = engine.stop_sandbox(&actor(), &name, Confirm::Yes);
        result.unwrap();
        assert_eq!(store.get(&secret).unwrap(), original);
        assert_eq!(engine.secret_list(&name).unwrap().len(), 1);
        let calls =
            std::fs::read_to_string(engine.sandbox_home(&name).join("hermes-calls")).unwrap();
        assert!(calls.contains("-p scout plugins enable enclos"), "{calls}");
        assert!(!calls.contains(original.as_ref().unwrap().expose()));
    }
}
