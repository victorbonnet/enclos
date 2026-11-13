//! Agent credentials and app history travel together, independently of a runtime.
use super::{ChannelRequest, Engine};
use crate::bridge::portable::{Credential, HostState};
use crate::bridge::store::Store;
use crate::error::{Error, Result};
use crate::model::{
    agent::AgentName,
    audit::Actor,
    channel::Channel,
    plan::Confirm,
    sandbox::SandboxName,
    secret::{SecretRef, SecretValue},
};
use std::collections::BTreeMap;
use toml_edit::{DocumentMut, Item, Table};

fn failed(e: impl std::fmt::Display) -> Error {
    Error::Session {
        what: e.to_string(),
    }
}
impl Engine {
    pub(super) fn export_host_state(
        &self,
        name: &SandboxName,
        agent: &AgentName,
    ) -> Result<HostState> {
        let mut policy = self.policy(name)?.snapshot.policy;
        let mut grants = policy.secrets.clone();
        if let Some(own) = policy.agent_secrets.get(agent) {
            grants.extend(own.clone());
        }
        let credentials = self
            .granted_values(&grants)?
            .into_iter()
            .map(|(variable, value)| Credential { variable, value })
            .collect();
        policy.agent_secrets.retain(|key, _| key == agent);
        let history = if self.app_store_path().exists() {
            Store::open(&self.app_store_path())
                .map_err(failed)?
                .export_history(
                    name.as_str(),
                    agent.as_str(),
                    &self.layout.data().join("app-media"),
                )
                .map_err(failed)?
        } else {
            Default::default()
        };
        let state = HostState {
            credentials,
            history,
            source_policy: Some(policy),
        };
        state.validate().map_err(failed)?;
        Ok(state)
    }

    pub(super) fn preflight_host_import(
        &self,
        name: &SandboxName,
        agent: &AgentName,
        state: Option<&HostState>,
    ) -> Result<()> {
        let view = self.policy(name)?;
        if view.pending.is_some() {
            return Err(failed(
                "apply or discard the destination's pending policy before importing an agent",
            ));
        }
        self.refuse_builtin(name, self.runtime_of(name)?, agent.as_str())?;
        self.refuse_known_agent(name, agent)?;
        let runtime = crate::runtime::adapter(self.runtime_of(name)?);
        let found = runtime
            .agents_in(&self.sandbox_home(name))
            .map_err(failed)?;
        if found.contains(&crate::runtime::RuntimeAgentName::from(agent)) {
            return Err(failed(
                "the destination runtime agent already exists; choose a fresh name",
            ));
        }
        if self.command_named(name, agent)?.is_some() {
            return Err(failed(
                "the destination agent name is already a command; choose a fresh name",
            ));
        }
        if let Some(state) = state {
            state.validate().map_err(failed)?;
            if state
                .credentials
                .iter()
                .any(|c| c.variable == Channel::App.token_variable())
                && self
                    .layout
                    .agent_app_socket(name.as_str(), agent.as_str())
                    .as_os_str()
                    .len()
                    > 103
            {
                return Err(failed(
                    "the destination app socket path is too long; set ENCLOS_HOME to a shorter folder before importing",
                ));
            }
            if !state.credentials.is_empty() {
                self.secrets.for_new()?.readable()?;
            }
            if !state.history.conversations.is_empty()
                && (!self.app_store_path().exists()
                    || Store::read_host_person(&self.app_store_path())
                        .map_err(failed)?
                        .is_none())
            {
                return Err(failed(
                    "pair the destination host before importing app history; imported history belongs to its host person",
                ));
            }
        }
        Ok(())
    }

    pub(super) fn restore_host_state(
        &self,
        by: &Actor,
        name: &SandboxName,
        agent: &AgentName,
        state: &HostState,
        conversations: &BTreeMap<String, String>,
    ) -> Result<()> {
        let before = self.layout.read_policy(name.as_str())?;
        let mut document = before.parse::<DocumentMut>().map_err(failed)?;
        let mut grants = Table::new();
        let nonce = crate::bridge::ids::new_id()
            .map_err(failed)?
            .replace('-', "");
        let mut imported = Vec::new();
        for (i, credential) in state.credentials.iter().enumerate() {
            let secret: SecretRef = format!("{name}/import-{}-{i}", &nonce[..16])
                .parse()
                .map_err(failed)?;
            if self.state.secrets(name)?.iter().any(|r| r.secret == secret) {
                return Err(failed("an import credential name already exists; retry"));
            }
            let mut replacement = None;
            if credential.variable == Channel::App.token_variable() {
                let mut bytes = [0u8; 32];
                getrandom::fill(&mut bytes).map_err(failed)?;
                replacement = Some(
                    SecretValue::new(enclos_protocol::pairing::encode(&bytes)).map_err(failed)?,
                );
            }
            let value = replacement.as_ref().unwrap_or(&credential.value);
            if let Err(error) = self.secret_set(by, &secret, Some(value), Confirm::Yes) {
                for secret in &imported {
                    let _ = self.secret_rm(by, secret, Confirm::Yes);
                }
                return Err(error);
            }
            imported.push(secret.clone());
            grants[&credential.variable] = toml_edit::value(secret.in_policy().to_string());
        }
        if !grants.is_empty() {
            let mut env = Table::new();
            env["env"] = Item::Table(grants);
            document["secrets"]["agents"][agent.as_str()] = Item::Table(env);
            let text = document.to_string();
            let saved = self.write(
                by,
                "agent import credentials",
                Some(format!("{name}/{agent}")),
                |_| {
                    format!(
                        "restored {} scoped credential bindings under new names",
                        state.credentials.len()
                    )
                },
                |lock| {
                    if self.layout.read_policy(name.as_str())? != before
                        || self.state.pending_policy(name)?.is_some()
                    {
                        return Err(failed(
                            "the destination policy changed during import; inspect it and retry",
                        ));
                    }
                    self.save_policy_for_runtime(
                        lock,
                        by,
                        name,
                        &text,
                        Some(self.runtime_of(name)?),
                    )
                },
            );
            if let Err(error) = saved {
                for secret in &imported {
                    let _ = self.secret_rm(by, secret, Confirm::Yes);
                }
                return Err(error);
            }
        }
        let app = state
            .credentials
            .iter()
            .any(|c| c.variable == Channel::App.token_variable());
        self.configure_agent(
            by,
            name,
            Some(agent),
            app.then(|| ChannelRequest {
                channel: Channel::App,
                token: None,
                answers: Vec::new(),
            }),
            &[],
            Confirm::Yes,
        )?;
        if !state.history.conversations.is_empty() {
            self.write(by,"agent import history",Some(format!("{name}/{agent}")),|_|format!("restored {} conversations and {} messages; imported requests cannot execute",state.history.conversations.len(),state.history.messages.len()),|_|Store::open(&self.app_store_path()).map_err(failed)?.import_history(&state.history,&format!("{name}/{agent}"),conversations,&self.layout.data().join("app-media")).map_err(failed))?;
        }
        Ok(())
    }
}
