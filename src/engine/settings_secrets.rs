//! The engine supplies bounded runtime settings reads and policy grants to
//! its adapter, retaining only normalized findings without secret values.

use std::collections::BTreeSet;

use super::Engine;
use super::restart::MAX_SETTINGS;
use crate::model::sandbox::SandboxRecord;
use crate::runtime::home::read_text;
use crate::runtime::settings::{SettingsFile, SettingsFinding};
use crate::runtime::{RuntimeAgentName, adapter};

impl Engine {
    /// What is reported of the settings files of the sandbox's runtime,
    /// for its built-in agent and every agent the runtime has (ADR 0031's
    /// files), read as other files of the home are (ADR 0023), and of each
    /// agent the policy grants secrets of its own. What could not be read
    /// is in `unreadable`; a sandbox without a runtime has nothing to look
    /// at.
    pub(super) fn settings_secrets(
        &self,
        record: &SandboxRecord,
        unreadable: &mut Vec<String>,
    ) -> Vec<SettingsFinding> {
        let Some(kind) = record.runtime else {
            return Vec::new();
        };
        let runtime = adapter(kind);
        let name = &record.name;
        let policy = match self.policy(name) {
            Ok(view) => view.snapshot.policy,
            Err(e) => {
                unreadable.push(format!(
                    "did not look for secrets in {}'s settings: cannot read its active policy: {e}",
                    kind.display_name()
                ));
                return Vec::new();
            }
        };
        let home = self.sandbox_home(name);
        let listed = runtime.agents_in(&home);
        let whole_list = listed.is_ok();
        let agents = listed.unwrap_or_else(|e| {
            unreadable.push(format!(
                "did not look for secrets in the settings of {}'s other agents: cannot list them: {e}",
                kind.display_name()
            ));
            Vec::new()
        });
        let builtin = runtime.builtin_agent().map(|b| b.runtime_name());
        let looked_at: Vec<_> = builtin.into_iter().chain(agents).collect();
        let mut files = Vec::new();
        let mut not_set_up = Vec::new();
        for agent in &looked_at {
            let own = policy.agent_secrets.get(agent.as_str());
            let granted: BTreeSet<String> = policy
                .secrets
                .keys()
                .chain(own.into_iter().flat_map(|g| g.keys()))
                .cloned()
                .collect();
            let secrets_file = self
                .layout
                .agent_secrets_file(name.as_str(), agent.as_str());
            let (mut reads, mut whole) = (false, true);
            for path in runtime.agent_settings_files(agent) {
                match read_text(&home, &path, MAX_SETTINGS) {
                    Ok(Some(text)) => {
                        reads |= runtime.reads_agent_secrets(&text, &secrets_file);
                        files.push(SettingsFile {
                            agent: agent.clone(),
                            path,
                            text,
                            granted: granted.clone(),
                        });
                    }
                    Ok(None) => {}
                    Err(e) => {
                        whole = false;
                        unreadable.push(format!("did not look for secrets in {path}: {e}"));
                    }
                }
            }
            if whole && !reads && own.is_some() {
                not_set_up.push(SettingsFinding::NotSetUp {
                    agent: agent.clone(),
                });
            }
        }
        // Granted to an agent the runtime does not have: it reaches no one.
        if whole_list {
            let absent = policy
                .agent_secrets
                .keys()
                .map(RuntimeAgentName::from)
                .filter(|agent| !looked_at.contains(agent));
            not_set_up.extend(absent.map(|agent| SettingsFinding::NotSetUp { agent }));
        }
        let mut found = runtime.inspect_settings(&files).unwrap_or_else(|why| {
            unreadable.push(format!(
                "did not inspect {} settings: {why}",
                kind.display_name()
            ));
            Vec::new()
        });
        found.append(&mut not_set_up);
        found
    }
}
