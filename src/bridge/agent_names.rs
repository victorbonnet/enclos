//! Shared agent display names live with the bridge, independent of runtime identifiers.
use super::*;
use enclos_protocol::agent_name::{AgentName, NameMetadata, NameSet};
use enclos_protocol::plugin::{ErrorBody, ErrorCode};

/// Leave room in one Noise frame even for the longest legal envelope id.
pub(super) const AGENT_MESSAGE_BUDGET: usize = 60 * 1024;

fn agent_message_fits(message: &ToDevice) -> Result<bool, String> {
    let envelope = enclos_protocol::Envelope::new(
        MessageId::new("m".repeat(128)).expect("a bounded message id"),
        message,
    );
    serde_json::to_vec(&envelope)
        .map(|bytes| bytes.len() <= AGENT_MESSAGE_BUDGET)
        .map_err(|error| error.to_string())
}

/// Keep ordinary names inline; a large inventory receives its names in bounded follow-up frames.
pub(super) fn agent_inventory_messages(agents: Vec<AgentInfo>) -> Result<Vec<ToDevice>, String> {
    let mut inventory = ToDevice::AgentsList { agents };
    if agent_message_fits(&inventory)? {
        return Ok(vec![inventory]);
    }
    let ToDevice::AgentsList { agents } = &mut inventory else {
        unreachable!("constructed an agent inventory");
    };
    let names: Vec<_> = agents
        .iter_mut()
        .filter_map(|agent| {
            let name = (agent.name_revision != 0 || agent.display_name.is_some()).then(|| {
                ToDevice::AgentName(AgentName {
                    agent: agent.agent.clone(),
                    revision: agent.name_revision,
                    display_name: agent.display_name.take(),
                    of: String::new(),
                })
            });
            agent.name_revision = 0;
            name
        })
        .collect();
    if !agent_message_fits(&inventory)? {
        return Err("The host has too many agents to fit its inventory in one app message.".into());
    }
    let mut messages = Vec::with_capacity(names.len() + 1);
    messages.push(inventory);
    for name in names {
        if !agent_message_fits(&name)? {
            return Err("An agent name is too large to send to the app.".into());
        }
        messages.push(name);
    }
    Ok(messages)
}

fn name_error(of: &str, code: ErrorCode, message: impl Into<String>) -> ErrorBody {
    ErrorBody {
        of: Some(MessageId::new(of).expect("a request has a valid id")),
        code,
        message: message.into(),
    }
}

fn name_message(agent: &str, metadata: NameMetadata, of: String) -> ToDevice {
    ToDevice::AgentName(AgentName {
        agent: agent.into(),
        revision: metadata.revision,
        display_name: metadata.display_name,
        of,
    })
}

impl Hub {
    fn name_authority(
        &self,
        store: &Store,
        device: &Device,
        person: &str,
        agent: &str,
        write: bool,
    ) -> Result<(), String> {
        self.avatar_authority(store, device, person, agent, false)?;
        if write && self.host.as_deref() != Some(person) {
            return Err("Only the host's person can change a shared agent name.".into());
        }
        Ok(())
    }

    pub(super) fn get_agent_name(
        &self,
        store: &Store,
        device: &Device,
        person: &str,
        agent: &str,
        of: String,
    ) -> Result<ToDevice, ErrorBody> {
        self.name_authority(store, device, person, agent, false)
            .map_err(|e| name_error(&of, ErrorCode::NotAllowed, e))?;
        let metadata = store
            .agent_name(agent)
            .map_err(|e| name_error(&of, ErrorCode::Unknown, e.to_string()))?;
        Ok(name_message(agent, metadata, of))
    }

    pub(super) fn set_agent_name(
        &self,
        store: &Store,
        device: &Device,
        person: &str,
        edit: &NameSet,
        of: String,
    ) -> Result<ToDevice, ErrorBody> {
        self.name_authority(store, device, person, &edit.agent, true)
            .map_err(|e| name_error(&of, ErrorCode::NotAllowed, e))?;
        if edit.revision < 0 {
            return Err(name_error(
                &of,
                ErrorCode::BadMessage,
                "An agent name revision cannot be negative.",
            ));
        }
        let normalized = enclos_protocol::agent_name::normalize(edit.display_name.as_deref())
            .map_err(|e| name_error(&of, ErrorCode::BadMessage, e))?;
        let Some(saved) = store
            .set_agent_name(
                &edit.agent,
                edit.revision,
                normalized.as_deref(),
                (&device.id, person),
            )
            .map_err(|e| name_error(&of, ErrorCode::Unknown, e.to_string()))?
        else {
            return Err(name_error(
                &of,
                ErrorCode::Conflict,
                "The agent name changed on another device. Refresh and try again.",
            ));
        };
        if saved.revision != edit.revision {
            // Never send shared metadata to a device that was unpaired while connected.
            let paired = store
                .devices()
                .map_err(|e| name_error(&of, ErrorCode::Unknown, e.to_string()))?;
            let broadcast = name_message(&edit.agent, saved.clone(), String::new());
            for (id, (person, sender)) in self.devices.lock().expect("not poisoned").iter() {
                if paired
                    .iter()
                    .any(|device| &device.id == id && &device.person == person)
                {
                    let _ = sender.send(broadcast.clone());
                }
            }
        }
        Ok(name_message(&edit.agent, saved, of))
    }
}
