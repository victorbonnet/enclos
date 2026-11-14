//! Policy management is available only to the host's person on a still-paired device.
use super::*;
use crate::engine::Engine;
use crate::model::{audit::Actor, sandbox::SandboxName};
use enclos_protocol::policy::{PolicyApply, PolicyState};

/// Whether policy entry `value` of list `field` is what an approved
/// `access` wrote: the request's target as the engine stored it, a
/// destination normalized (`API.example.com:443` is `api.example.com`) and a
/// writable path with its symlinks resolved.
pub(super) fn accepted_entry(
    field: &str,
    value: &str,
    access: &enclos_protocol::approval::Access,
) -> bool {
    use crate::net::host::AllowEntry;
    use enclos_protocol::approval::AccessKind;
    match (field, &access.kind) {
        ("allow", AccessKind::Network) => {
            AllowEntry::parse(&access.target).is_ok_and(|e| e.to_string() == value)
        }
        ("private", AccessKind::Network) if access.private => {
            AllowEntry::parse(&access.target).is_ok_and(|e| e.host_text() == value)
        }
        ("write", AccessKind::Write) => {
            access.target == value
                || crate::policy::paths::real_path(std::path::Path::new(&access.target))
                    .display()
                    .to_string()
                    == value
        }
        _ => false,
    }
}

/// What a device is sent for `body`, a sandbox's policy, its preview or
/// the sandboxes' list, as the answer to `of`: `body`, or, when it does not
/// fit one device-leg message (`agent_names::agent_message_fits`), an error
/// saying where to see it. Sent as it is, it could not be sealed, and the
/// device's connection would end.
pub(super) fn fitting(body: ToDevice, of: &MessageId) -> ToDevice {
    if super::agent_names::agent_message_fits(&body).unwrap_or(false) {
        return body;
    }
    let message = match &body {
        ToDevice::SandboxPolicy(state) => format!(
            "The policy of sandbox {} is too large to show on the phone. See it on the host with `enclos policy show {}`.",
            state.sandbox, state.sandbox
        ),
        ToDevice::SandboxPolicyPreview(preview) => format!(
            "This change to sandbox {} is too large to preview on the phone. Make it on the host with `enclos policy edit {}`.",
            preview.sandbox, preview.sandbox
        ),
        _ => "The list is too large to show on the phone. See it on the host with `enclos sandbox list`.".to_owned(),
    };
    ToDevice::Error(enclos_protocol::plugin::ErrorBody {
        of: Some(of.clone()),
        code: enclos_protocol::plugin::ErrorCode::Unsupported,
        message,
    })
}

impl Hub {
    /// Sends `body` to `person`'s devices when it fits one device-leg
    /// message; else none, which would end each device's connection: a
    /// device that asks for it is told why it does not come ([`fitting`]).
    pub(super) fn deliver_fitting(&self, person: &str, body: ToDevice) {
        if super::agent_names::agent_message_fits(&body).unwrap_or(false) {
            self.deliver(person, body);
        }
    }

    pub(super) fn policy_authority(
        &self,
        store: &Store,
        device: &Device,
        person: &str,
        sandbox: &str,
    ) -> Result<SandboxName, String> {
        self.host_authority(store, device, person)
            .map_err(|(_, message)| message)?;
        if !self
            .agents
            .iter()
            .any(|a| a.name.split('/').next() == Some(sandbox))
        {
            return Err("This sandbox is not listed by this bridge.".into());
        }
        sandbox.parse::<SandboxName>().map_err(|e| e.to_string())
    }
    pub(super) fn managed_policy(
        &self,
        store: &Store,
        name: &SandboxName,
    ) -> Result<PolicyState, String> {
        let mut state = Engine::open(self.layout.clone(), crate::state::Wait::Background)
            .mobile_policy(name)
            .map_err(|e| e.to_string())?;
        let accepted = store.accepted_access().map_err(|e| e.to_string())?;
        for field in &mut state.fields {
            for value in &mut field.values {
                let matches = accepted.iter().any(|a| {
                    a.sandbox == name.as_str()
                        && accepted_entry(&field.key, &value.value, &a.access)
                });
                if matches {
                    value.source = "Accepted access".into();
                }
            }
        }
        Ok(state)
    }
    pub(super) fn apply_managed_policy(
        self: &Arc<Self>,
        store: &Store,
        device: &Device,
        person: &str,
        name: &SandboxName,
        edit: &PolicyApply,
    ) -> Result<PolicyState, String> {
        // Authorization is rechecked for every operation, not retained from a page opening.
        self.policy_authority(store, device, person, name.as_str())?;
        let actor = Actor {
            user: format!("{person} (device {})", device.id),
            host: self.layout.data().display().to_string(),
        };
        let result = Engine::open(self.layout.clone(), crate::state::Wait::Background)
            .mobile_policy_apply(&actor, name, &edit.base, &edit.revision, &edit.change);
        self.refresh_access_context(name.as_str());
        if let Ok(state) = self.managed_policy(store, name) {
            self.deliver_fitting(person, ToDevice::SandboxPolicy(state));
        }
        result.map_err(|e| format!("{e}. Refresh the policy before retrying."))?;
        // Saved and audited: a failure to read it back is not a refusal
        self.managed_policy(store, name).map_err(|e| {
            format!("The edit was saved, but the policy could not be read back ({e}). Refresh the policy to see it.")
        })
    }
}
