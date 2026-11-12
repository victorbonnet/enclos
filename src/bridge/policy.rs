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

impl Hub {
    pub(super) fn policy_authority(
        &self,
        store: &Store,
        device: &Device,
        person: &str,
        sandbox: &str,
    ) -> Result<SandboxName, String> {
        if self.known_host().as_deref() != Some(person) {
            return Err("Only the host's person can manage sandbox policy.".into());
        }
        if !store
            .devices()
            .map_err(|e| e.to_string())?
            .iter()
            .any(|d| d.id == device.id && d.person == person)
        {
            return Err("This device is no longer paired.".into());
        }
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
            self.deliver(person, ToDevice::SandboxPolicy(state));
        }
        result.map_err(|e| format!("{e}. Refresh the policy before retrying."))?;
        self.managed_policy(store, name)
    }
}
