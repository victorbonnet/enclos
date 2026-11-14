//! Authority shared by operations reserved for the host's person.
use super::{Device, Hub, Store};
use crate::model::audit::Actor;
use enclos_protocol::plugin::ErrorCode;

/// Who a paired device's request is in the engine's audit log, the same on
/// every bridge path: its person and device, and the request when the entry
/// answers one, on this host.
pub(super) fn device_actor(person: &str, device: &str, request: Option<&str>) -> Actor {
    let user = match request {
        Some(request) => format!("{person} (device {device}, request {request})"),
        None => format!("{person} (device {device})"),
    };
    Actor::on_this_host(user)
}

impl Hub {
    /// Append each supported feature here so authentication has one capability list.
    pub(super) fn capabilities(&self, person: &str) -> Vec<String> {
        let mut capabilities = Vec::new();
        if self.known_host().as_deref() == Some(person) {
            capabilities.push("audit".to_owned());
            if self.provisioning.is_some() {
                capabilities.push("sandboxes".to_owned());
            }
        }
        capabilities
    }

    /// Recheck the host's current person and both keys of this paired device.
    /// Database details stay on the host, including before authority is established.
    pub(super) fn host_authority(
        &self,
        store: &Store,
        device: &Device,
        person: &str,
    ) -> Result<(), (ErrorCode, String)> {
        let internal = |e: rusqlite::Error| {
            eprintln!("enclos app: host authority could not be read: {e}");
            (
                ErrorCode::Internal,
                "The host's device access could not be checked. Try again later.".to_owned(),
            )
        };
        if store.host_person().map_err(internal)?.as_deref() != Some(person) {
            return Err((
                ErrorCode::NotAllowed,
                "Only the host's person can use this operation. The host's identity must be known."
                    .to_owned(),
            ));
        }
        if store.device(&device.id).map_err(internal)?.is_none_or(|d| {
            d.person != person
                || d.noise_key != device.noise_key
                || d.device_key != device.device_key
        }) {
            return Err((
                ErrorCode::NotAllowed,
                "This device is no longer paired with these keys.".to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_device_is_audited_as_its_person_and_device_on_this_host() {
        let here = Actor::on_this_host(String::new()).host;
        assert_eq!(
            device_actor("alice@example.com", "d-1", None),
            Actor {
                user: "alice@example.com (device d-1)".into(),
                host: here.clone(),
            }
        );
        assert_eq!(
            device_actor("alice@example.com", "d-1", Some("r-1")).user,
            "alice@example.com (device d-1, request r-1)"
        );
    }
}
