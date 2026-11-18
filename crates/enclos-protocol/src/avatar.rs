//! Shared agent presentation assets; always bounded raster images over the paired connection.
use serde::{Deserialize, Serialize};
pub const MAX_AVATAR_BYTES: usize = 32 * 1024;
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AvatarMetadata {
    pub revision: i64,
    pub version: Option<String>,
}
impl AvatarMetadata {
    pub fn is_default(&self) -> bool {
        self.revision == 0 && self.version.is_none()
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentAvatar {
    pub agent: String,
    pub revision: i64,
    pub version: Option<String>,
    pub image: Option<String>,
    pub of: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AvatarSet {
    pub agent: String,
    pub revision: i64,
    pub image: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        device::{FromDevice, ToDevice},
        envelope::Envelope,
        ids::MessageId,
        pairing::encode,
    };
    #[test]
    fn avatar_wire_messages_roundtrip_and_fit_one_noise_frame() {
        let id = MessageId::new("avatar-test").unwrap();
        let set = Envelope::new(
            id.clone(),
            FromDevice::AgentAvatarSet(AvatarSet {
                agent: "lab/coder".into(),
                revision: 7,
                image: Some(encode(&vec![42; MAX_AVATAR_BYTES])),
            }),
        );
        let json = serde_json::to_vec(&set).unwrap();
        assert!(json.len() < crate::noise::MAX_NOISE_MESSAGE - 16);
        assert_eq!(crate::device::decode_from_device(&json).unwrap(), set);
        let removed = Envelope::new(
            id.clone(),
            FromDevice::AgentAvatarSet(AvatarSet {
                agent: "lab/coder".into(),
                revision: 8,
                image: None,
            }),
        );
        assert_eq!(
            crate::device::decode_from_device(&serde_json::to_vec(&removed).unwrap()).unwrap(),
            removed
        );
        let reply = Envelope::new(
            id,
            ToDevice::AgentAvatar(AgentAvatar {
                agent: "lab/coder".into(),
                revision: 8,
                version: None,
                image: None,
                of: "avatar-test".into(),
            }),
        );
        assert_eq!(
            crate::device::decode_to_device(&serde_json::to_vec(&reply).unwrap()).unwrap(),
            reply
        );
    }

    #[test]
    fn a_refused_photo_edit_names_why_with_its_own_codes() {
        use crate::plugin::ErrorCode;
        for (code, wire) in [
            (ErrorCode::Conflict, "conflict"),
            (ErrorCode::Internal, "internal"),
        ] {
            assert_eq!(serde_json::to_value(code).unwrap(), wire);
            assert_eq!(
                serde_json::from_value::<ErrorCode>(wire.into()).unwrap(),
                code
            );
        }
    }
}
