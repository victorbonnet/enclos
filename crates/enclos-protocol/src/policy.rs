//! The host person's sandbox policy editor. Values never contain secret contents.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyValue {
    pub value: String,
    pub source: String,
    pub locked: bool,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyField {
    pub key: String,
    pub label: String,
    pub multiple: bool,
    pub editable: bool,
    pub choices: Vec<String>,
    pub values: Vec<PolicyValue>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyState {
    pub sandbox: String,
    pub version: u32,
    pub base: String,
    pub editable: bool,
    pub reason: Option<String>,
    pub fields: Vec<PolicyField>,
    pub of: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyChange {
    pub field: String,
    pub before: Option<String>,
    pub after: Option<String>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyPreview {
    pub sandbox: String,
    pub base: String,
    pub revision: String,
    pub change: PolicyChange,
    pub changes: Vec<String>,
    pub restart: bool,
    pub of: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyApply {
    pub base: String,
    pub revision: String,
    pub change: PolicyChange,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn policy_apply_decodes_the_flat_reviewed_edit() {
        let raw = br#"{"v":1,"id":"m1","type":"sandbox.policy.apply","sandbox":"lab","base":"b1","revision":"r1","change":{"field":"allow","before":"example.com","after":null}}"#;
        let message = crate::device::decode_from_device(raw).unwrap();
        let crate::device::FromDevice::SandboxPolicyApply { sandbox, edit } = message.body else {
            panic!("wrong message")
        };
        assert_eq!(sandbox, "lab");
        assert_eq!(edit.revision, "r1");
        assert!(edit.change.after.is_none());
    }
    #[test]
    fn policy_reply_is_a_recognized_device_message() {
        let state = PolicyState {
            sandbox: "lab".into(),
            version: 1,
            base: "b".into(),
            editable: true,
            reason: None,
            fields: vec![],
            of: "m1".into(),
        };
        let message = crate::Envelope {
            v: crate::VERSION,
            id: crate::MessageId::new("m2").unwrap(),
            body: crate::device::ToDevice::SandboxPolicy(state.clone()),
        };
        let bytes = crate::encode_line(&message);
        assert_eq!(
            crate::device::decode_to_device(&bytes).unwrap().body,
            crate::device::ToDevice::SandboxPolicy(state)
        );
    }
}
