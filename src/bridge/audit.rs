//! Bounded pages of the host's audit log for its owner.
use enclos_protocol::MessageId;
use enclos_protocol::device::{AuditEntryInfo, ToDevice};

use crate::model::audit::AuditEntry;

use super::{Device, Hub, Store};
use enclos_protocol::plugin::{ErrorBody, ErrorCode};

impl Hub {
    pub(super) fn host_audit(
        &self,
        store: &Store,
        device: &Device,
        person: &str,
        of: MessageId,
        before: Option<u64>,
    ) -> Result<ToDevice, ErrorBody> {
        let error = |code, message: String| ErrorBody {
            of: Some(of.clone()),
            code,
            message,
        };
        let owner = store
            .host_person()
            .map_err(|e| error(ErrorCode::Internal, e.to_string()))?;
        let paired = store
            .device(&device.id)
            .map_err(|e| error(ErrorCode::Internal, e.to_string()))?;
        if owner.as_deref() != Some(person)
            || paired.is_none_or(|d| {
                d.person != person
                    || d.noise_key != device.noise_key
                    || d.device_key != device.device_key
            })
        {
            return Err(error(
                ErrorCode::NotAllowed,
                "Only the host's person on a paired device can read the audit log.".to_owned(),
            ));
        }
        let entries =
            crate::engine::Engine::open(self.layout.clone(), crate::state::Wait::Background)
                .audit(None)
                .map_err(|e| error(ErrorCode::Internal, e.to_string()))?;
        Ok(page(entries, of, before))
    }
}

const PAGE_SIZE: usize = 25;
// Leave room for the envelope and Noise's authentication tag (65,535 bytes).
const PAGE_BYTES: usize = 48_000;

pub(super) fn page(entries: Vec<AuditEntry>, of: MessageId, before: Option<u64>) -> ToDevice {
    let mut candidates = entries
        .into_iter()
        .rev()
        .filter(|e| before.is_none_or(|b| e.seq < b))
        .peekable();
    let mut page = Vec::new();
    let mut bytes = 0;
    while let Some(entry) = candidates.peek() {
        let info = info(entry);
        let size = serde_json::to_vec(&info)
            .expect("audit entry serializes")
            .len()
            + 1;
        if page.len() == PAGE_SIZE || bytes + size > PAGE_BYTES {
            break;
        }
        candidates.next();
        bytes += size;
        page.push(info);
    }
    let next_before = candidates.peek().and_then(|_| page.last().map(|e| e.seq));
    ToDevice::AuditList {
        of,
        entries: page,
        next_before,
    }
}

fn info(entry: &AuditEntry) -> AuditEntryInfo {
    AuditEntryInfo {
        seq: entry.seq,
        time: entry.at.as_second(),
        user: display(&entry.intent.by.user),
        host: display(&entry.intent.by.host),
        command: display(&entry.intent.command),
        target: entry.intent.target.as_deref().map(display),
        result: entry
            .finished
            .as_ref()
            .map_or("unfinished", |f| f.outcome.result.as_str())
            .to_owned(),
        message: entry.finished.as_ref().map(|f| display(&f.outcome.message)),
        finished: entry.finished.as_ref().map(|f| f.at.as_second()),
    }
}

// Display summaries cannot let a single entry exceed the transport limit.
// An ellipsis makes the shortening visible; the original remains on the host.
fn display(text: &str) -> String {
    if text.len() <= 1024 {
        return text.to_owned();
    }
    let mut end = 1024;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &text[..end])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        audit::{Actor, Finished, Intent, Outcome},
        now,
    };

    fn entry(seq: u64) -> AuditEntry {
        AuditEntry {
            seq,
            at: now(),
            intent: Intent {
                by: Actor {
                    user: "alice".into(),
                    host: "laptop".into(),
                },
                command: "sandbox create".into(),
                target: Some("lab".into()),
            },
            finished: None,
        }
    }

    #[test]
    fn host_audit_rechecks_owner_pairing_and_keys_and_reads_the_engine_log() {
        use crate::audit::jsonl::JsonlAuditLog;
        use crate::bridge::server::{Hub, SILENCE};
        use crate::bridge::transport::Transport;
        use crate::engine::Engine;
        use crate::layout::Layout;
        use crate::model::{plan::Confirm, sandbox::BackendKind};
        use crate::state::sqlite::SqliteStateStore;
        let dir = tempfile::tempdir().unwrap();
        let layout = Layout::at(dir.path().join("enclos"));
        let engine = Engine::new(
            layout.clone(),
            Box::new(SqliteStateStore::new(
                layout.state_db(),
                layout.state_lock(),
                crate::state::Wait::Background,
            )),
            Box::new(JsonlAuditLog::new(layout.audit_log())),
            vec![Box::new(crate::backend::fake::FakeBackend::available(
                BackendKind::Seatbelt,
            ))],
        );
        engine
            .init(
                &Actor {
                    user: "alice".into(),
                    host: "laptop".into(),
                },
                Confirm::Yes,
            )
            .unwrap();
        let hub = Hub::new(
            Transport::Tailscale,
            std::sync::Arc::new(|_| Err("unused".into())),
            dir.path().join("bridge.db"),
            layout,
            vec![7; 32],
            vec![],
            Some("alice".into()),
            SILENCE,
        );
        let store = hub.store().unwrap();
        let mut device = Device {
            id: "phone".into(),
            name: "Phone".into(),
            person: "alice".into(),
            noise_key: vec![1; 32],
            device_key: vec![2; 32],
            push_key: vec![],
            push_token: None,
            paired: 0,
            seen: None,
            node: None,
        };
        store.add_device(&device).unwrap();
        let id = || MessageId::new("audit-request").unwrap();
        let reply = hub
            .host_audit(&store, &device, "alice", id(), None)
            .unwrap();
        assert!(
            matches!(reply, ToDevice::AuditList { of, entries, .. } if of == id() && entries[0].command == "init" && entries[0].result == "ok")
        );
        assert_eq!(
            hub.host_audit(&store, &device, "guest", id(), None)
                .unwrap_err()
                .code,
            ErrorCode::NotAllowed
        );
        device.device_key = vec![3; 32];
        assert_eq!(
            hub.host_audit(&store, &device, "alice", id(), None)
                .unwrap_err()
                .code,
            ErrorCode::NotAllowed
        );
        device.device_key = vec![2; 32];
        store.remove_device(&device.id).unwrap();
        assert_eq!(
            hub.host_audit(&store, &device, "alice", id(), None)
                .unwrap_err()
                .code,
            ErrorCode::NotAllowed
        );
        store.add_device(&device).unwrap();
        std::fs::write(hub.layout.audit_log(), "not JSON\n").unwrap();
        let error = hub
            .host_audit(&store, &device, "alice", id(), None)
            .unwrap_err();
        assert_eq!(error.of, Some(id()));
        assert_eq!(error.code, ErrorCode::Internal);
    }

    #[test]
    fn newest_first_pages_have_no_gaps_and_preserve_outcomes() {
        let mut all: Vec<_> = (1..=30).map(entry).collect();
        all[29].finished = Some(Finished {
            at: now(),
            outcome: Outcome::failed("refused"),
        });
        let of = MessageId::new("request").unwrap();
        let first = page(all.clone(), of.clone(), None);
        let ToDevice::AuditList {
            entries,
            next_before,
            ..
        } = first
        else {
            panic!()
        };
        assert_eq!(
            entries.iter().map(|e| e.seq).collect::<Vec<_>>(),
            (6..=30).rev().collect::<Vec<_>>()
        );
        assert_eq!(entries[0].result, "failed");
        assert_eq!(entries[0].message.as_deref(), Some("refused"));
        assert_eq!(entries[1].result, "unfinished");
        assert_eq!(next_before, Some(6));
        let ToDevice::AuditList {
            entries,
            next_before,
            ..
        } = page(all, of.clone(), next_before)
        else {
            panic!()
        };
        assert_eq!(
            entries.iter().map(|e| e.seq).collect::<Vec<_>>(),
            vec![5, 4, 3, 2, 1]
        );
        assert_eq!(next_before, None);
        assert!(
            matches!(page(vec![], of, None), ToDevice::AuditList { entries, next_before: None, .. } if entries.is_empty())
        );
    }

    #[test]
    fn escaped_and_unicode_fields_fit_the_noise_frame_and_round_trip() {
        let all = (1..=30)
            .map(|seq| {
                let mut e = entry(seq);
                e.intent.by.user = "\0".repeat(3000);
                e.intent.by.host = "\0".repeat(3000);
                e.intent.command = "\0".repeat(3000);
                e.intent.target = Some("\0".repeat(3000));
                assert!(display(&"🌍".repeat(3000)).ends_with('…'));
                e.finished = Some(Finished {
                    at: now(),
                    outcome: Outcome::ok("\0".repeat(3000)),
                });
                e
            })
            .collect();
        let response = page(all, MessageId::new("request").unwrap(), None);
        let wire = enclos_protocol::encode_line(&enclos_protocol::Envelope::new(
            MessageId::new("response").unwrap(),
            response.clone(),
        ));
        assert!(wire.len() < 65_000);
        assert!(matches!(&response, ToDevice::AuditList { entries, .. } if !entries.is_empty()));
        assert_eq!(
            enclos_protocol::device::decode_to_device(&wire)
                .unwrap()
                .body,
            response
        );
        assert!(matches!(
            response,
            ToDevice::AuditList {
                next_before: Some(_),
                ..
            }
        ));
    }
}
