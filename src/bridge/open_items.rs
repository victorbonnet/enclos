//! A read-only projection: no second queue and no new decision authority.
use super::*;
use enclos_protocol::open_items::{OpenItem, OpenItemKind};

fn summary(text: &str) -> String {
    let line = enclos_protocol::visible::stripped(text, true);
    line.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(300)
        .collect()
}

impl Hub {
    /// Bounded frames, one snapshot. A revision orders live reports against a sync.
    pub(super) fn open_item_frames(
        &self,
        store: &Store,
        person: &str,
    ) -> Result<Vec<ToDevice>, String> {
        let mut serial = self.open_items.lock().expect("not poisoned");
        let next = serial.entry(person.to_owned()).or_default();
        *next = next.checked_add(1).ok_or("Open-item revision exhausted")?;
        let revision = *next;
        let mut items = match self.collect_open_items(store, person) {
            Ok(items) => items,
            Err(error) => {
                eprintln!("enclos app: open requests could not be refreshed: {error}");
                return Ok(vec![ToDevice::OpenItems {
                    revision,
                    reset: true,
                    complete: true,
                    unavailable: true,
                    items: vec![],
                }]);
            }
        };
        items.sort_by(|a, b| b.since.cmp(&a.since).then(a.id.cmp(&b.id)));
        if items.len() > 8192 {
            return Ok(vec![ToDevice::OpenItems {
                revision,
                reset: true,
                complete: true,
                unavailable: true,
                items: vec![],
            }]);
        }
        let frame = |items: Vec<OpenItem>, reset, complete| ToDevice::OpenItems {
            revision,
            reset,
            complete,
            unavailable: false,
            items,
        };
        let mut frames = Vec::new();
        let mut chunk = Vec::new();
        for item in items {
            let mut candidate = chunk.clone();
            candidate.push(item.clone());
            let encoded = encode_line(&Envelope::new(
                MessageId::new("00000000-0000-0000-0000-000000000000").expect("valid id"),
                frame(candidate, frames.is_empty(), false),
            ));
            if chunk.len() == 24 || encoded.len() > enclos_protocol::device::MAX_DEVICE_MESSAGE {
                if chunk.is_empty() {
                    return Err("An open request exceeds the device frame limit".into());
                }
                frames.push(frame(std::mem::take(&mut chunk), frames.is_empty(), false));
            }
            chunk.push(item);
        }
        frames.push(frame(chunk, frames.is_empty(), true));
        Ok(frames)
    }

    fn collect_open_items(&self, store: &Store, person: &str) -> Result<Vec<OpenItem>, String> {
        let snapshot = store
            .db
            .unchecked_transaction()
            .map_err(|e| e.to_string())?;
        let host = store.host_person().map_err(|e| e.to_string())?;
        let mut items = vec![];
        for question in store
            .indexed_questions_for(person)
            .map_err(|e| e.to_string())?
        {
            let q = question.info;
            if q.definition.approval.is_some() && host.as_deref() != Some(person) {
                continue;
            }
            let since = store
                .question_time(&q.definition.id)
                .map_err(|e| e.to_string())?;
            items.push(OpenItem {
                id: q.definition.id.to_string(),
                kind: if q.definition.approval.is_some() {
                    OpenItemKind::RuntimeApproval
                } else {
                    OpenItemKind::Question
                },
                agent: Some(q.agent),
                conversation: Some(q.conversation),
                summary: summary(&q.definition.text),
                since,
                expired: q.state == enclos_protocol::question::QuestionState::Expired,
            });
        }
        // These two kinds carry host-person authority; a conversation share does not.
        if host.as_deref() == Some(person) {
            for held in store
                .indexed_held_tasks_for(person)
                .map_err(|e| e.to_string())?
            {
                let h = held.info;
                items.push(OpenItem {
                    id: h.task.to_string(),
                    kind: OpenItemKind::HeldTask,
                    agent: Some(h.agent),
                    conversation: Some(h.conversation),
                    summary: summary(&h.reason),
                    since: h.since,
                    expired: false,
                });
            }
            for a in store
                .approvals()
                .map_err(|e| e.to_string())?
                .into_iter()
                .filter(|a| matches!(a.state.as_str(), "pending" | "applying" | "failed"))
            {
                items.push(OpenItem {
                    id: a.request,
                    kind: OpenItemKind::PolicyRequest,
                    agent: (!a.agent.is_empty()).then_some(a.agent),
                    conversation: a.conversation.and_then(|id| ConversationId::new(id).ok()),
                    summary: summary(&a.action),
                    since: a.time,
                    expired: false,
                });
            }
        }
        snapshot.commit().map_err(|e| e.to_string())?;
        Ok(items)
    }

    pub(super) fn publish_open_items(&self, store: &Store, person: &str) {
        let subscribed = self.open_item_devices.lock().expect("not poisoned").clone();
        if subscribed.is_empty() {
            return;
        }
        match self.open_item_frames(store, person) {
            Ok(frames) => {
                let paired = store.devices().unwrap_or_default();
                let devices = self.devices.lock().expect("not poisoned");
                for (id, (owner, sender, _)) in devices.iter() {
                    if owner == person
                        && subscribed.contains(id)
                        && paired.iter().any(|d| d.id == *id && d.person == person)
                    {
                        for frame in &frames {
                            let _ = sender.send(frame.clone());
                        }
                    }
                }
            }
            Err(error) => eprintln!("enclos app: open requests could not be read: {error}"),
        }
    }
}
