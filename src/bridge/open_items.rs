//! A read-only projection: no second queue and no new decision authority.
use super::*;
use enclos_protocol::open_items::{OpenItem, OpenItemKind};

/// The exact discovery generation the device reviewed; not a native decision.
pub(super) struct ReminderRef<'a> {
    pub kind: OpenItemKind,
    pub id: &'a str,
    pub agent: Option<&'a str>,
    pub version: &'a str,
}

fn summary(text: &str) -> String {
    let line = enclos_protocol::visible::stripped(text, true);
    let cut: String = line
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(300)
        .collect();
    // Cutting a valid emoji sequence can expose a now-hidden trailing joiner.
    enclos_protocol::visible::stripped(&cut, false)
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
            eprintln!("enclos app: open requests exceed the 8192-item snapshot limit");
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
        let mut items = self.read_open_items(store, person)?;
        let dismissed = store
            .dismissed_open_items(person)
            .map_err(|e| e.to_string())?;
        items.retain(|item| {
            !dismissed.contains(&(
                item.kind.as_str().to_owned(),
                item.agent.clone().unwrap_or_default(),
                item.id.clone(),
                item.version.clone(),
            ))
        });
        snapshot.commit().map_err(|e| e.to_string())?;
        Ok(items)
    }

    /// Canonical sources, also read under the immediate dismissal transaction.
    fn read_open_items(&self, store: &Store, person: &str) -> Result<Vec<OpenItem>, String> {
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
                version: format!("question:{}", q.definition.id),
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
                    version: format!("held:{}", h.revision),
                    id: h.task.to_string(),
                    kind: OpenItemKind::HeldTask,
                    agent: Some(h.agent),
                    conversation: Some(h.conversation),
                    // The agent's question, when it wrote one (ADR 0073).
                    summary: summary(h.ask.as_ref().map_or(&h.reason, |ask| &ask.decision)),
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
                    version: format!("policy:{}:{}", a.revision, a.state),
                    id: a.request,
                    kind: OpenItemKind::PolicyRequest,
                    agent: (!a.agent.is_empty()).then_some(a.agent),
                    conversation: a.conversation.and_then(|id| ConversationId::new(id).ok()),
                    summary: summary(&format!(
                        "{} {}",
                        match a.access.kind {
                            enclos_protocol::approval::AccessKind::Network => "Connect to",
                            enclos_protocol::approval::AccessKind::Write => "Write to",
                            enclos_protocol::approval::AccessKind::Read => "Read",
                        },
                        enclos_protocol::visible::revealed(if a.scope.trim().is_empty() {
                            &a.access.target
                        } else {
                            &a.scope
                        })
                    )),
                    since: a.time,
                    expired: false,
                });
            }
        }
        Ok(items)
    }

    pub(super) fn dismiss_open_item(
        &self,
        store: &Store,
        device: &Device,
        person: &str,
        request: MessageId,
        reminder: ReminderRef<'_>,
    ) -> Result<ToDevice, ErrorBody> {
        let ReminderRef {
            kind,
            id,
            agent,
            version,
        } = reminder;
        let error = |code, message: &str| ErrorBody {
            of: Some(request.clone()),
            code,
            message: message.into(),
        };
        let internal = |detail: String| {
            eprintln!("enclos app: reminder dismissal failed: {detail}");
            error(
                ErrorCode::Internal,
                "The reminder could not be dismissed. Refresh and try again.",
            )
        };
        let transaction = rusqlite::Transaction::new_unchecked(
            &store.db,
            rusqlite::TransactionBehavior::Immediate,
        )
        .map_err(|e| internal(e.to_string()))?;
        if device.person != person
            || store
                .device(&device.id)
                .map_err(|e| internal(e.to_string()))?
                .is_none_or(|current| {
                    current.person != person
                        || current.noise_key != device.noise_key
                        || current.device_key != device.device_key
                })
        {
            return Err(error(ErrorCode::NotFound, "No such request."));
        }
        let item = self
            .read_open_items(store, person)
            .map_err(internal)?
            .into_iter()
            .find(|item| item.kind == kind && item.id == id && item.agent.as_deref() == agent)
            .ok_or_else(|| error(ErrorCode::NotFound, "No such request."))?;
        if item.version != version || version.is_empty() {
            return Err(error(
                ErrorCode::Conflict,
                "This request changed. Refresh before dismissing it.",
            ));
        }
        store
            .dismiss_open_item(person, &item, request.as_str())
            .map_err(|e| internal(e.to_string()))?;
        transaction.commit().map_err(|e| internal(e.to_string()))?;
        self.publish_open_items(store, person);
        Ok(ToDevice::OpenItemDismissed {
            of: request,
            kind,
            item: id.to_owned(),
            agent: item.agent,
            version: item.version,
        })
    }

    pub(super) fn publish_open_items(&self, store: &Store, person: &str) {
        let subscribed = self.open_item_devices.lock().expect("not poisoned").clone();
        if subscribed.is_empty() {
            return;
        }
        match self.open_item_frames(store, person) {
            Ok(frames) => {
                let paired = match store.devices() {
                    Ok(devices) => devices,
                    Err(error) => {
                        eprintln!(
                            "enclos app: open requests could not check paired devices: {error}"
                        );
                        return;
                    }
                };
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

impl Store {
    fn dismissed_open_items(
        &self,
        person: &str,
    ) -> rusqlite::Result<HashSet<(String, String, String, String)>> {
        self.db
            .prepare("SELECT kind,agent,item,version FROM open_item_dismissals WHERE person=?1")?
            .query_map([person], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })?
            .collect()
    }
    fn dismiss_open_item(
        &self,
        person: &str,
        item: &OpenItem,
        request: &str,
    ) -> rusqlite::Result<()> {
        self.db.execute("INSERT INTO open_item_dismissals(person,kind,agent,item,version,request) VALUES (?1,?2,?3,?4,?5,?6) ON CONFLICT(person,kind,agent,item) DO UPDATE SET version=excluded.version,request=excluded.request",
            rusqlite::params![person,item.kind.as_str(),item.agent.as_deref().unwrap_or(""),item.id,item.version,request]).map(drop)
    }
}

#[cfg(test)]
mod review_tests {
    use super::*;
    #[test]
    fn review_summary_cuts_never_leave_a_hidden_joiner() {
        let text = format!("{}👩‍💻", "a".repeat(298));
        let shown = summary(&text);
        assert!(shown.chars().count() <= 300);
        assert!(!enclos_protocol::visible::has_hidden(&shown, false));
        assert_eq!(summary(&shown), shown);
    }
}
