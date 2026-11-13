//! Runtime-confirmed deletion. Runtime state is touched only by its channel plugin.
use super::*;

#[cfg(test)]
#[path = "deletion_tests.rs"]
mod tests;

const WAIT: Duration = Duration::from_secs(25);
const MAX_PENDING: usize = 64;

pub(super) struct PendingDelete {
    agent: String,
    generation: u64,
    answer: Sender<Result<(), ErrorBody>>,
}

fn failure(code: ErrorCode, message: impl Into<String>) -> ErrorBody {
    ErrorBody {
        of: None,
        code,
        message: message.into(),
    }
}
fn storage(error: rusqlite::Error) -> ErrorBody {
    eprintln!("enclos app: conversation deletion: {error}");
    failure(
        ErrorCode::Internal,
        "Deletion could not finish. Retry Delete to finish removing this conversation.",
    )
}

impl Hub {
    pub(super) fn delete_answer(
        &self,
        agent: &str,
        generation: u64,
        of: Option<&MessageId>,
        result: Result<(), ErrorBody>,
    ) -> bool {
        let Some(of) = of else {
            return false;
        };
        let mut pending = self.deletions.lock().expect("not poisoned");
        if !pending
            .get(of.as_str())
            .is_some_and(|p| p.agent == agent && p.generation == generation)
        {
            return false;
        }
        let p = pending.remove(of.as_str()).expect("checked");
        let _ = p.answer.send(result);
        true
    }

    pub(super) fn delete_disconnected(&self, agent: &str, generation: u64) {
        self.deletions
            .lock()
            .expect("not poisoned")
            .retain(|_, p| p.agent != agent || p.generation != generation);
    }

    fn deletion_plugin(
        self: &Arc<Hub>,
        agent: &str,
    ) -> Result<(Arc<Mutex<PluginOut>>, u64), ErrorBody> {
        self.plugin(agent).map_err(|_| {
            failure(
                ErrorCode::AgentUnavailable,
                format!("Connect {agent}'s app channel, then retry Delete."),
            )
        })?;
        let plugins = self.plugins.lock().expect("not poisoned");
        let p = plugins.get(agent).ok_or_else(|| {
            failure(
                ErrorCode::AgentUnavailable,
                "The app channel disconnected. Retry Delete.",
            )
        })?;
        if !p.capabilities.contains(&Capability::ConversationDelete) {
            return Err(failure(
                ErrorCode::Unsupported,
                format!(
                    "Update {agent}'s runtime and app channel to support conversation deletion."
                ),
            ));
        }
        Ok((Arc::clone(&p.out), p.generation))
    }

    pub(super) fn delete_conversation(
        self: &Arc<Hub>,
        store: &Store,
        person: &str,
        conversation: &ConversationId,
    ) -> Result<(), ErrorBody> {
        let id = conversation.as_str();
        // Owner and Home checks precede all plugin access, including retries.
        if is_home(id) {
            return Err(failure(ErrorCode::NotAllowed, "Home cannot be deleted."));
        }
        if store.owner(id).map_err(storage)?.as_deref() != Some(person)
            && store.deletion_owner(id).map_err(storage)?.as_deref() != Some(person)
        {
            return Err(failure(ErrorCode::NotAllowed, "No such conversation."));
        }
        // One device's first refusal cannot release a reservation another is using.
        let serial = self
            .deletion_locks
            .lock()
            .expect("not poisoned")
            .entry(id.to_owned())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone();
        let _serial = serial.lock().expect("not poisoned");
        let fresh = !store.deletion_started(id).map_err(storage)?;
        let targets = store
            .begin_deletion(id, person)
            .map_err(storage)?
            .ok_or_else(|| failure(ErrorCode::NotAllowed, "No such conversation."))?;
        // An unavailable or older channel changes no native chat; a first attempt
        // releases its reservation, so normal conversation use can continue.
        let mut ready = Vec::new();
        for agent in targets {
            match self.deletion_plugin(&agent) {
                Ok((out, generation)) => ready.push((agent, out, generation)),
                Err(error) => {
                    if fresh {
                        store.cancel_deletion(id, person).map_err(storage)?;
                    }
                    return Err(error);
                }
            }
        }
        // Stop group scheduling before contacting its members. Native deletion interrupts
        // running work itself; no member may start another group turn during this operation.
        self.group_stop(store, id);
        for (agent, out, generation) in ready {
            let request = MessageId::new(new_id().map_err(|_| {
                failure(
                    ErrorCode::Internal,
                    "Could not create the deletion request.",
                )
            })?)
            .map_err(|_| {
                failure(
                    ErrorCode::Internal,
                    "Could not create the deletion request.",
                )
            })?;
            let (answer, receiver) = channel();
            {
                let mut pending = self.deletions.lock().expect("not poisoned");
                if pending.len() >= MAX_PENDING {
                    return Err(failure(
                        ErrorCode::AgentUnavailable,
                        "Too many deletions pending. Retry shortly.",
                    ));
                }
                pending.insert(
                    request.to_string(),
                    PendingDelete {
                        agent: agent.clone(),
                        generation,
                        answer,
                    },
                );
            }
            let sent = out.lock().expect("not poisoned").writer.send_as(
                &request,
                FromBridge::Delete {
                    conversation: conversation.clone(),
                },
            );
            let result = if sent.is_ok() {
                receiver.recv_timeout(WAIT).ok()
            } else {
                None
            };
            self.deletions
                .lock()
                .expect("not poisoned")
                .remove(request.as_str());
            result.ok_or_else(|| failure(ErrorCode::Unconfirmed, "The runtime has not confirmed deletion. Retry Delete to finish removing this conversation."))??;
            store.deletion_target_done(id, &agent).map_err(storage)?;
        }
        // Keep file ids until removal succeeds, including a crash between unlinks and commit.
        for file in store.deletion_files(id).map_err(storage)? {
            // These are bridge-generated ids, nevertheless refuse a path outside app-media.
            if Path::new(&file).components().count() != 1 || file == "." || file == ".." {
                return Err(failure(
                    ErrorCode::Internal,
                    "An attachment could not be removed.",
                ));
            }
            match std::fs::remove_file(self.media().join(file)) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => {
                    return Err(failure(
                        ErrorCode::Internal,
                        "An attachment could not be removed. Retry Delete.",
                    ));
                }
            }
        }
        store.finish_deletion(id, person).map_err(storage)?;
        self.groups.lock().expect("not poisoned").remove(id);
        self.deliver(
            person,
            ToDevice::ConversationDeleted {
                conversation: conversation.clone(),
            },
        );
        Ok(())
    }
}
