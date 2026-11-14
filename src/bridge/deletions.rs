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
    /// Native round-trips must never hold the device's receive/ping/outbox loop.
    pub(super) fn request_deletion(
        self: &Arc<Hub>,
        device: &Device,
        request: MessageId,
        conversation: ConversationId,
    ) {
        let route = self
            .devices
            .lock()
            .expect("not poisoned")
            .get(&device.id)
            .cloned();
        let Some((person, sender, generation)) = route.filter(|r| r.0 == device.person) else {
            return;
        };
        let key = (device.id.clone(), request.to_string());
        {
            let mut jobs = self.deletion_jobs.lock().expect("not poisoned");
            if jobs.contains(&key) {
                return;
            }
            if jobs.len() >= MAX_PENDING {
                let mut error = failure(
                    ErrorCode::AgentUnavailable,
                    "Too many deletions pending. Retry shortly.",
                );
                error.of = Some(request);
                let _ = sender.send(ToDevice::Error(error));
                return;
            }
            jobs.insert(key.clone());
        }
        let hub = Arc::clone(self);
        let device = device.clone();
        let original = request.clone();
        let job_key = key.clone();
        let started = std::thread::Builder::new()
            .name("conversation-delete".into())
            .spawn(move || {
                let result =
                    hub.store()
                        .map_err(|_| {
                            failure(
                                ErrorCode::Internal,
                                "The deletion store is unavailable. Retry Delete.",
                            )
                        })
                        .and_then(|store| {
                            if !store.device(&device.id).ok().flatten().is_some_and(|d| {
                                d.person == person && d.noise_key == device.noise_key
                            }) {
                                return Err(failure(
                                    ErrorCode::NotAllowed,
                                    "This device is no longer paired.",
                                ));
                            }
                            let result =
                                hub.delete_conversation(&store, &person, &conversation, &device.id);
                            // A revoked device gets no result, and a replacement connection
                            // recovers canonical state through sync instead of stale receipts.
                            if store.device(&device.id).ok().flatten().is_some_and(|d| {
                                d.person == person && d.noise_key == device.noise_key
                            }) {
                                let response = match result {
                                    Ok(()) => ToDevice::Ack {
                                        of: request.clone(),
                                    },
                                    Err(mut error) => {
                                        error.of = Some(request.clone());
                                        ToDevice::Error(error)
                                    }
                                };
                                let routes = hub.devices.lock().expect("not poisoned");
                                if let Some((owner, out, current)) = routes.get(&device.id)
                                    && owner == &person
                                    && *current == generation
                                {
                                    let _ = out.send(response);
                                }
                            }
                            Ok(())
                        });
                if let Err(mut error) = result {
                    error.of = Some(request);
                    let _ = sender.send(ToDevice::Error(error));
                }
                hub.deletion_jobs
                    .lock()
                    .expect("not poisoned")
                    .remove(&job_key);
            });
        if started.is_err() {
            self.deletion_jobs
                .lock()
                .expect("not poisoned")
                .remove(&key);
            // The original session's sender is obtained again only if its generation survived.
            let routes = self.devices.lock().expect("not poisoned");
            if let Some((_, out, current)) = routes.get(&key.0)
                && *current == generation
            {
                let mut error = failure(
                    ErrorCode::Internal,
                    "Could not start deletion. Retry Delete.",
                );
                error.of = Some(original);
                let _ = out.send(ToDevice::Error(error));
            }
        }
    }

    /// Whether `agent` (`<sandbox>/<agent>`) is gone with all its data, its
    /// sandbox included, so no native chat is left to delete. When the
    /// engine cannot tell, it is not: said on stderr, and the deletion then
    /// needs the agent's channel.
    fn deletion_target_absent(&self, target: &str) -> bool {
        let Some((sandbox, agent)) = target.split_once('/') else {
            return false;
        };
        let (Ok(sandbox), Ok(agent)) = (sandbox.parse(), agent.parse()) else {
            return false;
        };
        crate::engine::Engine::open(self.layout.clone(), crate::state::Wait::Background)
            .app_agent_data_absent(&sandbox, &agent)
            .unwrap_or_else(|e| {
                eprintln!("enclos app: cannot tell whether {target} has data left: {e}");
                false
            })
    }

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
        device: &str,
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
        let serial = {
            let mut locks = self.deletion_locks.lock().expect("not poisoned");
            locks.retain(|_, weak| weak.strong_count() > 0);
            let serial = locks
                .get(id)
                .and_then(std::sync::Weak::upgrade)
                .unwrap_or_else(|| Arc::new(Mutex::new(())));
            locks.insert(id.to_owned(), Arc::downgrade(&serial));
            serial
        };
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
            if self.deletion_target_absent(&agent) {
                store.deletion_target_done(id, &agent).map_err(storage)?;
                continue;
            }
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
        store.finish_deletion(id, person, device).map_err(storage)?;
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
