//! Owner-authorized, bounded, live requests to the runtime that owns a routine.
use super::*;
use std::collections::VecDeque;
use std::time::Instant;

use enclos_protocol::plugin::{ErrorBody, ErrorCode};
use enclos_protocol::routine::{
    PAGE_SIZE, RoutineChoice, RoutineReply, RoutineRequest, RoutineResult,
};
use sha2::{Digest, Sha256};

const MAX_PENDING: usize = 64;
const MAX_COMPLETED: usize = 64;
const MAX_REPLY_BYTES: usize = 60 * 1024;
const TIMEOUT: Duration = Duration::from_secs(25);

struct Pending {
    device: String,
    person: String,
    agent: String,
    connection: String,
    original: MessageId,
    request: RoutineRequest,
    started: Instant,
}

#[cfg(test)]
mod tests {
    use super::*;
    use enclos_protocol::routine::RoutineOptions;
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixListener;

    const OWNER: &str = "owner@example.com";
    const AGENT: &str = "lab/coder";

    fn fixture() -> (
        tempfile::TempDir,
        Arc<Hub>,
        Store,
        Device,
        Receiver<ToDevice>,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let hub = Arc::new(Hub {
            transport: Transport::Tailscale,
            store_path: dir.path().join("app.db"),
            layout: crate::layout::Layout::at(dir.path().join("enclos")),
            bridge_private: vec![],
            agents: vec![AgentEndpoint {
                name: AGENT.into(),
                runtime: "hermes".into(),
                socket: dir.path().join("plugin.sock"),
                token: "secret".into(),
            }],
            host: Some(OWNER.into()),
            plugins: Mutex::new(HashMap::new()),
            routines: Mutex::new(Default::default()),
            questions: Mutex::new(Default::default()),
            commands: Mutex::new(HashMap::new()),
            groups: Mutex::new(HashMap::new()),
            stops: Mutex::new(Default::default()),
            devices: Mutex::new(HashMap::new()),
        });
        let store = hub.store().unwrap();
        let device = Device {
            id: "phone".into(),
            name: "phone".into(),
            person: OWNER.into(),
            noise_key: vec![],
            device_key: vec![],
            push_key: vec![],
            push_token: None,
            paired: now(),
            seen: None,
        };
        store.add_device(&device).unwrap();
        store.ensure_home(AGENT, OWNER).unwrap();
        store.conversation("owned", "lab", "coder", OWNER).unwrap();
        store
            .conversation("foreign", "lab", "coder", "guest@example.com")
            .unwrap();
        store
            .conversation("other-agent", "lab", "helper", OWNER)
            .unwrap();
        store
            .group("group", "lab", &["coder".into(), "helper".into()], OWNER)
            .unwrap();
        let (tx, rx) = channel();
        hub.devices
            .lock()
            .unwrap()
            .insert(device.id.clone(), (OWNER.into(), tx));
        (dir, hub, store, device, rx)
    }

    fn list_result() -> RoutineResult {
        RoutineResult::List {
            routines: vec![],
            next_cursor: None,
            options: RoutineOptions {
                timezone: "UTC".into(),
                features: vec!["run".into()],
                skills: vec![],
                models: vec![],
                toolsets: vec![],
            },
            deliveries: vec![RoutineChoice {
                id: "foreign".into(),
                label: "untrusted".into(),
            }],
            deliveries_limited: false,
        }
    }

    fn claim(hub: &Hub, device: &Device, connection: &str, request: RoutineRequest) -> MessageId {
        let original = MessageId::new("app-request").unwrap();
        let rpc = rpc_id(&device.id, OWNER, AGENT, &original);
        hub.routines.lock().unwrap().pending.insert(
            rpc.to_string(),
            Pending {
                device: device.id.clone(),
                person: OWNER.into(),
                agent: AGENT.into(),
                connection: connection.into(),
                original,
                request,
                started: Instant::now(),
            },
        );
        rpc
    }

    #[test]
    fn routine_authority_and_delivery_catalog_exclude_other_people_agents_and_groups() {
        let (_dir, hub, store, device, _rx) = fixture();
        assert!(hub.routine_authority(&store, &device, OWNER, AGENT).is_ok());
        assert!(
            hub.routine_authority(&store, &device, "guest@example.com", AGENT)
                .is_err()
        );
        assert!(
            hub.routine_authority(&store, &device, OWNER, "missing/agent")
                .is_err()
        );
        let choices = hub.routine_deliveries(&store, OWNER, AGENT).unwrap();
        assert_eq!(choices.len(), 2);
        assert!(choices.iter().any(|d| d.id == "owned"));
        assert!(choices.iter().any(|d| d.id == home_id(AGENT)));
        let request = serde_json::from_value(serde_json::json!({"action":"create","definition":{"prompt":"hello","schedule":{"kind":"interval","minutes":5},"delivery":"foreign"}})).unwrap();
        let error = hub
            .routine_request(
                &store,
                &device,
                OWNER,
                AGENT,
                MessageId::new("bad-target").unwrap(),
                request,
            )
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::NotAllowed);
        store.remove_device(&device.id).unwrap();
        assert!(
            hub.routine_authority(&store, &device, OWNER, AGENT)
                .is_err()
        );
    }

    #[test]
    fn routine_replies_are_endpoint_bound_correlated_and_replayed_to_only_the_requesting_device() {
        let (_dir, hub, store, device, rx) = fixture();
        let (other_tx, other_rx) = channel();
        hub.devices
            .lock()
            .unwrap()
            .insert("another-phone".into(), (OWNER.into(), other_tx));
        let request = RoutineRequest::List { cursor: None };
        let rpc = claim(&hub, &device, "connection", request.clone());
        let reply = RoutineReply {
            of: rpc.clone(),
            result: list_result(),
        };
        hub.routine_response(&store, "lab/other", "connection", reply.clone());
        hub.routine_response(&store, AGENT, "old-connection", reply.clone());
        assert!(rx.try_recv().is_err());
        hub.routine_response(&store, AGENT, "connection", reply);
        let response = rx.recv().unwrap();
        let ToDevice::RoutineResponse { agent, reply } = &response else {
            panic!("routine response");
        };
        assert_eq!(agent, AGENT);
        assert_eq!(reply.of.as_str(), "app-request");
        let RoutineResult::List { deliveries, .. } = &reply.result else {
            panic!("list");
        };
        assert_eq!(deliveries.len(), 2);
        assert!(!deliveries.iter().any(|d| d.id == "foreign"));
        assert!(other_rx.try_recv().is_err());
        // A replay is answered from the receipt without opening the nonexistent socket.
        hub.routine_request(
            &store,
            &device,
            OWNER,
            AGENT,
            MessageId::new("app-request").unwrap(),
            request,
        )
        .unwrap();
        assert_eq!(rx.recv().unwrap(), response);
        let error = hub
            .routine_request(
                &store,
                &device,
                OWNER,
                AGENT,
                MessageId::new("app-request").unwrap(),
                RoutineRequest::Get {
                    routine: "different".into(),
                },
            )
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::Conflict);
    }

    #[test]
    fn timeout_and_disconnect_finish_once_and_late_or_revoked_responses_are_dropped() {
        let (_dir, hub, store, device, rx) = fixture();
        let rpc = claim(
            &hub,
            &device,
            "connection",
            RoutineRequest::List { cursor: None },
        );
        hub.routines
            .lock()
            .unwrap()
            .pending
            .get_mut(rpc.as_str())
            .unwrap()
            .started = Instant::now() - TIMEOUT;
        hub.expire_routines(&store);
        assert!(
            matches!(rx.recv().unwrap(), ToDevice::Error(ErrorBody { of: Some(id), code: ErrorCode::AgentUnavailable, .. }) if id.as_str() == "app-request")
        );
        hub.routine_response(
            &store,
            AGENT,
            "connection",
            RoutineReply {
                of: rpc,
                result: list_result(),
            },
        );
        assert!(rx.try_recv().is_err());
        claim(
            &hub,
            &device,
            "connection",
            RoutineRequest::List { cursor: None },
        );
        hub.routine_disconnected(&store, AGENT, "connection");
        assert!(matches!(rx.recv().unwrap(), ToDevice::Error(_)));
        let rpc = claim(
            &hub,
            &device,
            "new-connection",
            RoutineRequest::List { cursor: None },
        );
        store.remove_device(&device.id).unwrap();
        hub.routine_response(
            &store,
            AGENT,
            "new-connection",
            RoutineReply {
                of: rpc,
                result: list_result(),
            },
        );
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn live_routine_rpc_preserves_stable_id_and_uses_only_bridge_authorized_targets() {
        let (_dir, hub, store, device, rx) = fixture();
        let listener = UnixListener::bind(&hub.agents[0].socket).unwrap();
        let (capture_tx, capture_rx) = channel();
        let plugin = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut writer = stream.try_clone().unwrap();
            let mut reader = BufReader::new(stream);
            let mut line = Vec::new();
            reader.read_until(b'\n', &mut line).unwrap();
            let hello = enclos_protocol::plugin::decode_from_bridge(&line).unwrap();
            assert!(matches!(hello.body, FromBridge::Hello { token, .. } if token == "secret"));
            writer
                .write_all(&encode_line(&Envelope::new(
                    MessageId::new("hello").unwrap(),
                    FromPlugin::Hello {
                        runtime: "hermes".into(),
                        agent: "coder".into(),
                        capabilities: vec![Capability::Routines],
                    },
                )))
                .unwrap();
            line.clear();
            reader.read_until(b'\n', &mut line).unwrap();
            let frame = enclos_protocol::plugin::decode_from_bridge(&line).unwrap();
            capture_tx.send(frame.clone()).unwrap();
            writer
                .write_all(&encode_line(&Envelope::new(
                    MessageId::new("reply").unwrap(),
                    FromPlugin::RoutineResponse(RoutineReply {
                        of: frame.id,
                        result: list_result(),
                    }),
                )))
                .unwrap();
        });
        let original = MessageId::new("live-request").unwrap();
        hub.routine_request(
            &store,
            &device,
            OWNER,
            AGENT,
            original.clone(),
            RoutineRequest::List { cursor: None },
        )
        .unwrap();
        let frame = capture_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(frame.id, rpc_id(&device.id, OWNER, AGENT, &original));
        let FromBridge::RoutineRequest {
            allowed_deliveries,
            request,
        } = frame.body
        else {
            panic!("control request");
        };
        assert_eq!(*request, RoutineRequest::List { cursor: None });
        assert_eq!(allowed_deliveries.len(), 2);
        let response = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(
            matches!(response, ToDevice::RoutineResponse { reply: RoutineReply { of, .. }, .. } if of == original)
        );
        plugin.join().unwrap();
        assert_ne!(
            rpc_id("another-device", OWNER, AGENT, &original),
            rpc_id(&device.id, OWNER, AGENT, &original)
        );
    }

    #[test]
    fn routine_delivery_catalog_reports_its_limit_and_keeps_home() {
        let (_dir, hub, store, device, rx) = fixture();
        for i in 0..60 {
            store
                .conversation(&format!("conversation-{i:02}"), "lab", "coder", OWNER)
                .unwrap();
        }
        let rpc = claim(
            &hub,
            &device,
            "connection",
            RoutineRequest::List { cursor: None },
        );
        hub.routine_response(
            &store,
            AGENT,
            "connection",
            RoutineReply {
                of: rpc,
                result: list_result(),
            },
        );
        let ToDevice::RoutineResponse { reply, .. } = rx.recv().unwrap() else {
            panic!("routine reply");
        };
        let RoutineResult::List {
            deliveries,
            deliveries_limited,
            ..
        } = reply.result
        else {
            panic!("routine list");
        };
        assert!(deliveries_limited);
        assert_eq!(deliveries.len(), 51);
        assert_eq!(deliveries[0].id, home_id(AGENT));
    }

    #[test]
    fn wrong_response_kind_and_oversized_native_payload_become_correlated_errors() {
        for result in [
            RoutineResult::Run {
                routine: "unexpected".into(),
            },
            {
                let mut result = list_result();
                if let RoutineResult::List { options, .. } = &mut result {
                    options.timezone = "a".repeat(MAX_REPLY_BYTES);
                }
                result
            },
        ] {
            let (_dir, hub, store, device, rx) = fixture();
            let rpc = claim(
                &hub,
                &device,
                "connection",
                RoutineRequest::List { cursor: None },
            );
            hub.routine_response(
                &store,
                AGENT,
                "connection",
                RoutineReply { of: rpc, result },
            );
            assert!(
                matches!(rx.recv().unwrap(), ToDevice::Error(ErrorBody { of: Some(id), code: ErrorCode::BadMessage, .. }) if id.as_str() == "app-request")
            );
        }
    }
}

#[derive(Default)]
pub(super) struct RoutineRequests {
    connections: HashMap<String, String>,
    pending: HashMap<String, Pending>,
    completed: VecDeque<(String, RoutineRequest, ToDevice)>,
}

fn failure(of: MessageId, code: ErrorCode, message: impl Into<String>) -> ErrorBody {
    ErrorBody {
        of: Some(of),
        code,
        message: message.into(),
    }
}

fn rpc_id(device: &str, person: &str, agent: &str, request: &MessageId) -> MessageId {
    let bytes =
        serde_json::to_vec(&(device, person, agent, request.as_str())).expect("strings serialize");
    let digest = Sha256::digest(bytes);
    let suffix: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    MessageId::new(format!("routine-{suffix}")).expect("bounded digest")
}

impl Hub {
    fn routine_authority(
        &self,
        store: &Store,
        device: &Device,
        person: &str,
        agent: &str,
    ) -> Result<(), String> {
        if self.host.as_deref() != Some(person) {
            return Err("Only the host's person can manage routines.".into());
        }
        self.avatar_authority(store, device, person, agent, false)
    }

    fn routine_deliveries(
        &self,
        store: &Store,
        person: &str,
        agent: &str,
    ) -> Result<Vec<RoutineChoice>, String> {
        let mut choices = Vec::new();
        for conversation in store.conversations(person).map_err(|e| e.to_string())? {
            if format!("{}/{}", conversation.sandbox, conversation.agent) != agent
                || !store
                    .members(&conversation.id)
                    .map_err(|e| e.to_string())?
                    .is_empty()
            {
                continue;
            }
            choices.push(RoutineChoice {
                id: conversation.id.clone(),
                label: if is_home(&conversation.id) {
                    "Home".into()
                } else {
                    conversation
                        .title
                        .unwrap_or_else(|| "Conversation".into())
                        .chars()
                        .take(32)
                        .collect()
                },
            });
        }
        choices.reverse();
        if choices.len() > 4096 {
            return Err("Too many delivery conversations. Use a different agent.".into());
        }
        Ok(choices)
    }

    pub(super) fn routine_request(
        self: &Arc<Self>,
        store: &Store,
        device: &Device,
        person: &str,
        agent: &str,
        original: MessageId,
        request: RoutineRequest,
    ) -> Result<(), ErrorBody> {
        self.routine_authority(store, device, person, agent)
            .map_err(|e| failure(original.clone(), ErrorCode::NotAllowed, e))?;
        request
            .validate()
            .map_err(|e| failure(original.clone(), ErrorCode::BadMessage, e))?;
        let deliveries = self
            .routine_deliveries(store, person, agent)
            .map_err(|e| failure(original.clone(), ErrorCode::BadMessage, e))?;
        if let Some(target) = request.definition().and_then(|d| d.delivery.as_ref())
            && !deliveries.iter().any(|d| d.id == target.as_str())
        {
            return Err(failure(
                original,
                ErrorCode::NotAllowed,
                "A routine must deliver to one of your direct conversations with this agent.",
            ));
        }
        let rpc = rpc_id(&device.id, person, agent, &original);
        {
            let requests = self.routines.lock().expect("not poisoned");
            if let Some((_, previous, response)) = requests
                .completed
                .iter()
                .find(|(id, _, _)| id == rpc.as_str())
            {
                if previous != &request {
                    return Err(failure(
                        original,
                        ErrorCode::Conflict,
                        "A request id cannot be reused for another routine action.",
                    ));
                }
                self.deliver_routine_device(store, &device.id, person, response.clone());
                return Ok(());
            }
            if let Some(previous) = requests.pending.get(rpc.as_str()) {
                if previous.request != request {
                    return Err(failure(
                        original,
                        ErrorCode::Conflict,
                        "A request id cannot be reused for another routine action.",
                    ));
                }
                return Ok(());
            }
        }
        self.plugin(agent)
            .map_err(|e| failure(original.clone(), ErrorCode::AgentUnavailable, e))?;
        let mut plugins = self.plugins.lock().expect("not poisoned");
        let Some((writer, capabilities)) = plugins.get_mut(agent) else {
            return Err(failure(
                original,
                ErrorCode::AgentUnavailable,
                "The agent's channel is disconnected.",
            ));
        };
        if !capabilities.contains(&Capability::Routines) {
            return Err(failure(
                original,
                ErrorCode::Unsupported,
                "This agent's runtime does not support routines.",
            ));
        }
        let mut requests = self.routines.lock().expect("not poisoned");
        // Another device thread may have claimed the same id while the connection opened.
        if let Some((_, previous, response)) = requests
            .completed
            .iter()
            .find(|(id, _, _)| id == rpc.as_str())
        {
            if previous != &request {
                return Err(failure(
                    original,
                    ErrorCode::Conflict,
                    "A request id cannot be reused for another routine action.",
                ));
            }
            let response = response.clone();
            drop(requests);
            drop(plugins);
            self.deliver_routine_device(store, &device.id, person, response);
            return Ok(());
        }
        if let Some(previous) = requests.pending.get(rpc.as_str()) {
            return if previous.request == request {
                Ok(())
            } else {
                Err(failure(
                    original,
                    ErrorCode::Conflict,
                    "A request id cannot be reused for another routine action.",
                ))
            };
        }
        if requests.pending.len() >= MAX_PENDING {
            return Err(failure(
                original,
                ErrorCode::AgentUnavailable,
                "Too many routine requests are in progress. Try again shortly.",
            ));
        }
        let connection = requests.connections.get(agent).cloned().ok_or_else(|| {
            failure(
                original.clone(),
                ErrorCode::AgentUnavailable,
                "The agent's channel is disconnected.",
            )
        })?;
        requests.pending.insert(
            rpc.to_string(),
            Pending {
                device: device.id.clone(),
                person: person.into(),
                agent: agent.into(),
                connection,
                original: original.clone(),
                request: request.clone(),
                started: Instant::now(),
            },
        );
        drop(requests);
        let allowed_deliveries = deliveries
            .into_iter()
            .map(|d| ConversationId::new(d.id).expect("stored conversation id"))
            .collect();
        if let Err(e) = writer.send_with_id(
            rpc.clone(),
            FromBridge::RoutineRequest {
                allowed_deliveries,
                request: Box::new(request),
            },
        ) {
            self.routines
                .lock()
                .expect("not poisoned")
                .pending
                .remove(rpc.as_str());
            return Err(failure(
                original,
                ErrorCode::AgentUnavailable,
                format!("{e}. The outcome may be unknown; refresh routines before retrying."),
            ));
        }
        Ok(())
    }

    pub(super) fn routine_connected(&self, agent: &str) -> String {
        let connection = new_id().expect("system randomness available");
        self.routines
            .lock()
            .expect("not poisoned")
            .connections
            .insert(agent.into(), connection.clone());
        connection
    }

    fn deliver_routine_device(
        &self,
        store: &Store,
        device: &str,
        person: &str,
        response: ToDevice,
    ) {
        let paired = store
            .devices()
            .unwrap_or_default()
            .iter()
            .any(|d| d.id == device && d.person == person);
        if paired
            && let Some((owner, sender)) = self.devices.lock().expect("not poisoned").get(device)
            && owner == person
        {
            let _ = sender.send(response);
        }
    }

    pub(super) fn routine_response(
        &self,
        store: &Store,
        agent: &str,
        connection: &str,
        mut reply: RoutineReply,
    ) {
        let mut requests = self.routines.lock().expect("not poisoned");
        let Some(pending) = requests.pending.get(reply.of.as_str()) else {
            return;
        };
        if pending.agent != agent || pending.connection != connection {
            return;
        }
        let pending = requests
            .pending
            .remove(reply.of.as_str())
            .expect("looked up");
        let key = reply.of.to_string();
        reply.of = pending.original.clone();
        let canonical = self.routine_deliveries(store, &pending.person, agent);
        let valid = pending.request.accepts(&reply.result)
            && match &mut reply.result {
                RoutineResult::List {
                    routines,
                    deliveries,
                    deliveries_limited,
                    ..
                } => {
                    *deliveries = canonical.clone().unwrap_or_default();
                    deliveries.sort_by_key(|d| !is_home(&d.id));
                    *deliveries_limited = deliveries.len() > 51;
                    deliveries.truncate(51);
                    routines.len() <= PAGE_SIZE
                }
                RoutineResult::Routine { routine } => {
                    (!routine.summary.editable || routine.definition.validate().is_ok())
                        && routine.definition.delivery.as_ref().is_none_or(|id| {
                            canonical
                                .as_ref()
                                .is_ok_and(|ds| ds.iter().any(|d| d.id == id.as_str()))
                        })
                }
                _ => true,
            };
        let response = ToDevice::RoutineResponse {
            agent: agent.into(),
            reply,
        };
        let response =
            if valid && serde_json::to_vec(&response).is_ok_and(|b| b.len() <= MAX_REPLY_BYTES) {
                response
            } else {
                ToDevice::Error(failure(
                    pending.original,
                    ErrorCode::BadMessage,
                    "The runtime returned an invalid or oversized routine response.",
                ))
            };
        requests
            .completed
            .push_back((key, pending.request, response.clone()));
        while requests.completed.len() > MAX_COMPLETED {
            requests.completed.pop_front();
        }
        drop(requests);
        self.deliver_routine_device(store, &pending.device, &pending.person, response);
    }

    pub(super) fn routine_error(
        &self,
        store: &Store,
        agent: &str,
        connection: &str,
        mut error: ErrorBody,
    ) {
        let Some(id) = error.of.as_ref() else {
            return;
        };
        let mut requests = self.routines.lock().expect("not poisoned");
        let Some(pending) = requests.pending.get(id.as_str()) else {
            return;
        };
        if pending.agent != agent || pending.connection != connection {
            return;
        }
        let pending = requests.pending.remove(id.as_str()).expect("looked up");
        error.of = Some(pending.original);
        error.message = error.message.chars().take(1000).collect();
        let response = ToDevice::Error(error);
        drop(requests);
        self.deliver_routine_device(store, &pending.device, &pending.person, response);
    }

    pub(super) fn routine_disconnected(&self, store: &Store, agent: &str, connection: &str) {
        let mut requests = self.routines.lock().expect("not poisoned");
        if requests
            .connections
            .get(agent)
            .is_some_and(|s| s == connection)
        {
            requests.connections.remove(agent);
        }
        let keys: Vec<_> = requests
            .pending
            .iter()
            .filter(|(_, p)| p.agent == agent && p.connection == connection)
            .map(|(k, _)| k.clone())
            .collect();
        let pending: Vec<_> = keys
            .into_iter()
            .filter_map(|k| requests.pending.remove(&k))
            .collect();
        drop(requests);
        for p in pending {
            self.deliver_routine_device(store, &p.device, &p.person, ToDevice::Error(failure(p.original, ErrorCode::AgentUnavailable, "The agent disconnected. The outcome may be unknown; refresh routines before retrying.")));
        }
    }

    pub(super) fn expire_routines(&self, store: &Store) {
        let mut requests = self.routines.lock().expect("not poisoned");
        let keys: Vec<_> = requests
            .pending
            .iter()
            .filter(|(_, p)| p.started.elapsed() >= TIMEOUT)
            .map(|(k, _)| k.clone())
            .collect();
        let pending: Vec<_> = keys
            .into_iter()
            .filter_map(|k| requests.pending.remove(&k))
            .collect();
        drop(requests);
        for p in pending {
            self.deliver_routine_device(store, &p.device, &p.person, ToDevice::Error(failure(p.original, ErrorCode::AgentUnavailable, "The routine request timed out. The outcome may be unknown; refresh routines before retrying.")));
        }
    }
}
