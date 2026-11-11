//! Owner-authorized, bounded, live requests to the runtime that owns a routine.
use super::avatars::PhotoError;
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
/// The most conversations a routine may choose from for one agent.
const MAX_DELIVERIES: usize = 4096;
/// The most delivery choices sent with a list, Home first.
const LISTED_DELIVERIES: usize = 51;

/// The bridge's database failed before the request reached the runtime.
const NOT_READ_BEFORE: &str =
    "The bridge could not read its database, so nothing was sent to the agent. Try again.";
/// The bridge's database failed once the runtime had answered.
const NOT_READ_AFTER: &str = "The bridge could not read its database to check the agent's answer. The outcome may be unknown; refresh routines before retrying.";

struct Pending {
    device: String,
    person: String,
    agent: String,
    connection: String,
    original: MessageId,
    request: RoutineRequest,
    started: Instant,
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

/// The log event of a request that changes a routine, and the routine it
/// names (`new` for a creation); none for a read.
fn audited(request: &RoutineRequest) -> Option<(&'static str, &str)> {
    match request {
        RoutineRequest::List { .. } | RoutineRequest::Get { .. } => None,
        RoutineRequest::Create { .. } => Some(("routine.create", "new")),
        RoutineRequest::Update { routine, .. } => Some(("routine.update", routine)),
        RoutineRequest::Delete { routine, .. } => Some(("routine.delete", routine)),
        RoutineRequest::Run { routine, .. } => Some(("routine.run", routine)),
        RoutineRequest::SetEnabled {
            routine, enabled, ..
        } => Some((
            if *enabled {
                "routine.resume"
            } else {
                "routine.pause"
            },
            routine,
        )),
    }
}

/// Records in the bridge's log who asked what of which agent's routine,
/// and how it ended: a routine runs unattended long after the request, so
/// the log is what says which device made it. A read is not recorded.
fn audit(store: &Store, pending: &Pending, outcome: &str) {
    if let Some((event, routine)) = audited(&pending.request) {
        let reason = format!("{} {routine} {outcome}", pending.agent);
        if let Err(e) = store.log(
            Some(&pending.device),
            Some(&pending.person),
            event,
            Some(&reason),
        ) {
            eprintln!("enclos app: cannot log {event} for {}: {e}", pending.agent);
        }
    }
}

/// Whether `result` answers `request` within what the bridge lets
/// through: ids that show as themselves (a list leaves the others out), a
/// page of at most `PAGE_SIZE`, an editable routine in the app's format,
/// and a delivery among `deliveries`, the bridge's own choices, which also
/// replace whatever a list carried.
fn checked(
    request: &RoutineRequest,
    result: &mut RoutineResult,
    mut deliveries: Vec<RoutineChoice>,
) -> bool {
    request.accepts(result)
        && result.retain_valid_ids()
        && match result {
            RoutineResult::List {
                routines,
                deliveries: listed,
                deliveries_limited,
                ..
            } => {
                deliveries.sort_by_key(|d| !is_home(&d.id));
                *deliveries_limited = deliveries.len() > LISTED_DELIVERIES;
                deliveries.truncate(LISTED_DELIVERIES);
                *listed = deliveries;
                routines.len() <= PAGE_SIZE
            }
            RoutineResult::Routine { routine } => {
                (!routine.summary.editable || routine.definition.validate().is_ok())
                    && routine
                        .definition
                        .delivery
                        .as_ref()
                        .is_none_or(|id| deliveries.iter().any(|d| d.id == id.as_str()))
            }
            _ => true,
        }
}

/// What the bridge already knows of a request id.
enum Replay {
    /// Answered before: the same answer again.
    Completed(Box<ToDevice>),
    /// Still waiting for the runtime: its answer goes to the same device.
    Pending,
    /// Not seen.
    Fresh,
}

/// A request id seen before must name the same request: never another
/// action under an id already used.
fn replay(
    requests: &RoutineRequests,
    rpc: &MessageId,
    request: &RoutineRequest,
    original: &MessageId,
) -> Result<Replay, ErrorBody> {
    let reused = || {
        failure(
            original.clone(),
            ErrorCode::Conflict,
            "A request id cannot be reused for another routine action.",
        )
    };
    if let Some((_, previous, response)) = requests
        .completed
        .iter()
        .find(|(id, _, _)| id == rpc.as_str())
    {
        return if previous == request {
            Ok(Replay::Completed(Box::new(response.clone())))
        } else {
            Err(reused())
        };
    }
    match requests.pending.get(rpc.as_str()) {
        Some(previous) if previous.request == *request => Ok(Replay::Pending),
        Some(_) => Err(reused()),
        None => Ok(Replay::Fresh),
    }
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
            .map_err(|e| match e {
                PhotoError::NotAllowed(why)
                | PhotoError::UnknownAgent(why)
                | PhotoError::Invalid(why)
                | PhotoError::Conflict(why)
                | PhotoError::Internal(why) => why,
            })
    }

    /// Where a routine of `agent` may deliver for `person`: their direct
    /// conversations with it, newest first, read in one query.
    fn routine_deliveries(
        &self,
        store: &Store,
        person: &str,
        agent: &str,
    ) -> rusqlite::Result<Vec<RoutineChoice>> {
        let Some((sandbox, name)) = agent.split_once('/') else {
            return Ok(Vec::new());
        };
        let mut choices: Vec<_> = store
            .direct_conversations(person, sandbox, name)?
            .into_iter()
            .map(|conversation| RoutineChoice {
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
                id: conversation.id,
            })
            .collect();
        choices.reverse();
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
        let deliveries = self.routine_deliveries(store, person, agent).map_err(|e| {
            eprintln!("enclos app: cannot read the delivery conversations of {agent}: {e}");
            failure(original.clone(), ErrorCode::Unknown, NOT_READ_BEFORE)
        })?;
        if deliveries.len() > MAX_DELIVERIES {
            return Err(failure(
                original,
                ErrorCode::BadMessage,
                "Too many delivery conversations. Use a different agent.",
            ));
        }
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
        let requester = Person::new(person)
            .map_err(|e| failure(original.clone(), ErrorCode::BadMessage, e.to_string()))?;
        let answered = |hub: &Hub, response: ToDevice| {
            hub.deliver_routine_device(store, &device.id, person, response);
            Ok(())
        };
        {
            let requests = self.routines.lock().expect("not poisoned");
            match replay(&requests, &rpc, &request, &original)? {
                Replay::Completed(response) => {
                    drop(requests);
                    return answered(self, *response);
                }
                Replay::Pending => return Ok(()),
                Replay::Fresh => {}
            }
        }
        self.plugin(agent)
            .map_err(|e| failure(original.clone(), ErrorCode::AgentUnavailable, e))?;
        let mut plugins = self.plugins.lock().expect("not poisoned");
        let Some(Plugin {
            writer,
            capabilities,
            ..
        }) = plugins.get_mut(agent)
        else {
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
        match replay(&requests, &rpc, &request, &original)? {
            Replay::Completed(response) => {
                drop(requests);
                drop(plugins);
                return answered(self, *response);
            }
            Replay::Pending => return Ok(()),
            Replay::Fresh => {}
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
        let pending = Pending {
            device: device.id.clone(),
            person: person.into(),
            agent: agent.into(),
            connection,
            original: original.clone(),
            request: request.clone(),
            started: Instant::now(),
        };
        audit(store, &pending, "requested");
        requests.pending.insert(rpc.to_string(), pending);
        drop(requests);
        let allowed_deliveries = deliveries
            .into_iter()
            .map(|d| ConversationId::new(d.id).expect("stored conversation id"))
            .collect();
        if let Err(e) = writer.send_with_id(
            rpc.clone(),
            FromBridge::RoutineRequest {
                allowed_deliveries,
                person: requester,
                device: device.id.clone(),
                request: Box::new(request),
            },
        ) {
            let pending = self
                .routines
                .lock()
                .expect("not poisoned")
                .pending
                .remove(rpc.as_str());
            if let Some(pending) = pending {
                audit(store, &pending, "unknown: not sent");
            }
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
        let response = match store.devices() {
            Ok(devices) if devices.iter().any(|d| d.id == device && d.person == person) => response,
            Ok(_) => return,
            // The pairing cannot be read: the connected device, which the
            // bridge authenticated, is told only that the outcome is
            // unknown, never what the runtime answered.
            Err(e) => {
                eprintln!("enclos app: cannot read the paired devices to answer {device}: {e}");
                let of = match &response {
                    ToDevice::RoutineResponse { reply, .. } => Some(reply.of.clone()),
                    ToDevice::Error(error) => error.of.clone(),
                    _ => None,
                };
                ToDevice::Error(ErrorBody {
                    of,
                    code: ErrorCode::Unknown,
                    message: NOT_READ_AFTER.into(),
                })
            }
        };
        if let Some((owner, sender, _)) = self.devices.lock().expect("not poisoned").get(device)
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
        let is_ours = |p: &Pending| p.agent == agent && p.connection == connection;
        // The request stays pending while the delivery catalogue is read
        // without the lock, so a retry of it waits instead of reaching the
        // runtime a second time.
        let person = {
            let requests = self.routines.lock().expect("not poisoned");
            match requests.pending.get(reply.of.as_str()) {
                Some(p) if is_ours(p) => p.person.clone(),
                _ => return,
            }
        };
        let canonical = self.routine_deliveries(store, &person, agent);
        let mut requests = self.routines.lock().expect("not poisoned");
        // Timed out or disconnected meanwhile: already answered.
        if !requests.pending.get(reply.of.as_str()).is_some_and(is_ours) {
            return;
        }
        let pending = requests
            .pending
            .remove(reply.of.as_str())
            .expect("looked up");
        let key = reply.of.to_string();
        reply.of = pending.original.clone();
        let (response, outcome) = match canonical {
            Err(e) => {
                eprintln!(
                    "enclos app: cannot read the delivery conversations of {agent} to check its routine answer: {e}"
                );
                // Not kept for a retry: once the database reads again, the
                // runtime's own replay answers it.
                drop(requests);
                audit(store, &pending, "unknown: bridge database unreadable");
                let error = failure(pending.original, ErrorCode::Unknown, NOT_READ_AFTER);
                self.deliver_routine_device(
                    store,
                    &pending.device,
                    &pending.person,
                    ToDevice::Error(error),
                );
                return;
            }
            Ok(canonical) => {
                let valid = checked(&pending.request, &mut reply.result, canonical);
                let saved = match &reply.result {
                    RoutineResult::Routine { routine } => Some(routine.summary.id.clone()),
                    _ => None,
                };
                let response = ToDevice::RoutineResponse {
                    agent: agent.into(),
                    reply,
                };
                let valid = valid
                    && serde_json::to_vec(&response).is_ok_and(|b| b.len() <= MAX_REPLY_BYTES);
                match (valid, saved) {
                    (true, Some(id)) => (response, format!("confirmed as {id}")),
                    (true, None) => (response, "confirmed".to_owned()),
                    (false, _) => (
                        ToDevice::Error(failure(
                            pending.original.clone(),
                            ErrorCode::BadMessage,
                            "The runtime returned an invalid or oversized routine response.",
                        )),
                        "unknown: invalid response".to_owned(),
                    ),
                }
            }
        };
        requests
            .completed
            .push_back((key, pending.request.clone(), response.clone()));
        while requests.completed.len() > MAX_COMPLETED {
            requests.completed.pop_front();
        }
        drop(requests);
        audit(store, &pending, &outcome);
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
        let code = serde_json::to_value(error.code)
            .ok()
            .and_then(|v| v.as_str().map(str::to_owned))
            .unwrap_or_default();
        audit(store, &pending, &format!("answered {code}"));
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
            audit(store, &p, "unknown: disconnected");
            self.deliver_routine_device(store, &p.device, &p.person, ToDevice::Error(failure(p.original, ErrorCode::AgentUnavailable, "The agent disconnected. The outcome may be unknown; refresh routines before retrying.")));
        }
    }

    /// Every second, ends the requests the runtime left unanswered; a
    /// bridge database that cannot be opened is retried, never left to stop
    /// the timeouts for good.
    pub(super) fn expire_routines_forever(self: Arc<Self>) {
        loop {
            match self.store() {
                Ok(store) => loop {
                    std::thread::sleep(Duration::from_secs(1));
                    self.expire_routines(&store);
                },
                Err(e) => {
                    eprintln!("enclos app: routine timeouts wait for the database: {e}");
                    std::thread::sleep(Duration::from_secs(5));
                }
            }
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
            audit(store, &p, "unknown: timed out");
            self.deliver_routine_device(store, &p.device, &p.person, ToDevice::Error(failure(p.original, ErrorCode::AgentUnavailable, "The routine request timed out. The outcome may be unknown; refresh routines before retrying.")));
        }
    }
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
        let hub = Arc::new(Hub::new(
            Transport::Tailscale,
            Arc::new(|_: &str| Err("no transport in this test".to_owned())),
            dir.path().join("app.db"),
            crate::layout::Layout::at(dir.path().join("enclos")),
            vec![],
            vec![AgentEndpoint {
                name: AGENT.into(),
                runtime: "hermes".into(),
                socket: dir.path().join("plugin.sock"),
                token: "secret".into(),
            }],
            Some(OWNER.into()),
            SILENCE,
        ));
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
            node: None,
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
            .insert(device.id.clone(), (OWNER.into(), tx, 1));
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
            .insert("another-phone".into(), (OWNER.into(), other_tx, 2));
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
            person,
            device: from,
            request,
        } = frame.body
        else {
            panic!("control request");
        };
        assert_eq!(*request, RoutineRequest::List { cursor: None });
        assert_eq!(allowed_deliveries.len(), 2);
        assert_eq!(
            (person.as_str(), from.as_str()),
            (OWNER, device.id.as_str()),
            "the runtime is told who asked, from the bridge's authentication"
        );
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

    #[test]
    fn routine_changes_and_their_outcomes_are_logged_with_device_and_person_but_reads_are_not() {
        let (_dir, hub, store, device, _rx) = fixture();
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
        let create = serde_json::from_value(serde_json::json!({"action":"create","definition":{"prompt":"hello","schedule":{"kind":"interval","minutes":5}}})).unwrap();
        let rpc = claim(&hub, &device, "connection", create);
        let saved = serde_json::from_value(serde_json::json!({"result":"routine","routine":{"id":"native-1","revision":"r1","schedule":{"kind":"interval","minutes":5},"enabled":true,"prompt_preview":"hello","delivery_label":"Nowhere","editable":true,"definition":{"prompt":"hello","schedule":{"kind":"interval","minutes":5}}}})).unwrap();
        hub.routine_response(
            &store,
            AGENT,
            "connection",
            RoutineReply {
                of: rpc,
                result: saved,
            },
        );
        let rpc = claim(
            &hub,
            &device,
            "connection",
            RoutineRequest::Delete {
                routine: "native-1".into(),
                revision: "r1".into(),
            },
        );
        hub.routine_error(
            &store,
            AGENT,
            "connection",
            failure(rpc, ErrorCode::Conflict, "changed"),
        );
        let rpc = claim(
            &hub,
            &device,
            "connection",
            RoutineRequest::SetEnabled {
                routine: "native-1".into(),
                revision: "r1".into(),
                enabled: false,
            },
        );
        hub.routines
            .lock()
            .unwrap()
            .pending
            .get_mut(rpc.as_str())
            .unwrap()
            .started = Instant::now() - TIMEOUT;
        hub.expire_routines(&store);
        claim(
            &hub,
            &device,
            "connection",
            RoutineRequest::Run {
                routine: "native-1".into(),
                revision: "r1".into(),
            },
        );
        hub.routine_disconnected(&store, AGENT, "connection");
        let lines: Vec<_> = store
            .log_lines(100)
            .unwrap()
            .into_iter()
            .filter(|l| l.event.starts_with("routine."))
            .map(|l| {
                assert_eq!(l.device.as_deref(), Some(device.id.as_str()));
                assert_eq!(l.person.as_deref(), Some(OWNER));
                (l.event, l.reason.unwrap())
            })
            .collect();
        let expected = [
            ("routine.create", "lab/coder new confirmed as native-1"),
            ("routine.delete", "lab/coder native-1 answered conflict"),
            ("routine.pause", "lab/coder native-1 unknown: timed out"),
            ("routine.run", "lab/coder native-1 unknown: disconnected"),
        ];
        assert_eq!(
            lines,
            expected.map(|(e, r)| (e.to_owned(), r.to_owned())),
            "a list is not logged"
        );
    }

    fn saved_as(id: &str) -> RoutineResult {
        serde_json::from_value(serde_json::json!({"result":"routine","routine":{"id":id,"revision":"r1","schedule":{"kind":"interval","minutes":5},"enabled":true,"prompt_preview":"hello","delivery_label":"Nowhere","editable":true,"definition":{"prompt":"hello","schedule":{"kind":"interval","minutes":5}}}})).unwrap()
    }

    fn create() -> RoutineRequest {
        serde_json::from_value(serde_json::json!({"action":"create","definition":{"prompt":"hello","schedule":{"kind":"interval","minutes":5}}})).unwrap()
    }

    #[test]
    fn a_created_routine_whose_id_hides_characters_is_refused_and_never_logged() {
        let long = "a".repeat(200);
        for id in [
            "x\n2026-11-11 routine.delete phone owner@example.com",
            "x\u{1b}]52;c;cHduZWQ=\u{7}",
            "x\u{202E}",
            long.as_str(),
        ] {
            let (_dir, hub, store, device, rx) = fixture();
            let rpc = claim(&hub, &device, "connection", create());
            hub.routine_response(
                &store,
                AGENT,
                "connection",
                RoutineReply {
                    of: rpc,
                    result: saved_as(id),
                },
            );
            assert!(
                matches!(
                    rx.recv().unwrap(),
                    ToDevice::Error(ErrorBody {
                        code: ErrorCode::BadMessage,
                        ..
                    })
                ),
                "{id:?}"
            );
            let reasons: Vec<_> = store
                .log_lines(10)
                .unwrap()
                .into_iter()
                .filter(|l| l.event.starts_with("routine."))
                .filter_map(|l| l.reason)
                .collect();
            assert_eq!(reasons, ["lab/coder new unknown: invalid response"]);
        }
    }

    #[test]
    fn a_list_leaves_out_a_routine_whose_id_hides_characters() {
        let (_dir, hub, store, device, rx) = fixture();
        let mut result = list_result();
        if let RoutineResult::List { routines, .. } = &mut result {
            let RoutineResult::Routine { routine } = saved_as("good") else {
                unreachable!()
            };
            let mut bad = routine.summary.clone();
            bad.id = "bad\u{1b}[2J".into();
            routines.extend([routine.summary, bad]);
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
            RoutineReply { of: rpc, result },
        );
        let ToDevice::RoutineResponse { reply, .. } = rx.recv().unwrap() else {
            panic!("routine list");
        };
        let RoutineResult::List { routines, .. } = reply.result else {
            panic!("routine list");
        };
        assert_eq!(
            routines.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(),
            ["good"]
        );
    }

    #[test]
    fn a_device_cannot_name_a_routine_with_hidden_characters() {
        let (_dir, hub, store, device, _rx) = fixture();
        let error = hub
            .routine_request(
                &store,
                &device,
                OWNER,
                AGENT,
                MessageId::new("bad-id").unwrap(),
                RoutineRequest::Run {
                    routine: "x\n[forged]".into(),
                    revision: "r1".into(),
                },
            )
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::BadMessage);
        assert!(store.log_lines(10).unwrap().is_empty());
    }

    /// Breaks the bridge's database under `store` by dropping `table`.
    fn drop_table(hub: &Hub, table: &str) {
        rusqlite::Connection::open(&hub.store_path)
            .unwrap()
            .execute_batch(&format!("PRAGMA foreign_keys = OFF; DROP TABLE {table};"))
            .unwrap();
    }

    #[test]
    fn a_database_failure_is_answered_as_unknown_not_blamed_on_the_runtime() {
        // Before the request is sent: nothing reaches the runtime.
        let (_dir, hub, store, device, rx) = fixture();
        drop_table(&hub, "members");
        let error = hub
            .routine_request(
                &store,
                &device,
                OWNER,
                AGENT,
                MessageId::new("before").unwrap(),
                RoutineRequest::List { cursor: None },
            )
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::Unknown);
        assert!(!error.message.contains("members"), "{}", error.message);
        // Once the runtime answered, a list or a saved routine.
        for (request, result) in [
            (RoutineRequest::List { cursor: None }, list_result()),
            (create(), saved_as("native-1")),
        ] {
            let rpc = claim(&hub, &device, "connection", request);
            hub.routine_response(
                &store,
                AGENT,
                "connection",
                RoutineReply { of: rpc, result },
            );
            assert!(
                matches!(rx.recv().unwrap(), ToDevice::Error(ErrorBody { of: Some(id), code: ErrorCode::Unknown, .. }) if id.as_str() == "app-request")
            );
            assert!(hub.routines.lock().unwrap().completed.is_empty());
        }
        let reasons: Vec<_> = store
            .log_lines(10)
            .unwrap()
            .into_iter()
            .filter(|l| l.event.starts_with("routine."))
            .filter_map(|l| l.reason)
            .collect();
        assert_eq!(
            reasons,
            ["lab/coder new unknown: bridge database unreadable"]
        );
    }

    #[test]
    fn an_answer_is_not_dropped_when_the_paired_devices_cannot_be_read() {
        let (_dir, hub, store, device, rx) = fixture();
        let rpc = claim(
            &hub,
            &device,
            "connection",
            RoutineRequest::List { cursor: None },
        );
        drop_table(&hub, "devices");
        hub.routine_response(
            &store,
            AGENT,
            "connection",
            RoutineReply {
                of: rpc,
                result: list_result(),
            },
        );
        assert!(
            matches!(rx.recv_timeout(Duration::from_secs(1)).unwrap(), ToDevice::Error(ErrorBody { of: Some(id), code: ErrorCode::Unknown, .. }) if id.as_str() == "app-request")
        );
    }

    #[test]
    fn only_the_hosts_person_is_told_they_may_manage_routines() {
        let (_dir, hub, store, _device, _rx) = fixture();
        let host = hub.agent_infos(&store, OWNER).unwrap();
        let guest = hub.agent_infos(&store, "guest@example.com").unwrap();
        assert!(host.iter().all(|a| a.can_manage_routines));
        assert!(guest.iter().all(|a| !a.can_manage_routines));
        let sent = serde_json::to_value(&guest[0]).unwrap();
        assert_eq!(
            sent["can_manage_routines"], false,
            "always sent by a new host"
        );
    }
}
