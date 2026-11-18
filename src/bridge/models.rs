//! An agent's model, read and changed from the app (issue #325): the
//! runtime keeps the setting and its catalogue, and answers through the
//! agent's channel (`model` capability). The bridge lets only the host's
//! person ask, on a device still paired, binds each request to the
//! channel connection it went out on, never queues or retries one, and
//! records each change in its log.
use super::*;
use std::collections::VecDeque;
use std::time::Instant;

use enclos_protocol::model::{ModelReply, ModelRequest, ModelResult};
use enclos_protocol::plugin::{ErrorBody, ErrorCode};
use sha2::{Digest, Sha256};

const MAX_PENDING: usize = 32;
const MAX_COMPLETED: usize = 32;
/// A runtime may check a model with its provider before saving it.
const TIMEOUT: Duration = Duration::from_secs(60);
const UNKNOWN: &str = "The outcome is unknown: open the agent's model again before retrying.";

struct Pending {
    device: String,
    person: String,
    agent: String,
    connection: String,
    original: MessageId,
    request: ModelRequest,
    started: Instant,
}

#[derive(Default)]
pub(super) struct ModelRequests {
    pending: HashMap<String, Pending>,
    completed: VecDeque<(String, ModelRequest, ToDevice)>,
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
    MessageId::new(format!("model-{suffix}")).expect("bounded digest")
}

/// Records a change of model, asked or answered, in the bridge's log, with
/// the person and device: the model decides what the host's accounts are
/// charged. A read is not recorded.
fn audit(store: &Store, pending: &Pending, outcome: &str) {
    let ModelRequest::Set {
        provider, model, ..
    } = &pending.request
    else {
        return;
    };
    let reason = format!("{} {provider}/{model} {outcome}", pending.agent);
    if let Err(e) = store.log(
        Some(&pending.device),
        Some(&pending.person),
        "agent.model.set",
        Some(&reason),
    ) {
        eprintln!(
            "enclos app: cannot log agent.model.set for {}: {e}",
            pending.agent
        );
    }
}

/// What the bridge already knows of a request id.
enum Replay {
    Completed(Box<ToDevice>),
    Pending,
    Fresh,
}

/// A request id seen before must name the same request.
fn replay(
    requests: &ModelRequests,
    rpc: &MessageId,
    request: &ModelRequest,
    original: &MessageId,
) -> Result<Replay, ErrorBody> {
    let reused = || {
        failure(
            original.clone(),
            ErrorCode::Conflict,
            "A request id cannot be reused for another model request.",
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
    pub(super) fn model_request(
        self: &Arc<Self>,
        store: &Store,
        device: &Device,
        person: &str,
        agent: &str,
        original: MessageId,
        request: ModelRequest,
    ) -> Result<(), ErrorBody> {
        self.agent_control_authority(store, device, person, agent)
            .map_err(|(code, why)| failure(original.clone(), code, why))?;
        request
            .validate()
            .map_err(|e| failure(original.clone(), ErrorCode::BadMessage, e))?;
        let requester = Person::new(person)
            .map_err(|e| failure(original.clone(), ErrorCode::BadMessage, e.to_string()))?;
        let rpc = rpc_id(&device.id, person, agent, &original);
        {
            let requests = self.models.lock().expect("not poisoned");
            match replay(&requests, &rpc, &request, &original)? {
                Replay::Completed(response) => {
                    drop(requests);
                    self.deliver_live_reply(store, &device.id, person, *response);
                    return Ok(());
                }
                Replay::Pending => return Ok(()),
                Replay::Fresh => {}
            }
        }
        self.plugin(agent)
            .map_err(|e| failure(original.clone(), ErrorCode::AgentUnavailable, e))?;
        let found = {
            let plugins = self.plugins.lock().expect("not poisoned");
            plugins.get(agent).map(|plugin| {
                (
                    Arc::clone(&plugin.out),
                    plugin.capabilities.contains(&Capability::Model),
                )
            })
        };
        let Some((out, supported)) = found else {
            return Err(failure(
                original,
                ErrorCode::AgentUnavailable,
                "The agent's channel is disconnected.",
            ));
        };
        if !supported {
            return Err(failure(
                original,
                ErrorCode::Unsupported,
                "This agent's runtime does not let the app choose its model.",
            ));
        }
        let connection = self.agent_connection(agent).ok_or_else(|| {
            failure(
                original.clone(),
                ErrorCode::AgentUnavailable,
                "The agent's channel is disconnected.",
            )
        })?;
        let mut requests = self.models.lock().expect("not poisoned");
        // Another device thread may have claimed the same id meanwhile.
        match replay(&requests, &rpc, &request, &original)? {
            Replay::Completed(response) => {
                drop(requests);
                self.deliver_live_reply(store, &device.id, person, *response);
                return Ok(());
            }
            Replay::Pending => return Ok(()),
            Replay::Fresh => {}
        }
        if requests.pending.len() >= MAX_PENDING {
            return Err(failure(
                original,
                ErrorCode::AgentUnavailable,
                "Too many model requests are in progress. Try again shortly.",
            ));
        }
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
        let sent = out.lock().expect("not poisoned").writer.send_with_id(
            rpc.clone(),
            FromBridge::ModelRequest {
                person: requester,
                device: device.id.clone(),
                request,
            },
        );
        if let Err(e) = sent {
            let pending = self
                .models
                .lock()
                .expect("not poisoned")
                .pending
                .remove(rpc.as_str());
            if let Some(pending) = pending {
                audit(store, &pending, "unknown: not sent");
            }
            return Err(failure(
                original,
                ErrorCode::Unknown,
                format!("{e}. {UNKNOWN}"),
            ));
        }
        Ok(())
    }

    /// Takes the request `reply` answers off the pending ones, if it is one
    /// this connection of `agent` was sent.
    fn take_model_request(&self, agent: &str, connection: &str, of: &str) -> Option<Pending> {
        let mut requests = self.models.lock().expect("not poisoned");
        let ours = requests
            .pending
            .get(of)
            .is_some_and(|p| p.agent == agent && p.connection == connection);
        ours.then(|| requests.pending.remove(of).expect("looked up"))
    }

    pub(super) fn model_response(
        &self,
        store: &Store,
        agent: &str,
        connection: &str,
        mut reply: ModelReply,
    ) {
        let key = reply.of.to_string();
        let Some(pending) = self.take_model_request(agent, connection, &key) else {
            return;
        };
        reply.of = pending.original.clone();
        let accepted = pending.request.accepts(&reply.result);
        let outcome = match &reply.result {
            ModelResult::Set {
                previous, current, ..
            } => match previous {
                Some(previous) => format!("confirmed: {previous} to {current}"),
                None => format!("confirmed: {current}"),
            },
            _ => "confirmed".to_owned(),
        };
        let response = ToDevice::ModelResponse {
            agent: agent.into(),
            reply,
        };
        let fits = agent_names::agent_message_fits(&response).unwrap_or(false);
        let (response, outcome) = if accepted && fits {
            (response, outcome)
        } else {
            (
                ToDevice::Error(failure(
                    pending.original.clone(),
                    ErrorCode::Unknown,
                    format!("The runtime's answer was invalid or too large. {UNKNOWN}"),
                )),
                "unknown: invalid response".to_owned(),
            )
        };
        let mut requests = self.models.lock().expect("not poisoned");
        requests
            .completed
            .push_back((key, pending.request.clone(), response.clone()));
        while requests.completed.len() > MAX_COMPLETED {
            requests.completed.pop_front();
        }
        drop(requests);
        audit(store, &pending, &outcome);
        self.deliver_live_reply(store, &pending.device, &pending.person, response);
    }

    /// A plugin's `error` about a model request: the device that asked
    /// gets it. Whether it was one.
    pub(super) fn model_error(
        &self,
        store: &Store,
        agent: &str,
        connection: &str,
        error: &ErrorBody,
    ) -> bool {
        let Some(of) = error.of.as_ref() else {
            return false;
        };
        let Some(pending) = self.take_model_request(agent, connection, of.as_str()) else {
            return false;
        };
        let code = serde_json::to_value(error.code)
            .ok()
            .and_then(|v| v.as_str().map(str::to_owned))
            .unwrap_or_default();
        audit(store, &pending, &format!("answered {code}"));
        let response = ToDevice::Error(ErrorBody {
            of: Some(pending.original.clone()),
            code: error.code,
            message: error.message.chars().take(1000).collect(),
        });
        self.deliver_live_reply(store, &pending.device, &pending.person, response);
        true
    }

    fn end_model_requests(&self, store: &Store, ended: impl Fn(&Pending) -> bool, why: &str) {
        let mut requests = self.models.lock().expect("not poisoned");
        let keys: Vec<_> = requests
            .pending
            .iter()
            .filter(|(_, p)| ended(p))
            .map(|(k, _)| k.clone())
            .collect();
        let pending: Vec<_> = keys
            .into_iter()
            .filter_map(|k| requests.pending.remove(&k))
            .collect();
        drop(requests);
        for p in pending {
            audit(store, &p, &format!("unknown: {why}"));
            let error = failure(
                p.original,
                ErrorCode::Unknown,
                format!("The agent {why}. {UNKNOWN}"),
            );
            self.deliver_live_reply(store, &p.device, &p.person, ToDevice::Error(error));
        }
    }

    pub(super) fn model_disconnected(&self, store: &Store, agent: &str, connection: &str) {
        self.end_model_requests(
            store,
            |p| p.agent == agent && p.connection == connection,
            "disconnected",
        );
    }

    pub(super) fn expire_models(&self, store: &Store) {
        self.end_model_requests(
            store,
            |p| p.started.elapsed() >= TIMEOUT,
            "did not answer in time",
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use enclos_protocol::model::{ModelApply, ModelSelection};
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
                runtime: "openclaw".into(),
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
        let (tx, rx) = channel();
        hub.devices
            .lock()
            .unwrap()
            .insert(device.id.clone(), (OWNER.into(), tx, 1));
        (dir, hub, store, device, rx)
    }

    fn set() -> ModelRequest {
        ModelRequest::Set {
            provider: "provider-a".into(),
            model: "model-2".into(),
            revision: "r1".into(),
        }
    }

    fn set_result() -> ModelResult {
        ModelResult::Set {
            previous: Some(ModelSelection {
                provider: Some("provider-a".into()),
                model: "model-1".into(),
            }),
            current: ModelSelection {
                provider: Some("provider-a".into()),
                model: "model-2".into(),
            },
            revision: "r2".into(),
            applies: ModelApply::Live,
        }
    }

    /// A request already sent on connection `c1`, as `model_request` leaves it.
    fn claim(hub: &Hub, device: &Device, request: ModelRequest) -> MessageId {
        let original = MessageId::new("app-1").unwrap();
        let rpc = rpc_id(&device.id, OWNER, AGENT, &original);
        hub.models.lock().unwrap().pending.insert(
            rpc.to_string(),
            Pending {
                device: device.id.clone(),
                person: OWNER.into(),
                agent: AGENT.into(),
                connection: "c1".into(),
                original,
                request,
                started: Instant::now(),
            },
        );
        rpc
    }

    fn logged(store: &Store) -> Vec<String> {
        store
            .log_lines(100)
            .unwrap()
            .into_iter()
            .filter(|l| l.event == "agent.model.set")
            .filter_map(|l| l.reason)
            .collect()
    }

    #[test]
    fn only_the_hosts_person_may_ask() {
        let (_dir, hub, store, device, _rx) = fixture();
        let original = MessageId::new("app-1").unwrap();
        let refused = hub
            .model_request(
                &store,
                &device,
                "guest@example.com",
                AGENT,
                original,
                ModelRequest::Options,
            )
            .unwrap_err();
        assert_eq!(refused.code, ErrorCode::NotAllowed);
        assert!(hub.models.lock().unwrap().pending.is_empty());
    }

    #[test]
    fn an_agent_without_a_connected_channel_is_unavailable() {
        let (_dir, hub, store, device, _rx) = fixture();
        let refused = hub
            .model_request(
                &store,
                &device,
                OWNER,
                AGENT,
                MessageId::new("app-1").unwrap(),
                ModelRequest::Options,
            )
            .unwrap_err();
        assert_eq!(refused.code, ErrorCode::AgentUnavailable);
    }

    #[test]
    fn an_invalid_request_is_refused_before_the_runtime() {
        let (_dir, hub, store, device, _rx) = fixture();
        let refused = hub
            .model_request(
                &store,
                &device,
                OWNER,
                AGENT,
                MessageId::new("app-1").unwrap(),
                ModelRequest::Models {
                    provider: "a\u{202e}b".into(),
                },
            )
            .unwrap_err();
        assert_eq!(refused.code, ErrorCode::BadMessage);
    }

    #[test]
    fn an_answer_reaches_the_device_under_its_own_id_and_is_logged() {
        let (_dir, hub, store, device, rx) = fixture();
        let rpc = claim(&hub, &device, set());
        hub.model_response(
            &store,
            AGENT,
            "c1",
            ModelReply {
                of: rpc,
                result: set_result(),
            },
        );
        let ToDevice::ModelResponse { agent, reply } = rx.recv().unwrap() else {
            panic!("a model response");
        };
        assert_eq!(agent, AGENT);
        assert_eq!(reply.of.as_str(), "app-1");
        assert_eq!(
            logged(&store),
            vec![format!(
                "{AGENT} provider-a/model-2 confirmed: provider-a/model-1 to provider-a/model-2"
            )]
        );
    }

    #[test]
    fn an_answer_from_another_connection_or_of_another_kind_is_not_taken() {
        let (_dir, hub, store, device, rx) = fixture();
        let rpc = claim(&hub, &device, set());
        hub.model_response(
            &store,
            AGENT,
            "c2",
            ModelReply {
                of: rpc.clone(),
                result: set_result(),
            },
        );
        assert!(
            rx.try_recv().is_err(),
            "a reconnected channel's late answer"
        );
        hub.model_response(
            &store,
            AGENT,
            "c1",
            ModelReply {
                of: rpc,
                result: ModelResult::Models {
                    provider: "provider-a".into(),
                    models: vec![],
                    limited: false,
                },
            },
        );
        let ToDevice::Error(error) = rx.recv().unwrap() else {
            panic!("an answer of the wrong kind is an error");
        };
        assert_eq!(error.code, ErrorCode::Unknown);
        assert_eq!(error.of.unwrap().as_str(), "app-1");
    }

    #[test]
    fn a_runtime_refusal_passes_on_with_its_code() {
        let (_dir, hub, store, device, rx) = fixture();
        let rpc = claim(&hub, &device, set());
        let taken = hub.model_error(
            &store,
            AGENT,
            "c1",
            &ErrorBody {
                of: Some(rpc),
                code: ErrorCode::Conflict,
                message: "The model changed since it was read.".into(),
            },
        );
        assert!(taken);
        let ToDevice::Error(error) = rx.recv().unwrap() else {
            panic!("an error");
        };
        assert_eq!(error.code, ErrorCode::Conflict);
        assert_eq!(
            logged(&store),
            vec![format!("{AGENT} provider-a/model-2 answered conflict")]
        );
    }

    #[test]
    fn a_disconnect_ends_its_requests_as_unknown() {
        let (_dir, hub, store, device, rx) = fixture();
        claim(&hub, &device, ModelRequest::Options);
        hub.model_disconnected(&store, AGENT, "c2");
        assert!(rx.try_recv().is_err(), "another connection");
        hub.model_disconnected(&store, AGENT, "c1");
        let ToDevice::Error(error) = rx.recv().unwrap() else {
            panic!("an error");
        };
        assert_eq!(error.code, ErrorCode::Unknown);
        assert!(logged(&store).is_empty(), "a read is not logged");
    }

    #[test]
    fn a_request_reaches_a_connected_channel_with_who_asked() {
        let (_dir, hub, store, device, rx) = fixture();
        let listener = UnixListener::bind(&hub.agents()[0].socket).unwrap();
        let plugin = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut writer = stream.try_clone().unwrap();
            let mut reader = BufReader::new(stream);
            let mut line = Vec::new();
            reader.read_until(b'\n', &mut line).unwrap();
            writer
                .write_all(&encode_line(&Envelope::new(
                    MessageId::new("hello").unwrap(),
                    FromPlugin::Hello {
                        runtime: "openclaw".into(),
                        agent: "coder".into(),
                        capabilities: vec![Capability::Model],
                    },
                )))
                .unwrap();
            line.clear();
            reader.read_until(b'\n', &mut line).unwrap();
            let frame = enclos_protocol::plugin::decode_from_bridge(&line).unwrap();
            writer
                .write_all(&encode_line(&Envelope::new(
                    MessageId::new("reply").unwrap(),
                    FromPlugin::ModelResponse(ModelReply {
                        of: frame.id.clone(),
                        result: set_result(),
                    }),
                )))
                .unwrap();
            frame
        });
        let original = MessageId::new("app-1").unwrap();
        hub.model_request(&store, &device, OWNER, AGENT, original.clone(), set())
            .unwrap();
        let frame = plugin.join().unwrap();
        assert_eq!(frame.id, rpc_id(&device.id, OWNER, AGENT, &original));
        let FromBridge::ModelRequest {
            person,
            device: from,
            request,
        } = frame.body
        else {
            panic!("a model request");
        };
        assert_eq!((person.as_str(), from.as_str()), (OWNER, "phone"));
        assert_eq!(request, set());
        let answer = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(
            matches!(answer, ToDevice::ModelResponse { reply: ModelReply { of, .. }, .. } if of == original)
        );
        assert_eq!(
            logged(&store),
            vec![
                format!("{AGENT} provider-a/model-2 requested"),
                format!(
                    "{AGENT} provider-a/model-2 confirmed: provider-a/model-1 to provider-a/model-2"
                ),
            ]
        );
    }
}
