//! An agent's model, read and changed from the app (issue #325): the
//! runtime keeps the setting and its catalogue, and answers through the
//! agent's channel (`model` capability). The bridge lets only the host's
//! person ask, on a device still paired, binds each request to the
//! channel connection it went out on, never queues or retries one, and
//! records each change in its log, a late answer included.
use super::*;
use std::collections::VecDeque;
use std::time::Instant;

use enclos_protocol::model::{ModelReply, ModelRequest, ModelResult};
use enclos_protocol::plugin::{ErrorBody, ErrorCode};
use sha2::{Digest, Sha256};

const MAX_PENDING: usize = 32;
const MAX_COMPLETED: usize = 32;
/// A runtime may check a model with its model provider before saving it.
const TIMEOUT: Duration = Duration::from_secs(60);
const UNKNOWN: &str = "The outcome is unknown: open the agent's model again before retrying.";

struct Pending {
    device: String,
    person: String,
    agent: String,
    /// The plugin connection it went out on ([`Plugin::generation`]).
    generation: u64,
    original: MessageId,
    request: ModelRequest,
    started: Instant,
}

#[derive(Default)]
pub(super) struct ModelRequests {
    pending: HashMap<String, Pending>,
    completed: VecDeque<(String, ModelRequest, ToDevice)>,
    /// Changes that ended unknown (a timeout, a disconnection), kept a
    /// while so that the runtime's late answer still reaches the log.
    ended: VecDeque<(String, Pending)>,
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

fn code_name(code: ErrorCode) -> String {
    serde_json::to_value(code)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_default()
}

/// Records a change of model, asked or answered, in the bridge's log, with
/// the person and device: the model decides what the host's accounts are
/// charged. A read is not recorded. Whether the line was written.
fn audit(store: &Store, pending: &Pending, outcome: &str) -> bool {
    let ModelRequest::Set {
        provider, model, ..
    } = &pending.request
    else {
        return true;
    };
    let reason = format!("{} {model} ({provider}) {outcome}", pending.agent);
    match store.log(
        Some(&pending.device),
        Some(&pending.person),
        "agent.model.set",
        Some(&reason),
    ) {
        Ok(_) => true,
        Err(e) => {
            eprintln!(
                "enclos app: cannot log agent.model.set for {}: {e}",
                pending.agent
            );
            false
        }
    }
}

/// The code a device gets for a plugin's `error`: one the protocol names
/// for a model request, else `unknown`. A change the runtime may have made
/// is never answered as one that is safe to try again.
fn passed_on(request: &ModelRequest, code: ErrorCode) -> ErrorCode {
    use ErrorCode::*;
    match (request, code) {
        (_, Conflict | NotFound | NotAllowed | Unsupported | BadMessage | Unknown) => code,
        (ModelRequest::Options | ModelRequest::Models { .. }, AgentUnavailable) => code,
        _ => Unknown,
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
        // The connection the request goes out on, and its generation, read
        // together: an answer is taken only from that connection.
        let found = {
            let plugins = self.plugins.lock().expect("not poisoned");
            plugins.get(agent).map(|plugin| {
                (
                    Arc::clone(&plugin.out),
                    plugin.generation,
                    plugin.capabilities.contains(&Capability::Model),
                )
            })
        };
        let Some((out, generation, supported)) = found else {
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
            generation,
            original: original.clone(),
            request: request.clone(),
            started: Instant::now(),
        };
        // A change the log cannot record is not made.
        if !audit(store, &pending, "requested") {
            return Err(failure(
                original,
                ErrorCode::Internal,
                "The bridge cannot record this change in its log, so nothing was changed. Try again later.",
            ));
        }
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

    /// Takes the pending request `of` names off the pending ones, if it went
    /// out on this connection of `agent`.
    fn take_model_request(&self, agent: &str, generation: u64, of: &str) -> Option<Pending> {
        let mut requests = self.models.lock().expect("not poisoned");
        let ours = requests
            .pending
            .get(of)
            .is_some_and(|p| p.agent == agent && p.generation == generation);
        ours.then(|| requests.pending.remove(of).expect("looked up"))
    }

    /// A change of `agent` that ended unknown and that `of` answers, on
    /// whichever connection the answer came.
    fn take_ended_model_request(&self, agent: &str, of: &str) -> Option<Pending> {
        let mut requests = self.models.lock().expect("not poisoned");
        let at = requests
            .ended
            .iter()
            .position(|(key, p)| key == of && p.agent == agent)?;
        requests.ended.remove(at).map(|(_, p)| p)
    }

    pub(super) fn model_response(
        &self,
        store: &Store,
        agent: &str,
        generation: u64,
        mut reply: ModelReply,
    ) {
        let key = reply.of.to_string();
        let Some(pending) = self.take_model_request(agent, generation, &key) else {
            // The device was told the outcome is unknown; the log learns it.
            if let Some(late) = self.take_ended_model_request(agent, &key) {
                let outcome = match (&reply.result, late.request.accepts(&reply.result)) {
                    (ModelResult::Set { current, .. }, true) => {
                        format!("confirmed late: {current}")
                    }
                    _ => "unknown: invalid late response".to_owned(),
                };
                eprintln!("enclos app: {agent} answered a model change late: {outcome}");
                audit(store, &late, &outcome);
            }
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
        let read = !matches!(pending.request, ModelRequest::Set { .. });
        let response = ToDevice::ModelResponse {
            agent: agent.into(),
            reply,
        };
        let fits = agent_names::agent_message_fits(&response);
        let (response, outcome) = match (accepted, fits) {
            (true, Ok(true)) => (response, outcome),
            // A read too large changed nothing: say so, as for routines.
            (true, Ok(false)) if read => {
                eprintln!("enclos app: {agent}'s model answer is too large for the phone");
                (
                    ToDevice::Error(failure(
                        pending.original.clone(),
                        ErrorCode::Unsupported,
                        "The runtime's list is too large to show on the phone. See it on the host.",
                    )),
                    "refused: too large".to_owned(),
                )
            }
            (accepted, fits) => {
                let why = match fits {
                    Err(e) => format!("it cannot be encoded: {e}"),
                    Ok(false) => "it is too large".to_owned(),
                    Ok(true) if !accepted => {
                        "it does not answer the request or breaks its bounds".to_owned()
                    }
                    Ok(true) => unreachable!("accepted and fitting"),
                };
                eprintln!("enclos app: {agent}'s model answer was refused: {why}");
                (
                    ToDevice::Error(failure(
                        pending.original.clone(),
                        if read {
                            ErrorCode::AgentUnavailable
                        } else {
                            ErrorCode::Unknown
                        },
                        if read {
                            "The runtime's answer could not be read. Nothing was changed."
                                .to_owned()
                        } else {
                            format!("The runtime's answer could not be read. {UNKNOWN}")
                        },
                    )),
                    "unknown: invalid response".to_owned(),
                )
            }
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
    /// gets it, cleaned, with a code the protocol names for it. Whether it
    /// was one.
    pub(super) fn model_error(
        &self,
        store: &Store,
        agent: &str,
        generation: u64,
        error: &ErrorBody,
    ) -> bool {
        let Some(of) = error.of.as_ref() else {
            return false;
        };
        let Some(pending) = self.take_model_request(agent, generation, of.as_str()) else {
            if let Some(late) = self.take_ended_model_request(agent, of.as_str()) {
                let outcome = format!("answered late {}", code_name(error.code));
                eprintln!("enclos app: {agent} answered a model change late: {outcome}");
                audit(store, &late, &outcome);
                return true;
            }
            return false;
        };
        let code = passed_on(&pending.request, error.code);
        audit(
            store,
            &pending,
            &format!("answered {}", code_name(error.code)),
        );
        let message: String = enclos_protocol::visible::stripped(&error.message, false)
            .chars()
            .take(1000)
            .collect();
        let response = ToDevice::Error(ErrorBody {
            of: Some(pending.original.clone()),
            code,
            message: if message.trim().is_empty() {
                UNKNOWN.to_owned()
            } else {
                message
            },
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
            .filter_map(|k| requests.pending.remove(&k).map(|p| (k, p)))
            .collect();
        drop(requests);
        for (key, p) in pending {
            audit(store, &p, &format!("unknown: {why}"));
            let error = failure(
                p.original.clone(),
                ErrorCode::Unknown,
                format!("The agent {why}. {UNKNOWN}"),
            );
            self.deliver_live_reply(store, &p.device, &p.person, ToDevice::Error(error));
            if matches!(p.request, ModelRequest::Set { .. }) {
                let mut requests = self.models.lock().expect("not poisoned");
                requests.ended.push_back((key, p));
                while requests.ended.len() > MAX_COMPLETED {
                    requests.ended.pop_front();
                }
            }
        }
    }

    pub(super) fn model_disconnected(&self, store: &Store, agent: &str, generation: u64) {
        self.end_model_requests(
            store,
            |p| p.agent == agent && p.generation == generation,
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
    use enclos_protocol::model::{ModelApply, ModelChoice, ModelSelection};
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

    /// A request already sent on connection 1, as `model_request` leaves it.
    fn claim(hub: &Hub, device: &Device, request: ModelRequest) -> MessageId {
        claim_at(hub, device, request, Instant::now())
    }

    fn claim_at(hub: &Hub, device: &Device, request: ModelRequest, started: Instant) -> MessageId {
        let original = MessageId::new("app-1").unwrap();
        let rpc = rpc_id(&device.id, OWNER, AGENT, &original);
        hub.models.lock().unwrap().pending.insert(
            rpc.to_string(),
            Pending {
                device: device.id.clone(),
                person: OWNER.into(),
                agent: AGENT.into(),
                generation: 1,
                original,
                request,
                started,
            },
        );
        rpc
    }

    /// The log's `agent.model.set` lines: device, person and reason.
    fn logged(store: &Store) -> Vec<(Option<String>, Option<String>, String)> {
        store
            .log_lines(100)
            .unwrap()
            .into_iter()
            .filter(|l| l.event == "agent.model.set")
            .map(|l| (l.device, l.person, l.reason.unwrap_or_default()))
            .collect()
    }

    fn reasons(store: &Store) -> Vec<String> {
        logged(store).into_iter().map(|(_, _, r)| r).collect()
    }

    /// A plugin on the agent's socket that answers its one request with
    /// what `answer` makes of it, and returns the request it got.
    fn plugin(
        hub: &Hub,
        answer: impl FnOnce(MessageId) -> FromPlugin + Send + 'static,
    ) -> std::thread::JoinHandle<Vec<enclos_protocol::Envelope<FromBridge>>> {
        let listener = UnixListener::bind(&hub.agents()[0].socket).unwrap();
        std::thread::spawn(move || {
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
                    answer(frame.id.clone()),
                )))
                .unwrap();
            // Anything else the bridge sends within a moment: a second
            // request would show here.
            let mut frames = vec![frame];
            reader
                .get_ref()
                .set_read_timeout(Some(Duration::from_millis(300)))
                .unwrap();
            line.clear();
            if reader.read_until(b'\n', &mut line).is_ok_and(|n| n > 0) {
                frames.push(enclos_protocol::plugin::decode_from_bridge(&line).unwrap());
            }
            frames
        })
    }

    #[test]
    fn only_the_hosts_person_may_ask() {
        let (_dir, hub, store, device, _rx) = fixture();
        let refused = hub
            .model_request(
                &store,
                &device,
                "guest@example.com",
                AGENT,
                MessageId::new("app-1").unwrap(),
                set(),
            )
            .unwrap_err();
        assert_eq!(refused.code, ErrorCode::NotAllowed);
        assert!(hub.models.lock().unwrap().pending.is_empty());
        assert!(reasons(&store).is_empty(), "nothing asked, nothing logged");
    }

    #[test]
    fn a_device_no_longer_paired_cannot_change_the_model() {
        let (_dir, hub, store, device, _rx) = fixture();
        store.remove_device(&device.id).unwrap();
        let refused = hub
            .model_request(
                &store,
                &device,
                OWNER,
                AGENT,
                MessageId::new("app-1").unwrap(),
                set(),
            )
            .unwrap_err();
        assert_eq!(refused.code, ErrorCode::NotAllowed);
    }

    #[test]
    fn only_the_hosts_person_is_told_they_may_choose_the_model() {
        let (_dir, hub, store, _device, _rx) = fixture();
        let host = hub.agent_infos(&store, OWNER).unwrap();
        let guest = hub.agent_infos(&store, "guest@example.com").unwrap();
        assert!(host.iter().all(|a| a.can_manage_model));
        assert!(guest.iter().all(|a| !a.can_manage_model));
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
            1,
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
            vec![(
                Some("phone".to_owned()),
                Some(OWNER.to_owned()),
                format!(
                    "{AGENT} model-2 (provider-a) confirmed: model-1 (provider-a) to model-2 (provider-a)"
                )
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
            2,
            ModelReply {
                of: rpc.clone(),
                result: set_result(),
            },
        );
        assert!(rx.try_recv().is_err(), "a reconnected channel's answer");
        hub.model_response(
            &store,
            AGENT,
            1,
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
        assert_eq!(
            error.code,
            ErrorCode::Unknown,
            "a change may have been made"
        );
        assert_eq!(error.of.unwrap().as_str(), "app-1");
        assert_eq!(
            reasons(&store),
            vec![format!(
                "{AGENT} model-2 (provider-a) unknown: invalid response"
            )]
        );
    }

    #[test]
    fn a_read_too_large_for_the_phone_is_unsupported_not_unknown() {
        let (_dir, hub, store, device, rx) = fixture();
        let provider = "p".repeat(50);
        let rpc = claim(
            &hub,
            &device,
            ModelRequest::Models {
                provider: provider.clone(),
            },
        );
        let models = (0..enclos_protocol::model::MAX_MODELS)
            .map(|i| ModelChoice {
                id: format!("{i:0>190}"),
                label: format!("{i:0>190}"),
            })
            .collect();
        hub.model_response(
            &store,
            AGENT,
            1,
            ModelReply {
                of: rpc,
                result: ModelResult::Models {
                    provider,
                    models,
                    limited: false,
                },
            },
        );
        let ToDevice::Error(error) = rx.recv().unwrap() else {
            panic!("an error");
        };
        assert_eq!(error.code, ErrorCode::Unsupported);
    }

    #[test]
    fn a_runtime_refusal_passes_on_with_its_code_and_clean_text() {
        let (_dir, hub, store, device, rx) = fixture();
        let rpc = claim(&hub, &device, set());
        let taken = hub.model_error(
            &store,
            AGENT,
            1,
            &ErrorBody {
                of: Some(rpc),
                code: ErrorCode::Conflict,
                message: "The model changed\u{202e} since it was read.".into(),
            },
        );
        assert!(taken);
        let ToDevice::Error(error) = rx.recv().unwrap() else {
            panic!("an error");
        };
        assert_eq!(error.code, ErrorCode::Conflict);
        assert!(!enclos_protocol::visible::has_hidden(&error.message, false));
        assert_eq!(
            reasons(&store),
            vec![format!("{AGENT} model-2 (provider-a) answered conflict")]
        );
    }

    #[test]
    fn a_change_is_never_answered_as_safe_to_retry() {
        let (_dir, hub, store, device, rx) = fixture();
        let rpc = claim(&hub, &device, set());
        hub.model_error(
            &store,
            AGENT,
            1,
            &ErrorBody {
                of: Some(rpc),
                code: ErrorCode::AgentUnavailable,
                message: "native control could not be confirmed".into(),
            },
        );
        let ToDevice::Error(error) = rx.recv().unwrap() else {
            panic!("an error");
        };
        assert_eq!(error.code, ErrorCode::Unknown);
        // A read that failed changed nothing: it may say so.
        let rpc = claim(&hub, &device, ModelRequest::Options);
        hub.model_error(
            &store,
            AGENT,
            1,
            &ErrorBody {
                of: Some(rpc),
                code: ErrorCode::AgentUnavailable,
                message: "OpenClaw could not read its catalogue".into(),
            },
        );
        let ToDevice::Error(error) = rx.recv().unwrap() else {
            panic!("an error");
        };
        assert_eq!(error.code, ErrorCode::AgentUnavailable);
    }

    #[test]
    fn a_change_cut_by_a_disconnect_or_a_timeout_is_logged_unknown() {
        let (_dir, hub, store, device, rx) = fixture();
        claim(&hub, &device, set());
        hub.model_disconnected(&store, AGENT, 2);
        assert!(rx.try_recv().is_err(), "another connection");
        hub.model_disconnected(&store, AGENT, 1);
        let ToDevice::Error(error) = rx.recv().unwrap() else {
            panic!("an error");
        };
        assert_eq!(error.code, ErrorCode::Unknown);
        claim_at(&hub, &device, set(), Instant::now() - TIMEOUT);
        hub.expire_models(&store);
        let ToDevice::Error(error) = rx.recv().unwrap() else {
            panic!("an error");
        };
        assert_eq!(error.code, ErrorCode::Unknown);
        assert_eq!(
            reasons(&store),
            vec![
                format!("{AGENT} model-2 (provider-a) unknown: disconnected"),
                format!("{AGENT} model-2 (provider-a) unknown: did not answer in time"),
            ]
        );
        // A read cut the same way is not logged.
        claim(&hub, &device, ModelRequest::Options);
        hub.model_disconnected(&store, AGENT, 1);
        assert_eq!(reasons(&store).len(), 2);
    }

    #[test]
    fn a_late_confirmation_reaches_the_log() {
        let (_dir, hub, store, device, rx) = fixture();
        let rpc = claim_at(&hub, &device, set(), Instant::now() - TIMEOUT);
        hub.expire_models(&store);
        rx.recv().unwrap();
        // On a new connection, as after the runtime reconnected.
        hub.model_response(
            &store,
            AGENT,
            7,
            ModelReply {
                of: rpc,
                result: set_result(),
            },
        );
        assert!(rx.try_recv().is_err(), "the device was answered already");
        assert_eq!(
            reasons(&store).last().unwrap(),
            &format!("{AGENT} model-2 (provider-a) confirmed late: model-2 (provider-a)")
        );
    }

    #[test]
    fn a_request_reaches_a_connected_channel_with_who_asked_and_is_answered_once() {
        let (_dir, hub, store, device, rx) = fixture();
        let plugin = plugin(&hub, |of| {
            FromPlugin::ModelResponse(ModelReply {
                of,
                result: set_result(),
            })
        });
        let original = MessageId::new("app-1").unwrap();
        hub.model_request(&store, &device, OWNER, AGENT, original.clone(), set())
            .unwrap();
        let answer = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(
            matches!(answer, ToDevice::ModelResponse { reply: ModelReply { ref of, .. }, .. } if *of == original)
        );
        // The same request again: the same answer, nothing sent again.
        hub.model_request(&store, &device, OWNER, AGENT, original.clone(), set())
            .unwrap();
        assert!(matches!(
            rx.recv_timeout(Duration::from_secs(5)).unwrap(),
            ToDevice::ModelResponse { .. }
        ));
        // Another request under the same id is refused.
        let reused = hub
            .model_request(
                &store,
                &device,
                OWNER,
                AGENT,
                original.clone(),
                ModelRequest::Options,
            )
            .unwrap_err();
        assert_eq!(reused.code, ErrorCode::Conflict);
        let frames = plugin.join().unwrap();
        assert_eq!(frames.len(), 1, "sent once");
        assert_eq!(frames[0].id, rpc_id(&device.id, OWNER, AGENT, &original));
        let FromBridge::ModelRequest {
            person,
            device: from,
            request,
        } = &frames[0].body
        else {
            panic!("a model request");
        };
        assert_eq!((person.as_str(), from.as_str()), (OWNER, "phone"));
        assert_eq!(*request, set());
        let lines = logged(&store);
        assert_eq!(lines.len(), 2);
        assert!(
            lines
                .iter()
                .all(|(d, p, _)| d.as_deref() == Some("phone") && p.as_deref() == Some(OWNER))
        );
        assert_eq!(
            lines[0].2,
            format!("{AGENT} model-2 (provider-a) requested")
        );
    }

    #[test]
    fn a_runtime_error_goes_through_the_bridge_to_the_device() {
        let (_dir, hub, store, device, rx) = fixture();
        let plugin = plugin(&hub, |of| {
            FromPlugin::Error(ErrorBody {
                of: Some(of),
                code: ErrorCode::Conflict,
                message: "The agent's model changed since it was read.".into(),
            })
        });
        hub.model_request(
            &store,
            &device,
            OWNER,
            AGENT,
            MessageId::new("app-1").unwrap(),
            set(),
        )
        .unwrap();
        let ToDevice::Error(error) = rx.recv_timeout(Duration::from_secs(5)).unwrap() else {
            panic!("an error");
        };
        assert_eq!(error.code, ErrorCode::Conflict);
        assert_eq!(error.of.unwrap().as_str(), "app-1");
        plugin.join().unwrap();
        assert_eq!(
            reasons(&store).last().unwrap(),
            &format!("{AGENT} model-2 (provider-a) answered conflict")
        );
    }
}
