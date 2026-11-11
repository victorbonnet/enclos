//! Durable native questions and bounded, connection-fenced answer receipts.
use super::*;
use std::collections::{HashSet, VecDeque};
use std::time::Instant;

use super::super::store::{QuestionChange, QuestionStoreError, Settlement, StoredQuestion};
use enclos_protocol::QuestionId;
use enclos_protocol::plugin::{ErrorBody, ErrorCode};
use enclos_protocol::question::{
    MAX_SYNC_QUESTIONS, QuestionAnswer, QuestionDefinition, QuestionInfo, QuestionState,
};
use sha2::{Digest, Sha256};

/// Answers in flight to agents, for all people together.
const MAX_PENDING: usize = 256;
/// Answers in flight for one person: one person's stalled agent cannot
/// hold another person's answers back.
const MAX_PENDING_PER_PERSON: usize = 16;
const MAX_COMPLETED: usize = 128;
const TIMEOUT: Duration = Duration::from_secs(25);
const FRAME_BUDGET: usize = 60 * 1024;
/// A pending question of an agent whose channel is not connected expires
/// this long after it was asked. Twice the runtime's wait enclos sets
/// (Hermes: `runtime::hermes::CLARIFY_TIMEOUT_SECONDS`): by then no runtime
/// still waits for it, and a channel that does reconnect is asked first
/// (`question.sync`).
const UNCONNECTED_LIFETIME_SECONDS: i64 = 2 * 60 * 60;
/// How often the bridge looks for such questions.
const SWEEP: Duration = Duration::from_secs(60);

/// What a paired device asks: this answer, to this question, at this revision.
#[derive(Clone, PartialEq, Eq)]
pub(super) struct AnswerRequest {
    pub question: QuestionId,
    pub revision: u64,
    pub answer: QuestionAnswer,
}

/// An agent's channel and the connection it spoke on.
#[derive(Clone, Copy)]
pub(super) struct Origin<'a> {
    pub agent: &'a str,
    pub connection: &'a str,
}

/// A `question.update` from a channel.
pub(super) struct Update {
    pub question: QuestionId,
    pub state: QuestionState,
    pub answer: Option<QuestionAnswer>,
    pub of: Option<MessageId>,
}

struct Pending {
    device: String,
    person: String,
    agent: String,
    connection: String,
    original: MessageId,
    request: AnswerRequest,
    started: Instant,
}

#[derive(Default)]
pub(super) struct QuestionRequests {
    connections: HashMap<String, String>,
    pending: HashMap<String, Pending>,
    // Keep ambiguous outcomes too: replaying a device packet must never resend an answer.
    completed: VecDeque<(String, AnswerRequest, ToDevice)>,
    swept: Option<Instant>,
}

fn failure(of: MessageId, code: ErrorCode, message: impl Into<String>) -> ErrorBody {
    ErrorBody {
        of: Some(of),
        code,
        message: message.into(),
    }
}

fn rpc_id(device: &str, person: &str, original: &MessageId) -> MessageId {
    let bytes =
        serde_json::to_vec(&(device, person, original.as_str())).expect("strings serialize");
    let suffix: String = Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    MessageId::new(format!("question-{suffix}")).expect("bounded digest")
}

fn canonical_answer(mut answer: QuestionAnswer) -> QuestionAnswer {
    if let QuestionAnswer::Choices { indices } = &mut answer {
        indices.sort_unstable();
    }
    answer
}

/// Whether a settlement is what `requested` asked for.
fn settles_as(
    requested: &QuestionAnswer,
    state: QuestionState,
    answer: Option<&QuestionAnswer>,
) -> bool {
    match requested {
        QuestionAnswer::Skip => state == QuestionState::Skipped && answer.is_none(),
        requested => state == QuestionState::Answered && answer == Some(requested),
    }
}

fn bounded(body: &ToDevice) -> bool {
    let id = MessageId::new("x".repeat(128)).expect("bounded id");
    encode_line(&Envelope::new(id, body)).len() <= FRAME_BUDGET
}

fn remember(requests: &mut QuestionRequests, key: String, pending: &Pending, response: ToDevice) {
    requests
        .completed
        .push_back((key, pending.request.clone(), response));
    while requests.completed.len() > MAX_COMPLETED {
        requests.completed.pop_front();
    }
}

/// The device requests a terminal `info` closes. `exact` is the request the
/// channel says it resolved, and the connection it said so on: only that
/// one, when the settlement is what it asked, gets a receipt; the others
/// get a conflict. A broadcast that matches a request leaves it waiting for
/// its own receipt.
fn receipts(
    requests: &mut QuestionRequests,
    agent: &str,
    info: &QuestionInfo,
    exact: Option<(&MessageId, &str)>,
    conflict: bool,
) -> Vec<(Pending, ToDevice)> {
    let question = &info.definition.id;
    let keys: Vec<_> = requests
        .pending
        .iter()
        .filter(|(_, pending)| pending.agent == agent && pending.request.question == *question)
        .map(|(key, _)| key.clone())
        .collect();
    let mut replies = Vec::new();
    for key in keys {
        let pending = requests.pending.get(&key).expect("looked up");
        let expected = settles_as(&pending.request.answer, info.state, info.answer.as_ref());
        // A native watcher may publish before the resolving RPC returns. Its
        // broadcast updates the card but cannot confirm the matching answer.
        if exact.is_none() && expected {
            continue;
        }
        let pending = requests.pending.remove(&key).expect("looked up");
        let receipt = !conflict
            && exact.is_some_and(|(of, connection)| {
                of.as_str() == key && pending.connection == connection
            })
            && expected;
        let response = if receipt {
            ToDevice::QuestionResult {
                of: pending.original.clone(),
                question: info.clone(),
            }
        } else {
            ToDevice::Error(failure(
                pending.original.clone(),
                ErrorCode::Conflict,
                "This question was settled. Its current state is shown in the conversation.",
            ))
        };
        remember(requests, key, &pending, response.clone());
        replies.push((pending, response));
    }
    replies
}

/// Poison outbox entries are acknowledged with an explicit error; a failed transaction is retried.
pub(super) fn acknowledge_question(
    writer: &mut PluginWriter,
    id: &MessageId,
    result: Result<(), QuestionStoreError>,
) {
    match result {
        Ok(()) => {
            let _ = writer.ack(id);
        }
        Err(QuestionStoreError::Sql(error)) => {
            eprintln!("enclos app: could not persist a question: {error}")
        }
        Err(error) => {
            let code = match error {
                QuestionStoreError::Unknown => ErrorCode::NotFound,
                QuestionStoreError::Conflict => ErrorCode::Conflict,
                _ => ErrorCode::BadMessage,
            };
            let _ = writer.send(FromBridge::Error(failure(
                id.clone(),
                code,
                error.to_string(),
            )));
            let _ = writer.ack(id);
        }
    }
}

impl Hub {
    /// A channel connected. One without the `questions` capability cannot
    /// answer the cards it left (a runtime that lost its native API, or
    /// one replaced): they expire now rather than wait for an answer that
    /// cannot be given.
    pub(super) fn question_connected(&self, store: Option<&Store>, origin: Origin, capable: bool) {
        self.questions
            .lock()
            .expect("not poisoned")
            .connections
            .insert(origin.agent.into(), origin.connection.into());
        if !capable && let Some(store) = store {
            for id in store.pending_questions(origin.agent).unwrap_or_default() {
                self.expire_question(store, origin.agent, &id);
            }
        }
    }

    pub(super) fn sync_questions(
        &self,
        store: &Store,
        agent: &str,
        writer: &mut PluginWriter,
    ) -> Result<(), String> {
        let pending = store.pending_questions(agent).map_err(|e| e.to_string())?;
        for batch in pending.chunks(MAX_SYNC_QUESTIONS) {
            writer
                .send(FromBridge::QuestionSync {
                    questions: batch.to_vec(),
                })
                .map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    fn current_connection(
        requests: &QuestionRequests,
        origin: Origin,
    ) -> Result<(), QuestionStoreError> {
        if requests
            .connections
            .get(origin.agent)
            .is_some_and(|current| current == origin.connection)
        {
            Ok(())
        } else {
            Err(QuestionStoreError::Invalid(
                "The question belongs to an old connection.".into(),
            ))
        }
    }

    pub(super) fn question_ask(
        &self,
        store: &Store,
        origin: Origin,
        conversation: &ConversationId,
        question: &QuestionDefinition,
        id: &MessageId,
    ) -> Result<(), QuestionStoreError> {
        let requests = self.questions.lock().expect("not poisoned");
        Self::current_connection(&requests, origin)?;
        let change = store.ask_question(origin.agent, conversation, question, id.as_str())?;
        drop(requests);
        self.publish_question(store, change);
        Ok(())
    }

    /// The only source of a successful device receipt is this matching native result.
    pub(super) fn question_update(
        &self,
        store: &Store,
        origin: Origin,
        update: Update,
        id: &MessageId,
    ) -> Result<(), QuestionStoreError> {
        let Update {
            question,
            state,
            answer,
            of,
        } = update;
        let answer = answer.map(canonical_answer);
        let mut requests = self.questions.lock().expect("not poisoned");
        Self::current_connection(&requests, origin)?;
        let correlated = of.as_ref().and_then(|id| requests.pending.get(id.as_str()));
        if let Some(pending) = correlated
            && (pending.agent != origin.agent
                || pending.connection != origin.connection
                || pending.request.question != question)
        {
            return Err(QuestionStoreError::Invalid(
                "The native question receipt does not match its request.".into(),
            ));
        }
        let confirmed = correlated
            .is_some_and(|pending| settles_as(&pending.request.answer, state, answer.as_ref()));
        let settlement = Settlement {
            state,
            answer,
            confirmed,
        };
        let (change, conflict) =
            match store.settle_question(origin.agent, &question, settlement, id.as_str()) {
                Ok(change) => (change, false),
                Err(QuestionStoreError::Conflict) => {
                    let current = store
                        .question(&question)?
                        .filter(|q| q.info.agent == origin.agent)
                        .ok_or(QuestionStoreError::Unknown)?;
                    if !current.info.state.is_terminal() {
                        return Err(QuestionStoreError::Conflict);
                    }
                    // An orphaned outbox ask can be expired after reconnect even if its earlier
                    // terminal update was already stored. Preserve the first native settlement.
                    (
                        QuestionChange {
                            question: current,
                            message: None,
                        },
                        true,
                    )
                }
                Err(error) => return Err(error),
            };
        let info = change.question.info.clone();
        let replies = if info.state.is_terminal() {
            let exact = of.as_ref().map(|of| (of, origin.connection));
            receipts(&mut requests, origin.agent, &info, exact, conflict)
        } else {
            Vec::new()
        };
        drop(requests);
        // Metadata and history always precede the receipt, including the losing phone's state.
        self.publish_question(store, change);
        self.deliver_replies(store, replies);
        Ok(())
    }

    /// The bridge closes a question itself: its channel cannot answer it.
    fn expire_question(&self, store: &Store, agent: &str, id: &QuestionId) {
        let Ok(message) = new_id() else { return };
        let mut requests = self.questions.lock().expect("not poisoned");
        let settlement = Settlement::reported(QuestionState::Expired, None);
        let change = match store.settle_question(agent, id, settlement, &message) {
            Ok(change) => change,
            Err(error) => {
                eprintln!("enclos app: could not expire question {id}: {error}");
                return;
            }
        };
        let replies = receipts(&mut requests, agent, &change.question.info, None, false);
        drop(requests);
        self.publish_question(store, change);
        self.deliver_replies(store, replies);
    }

    fn deliver_replies(&self, store: &Store, replies: Vec<(Pending, ToDevice)>) {
        for (pending, response) in replies {
            self.deliver_question_device(
                store,
                &pending.device,
                &pending.person,
                &pending.request.question,
                response,
            );
        }
    }

    fn question_authority(
        &self,
        store: &Store,
        device: &Device,
        person: &str,
        id: &QuestionId,
    ) -> Result<StoredQuestion, ()> {
        if device.person != person
            || !store
                .devices()
                .map_err(|_| ())?
                .iter()
                .any(|d| d.id == device.id && d.person == person)
        {
            return Err(());
        }
        store
            .question(id)
            .map_err(|_| ())?
            .filter(|question| question.owner == person)
            .ok_or(())
    }

    pub(super) fn question_answer(
        self: &Arc<Self>,
        store: &Store,
        device: &Device,
        person: &str,
        original: MessageId,
        request: AnswerRequest,
    ) -> Result<(), ErrorBody> {
        let request = AnswerRequest {
            answer: canonical_answer(request.answer),
            ..request
        };
        let rpc = rpc_id(&device.id, person, &original);
        // A live writer and its epoch are held through registration and send. No offline queue or reconnect retry.
        let mut plugins = self.plugins.lock().expect("not poisoned");
        let mut requests = self.questions.lock().expect("not poisoned");
        let current = self
            .question_authority(store, device, person, &request.question)
            .map_err(|_| failure(original.clone(), ErrorCode::NotFound, "No such question."))?;
        request
            .answer
            .validate(&current.info.definition)
            .map_err(|e| failure(original.clone(), ErrorCode::BadMessage, e))?;
        if let Some((_, previous, response)) = requests
            .completed
            .iter()
            .find(|(key, _, _)| key == rpc.as_str())
        {
            if previous != &request {
                return Err(failure(
                    original,
                    ErrorCode::Conflict,
                    "A request id cannot be reused for another question answer.",
                ));
            }
            let response = response.clone();
            drop(requests);
            drop(plugins);
            self.deliver_question_device(store, &device.id, person, &request.question, response);
            return Ok(());
        }
        if let Some(previous) = requests.pending.get(rpc.as_str()) {
            return if previous.request == request {
                Ok(())
            } else {
                Err(failure(
                    original,
                    ErrorCode::Conflict,
                    "A request id cannot be reused for another question answer.",
                ))
            };
        }
        if current.info.state != QuestionState::Pending || current.info.revision != request.revision
        {
            drop(requests);
            drop(plugins);
            self.deliver_question_device(
                store,
                &device.id,
                person,
                &request.question,
                ToDevice::Question {
                    question: current.info,
                },
            );
            return Err(failure(
                original,
                ErrorCode::Conflict,
                "This question has changed. Review its current state.",
            ));
        }
        // Until the answer is written to the channel, a refusal is certain:
        // nothing was sent, and answering again is safe (`agent_unavailable`).
        let Some((writer, capabilities)) = plugins.get_mut(&current.info.agent) else {
            return Err(failure(
                original,
                ErrorCode::AgentUnavailable,
                "The agent is disconnected. Nothing was sent; answer again when it is back.",
            ));
        };
        if !capabilities.contains(&Capability::Questions) {
            return Err(failure(
                original,
                ErrorCode::Unsupported,
                "This runtime does not support native app answers.",
            ));
        }
        let in_flight = requests
            .pending
            .values()
            .filter(|pending| pending.person == person)
            .count();
        if in_flight >= MAX_PENDING_PER_PERSON || requests.pending.len() >= MAX_PENDING {
            return Err(failure(
                original,
                ErrorCode::AgentUnavailable,
                "Too many question answers are in progress. Nothing was sent; try again shortly.",
            ));
        }
        let connection = requests
            .connections
            .get(&current.info.agent)
            .cloned()
            .ok_or_else(|| {
                failure(
                    original.clone(),
                    ErrorCode::AgentUnavailable,
                    "The agent is disconnected. Nothing was sent.",
                )
            })?;
        requests.pending.insert(
            rpc.to_string(),
            Pending {
                device: device.id.clone(),
                person: person.into(),
                agent: current.info.agent.clone(),
                connection,
                original: original.clone(),
                request: request.clone(),
                started: Instant::now(),
            },
        );
        drop(requests);
        if let Err(error) = writer.send_with_id(
            rpc.clone(),
            FromBridge::QuestionAnswer {
                conversation: current.info.conversation,
                question: request.question.clone(),
                answer: request.answer,
            },
        ) {
            let mut requests = self.questions.lock().expect("not poisoned");
            let pending = requests.pending.remove(rpc.as_str());
            let error = failure(
                original,
                ErrorCode::Unconfirmed,
                format!(
                    "{error}. The outcome may be unknown; review this question before answering again."
                ),
            );
            if let Some(pending) = pending {
                remember(
                    &mut requests,
                    rpc.to_string(),
                    &pending,
                    ToDevice::Error(error.clone()),
                );
            }
            return Err(error);
        }
        Ok(())
    }

    fn deliver_question_device(
        &self,
        store: &Store,
        device: &str,
        person: &str,
        question: &QuestionId,
        response: ToDevice,
    ) {
        if !bounded(&response)
            || store
                .question(question)
                .ok()
                .flatten()
                .is_none_or(|q| q.owner != person)
        {
            return;
        }
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

    fn publish_question(&self, store: &Store, change: QuestionChange) {
        // Read the current owner and state; a Home may have been claimed since the original ask.
        let Some(current) = store
            .question(&change.question.info.definition.id)
            .ok()
            .flatten()
        else {
            return;
        };
        let question = ToDevice::Question {
            question: current.info.clone(),
        };
        if !bounded(&question) {
            return;
        }
        let message = change.message.map(|message| {
            ToDevice::Message(ConversationMessage {
                question: message.question,
                conversation: current.info.conversation.clone(),
                agent: current.info.agent.clone(),
                from: "agent".into(),
                text: message.text,
                kind: message.kind,
                time: message.at,
                seq: message.seq,
                attachments: vec![],
            })
        });
        let paired = store.devices().unwrap_or_default();
        let devices = self.devices.lock().expect("not poisoned");
        for (device, (person, sender)) in devices.iter() {
            if person == &current.owner
                && paired
                    .iter()
                    .any(|d| d.id == *device && d.person == *person)
            {
                let _ = sender.send(question.clone());
                if let Some(message) = &message
                    && bounded(message)
                {
                    let _ = sender.send(message.clone());
                }
            }
        }
    }

    pub(super) fn question_error(&self, store: &Store, origin: Origin, mut error: ErrorBody) {
        let Some(key) = error.of.as_ref().map(ToString::to_string) else {
            return;
        };
        let mut requests = self.questions.lock().expect("not poisoned");
        let Some(pending) = requests.pending.get(&key) else {
            return;
        };
        if pending.agent != origin.agent || pending.connection != origin.connection {
            return;
        }
        let pending = requests.pending.remove(&key).expect("looked up");
        error.of = Some(pending.original.clone());
        error.message = error.message.chars().take(1000).collect();
        let response = ToDevice::Error(error);
        remember(&mut requests, key, &pending, response.clone());
        drop(requests);
        self.deliver_replies(store, vec![(pending, response)]);
    }

    fn fail_questions(&self, store: &Store, origin: Option<Origin>) {
        let mut requests = self.questions.lock().expect("not poisoned");
        if let Some(origin) = origin
            && requests
                .connections
                .get(origin.agent)
                .is_some_and(|value| value == origin.connection)
        {
            requests.connections.remove(origin.agent);
        }
        let keys: Vec<_> = requests
            .pending
            .iter()
            .filter(|(_, p)| match origin {
                Some(origin) => p.agent == origin.agent && p.connection == origin.connection,
                None => p.started.elapsed() >= TIMEOUT,
            })
            .map(|(key, _)| key.clone())
            .collect();
        let mut replies = Vec::new();
        for key in keys {
            let pending = requests.pending.remove(&key).expect("looked up");
            let response = ToDevice::Error(failure(
                pending.original.clone(),
                ErrorCode::Unconfirmed,
                "The answer was not confirmed. The outcome may be unknown; review this question before answering again.",
            ));
            remember(&mut requests, key, &pending, response.clone());
            replies.push((pending, response));
        }
        drop(requests);
        self.deliver_replies(store, replies);
    }

    pub(super) fn question_disconnected(&self, store: &Store, origin: Origin) {
        self.fail_questions(store, Some(origin));
    }

    /// Times out answers in flight, and, once a [`SWEEP`], expires pending
    /// questions no channel can answer: an agent enclos no longer serves,
    /// or one whose channel stayed away longer than
    /// [`UNCONNECTED_LIFETIME_SECONDS`].
    pub(super) fn expire_questions(&self, store: &Store) {
        self.fail_questions(store, None);
        let connected: HashSet<String> = {
            let mut requests = self.questions.lock().expect("not poisoned");
            if requests.swept.is_some_and(|at| at.elapsed() < SWEEP) {
                return;
            }
            requests.swept = Some(Instant::now());
            requests.connections.keys().cloned().collect()
        };
        let cutoff = now() - UNCONNECTED_LIFETIME_SECONDS;
        for (agent, id, asked) in store.pending_questions_by_age().unwrap_or_default() {
            let served = self.agents.iter().any(|a| a.name == agent);
            if !served || (!connected.contains(&agent) && asked < cutoff) {
                self.expire_question(store, &agent, &id);
            }
        }
    }
}

#[cfg(test)]
#[path = "question_tests.rs"]
mod tests;
