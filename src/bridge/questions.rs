//! Durable native questions and bounded, connection-fenced answer receipts.
use super::*;
use std::collections::VecDeque;
use std::time::Instant;

use super::super::store::{QuestionChange, QuestionStoreError, StoredQuestion};
use enclos_protocol::QuestionId;
use enclos_protocol::plugin::{ErrorBody, ErrorCode};
use enclos_protocol::question::{
    MAX_SYNC_QUESTIONS, QuestionAnswer, QuestionDefinition, QuestionState,
};
use sha2::{Digest, Sha256};

const MAX_PENDING: usize = 64;
const MAX_COMPLETED: usize = 128;
const TIMEOUT: Duration = Duration::from_secs(25);
const FRAME_BUDGET: usize = 60 * 1024;

#[derive(Clone, PartialEq, Eq)]
struct Request {
    question: QuestionId,
    revision: u64,
    answer: QuestionAnswer,
}

struct Pending {
    device: String,
    person: String,
    agent: String,
    connection: String,
    original: MessageId,
    request: Request,
    started: Instant,
}

#[derive(Default)]
pub(super) struct QuestionRequests {
    connections: HashMap<String, String>,
    pending: HashMap<String, Pending>,
    // Keep ambiguous outcomes too: replaying a device packet must never resend an answer.
    completed: VecDeque<(String, Request, ToDevice)>,
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

/// Whether a character is whitespace to Python's `str.split` and `lstrip`,
/// which Hermes parses commands with: Unicode's whitespace and also the
/// separators U+001C to U+001F, which Rust's `char::is_whitespace` is not.
fn python_space(c: char) -> bool {
    c.is_whitespace() || ('\u{1C}'..='\u{1F}').contains(&c)
}

/// Whether a runtime reads `text` as one of its commands that decide or
/// skip approvals: `/approve`, `/deny`, `/yolo` (no approval for the rest
/// of the session) or `/approvals` (sets the approval mode, `off`
/// included), in any case, with or without arguments or an `@name` suffix,
/// after any leading `@image:`, `@file:` or `@url:` lines (Hermes's own
/// parsing of a command message, `MessageEvent.get_command`). The channel
/// checks again with Hermes's own parser and aliases (`message.in`'s
/// `host`); this is the bridge's own line, for a channel that does not.
pub(super) fn typed_approval(text: &str) -> bool {
    let mut rest = text.trim_start_matches(python_space);
    while ["@image:", "@file:", "@url:"].iter().any(|prefix| {
        rest.get(..prefix.len())
            .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
    }) {
        rest = rest.split_once('\n').map_or("", |(_, after)| after);
        rest = rest.trim_start_matches(python_space);
    }
    let Some(name) = rest
        .split(python_space)
        .find(|word| !word.is_empty())
        .and_then(|word| word.strip_prefix('/'))
    else {
        return false;
    };
    let name = name.to_lowercase();
    matches!(
        name.split('@').next(),
        Some("approve" | "deny" | "yolo" | "approvals")
    )
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

fn canonical_answer(mut answer: QuestionAnswer) -> QuestionAnswer {
    if let QuestionAnswer::Choices { indices } = &mut answer {
        indices.sort_unstable();
    }
    answer
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
                // The channel denies such a runtime approval at once.
                QuestionStoreError::NotAllowed(_) => ErrorCode::NotAllowed,
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
    /// Whether `person`'s `text` is a typed runtime approval the bridge must
    /// not pass on: only the host's person decides runtime approvals, typed
    /// or through the app's controls, and an unknown host decides none.
    pub(super) fn refuses_typed_approval(&self, person: &str, text: &str) -> bool {
        typed_approval(text) && self.host.as_deref() != Some(person)
    }

    /// Whether `person`'s devices get `definition`'s structured metadata. A
    /// runtime approval's controls are the host's person's alone; anyone else
    /// reads its history text, which says who can answer it.
    pub(super) fn shows_question(&self, person: &str, definition: &QuestionDefinition) -> bool {
        definition.approval.is_none() || self.host.as_deref() == Some(person)
    }

    /// A channel connected. One without the `runtime_approvals` capability
    /// cannot answer the runtime approvals it left (a runtime that lost the
    /// native API, or one replaced): they expire now, rather than stay on
    /// the host's person's devices with nothing to answer them.
    pub(super) fn question_connected(
        &self,
        store: Option<&Store>,
        agent: &str,
        connection: &str,
        capabilities: &[Capability],
    ) {
        self.questions
            .lock()
            .expect("not poisoned")
            .connections
            .insert(agent.into(), connection.into());
        if capabilities.contains(&Capability::RuntimeApprovals) {
            return;
        }
        let Some(store) = store else { return };
        for id in store.pending_approvals(agent).unwrap_or_default() {
            let Ok(message) = new_id() else { return };
            match store.settle_question(agent, &id, QuestionState::Expired, None, &message) {
                Ok(change) => self.publish_question(store, change),
                Err(error) => {
                    eprintln!("enclos app: could not expire runtime approval {id}: {error}")
                }
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

    pub(super) fn question_ask(
        &self,
        store: &Store,
        agent: &str,
        connection: &str,
        conversation: &ConversationId,
        question: &QuestionDefinition,
        id: &MessageId,
    ) -> Result<(), QuestionStoreError> {
        if question.approval.is_some()
            && !self
                .plugins
                .lock()
                .expect("not poisoned")
                .get(agent)
                .is_some_and(|(_, capabilities)| {
                    capabilities.contains(&Capability::RuntimeApprovals)
                })
        {
            return Err(QuestionStoreError::Invalid(
                "The runtime does not support native runtime approvals.".into(),
            ));
        }
        question.validate().map_err(QuestionStoreError::Invalid)?;
        // Refuse before persistence if a future fallback renderer exceeds the device frame,
        // with or without the typed commands the host's person sees.
        let introduction = |typed: bool| {
            ToDevice::Message(ConversationMessage {
                conversation: conversation.clone(),
                agent: agent.into(),
                from: "agent".into(),
                text: question.fallback_text(typed),
                kind: if question.approval.is_some() {
                    "runtime_approval"
                } else {
                    "question"
                }
                .into(),
                time: i64::MAX,
                seq: i64::MAX,
                attachments: vec![],
                question: Some(question.id.clone()),
            })
        };
        if !(bounded(&introduction(true)) && bounded(&introduction(false))) {
            return Err(QuestionStoreError::Invalid(
                "The readable question history exceeds the device frame limit.".into(),
            ));
        }
        let requests = self.questions.lock().expect("not poisoned");
        if !requests
            .connections
            .get(agent)
            .is_some_and(|current| current == connection)
        {
            return Err(QuestionStoreError::Invalid(
                "The question belongs to an old connection.".into(),
            ));
        }
        let change = store.ask_question(
            agent,
            conversation,
            question,
            id.as_str(),
            self.host.as_deref(),
        )?;
        drop(requests);
        self.publish_question(store, change);
        Ok(())
    }

    /// The only source of a successful device receipt is this matching native result.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn question_update(
        &self,
        store: &Store,
        agent: &str,
        connection: &str,
        question: &QuestionId,
        state: QuestionState,
        answer: Option<QuestionAnswer>,
        of: Option<&MessageId>,
        id: &MessageId,
    ) -> Result<(), QuestionStoreError> {
        let answer = answer.map(canonical_answer);
        let mut requests = self.questions.lock().expect("not poisoned");
        if !requests
            .connections
            .get(agent)
            .is_some_and(|current| current == connection)
        {
            return Err(QuestionStoreError::Invalid(
                "The question belongs to an old connection.".into(),
            ));
        }
        if let Some(pending) = of.and_then(|id| requests.pending.get(id.as_str()))
            && (pending.agent != agent
                || pending.connection != connection
                || pending.request.question != *question)
        {
            return Err(QuestionStoreError::Invalid(
                "The native question receipt does not match its request.".into(),
            ));
        }
        // Only the settlement of the device request it names, as that request
        // asked, is the person's: anything else is the agent's report.
        let confirmed = of
            .and_then(|id| requests.pending.get(id.as_str()))
            .is_some_and(|pending| settles_as(&pending.request.answer, state, answer.as_ref()));
        let (change, conflict) = match store.settle_question_as(
            agent,
            question,
            state,
            answer,
            id.as_str(),
            confirmed,
        ) {
            Ok(change) => (change, false),
            Err(QuestionStoreError::Conflict) => {
                let current = store
                    .question(question)?
                    .filter(|q| q.info.agent == agent)
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
        let mut replies = Vec::new();
        if info.state.is_terminal() {
            let keys: Vec<_> = requests
                .pending
                .iter()
                .filter(|(_, pending)| {
                    pending.agent == agent && pending.request.question == *question
                })
                .map(|(key, _)| key.clone())
                .collect();
            for key in keys {
                let pending = requests.pending.get(&key).expect("looked up");
                let expected =
                    settles_as(&pending.request.answer, info.state, info.answer.as_ref());
                // A native watcher may publish before the resolving RPC returns. Its
                // broadcast updates the card but cannot confirm the matching answer.
                if of.is_none() && expected {
                    continue;
                }
                let pending = requests.pending.remove(&key).expect("looked up");
                let exact = !conflict
                    && of.is_some_and(|id| id.as_str() == key)
                    && pending.connection == connection
                    && expected;
                let response = if exact {
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
                remember(&mut requests, key, &pending, response.clone());
                replies.push((pending, response));
            }
        }
        drop(requests);
        // Metadata and history always precede the receipt, including the losing phone's state.
        self.publish_question(store, change);
        for (pending, response) in replies {
            self.deliver_question_device(
                store,
                &pending.device,
                &pending.person,
                question,
                response,
            );
        }
        Ok(())
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
            .filter(|question| {
                question.owner == person
                    && (question.info.definition.approval.is_none()
                        || self.host.as_deref() == Some(person))
            })
            .ok_or(())
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn question_answer(
        self: &Arc<Self>,
        store: &Store,
        device: &Device,
        person: &str,
        original: MessageId,
        question: QuestionId,
        revision: u64,
        answer: QuestionAnswer,
    ) -> Result<(), ErrorBody> {
        let current = self
            .question_authority(store, device, person, &question)
            .map_err(|_| failure(original.clone(), ErrorCode::NotFound, "No such question."))?;
        answer
            .validate(&current.info.definition)
            .map_err(|e| failure(original.clone(), ErrorCode::BadMessage, e))?;
        let request = Request {
            question,
            revision,
            answer: canonical_answer(answer),
        };
        let rpc = rpc_id(&device.id, person, &original);
        // A live writer and its epoch are held through registration and send. No offline queue or reconnect retry.
        let mut plugins = self.plugins.lock().expect("not poisoned");
        let mut requests = self.questions.lock().expect("not poisoned");
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
        let current = self
            .question_authority(store, device, person, &request.question)
            .map_err(|_| failure(original.clone(), ErrorCode::NotFound, "No such question."))?;
        if current.info.state != QuestionState::Pending || current.info.revision != revision {
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
        let Some((writer, capabilities)) = plugins.get_mut(&current.info.agent) else {
            return Err(failure(
                original,
                ErrorCode::AgentUnavailable,
                "The agent is disconnected. Reconnect and review this question before answering.",
            ));
        };
        let capability = if current.info.definition.approval.is_some() {
            Capability::RuntimeApprovals
        } else {
            Capability::Questions
        };
        if !capabilities.contains(&capability) {
            return Err(failure(
                original,
                ErrorCode::Unsupported,
                "This runtime does not support native app answers.",
            ));
        }
        if requests.pending.len() >= MAX_PENDING {
            return Err(failure(
                original,
                ErrorCode::AgentUnavailable,
                "Too many question answers are in progress. Try again shortly.",
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
                    "The agent is disconnected.",
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
                ErrorCode::AgentUnavailable,
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
        let shown = self.shows_question(&current.owner, &current.info.definition);
        let devices = self.devices.lock().expect("not poisoned");
        for (device, (person, sender)) in devices.iter() {
            if person == &current.owner
                && paired
                    .iter()
                    .any(|d| d.id == *device && d.person == *person)
            {
                if shown {
                    let _ = sender.send(question.clone());
                }
                if let Some(message) = &message
                    && bounded(message)
                {
                    let _ = sender.send(message.clone());
                }
            }
        }
    }

    pub(super) fn question_error(
        &self,
        store: &Store,
        agent: &str,
        connection: &str,
        mut error: ErrorBody,
    ) {
        let Some(key) = error.of.as_ref().map(ToString::to_string) else {
            return;
        };
        let mut requests = self.questions.lock().expect("not poisoned");
        let Some(pending) = requests.pending.get(&key) else {
            return;
        };
        if pending.agent != agent || pending.connection != connection {
            return;
        }
        let pending = requests.pending.remove(&key).expect("looked up");
        error.of = Some(pending.original.clone());
        error.message = error.message.chars().take(1000).collect();
        let response = ToDevice::Error(error);
        remember(&mut requests, key, &pending, response.clone());
        drop(requests);
        self.deliver_question_device(
            store,
            &pending.device,
            &pending.person,
            &pending.request.question,
            response,
        );
    }

    fn fail_questions(&self, store: &Store, agent: Option<(&str, &str)>) {
        let mut requests = self.questions.lock().expect("not poisoned");
        if let Some((agent, connection)) = agent
            && requests
                .connections
                .get(agent)
                .is_some_and(|value| value == connection)
        {
            requests.connections.remove(agent);
        }
        let keys: Vec<_> = requests
            .pending
            .iter()
            .filter(|(_, p)| match agent {
                Some((agent, connection)) => p.agent == agent && p.connection == connection,
                None => p.started.elapsed() >= TIMEOUT,
            })
            .map(|(key, _)| key.clone())
            .collect();
        let mut replies = Vec::new();
        for key in keys {
            let pending = requests.pending.remove(&key).expect("looked up");
            let response = ToDevice::Error(failure(
                pending.original.clone(),
                ErrorCode::AgentUnavailable,
                "The answer was not confirmed. The outcome may be unknown; review this question before answering again.",
            ));
            remember(&mut requests, key, &pending, response.clone());
            replies.push((pending, response));
        }
        drop(requests);
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

    pub(super) fn question_disconnected(&self, store: &Store, agent: &str, connection: &str) {
        self.fail_questions(store, Some((agent, connection)));
    }
    pub(super) fn expire_questions(&self, store: &Store) {
        self.fail_questions(store, None);
    }
}

#[cfg(test)]
#[path = "question_tests.rs"]
mod tests;
