//! Held tasks (ADR 0066, proposed; `docs/protocol.md`, Held tasks): the
//! cards of a runtime's stopped background work, and the one control, a
//! resume from the host's person, passed live to the plugin and never
//! queued.
use super::*;
use std::collections::{HashSet, VecDeque};
use std::time::Instant;

use super::super::store::{HeldTaskChange, StoredHeldTask};
use enclos_protocol::held_task::{
    AnswerMessage, HeldTask, HeldTaskAnswer, HeldTaskInfo, HeldTaskState, accept,
};
use enclos_protocol::plugin::{ErrorBody, ErrorCode};
use enclos_protocol::{HeldTaskId, HeldTaskRevision};
use sha2::{Digest, Sha256};

/// Resumes in flight, for all agents together.
const MAX_PENDING: usize = 64;
const MAX_COMPLETED: usize = 64;
/// How long a resume waits for the runtime's answer.
const TIMEOUT: Duration = Duration::from_secs(25);

const NOT_READ: &str =
    "The bridge could not read or write its database, so nothing was sent to the agent. Try again.";
const UNCONFIRMED: &str = "The agent may have resumed the task, but did not confirm it. Its card shows what happened after the next sync.";

/// What a device asked: resume `task` of `agent`, at card `revision`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ResumeRequest {
    pub agent: String,
    pub task: HeldTaskId,
    pub revision: u64,
}

struct Pending {
    device: String,
    person: String,
    /// The asking device's pairing keys when it asked: its answer goes to
    /// that pairing alone.
    noise_key: Vec<u8>,
    device_key: Vec<u8>,
    connection: String,
    original: MessageId,
    request: ResumeRequest,
    /// The runtime's revision the resume was sent at.
    sent: HeldTaskRevision,
    started: Instant,
}

/// The device that asked for a resume, as it was paired when it asked.
#[derive(Clone, Copy)]
struct Asker<'a> {
    device: &'a str,
    person: &'a str,
    noise_key: &'a [u8],
    device_key: &'a [u8],
}

impl<'a> Asker<'a> {
    fn of(device: &'a Device, person: &'a str) -> Self {
        Asker {
            device: &device.id,
            person,
            noise_key: &device.noise_key,
            device_key: &device.device_key,
        }
    }
}

impl Pending {
    fn asker(&self) -> Asker<'_> {
        Asker {
            device: &self.device,
            person: &self.person,
            noise_key: &self.noise_key,
            device_key: &self.device_key,
        }
    }
}

#[derive(Default)]
pub(super) struct HeldTaskRequests {
    #[cfg(test)]
    before_open: Option<std::sync::Arc<(std::sync::Barrier, std::sync::Barrier)>>,
    /// Each agent's current plugin connection, as `held_task_connected` saw it.
    connections: HashMap<String, String>,
    pending: HashMap<String, Pending>,
    /// Answered resumes, unconfirmed ones included: a device that sends the
    /// same request again gets the same answer, and the runtime is not
    /// asked twice.
    completed: VecDeque<(String, ResumeRequest, ToDevice)>,
    /// Resumes that timed out, by plugin request id: a confirmation that
    /// comes late is still recorded.
    late: VecDeque<(String, Pending)>,
    /// Resumes the runtime confirmed that the bridge could not record yet:
    /// recorded at its next chance, so the card does not read as released.
    unrecorded: HashSet<(String, String, HeldTaskRevision)>,
    /// Agents whose channel connected without `held_tasks` and whose cards
    /// could not be expired then: tried again.
    expiring: HashSet<String>,
}

fn failure(of: MessageId, code: ErrorCode, message: impl Into<String>) -> ErrorBody {
    ErrorBody {
        of: Some(of),
        code,
        message: message.into(),
    }
}

/// The plugin request's id: the same for the same device, person and
/// request, so a replay finds it.
fn rpc_id(device: &str, person: &str, request: &MessageId) -> MessageId {
    let bytes = serde_json::to_vec(&(device, person, request.as_str())).expect("strings serialize");
    let digest = Sha256::digest(bytes);
    let suffix: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    MessageId::new(format!("held-{suffix}")).expect("bounded digest")
}

/// Records a resume in the bridge's log: once before it is sent, which
/// must succeed for it to be sent, and once with its outcome. The work
/// runs again, unattended, after the person's tap. Whether it was written.
fn audit(store: &Store, pending: &Pending, outcome: &str) -> bool {
    let reason = format!(
        "{} {} {outcome}",
        pending.request.agent, pending.request.task
    );
    match store.log(
        Some(&pending.device),
        Some(&pending.person),
        "held_task.resume",
        Some(&reason),
    ) {
        Ok(_) => true,
        Err(e) => {
            eprintln!(
                "enclos app: cannot log a held task's resume for {}: {e}",
                pending.request.agent
            );
            false
        }
    }
}

/// Records a held task's answer in the bridge's log (ADR 0073): once
/// before it is taken, which must succeed for it to be taken, then its
/// outcome (`taken`, `conflict`, `not sent`, `unknown`). Whether it was written.
fn log_answer(store: &Store, device: &str, person: &str, entry: &str) -> bool {
    match store.log(Some(device), Some(person), "held_task.answer", Some(entry)) {
        Ok(_) => true,
        Err(e) => {
            eprintln!("enclos app: cannot log a held task's answer ({entry}): {e}");
            false
        }
    }
}

fn code_name(code: ErrorCode) -> String {
    serde_json::to_value(code)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_default()
}

/// The whole answer to request `of` of a device that may not read what
/// became of the resume: fixed, with nothing of the card, the runtime or
/// whoever owns the card now.
fn notice(of: &MessageId) -> ToDevice {
    ToDevice::Error(failure(of.clone(), ErrorCode::Unconfirmed, UNCONFIRMED))
}

/// The current card owned by this person, regardless of changes to its revision.
pub(super) fn current_held_task(
    store: &Store,
    person: &str,
    request: &ResumeRequest,
) -> Result<StoredHeldTask, (ErrorCode, String)> {
    let card = store
        .held_task(&request.agent, request.task.as_str())
        .map_err(|e| {
            eprintln!(
                "enclos app: cannot read a held task of {}: {e}",
                request.agent
            );
            (ErrorCode::Internal, NOT_READ.to_owned())
        })?
        // Another person's and an unknown card read the same.
        .filter(|card| card.owner == person)
        .ok_or_else(|| (ErrorCode::NotFound, "No such held task.".to_owned()))?;
    // An answered card's task is still held by the runtime: its board and
    // details stay open to the person (ADR 0073). A resume or an answer
    // also needs the card to wait on the person (`waiting`).
    if !matches!(
        card.info.state,
        HeldTaskState::Held | HeldTaskState::Answered
    ) {
        return Err((ErrorCode::Conflict, CHANGED.into()));
    }
    Ok(card)
}

const CHANGED: &str = "The task changed since its card was shown. Refresh before deciding again.";

/// `card`, when it still waits on the person: `held`, not answered.
fn waiting(card: StoredHeldTask) -> Result<StoredHeldTask, (ErrorCode, String)> {
    if card.info.state == HeldTaskState::Held {
        Ok(card)
    } else {
        Err((ErrorCode::Conflict, CHANGED.into()))
    }
}

impl Hub {
    /// An agent's channel connected on `connection`. One without
    /// `held_tasks` can neither report nor resume: its held cards expire,
    /// now or, should that fail, at the next sweep.
    pub(super) fn held_task_connected(
        &self,
        store: Option<&Store>,
        agent: &str,
        connection: &str,
        capabilities: &[Capability],
    ) {
        let reports = capabilities.contains(&Capability::HeldTasks);
        {
            let mut requests = self.held_tasks.lock().expect("not poisoned");
            requests.connections.insert(agent.into(), connection.into());
            if reports {
                requests.expiring.remove(agent);
            } else {
                requests.expiring.insert(agent.into());
            }
        }
        if reports {
            return;
        }
        match store {
            Some(store) => self.expire_held(store, agent),
            None => eprintln!(
                "enclos app: {agent}'s held tasks expire once the bridge's database opens"
            ),
        }
    }

    /// Expires `agent`'s held cards, and stops trying once that worked.
    fn expire_held(&self, store: &Store, agent: &str) {
        match store.expire_held_tasks(agent) {
            Ok(changes) => {
                self.held_tasks
                    .lock()
                    .expect("not poisoned")
                    .expiring
                    .remove(agent);
                self.publish_held(store, changes);
            }
            Err(e) => eprintln!("enclos app: {agent}'s held tasks could not expire yet: {e}"),
        }
    }

    /// A plugin's `held_tasks`: every task its runtime holds now. Checked
    /// and cut by the bridge, stored as cards in the agent's Home, and the
    /// changes sent to the Home owner's devices. `Err` with the code to
    /// answer; nothing is stored then.
    pub(super) fn held_tasks_report(
        &self,
        store: &Store,
        agent: &str,
        tasks: Vec<HeldTask>,
    ) -> Result<(), (ErrorCode, String)> {
        let announced = self
            .plugins
            .lock()
            .expect("not poisoned")
            .get(agent)
            .is_some_and(|plugin| plugin.capabilities.contains(&Capability::HeldTasks));
        if !announced {
            return Err((
                ErrorCode::Unsupported,
                "Held tasks need the held_tasks capability in the plugin's hello.".into(),
            ));
        }
        let tasks = accept(tasks).map_err(|why| (ErrorCode::BadMessage, why))?;
        let internal = |e: rusqlite::Error| {
            eprintln!("enclos app: {agent}'s held tasks could not be stored: {e}");
            (
                ErrorCode::Internal,
                "The bridge could not store the held tasks.".to_owned(),
            )
        };
        // Forgotten (ADR 0067): no Home to hold a card until it is set up again.
        let home = store.home_of(agent).map_err(internal)?.ok_or_else(|| {
            (
                ErrorCode::NotAllowed,
                "This agent was forgotten on the host and has no Home.".to_owned(),
            )
        })?;
        let host = store.host_person().map_err(internal)?;
        // A Home not made would hide the cards from every device.
        store
            .ensure_home(agent, host.as_deref().unwrap_or(""), host.is_some())
            .map_err(internal)?;
        self.record_unrecorded(store, Some(agent));
        // The same lock linearizes capability updates with resume admission and dispatch.
        let admission = self.held_tasks.lock().expect("not poisoned");
        let changes = store
            .report_held_tasks(agent, &home, &tasks)
            .map_err(internal)?;
        drop(admission);
        self.publish_held(store, changes);
        Ok(())
    }

    /// Records the resumes the runtime confirmed and the bridge could not
    /// record then, those of `agent` or of every agent.
    fn record_unrecorded(&self, store: &Store, agent: Option<&str>) {
        let waiting: Vec<_> = self
            .held_tasks
            .lock()
            .expect("not poisoned")
            .unrecorded
            .iter()
            .filter(|(a, _, _)| agent.is_none_or(|agent| a == agent))
            .cloned()
            .collect();
        for key in waiting {
            let (agent, task, sent) = &key;
            match store.resume_held_task(agent, task, sent) {
                Ok(change) => {
                    self.held_tasks
                        .lock()
                        .expect("not poisoned")
                        .unrecorded
                        .remove(&key);
                    self.publish_held(store, change.into_iter().collect());
                }
                Err(e) => {
                    eprintln!("enclos app: {agent}'s resumed task {task} is not recorded yet: {e}")
                }
            }
        }
    }

    /// Sends each changed card, then its history message, to the paired
    /// devices of the person whose Home it is in.
    fn publish_held(&self, store: &Store, changes: Vec<HeldTaskChange>) {
        if changes.is_empty() {
            return;
        }
        let paired = match store.devices() {
            Ok(paired) => paired,
            Err(e) => {
                // Stored: the devices learn it at their next sync.
                eprintln!(
                    "enclos app: held tasks changed, but the paired devices could not be read: {e}"
                );
                return;
            }
        };
        let owners: std::collections::HashSet<_> =
            changes.iter().map(|c| c.card.owner.clone()).collect();
        for change in changes {
            let owner = change.card.owner.clone();
            if let Some(message) = &change.message
                && message.kind == "notify"
                && change.card.info.state == HeldTaskState::Held
            {
                self.push_if_away(
                    store,
                    &owner,
                    &change.card.info.agent,
                    change.card.info.conversation.as_str(),
                    message.seq,
                    &format!("Needs you: {}", change.card.info.title),
                );
            }
            let mut frames = vec![ToDevice::HeldTask {
                held_task: change.card.info,
            }];
            if let Some(message) = change.message {
                match message_frame(store, message) {
                    Ok(frame) => frames.push(frame),
                    Err(e) => eprintln!("enclos app: a held task's message could not be read: {e}"),
                }
            }
            frames.retain(|frame| {
                let fits = fits_device(frame);
                if !fits {
                    eprintln!(
                        "enclos app: a held task's frame is too large for a device: not sent"
                    );
                }
                fits
            });
            let devices = self.devices.lock().expect("not poisoned");
            for (device, (person, sender, _)) in devices.iter() {
                if *person == owner && paired.iter().any(|d| d.id == *device && d.person == owner) {
                    for frame in &frames {
                        let _ = sender.send(frame.clone());
                    }
                }
            }
        }
        for owner in owners {
            self.publish_open_items(store, &owner);
        }
    }

    /// The current held card, if this device may act on it at its reviewed revision.
    pub(super) fn held_task_authority(
        &self,
        store: &Store,
        device: &Device,
        person: &str,
        request: &ResumeRequest,
    ) -> Result<StoredHeldTask, (ErrorCode, String)> {
        self.host_authority(store, device, person)?;
        let card = current_held_task(store, person, request)?;
        if card.info.revision != request.revision {
            return Err((
                ErrorCode::Conflict,
                "The task changed since its card was shown. Refresh before deciding again.".into(),
            ));
        }
        Ok(card)
    }

    /// A device's `held_task.answer` (ADR 0073, proposed), checked as a
    /// resume is and taken: logged, then the card marked `answered`, at its
    /// revision, so the same answer is never taken twice, and sent to the
    /// person's devices. What the caller then sends the agent as the
    /// person's message, in the card's conversation, with the card as it
    /// now is. `Err` is the answer to send now, with nothing taken.
    pub(super) fn held_task_answer(
        &self,
        store: &Store,
        device: &Device,
        person: &str,
        original: &MessageId,
        request: &ResumeRequest,
        answer: &HeldTaskAnswer,
    ) -> Result<(ConversationId, AnswerMessage, HeldTaskInfo), ErrorBody> {
        let refuse = |code, why: &str| failure(original.clone(), code, why);
        let card = self
            .held_task_authority(store, device, person, request)
            .and_then(waiting)
            .map_err(|(code, why)| refuse(code, why.as_str()))?;
        let said = answer
            .message(&card.info)
            .map_err(|why| refuse(ErrorCode::BadMessage, why.as_str()))?;
        // A resume of this card on its way to the runtime: the person's
        // answer could tell the agent the opposite of what is running.
        let resuming = self
            .held_tasks
            .lock()
            .expect("not poisoned")
            .pending
            .values()
            .any(|p| p.request.agent == request.agent && p.request.task == request.task);
        if resuming {
            return Err(refuse(
                ErrorCode::Conflict,
                "A resume of this task is in progress. Refresh before answering.",
            ));
        }
        // The answer goes in the card's conversation as the person's
        // message: one that could not take it is said now, not taken.
        let conversation = card.info.conversation.as_str();
        let usable = store.conversation_of(conversation).and_then(|found| {
            Ok(found.is_some_and(|(_, _, owner)| owner == person)
                && !store.deletion_started(conversation)?)
        });
        match usable {
            Ok(true) => {}
            Ok(false) => {
                return Err(refuse(
                    ErrorCode::Conflict,
                    "The agent's Home cannot take a message now. Nothing was sent.",
                ));
            }
            Err(e) => {
                eprintln!(
                    "enclos app: cannot read a held task's conversation for {}: {e}",
                    request.agent
                );
                return Err(refuse(ErrorCode::Internal, NOT_READ));
            }
        }
        // No answer the log cannot name: the agent would act on it with no
        // record of who answered.
        let entry = format!("{} {} {}", request.agent, request.task, answer.kind());
        if !log_answer(store, &device.id, person, &entry) {
            return Err(refuse(ErrorCode::Internal, NOT_READ));
        }
        let taken = store
            .answer_held_task(
                &request.agent,
                request.task.as_str(),
                request.revision,
                &said.answer,
            )
            .map_err(|e| {
                eprintln!(
                    "enclos app: cannot record a held task's answer for {}: {e}",
                    request.agent
                );
                log_answer(store, &device.id, person, &format!("{entry} unknown"));
                refuse(ErrorCode::Internal, NOT_READ)
            })?;
        let Some(change) = taken else {
            log_answer(store, &device.id, person, &format!("{entry} conflict"));
            return Err(refuse(ErrorCode::Conflict, CHANGED));
        };
        log_answer(store, &device.id, person, &format!("{entry} taken"));
        let info = change.card.info.clone();
        self.publish_held(store, vec![change]);
        Ok((card.info.conversation, said, info))
    }

    /// The person's message answering `request`'s card could not be stored
    /// or given to the agent: the card, still answered with `answer`, is
    /// held again, so the person can answer once more; logged as not sent.
    pub(super) fn held_task_unanswered(
        &self,
        store: &Store,
        device: &Device,
        person: &str,
        request: &ResumeRequest,
        kind: &str,
        answer: &str,
    ) {
        log_answer(
            store,
            &device.id,
            person,
            &format!("{} {} {kind} not sent", request.agent, request.task),
        );
        match store.unanswer_held_task(&request.agent, request.task.as_str(), answer) {
            Ok(Some(change)) => self.publish_held(store, vec![change]),
            Ok(None) => {}
            Err(e) => eprintln!(
                "enclos app: cannot hold again a held task whose answer was not sent, of {}: {e}",
                request.agent
            ),
        }
    }

    /// A device's `held_task.resume`. `Err` is the answer to send now,
    /// with nothing sent to the plugin; `Ok` once the plugin was sent the
    /// resume (its answer comes later) or a replay was answered.
    pub(super) fn held_task_resume(
        self: &Arc<Self>,
        store: &Store,
        device: &Device,
        person: &str,
        original: MessageId,
        request: ResumeRequest,
    ) -> Result<(), ErrorBody> {
        let rpc = rpc_id(&device.id, person, &original);
        {
            let requests = self.held_tasks.lock().expect("not poisoned");
            if let Some(answer) = self.replayed(&requests, &rpc, &request, &original)? {
                drop(requests);
                let asker = Asker::of(device, person);
                self.deliver_held_device(store, &asker, &request, &original, answer);
                return Ok(());
            }
            if requests.pending.contains_key(rpc.as_str()) {
                return Ok(());
            }
        }
        let card = self
            .held_task_authority(store, device, person, &request)
            .and_then(waiting)
            .map_err(|(code, why)| failure(original.clone(), code, why))?;
        // Said only to whoever may resume the card as it is, and before the
        // channel is opened: the runtime is not asked.
        if !card.info.resumable {
            return Err(failure(
                original,
                ErrorCode::Unsupported,
                "This task cannot be resumed from the app. Nothing was sent.",
            ));
        }
        #[cfg(test)]
        {
            let checkpoint = self
                .held_tasks
                .lock()
                .expect("not poisoned")
                .before_open
                .take();
            if let Some(checkpoint) = checkpoint {
                checkpoint.0.wait();
                checkpoint.1.wait();
            }
        }
        let requester = Person::new(person)
            .map_err(|e| failure(original.clone(), ErrorCode::BadMessage, e.to_string()))?;
        // Opened if it is not: a resume is live, but the connection may
        // simply not be open yet.
        let opened = self.plugin(&request.agent);
        let found = {
            let plugins = self.plugins.lock().expect("not poisoned");
            plugins.get(&request.agent).map(|plugin| {
                (
                    Arc::clone(&plugin.out),
                    plugin.capabilities.contains(&Capability::HeldTasks),
                )
            })
        };
        let out = match found {
            Some((out, true)) => out,
            Some((_, false)) => {
                return Err(failure(
                    original,
                    ErrorCode::Unsupported,
                    "The agent's channel does not report held tasks. Nothing was sent.",
                ));
            }
            None => {
                let why = opened.err().unwrap_or_else(|| "it closed".into());
                return Err(failure(
                    original,
                    ErrorCode::AgentUnavailable,
                    format!("The agent's channel cannot be reached ({why}). Nothing was sent."),
                ));
            }
        };
        let mut requests = self.held_tasks.lock().expect("not poisoned");
        // Another device thread may have claimed the same id meanwhile.
        if let Some(answer) = self.replayed(&requests, &rpc, &request, &original)? {
            drop(requests);
            let asker = Asker::of(device, person);
            self.deliver_held_device(store, &asker, &request, &original, answer);
            return Ok(());
        }
        if requests.pending.contains_key(rpc.as_str()) {
            return Ok(());
        }
        if requests.pending.len() >= MAX_PENDING {
            return Err(failure(
                original,
                ErrorCode::AgentUnavailable,
                "Too many resumes are in progress. Nothing was sent; try again shortly.",
            ));
        }
        let connection = requests
            .connections
            .get(&request.agent)
            .cloned()
            .ok_or_else(|| {
                failure(
                    original.clone(),
                    ErrorCode::AgentUnavailable,
                    "The agent's channel is disconnected. Nothing was sent.",
                )
            })?;
        // Opening a channel may have taken time. Read authority again under the
        // lock that reports hold through their store write, and retain it through
        // admission/audit and the actual send: no accepted revocation can slip in.
        let card = self
            .held_task_authority(store, device, person, &request)
            .and_then(waiting)
            .map_err(|(code, why)| failure(original.clone(), code, why))?;
        if !card.info.resumable {
            return Err(failure(
                original,
                ErrorCode::Unsupported,
                "This task cannot be resumed from the app. Nothing was sent.",
            ));
        }
        let pending = Pending {
            device: device.id.clone(),
            person: person.into(),
            noise_key: device.noise_key.clone(),
            device_key: device.device_key.clone(),
            connection,
            original: original.clone(),
            request: request.clone(),
            sent: card.runtime_revision.clone(),
            started: Instant::now(),
        };
        // No resume the log cannot name: the runtime would change with no
        // record of who asked.
        if !audit(store, &pending, "requested") {
            return Err(failure(original, ErrorCode::Internal, NOT_READ));
        }
        requests.pending.insert(rpc.to_string(), pending);
        let sent = out.lock().expect("not poisoned").writer.send_with_id(
            rpc.clone(),
            FromBridge::HeldTaskResume {
                task: request.task.clone(),
                revision: card.runtime_revision,
                person: requester,
                device: device.id.clone(),
            },
        );
        drop(requests);
        if let Err(e) = sent {
            let taken = self.take_pending(&request.agent, None, &rpc);
            if let Some((key, pending)) = taken {
                audit(store, &pending, "unknown: not sent");
                let answer = ToDevice::Error(failure(
                    original,
                    ErrorCode::Unconfirmed,
                    format!("{e}. {UNCONFIRMED}"),
                ));
                self.finish(store, key, &pending, answer);
            }
        }
        Ok(())
    }

    /// The answer kept for a device that sends request `original` again:
    /// `Err(conflict)` when the same id names another resume.
    fn replayed(
        &self,
        requests: &HeldTaskRequests,
        rpc: &MessageId,
        request: &ResumeRequest,
        original: &MessageId,
    ) -> Result<Option<ToDevice>, ErrorBody> {
        let other = || {
            failure(
                original.clone(),
                ErrorCode::Conflict,
                "This request id names another resume.",
            )
        };
        if let Some(pending) = requests.pending.get(rpc.as_str())
            && pending.request != *request
        {
            return Err(other());
        }
        match requests
            .completed
            .iter()
            .find(|(key, _, _)| key == rpc.as_str())
        {
            Some((_, done, _)) if done != request => Err(other()),
            Some((_, _, answer)) => Ok(Some(answer.clone())),
            None => Ok(None),
        }
    }

    /// What the device that asked may be sent of a resume's answer to its
    /// request `original`: nothing when the device is no longer paired to
    /// its person with the keys it asked with; all of it while its person
    /// is the host's and the card still theirs; otherwise, or when any of
    /// these cannot be read, only the fixed [`notice`].
    fn vetted(
        &self,
        store: &Store,
        asker: &Asker,
        request: &ResumeRequest,
        original: &MessageId,
        answer: ToDevice,
    ) -> Option<ToDevice> {
        let Asker {
            device,
            person,
            noise_key,
            device_key,
        } = *asker;
        match store.device(device) {
            Ok(paired) => {
                if !paired.is_some_and(|d| {
                    d.person == person && d.noise_key == noise_key && d.device_key == device_key
                }) {
                    return None;
                }
            }
            // The connection it asked on, which the bridge authenticated and
            // checks again before it sends anything, may still be told the
            // outcome is not confirmed, never what it was.
            Err(e) => {
                eprintln!("enclos app: cannot read the paired devices to answer {device}: {e}");
                return Some(notice(original));
            }
        }
        let host = match store.host_person() {
            Ok(host) => host.as_deref() == Some(person),
            Err(e) => {
                eprintln!("enclos app: cannot read the host's person to answer {device}: {e}");
                false
            }
        };
        let theirs = host
            && match store.held_task(&request.agent, request.task.as_str()) {
                Ok(card) => card.is_some_and(|card| card.owner == person),
                Err(e) => {
                    eprintln!(
                        "enclos app: cannot read a held task of {} to answer {device}: {e}",
                        request.agent
                    );
                    false
                }
            };
        Some(if theirs { answer } else { notice(original) })
    }

    /// Sends what [`Self::vetted`] allows of a resume's answer to the
    /// device that asked, on its live connection, if it has one.
    fn deliver_held_device(
        &self,
        store: &Store,
        asker: &Asker,
        request: &ResumeRequest,
        original: &MessageId,
        answer: ToDevice,
    ) {
        if let Some(answer) = self.vetted(store, asker, request, original, answer) {
            self.send_held_device(asker.device, asker.person, answer);
        }
    }

    fn send_held_device(&self, device: &str, person: &str, answer: ToDevice) {
        if let Some((owner, sender, _)) = self.devices.lock().expect("not poisoned").get(device)
            && owner == person
        {
            let _ = sender.send(answer);
        }
    }

    /// Ends `pending` with `answer`: what may be sent of it is kept as the
    /// answer to a replay, the notice alone when nothing may, then sent.
    fn finish(&self, store: &Store, key: String, pending: &Pending, answer: ToDevice) {
        let vetted = self.vetted(
            store,
            &pending.asker(),
            &pending.request,
            &pending.original,
            answer,
        );
        let kept = vetted.clone().unwrap_or_else(|| notice(&pending.original));
        self.complete(key, pending, &kept);
        if let Some(answer) = vetted {
            self.send_held_device(&pending.device, &pending.person, answer);
        }
    }

    /// Takes the pending resume `of` names, if it was sent to `agent` (on
    /// `connection`, when given).
    fn take_pending(
        &self,
        agent: &str,
        connection: Option<&str>,
        of: &MessageId,
    ) -> Option<(String, Pending)> {
        let mut requests = self.held_tasks.lock().expect("not poisoned");
        let ours = requests.pending.get(of.as_str()).is_some_and(|p| {
            p.request.agent == agent && connection.is_none_or(|c| p.connection == c)
        });
        if !ours {
            return None;
        }
        let pending = requests.pending.remove(of.as_str())?;
        Some((of.to_string(), pending))
    }

    fn complete(&self, key: String, pending: &Pending, answer: &ToDevice) {
        let mut requests = self.held_tasks.lock().expect("not poisoned");
        requests
            .completed
            .push_back((key, pending.request.clone(), answer.clone()));
        while requests.completed.len() > MAX_COMPLETED {
            requests.completed.pop_front();
        }
    }

    /// Records a resume the runtime confirmed: the card, `resumed`, and
    /// its line to the person's devices. The card as the devices should
    /// read it, `None` when it cannot be read. When the store cannot be
    /// written, the resume is remembered and recorded at the next chance,
    /// and the card read as resumed meanwhile.
    fn record_resume(&self, store: &Store, agent: &str, pending: &Pending) -> Option<HeldTaskInfo> {
        let task = pending.request.task.as_str();
        match store.resume_held_task(agent, task, &pending.sent) {
            // Sent to its owner's devices, whoever that is now; the asking
            // person reads it only if it is still theirs.
            Ok(Some(change)) => {
                let card = (change.card.owner == pending.person).then(|| change.card.info.clone());
                self.publish_held(store, vec![change]);
                card
            }
            // Resumed already, or held again since: the card as it is, if
            // it is still the asking person's.
            Ok(None) => store
                .held_task(agent, task)
                .ok()
                .flatten()
                .filter(|c| c.owner == pending.person)
                .map(|c| c.info),
            Err(e) => {
                eprintln!(
                    "enclos app: {agent}'s resumed task {task} could not be recorded yet: {e}"
                );
                self.held_tasks
                    .lock()
                    .expect("not poisoned")
                    .unrecorded
                    .insert((agent.into(), task.into(), pending.sent.clone()));
                store
                    .held_task(agent, task)
                    .ok()
                    .flatten()
                    .filter(|c| c.owner == pending.person)
                    .map(|c| {
                        let mut info = c.info;
                        info.state = HeldTaskState::Resumed;
                        info.revision += 1;
                        info
                    })
            }
        }
    }

    /// The plugin's `held_task.resumed`: the runtime resumed the task.
    pub(super) fn held_task_resumed(
        &self,
        store: &Store,
        agent: &str,
        connection: &str,
        of: &MessageId,
    ) {
        let Some((key, pending)) = self.take_pending(agent, Some(connection), of) else {
            self.late_resumed(store, agent, connection, of);
            return;
        };
        audit(store, &pending, "confirmed");
        let answer = match self.record_resume(store, agent, &pending) {
            Some(held_task) => ToDevice::HeldTaskResult {
                of: pending.original.clone(),
                held_task,
            },
            None => notice(&pending.original),
        };
        self.finish(store, key, &pending, answer);
    }

    /// A confirmation that came after the resume timed out: the device was
    /// told `unconfirmed`; the card and the log still say what happened.
    fn late_resumed(&self, store: &Store, agent: &str, connection: &str, of: &MessageId) {
        let late = {
            let mut requests = self.held_tasks.lock().expect("not poisoned");
            let found = requests.late.iter().position(|(key, p)| {
                key == of.as_str() && p.request.agent == agent && p.connection == connection
            });
            found.and_then(|n| requests.late.remove(n))
        };
        let Some((_, pending)) = late else { return };
        eprintln!(
            "enclos app: {agent} confirmed the resume of {} after it timed out",
            pending.request.task
        );
        audit(store, &pending, "confirmed late");
        self.record_resume(store, agent, &pending);
    }

    /// A plugin's `error` naming a resume: passed on to the device with its
    /// code, its message bounded. Whether it named one.
    pub(super) fn held_task_error(
        &self,
        store: &Store,
        agent: &str,
        connection: &str,
        error: &ErrorBody,
    ) -> bool {
        let Some(of) = &error.of else { return false };
        let Some((key, pending)) = self.take_pending(agent, Some(connection), of) else {
            return false;
        };
        audit(
            store,
            &pending,
            &format!("answered {}", code_name(error.code)),
        );
        let answer = ToDevice::Error(ErrorBody {
            of: Some(pending.original.clone()),
            code: error.code,
            message: error.message.chars().take(1000).collect(),
        });
        self.finish(store, key, &pending, answer);
        true
    }

    /// Ends `pending` as unconfirmed: logged, kept as the answer to a
    /// replay, and told to the device.
    fn unconfirmed(&self, store: &Store, key: String, pending: &Pending, outcome: &str, why: &str) {
        audit(store, pending, outcome);
        let answer = ToDevice::Error(failure(
            pending.original.clone(),
            ErrorCode::Unconfirmed,
            format!("{why} {UNCONFIRMED}"),
        ));
        self.finish(store, key, pending, answer);
    }

    /// The agent's channel closed: a resume sent on it may have run.
    pub(super) fn held_task_disconnected(&self, store: &Store, agent: &str, connection: &str) {
        let mut requests = self.held_tasks.lock().expect("not poisoned");
        if requests
            .connections
            .get(agent)
            .is_some_and(|c| c == connection)
        {
            requests.connections.remove(agent);
        }
        let keys: Vec<_> = requests
            .pending
            .iter()
            .filter(|(_, p)| p.request.agent == agent && p.connection == connection)
            .map(|(k, _)| k.clone())
            .collect();
        let pending: Vec<_> = keys
            .into_iter()
            .filter_map(|k| requests.pending.remove(&k).map(|p| (k, p)))
            .collect();
        drop(requests);
        for (key, p) in pending {
            self.unconfirmed(
                store,
                key,
                &p,
                "unknown: disconnected",
                "The agent disconnected.",
            );
        }
    }

    /// Every second: ends the resumes the runtime left unanswered, and
    /// tries again what could not be done when it should have been
    /// (expiring an agent's cards, recording a confirmed resume).
    pub(super) fn expire_held_resumes(&self, store: &Store) {
        let mut requests = self.held_tasks.lock().expect("not poisoned");
        let keys: Vec<_> = requests
            .pending
            .iter()
            .filter(|(_, p)| p.started.elapsed() >= TIMEOUT)
            .map(|(k, _)| k.clone())
            .collect();
        let pending: Vec<_> = keys
            .into_iter()
            .filter_map(|k| requests.pending.remove(&k).map(|p| (k, p)))
            .collect();
        let expiring: Vec<String> = requests.expiring.iter().cloned().collect();
        let unrecorded = !requests.unrecorded.is_empty();
        drop(requests);
        for (key, p) in pending {
            self.unconfirmed(
                store,
                key.clone(),
                &p,
                "unknown: timed out",
                "The agent did not answer in time.",
            );
            let mut requests = self.held_tasks.lock().expect("not poisoned");
            requests.late.push_back((key, p));
            while requests.late.len() > MAX_COMPLETED {
                requests.late.pop_front();
            }
        }
        for agent in expiring {
            self.expire_held(store, &agent);
        }
        if unrecorded {
            self.record_unrecorded(store, None);
        }
    }
}

/// Answers a plugin's `held_tasks`: `ack` once stored, or the `error` that
/// says why not. The plugin keeps no copy; its next report replaces it.
pub(super) fn acknowledge_report(
    writer: &mut PluginWriter,
    id: &MessageId,
    result: Result<(), (ErrorCode, String)>,
) {
    let answer = match result {
        Ok(()) => FromBridge::Ack { of: id.clone() },
        Err((code, message)) => FromBridge::Error(ErrorBody {
            of: Some(id.clone()),
            code,
            message,
        }),
    };
    let _ = writer.send(answer);
}

#[cfg(test)]
mod tests {
    use super::*;
    use enclos_protocol::held_task::HeldTaskInfo;
    use enclos_protocol::plugin::{decode_from_bridge, decode_from_plugin};
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::{UnixListener, UnixStream};

    const OWNER: &str = "owner@example.com";
    const GUEST: &str = "guest@example.com";
    const AGENT: &str = "lab/main";

    fn device(id: &str, person: &str) -> Device {
        Device {
            id: id.into(),
            name: id.into(),
            person: person.into(),
            noise_key: id.as_bytes().to_vec(),
            device_key: vec![],
            push_key: vec![],
            push_token: None,
            paired: now(),
            seen: None,
            node: None,
        }
    }

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
        let phone = device("phone", OWNER);
        store.add_device(&phone).unwrap();
        store.ensure_home(AGENT, OWNER, true).unwrap();
        let (tx, rx) = channel();
        hub.devices
            .lock()
            .unwrap()
            .insert(phone.id.clone(), (OWNER.into(), tx, 1));
        (dir, hub, store, phone, rx)
    }

    fn task(id: &str) -> HeldTask {
        HeldTask {
            task: HeldTaskId::new(id).unwrap(),
            title: format!("Task {id}"),
            assignee: None,
            reason: "Gave up after 3 failures".into(),
            last_error: None,
            since: 1_763_000_000,
            revision: HeldTaskRevision::new("e:7").unwrap(),
            resume: "Runs it again with a fresh retry budget.".into(),
            resumable: true,
            ask: None,
        }
    }

    /// A plugin on the agent's socket that announces `capabilities`: what
    /// the bridge sends it comes on the receiver; the stream writes to it.
    fn fake_plugin(
        hub: &Arc<Hub>,
        capabilities: Vec<Capability>,
    ) -> (UnixStream, Receiver<Envelope<FromBridge>>) {
        let listener = UnixListener::bind(&hub.agents()[0].socket).unwrap();
        let (frames, received) = channel();
        let accepted = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut writer = stream.try_clone().unwrap();
            let mut reader = BufReader::new(stream);
            let mut line = Vec::new();
            reader.read_until(b'\n', &mut line).unwrap();
            writer
                .write_all(&encode_line(&Envelope::new(
                    MessageId::new("hello").unwrap(),
                    FromPlugin::Hello {
                        runtime: "hermes".into(),
                        agent: "main".into(),
                        capabilities,
                    },
                )))
                .unwrap();
            std::thread::spawn(move || {
                loop {
                    line.clear();
                    match reader.read_until(b'\n', &mut line) {
                        Ok(0) | Err(_) => break,
                        Ok(_) => {}
                    }
                    if let Ok(frame) = decode_from_bridge(&line) {
                        let _ = frames.send(frame);
                    }
                }
            });
            writer
        });
        hub.plugin(AGENT).unwrap();
        (accepted.join().unwrap(), received)
    }

    fn say(writer: &mut UnixStream, id: &str, body: FromPlugin) {
        writer
            .write_all(&encode_line(&Envelope::new(
                MessageId::new(id).unwrap(),
                body,
            )))
            .unwrap();
    }

    fn next(rx: &Receiver<ToDevice>) -> ToDevice {
        rx.recv_timeout(Duration::from_secs(5))
            .expect("a frame for the device")
    }

    fn card(frame: ToDevice) -> HeldTaskInfo {
        match frame {
            ToDevice::HeldTask { held_task } => held_task,
            other => panic!("a held task's card, not {other:?}"),
        }
    }

    fn plugin_frame(rx: &Receiver<Envelope<FromBridge>>) -> Envelope<FromBridge> {
        rx.recv_timeout(Duration::from_secs(5))
            .expect("a frame for the plugin")
    }

    fn resume(task: &str, revision: u64) -> ResumeRequest {
        ResumeRequest {
            agent: AGENT.into(),
            task: HeldTaskId::new(task).unwrap(),
            revision,
        }
    }

    fn resume_lines(store: &Store) -> Vec<String> {
        store
            .log_lines(100)
            .unwrap()
            .into_iter()
            .filter(|l| l.event == "held_task.resume")
            .map(|l| {
                assert_eq!(l.device.as_deref(), Some("phone"));
                assert_eq!(l.person.as_deref(), Some(OWNER));
                l.reason.unwrap()
            })
            .collect()
    }

    /// A plugin with the capability, which reported `t1`; the report's
    /// ack and the card's two frames already read.
    fn reported(
        hub: &Arc<Hub>,
        rx: &Receiver<ToDevice>,
    ) -> (UnixStream, Receiver<Envelope<FromBridge>>) {
        let (mut plugin, from_bridge) = fake_plugin(hub, vec![Capability::HeldTasks]);
        say(
            &mut plugin,
            "report-1",
            FromPlugin::HeldTasks {
                tasks: vec![task("t1")],
            },
        );
        plugin_frame(&from_bridge);
        next(rx);
        next(rx);
        (plugin, from_bridge)
    }

    #[test]
    fn a_resume_revoked_while_opening_the_channel_has_no_admission_side_effects() {
        let (_dir, hub, store, phone, rx) = fixture();
        let (_plugin, from_bridge) = reported(&hub, &rx);
        let checkpoint = Arc::new((std::sync::Barrier::new(2), std::sync::Barrier::new(2)));
        hub.held_tasks.lock().unwrap().before_open = Some(Arc::clone(&checkpoint));
        let worker_hub = Arc::clone(&hub);
        let worker = std::thread::spawn(move || {
            let store = worker_hub.store().unwrap();
            worker_hub.held_task_resume(
                &store,
                &phone,
                OWNER,
                MessageId::new("revoked-before-admission").unwrap(),
                resume("t1", 0),
            )
        });
        checkpoint.0.wait();
        // The same opaque runtime hold gets a new bridge revision when capability
        // is revoked. An in-flight request must recheck it after opening.
        hub.held_tasks_report(&store, AGENT, vec![not_resumable("t1")])
            .unwrap();
        checkpoint.1.wait();
        let error = worker.join().unwrap().unwrap_err();
        assert_eq!(error.code, ErrorCode::Conflict);
        assert!(resume_lines(&store).is_empty());
        assert!(hub.held_tasks.lock().unwrap().pending.is_empty());
        assert!(
            from_bridge
                .try_iter()
                .all(|f| !matches!(f.body, FromBridge::HeldTaskResume { .. }))
        );
    }

    #[test]
    fn a_report_becomes_a_card_and_a_resume_reaches_the_runtime_once() {
        let (_dir, hub, store, phone, rx) = fixture();
        let (mut plugin, from_bridge) = fake_plugin(&hub, vec![Capability::HeldTasks]);
        say(
            &mut plugin,
            "report-1",
            FromPlugin::HeldTasks {
                tasks: vec![task("t1")],
            },
        );
        let FromBridge::Ack { of } = plugin_frame(&from_bridge).body else {
            panic!("the report is acknowledged");
        };
        assert_eq!(of.as_str(), "report-1");
        let held = card(next(&rx));
        assert_eq!(
            (held.state, held.revision, held.conversation.as_str()),
            (HeldTaskState::Held, 0, home_id(AGENT).as_str())
        );
        let ToDevice::Message(introduction) = next(&rx) else {
            panic!("the card's message");
        };
        assert_eq!(introduction.kind, "notify");
        assert_eq!(introduction.held_task, Some(HeldTaskId::new("t1").unwrap()));

        let original = MessageId::new("tap-1").unwrap();
        hub.held_task_resume(&store, &phone, OWNER, original.clone(), resume("t1", 0))
            .unwrap();
        let sent = plugin_frame(&from_bridge);
        assert_eq!(sent.id, rpc_id("phone", OWNER, &original));
        let FromBridge::HeldTaskResume {
            task,
            revision,
            person,
            device,
        } = sent.body
        else {
            panic!("a resume for the plugin");
        };
        assert_eq!(
            (
                task.as_str(),
                revision.as_str(),
                person.as_str(),
                device.as_str()
            ),
            ("t1", "e:7", OWNER, "phone"),
            "the runtime's own revision, and who asked as the bridge authenticated them"
        );
        say(
            &mut plugin,
            "resumed-1",
            FromPlugin::HeldTaskResumed { of: sent.id },
        );
        let resumed = card(next(&rx));
        assert_eq!(
            (resumed.state, resumed.revision),
            (HeldTaskState::Resumed, 1)
        );
        let ToDevice::Message(line) = next(&rx) else {
            panic!("the quiet line");
        };
        assert_eq!(
            (line.kind.as_str(), line.text.as_str()),
            ("status", "Resumed from the app: Task t1")
        );
        let answer = next(&rx);
        assert!(matches!(
            &answer,
            ToDevice::HeldTaskResult { of, held_task }
                if *of == original && held_task.state == HeldTaskState::Resumed
        ));
        // The same request again: the same answer, and the runtime is not
        // asked a second time.
        hub.held_task_resume(&store, &phone, OWNER, original.clone(), resume("t1", 0))
            .unwrap();
        assert_eq!(next(&rx), answer);
        assert!(
            from_bridge
                .recv_timeout(Duration::from_millis(300))
                .is_err()
        );
        // The same id for another resume is refused.
        let error = hub
            .held_task_resume(&store, &phone, OWNER, original, resume("t2", 0))
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::Conflict);
        assert_eq!(
            resume_lines(&store),
            ["lab/main t1 requested", "lab/main t1 confirmed"]
        );
    }

    #[test]
    fn only_the_hosts_person_resumes_a_held_card_at_its_revision() {
        let (_dir, hub, store, phone, _rx) = fixture();
        store
            .report_held_tasks(AGENT, &home_id(AGENT), &[task("t1")])
            .unwrap();
        let refused = |device: &Device, person: &str, request: ResumeRequest| {
            hub.held_task_resume(
                &store,
                device,
                person,
                MessageId::new("tap").unwrap(),
                request,
            )
            .unwrap_err()
            .code
        };
        let guest = device("guest-phone", GUEST);
        store.add_device(&guest).unwrap();
        assert_eq!(
            refused(&guest, GUEST, resume("t1", 0)),
            ErrorCode::NotAllowed
        );
        assert_eq!(refused(&phone, OWNER, resume("t1", 1)), ErrorCode::Conflict);
        assert_eq!(refused(&phone, OWNER, resume("t9", 0)), ErrorCode::NotFound);
        let elsewhere = ResumeRequest {
            agent: "lab/other".into(),
            ..resume("t1", 0)
        };
        assert_eq!(refused(&phone, OWNER, elsewhere), ErrorCode::NotFound);
        // No plugin listens: nothing can be sent.
        assert_eq!(
            refused(&phone, OWNER, resume("t1", 0)),
            ErrorCode::AgentUnavailable
        );
        // A device unpaired since it connected.
        store.remove_device(&phone.id).unwrap();
        assert_eq!(
            refused(&phone, OWNER, resume("t1", 0)),
            ErrorCode::NotAllowed
        );
        assert!(
            resume_lines(&store).is_empty(),
            "nothing was sent, nothing logged"
        );
    }

    /// ADR 0073: an answer is checked as a resume is, then logged and taken
    /// once, the card answered and sent to the person's devices; what the
    /// agent is sent reads on its own.
    #[test]
    fn only_the_hosts_person_answers_a_held_card_once_at_its_revision() {
        use enclos_protocol::held_task::HeldTaskAsk;
        let (_dir, hub, store, phone, rx) = fixture();
        let asked = HeldTask {
            ask: Some(HeldTaskAsk {
                decision: "Allow one more hour?".into(),
                blocked: "Both coding runs are used up.".into(),
                choices: vec!["Allow one fix".into(), "Keep paused".into()],
                recommended: Some(0),
                settled: false,
                asked: None,
            }),
            ..task("t1")
        };
        store
            .report_held_tasks(AGENT, &home_id(AGENT), &[asked])
            .unwrap();
        let answer = |device: &Device, person: &str, revision: u64, answer: HeldTaskAnswer| {
            hub.held_task_answer(
                &store,
                device,
                person,
                &MessageId::new("tap").unwrap(),
                &resume("t1", revision),
                &answer,
            )
        };
        let guest = device("guest-phone", GUEST);
        store.add_device(&guest).unwrap();
        let code = |result: Result<(ConversationId, AnswerMessage, HeldTaskInfo), ErrorBody>| {
            result.unwrap_err().code
        };
        assert_eq!(
            code(answer(&guest, GUEST, 0, HeldTaskAnswer::Agent)),
            ErrorCode::NotAllowed
        );
        assert_eq!(
            code(answer(&phone, OWNER, 1, HeldTaskAnswer::Agent)),
            ErrorCode::Conflict
        );
        assert_eq!(
            code(answer(
                &phone,
                OWNER,
                0,
                HeldTaskAnswer::Choice { index: 2 }
            )),
            ErrorCode::BadMessage
        );
        assert_eq!(
            code(answer(
                &phone,
                OWNER,
                0,
                HeldTaskAnswer::Text { text: " ".into() }
            )),
            ErrorCode::BadMessage
        );
        let lines = |store: &Store| {
            store
                .log_lines(100)
                .unwrap()
                .into_iter()
                .filter(|l| l.event == "held_task.answer")
                .map(|l| l.reason.unwrap())
                .collect::<Vec<_>>()
        };
        assert!(lines(&store).is_empty(), "nothing taken, nothing logged");

        let (conversation, said, card) =
            answer(&phone, OWNER, 0, HeldTaskAnswer::Choice { index: 0 }).unwrap();
        assert_eq!(conversation.as_str(), home_id(AGENT));
        assert_eq!(
            said.text,
            "About held task t1 \"Task t1\": Allow one more hour?\nMy answer: Allow one fix"
        );
        assert_eq!(card.state, HeldTaskState::Answered);
        assert_eq!(card.answer.as_deref(), Some("Allow one fix"));
        assert_eq!(
            lines(&store),
            ["lab/main t1 choice", "lab/main t1 choice taken"]
        );
        // The person's devices are sent the answered card.
        let sent = std::iter::from_fn(|| rx.try_recv().ok())
            .find_map(|frame| match frame {
                ToDevice::HeldTask { held_task } => Some(held_task),
                _ => None,
            })
            .unwrap();
        assert_eq!(sent.state, HeldTaskState::Answered);
        // Taken once: the same answer at the card's new revision is refused.
        assert_eq!(
            code(answer(&phone, OWNER, card.revision, HeldTaskAnswer::Agent)),
            ErrorCode::Conflict
        );
        // An answered card's board stays open: the runtime still holds it.
        assert!(
            hub.held_task_authority(&store, &phone, OWNER, &resume("t1", card.revision))
                .is_ok()
        );
        // An answer that could not be given holds the card again, logged.
        hub.held_task_unanswered(
            &store,
            &phone,
            OWNER,
            &resume("t1", card.revision),
            "choice",
            "Allow one fix",
        );
        let again = store.held_task(AGENT, "t1").unwrap().unwrap();
        assert_eq!(again.info.state, HeldTaskState::Held);
        assert_eq!(
            lines(&store).last().map(String::as_str),
            Some("lab/main t1 choice not sent")
        );
        // A resume of the card on its way: an answer is refused.
        hub.held_tasks.lock().unwrap().pending.insert(
            "held-x".into(),
            Pending {
                device: phone.id.clone(),
                person: OWNER.into(),
                noise_key: phone.noise_key.clone(),
                device_key: phone.device_key.clone(),
                connection: "c".into(),
                original: MessageId::new("tap-r").unwrap(),
                request: resume("t1", again.info.revision),
                sent: again.runtime_revision.clone(),
                started: Instant::now(),
            },
        );
        assert_eq!(
            code(answer(
                &phone,
                OWNER,
                again.info.revision,
                HeldTaskAnswer::Agent
            )),
            ErrorCode::Conflict
        );
    }

    fn not_resumable(id: &str) -> HeldTask {
        HeldTask {
            resumable: false,
            resume: "Decide on the agent's task board.".into(),
            ..task(id)
        }
    }

    /// A card the runtime says cannot be resumed from the app: the host's
    /// person's resume of it, current, is answered `unsupported` before any
    /// channel is opened, with nothing logged, pending or changed.
    #[test]
    fn a_task_not_resumable_here_is_refused_before_the_channel_is_opened() {
        let (_dir, hub, store, phone, _rx) = fixture();
        store
            .report_held_tasks(AGENT, &home_id(AGENT), &[not_resumable("t1")])
            .unwrap();
        // `Hub::plugin` counts a generation before it opens anything, even
        // an opening that then fails: unchanged, it was not called.
        let generations = hub.generations.load(Ordering::Relaxed);
        // No plugin listens: what answers is the card, not the channel.
        let error = hub
            .held_task_resume(
                &store,
                &phone,
                OWNER,
                MessageId::new("tap").unwrap(),
                resume("t1", 0),
            )
            .unwrap_err();
        assert_eq!(
            (error.code, error.of.as_ref().map(MessageId::as_str)),
            (ErrorCode::Unsupported, Some("tap"))
        );
        assert!(error.message.contains("cannot be resumed from the app"));
        assert_eq!(hub.generations.load(Ordering::Relaxed), generations);
        assert!(hub.opening.lock().unwrap().is_empty());
        assert!(!hub.plugins.lock().unwrap().contains_key(AGENT));
        assert!(hub.held_tasks.lock().unwrap().pending.is_empty());
        assert!(resume_lines(&store).is_empty());
        let card = store.held_task(AGENT, "t1").unwrap().unwrap();
        assert_eq!(
            (
                card.info.state,
                card.info.revision,
                card.runtime_revision.as_str()
            ),
            (HeldTaskState::Held, 0, "e:7")
        );
    }

    /// Whether it can be resumed is said only to whoever may resume the card
    /// as it is: every other request is answered as before.
    #[test]
    fn a_task_not_resumable_here_is_answered_as_any_card_to_whoever_may_not_resume_it() {
        let (_dir, hub, store, phone, _rx) = fixture();
        store
            .report_held_tasks(AGENT, &home_id(AGENT), &[not_resumable("t1")])
            .unwrap();
        let answer = |device: &Device, person: &str, request: ResumeRequest| {
            hub.held_task_resume(
                &store,
                device,
                person,
                MessageId::new("tap").unwrap(),
                request,
            )
            .unwrap_err()
            .code
        };
        let guest = device("guest-phone", GUEST);
        store.add_device(&guest).unwrap();
        let unpaired = device("tablet", OWNER);
        let other_noise = Device {
            noise_key: b"another noise key".to_vec(),
            ..phone.clone()
        };
        let other_signing = Device {
            device_key: b"another signing key".to_vec(),
            ..phone.clone()
        };
        let elsewhere = ResumeRequest {
            agent: "lab/other".into(),
            ..resume("t1", 0)
        };
        assert_eq!(
            [
                answer(&guest, GUEST, resume("t1", 0)),
                answer(&unpaired, OWNER, resume("t1", 0)),
                answer(&other_noise, OWNER, resume("t1", 0)),
                answer(&other_signing, OWNER, resume("t1", 0)),
                answer(&phone, OWNER, resume("t9", 0)),
                answer(&phone, OWNER, elsewhere),
                answer(&phone, OWNER, resume("t1", 1)),
                answer(&phone, OWNER, resume("t1", 0)),
            ],
            [
                ErrorCode::NotAllowed,
                ErrorCode::NotAllowed,
                ErrorCode::NotAllowed,
                ErrorCode::NotAllowed,
                ErrorCode::NotFound,
                ErrorCode::NotFound,
                ErrorCode::Conflict,
                ErrorCode::Unsupported,
            ]
        );
        // No longer held: a conflict, as for any card.
        store
            .report_held_tasks(AGENT, &home_id(AGENT), &[])
            .unwrap();
        assert_eq!(answer(&phone, OWNER, resume("t1", 1)), ErrorCode::Conflict);
        // Held again, then the host's person changes: not theirs to resume.
        store
            .report_held_tasks(AGENT, &home_id(AGENT), &[not_resumable("t1")])
            .unwrap();
        assert_eq!(
            answer(&phone, OWNER, resume("t1", 2)),
            ErrorCode::Unsupported
        );
        store.set_host(GUEST).unwrap();
        assert_eq!(
            answer(&phone, OWNER, resume("t1", 2)),
            ErrorCode::NotAllowed
        );
        assert!(!hub.plugins.lock().unwrap().contains_key(AGENT));
        assert!(hub.held_tasks.lock().unwrap().pending.is_empty());
        assert!(resume_lines(&store).is_empty());
    }

    /// A card not resumable here in another person's Home reads, to the
    /// host's person, exactly as a card that does not exist: no oracle.
    #[test]
    fn another_persons_card_not_resumable_here_reads_as_an_unknown_one() {
        let (_dir, hub, store, phone, _rx) = fixture();
        const THEIRS: &str = "lab/theirs";
        store.ensure_home(THEIRS, GUEST, true).unwrap();
        store
            .report_held_tasks(THEIRS, &home_id(THEIRS), &[not_resumable("t1")])
            .unwrap();
        let theirs = store.held_task(THEIRS, "t1").unwrap().unwrap();
        assert_eq!(
            (theirs.owner.as_str(), theirs.info.resumable),
            (GUEST, false)
        );
        let generations = hub.generations.load(Ordering::Relaxed);
        let answer = |request: ResumeRequest| {
            hub.held_task_resume(
                &store,
                &phone,
                OWNER,
                MessageId::new("tap").unwrap(),
                request,
            )
            .unwrap_err()
        };
        let other = answer(ResumeRequest {
            agent: THEIRS.into(),
            ..resume("t1", 0)
        });
        let unknown = answer(resume("t9", 0));
        assert_eq!(other.code, ErrorCode::NotFound);
        assert_eq!(other, unknown);
        assert_eq!(hub.generations.load(Ordering::Relaxed), generations);
        assert!(hub.held_tasks.lock().unwrap().pending.is_empty());
        assert!(resume_lines(&store).is_empty());
        assert_eq!(store.held_task(THEIRS, "t1").unwrap().unwrap(), theirs);
    }

    /// Writes `line` to the bridge as the plugin, as it is: what `say`
    /// cannot, a message the protocol's types would not make.
    fn say_raw(writer: &mut UnixStream, line: &serde_json::Value) {
        writer.write_all(format!("{line}\n").as_bytes()).unwrap();
    }

    /// A report whose `resumable` is not a JSON boolean is refused whole,
    /// on the socket, answered to its id: the card already held stays as it
    /// was, nothing is released, and a valid report after it is read.
    #[test]
    fn a_report_whose_resumable_is_not_a_boolean_is_refused_and_releases_nothing() {
        let (_dir, hub, store, phone, rx) = fixture();
        let (mut plugin, from_bridge) = fake_plugin(&hub, vec![Capability::HeldTasks]);
        say(
            &mut plugin,
            "report-1",
            FromPlugin::HeldTasks {
                tasks: vec![not_resumable("t1")],
            },
        );
        plugin_frame(&from_bridge);
        assert!(!card(next(&rx)).resumable);
        next(&rx);
        let before = store.held_task(AGENT, "t1").unwrap().unwrap();
        let seq = store.newest_seq().unwrap();
        for (n, bad) in [
            serde_json::Value::Null,
            serde_json::json!("false"),
            serde_json::json!("true"),
            serde_json::json!(0),
            serde_json::json!(1),
            serde_json::json!({}),
            serde_json::json!([]),
            serde_json::json!([false]),
        ]
        .into_iter()
        .enumerate()
        {
            let id = format!("bad-{n}");
            let mut listed = serde_json::to_value(not_resumable("t1")).unwrap();
            listed["resumable"] = bad.clone();
            say_raw(
                &mut plugin,
                &serde_json::json!({"v": 1, "id": id, "type": "held_tasks", "tasks": [listed]}),
            );
            let answer = plugin_frame(&from_bridge);
            let FromBridge::Error(error) = answer.body else {
                panic!("{bad}: refused, not {:?}", answer.body);
            };
            assert_eq!(
                (error.of.as_ref().map(MessageId::as_str), error.code),
                (Some(id.as_str()), ErrorCode::BadMessage),
                "{bad}"
            );
            assert_eq!(
                store.held_task(AGENT, "t1").unwrap().unwrap(),
                before,
                "{bad}"
            );
            assert_eq!(store.newest_seq().unwrap(), seq, "{bad}: no history");
            assert!(rx.try_recv().is_err(), "{bad}: no device heard of it");
        }
        assert_eq!(store.held_tasks_for(OWNER).unwrap(), [before]);
        // A valid report after them is read: the same task, held anew.
        say(
            &mut plugin,
            "report-2",
            FromPlugin::HeldTasks {
                tasks: vec![HeldTask {
                    reason: "Blocked again".into(),
                    revision: HeldTaskRevision::new("e:8").unwrap(),
                    ..task("t1")
                }],
            },
        );
        assert!(matches!(
            plugin_frame(&from_bridge).body,
            FromBridge::Ack { ref of } if of.as_str() == "report-2"
        ));
        let changed = card(next(&rx));
        assert_eq!(
            (
                changed.state,
                changed.revision,
                changed.resumable,
                changed.reason.as_str()
            ),
            (HeldTaskState::Held, 1, true, "Blocked again")
        );
        assert!(rx.recv_timeout(Duration::from_millis(200)).is_err());
        assert_eq!(store.newest_seq().unwrap(), seq);
        hub.held_task_resume(
            &store,
            &phone,
            OWNER,
            MessageId::new("tap").unwrap(),
            resume("t1", 1),
        )
        .unwrap();
        assert!(matches!(
            plugin_frame(&from_bridge).body,
            FromBridge::HeldTaskResume { ref revision, .. } if revision.as_str() == "e:8"
        ));
    }

    /// Only `resumable` changes, at the same runtime revision: the card is
    /// sent once each way with the bridge's revision advanced, with no
    /// message, and the same report again sends nothing.
    #[test]
    fn a_change_of_resumable_alone_is_sent_once_each_way_with_no_message() {
        let (_dir, hub, store, _phone, rx) = fixture();
        let (mut plugin, from_bridge) = reported(&hub, &rx);
        let seq = store.newest_seq().unwrap();
        for (n, (resumable, revision)) in [(false, 1), (true, 2)].into_iter().enumerate() {
            let listed = HeldTask {
                resumable,
                ..task("t1")
            };
            for again in 0..2 {
                let id = format!("report-{n}-{again}");
                say(
                    &mut plugin,
                    &id,
                    FromPlugin::HeldTasks {
                        tasks: vec![listed.clone()],
                    },
                );
                assert!(matches!(
                    plugin_frame(&from_bridge).body,
                    FromBridge::Ack { ref of } if *of.as_str() == id
                ));
                if again == 0 {
                    let changed = card(next(&rx));
                    assert_eq!(
                        (changed.resumable, changed.revision, changed.state),
                        (resumable, revision, HeldTaskState::Held)
                    );
                }
                assert!(
                    rx.recv_timeout(Duration::from_millis(200)).is_err(),
                    "{id}: no message, and a repeat sends nothing"
                );
                let stored = store.held_task(AGENT, "t1").unwrap().unwrap();
                assert_eq!(
                    (
                        stored.info.resumable,
                        stored.info.revision,
                        stored.runtime_revision.as_str()
                    ),
                    (resumable, revision, "e:7")
                );
                assert_eq!(store.newest_seq().unwrap(), seq, "{id}: no history");
            }
        }
    }

    /// A card that turned not resumable while its resume ran: the result,
    /// and the same request's replay, carry `resumable: false` on the wire.
    #[test]
    fn a_result_and_its_replay_carry_a_card_that_is_not_resumable() {
        use enclos_protocol::device::decode_to_device;
        let (_dir, hub, store, phone, rx) = fixture();
        let (mut plugin, from_bridge) = reported(&hub, &rx);
        let original = MessageId::new("tap").unwrap();
        hub.held_task_resume(&store, &phone, OWNER, original.clone(), resume("t1", 0))
            .unwrap();
        let sent = plugin_frame(&from_bridge);
        say(
            &mut plugin,
            "report-2",
            FromPlugin::HeldTasks {
                tasks: vec![HeldTask {
                    resumable: false,
                    ..task("t1")
                }],
            },
        );
        plugin_frame(&from_bridge);
        assert!(!card(next(&rx)).resumable);
        say(
            &mut plugin,
            "resumed",
            FromPlugin::HeldTaskResumed { of: sent.id },
        );
        let resumed = card(next(&rx));
        assert_eq!(
            (resumed.state, resumed.revision, resumed.resumable),
            (HeldTaskState::Resumed, 2, false)
        );
        let ToDevice::Message(_) = next(&rx) else {
            panic!("the quiet line");
        };
        let answer = next(&rx);
        assert!(matches!(&answer, ToDevice::HeldTaskResult { of, .. } if *of == original));
        let on_the_wire = |answer: &ToDevice| {
            let line = encode_line(&Envelope::new(
                MessageId::new("out").unwrap(),
                answer.clone(),
            ));
            let value: serde_json::Value = serde_json::from_slice(&line).unwrap();
            assert_eq!(value["held_task"]["resumable"], false, "{value}");
            assert_eq!(decode_to_device(&line).unwrap().body, *answer);
        };
        on_the_wire(&answer);
        hub.held_task_resume(&store, &phone, OWNER, original, resume("t1", 0))
            .unwrap();
        let replay = next(&rx);
        assert_eq!(replay, answer);
        on_the_wire(&replay);
        assert!(
            from_bridge
                .recv_timeout(Duration::from_millis(200))
                .is_err()
        );
    }

    /// From the plugin's JSON to a reopened store, a task not resumable
    /// here stays so at every step, cut to the bridge's bounds.
    #[test]
    fn a_task_not_resumable_here_stays_so_and_bounded_from_its_report_to_a_reopened_store() {
        let (dir, hub, store, _phone, rx) = fixture();
        let mut listed = serde_json::to_value(not_resumable("t1")).unwrap();
        listed["title"] = format!("Pay \u{202E}gpj.exe{}", "x".repeat(500)).into();
        listed["resume"] = format!("Decide\u{200B} on the\nboard {}", "y".repeat(500)).into();
        listed["resumable"] = false.into();
        let line =
            serde_json::json!({"v": 1, "id": "report-1", "type": "held_tasks", "tasks": [listed]});
        let bounded = |title: &str, resume: &str, resumable: bool, at: &str| {
            assert!(!resumable, "{at}");
            assert!(
                title.chars().count() <= enclos_protocol::held_task::MAX_TITLE_CHARS,
                "{at}"
            );
            assert!(
                resume.chars().count() <= enclos_protocol::held_task::MAX_RESUME_CHARS,
                "{at}"
            );
            for text in [title, resume] {
                assert!(
                    !text.contains(['\u{202E}', '\u{200B}', '\n']),
                    "{at}: {text:?}"
                );
            }
        };
        // Decoded.
        let FromPlugin::HeldTasks { tasks } = decode_from_plugin(line.to_string().as_bytes())
            .unwrap()
            .body
        else {
            panic!("a report");
        };
        assert!(!tasks[0].resumable);
        // Accepted.
        let accepted = accept(tasks).unwrap();
        bounded(
            &accepted[0].title,
            &accepted[0].resume,
            accepted[0].resumable,
            "accepted",
        );
        // Through the socket, stored and sent.
        let (mut plugin, from_bridge) = fake_plugin(&hub, vec![Capability::HeldTasks]);
        say_raw(&mut plugin, &line);
        assert!(matches!(
            plugin_frame(&from_bridge).body,
            FromBridge::Ack { .. }
        ));
        let sent = card(next(&rx));
        bounded(&sent.title, &sent.resume, sent.resumable, "sent");
        assert_eq!(
            (sent.title.as_str(), sent.resume.as_str()),
            (accepted[0].title.as_str(), accepted[0].resume.as_str())
        );
        // Read again from the database by a store opened afresh.
        drop(store);
        let reopened = Store::open(&dir.path().join("app.db")).unwrap();
        let stored = reopened.held_task(AGENT, "t1").unwrap().unwrap();
        bounded(
            &stored.info.title,
            &stored.info.resume,
            stored.info.resumable,
            "reopened",
        );
        assert_eq!(stored.info, sent);
        assert_eq!(reopened.held_tasks_for(OWNER).unwrap()[0].info, sent);
    }

    /// With the channel connected, a task it reports as not resumable here
    /// is not sent to it; one it reports resumable, or says nothing of, is,
    /// once.
    #[test]
    fn a_connected_channel_is_sent_only_the_resume_of_a_resumable_task() {
        let (_dir, hub, store, phone, rx) = fixture();
        let (mut plugin, from_bridge) = fake_plugin(&hub, vec![Capability::HeldTasks]);
        // t2 as an older plugin lists it: with no `resumable` at all.
        let mut silent = serde_json::to_value(task("t2")).unwrap();
        assert_eq!(
            silent.as_object_mut().unwrap().remove("resumable"),
            Some(true.into())
        );
        say_raw(
            &mut plugin,
            &serde_json::json!({"v": 1, "id": "report-1", "type": "held_tasks",
                "tasks": [serde_json::to_value(not_resumable("t1")).unwrap(), silent]}),
        );
        assert!(matches!(
            plugin_frame(&from_bridge).body,
            FromBridge::Ack { .. }
        ));
        let first = card(next(&rx));
        assert!(!first.resumable);
        let ToDevice::Message(introduction) = next(&rx) else {
            panic!("the card's message");
        };
        assert_eq!(
            introduction.text,
            "Held task: Task t1\nGave up after 3 failures\nDecide on the agent's task board."
        );
        assert!(card(next(&rx)).resumable);
        next(&rx);
        let error = hub
            .held_task_resume(
                &store,
                &phone,
                OWNER,
                MessageId::new("tap-1").unwrap(),
                resume("t1", 0),
            )
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::Unsupported);
        assert!(
            from_bridge
                .recv_timeout(Duration::from_millis(300))
                .is_err(),
            "nothing reaches the runtime"
        );
        // The same request again: the same answer, still nothing sent.
        let again = hub
            .held_task_resume(
                &store,
                &phone,
                OWNER,
                MessageId::new("tap-1").unwrap(),
                resume("t1", 0),
            )
            .unwrap_err();
        assert_eq!(again.code, ErrorCode::Unsupported);
        // A resumable task's resume is sent, once.
        let original = MessageId::new("tap-2").unwrap();
        hub.held_task_resume(&store, &phone, OWNER, original.clone(), resume("t2", 0))
            .unwrap();
        let sent = plugin_frame(&from_bridge);
        assert_eq!(sent.id, rpc_id("phone", OWNER, &original));
        assert!(matches!(
            sent.body,
            FromBridge::HeldTaskResume { ref task, .. } if task.as_str() == "t2"
        ));
        assert!(
            from_bridge
                .recv_timeout(Duration::from_millis(300))
                .is_err()
        );
        assert_eq!(resume_lines(&store), ["lab/main t2 requested"]);
        assert_eq!(
            state(&store, "t1"),
            HeldTaskState::Held,
            "the card not resumable here is as it was"
        );
    }

    #[test]
    fn the_runtimes_refusal_reaches_the_device_and_a_lost_answer_is_unconfirmed() {
        let (_dir, hub, store, phone, rx) = fixture();
        let (mut plugin, from_bridge) = reported(&hub, &rx);
        let first = MessageId::new("tap-1").unwrap();
        hub.held_task_resume(&store, &phone, OWNER, first.clone(), resume("t1", 0))
            .unwrap();
        let sent = plugin_frame(&from_bridge);
        say(
            &mut plugin,
            "refused-1",
            FromPlugin::Error(ErrorBody {
                of: Some(sent.id),
                code: ErrorCode::Conflict,
                message: "no longer blocked".into(),
            }),
        );
        let ToDevice::Error(error) = next(&rx) else {
            panic!("the runtime's refusal");
        };
        assert_eq!((error.of, error.code), (Some(first), ErrorCode::Conflict));

        let second = MessageId::new("tap-2").unwrap();
        hub.held_task_resume(&store, &phone, OWNER, second.clone(), resume("t1", 0))
            .unwrap();
        plugin_frame(&from_bridge);
        let connection = hub.held_tasks.lock().unwrap().connections[AGENT].clone();
        hub.held_task_disconnected(&store, AGENT, &connection);
        let ToDevice::Error(error) = next(&rx) else {
            panic!("an unconfirmed resume");
        };
        assert_eq!(
            (error.of, error.code),
            (Some(second), ErrorCode::Unconfirmed)
        );
        // Still held: neither outcome changed the card.
        assert_eq!(
            store.held_task(AGENT, "t1").unwrap().unwrap().info.state,
            HeldTaskState::Held
        );
        assert_eq!(
            resume_lines(&store),
            [
                "lab/main t1 requested",
                "lab/main t1 answered conflict",
                "lab/main t1 requested",
                "lab/main t1 unknown: disconnected"
            ]
        );
    }

    #[test]
    fn a_resume_the_runtime_leaves_unanswered_times_out_unconfirmed() {
        let (_dir, hub, store, phone, rx) = fixture();
        let (_plugin, from_bridge) = reported(&hub, &rx);
        hub.held_task_resume(
            &store,
            &phone,
            OWNER,
            MessageId::new("tap").unwrap(),
            resume("t1", 0),
        )
        .unwrap();
        plugin_frame(&from_bridge);
        for pending in hub.held_tasks.lock().unwrap().pending.values_mut() {
            pending.started -= TIMEOUT;
        }
        hub.expire_held_resumes(&store);
        let ToDevice::Error(error) = next(&rx) else {
            panic!("an unconfirmed resume");
        };
        assert_eq!(error.code, ErrorCode::Unconfirmed);
        assert_eq!(
            resume_lines(&store).last().unwrap(),
            "lab/main t1 unknown: timed out"
        );
    }

    #[test]
    fn a_channel_without_held_tasks_expires_its_cards_and_cannot_report() {
        let (_dir, hub, store, _phone, rx) = fixture();
        let changes = store
            .report_held_tasks(AGENT, &home_id(AGENT), &[task("t1")])
            .unwrap();
        assert_eq!(changes.len(), 1);
        let (mut plugin, from_bridge) = fake_plugin(&hub, vec![Capability::Typing]);
        let expired = card(next(&rx));
        assert_eq!(
            (expired.state, expired.revision),
            (HeldTaskState::Expired, 1)
        );
        let ToDevice::Message(line) = next(&rx) else {
            panic!("the quiet line");
        };
        assert!(line.text.starts_with("No longer tracked: Task t1."));
        say(
            &mut plugin,
            "report-1",
            FromPlugin::HeldTasks {
                tasks: vec![task("t2")],
            },
        );
        let FromBridge::Error(error) = plugin_frame(&from_bridge).body else {
            panic!("a report refused");
        };
        assert_eq!(error.code, ErrorCode::Unsupported);
        assert!(store.held_task(AGENT, "t2").unwrap().is_none());
    }

    #[test]
    fn a_report_beyond_the_bound_or_naming_a_task_twice_changes_nothing() {
        let (_dir, hub, store, _phone, rx) = fixture();
        let (mut plugin, from_bridge) = reported(&hub, &rx);
        say(
            &mut plugin,
            "twice",
            FromPlugin::HeldTasks {
                tasks: vec![task("t1"), task("t1")],
            },
        );
        let FromBridge::Error(error) = plugin_frame(&from_bridge).body else {
            panic!("refused");
        };
        assert_eq!(error.code, ErrorCode::BadMessage);
        let many = (0..=enclos_protocol::held_task::MAX_HELD_TASKS)
            .map(|n| task(&format!("t{n}")))
            .collect();
        say(&mut plugin, "many", FromPlugin::HeldTasks { tasks: many });
        let FromBridge::Error(error) = plugin_frame(&from_bridge).body else {
            panic!("refused");
        };
        assert_eq!(error.code, ErrorCode::BadMessage);
        // The card held before either report is as it was, and no device
        // heard of a change.
        let kept = store.held_tasks_for(OWNER).unwrap();
        assert_eq!(kept.len(), 1);
        assert_eq!(
            (kept[0].info.task.as_str(), kept[0].info.revision),
            ("t1", 0)
        );
        assert!(rx.recv_timeout(Duration::from_millis(200)).is_err());
    }

    #[test]
    fn a_sync_sends_held_cards_past_since_and_each_cards_state_before_its_lines() {
        use enclos_protocol::device::decode_to_device;
        use enclos_protocol::noise::{Initiator, Responder, generate_keypair};
        let (_dir, hub, store, phone, rx) = fixture();
        let home = home_id(AGENT);
        // t2 is not resumable from the app: its card says so at every sync.
        store
            .report_held_tasks(AGENT, &home, &[task("t1"), not_resumable("t2")])
            .unwrap();
        let introduced = store.newest_seq().unwrap();
        // t1 is no longer held: its quiet line comes after `introduced`.
        store
            .report_held_tasks(AGENT, &home, &[not_resumable("t2")])
            .unwrap();
        let newest = store.newest_seq().unwrap();
        let bridge_key = generate_keypair().unwrap();
        let device_key = generate_keypair().unwrap();
        let mut initiator = Initiator::new(&device_key.private, &bridge_key.public).unwrap();
        let mut responder = Responder::new(&bridge_key.private).unwrap();
        responder.read_hello(&initiator.hello().unwrap()).unwrap();
        let (answer, bridge_session) = responder.answer().unwrap();
        let mut device_session = initiator.finish(&answer).unwrap();
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let server_hub = Arc::clone(&hub);
        let thread = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_millis(100)))
                .unwrap();
            let socket = tungstenite::accept(stream).unwrap();
            let mut link = Link {
                socket,
                session: bridge_session,
                heard: std::time::Instant::now(),
                scoped_approvals: false,
                task_events: false,
            };
            let store = server_hub.store().unwrap();
            run_session(&server_hub, &store, &mut link, &phone, OWNER, &rx)
        });
        let stream = std::net::TcpStream::connect(address).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let (mut socket, _) = tungstenite::client(format!("ws://{address}"), stream).unwrap();
        let mut sync = |since| {
            let message = encode_line(&Envelope::new(
                MessageId::new(format!("sync-{since}")).unwrap(),
                FromDevice::Sync {
                    since,
                    open_items: false,
                },
            ));
            socket
                .send(Message::Binary(
                    device_session.encrypt(&message).unwrap().into(),
                ))
                .unwrap();
            let mut messages = vec![];
            loop {
                let Message::Binary(encoded) = socket.read().unwrap() else {
                    panic!("encrypted device message")
                };
                let decoded = decode_to_device(&device_session.decrypt(&encoded).unwrap())
                    .unwrap()
                    .body;
                let done = matches!(decoded, ToDevice::Synced { .. });
                messages.push(decoded);
                if done {
                    break;
                }
            }
            messages
        };
        let after = sync(introduced);
        let held = |messages: &[ToDevice]| -> Vec<(String, bool)> {
            messages
                .iter()
                .filter_map(|m| match m {
                    ToDevice::HeldTask { held_task } if held_task.state == HeldTaskState::Held => {
                        Some((held_task.task.as_str().to_owned(), held_task.resumable))
                    }
                    _ => None,
                })
                .collect()
        };
        assert_eq!(
            held(&after),
            [("t2".to_owned(), false)],
            "a held card, though its message predates since"
        );
        // The highest since: nothing new, and still the held card, as it is.
        let latest = sync(newest);
        assert_eq!(held(&latest), [("t2".to_owned(), false)]);
        assert!(
            !latest.iter().any(|m| matches!(m, ToDevice::Message(_))),
            "no line past the newest"
        );
        let line = after
            .iter()
            .position(|m| matches!(m, ToDevice::Message(m) if m.kind == "status"))
            .unwrap();
        assert!(matches!(
            &after[line - 1],
            ToDevice::HeldTask { held_task }
                if held_task.task.as_str() == "t1" && held_task.state == HeldTaskState::Released
        ));
        let all = sync(0);
        let mut linked = 0;
        for (index, message) in all.iter().enumerate() {
            if let ToDevice::Message(message) = message
                && let Some(task) = &message.held_task
            {
                linked += 1;
                assert!(
                    matches!(&all[index - 1], ToDevice::HeldTask { held_task } if held_task.task == *task),
                    "each line comes after its card's state"
                );
                if task.as_str() == "t2" {
                    // Its card, before it, is not resumable, and its text
                    // offers no Resume.
                    assert!(
                        matches!(&all[index - 1], ToDevice::HeldTask { held_task } if !held_task.resumable)
                    );
                    assert_eq!(
                        message.text,
                        "Held task: Task t2\nGave up after 3 failures\nDecide on the agent's task board."
                    );
                }
            }
        }
        assert_eq!(linked, 3, "two holds and one release");
        socket.close(None).unwrap();
        assert_eq!(thread.join().unwrap(), Err("closed".into()));
    }

    #[test]
    fn the_bridge_cuts_what_the_sandbox_sent_before_storing_it() {
        let (_dir, hub, store, _phone, rx) = fixture();
        let (mut plugin, from_bridge) = fake_plugin(&hub, vec![Capability::HeldTasks]);
        let sneaky = HeldTask {
            title: format!("Pay \u{202E}gpj.exe{}", "x".repeat(500)),
            ..task("t1")
        };
        say(
            &mut plugin,
            "report",
            FromPlugin::HeldTasks {
                tasks: vec![sneaky],
            },
        );
        plugin_frame(&from_bridge);
        let held = card(next(&rx));
        assert!(!enclos_protocol::visible::has_hidden(&held.title, false));
        assert_eq!(
            held.title.chars().count(),
            enclos_protocol::held_task::MAX_TITLE_CHARS
        );
        assert_eq!(
            store.held_tasks_for(OWNER).unwrap()[0].info.title,
            held.title
        );
    }

    fn state(store: &Store, task: &str) -> HeldTaskState {
        store.held_task(AGENT, task).unwrap().unwrap().info.state
    }

    /// Makes the bridge's database refuse to change held cards, as a full
    /// disk would, until [`unblock_writes`].
    fn block_writes(hub: &Hub) {
        rusqlite::Connection::open(&hub.store_path)
            .unwrap()
            .execute_batch(
                "CREATE TRIGGER held_full BEFORE UPDATE ON held_tasks BEGIN SELECT RAISE(ABORT, 'disk full'); END;",
            )
            .unwrap();
    }

    fn unblock_writes(hub: &Hub) {
        rusqlite::Connection::open(&hub.store_path)
            .unwrap()
            .execute_batch("DROP TRIGGER held_full;")
            .unwrap();
    }

    fn break_table(hub: &Hub, table: &str) {
        rusqlite::Connection::open(&hub.store_path)
            .unwrap()
            .execute_batch(&format!(
                "PRAGMA foreign_keys = OFF; DROP TABLE {table}; CREATE TABLE {table} (broken INTEGER);"
            ))
            .unwrap();
    }

    #[test]
    fn a_channel_that_reconnects_with_held_tasks_expires_nothing() {
        let (_dir, hub, store, _phone, rx) = fixture();
        store
            .report_held_tasks(AGENT, &home_id(AGENT), &[task("t1")])
            .unwrap();
        let (_plugin, _from_bridge) = fake_plugin(&hub, vec![Capability::HeldTasks]);
        assert!(rx.recv_timeout(Duration::from_millis(300)).is_err());
        let card = store.held_task(AGENT, "t1").unwrap().unwrap().info;
        assert_eq!((card.state, card.revision), (HeldTaskState::Held, 0));
    }

    #[test]
    fn a_confirmation_from_another_agent_or_an_old_connection_changes_nothing() {
        let (_dir, hub, store, phone, rx) = fixture();
        let (_plugin, from_bridge) = reported(&hub, &rx);
        hub.held_task_resume(
            &store,
            &phone,
            OWNER,
            MessageId::new("tap").unwrap(),
            resume("t1", 0),
        )
        .unwrap();
        let sent = plugin_frame(&from_bridge).id;
        let connection = hub.held_tasks.lock().unwrap().connections[AGENT].clone();
        hub.held_task_resumed(&store, "lab/other", &connection, &sent);
        hub.held_task_resumed(&store, AGENT, "an-old-connection", &sent);
        let forged = ErrorBody {
            of: Some(sent.clone()),
            code: ErrorCode::Conflict,
            message: "forged".into(),
        };
        assert!(!hub.held_task_error(&store, "lab/other", &connection, &forged));
        assert!(!hub.held_task_error(&store, AGENT, "an-old-connection", &forged));
        assert!(rx.recv_timeout(Duration::from_millis(200)).is_err());
        assert_eq!(state(&store, "t1"), HeldTaskState::Held);
        // The real one still settles it.
        hub.held_task_resumed(&store, AGENT, &connection, &sent);
        assert_eq!(state(&store, "t1"), HeldTaskState::Resumed);
    }

    #[test]
    fn cards_reach_only_the_home_owners_paired_devices() {
        let (_dir, hub, store, _phone, rx) = fixture();
        let guest = device("guest-phone", GUEST);
        store.add_device(&guest).unwrap();
        let (guest_tx, guest_rx) = channel();
        let (unpaired_tx, unpaired_rx) = channel();
        let (second_tx, second_rx) = channel();
        let second = device("tablet", OWNER);
        store.add_device(&second).unwrap();
        {
            let mut devices = hub.devices.lock().unwrap();
            devices.insert(guest.id.clone(), (GUEST.into(), guest_tx, 2));
            // Connected, and unpaired since.
            devices.insert("gone-phone".into(), (OWNER.into(), unpaired_tx, 3));
            devices.insert(second.id.clone(), (OWNER.into(), second_tx, 4));
        }
        let _plugin = reported(&hub, &rx);
        assert!(matches!(next(&second_rx), ToDevice::HeldTask { .. }));
        assert!(guest_rx.recv_timeout(Duration::from_millis(200)).is_err());
        assert!(unpaired_rx.try_recv().is_err());
    }

    #[test]
    fn the_persons_other_devices_get_the_resumed_card_too() {
        let (_dir, hub, store, phone, rx) = fixture();
        let second = device("tablet", OWNER);
        store.add_device(&second).unwrap();
        let (second_tx, second_rx) = channel();
        let (mut plugin, from_bridge) = reported(&hub, &rx);
        hub.devices
            .lock()
            .unwrap()
            .insert(second.id.clone(), (OWNER.into(), second_tx, 2));
        hub.held_task_resume(
            &store,
            &phone,
            OWNER,
            MessageId::new("tap").unwrap(),
            resume("t1", 0),
        )
        .unwrap();
        let sent = plugin_frame(&from_bridge).id;
        say(
            &mut plugin,
            "resumed",
            FromPlugin::HeldTaskResumed { of: sent },
        );
        let resumed = card(next(&second_rx));
        assert_eq!(resumed.state, HeldTaskState::Resumed);
        // The receipt is the asking device's alone.
        assert!(matches!(next(&second_rx), ToDevice::Message(_)));
        assert!(second_rx.recv_timeout(Duration::from_millis(200)).is_err());
    }

    #[test]
    fn a_card_no_longer_held_cannot_be_resumed() {
        let (_dir, hub, store, phone, rx) = fixture();
        let (mut plugin, from_bridge) = reported(&hub, &rx);
        say(
            &mut plugin,
            "report-2",
            FromPlugin::HeldTasks { tasks: vec![] },
        );
        plugin_frame(&from_bridge);
        let released = card(next(&rx));
        assert_eq!(released.state, HeldTaskState::Released);
        let error = hub
            .held_task_resume(
                &store,
                &phone,
                OWNER,
                MessageId::new("tap").unwrap(),
                resume("t1", released.revision),
            )
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::Conflict);
        assert!(
            from_bridge
                .recv_timeout(Duration::from_millis(200))
                .is_err()
        );
    }

    #[test]
    fn the_same_request_while_pending_and_after_unconfirmed_reaches_the_runtime_once() {
        let (_dir, hub, store, phone, rx) = fixture();
        let (_plugin, from_bridge) = reported(&hub, &rx);
        let tap = MessageId::new("tap").unwrap();
        hub.held_task_resume(&store, &phone, OWNER, tap.clone(), resume("t1", 0))
            .unwrap();
        hub.held_task_resume(&store, &phone, OWNER, tap.clone(), resume("t1", 0))
            .unwrap();
        plugin_frame(&from_bridge);
        assert!(
            from_bridge
                .recv_timeout(Duration::from_millis(200))
                .is_err()
        );
        for pending in hub.held_tasks.lock().unwrap().pending.values_mut() {
            pending.started -= TIMEOUT;
        }
        hub.expire_held_resumes(&store);
        let first = next(&rx);
        assert!(matches!(&first, ToDevice::Error(e) if e.code == ErrorCode::Unconfirmed));
        // Sent again by the device: the same answer, nothing to the runtime.
        hub.held_task_resume(&store, &phone, OWNER, tap, resume("t1", 0))
            .unwrap();
        assert_eq!(next(&rx), first);
        assert!(
            from_bridge
                .recv_timeout(Duration::from_millis(200))
                .is_err()
        );
    }

    #[test]
    fn a_confirmation_after_the_timeout_is_still_recorded() {
        let (_dir, hub, store, phone, rx) = fixture();
        let (mut plugin, from_bridge) = reported(&hub, &rx);
        hub.held_task_resume(
            &store,
            &phone,
            OWNER,
            MessageId::new("tap").unwrap(),
            resume("t1", 0),
        )
        .unwrap();
        let sent = plugin_frame(&from_bridge).id;
        for pending in hub.held_tasks.lock().unwrap().pending.values_mut() {
            pending.started -= TIMEOUT;
        }
        hub.expire_held_resumes(&store);
        assert!(matches!(next(&rx), ToDevice::Error(e) if e.code == ErrorCode::Unconfirmed));
        say(
            &mut plugin,
            "late",
            FromPlugin::HeldTaskResumed { of: sent },
        );
        assert_eq!(card(next(&rx)).state, HeldTaskState::Resumed);
        assert_eq!(
            resume_lines(&store),
            [
                "lab/main t1 requested",
                "lab/main t1 unknown: timed out",
                "lab/main t1 confirmed late"
            ]
        );
    }

    #[test]
    fn an_answer_is_not_dropped_when_the_paired_devices_cannot_be_read() {
        let (_dir, hub, store, phone, rx) = fixture();
        let (mut plugin, from_bridge) = reported(&hub, &rx);
        hub.held_task_resume(
            &store,
            &phone,
            OWNER,
            MessageId::new("tap").unwrap(),
            resume("t1", 0),
        )
        .unwrap();
        let sent = plugin_frame(&from_bridge).id;
        break_table(&hub, "devices");
        say(
            &mut plugin,
            "refused",
            FromPlugin::Error(ErrorBody {
                of: Some(sent),
                code: ErrorCode::Conflict,
                message: "no longer blocked".into(),
            }),
        );
        let ToDevice::Error(error) = next(&rx) else {
            panic!("an answer");
        };
        assert_eq!(
            (error.of.unwrap().as_str(), error.code),
            ("tap", ErrorCode::Unconfirmed)
        );
    }

    #[test]
    fn a_resume_the_log_cannot_record_is_not_sent() {
        let (_dir, hub, store, phone, rx) = fixture();
        let (_plugin, from_bridge) = reported(&hub, &rx);
        break_table(&hub, "log");
        let error = hub
            .held_task_resume(
                &store,
                &phone,
                OWNER,
                MessageId::new("tap").unwrap(),
                resume("t1", 0),
            )
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::Internal);
        assert!(
            from_bridge
                .recv_timeout(Duration::from_millis(200))
                .is_err()
        );
        assert!(hub.held_tasks.lock().unwrap().pending.is_empty());
    }

    #[test]
    fn a_confirmed_resume_the_bridge_cannot_record_reads_resumed_and_is_recorded_later() {
        let (_dir, hub, store, phone, rx) = fixture();
        let (mut plugin, from_bridge) = reported(&hub, &rx);
        hub.held_task_resume(
            &store,
            &phone,
            OWNER,
            MessageId::new("tap").unwrap(),
            resume("t1", 0),
        )
        .unwrap();
        let sent = plugin_frame(&from_bridge).id;
        block_writes(&hub);
        say(
            &mut plugin,
            "resumed",
            FromPlugin::HeldTaskResumed { of: sent },
        );
        let ToDevice::HeldTaskResult { held_task, .. } = next(&rx) else {
            panic!("a result");
        };
        assert_eq!(held_task.state, HeldTaskState::Resumed);
        assert_eq!(state(&store, "t1"), HeldTaskState::Held, "not written yet");
        unblock_writes(&hub);
        // The plugin's next report, without the task, does not release it:
        // the resume is recorded first.
        say(
            &mut plugin,
            "report-2",
            FromPlugin::HeldTasks { tasks: vec![] },
        );
        plugin_frame(&from_bridge);
        assert_eq!(state(&store, "t1"), HeldTaskState::Resumed);
        assert!(hub.held_tasks.lock().unwrap().unrecorded.is_empty());
    }

    #[test]
    fn cards_that_could_not_expire_expire_at_the_next_sweep() {
        let (_dir, hub, store, _phone, rx) = fixture();
        store
            .report_held_tasks(AGENT, &home_id(AGENT), &[task("t1")])
            .unwrap();
        block_writes(&hub);
        let _plugin = fake_plugin(&hub, vec![Capability::Typing]);
        assert_eq!(state(&store, "t1"), HeldTaskState::Held);
        unblock_writes(&hub);
        hub.expire_held_resumes(&store);
        assert_eq!(card(next(&rx)).state, HeldTaskState::Expired);
        assert!(hub.held_tasks.lock().unwrap().expiring.is_empty());
    }

    #[test]
    fn a_channel_without_held_tasks_answers_a_resume_unsupported() {
        let (_dir, hub, store, phone, rx) = fixture();
        store
            .report_held_tasks(AGENT, &home_id(AGENT), &[task("t1")])
            .unwrap();
        // Expiry fails, so the card is still held when the person taps.
        block_writes(&hub);
        let (_plugin, from_bridge) = fake_plugin(&hub, vec![Capability::Typing]);
        unblock_writes(&hub);
        let error = hub
            .held_task_resume(
                &store,
                &phone,
                OWNER,
                MessageId::new("tap").unwrap(),
                resume("t1", 0),
            )
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::Unsupported);
        assert!(
            from_bridge
                .recv_timeout(Duration::from_millis(200))
                .is_err()
        );
        drop(rx);
    }

    #[test]
    fn a_forgotten_agents_report_is_refused() {
        let (_dir, hub, store, phone, rx) = fixture();
        let (mut plugin, from_bridge) = reported(&hub, &rx);
        store.forget_agent(AGENT, OWNER, &phone.id).unwrap();
        say(
            &mut plugin,
            "report-2",
            FromPlugin::HeldTasks {
                tasks: vec![task("t1")],
            },
        );
        let FromBridge::Error(error) = plugin_frame(&from_bridge).body else {
            panic!("refused");
        };
        assert_eq!(error.code, ErrorCode::NotAllowed);
        assert!(store.held_task(AGENT, "t1").unwrap().is_none());
    }

    // A resume's answer once the host's person, the card's owner or the
    // asking device's pairing changed: only the fixed notice, or nothing.

    const NEW_OWNER: &str = "new-owner@example.com";
    const MARKER: &str = "SYNTHETIC-B-ONLY-MARKER";

    /// The one answer a device that may no longer read the card is sent.
    fn notice(of: &str) -> ToDevice {
        ToDevice::Error(ErrorBody {
            of: Some(MessageId::new(of).unwrap()),
            code: ErrorCode::Unconfirmed,
            message: UNCONFIRMED.into(),
        })
    }

    /// Every frame `rx` gets, until none comes for `ms`.
    fn drain(rx: &Receiver<ToDevice>, ms: u64) -> Vec<ToDevice> {
        std::iter::from_fn(|| rx.recv_timeout(Duration::from_millis(ms)).ok()).collect()
    }

    /// The phone's resume `tap` of t1, sent to the runtime: the plugin, the
    /// frames it was sent, its connection and the plugin request's id.
    fn sent_resume(
        hub: &Arc<Hub>,
        store: &Store,
        phone: &Device,
        rx: &Receiver<ToDevice>,
    ) -> (
        UnixStream,
        Receiver<Envelope<FromBridge>>,
        String,
        MessageId,
    ) {
        let (plugin, from_bridge) = reported(hub, rx);
        hub.held_task_resume(
            store,
            phone,
            OWNER,
            MessageId::new("tap").unwrap(),
            resume("t1", 0),
        )
        .unwrap();
        let sent = plugin_frame(&from_bridge).id;
        let connection = hub.held_tasks.lock().unwrap().connections[AGENT].clone();
        (plugin, from_bridge, connection, sent)
    }

    /// A paired and connected device of the next host's person.
    fn new_owners_device(hub: &Hub, store: &Store) -> Receiver<ToDevice> {
        store.add_device(&device("b-phone", NEW_OWNER)).unwrap();
        let (tx, rx) = channel();
        hub.devices
            .lock()
            .unwrap()
            .insert("b-phone".into(), (NEW_OWNER.into(), tx, 9));
        rx
    }

    /// The host's person becomes NEW_OWNER, then the runtime reports t1
    /// again with text that is theirs alone to read.
    fn transfer_with_new_text(hub: &Hub, store: &Store) {
        store.set_host(NEW_OWNER).unwrap();
        hub.held_tasks_report(
            store,
            AGENT,
            vec![HeldTask {
                title: format!("{MARKER} title"),
                reason: MARKER.into(),
                revision: HeldTaskRevision::new("e:99").unwrap(),
                ..task("t1")
            }],
        )
        .unwrap();
        assert_eq!(
            store.held_task(AGENT, "t1").unwrap().unwrap().owner,
            NEW_OWNER
        );
    }

    /// Whether any of `frames` carries the next owner's text.
    fn carries_marker(frames: &[ToDevice]) -> bool {
        frames.iter().any(|f| format!("{f:?}").contains(MARKER))
    }

    /// Unchanged host, owner and pairing: the result reaches the asking
    /// device, is kept, and a replay gets it again without the runtime.
    #[test]
    fn an_unchanged_owner_and_pairing_get_the_result_and_its_replay() {
        let (_dir, hub, store, phone, rx) = fixture();
        let (_plugin, from_bridge, connection, sent) = sent_resume(&hub, &store, &phone, &rx);
        hub.held_task_resumed(&store, AGENT, &connection, &sent);
        let frames = drain(&rx, 300);
        let result = frames.last().unwrap().clone();
        assert!(matches!(
            &result,
            ToDevice::HeldTaskResult { of, held_task }
                if of.as_str() == "tap" && held_task.state == HeldTaskState::Resumed
                    && held_task.title == "Task t1"
        ));
        hub.held_task_resume(
            &store,
            &phone,
            OWNER,
            MessageId::new("tap").unwrap(),
            resume("t1", 0),
        )
        .unwrap();
        assert_eq!(drain(&rx, 300), [result]);
        assert!(
            from_bridge
                .recv_timeout(Duration::from_millis(200))
                .is_err()
        );
        assert_eq!(
            resume_lines(&store),
            ["lab/main t1 requested", "lab/main t1 confirmed"]
        );
    }

    /// The host's person changed, then the runtime confirmed: the former
    /// one's device gets the fixed notice alone, never the new owner's card.
    #[test]
    fn a_result_after_the_hosts_person_changed_is_only_the_fixed_notice() {
        let (_dir, hub, store, phone, rx) = fixture();
        let (_plugin, from_bridge, connection, sent) = sent_resume(&hub, &store, &phone, &rx);
        let b = new_owners_device(&hub, &store);
        transfer_with_new_text(&hub, &store);
        assert!(carries_marker(&drain(&b, 100)), "the new owner's card");
        hub.held_task_resumed(&store, AGENT, &connection, &sent);
        assert_eq!(drain(&rx, 300), [notice("tap")]);
        assert!(
            from_bridge
                .recv_timeout(Duration::from_millis(200))
                .is_err()
        );
        assert_eq!(
            resume_lines(&store),
            ["lab/main t1 requested", "lab/main t1 confirmed"]
        );
    }

    /// The answer kept for a replay of plugin request `sent`.
    fn kept(hub: &Hub, sent: &MessageId) -> ToDevice {
        hub.held_tasks
            .lock()
            .unwrap()
            .completed
            .iter()
            .find(|(key, _, _)| key == sent.as_str())
            .map(|(_, _, answer)| answer.clone())
            .expect("a kept answer")
    }

    /// Held again since, by the new owner's runtime revision (`Ok(None)`):
    /// the answer kept for a replay holds no card of theirs.
    #[test]
    fn the_answer_kept_after_the_hosts_person_changed_holds_no_card_of_theirs() {
        let (_dir, hub, store, phone, rx) = fixture();
        let (_plugin, _from_bridge, connection, sent) = sent_resume(&hub, &store, &phone, &rx);
        transfer_with_new_text(&hub, &store);
        hub.held_task_resumed(&store, AGENT, &connection, &sent);
        assert_eq!(drain(&rx, 300), [notice("tap")]);
        assert_eq!(kept(&hub, &sent), notice("tap"));
    }

    /// Released since with the new owner's text, then confirmed
    /// (`Ok(Some)`): the card is resumed and sent to the new owner's
    /// devices; the former one's device gets, and keeps, only the notice.
    #[test]
    fn a_released_card_resumed_after_the_hosts_person_changed_goes_to_the_new_owner_alone() {
        let (_dir, hub, store, phone, rx) = fixture();
        let (_plugin, from_bridge, connection, sent) = sent_resume(&hub, &store, &phone, &rx);
        let b = new_owners_device(&hub, &store);
        transfer_with_new_text(&hub, &store);
        hub.held_tasks_report(&store, AGENT, vec![]).unwrap();
        assert_eq!(state(&store, "t1"), HeldTaskState::Released);
        drain(&b, 100);
        hub.held_task_resumed(&store, AGENT, &connection, &sent);
        assert_eq!(drain(&rx, 300), [notice("tap")]);
        assert_eq!(kept(&hub, &sent), notice("tap"));
        let theirs = drain(&b, 300);
        assert!(theirs.iter().any(|f| matches!(
            f,
            ToDevice::HeldTask { held_task }
                if held_task.state == HeldTaskState::Resumed && held_task.reason == MARKER
        )));
        assert!(
            !theirs
                .iter()
                .any(|f| matches!(f, ToDevice::HeldTaskResult { .. } | ToDevice::Error(_))),
            "the receipt is the asking device's alone"
        );
        assert!(
            from_bridge
                .recv_timeout(Duration::from_millis(200))
                .is_err()
        );
        assert_eq!(
            resume_lines(&store),
            ["lab/main t1 requested", "lab/main t1 confirmed"]
        );
    }

    /// The host's person changed at the same runtime revision, and the
    /// confirmation cannot be written: the former one's device gets, and
    /// keeps, only the notice; the resume is recorded later, for the new
    /// owner's devices.
    #[test]
    fn a_resume_that_cannot_be_recorded_after_the_hosts_person_changed_is_only_the_notice() {
        let (_dir, hub, store, phone, rx) = fixture();
        let (_plugin, from_bridge, connection, sent) = sent_resume(&hub, &store, &phone, &rx);
        let b = new_owners_device(&hub, &store);
        store.set_host(NEW_OWNER).unwrap();
        // The new owner's text, at the runtime revision the resume was sent at.
        rusqlite::Connection::open(&hub.store_path)
            .unwrap()
            .execute(
                "UPDATE held_tasks SET body = replace(body, 'Task t1', ?1)",
                [MARKER],
            )
            .unwrap();
        assert_eq!(
            store.held_task(AGENT, "t1").unwrap().unwrap().info.title,
            MARKER
        );
        block_writes(&hub);
        hub.held_task_resumed(&store, AGENT, &connection, &sent);
        assert_eq!(drain(&rx, 300), [notice("tap")]);
        assert_eq!(kept(&hub, &sent), notice("tap"));
        assert_eq!(state(&store, "t1"), HeldTaskState::Held, "not written yet");
        assert_eq!(hub.held_tasks.lock().unwrap().unrecorded.len(), 1);
        unblock_writes(&hub);
        hub.expire_held_resumes(&store);
        assert_eq!(state(&store, "t1"), HeldTaskState::Resumed);
        assert!(drain(&b, 300).iter().any(|f| matches!(
            f,
            ToDevice::HeldTask { held_task }
                if held_task.state == HeldTaskState::Resumed && held_task.title == MARKER
        )));
        assert!(drain(&rx, 200).is_empty());
        assert!(
            from_bridge
                .recv_timeout(Duration::from_millis(200))
                .is_err()
        );
        assert_eq!(
            resume_lines(&store),
            ["lab/main t1 requested", "lab/main t1 confirmed"]
        );
    }

    /// The runtime's refusal, written after the host's person changed:
    /// its text reaches neither the former one's device nor its replay.
    #[test]
    fn a_runtime_error_after_the_hosts_person_changed_is_only_the_notice() {
        let (_dir, hub, store, phone, rx) = fixture();
        let (_plugin, from_bridge, connection, sent) = sent_resume(&hub, &store, &phone, &rx);
        store.set_host(NEW_OWNER).unwrap();
        assert!(hub.held_task_error(
            &store,
            AGENT,
            &connection,
            &ErrorBody {
                of: Some(sent.clone()),
                code: ErrorCode::Conflict,
                message: format!("{MARKER}: written after the change"),
            },
        ));
        assert_eq!(drain(&rx, 300), [notice("tap")]);
        assert_eq!(kept(&hub, &sent), notice("tap"));
        hub.held_task_resume(
            &store,
            &phone,
            OWNER,
            MessageId::new("tap").unwrap(),
            resume("t1", 0),
        )
        .unwrap();
        assert_eq!(drain(&rx, 300), [notice("tap")]);
        assert!(
            from_bridge
                .recv_timeout(Duration::from_millis(200))
                .is_err()
        );
        assert_eq!(
            resume_lines(&store),
            ["lab/main t1 requested", "lab/main t1 answered conflict"]
        );
    }

    /// The card is no longer the asking person's, though they are still the
    /// host's: the runtime's refusal of the resume reaches their device only
    /// as the notice.
    #[test]
    fn a_runtime_error_for_a_card_now_anothers_is_only_the_notice() {
        let (_dir, hub, store, phone, rx) = fixture();
        let (_plugin, _from_bridge, connection, sent) = sent_resume(&hub, &store, &phone, &rx);
        rusqlite::Connection::open(&hub.store_path)
            .unwrap()
            .execute(
                "UPDATE conversations SET owner = ?1 WHERE id = ?2",
                [NEW_OWNER, home_id(AGENT).as_str()],
            )
            .unwrap();
        assert_eq!(store.host_person().unwrap().as_deref(), Some(OWNER));
        assert_eq!(
            store.held_task(AGENT, "t1").unwrap().unwrap().owner,
            NEW_OWNER
        );
        assert!(hub.held_task_error(
            &store,
            AGENT,
            &connection,
            &ErrorBody {
                of: Some(sent.clone()),
                code: ErrorCode::Internal,
                message: format!("{MARKER}: the runtime failed"),
            },
        ));
        assert_eq!(drain(&rx, 300), [notice("tap")]);
        assert_eq!(kept(&hub, &sent), notice("tap"));
    }

    /// While its resume is pending, the host's person changes to NEW_OWNER,
    /// whose text the card now holds, and the asking device's pairing is
    /// replaced, under the same id and person, by one `rekey` changes. The
    /// change of host alone would earn the notice; the old keys earn
    /// nothing: the device id under them is sent no frame at all, neither
    /// for the answer nor for a replay, and the runtime is not asked again.
    /// The card is NEW_OWNER's, so no ordinary publication reaches the
    /// device either.
    fn a_rekeyed_pairing_is_sent_no_answer(rekey: fn(&mut Device)) {
        let (_dir, hub, store, phone, rx) = fixture();
        let (_plugin, from_bridge, connection, sent) = sent_resume(&hub, &store, &phone, &rx);
        // Whatever the device was sent while the card was its person's.
        drain(&rx, 100);
        transfer_with_new_text(&hub, &store);
        let mut again = phone.clone();
        rekey(&mut again);
        assert!(store.remove_device(&phone.id).unwrap());
        store.add_device(&again).unwrap();
        let paired = store.device(&phone.id).unwrap().unwrap();
        assert_eq!(paired.person, OWNER);
        assert!(paired.noise_key != phone.noise_key || paired.device_key != phone.device_key);
        hub.held_task_resumed(&store, AGENT, &connection, &sent);
        assert_eq!(drain(&rx, 300), []);
        assert_eq!(kept(&hub, &sent), notice("tap"));
        hub.held_task_resume(
            &store,
            &phone,
            OWNER,
            MessageId::new("tap").unwrap(),
            resume("t1", 0),
        )
        .unwrap();
        assert_eq!(drain(&rx, 300), []);
        assert!(
            from_bridge
                .recv_timeout(Duration::from_millis(200))
                .is_err()
        );
        assert_eq!(
            resume_lines(&store),
            ["lab/main t1 requested", "lab/main t1 confirmed"]
        );
    }

    #[test]
    fn a_pairing_whose_noise_key_changed_is_sent_no_answer() {
        a_rekeyed_pairing_is_sent_no_answer(|d| d.noise_key = vec![77; 32]);
    }

    #[test]
    fn a_pairing_whose_device_key_changed_is_sent_no_answer() {
        a_rekeyed_pairing_is_sent_no_answer(|d| d.device_key = vec![88; 32]);
    }

    /// Whether any of `frames` answers a resume.
    fn answers(frames: &[ToDevice]) -> bool {
        frames
            .iter()
            .any(|f| matches!(f, ToDevice::HeldTaskResult { .. } | ToDevice::Error(_)))
    }

    /// `table` cannot be read once the resume was sent: whether the runtime
    /// confirmed (`refused` false) or refused it, the asking device is sent
    /// the notice alone, and it is what a replay gets.
    fn an_unreadable_table_answers_only_the_notice(table: &str, refused: bool) {
        let (_dir, hub, store, phone, rx) = fixture();
        let (_plugin, _from_bridge, connection, sent) = sent_resume(&hub, &store, &phone, &rx);
        break_table(&hub, table);
        if refused {
            assert!(hub.held_task_error(
                &store,
                AGENT,
                &connection,
                &ErrorBody {
                    of: Some(sent.clone()),
                    code: ErrorCode::Conflict,
                    message: format!("{MARKER}: the runtime refused"),
                },
            ));
        } else {
            hub.held_task_resumed(&store, AGENT, &connection, &sent);
        }
        let frames = drain(&rx, 300);
        assert_eq!(
            frames
                .iter()
                .filter(|f| answers(std::slice::from_ref(f)))
                .collect::<Vec<_>>(),
            [&notice("tap")],
            "{table}: {frames:?}"
        );
        assert_eq!(kept(&hub, &sent), notice("tap"), "{table}");
    }

    #[test]
    fn a_result_when_the_paired_devices_cannot_be_read_is_only_the_notice() {
        an_unreadable_table_answers_only_the_notice("devices", false);
    }

    #[test]
    fn a_runtime_error_when_the_paired_devices_cannot_be_read_is_only_the_notice() {
        an_unreadable_table_answers_only_the_notice("devices", true);
    }

    #[test]
    fn a_result_when_the_hosts_person_cannot_be_read_is_only_the_notice() {
        an_unreadable_table_answers_only_the_notice("settings", false);
    }

    #[test]
    fn a_runtime_error_when_the_hosts_person_cannot_be_read_is_only_the_notice() {
        an_unreadable_table_answers_only_the_notice("settings", true);
    }

    #[test]
    fn a_result_when_the_card_cannot_be_read_is_only_the_notice() {
        an_unreadable_table_answers_only_the_notice("held_tasks", false);
    }

    #[test]
    fn a_runtime_error_when_the_card_cannot_be_read_is_only_the_notice() {
        an_unreadable_table_answers_only_the_notice("held_tasks", true);
    }

    /// Answered while the asking person was the host's, then the host's
    /// person changed: the same request again gets only the notice, and the
    /// runtime is not asked again.
    #[test]
    fn a_replay_after_the_hosts_person_changed_is_only_the_notice() {
        let (_dir, hub, store, phone, rx) = fixture();
        let (_plugin, from_bridge, connection, sent) = sent_resume(&hub, &store, &phone, &rx);
        hub.held_task_resumed(&store, AGENT, &connection, &sent);
        assert!(matches!(
            drain(&rx, 300).last(),
            Some(ToDevice::HeldTaskResult { .. })
        ));
        transfer_with_new_text(&hub, &store);
        hub.held_task_resume(
            &store,
            &phone,
            OWNER,
            MessageId::new("tap").unwrap(),
            resume("t1", 0),
        )
        .unwrap();
        assert_eq!(drain(&rx, 300), [notice("tap")]);
        assert!(
            from_bridge
                .recv_timeout(Duration::from_millis(200))
                .is_err()
        );
        assert_eq!(
            resume_lines(&store),
            ["lab/main t1 requested", "lab/main t1 confirmed"]
        );
    }

    /// No answer in time, the host's person changed: the former one's
    /// device gets only the notice; the confirmation that comes late
    /// resumes the card for the new owner's devices and sends the former
    /// one's nothing; nothing reaches the runtime again.
    #[test]
    fn a_timeout_and_a_late_confirmation_after_the_hosts_person_changed() {
        let (_dir, hub, store, phone, rx) = fixture();
        let (_plugin, from_bridge, connection, sent) = sent_resume(&hub, &store, &phone, &rx);
        let b = new_owners_device(&hub, &store);
        store.set_host(NEW_OWNER).unwrap();
        for pending in hub.held_tasks.lock().unwrap().pending.values_mut() {
            pending.started -= TIMEOUT;
        }
        hub.expire_held_resumes(&store);
        assert_eq!(drain(&rx, 300), [notice("tap")]);
        assert_eq!(kept(&hub, &sent), notice("tap"));
        hub.held_task_resumed(&store, AGENT, &connection, &sent);
        assert_eq!(state(&store, "t1"), HeldTaskState::Resumed);
        assert!(drain(&b, 300).iter().any(|f| matches!(
            f,
            ToDevice::HeldTask { held_task } if held_task.state == HeldTaskState::Resumed
        )));
        assert!(drain(&rx, 200).is_empty());
        hub.held_task_resume(
            &store,
            &phone,
            OWNER,
            MessageId::new("tap").unwrap(),
            resume("t1", 0),
        )
        .unwrap();
        assert_eq!(drain(&rx, 300), [notice("tap")]);
        assert!(
            from_bridge
                .recv_timeout(Duration::from_millis(200))
                .is_err()
        );
        assert_eq!(
            resume_lines(&store),
            [
                "lab/main t1 requested",
                "lab/main t1 unknown: timed out",
                "lab/main t1 confirmed late"
            ]
        );
    }

    /// The agent's channel closed after the host's person changed: the
    /// former one's device gets only the notice.
    #[test]
    fn a_plugin_disconnect_after_the_hosts_person_changed_is_only_the_notice() {
        let (_dir, hub, store, phone, rx) = fixture();
        let (_plugin, _from_bridge, connection, sent) = sent_resume(&hub, &store, &phone, &rx);
        transfer_with_new_text(&hub, &store);
        hub.held_task_disconnected(&store, AGENT, &connection);
        assert_eq!(drain(&rx, 300), [notice("tap")]);
        assert_eq!(kept(&hub, &sent), notice("tap"));
        assert_eq!(
            resume_lines(&store),
            ["lab/main t1 requested", "lab/main t1 unknown: disconnected"]
        );
    }

    /// The asking device was not connected when the answer came, after the
    /// host's person changed: nothing is sent when it connects again, and
    /// the same request then gets only the notice, without the runtime.
    #[test]
    fn a_device_away_when_its_answer_came_gets_only_the_notice_when_it_asks_again() {
        let (_dir, hub, store, phone, rx) = fixture();
        let (_plugin, from_bridge, connection, sent) = sent_resume(&hub, &store, &phone, &rx);
        transfer_with_new_text(&hub, &store);
        hub.devices.lock().unwrap().remove(&phone.id);
        hub.held_task_resumed(&store, AGENT, &connection, &sent);
        assert!(drain(&rx, 200).is_empty());
        let (tx, back) = channel();
        hub.devices
            .lock()
            .unwrap()
            .insert(phone.id.clone(), (OWNER.into(), tx, 2));
        assert!(drain(&back, 300).is_empty(), "nothing on its own");
        hub.held_task_resume(
            &store,
            &phone,
            OWNER,
            MessageId::new("tap").unwrap(),
            resume("t1", 0),
        )
        .unwrap();
        assert_eq!(drain(&back, 300), [notice("tap")]);
        assert!(
            from_bridge
                .recv_timeout(Duration::from_millis(200))
                .is_err()
        );
    }
}
