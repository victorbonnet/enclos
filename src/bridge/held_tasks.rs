//! Held tasks (ADR 0066, proposed; `docs/protocol.md`, Held tasks): the
//! cards of a runtime's stopped background work, and the one control, a
//! resume from the host's person, passed live to the plugin and never
//! queued.
use super::*;
use std::collections::VecDeque;
use std::time::Instant;

use super::super::store::{HeldTaskChange, StoredHeldTask};
use enclos_protocol::HeldTaskId;
use enclos_protocol::held_task::{HeldTask, HeldTaskState, check_snapshot};
use enclos_protocol::plugin::{ErrorBody, ErrorCode};
use sha2::{Digest, Sha256};

/// Resumes in flight, for all agents together.
const MAX_PENDING: usize = 64;
const MAX_COMPLETED: usize = 64;
/// How long a resume waits for the runtime's answer.
const TIMEOUT: Duration = Duration::from_secs(25);

const NOT_READ: &str =
    "The bridge could not read its database, so nothing was sent to the agent. Try again.";
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
    connection: String,
    original: MessageId,
    request: ResumeRequest,
    started: Instant,
}

#[derive(Default)]
pub(super) struct HeldTaskRequests {
    /// Each agent's current plugin connection, as `held_task_connected` saw it.
    connections: HashMap<String, String>,
    pending: HashMap<String, Pending>,
    /// Answered resumes: a device that sends the same request again gets the
    /// same answer, and the runtime is not asked twice.
    completed: VecDeque<(String, ResumeRequest, ToDevice)>,
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

/// Records a resume in the bridge's log: once when it is sent, once with
/// its outcome. The work runs again, unattended, after the person's tap.
fn audit(store: &Store, pending: &Pending, outcome: &str) {
    let reason = format!(
        "{} {} {outcome}",
        pending.request.agent, pending.request.task
    );
    if let Err(e) = store.log(
        Some(&pending.device),
        Some(&pending.person),
        "held_task.resume",
        Some(&reason),
    ) {
        eprintln!(
            "enclos app: cannot log a held task's resume for {}: {e}",
            pending.request.agent
        );
    }
}

fn code_name(code: ErrorCode) -> String {
    serde_json::to_value(code)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_default()
}

impl Hub {
    /// An agent's channel connected on `connection`. One without
    /// `held_tasks` can neither report nor resume: its held cards expire.
    pub(super) fn held_task_connected(
        &self,
        store: Option<&Store>,
        agent: &str,
        connection: &str,
        capabilities: &[Capability],
    ) {
        self.held_tasks
            .lock()
            .expect("not poisoned")
            .connections
            .insert(agent.into(), connection.into());
        let Some(store) = store else { return };
        if !capabilities.contains(&Capability::HeldTasks) {
            match store.expire_held_tasks(agent) {
                Ok(changes) => self.publish_held(store, changes),
                Err(e) => eprintln!("enclos app: {agent}'s held tasks could not expire: {e}"),
            }
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
        check_snapshot(&tasks).map_err(|why| (ErrorCode::BadMessage, why))?;
        let tasks: Vec<HeldTask> = tasks.into_iter().map(HeldTask::normalized).collect();
        let home = ConversationId::new(home_id(agent)).map_err(|e| {
            (
                ErrorCode::BadMessage,
                format!("its Home's id is refused: {e}"),
            )
        })?;
        let host = store.host_person().map_err(|e| {
            eprintln!("enclos app: {agent}'s held tasks: {e}");
            (
                ErrorCode::Internal,
                "The bridge could not store the held tasks.".to_owned(),
            )
        })?;
        // A Home not made would hide the cards from every device.
        let changes = store
            .ensure_home(agent, host.as_deref().unwrap_or(""), host.is_some())
            .and_then(|_| store.report_held_tasks(agent, home.as_str(), &tasks))
            .map_err(|e| {
                eprintln!("enclos app: {agent}'s held tasks could not be stored: {e}");
                (
                    ErrorCode::Internal,
                    "The bridge could not store the held tasks.".to_owned(),
                )
            })?;
        // A task held waits for the person: an archived Home cannot be (ADR
        // 0049), so nothing to bring back.
        self.publish_held(store, changes);
        Ok(())
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
        for change in changes {
            let owner = change.card.owner.clone();
            let mut frames = vec![ToDevice::HeldTask {
                held_task: change.card.info,
            }];
            if let Some(message) = change.message {
                match message_frame(store, message) {
                    Ok(frame) => frames.push(frame),
                    Err(e) => eprintln!("enclos app: a held task's message could not be read: {e}"),
                }
            }
            let devices = self.devices.lock().expect("not poisoned");
            for (device, (person, sender, _)) in devices.iter() {
                if *person == owner && paired.iter().any(|d| d.id == *device && d.person == owner) {
                    for frame in &frames {
                        if fits_device(frame) {
                            let _ = sender.send(frame.clone());
                        }
                    }
                }
            }
        }
    }

    /// The card a resume names, if `person` may resume it at `revision`;
    /// otherwise the code to answer, with nothing sent to the plugin.
    fn resume_authority(
        &self,
        store: &Store,
        device: &Device,
        person: &str,
        request: &ResumeRequest,
    ) -> Result<StoredHeldTask, (ErrorCode, String)> {
        self.host_authority(store, device, person)?;
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
        if card.info.state != HeldTaskState::Held || card.info.revision != request.revision {
            return Err((
                ErrorCode::Conflict,
                "The task changed since its card was shown. Refresh before deciding again.".into(),
            ));
        }
        Ok(card)
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
                self.deliver_held_device(store, &device.id, person, answer);
                return Ok(());
            }
            if requests.pending.contains_key(rpc.as_str()) {
                return Ok(());
            }
        }
        let card = self
            .resume_authority(store, device, person, &request)
            .map_err(|(code, why)| failure(original.clone(), code, why))?;
        let requester = Person::new(person)
            .map_err(|e| failure(original.clone(), ErrorCode::BadMessage, e.to_string()))?;
        // Opened if it is not: a resume is live, but the connection may
        // simply not be open yet.
        let _ = self.plugin(&request.agent);
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
                    ErrorCode::AgentUnavailable,
                    "The agent's channel no longer reports held tasks.",
                ));
            }
            None => {
                return Err(failure(
                    original,
                    ErrorCode::AgentUnavailable,
                    "The agent's channel is disconnected. Nothing was sent.",
                ));
            }
        };
        let mut requests = self.held_tasks.lock().expect("not poisoned");
        // Another device thread may have claimed the same id meanwhile.
        if let Some(answer) = self.replayed(&requests, &rpc, &request, &original)? {
            drop(requests);
            self.deliver_held_device(store, &device.id, person, answer);
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
        let pending = Pending {
            device: device.id.clone(),
            person: person.into(),
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
            FromBridge::HeldTaskResume {
                task: request.task.clone(),
                revision: card.runtime_revision,
                person: requester,
                device: device.id.clone(),
            },
        );
        if let Err(e) = sent {
            let pending = self
                .held_tasks
                .lock()
                .expect("not poisoned")
                .pending
                .remove(rpc.as_str());
            if let Some(pending) = pending {
                audit(store, &pending, "unknown: not sent");
            }
            return Err(failure(
                original,
                ErrorCode::Unconfirmed,
                format!("{e}. {UNCONFIRMED}"),
            ));
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
        let same_id = |key: &str| key == rpc.as_str();
        if let Some(pending) = requests.pending.get(rpc.as_str())
            && pending.request != *request
        {
            return Err(failure(
                original.clone(),
                ErrorCode::Conflict,
                "This request id names another resume.",
            ));
        }
        match requests.completed.iter().find(|(key, _, _)| same_id(key)) {
            Some((_, done, _)) if done != request => Err(failure(
                original.clone(),
                ErrorCode::Conflict,
                "This request id names another resume.",
            )),
            Some((_, _, answer)) => Ok(Some(answer.clone())),
            None => Ok(None),
        }
    }

    /// Sends a resume's answer to the device that asked, if it is still
    /// paired to the same person.
    fn deliver_held_device(&self, store: &Store, device: &str, person: &str, answer: ToDevice) {
        match store.devices() {
            Ok(devices) if devices.iter().any(|d| d.id == device && d.person == person) => {}
            Ok(_) => return,
            Err(e) => {
                eprintln!("enclos app: cannot read the paired devices to answer {device}: {e}");
                return;
            }
        }
        if let Some((owner, sender, _)) = self.devices.lock().expect("not poisoned").get(device)
            && owner == person
        {
            let _ = sender.send(answer);
        }
    }

    /// Takes the pending resume `of` names, if it was sent on `connection`
    /// to `agent`.
    fn take_pending(
        &self,
        agent: &str,
        connection: &str,
        of: &MessageId,
    ) -> Option<(String, Pending)> {
        let mut requests = self.held_tasks.lock().expect("not poisoned");
        let ours = requests
            .pending
            .get(of.as_str())
            .is_some_and(|p| p.request.agent == agent && p.connection == connection);
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

    /// The plugin's `held_task.resumed`: the runtime resumed the task.
    pub(super) fn held_task_resumed(
        &self,
        store: &Store,
        agent: &str,
        connection: &str,
        of: &MessageId,
    ) {
        let Some((key, pending)) = self.take_pending(agent, connection, of) else {
            return;
        };
        let change = match store.resume_held_task(agent, pending.request.task.as_str()) {
            Ok(change) => change,
            Err(e) => {
                eprintln!("enclos app: {agent}'s resumed task could not be recorded: {e}");
                None
            }
        };
        audit(store, &pending, "confirmed");
        let card = match change {
            Some(change) => {
                let card = change.card.info.clone();
                self.publish_held(store, vec![change]);
                Some(card)
            }
            // Resumed already, or the card cannot be read: the runtime's
            // answer stands, and the card is sent as it is.
            None => store
                .held_task(agent, pending.request.task.as_str())
                .ok()
                .flatten()
                .map(|card| card.info),
        };
        let answer = match card {
            Some(held_task) => ToDevice::HeldTaskResult {
                of: pending.original.clone(),
                held_task,
            },
            None => ToDevice::Error(failure(
                pending.original.clone(),
                ErrorCode::Unconfirmed,
                "The agent resumed the task, but the bridge could not read its card.",
            )),
        };
        self.complete(key, &pending, &answer);
        self.deliver_held_device(store, &pending.device, &pending.person, answer);
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
        let Some((key, pending)) = self.take_pending(agent, connection, of) else {
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
        self.complete(key, &pending, &answer);
        self.deliver_held_device(store, &pending.device, &pending.person, answer);
        true
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
            .filter_map(|k| requests.pending.remove(&k))
            .collect();
        drop(requests);
        for p in pending {
            audit(store, &p, "unknown: disconnected");
            let answer = ToDevice::Error(failure(
                p.original.clone(),
                ErrorCode::Unconfirmed,
                format!("The agent disconnected. {UNCONFIRMED}"),
            ));
            self.deliver_held_device(store, &p.device, &p.person, answer);
        }
    }

    /// Ends the resumes the runtime left unanswered.
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
            .filter_map(|k| requests.pending.remove(&k))
            .collect();
        drop(requests);
        for p in pending {
            audit(store, &p, "unknown: timed out");
            let answer = ToDevice::Error(failure(
                p.original.clone(),
                ErrorCode::Unconfirmed,
                format!("The agent did not answer in time. {UNCONFIRMED}"),
            ));
            self.deliver_held_device(store, &p.device, &p.person, answer);
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
    use enclos_protocol::plugin::decode_from_bridge;
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
            revision: "e:7".into(),
            resume: "Runs it again with a fresh retry budget.".into(),
        }
    }

    /// A plugin on the agent's socket that announces `capabilities`: what
    /// the bridge sends it comes on the receiver; the stream writes to it.
    fn fake_plugin(
        hub: &Arc<Hub>,
        capabilities: Vec<Capability>,
    ) -> (UnixStream, Receiver<Envelope<FromBridge>>) {
        let listener = UnixListener::bind(&hub.agents[0].socket).unwrap();
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
        let (_dir, hub, store, _phone, _rx) = fixture();
        let (mut plugin, from_bridge) = fake_plugin(&hub, vec![Capability::HeldTasks]);
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
        assert!(store.held_tasks_for(OWNER).unwrap().is_empty());
    }

    #[test]
    fn a_sync_sends_held_cards_past_since_and_each_cards_state_before_its_lines() {
        use enclos_protocol::device::decode_to_device;
        use enclos_protocol::noise::{Initiator, Responder, generate_keypair};
        let (_dir, hub, store, phone, rx) = fixture();
        let home = home_id(AGENT);
        store
            .report_held_tasks(AGENT, &home, &[task("t1"), task("t2")])
            .unwrap();
        let introduced = store.newest_seq().unwrap();
        // t1 is no longer held: its quiet line comes after `introduced`.
        store
            .report_held_tasks(AGENT, &home, &[task("t2")])
            .unwrap();
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
                FromDevice::Sync { since },
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
        let held: Vec<_> = after
            .iter()
            .filter_map(|m| match m {
                ToDevice::HeldTask { held_task } if held_task.state == HeldTaskState::Held => {
                    Some(held_task.task.as_str())
                }
                _ => None,
            })
            .collect();
        assert_eq!(
            held,
            ["t2"],
            "a held card, though its message predates since"
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
}
