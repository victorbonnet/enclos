//! Task details (`docs/protocol.md`, Task details; issue #318): a device's
//! `task.get`, passed live to the assignee's plugin, and its `task.detail`
//! passed back, cleaned, to that device alone. A read: the bridge keeps
//! none of it and logs nothing, and a request is never queued.
use super::*;
use std::time::Instant;

use enclos_protocol::plugin::{ErrorBody, ErrorCode};
use enclos_protocol::task_detail::TaskDetail;

/// Reads in flight, for all agents together.
const MAX_PENDING: usize = 64;
/// How long a read waits for the runtime's answer.
const TIMEOUT: Duration = Duration::from_secs(15);

struct Pending {
    device: String,
    device_key: Vec<u8>,
    noise_key: Vec<u8>,
    person: String,
    agent: String,
    task: String,
    connection: String,
    original: MessageId,
    started: Instant,
}

#[derive(Default)]
pub(super) struct TaskDetailRequests {
    /// By the plugin request's id.
    pending: HashMap<String, Pending>,
}

fn failure(of: MessageId, code: ErrorCode, message: impl Into<String>) -> ErrorBody {
    ErrorBody {
        of: Some(of),
        code,
        message: message.into(),
    }
}

struct TaskRead {
    agent: String,
    task: String,
    held: bool,
}

impl Hub {
    /// A device's `task.get` for `task` of `agent` (`<sandbox>/<agent>`).
    /// `Err` is the answer to send now, with nothing sent to the plugin;
    /// `Ok` once the plugin was asked (its answer comes later).
    pub(super) fn task_get(
        self: &Arc<Self>,
        store: &Store,
        device: &Device,
        person: &str,
        original: MessageId,
        agent: String,
        task: String,
    ) -> Result<(), ErrorBody> {
        self.read_task_details(
            store,
            device,
            person,
            original,
            TaskRead {
                agent,
                task,
                held: false,
            },
        )
    }
    pub(super) fn held_task_get(
        self: &Arc<Self>,
        store: &Store,
        device: &Device,
        person: &str,
        original: MessageId,
        agent: String,
        task: String,
    ) -> Result<(), ErrorBody> {
        self.read_task_details(
            store,
            device,
            person,
            original,
            TaskRead {
                agent,
                task,
                held: true,
            },
        )
    }
    fn read_task_details(
        self: &Arc<Self>,
        store: &Store,
        device: &Device,
        person: &str,
        original: MessageId,
        target: TaskRead,
    ) -> Result<(), ErrorBody> {
        let TaskRead { agent, task, held } = target;
        // Only the host's person sees tasks: a task can name repository
        // paths and internal plans, and so can its detail.
        self.host_authority(store, device, person)
            .map_err(|(code, why)| failure(original.clone(), code, why))?;
        if !self.serves(&agent) {
            return Err(failure(original, ErrorCode::UnknownAgent, "No such agent."));
        }
        // Only a task the bridge keeps, so only one the assignee's own
        // plugin reported as its own.
        let known = if held {
            store
                .held_task(&agent, &task)
                .map(|card| card.is_some_and(|card| card.owner == person))
        } else {
            store.keeps_task(&agent, &task)
        };
        match known {
            Ok(true) => {}
            Ok(false) => return Err(failure(original, ErrorCode::NotFound, "No such task.")),
            Err(e) => {
                eprintln!("enclos app: cannot read the tasks of {agent}: {e}");
                return Err(failure(
                    original,
                    ErrorCode::Internal,
                    "The bridge could not read its database. Try again.",
                ));
            }
        }
        // Opened if it is not: the read is live, but the connection may
        // simply not be open yet.
        let opened = self.plugin(&agent);
        let found = {
            let plugins = self.plugins.lock().expect("not poisoned");
            plugins.get(&agent).map(|plugin| {
                (
                    Arc::clone(&plugin.out),
                    plugin.capabilities.contains(if held {
                        &Capability::HeldTaskDetails
                    } else {
                        &Capability::TaskDetails
                    }),
                )
            })
        };
        let out = match found {
            Some((out, true)) => out,
            Some((_, false)) => {
                return Err(failure(
                    original,
                    ErrorCode::Unsupported,
                    "The agent's runtime does not share task details.",
                ));
            }
            None => {
                let why = opened.err().unwrap_or_else(|| "it closed".into());
                return Err(failure(
                    original,
                    ErrorCode::AgentUnavailable,
                    format!("The agent's channel cannot be reached ({why})."),
                ));
            }
        };
        let connection = self.agent_connection(&agent).ok_or_else(|| {
            failure(
                original.clone(),
                ErrorCode::AgentUnavailable,
                "The agent's channel is disconnected.",
            )
        })?;
        let rpc = new_id()
            .ok()
            .and_then(|id| MessageId::new(format!("task-{id}")).ok())
            .ok_or_else(|| {
                failure(
                    original.clone(),
                    ErrorCode::Internal,
                    "The bridge could not make a request id.",
                )
            })?;
        {
            let mut requests = self.task_details.lock().expect("not poisoned");
            if requests.pending.len() >= MAX_PENDING {
                return Err(failure(
                    original,
                    ErrorCode::Busy,
                    "Too many task details are being read. Try again shortly.",
                ));
            }
            requests.pending.insert(
                rpc.to_string(),
                Pending {
                    device: device.id.clone(),
                    device_key: device.device_key.clone(),
                    noise_key: device.noise_key.clone(),
                    person: person.into(),
                    agent: agent.clone(),
                    task: task.clone(),
                    connection,
                    original: original.clone(),
                    started: Instant::now(),
                },
            );
        }
        let sent = out
            .lock()
            .expect("not poisoned")
            .writer
            .send_with_id(rpc.clone(), FromBridge::TaskGet { task, held });
        if let Err(e) = sent {
            self.task_details
                .lock()
                .expect("not poisoned")
                .pending
                .remove(rpc.as_str());
            return Err(failure(
                original,
                ErrorCode::AgentUnavailable,
                format!("The agent's channel cannot be reached ({e})."),
            ));
        }
        Ok(())
    }

    /// Takes the read `of` names, if it was sent to `agent` on `connection`.
    fn take_task_get(&self, agent: &str, connection: &str, of: &MessageId) -> Option<Pending> {
        let mut requests = self.task_details.lock().expect("not poisoned");
        let ours = requests
            .pending
            .get(of.as_str())
            .is_some_and(|p| p.agent == agent && p.connection == connection);
        if !ours {
            return None;
        }
        requests.pending.remove(of.as_str())
    }

    /// The plugin's `task.detail`: cleaned by the bridge itself, its names
    /// made `<sandbox>/<agent>`, and passed to the device that asked.
    pub(super) fn task_detail_answered(
        &self,
        store: &Store,
        agent: &str,
        connection: &str,
        of: &MessageId,
        detail: TaskDetail,
    ) {
        let Some(pending) = self.take_task_get(agent, connection, of) else {
            // Late, after its time, or never asked on this connection.
            return;
        };
        let (sandbox, _) = agent.split_once('/').unwrap_or((agent, ""));
        let detail = detail.cleaned(now(), sandbox, |address| self.serves(address));
        let answer = ToDevice::TaskDetail {
            of: pending.original.clone(),
            agent: pending.agent.clone(),
            task: pending.task.clone(),
            detail,
        };
        self.deliver_task_device(store, &pending, answer);
    }

    /// A plugin's `error` naming a read: passed on to the device with its
    /// code, its message bounded. Whether it named one.
    pub(super) fn task_detail_error(
        &self,
        store: &Store,
        agent: &str,
        connection: &str,
        error: &ErrorBody,
    ) -> bool {
        let Some(of) = &error.of else { return false };
        let Some(pending) = self.take_task_get(agent, connection, of) else {
            return false;
        };
        let answer = ToDevice::Error(ErrorBody {
            of: Some(pending.original.clone()),
            code: error.code,
            message: error.message.chars().take(1000).collect(),
        });
        self.deliver_task_device(store, &pending, answer);
        true
    }

    /// The agent's channel closed: the reads sent on it get no answer.
    pub(super) fn task_details_disconnected(&self, store: &Store, agent: &str, connection: &str) {
        let pending: Vec<Pending> = {
            let mut requests = self.task_details.lock().expect("not poisoned");
            let keys: Vec<String> = requests
                .pending
                .iter()
                .filter(|(_, p)| p.agent == agent && p.connection == connection)
                .map(|(k, _)| k.clone())
                .collect();
            keys.iter()
                .filter_map(|k| requests.pending.remove(k))
                .collect()
        };
        for p in pending {
            let answer = ToDevice::Error(failure(
                p.original.clone(),
                ErrorCode::AgentUnavailable,
                "The agent's channel closed before it answered. Try again.",
            ));
            self.deliver_task_device(store, &p, answer);
        }
    }

    /// Every second: ends the reads the runtime left unanswered.
    pub(super) fn expire_task_gets(&self, store: &Store) {
        let pending: Vec<Pending> = {
            let mut requests = self.task_details.lock().expect("not poisoned");
            let keys: Vec<String> = requests
                .pending
                .iter()
                .filter(|(_, p)| p.started.elapsed() >= TIMEOUT)
                .map(|(k, _)| k.clone())
                .collect();
            keys.iter()
                .filter_map(|k| requests.pending.remove(k))
                .collect()
        };
        for p in pending {
            let answer = ToDevice::Error(failure(
                p.original.clone(),
                ErrorCode::AgentUnavailable,
                "The agent did not answer in time. Try again.",
            ));
            self.deliver_task_device(store, &p, answer);
        }
    }

    /// Sends `answer` to the device that asked, if it is still connected
    /// and still paired to the same person.
    fn deliver_task_device(&self, store: &Store, pending: &Pending, answer: ToDevice) {
        if store.host_person().ok().flatten().as_deref() != Some(pending.person.as_str()) {
            return;
        }
        let answer = match store.devices() {
            Ok(devices)
                if devices.iter().any(|d| {
                    d.id == pending.device
                        && d.person == pending.person
                        && d.device_key == pending.device_key
                        && d.noise_key == pending.noise_key
                }) =>
            {
                answer
            }
            Ok(_) => return,
            Err(e) => {
                eprintln!(
                    "enclos app: cannot read the paired devices to answer {}: {e}",
                    pending.device
                );
                ToDevice::Error(failure(
                    pending.original.clone(),
                    ErrorCode::Internal,
                    "The bridge could not check this device's pairing. Try again.",
                ))
            }
        };
        if let Some((owner, sender, _)) = self
            .devices
            .lock()
            .expect("not poisoned")
            .get(&pending.device)
            && owner == &pending.person
        {
            let _ = sender.send(answer);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use enclos_protocol::plugin::decode_from_bridge;
    use enclos_protocol::task::{Task, TaskState};
    use enclos_protocol::task_detail::{HistoryEntry, HistoryKind, TaskComment};
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

    fn plugin_frame(rx: &Receiver<Envelope<FromBridge>>) -> Envelope<FromBridge> {
        rx.recv_timeout(Duration::from_secs(5))
            .expect("a frame for the plugin")
    }

    fn nothing_for_the_plugin(rx: &Receiver<Envelope<FromBridge>>) {
        assert!(rx.recv_timeout(Duration::from_millis(300)).is_err());
    }

    /// A plugin with `capabilities` that reported task `t1`: the report's
    /// ack and the task's frame already read.
    fn reported(
        hub: &Arc<Hub>,
        rx: &Receiver<ToDevice>,
        capabilities: Vec<Capability>,
    ) -> (UnixStream, Receiver<Envelope<FromBridge>>) {
        let (mut plugin, from_bridge) = fake_plugin(hub, capabilities);
        say(
            &mut plugin,
            "report-1",
            FromPlugin::TaskUpdate {
                task: Task {
                    id: "t1".into(),
                    title: "Fix the login page".into(),
                    assignee: "main".into(),
                    asked_by: Some("lead".into()),
                    conversation: None,
                    state: TaskState::Running,
                    since: 1_763_000_000,
                    summary: None,
                    comments: Some(2),
                },
            },
        );
        assert!(matches!(
            plugin_frame(&from_bridge).body,
            FromBridge::Ack { .. }
        ));
        assert!(matches!(next(rx), ToDevice::Task { task } if task.comments == Some(2)));
        (plugin, from_bridge)
    }

    fn asked(from_bridge: &Receiver<Envelope<FromBridge>>) -> MessageId {
        let sent = plugin_frame(from_bridge);
        let FromBridge::TaskGet { task, .. } = sent.body else {
            panic!("a task.get for the plugin");
        };
        assert_eq!(task, "t1");
        sent.id
    }

    fn get(hub: &Arc<Hub>, store: &Store, phone: &Device, id: &str) -> Result<(), ErrorBody> {
        hub.task_get(
            store,
            phone,
            &phone.person,
            MessageId::new(id).unwrap(),
            AGENT.into(),
            "t1".into(),
        )
    }

    #[test]
    fn a_kept_tasks_detail_reaches_the_device_that_asked_cleaned_and_named() {
        let (_dir, hub, store, phone, rx) = fixture();
        let (mut plugin, from_bridge) =
            reported(&hub, &rx, vec![Capability::Tasks, Capability::TaskDetails]);
        get(&hub, &store, &phone, "open-1").unwrap();
        let of = asked(&from_bridge);
        say(
            &mut plugin,
            "detail-1",
            FromPlugin::TaskDetail {
                of,
                detail: TaskDetail {
                    body: Some("Fix it\u{202E}\n\n\n\nthen test".into()),
                    comments: vec![
                        TaskComment {
                            author: "main".into(),
                            agent: Some("lab/elsewhere".into()),
                            time: 5,
                            text: "On it".into(),
                        },
                        TaskComment {
                            author: "victor".into(),
                            agent: None,
                            time: 6,
                            text: "Thanks".into(),
                        },
                    ],
                    comments_total: 2,
                    history: vec![HistoryEntry {
                        kind: HistoryKind::Attempt,
                        time: 4,
                        until: None,
                        outcome: None,
                        by: Some("main".into()),
                        text: None,
                    }],
                    ..Default::default()
                },
            },
        );
        let ToDevice::TaskDetail {
            of,
            agent,
            task,
            detail,
        } = next(&rx)
        else {
            panic!("the task's detail");
        };
        assert_eq!(
            (of.as_str(), agent.as_str(), task.as_str()),
            ("open-1", AGENT, "t1")
        );
        assert_eq!(detail.body.as_deref(), Some("Fix it\n\nthen test"));
        // An agent the host serves is named; a person, or a name the
        // plugin claims, is not.
        assert_eq!(detail.comments[0].agent.as_deref(), Some(AGENT));
        assert_eq!(detail.comments[1].agent, None);
        assert_eq!(detail.history[0].by.as_deref(), Some(AGENT));
        // An answer to a read never sent goes nowhere.
        say(
            &mut plugin,
            "detail-2",
            FromPlugin::TaskDetail {
                of: MessageId::new("task-unknown").unwrap(),
                detail: TaskDetail::default(),
            },
        );
        assert!(rx.recv_timeout(Duration::from_millis(300)).is_err());
    }

    #[test]
    fn only_the_hosts_person_reads_a_task_the_bridge_keeps() {
        let (_dir, hub, store, phone, rx) = fixture();
        let (_plugin, from_bridge) =
            reported(&hub, &rx, vec![Capability::Tasks, Capability::TaskDetails]);
        let guest = device("tablet", GUEST);
        store.add_device(&guest).unwrap();
        let refused = get(&hub, &store, &guest, "g-1").unwrap_err();
        assert_eq!(refused.code, ErrorCode::NotAllowed);
        assert_eq!(refused.of.unwrap().as_str(), "g-1");
        let unknown_task = hub
            .task_get(
                &store,
                &phone,
                OWNER,
                MessageId::new("o-1").unwrap(),
                AGENT.into(),
                "t9".into(),
            )
            .unwrap_err();
        assert_eq!(unknown_task.code, ErrorCode::NotFound);
        let unknown_agent = hub
            .task_get(
                &store,
                &phone,
                OWNER,
                MessageId::new("o-2").unwrap(),
                "lab/other".into(),
                "t1".into(),
            )
            .unwrap_err();
        assert_eq!(unknown_agent.code, ErrorCode::UnknownAgent);
        nothing_for_the_plugin(&from_bridge);
    }

    #[test]
    fn a_channel_without_task_details_is_not_asked() {
        let (_dir, hub, store, phone, rx) = fixture();
        let (_plugin, from_bridge) = reported(&hub, &rx, vec![Capability::Tasks]);
        let error = get(&hub, &store, &phone, "open-1").unwrap_err();
        assert_eq!(error.code, ErrorCode::Unsupported);
        nothing_for_the_plugin(&from_bridge);
    }

    #[test]
    fn the_runtimes_refusal_a_silence_and_a_closed_channel_reach_the_device() {
        let (_dir, hub, store, phone, rx) = fixture();
        let (mut plugin, from_bridge) =
            reported(&hub, &rx, vec![Capability::Tasks, Capability::TaskDetails]);

        get(&hub, &store, &phone, "open-1").unwrap();
        let of = asked(&from_bridge);
        say(
            &mut plugin,
            "error-1",
            FromPlugin::Error(ErrorBody {
                of: Some(of),
                code: ErrorCode::NotFound,
                message: "No such task on the board.".into(),
            }),
        );
        let ToDevice::Error(refused) = next(&rx) else {
            panic!("the runtime's refusal");
        };
        assert_eq!(
            (refused.of.unwrap().as_str(), refused.code),
            ("open-1", ErrorCode::NotFound)
        );

        get(&hub, &store, &phone, "open-2").unwrap();
        asked(&from_bridge);
        // Its time passed.
        for pending in hub.task_details.lock().unwrap().pending.values_mut() {
            pending.started -= TIMEOUT;
        }
        hub.expire_task_gets(&store);
        let ToDevice::Error(late) = next(&rx) else {
            panic!("the timeout");
        };
        assert_eq!(
            (late.of.unwrap().as_str(), late.code),
            ("open-2", ErrorCode::AgentUnavailable)
        );

        get(&hub, &store, &phone, "open-3").unwrap();
        asked(&from_bridge);
        plugin.shutdown(std::net::Shutdown::Both).unwrap();
        let ToDevice::Error(closed) = next(&rx) else {
            panic!("the closed channel");
        };
        assert_eq!(
            (closed.of.unwrap().as_str(), closed.code),
            ("open-3", ErrorCode::AgentUnavailable)
        );
        assert!(hub.task_details.lock().unwrap().pending.is_empty());
    }
    #[test]
    fn held_detail_reads_the_exact_creator_reference_without_resuming() {
        let (_dir, hub, store, phone, rx) = fixture();
        let (mut plugin, from_bridge) = fake_plugin(&hub, vec![Capability::HeldTaskDetails]);
        store.ensure_home(AGENT, OWNER, true).unwrap();
        let home = crate::bridge::store::home_id(AGENT);
        let task: enclos_protocol::held_task::HeldTask =
            serde_json::from_value(serde_json::json!({
                "task":"app/t1", "title":"Review", "reason":"Needs a decision", "since":1,
                "revision":"v1", "resume":"Review on board", "resumable":false
            }))
            .unwrap();
        store
            .report_held_tasks(AGENT, home.as_str(), &[task])
            .unwrap();
        let before = store.held_task(AGENT, "app/t1").unwrap().unwrap();
        let read = |phone: &Device, reference: &str| {
            hub.held_task_get(
                &store,
                phone,
                &phone.person,
                MessageId::new("read-held").unwrap(),
                AGENT.into(),
                reference.into(),
            )
        };
        let guest = device("guest", "guest@example.com");
        store.add_device(&guest).unwrap();
        assert_eq!(
            read(&guest, "app/t1").unwrap_err().code,
            ErrorCode::NotAllowed
        );
        assert_eq!(read(&phone, "t1").unwrap_err().code, ErrorCode::NotFound);
        read(&phone, "app/t1").unwrap();
        let frame = plugin_frame(&from_bridge);
        assert!(matches!(frame.body, FromBridge::TaskGet {task,held:true} if task == "app/t1"));
        say(
            &mut plugin,
            "held-detail",
            FromPlugin::TaskDetail {
                of: frame.id,
                detail: TaskDetail {
                    body: Some("Description".into()),
                    ..Default::default()
                },
            },
        );
        assert!(
            matches!(next(&rx),ToDevice::TaskDetail{task,detail,..} if task == "app/t1" && detail.body.as_deref()==Some("Description"))
        );
        assert_eq!(store.held_task(AGENT, "app/t1").unwrap().unwrap(), before);
    }
}
