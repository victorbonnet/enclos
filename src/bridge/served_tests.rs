use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::sync::mpsc::Receiver;

use super::*;

const HOST: &str = "alice@example.com";

fn endpoint(dir: &Path, name: &str, token: &str) -> AgentEndpoint {
    AgentEndpoint {
        name: format!("lab/{name}"),
        runtime: "hermes".to_owned(),
        socket: dir.join(format!("{name}.sock")),
        token: token.to_owned(),
    }
}

/// What the stand-in for enclos's state answers.
type Answer = Result<Served, String>;

/// enclos's state as a test sets it, and its audit log.
struct State {
    answer: Arc<Mutex<Answer>>,
    changes: PathBuf,
}

impl State {
    fn new(dir: &Path, agents: Vec<AgentEndpoint>) -> State {
        let changes = dir.join("audit.jsonl");
        std::fs::write(&changes, "").unwrap();
        State {
            answer: Arc::new(Mutex::new(Ok(Served {
                agents,
                left_out: Vec::new(),
            }))),
            changes,
        }
    }

    fn source(&self) -> AgentSource {
        let answer = Arc::clone(&self.answer);
        AgentSource::new(self.changes.clone(), move || {
            match &*answer.lock().unwrap() {
                Ok(served) => Ok(Served {
                    agents: served.agents.clone(),
                    left_out: served.left_out.clone(),
                }),
                Err(why) => Err(why.clone()),
            }
        })
    }

    /// The state answers `answer` from now on, said by no audit entry.
    fn quietly(&self, answer: Answer) {
        *self.answer.lock().unwrap() = answer;
    }

    /// The state answers `agents`, after an audited change.
    fn set(&self, agents: Vec<AgentEndpoint>) {
        self.quietly(Ok(Served {
            agents,
            left_out: Vec::new(),
        }));
        self.audited();
    }

    fn audited(&self) {
        let mut log = std::fs::OpenOptions::new()
            .append(true)
            .open(&self.changes)
            .unwrap();
        writeln!(log, "{{}}").unwrap();
    }
}

/// A hub watching `state`, whose host's person has one connected device:
/// what it receives.
fn watching(dir: &Path, state: &State) -> (Arc<Hub>, Receiver<ToDevice>) {
    hub_for(dir, AgentWatch::start(state.source()).unwrap())
}

/// A hub serving `watch`'s agents, whose host's person has one connected
/// device: what it receives.
fn hub_for(dir: &Path, watch: AgentWatch) -> (Arc<Hub>, Receiver<ToDevice>) {
    let hub = Hub::new(
        Transport::Tailscale,
        Arc::new(|_: &str| Err("no transport in this test".to_owned())),
        dir.join("bridge.db"),
        crate::layout::Layout::at(dir.join("enclos")),
        vec![7; 32],
        Vec::new(),
        Some(HOST.to_owned()),
        Duration::from_secs(75),
    )
    .with_agent_watch(watch);
    let (sender, received) = channel();
    hub.devices
        .lock()
        .unwrap()
        .insert("d-1".to_owned(), (HOST.to_owned(), sender, 1));
    (Arc::new(hub), received)
}

fn served(hub: &Hub) -> Vec<String> {
    hub.agents().iter().map(|a| a.name.clone()).collect()
}

/// As if `hub` had just read its agents: a retry is not due yet, however
/// slow the test runs.
fn just_read(hub: &Hub) {
    hub.watch.as_ref().unwrap().seen.lock().unwrap().read_at = Instant::now();
}

/// The names of the next agents' list `device` is sent, within 5 seconds.
fn listed(device: &Receiver<ToDevice>) -> Vec<String> {
    loop {
        match device.recv_timeout(Duration::from_secs(5)).unwrap() {
            ToDevice::AgentsList { agents } => {
                return agents.into_iter().map(|a| a.agent).collect();
            }
            _ => continue,
        }
    }
}

/// What a stand-in plugin saw of one connection.
#[derive(Debug, PartialEq)]
enum Seen {
    Opened(String),
    Closed(String),
}

/// A stand-in plugin at `socket`: says hello on every connection, and
/// tells the test the token each came with, then that it closed.
fn plugin(socket: &Path) -> Receiver<Seen> {
    let listener = UnixListener::bind(socket).unwrap();
    let (seen, events) = channel();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { return };
            let seen = seen.clone();
            std::thread::spawn(move || {
                let mut out = stream.try_clone().unwrap();
                let mut lines = BufReader::new(stream);
                let mut line = Vec::new();
                lines.read_until(b'\n', &mut line).unwrap();
                let FromBridge::Hello { token, .. } =
                    enclos_protocol::plugin::decode_from_bridge(&line)
                        .unwrap()
                        .body
                else {
                    panic!("the bridge did not start with its hello");
                };
                let _ = seen.send(Seen::Opened(token.clone()));
                let id = MessageId::new(new_id().unwrap()).unwrap();
                out.write_all(&encode_line(&Envelope::new(
                    id,
                    FromPlugin::Hello {
                        runtime: "hermes".into(),
                        agent: "main".into(),
                        capabilities: Vec::new(),
                    },
                )))
                .unwrap();
                while lines.read_until(b'\n', &mut line).unwrap_or(0) > 0 {}
                let _ = seen.send(Seen::Closed(token));
            });
        }
    });
    events
}

fn next(events: &Receiver<Seen>) -> Seen {
    events.recv_timeout(Duration::from_secs(5)).unwrap()
}

/// Waits up to 5 seconds for `done`.
fn until(done: impl Fn() -> bool) {
    let started = Instant::now();
    while !done() {
        assert!(started.elapsed() < Duration::from_secs(5), "never came");
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn an_agent_given_an_app_channel_is_served_with_its_home_and_listed_to_devices() {
    let dir = tempfile::tempdir().unwrap();
    let state = State::new(dir.path(), vec![endpoint(dir.path(), "main", "t0ken")]);
    let (hub, device) = watching(dir.path(), &state);
    assert_eq!(served(&hub), ["lab/main"]);
    // Nothing audited: not read again, so not served yet.
    state.quietly(Ok(Served {
        agents: vec![
            endpoint(dir.path(), "main", "t0ken"),
            endpoint(dir.path(), "helper", "t0ken"),
        ],
        left_out: Vec::new(),
    }));
    hub.refresh_agents();
    assert_eq!(served(&hub), ["lab/main"]);
    assert!(device.try_recv().is_err());
    // Audited: served, with its Home the host's person's, and listed.
    state.audited();
    hub.refresh_agents();
    assert_eq!(served(&hub), ["lab/helper", "lab/main"]);
    assert_eq!(listed(&device), ["lab/helper", "lab/main"]);
    let store = hub.store().unwrap();
    assert!(store.home_of("lab/helper").unwrap().is_some());
    assert!(
        store.log_lines(10).unwrap().iter().any(
            |line| line.event == "agent served" && line.reason.as_deref() == Some("lab/helper")
        )
    );
    // Read again after an audited change that changes no agent: nothing
    // is sent again.
    state.audited();
    hub.refresh_agents();
    assert!(device.try_recv().is_err());
}

#[test]
fn an_agent_whose_grant_is_dropped_is_no_longer_served_and_its_connection_ends() {
    let dir = tempfile::tempdir().unwrap();
    let main = endpoint(dir.path(), "main", "t0ken");
    let helper = endpoint(dir.path(), "helper", "t0ken");
    let state = State::new(dir.path(), vec![main.clone(), helper.clone()]);
    let (hub, device) = watching(dir.path(), &state);
    let events = plugin(&helper.socket);
    hub.plugin("lab/helper").unwrap();
    assert_eq!(next(&events), Seen::Opened("t0ken".to_owned()));

    state.set(vec![main]);
    hub.refresh_agents();
    assert_eq!(served(&hub), ["lab/main"]);
    assert_eq!(next(&events), Seen::Closed("t0ken".to_owned()));
    assert_eq!(listed(&device), ["lab/main"]);
    until(|| !hub.plugins.lock().unwrap().contains_key("lab/helper"));
    // Not opened again, by a message or the background pass.
    assert!(hub.plugin("lab/helper").is_err());
    assert!(!hub.sees_agent(HOST, "lab/helper"));
    assert!(
        hub.store()
            .unwrap()
            .log_lines(10)
            .unwrap()
            .iter()
            .any(|line| line.event == "agent no longer served"
                && line.reason.as_deref() == Some("lab/helper"))
    );
}

#[test]
fn a_rotated_token_is_used_without_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    let state = State::new(dir.path(), vec![endpoint(dir.path(), "main", "t0ken")]);
    let (hub, _device) = watching(dir.path(), &state);
    let events = plugin(&dir.path().join("main.sock"));
    // Opened by this test alone, not by a pass of `open_plugins` too.
    hub.opening_all.store(true, Ordering::SeqCst);
    hub.plugin("lab/main").unwrap();
    assert_eq!(next(&events), Seen::Opened("t0ken".to_owned()));

    state.set(vec![endpoint(dir.path(), "main", "n3w-t0ken")]);
    hub.refresh_agents();
    // The connection opened with the old token ends, and the next one
    // opens with the new.
    assert_eq!(next(&events), Seen::Closed("t0ken".to_owned()));
    until(|| !hub.plugins.lock().unwrap().contains_key("lab/main"));
    hub.plugin("lab/main").unwrap();
    assert_eq!(next(&events), Seen::Opened("n3w-t0ken".to_owned()));
}

#[test]
fn a_connection_opened_with_an_endpoint_changed_meanwhile_is_not_kept() {
    let dir = tempfile::tempdir().unwrap();
    let state = State::new(dir.path(), vec![endpoint(dir.path(), "main", "t0ken")]);
    let (hub, _device) = watching(dir.path(), &state);
    let events = plugin(&dir.path().join("main.sock"));
    // No pass of `open_plugins` opens it meanwhile with the new token: as
    // if one were running already.
    hub.opening_all.store(true, Ordering::SeqCst);
    // Another opening of the agent's holds its turn: this one looks the
    // endpoint up, then waits, while the token changes.
    let turn = Arc::new(Mutex::new(()));
    hub.opening
        .lock()
        .unwrap()
        .insert("lab/main".to_owned(), Arc::clone(&turn));
    let held = turn.lock().unwrap();
    let opener = Arc::clone(&hub);
    let opening = std::thread::spawn(move || opener.plugin("lab/main"));
    // It holds the lock it waits on once it has looked the endpoint up:
    // the map's, the test's, and its own.
    until(|| Arc::strong_count(&turn) == 3);
    state.set(vec![endpoint(dir.path(), "main", "n3w-t0ken")]);
    hub.refresh_agents();
    drop(held);
    // It connects with the old token, then sees the change and ends.
    let result = opening.join().unwrap();
    assert_eq!(next(&events), Seen::Opened("t0ken".to_owned()));
    assert!(result.unwrap_err().contains("changed"), "kept");
    assert_eq!(next(&events), Seen::Closed("t0ken".to_owned()));
    assert!(!hub.plugins.lock().unwrap().contains_key("lab/main"));
}

#[test]
fn a_reading_that_fails_keeps_the_agents_served_and_is_tried_again() {
    let dir = tempfile::tempdir().unwrap();
    let main = endpoint(dir.path(), "main", "t0ken");
    let state = State::new(dir.path(), vec![main.clone()]);
    let (hub, device) = watching(dir.path(), &state);
    // enclos's state cannot be read: nothing changes.
    state.quietly(Err("database is locked".to_owned()));
    state.audited();
    hub.refresh_agents();
    assert_eq!(served(&hub), ["lab/main"]);
    assert!(device.try_recv().is_err());
    // Readable again, with no change audited since: read after a while.
    state.quietly(Ok(Served {
        agents: vec![main, endpoint(dir.path(), "helper", "t0ken")],
        left_out: Vec::new(),
    }));
    just_read(&hub);
    hub.refresh_agents();
    assert_eq!(served(&hub), ["lab/main"]);
    std::thread::sleep(RETRY_UNREAD);
    hub.refresh_agents();
    assert_eq!(served(&hub), ["lab/helper", "lab/main"]);
}

#[test]
fn a_token_that_cannot_be_read_now_keeps_its_agent_served_as_it_was() {
    let dir = tempfile::tempdir().unwrap();
    let main = endpoint(dir.path(), "main", "t0ken");
    let state = State::new(dir.path(), vec![main.clone()]);
    let (hub, device) = watching(dir.path(), &state);
    let left = |unreadable| LeftOut::Agent {
        agent: "lab/main".to_owned(),
        why: "the Keychain did not answer".to_owned(),
        unreadable,
    };
    // A store that does not answer: still served as before.
    state.quietly(Ok(Served {
        agents: Vec::new(),
        left_out: vec![left(true)],
    }));
    state.audited();
    hub.refresh_agents();
    assert!(*hub.agents() == vec![main.clone()]);
    assert!(device.try_recv().is_err());
    // The secret gone: no longer served.
    state.quietly(Ok(Served {
        agents: Vec::new(),
        left_out: vec![left(false)],
    }));
    state.audited();
    hub.refresh_agents();
    assert!(served(&hub).is_empty());
    assert!(listed(&device).is_empty());
}

#[test]
fn the_background_pass_reads_the_agents_again() {
    let dir = tempfile::tempdir().unwrap();
    let state = State::new(dir.path(), vec![endpoint(dir.path(), "main", "t0ken")]);
    let (hub, _device) = watching(dir.path(), &state);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    {
        let hub = Arc::clone(&hub);
        std::thread::spawn(move || serve_on(listener, hub, Duration::from_millis(100)));
    }
    state.set(vec![
        endpoint(dir.path(), "main", "t0ken"),
        endpoint(dir.path(), "helper", "t0ken"),
    ]);
    until(|| hub.serves("lab/helper"));
}

/// A store in memory whose reads fail while `.1` is set, as a Keychain
/// that does not answer does.
struct Unanswering(crate::secrets::InMemory, std::cell::Cell<bool>);

impl crate::secrets::SecretStore for Unanswering {
    fn name(&self) -> crate::model::secret::StoreName {
        self.0.name()
    }

    fn set(
        &self,
        secret: &crate::model::secret::SecretRef,
        value: &crate::model::secret::SecretValue,
    ) -> Result<(), crate::secrets::SecretError> {
        self.0.set(secret, value)
    }

    fn get(
        &self,
        secret: &crate::model::secret::SecretRef,
    ) -> Result<Option<crate::model::secret::SecretValue>, crate::secrets::SecretError> {
        if self.1.get() {
            return Err(crate::secrets::SecretError {
                what: "the store in memory does not answer".to_owned(),
                untouched: true,
            });
        }
        self.0.get(secret)
    }

    fn remove(
        &self,
        secret: &crate::model::secret::SecretRef,
    ) -> Result<bool, crate::secrets::SecretError> {
        self.0.remove(secret)
    }

    fn whereabouts(&self, secret: &crate::model::secret::SecretRef) -> String {
        self.0.whereabouts(secret)
    }

    fn removed_before_record(&self) -> bool {
        self.0.removed_before_record()
    }
}

/// An engine in `dir` whose secret store stands for the Keychain, with
/// sandbox `lab` made by `actor`.
fn lab_engine(
    dir: &Path,
) -> (
    crate::engine::Engine,
    std::rc::Rc<Unanswering>,
    crate::model::audit::Actor,
    crate::layout::Layout,
) {
    use crate::audit::jsonl::JsonlAuditLog;
    use crate::backend::fake::FakeBackend;
    use crate::engine::{Engine, SandboxSpec};
    use crate::model::agent::AgentRecord;
    use crate::model::runtime::RuntimeKind;
    use crate::model::{audit::Actor, plan::Confirm, sandbox::BackendKind};
    use crate::state::StateStore;
    use crate::state::sqlite::SqliteStateStore;

    let layout = crate::layout::Layout::at(dir.join("enclos"));
    let secrets = std::rc::Rc::new(Unanswering(Default::default(), Default::default()));
    let engine = Engine::new(
        layout.clone(),
        Box::new(SqliteStateStore::new(
            layout.state_db(),
            layout.state_lock(),
            crate::state::Wait::Command,
        )),
        Box::new(JsonlAuditLog::new(layout.audit_log())),
        vec![Box::new(FakeBackend::available(BackendKind::Seatbelt))],
    )
    .with_secrets(Box::new(std::rc::Rc::clone(&secrets)));
    let actor = Actor {
        user: HOST.into(),
        host: "test".into(),
    };
    engine.init(&actor, Confirm::Yes).unwrap();
    engine
        .create_sandbox(
            &actor,
            SandboxSpec {
                name: "lab".parse().unwrap(),
                backend: BackendKind::Seatbelt,
                template: "minimal".parse().unwrap(),
            },
            Confirm::Yes,
        )
        .unwrap();
    let state = SqliteStateStore::new(
        layout.state_db(),
        layout.state_lock(),
        crate::state::Wait::Command,
    );
    let lock = state.lock().unwrap();
    let lab = "lab".parse().unwrap();
    let mut record = state.get(&lab).unwrap().unwrap();
    record.runtime = Some(RuntimeKind::Hermes);
    state.put(&lock, &record).unwrap();
    state
        .insert_agent(
            &lock,
            &lab,
            &AgentRecord {
                name: "main".parse().unwrap(),
                created_at: crate::model::now(),
            },
        )
        .unwrap();
    (engine, secrets, actor, layout)
}

/// The engine's side, with a secret store standing for the Keychain: an
/// agent granted an app channel is read with its token; a store that does
/// not answer leaves it out as unreadable; a token not set, or a grant
/// dropped, leaves it out as gone. Each change is an audited write.
#[test]
fn the_state_gives_each_agent_with_an_app_channel_and_says_why_one_is_left_out() {
    use crate::model::plan::Confirm;
    use crate::model::secret::{SecretRef, SecretValue};

    let dir = tempfile::tempdir().unwrap();
    let (engine, secrets, actor, layout) = lab_engine(dir.path());
    let lab = "lab".parse().unwrap();
    let names = |served: &Served| -> Vec<(String, String)> {
        served
            .agents
            .iter()
            .map(|a| (a.name.clone(), a.token.clone()))
            .collect()
    };
    assert!(names(&super::served(&engine).unwrap()).is_empty());

    let gone = |read: &Served| {
        matches!(
            read.left_out.as_slice(),
            [LeftOut::Agent { agent, unreadable: false, .. }] if agent == "lab/main"
        )
    };
    let marked = mark(&layout.audit_log());
    let before = layout.read_policy("lab").unwrap();
    let granted = format!(
        "{before}\n[secrets.agents.main]\nenv = {{ MOBILE_APP_TOKEN = \"secret:lab/main-app\" }}\n"
    );
    let token: SecretRef = "lab/main-app".parse().unwrap();
    let set = |value: &str| {
        engine
            .secret_set(
                &actor,
                &token,
                Some(&SecretValue::new(value.into()).unwrap()),
                Confirm::Yes,
            )
            .unwrap();
    };
    set("t0ken");
    engine
        .policy_edit(&actor, &lab, &before, &granted, Confirm::Yes)
        .unwrap();
    assert_ne!(mark(&layout.audit_log()), marked);
    let read = super::served(&engine).unwrap();
    assert_eq!(read.agents.len(), 1);
    assert_eq!(names(&read), [("lab/main".to_owned(), "t0ken".to_owned())]);

    // Its token's value gone from the store: left out as gone, not kept.
    let kept = std::mem::take(&mut *secrets.0.0.borrow_mut());
    let read = super::served(&engine).unwrap();
    assert!(read.agents.is_empty());
    assert!(gone(&read), "not gone");
    *secrets.0.0.borrow_mut() = kept;

    // Rotated: read with its new value, after an audited write.
    let marked = mark(&layout.audit_log());
    set("n3w-t0ken");
    assert_ne!(mark(&layout.audit_log()), marked);
    assert_eq!(
        names(&super::served(&engine).unwrap()),
        [("lab/main".to_owned(), "n3w-t0ken".to_owned())]
    );

    // A store that does not answer: unreadable, not gone.
    secrets.1.set(true);
    let read = super::served(&engine).unwrap();
    assert!(read.agents.is_empty());
    assert!(
        matches!(
            read.left_out.as_slice(),
            [LeftOut::Agent {
                unreadable: true,
                ..
            }]
        ),
        "not unreadable"
    );
    secrets.1.set(false);

    // The grant dropped: not listed at all, after an audited write.
    let marked = mark(&layout.audit_log());
    engine
        .policy_edit(&actor, &lab, &granted, &before, Confirm::Yes)
        .unwrap();
    assert_ne!(mark(&layout.audit_log()), marked);
    let read = super::served(&engine).unwrap();
    assert!(read.agents.is_empty() && read.left_out.is_empty());
}

#[test]
fn a_sandbox_whose_policy_cannot_be_read_keeps_its_agents_served() {
    let dir = tempfile::tempdir().unwrap();
    let main = endpoint(dir.path(), "main", "t0ken");
    let other = AgentEndpoint {
        name: "prod/ops".to_owned(),
        ..endpoint(dir.path(), "ops", "t0ken")
    };
    let state = State::new(dir.path(), vec![main.clone(), other]);
    let (hub, device) = watching(dir.path(), &state);
    // `lab`'s policy cannot be read, and `prod`'s agent is gone: `lab`'s
    // agent stays served, `prod`'s does not.
    state.quietly(Ok(Served {
        agents: Vec::new(),
        left_out: vec![LeftOut::Sandbox {
            sandbox: "lab".to_owned(),
            why: "its policy cannot be read: database is locked".to_owned(),
        }],
    }));
    state.audited();
    hub.refresh_agents();
    assert_eq!(served(&hub), ["lab/main"]);
    assert_eq!(listed(&device), ["lab/main"]);
    // Readable again a while later, with no change audited.
    state.quietly(Ok(Served {
        agents: vec![main, endpoint(dir.path(), "helper", "t0ken")],
        left_out: Vec::new(),
    }));
    std::thread::sleep(RETRY_UNREAD);
    hub.refresh_agents();
    assert_eq!(served(&hub), ["lab/helper", "lab/main"]);
}

/// A policy that cannot be read is never taken for one that grants no app
/// channel: the reading fails, and the bridge serves its agents as they
/// were. (Listing the sandboxes reads their policies too, so a damaged one
/// fails the listing; one that fails after it, `LeftOut::Sandbox`, is
/// served as it was too: `a_sandbox_whose_policy_cannot_be_read_...`.)
#[test]
fn a_policy_that_cannot_be_read_fails_the_reading_rather_than_drop_agents() {
    let dir = tempfile::tempdir().unwrap();
    let (engine, _secrets, _actor, layout) = lab_engine(dir.path());
    let db = rusqlite::Connection::open(layout.state_db()).unwrap();
    db.execute("UPDATE policy_snapshots SET policy = 'not a policy'", [])
        .unwrap();
    let Err(why) = super::served(&engine) else {
        panic!("read as a sandbox with no agent");
    };
    assert!(why.contains("cannot read"), "{why}");
}

#[test]
fn an_unreadable_sandbox_covers_its_own_agents_alone() {
    let lab = LeftOut::Sandbox {
        sandbox: "lab".to_owned(),
        why: String::new(),
    };
    assert!(lab.covers("lab/main"));
    for other in ["lab2/main", "labs/x", "prod/lab", "lab"] {
        assert!(!lab.covers(other), "{other}");
    }
    let agent = LeftOut::Agent {
        agent: "lab/main".to_owned(),
        why: String::new(),
        unreadable: true,
    };
    assert!(agent.covers("lab/main"));
    assert!(!agent.covers("lab/mainly"));
}

/// A change made while the first reading ran is read on the next pass.
#[test]
fn a_change_during_the_first_reading_is_read_again() {
    let dir = tempfile::tempdir().unwrap();
    let changes = dir.path().join("audit.jsonl");
    std::fs::write(&changes, "").unwrap();
    let main = endpoint(dir.path(), "main", "t0ken");
    let helper = endpoint(dir.path(), "helper", "t0ken");
    let readings = std::sync::atomic::AtomicUsize::new(0);
    let log = changes.clone();
    let source = AgentSource::new(changes, move || {
        let mut agents = vec![main.clone()];
        if readings.fetch_add(1, Ordering::SeqCst) == 0 {
            // Audited while this first reading runs.
            let mut file = std::fs::OpenOptions::new().append(true).open(&log).unwrap();
            writeln!(file, "{{}}").unwrap();
        } else {
            agents.push(helper.clone());
        }
        Ok(Served {
            agents,
            left_out: Vec::new(),
        })
    });
    let watch = AgentWatch::start(source).unwrap();
    assert_eq!(watch.agents().len(), 1);
    let (hub, _device) = hub_for(dir.path(), watch);
    assert_eq!(served(&hub), ["lab/main"]);
    hub.refresh_agents();
    assert_eq!(served(&hub), ["lab/helper", "lab/main"]);
}

/// Each person connected is sent the list as they are shown it: the
/// host's person may name the agents, another person may not.
#[test]
fn every_connected_person_is_sent_the_list_as_they_are_shown_it() {
    let dir = tempfile::tempdir().unwrap();
    let main = endpoint(dir.path(), "main", "t0ken");
    let state = State::new(dir.path(), vec![main.clone()]);
    let (hub, host) = watching(dir.path(), &state);
    let (sender, guest) = channel();
    hub.devices
        .lock()
        .unwrap()
        .insert("d-2".to_owned(), ("bob@example.com".to_owned(), sender, 2));
    state.set(vec![main, endpoint(dir.path(), "helper", "t0ken")]);
    hub.refresh_agents();
    for (device, host_person) in [(&host, true), (&guest, false)] {
        let agents = loop {
            if let ToDevice::AgentsList { agents } =
                device.recv_timeout(Duration::from_secs(5)).unwrap()
            {
                break agents;
            }
        };
        let names: Vec<&str> = agents.iter().map(|a| a.agent.as_str()).collect();
        assert_eq!(names, ["lab/helper", "lab/main"]);
        assert!(agents.iter().all(|a| a.can_edit_name == host_person));
    }
}

/// A connection is ended at once, though a write to its plugin holds its
/// writer: no pass waits on a plugin that does not read.
#[test]
fn a_dropped_agent_is_closed_while_a_write_to_it_waits() {
    let dir = tempfile::tempdir().unwrap();
    let main = endpoint(dir.path(), "main", "t0ken");
    let helper = endpoint(dir.path(), "helper", "t0ken");
    let state = State::new(dir.path(), vec![main.clone(), helper.clone()]);
    let (hub, _device) = watching(dir.path(), &state);
    let events = plugin(&helper.socket);
    hub.plugin("lab/helper").unwrap();
    assert_eq!(next(&events), Seen::Opened("t0ken".to_owned()));
    let out = Arc::clone(&hub.plugins.lock().unwrap()["lab/helper"].out);
    let writing = out.lock().unwrap();

    state.set(vec![main]);
    let (done, passed) = channel();
    let refreshing = Arc::clone(&hub);
    std::thread::spawn(move || {
        refreshing.refresh_agents();
        let _ = done.send(());
    });
    passed.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(next(&events), Seen::Closed("t0ken".to_owned()));
    drop(writing);
}

/// The bridge's database failing as the agents change: nothing changes,
/// and once it opens again, a while later, they are served and listed.
#[test]
fn a_change_the_bridge_cannot_store_is_served_once_it_can() {
    let dir = tempfile::tempdir().unwrap();
    let main = endpoint(dir.path(), "main", "t0ken");
    let state = State::new(dir.path(), vec![main.clone()]);
    let (hub, device) = watching(dir.path(), &state);
    let db = dir.path().join("bridge.db");
    let aside = dir.path().join("bridge.db.aside");
    std::fs::rename(&db, &aside).unwrap();
    std::fs::create_dir(&db).unwrap();

    state.set(vec![main, endpoint(dir.path(), "helper", "t0ken")]);
    hub.refresh_agents();
    assert_eq!(served(&hub), ["lab/main"]);
    assert!(device.try_recv().is_err());

    std::fs::remove_dir(&db).unwrap();
    std::fs::rename(&aside, &db).unwrap();
    std::thread::sleep(RETRY_UNREAD);
    hub.refresh_agents();
    assert_eq!(served(&hub), ["lab/helper", "lab/main"]);
    assert_eq!(listed(&device), ["lab/helper", "lab/main"]);
}
