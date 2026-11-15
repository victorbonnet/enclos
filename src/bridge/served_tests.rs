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
    let (watch, agents) = AgentWatch::start(state.source()).unwrap();
    let hub = Hub::new(
        Transport::Tailscale,
        Arc::new(|_: &str| Err("no transport in this test".to_owned())),
        dir.join("bridge.db"),
        crate::layout::Layout::at(dir.join("enclos")),
        vec![7; 32],
        agents,
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
    // Read again with nothing changed: nothing is sent again.
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
    std::thread::sleep(Duration::from_millis(200));
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
    let left = |unreadable| LeftOut {
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

/// The engine's side, with a secret store standing for the Keychain: an
/// agent granted an app channel is read with its token; a store that does
/// not answer leaves it out as unreadable; a token not set, or a grant
/// dropped, leaves it out as gone. Each change is an audited write.
#[test]
fn the_state_gives_each_agent_with_an_app_channel_and_says_why_one_is_left_out() {
    use crate::audit::jsonl::JsonlAuditLog;
    use crate::backend::fake::FakeBackend;
    use crate::engine::{Engine, SandboxSpec};
    use crate::model::secret::{SecretRef, SecretValue};
    use crate::model::{audit::Actor, plan::Confirm, sandbox::BackendKind};
    use crate::state::sqlite::SqliteStateStore;

    let dir = tempfile::tempdir().unwrap();
    let layout = crate::layout::Layout::at(dir.path().join("enclos"));
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
    let lab = "lab".parse().unwrap();
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
    let names = |served: &Served| -> Vec<(String, String)> {
        served
            .agents
            .iter()
            .map(|a| (a.name.clone(), a.token.clone()))
            .collect()
    };
    assert!(names(&super::served(&engine).unwrap()).is_empty());

    // Granted before its token is set: left out, as the user left it.
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
    assert_eq!(read.left_out.len(), 1);
    assert!(read.left_out[0].unreadable, "{}", read.left_out[0].why);
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
        left_out: vec![LeftOut {
            agent: "lab".to_owned(),
            why: "its policy cannot be read: database is locked".to_owned(),
            unreadable: true,
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
