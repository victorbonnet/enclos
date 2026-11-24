//! Telling a restarting agent from a stopped sandbox or a channel that never
//! answered (issue #376).

use super::*;
use crate::model::sandbox::SandboxState;
use crate::state::{StateStore, Wait};
use enclos_protocol::incoming::{Begin, IncomingFile, MAX_PART_BYTES, Part, PartData};
use std::time::{Duration, Instant};

/// The state `enclos` has recorded for sandbox `lab`, as a stop or a
/// restart leaves it.
fn record_state(layout: &crate::layout::Layout, state: SandboxState) {
    let store = crate::state::sqlite::SqliteStateStore::new(
        layout.state_db(),
        layout.state_lock(),
        Wait::Command,
    );
    let name: crate::model::sandbox::SandboxName = "lab".parse().unwrap();
    let lock = store.lock().unwrap();
    let mut record = store.get(&name).unwrap().expect("lab's record");
    record.state = state;
    store.put(&lock, &record).unwrap();
}

/// Ends the bridge's channel to `lab/main` the way a restart does: the
/// socket goes first so background reconnects cannot reopen it while the
/// existing connection shuts down.
fn the_channel_goes(bridge: &Bridge, socket: &Path) {
    std::fs::remove_file(socket).unwrap();
    bridge
        .hub
        .plugins
        .lock()
        .unwrap()
        .get("lab/main")
        .expect("the channel is open")
        .closer
        .shutdown();
    assert!(eventually(|| !bridge
        .hub
        .plugins
        .lock()
        .unwrap()
        .contains_key("lab/main")));
}

/// Messages received by the stand-in plugin: `(id, text)`.
type Received = Arc<Mutex<Vec<(String, String)>>>;

/// A device paired to `bridge`, in a conversation with `lab/main`, whose
/// channel answered once.
fn talking_to_the_agent(bridge: &Bridge, socket: &Path) -> (PhoneLink, Received) {
    let got = plugin(socket);
    let phone = paired(bridge, "n-pixel");
    let (mut device, _) = connect(bridge, &phone);
    start_conversation(&mut device);
    synced(&mut device, 0);
    say(&mut device, "m-1", "first");
    let echo = device.receive().unwrap();
    assert!(matches!(echo, ToDevice::Message(ref m) if m.text == "first"));
    assert!(eventually(|| !got.lock().unwrap().is_empty()));
    (device, got)
}

/// Reads until the echo `ToDevice::Message` arrives, passing over unrelated
/// updates such as `agents.list` broadcast by `serve_agents`.
fn expect_echo(device: &mut PhoneLink, text: &str) {
    loop {
        if let ToDevice::Message(m) = device.receive().expect("closed before echo") {
            assert_eq!(m.text, text);
            return;
        }
    }
}

/// The error frame the device got for `id`, after the echo.
fn the_answer(device: &mut PhoneLink, id: &str) -> Option<ErrorBody> {
    loop {
        match device.receive()? {
            ToDevice::Error(e) if e.of.as_ref().map(MessageId::as_str) == Some(id) => {
                return Some(e);
            }
            _ => {}
        }
    }
}

/// The connect failure text the bridge produces for an absent socket at `path`,
/// byte-identical to what `PluginError::Connect` formats on this host.
fn connect_failure(path: &Path) -> String {
    let source = UnixStream::connect(path).unwrap_err();
    PluginError::Connect {
        path: path.display().to_string(),
        source,
    }
    .to_string()
}

/// The old fallback message for a chat message that failed with `why`.
fn fallback_chat(why: &str) -> String {
    format!("{why}: the message is kept, and goes to the agent once it can be reached")
}

/// Takes sandbox `lab`'s record away, as a state database that cannot say
/// which state the sandbox is in does (#376): the bridge must answer as it
/// did before, never guess a restart.
fn forget_state(layout: &crate::layout::Layout) {
    let store = crate::state::sqlite::SqliteStateStore::new(
        layout.state_db(),
        layout.state_lock(),
        Wait::Command,
    );
    let name: crate::model::sandbox::SandboxName = "lab".parse().unwrap();
    let lock = store.lock().unwrap();
    store.remove(&lock, &name).unwrap();
}

fn file(name: &str, mime: &str, size: usize) -> IncomingFile {
    IncomingFile::new(name.into(), mime.into(), size as u64).unwrap()
}

fn bytes(size: usize, seed: u8) -> Vec<u8> {
    (0..size)
        .map(|i| (i as u8).wrapping_mul(31) ^ seed)
        .collect()
}

fn begin(device: &mut PhoneLink, id: &str, conversation: &str, text: &str, files: &[IncomingFile]) {
    let begin = Begin {
        conversation: ConversationId::new(conversation).unwrap(),
        text: text.into(),
        files: files.to_vec(),
    };
    device.send(id, FromDevice::MessageBegin(begin));
}

fn part(device: &mut PhoneLink, id: &str, message: &str, file: u8, offset: u64, data: &[u8]) {
    let part = Part {
        message: MessageId::new(message).unwrap(),
        file,
        offset,
        data: PartData::new(data.to_vec()).unwrap(),
    };
    device.send(id, FromDevice::MessagePart(part));
}

fn send_all(device: &mut PhoneLink, message: &str, contents: &[Vec<u8>]) {
    let mut n = 0;
    for (i, content) in contents.iter().enumerate() {
        for (k, chunk) in content.chunks(MAX_PART_BYTES).enumerate() {
            n += 1;
            let (id, offset) = (format!("{message}-p{n}"), (k * MAX_PART_BYTES) as u64);
            part(device, &id, message, i as u8, offset, chunk);
        }
    }
}

/// A stand-in plugin at `socket` that advertises `incoming_files`, records
/// every `message.in` and `message.part`, and acknowledges each `message.in`.
fn files_plugin(socket: &Path) -> Arc<Mutex<Vec<FromBridge>>> {
    let listener = UnixListener::bind(socket).unwrap();
    let got = Arc::new(Mutex::new(Vec::new()));
    let kept = Arc::clone(&got);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let stream = stream.unwrap();
            let mut out = stream.try_clone().unwrap();
            let mut lines = BufReader::new(stream);
            let mut line = Vec::new();
            while lines.read_until(b'\n', &mut line).unwrap_or(0) > 0 {
                let message = decode_from_bridge(&line).unwrap();
                line.clear();
                match message.body {
                    FromBridge::Hello { .. } => {
                        let hello = FromPlugin::Hello {
                            runtime: "hermes".into(),
                            agent: "main".into(),
                            capabilities: vec![Capability::IncomingFiles],
                        };
                        let id = MessageId::new(new_id().unwrap()).unwrap();
                        let _ = out.write_all(&encode_line(&Envelope::new(id, hello)));
                    }
                    body @ FromBridge::MessageIn { .. } => {
                        kept.lock().unwrap().push(body);
                        let id = MessageId::new(new_id().unwrap()).unwrap();
                        let _ = out.write_all(&encode_line(&Envelope::new(
                            id,
                            FromPlugin::Ack { of: message.id },
                        )));
                    }
                    body @ FromBridge::MessagePart(_) => {
                        kept.lock().unwrap().push(body);
                    }
                    _ => {}
                }
            }
        }
    });
    got
}

#[test]
fn a_restarting_agents_message_is_kept_and_said_to_be_restarting() {
    let folder = tempfile::tempdir().unwrap();
    let layout = provisioning_state(folder.path());
    record_state(&layout, SandboxState::Running);
    let bridge = bridge_restarting(folder.path(), Duration::from_millis(200));
    let (mut device, _got) = talking_to_the_agent(&bridge, &bridge.socket);

    the_channel_goes(&bridge, &bridge.socket);
    say(&mut device, "m-2", "during restart");
    let echo = device.receive().unwrap();
    assert!(matches!(echo, ToDevice::Message(ref m) if m.text == "during restart"));
    let error = the_answer(&mut device, "m-2").expect("error frame");
    assert_eq!(error.code, ErrorCode::AgentUnavailable);
    assert_eq!(error.message, RESTARTING);
}

#[test]
fn a_refused_connection_is_a_restart_too() {
    let folder = tempfile::tempdir().unwrap();
    let layout = provisioning_state(folder.path());
    record_state(&layout, SandboxState::Running);
    let bridge = bridge_restarting(folder.path(), Duration::from_millis(200));
    let (mut device, _got) = talking_to_the_agent(&bridge, &bridge.socket);

    the_channel_goes(&bridge, &bridge.socket);
    // Binding and dropping leaves the socket file behind so connect fails with ECONNREFUSED.
    drop(UnixListener::bind(&bridge.socket).unwrap());
    say(&mut device, "m-2", "refused");
    let echo = device.receive().unwrap();
    assert!(matches!(echo, ToDevice::Message(ref m) if m.text == "refused"));
    let error = the_answer(&mut device, "m-2").expect("error frame");
    assert_eq!(error.code, ErrorCode::AgentUnavailable);
    assert_eq!(error.message, RESTARTING);
}

#[test]
fn a_channel_that_never_answered_is_reported_as_before() {
    let folder = tempfile::tempdir().unwrap();
    let layout = provisioning_state(folder.path());
    record_state(&layout, SandboxState::Running);
    let bridge = bridge_restarting(folder.path(), Duration::from_secs(5));
    let phone = paired(&bridge, "n-pixel");
    let (mut device, _) = connect(&bridge, &phone);
    start_conversation(&mut device);
    synced(&mut device, 0);

    let expected = fallback_chat(&connect_failure(&bridge.socket));
    let started = Instant::now();
    say(&mut device, "m-1", "first");
    let echo = device.receive().unwrap();
    assert!(matches!(echo, ToDevice::Message(ref m) if m.text == "first"));
    let error = the_answer(&mut device, "m-1").expect("error frame");
    let elapsed = started.elapsed();

    assert_eq!(error.code, ErrorCode::AgentUnavailable);
    assert_eq!(error.message, expected);
    assert!(
        elapsed < Duration::from_secs(1),
        "waited when the channel never answered: {elapsed:?}"
    );
}

#[test]
fn a_stopped_sandbox_is_said_to_be_stopped() {
    let folder = tempfile::tempdir().unwrap();
    let layout = provisioning_state(folder.path());
    record_state(&layout, SandboxState::Stopped);
    let bridge = bridge_restarting(folder.path(), Duration::from_secs(5));
    let phone = paired(&bridge, "n-pixel");
    let (mut device, _) = connect(&bridge, &phone);
    start_conversation(&mut device);
    synced(&mut device, 0);

    let started = Instant::now();
    say(&mut device, "m-1", "hello");
    let echo = device.receive().unwrap();
    assert!(matches!(echo, ToDevice::Message(ref m) if m.text == "hello"));
    let error = the_answer(&mut device, "m-1").expect("error frame");
    let elapsed = started.elapsed();

    assert_eq!(error.code, ErrorCode::AgentUnavailable);
    assert_eq!(error.message, STOPPED);
    assert!(
        elapsed < Duration::from_secs(1),
        "waited for a stopped sandbox: {elapsed:?}"
    );
}

#[test]
fn a_sandbox_never_started_is_said_to_be_stopped() {
    let folder = tempfile::tempdir().unwrap();
    let _layout = provisioning_state(folder.path());
    let bridge = bridge_restarting(folder.path(), Duration::from_secs(5));
    let phone = paired(&bridge, "n-pixel");
    let (mut device, _) = connect(&bridge, &phone);
    start_conversation(&mut device);
    synced(&mut device, 0);

    let started = Instant::now();
    say(&mut device, "m-1", "hello");
    let echo = device.receive().unwrap();
    assert!(matches!(echo, ToDevice::Message(ref m) if m.text == "hello"));
    let error = the_answer(&mut device, "m-1").expect("error frame");
    let elapsed = started.elapsed();

    assert_eq!(error.code, ErrorCode::AgentUnavailable);
    assert_eq!(error.message, STOPPED);
    assert!(
        elapsed < Duration::from_secs(1),
        "waited for a created sandbox: {elapsed:?}"
    );
}

#[test]
fn a_failed_sandbox_is_not_called_a_restart() {
    let folder = tempfile::tempdir().unwrap();
    let layout = provisioning_state(folder.path());
    record_state(&layout, SandboxState::Running);
    let bridge = bridge_restarting(folder.path(), Duration::from_secs(5));
    let (mut device, _got) = talking_to_the_agent(&bridge, &bridge.socket);

    the_channel_goes(&bridge, &bridge.socket);
    record_state(
        &layout,
        SandboxState::Failed {
            reason: "members survived stop".to_owned(),
        },
    );
    let expected = fallback_chat(&connect_failure(&bridge.socket));
    let started = Instant::now();
    say(&mut device, "m-2", "after failure");
    let echo = device.receive().unwrap();
    assert!(matches!(echo, ToDevice::Message(ref m) if m.text == "after failure"));
    let error = the_answer(&mut device, "m-2").expect("error frame");
    let elapsed = started.elapsed();

    assert_eq!(error.code, ErrorCode::AgentUnavailable);
    assert_eq!(error.message, expected);
    assert!(
        elapsed < Duration::from_secs(1),
        "waited for a failed sandbox: {elapsed:?}"
    );
}

#[test]
fn a_state_that_cannot_be_read_is_not_called_a_restart() {
    let folder = tempfile::tempdir().unwrap();
    let layout = provisioning_state(folder.path());
    record_state(&layout, SandboxState::Running);
    let bridge = bridge_restarting(folder.path(), Duration::from_secs(5));
    let (mut device, _got) = talking_to_the_agent(&bridge, &bridge.socket);

    the_channel_goes(&bridge, &bridge.socket);
    forget_state(&layout);
    let expected = fallback_chat(&connect_failure(&bridge.socket));
    let started = Instant::now();
    say(&mut device, "m-2", "unknown state");
    let echo = device.receive().unwrap();
    assert!(matches!(echo, ToDevice::Message(ref m) if m.text == "unknown state"));
    let error = the_answer(&mut device, "m-2").expect("error frame");
    let elapsed = started.elapsed();

    assert_eq!(error.code, ErrorCode::AgentUnavailable);
    assert_eq!(error.message, expected);
    assert!(
        elapsed < Duration::from_secs(1),
        "guessed a restart from an unreadable state: {elapsed:?}"
    );
}

#[test]
fn a_wrong_token_is_not_called_a_restart() {
    let folder = tempfile::tempdir().unwrap();
    let layout = provisioning_state(folder.path());
    record_state(&layout, SandboxState::Running);
    let bridge = bridge_restarting(folder.path(), Duration::from_secs(5));
    let (mut device, _got) = talking_to_the_agent(&bridge, &bridge.socket);

    the_channel_goes(&bridge, &bridge.socket);
    // Read the bridge's hello, then close without answering: PluginError::Refused.
    let listener = UnixListener::bind(&bridge.socket).unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let mut lines = BufReader::new(stream);
            let mut line = Vec::new();
            let _ = lines.read_until(b'\n', &mut line);
        }
    });

    let expected = fallback_chat(&PluginError::Refused.to_string());
    let started = Instant::now();
    say(&mut device, "m-2", "wrong token");
    let echo = device.receive().unwrap();
    assert!(matches!(echo, ToDevice::Message(ref m) if m.text == "wrong token"));
    let error = the_answer(&mut device, "m-2").expect("error frame");
    let elapsed = started.elapsed();

    assert_eq!(error.code, ErrorCode::AgentUnavailable);
    assert_eq!(error.message, expected);
    assert!(
        elapsed < Duration::from_secs(1),
        "waited when the token was refused: {elapsed:?}"
    );
}

#[test]
fn an_agent_the_app_forgot_keeps_its_own_answer() {
    let folder = tempfile::tempdir().unwrap();
    let layout = provisioning_state(folder.path());
    record_state(&layout, SandboxState::Running);
    let bridge = bridge_restarting(folder.path(), Duration::from_secs(5));
    let (mut device, _got) = talking_to_the_agent(&bridge, &bridge.socket);

    the_channel_goes(&bridge, &bridge.socket);
    let store = Store::open(&bridge.store).unwrap();
    store.set_host(PERSON).unwrap();
    store.forget_agent("lab/main", PERSON, "phone").unwrap();
    store.conversation("c-2", "lab", "main", PERSON).unwrap();

    let expected = fallback_chat(
        "lab/main was forgotten in the app: set up its app channel again with `enclos runtime configure --channel app`",
    );
    let started = Instant::now();
    device.send(
        "m-2",
        FromDevice::MessageSend {
            conversation: ConversationId::new("c-2").unwrap(),
            text: "after forget".to_owned(),
        },
    );
    let echo = device.receive().unwrap();
    assert!(matches!(echo, ToDevice::Message(ref m) if m.text == "after forget"));
    let error = the_answer(&mut device, "m-2").expect("error frame");
    let elapsed = started.elapsed();

    assert_eq!(error.code, ErrorCode::AgentUnavailable);
    assert_eq!(error.message, expected);
    assert!(
        elapsed < Duration::from_secs(1),
        "waited for a forgotten agent: {elapsed:?}"
    );
}

#[test]
fn an_agent_not_served_keeps_its_own_answer() {
    let folder = tempfile::tempdir().unwrap();
    let layout = provisioning_state(folder.path());
    record_state(&layout, SandboxState::Running);
    let bridge = bridge_restarting(folder.path(), Duration::from_secs(5));
    let (mut device, _got) = talking_to_the_agent(&bridge, &bridge.socket);

    bridge.hub.serve_agents(Vec::new()).unwrap();
    assert!(eventually(|| !bridge
        .hub
        .plugins
        .lock()
        .unwrap()
        .contains_key("lab/main")));

    let expected = fallback_chat("no agent lab/main with an app channel");
    let started = Instant::now();
    say(&mut device, "m-2", "unserved");
    expect_echo(&mut device, "unserved");
    let error = the_answer(&mut device, "m-2").expect("error frame");
    let elapsed = started.elapsed();

    assert_eq!(error.code, ErrorCode::AgentUnavailable);
    assert_eq!(error.message, expected);
    assert!(
        elapsed < Duration::from_secs(1),
        "waited for an unserved agent: {elapsed:?}"
    );
}

#[test]
fn a_channel_that_answers_inside_the_wait_takes_the_message_once() {
    let folder = tempfile::tempdir().unwrap();
    let layout = provisioning_state(folder.path());
    record_state(&layout, SandboxState::Running);
    let bridge = bridge_restarting(folder.path(), Duration::from_secs(2));
    let (mut device, _got) = talking_to_the_agent(&bridge, &bridge.socket);

    the_channel_goes(&bridge, &bridge.socket);
    let socket = bridge.socket.clone();
    let (tx, rx) = channel();
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(100));
        tx.send(plugin(&socket)).unwrap();
    });

    say(&mut device, "m-2", "during restart");
    let echo = device.receive().unwrap();
    assert!(matches!(echo, ToDevice::Message(ref m) if m.text == "during restart"));

    let got_after = rx.recv_timeout(Duration::from_secs(5)).unwrap();
    std::thread::sleep(Duration::from_millis(2_500));
    device.send(
        "sync-x",
        FromDevice::Sync {
            since: 0,
            open_items: false,
        },
    );
    loop {
        match device.receive().expect("closed") {
            ToDevice::Error(e) if e.of.as_ref().map(MessageId::as_str) == Some("m-2") => {
                panic!("unexpected error for message delivered during wait: {e:?}");
            }
            ToDevice::Synced { .. } => break,
            _ => {}
        }
    }
    assert!(eventually(|| !got_after.lock().unwrap().is_empty()));
    let delivered: Vec<_> = got_after
        .lock()
        .unwrap()
        .iter()
        .filter(|(_, text)| text == "during restart")
        .cloned()
        .collect();
    assert_eq!(delivered.len(), 1, "expected exactly once: {delivered:?}");
}

#[test]
fn a_message_waits_no_longer_than_the_restart_wait() {
    let folder = tempfile::tempdir().unwrap();
    let layout = provisioning_state(folder.path());
    record_state(&layout, SandboxState::Running);
    let bridge = bridge_restarting(folder.path(), Duration::from_millis(300));
    let (mut device, _got) = talking_to_the_agent(&bridge, &bridge.socket);

    the_channel_goes(&bridge, &bridge.socket);
    let started = Instant::now();
    say(&mut device, "m-2", "bounded wait");
    let echo = device.receive().unwrap();
    assert!(matches!(echo, ToDevice::Message(ref m) if m.text == "bounded wait"));
    let error = the_answer(&mut device, "m-2").expect("error frame");
    let elapsed = started.elapsed();

    assert_eq!(error.code, ErrorCode::AgentUnavailable);
    assert_eq!(error.message, RESTARTING);
    assert!(
        elapsed >= Duration::from_millis(300),
        "returned before the restart wait elapsed: {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_secs(3),
        "waited far longer than the restart wait: {elapsed:?}"
    );
}

#[test]
fn a_file_message_that_meets_a_restart_is_not_kept() {
    let folder = tempfile::tempdir().unwrap();
    let layout = provisioning_state(folder.path());
    record_state(&layout, SandboxState::Running);
    let _initial = files_plugin(&bridge_socket_path(folder.path()));
    let bridge = bridge_restarting(folder.path(), Duration::from_millis(200));
    // Wait for serve_on's initial open_plugins pass to connect and remember lab/main.
    assert!(eventually(|| bridge
        .hub
        .plugins
        .lock()
        .unwrap()
        .contains_key("lab/main")));

    let phone = paired(&bridge, "n-pixel");
    let (mut device, _) = connect(&bridge, &phone);
    start_conversation(&mut device);
    synced(&mut device, 0);

    // Part 1: channel stays away past the wait -> old file refusal, no "kept".
    the_channel_goes(&bridge, &bridge.socket);
    let expected = format!(
        "{}: nothing was sent; send it again once the agent can be reached",
        connect_failure(&bridge.socket)
    );
    let one = [file("note.txt", "text/plain", 4)];
    begin(&mut device, "f-1", "c-1", "see attached", &one);
    let error = the_answer(&mut device, "f-1").expect("error frame");
    assert_eq!(error.code, ErrorCode::AgentUnavailable);
    assert_eq!(error.message, expected);
    assert!(
        !error.message.contains("kept"),
        "file message must not claim to be kept: {}",
        error.message
    );

    // Part 2: channel comes back inside the wait -> stored and forwarded once.
    let folder2 = tempfile::tempdir().unwrap();
    let layout2 = provisioning_state(folder2.path());
    record_state(&layout2, SandboxState::Running);
    let _initial2 = files_plugin(&bridge_socket_path(folder2.path()));
    let bridge2 = bridge_restarting(folder2.path(), Duration::from_secs(2));
    assert!(eventually(|| bridge2
        .hub
        .plugins
        .lock()
        .unwrap()
        .contains_key("lab/main")));
    let phone2 = paired(&bridge2, "n-pixel");
    let (mut device2, _) = connect(&bridge2, &phone2);
    start_conversation(&mut device2);
    synced(&mut device2, 0);

    the_channel_goes(&bridge2, &bridge2.socket);
    let socket2 = bridge2.socket.clone();
    let (tx, rx) = channel();
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(100));
        tx.send(files_plugin(&socket2)).unwrap();
    });

    let payload = bytes(4, 1);
    begin(&mut device2, "f-2", "c-1", "arrives after restart", &one);
    send_all(&mut device2, "f-2", &[payload]);
    loop {
        match device2.receive().expect("closed") {
            ToDevice::Ack { of } if of.as_str() == "f-2" => break,
            ToDevice::Error(e) if e.of.as_ref().map(MessageId::as_str) == Some("f-2") => {
                panic!("unexpected error for file message delivered during wait: {e:?}");
            }
            _ => {}
        }
    }
    let got_after = rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert!(eventually(|| got_after
        .lock()
        .unwrap()
        .iter()
        .any(|b| matches!(b, FromBridge::MessageIn { .. }))));
    let messages = got_after
        .lock()
        .unwrap()
        .iter()
        .filter(|b| matches!(b, FromBridge::MessageIn { .. }))
        .count();
    assert_eq!(messages, 1);
}

fn bridge_socket_path(folder: &Path) -> PathBuf {
    folder.join("main.sock")
}

#[test]
fn a_restarting_channel_is_forgotten_when_the_agent_leaves() {
    let folder = tempfile::tempdir().unwrap();
    let layout = provisioning_state(folder.path());
    record_state(&layout, SandboxState::Running);
    let bridge = bridge_restarting(folder.path(), Duration::from_secs(5));
    let (mut device, _got) = talking_to_the_agent(&bridge, &bridge.socket);

    let endpoint = bridge
        .hub
        .agents()
        .iter()
        .find(|a| a.name == "lab/main")
        .cloned()
        .unwrap();
    bridge.hub.serve_agents(Vec::new()).unwrap();
    assert!(eventually(|| !bridge
        .hub
        .plugins
        .lock()
        .unwrap()
        .contains_key("lab/main")));
    std::fs::remove_file(&bridge.socket).unwrap();
    bridge.hub.serve_agents(vec![endpoint]).unwrap();

    let expected = fallback_chat(&connect_failure(&bridge.socket));
    let started = Instant::now();
    say(&mut device, "m-2", "after leaving");
    expect_echo(&mut device, "after leaving");
    let error = the_answer(&mut device, "m-2").expect("error frame");
    let elapsed = started.elapsed();

    assert_eq!(error.code, ErrorCode::AgentUnavailable);
    assert_eq!(error.message, expected);
    assert!(
        elapsed < Duration::from_secs(1),
        "waited after the agent left and returned: {elapsed:?}"
    );
}

#[test]
fn a_model_read_does_not_wait() {
    let folder = tempfile::tempdir().unwrap();
    let layout = provisioning_state(folder.path());
    record_state(&layout, SandboxState::Running);
    let bridge = bridge_restarting(folder.path(), Duration::from_secs(5));
    let (mut device, _got) = talking_to_the_agent(&bridge, &bridge.socket);
    Store::open(&bridge.store)
        .unwrap()
        .set_host(PERSON)
        .unwrap();

    the_channel_goes(&bridge, &bridge.socket);
    let expected = connect_failure(&bridge.socket);
    let started = Instant::now();
    device.send(
        "model-1",
        FromDevice::ModelRequest {
            agent: "lab/main".to_owned(),
            request: enclos_protocol::model::ModelRequest::Options,
        },
    );
    let error = the_answer(&mut device, "model-1").expect("error frame");
    let elapsed = started.elapsed();

    assert_eq!(error.code, ErrorCode::AgentUnavailable);
    assert_eq!(error.message, expected);
    assert!(
        elapsed < Duration::from_secs(1),
        "model read waited for a restarting channel: {elapsed:?}"
    );
}

#[test]
fn a_restarting_report_writes_nothing() {
    let folder = tempfile::tempdir().unwrap();
    let layout = provisioning_state(folder.path());
    record_state(&layout, SandboxState::Running);
    let bridge = bridge_restarting(folder.path(), Duration::from_millis(200));
    let (mut device, _got) = talking_to_the_agent(&bridge, &bridge.socket);

    the_channel_goes(&bridge, &bridge.socket);
    let name: crate::model::sandbox::SandboxName = "lab".parse().unwrap();
    let db_before = std::fs::read(layout.state_db()).unwrap();
    let audit_before = std::fs::read(layout.audit_log()).ok();
    let state_before = crate::engine::Engine::open(layout.clone(), Wait::Command)
        .sandbox_state(&name)
        .unwrap();

    say(&mut device, "m-2", "read only");
    let echo = device.receive().unwrap();
    assert!(matches!(echo, ToDevice::Message(ref m) if m.text == "read only"));
    let error = the_answer(&mut device, "m-2").expect("error frame");
    assert_eq!(error.code, ErrorCode::AgentUnavailable);
    assert_eq!(error.message, RESTARTING);

    let db_after = std::fs::read(layout.state_db()).unwrap();
    let audit_after = std::fs::read(layout.audit_log()).ok();
    let state_after = crate::engine::Engine::open(layout.clone(), Wait::Command)
        .sandbox_state(&name)
        .unwrap();

    assert_eq!(db_before, db_after);
    assert_eq!(audit_before, audit_after);
    assert_eq!(state_before, SandboxState::Running);
    assert_eq!(state_after, SandboxState::Running);
}

fn link_failure(socket: &Path) -> String {
    PluginError::Linked {
        path: socket.display().to_string(),
        source: std::io::Error::other(format!(
            "{} is a link, not the channel's own socket",
            socket.display()
        )),
    }
    .to_string()
}

#[test]
fn a_file_message_to_a_stopped_sandbox_is_not_said_to_go() {
    let folder = tempfile::tempdir().unwrap();
    let layout = provisioning_state(folder.path());
    record_state(&layout, SandboxState::Stopped);
    let bridge = bridge_restarting(folder.path(), Duration::from_secs(5));
    let phone = paired(&bridge, "n-pixel");
    let (mut device, _) = connect(&bridge, &phone);
    start_conversation(&mut device);
    synced(&mut device, 0);

    let expected = format!(
        "{}: nothing was sent; send it again once the agent can be reached",
        connect_failure(&bridge.socket)
    );
    let one = [file("note.txt", "text/plain", 4)];
    let started = Instant::now();
    begin(&mut device, "f-1", "c-1", "see attached", &one);
    let error = the_answer(&mut device, "f-1").expect("error frame");
    let elapsed = started.elapsed();

    assert_eq!(error.code, ErrorCode::AgentUnavailable);
    assert_eq!(error.message, expected);
    assert_ne!(error.message, STOPPED);
    assert!(
        !error.message.contains("kept"),
        "file message must not claim to be kept: {}",
        error.message
    );
    assert!(
        elapsed < Duration::from_secs(1),
        "waited for a stopped sandbox on file message: {elapsed:?}"
    );
}

#[test]
fn a_file_message_to_a_created_sandbox_is_not_said_to_go() {
    let folder = tempfile::tempdir().unwrap();
    let _layout = provisioning_state(folder.path());
    let bridge = bridge_restarting(folder.path(), Duration::from_secs(5));
    let phone = paired(&bridge, "n-pixel");
    let (mut device, _) = connect(&bridge, &phone);
    start_conversation(&mut device);
    synced(&mut device, 0);

    let expected = format!(
        "{}: nothing was sent; send it again once the agent can be reached",
        connect_failure(&bridge.socket)
    );
    let one = [file("note.txt", "text/plain", 4)];
    let started = Instant::now();
    begin(&mut device, "f-1", "c-1", "see attached", &one);
    let error = the_answer(&mut device, "f-1").expect("error frame");
    let elapsed = started.elapsed();

    assert_eq!(error.code, ErrorCode::AgentUnavailable);
    assert_eq!(error.message, expected);
    assert_ne!(error.message, STOPPED);
    assert!(
        !error.message.contains("kept"),
        "file message must not claim to be kept: {}",
        error.message
    );
    assert!(
        elapsed < Duration::from_secs(1),
        "waited for a created sandbox on file message: {elapsed:?}"
    );
}

#[test]
fn a_retry_that_is_refused_is_not_called_a_restart() {
    let folder = tempfile::tempdir().unwrap();
    let layout = provisioning_state(folder.path());
    record_state(&layout, SandboxState::Running);
    let bridge = bridge_restarting(folder.path(), Duration::from_secs(2));
    let (mut device, _got) = talking_to_the_agent(&bridge, &bridge.socket);

    the_channel_goes(&bridge, &bridge.socket);
    // Let the first attempt fail with Connect and enter the restart wait,
    // then bind a listener that reads the bridge's hello and closes without
    // answering (PluginError::Refused) on the retry.
    let socket = bridge.socket.clone();
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(100));
        let listener = UnixListener::bind(&socket).unwrap();
        for stream in listener.incoming().flatten() {
            let mut lines = BufReader::new(stream);
            let mut line = Vec::new();
            let _ = lines.read_until(b'\n', &mut line);
        }
    });

    let expected = fallback_chat(&PluginError::Refused.to_string());
    let started = Instant::now();
    say(&mut device, "m-2", "refused on retry");
    expect_echo(&mut device, "refused on retry");
    let error = the_answer(&mut device, "m-2").expect("error frame");
    let elapsed = started.elapsed();

    assert_eq!(error.code, ErrorCode::AgentUnavailable);
    assert_eq!(error.message, expected);
    assert_ne!(error.message, RESTARTING);
    assert!(
        elapsed < Duration::from_secs(1),
        "kept waiting after retry was refused: {elapsed:?}"
    );
}

#[test]
fn a_linked_socket_is_not_called_a_restart() {
    let folder = tempfile::tempdir().unwrap();
    let layout = provisioning_state(folder.path());
    record_state(&layout, SandboxState::Running);
    let bridge = bridge_restarting(folder.path(), Duration::from_secs(5));
    let (mut device, _got) = talking_to_the_agent(&bridge, &bridge.socket);

    the_channel_goes(&bridge, &bridge.socket);
    std::os::unix::fs::symlink(folder.path().join("other.sock"), &bridge.socket).unwrap();

    let expected = fallback_chat(&link_failure(&bridge.socket));
    let started = Instant::now();
    say(&mut device, "m-2", "linked socket");
    expect_echo(&mut device, "linked socket");
    let error = the_answer(&mut device, "m-2").expect("error frame");
    let elapsed = started.elapsed();

    assert_eq!(error.code, ErrorCode::AgentUnavailable);
    assert_eq!(error.message, expected);
    assert!(
        error
            .message
            .contains("is a link, not the channel's own socket"),
        "unexpected message: {}",
        error.message
    );
    assert_ne!(error.message, RESTARTING);
    assert!(
        elapsed < Duration::from_secs(1),
        "waited for a linked socket: {elapsed:?}"
    );
}

#[test]
fn a_held_task_answer_is_not_held() {
    let folder = tempfile::tempdir().unwrap();
    let layout = provisioning_state(folder.path());
    record_state(&layout, SandboxState::Running);
    let bridge = bridge_restarting(folder.path(), Duration::from_secs(5));
    let (_device, _got) = talking_to_the_agent(&bridge, &bridge.socket);

    the_channel_goes(&bridge, &bridge.socket);
    let store = Store::open(&bridge.store).unwrap();
    let device = Device {
        id: "held-task-device".into(),
        name: "held-task-device".into(),
        person: PERSON.into(),
        noise_key: b"held-task-device".to_vec(),
        device_key: vec![],
        push_key: vec![],
        push_token: None,
        paired: now(),
        seen: None,
        node: None,
    };
    let conversation = ConversationId::new("c-1").unwrap();
    let expected = fallback_chat(&connect_failure(&bridge.socket));

    let started = Instant::now();
    // `SendWait::Never` is the argument the held-task answer path passes.
    let answer = send(
        &bridge.hub,
        &store,
        &device,
        &conversation,
        MessageId::new("ht-1").unwrap(),
        "held task answer".to_owned(),
        SendWait::Never,
    )
    .unwrap();
    let elapsed = started.elapsed();

    let Some(ToDevice::Error(error)) = answer else {
        panic!("expected AgentUnavailable error, got {answer:?}");
    };
    assert_eq!(error.code, ErrorCode::AgentUnavailable);
    assert_eq!(error.message, expected);
    assert_ne!(error.message, RESTARTING);
    assert!(
        elapsed < Duration::from_secs(1),
        "held task answer waited for a restarting channel: {elapsed:?}"
    );
}
