use super::*;
use enclos_protocol::plugin::decode_from_bridge;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};

type NativeRequest = (MessageId, ConversationId, Sender<Result<(), ErrorCode>>);

fn native(socket: &Path, supports: bool) -> Receiver<NativeRequest> {
    let listener = UnixListener::bind(socket).unwrap();
    let (send, receive) = channel();
    std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let mut writer = stream.try_clone().unwrap();
        let mut lines = BufReader::new(stream);
        let mut line = String::new();
        lines.read_line(&mut line).unwrap();
        writer
            .write_all(&encode_line(&Envelope::new(
                MessageId::new("hello").unwrap(),
                FromPlugin::Hello {
                    runtime: "hermes".into(),
                    agent: "main".into(),
                    capabilities: if supports {
                        vec![Capability::ConversationDelete]
                    } else {
                        vec![]
                    },
                },
            )))
            .unwrap();
        loop {
            line.clear();
            if lines.read_line(&mut line).unwrap_or(0) == 0 {
                break;
            }
            let packet = decode_from_bridge(line.as_bytes()).unwrap();
            if let FromBridge::Delete { conversation } = packet.body {
                let (answer, result) = channel();
                if send
                    .send((packet.id.clone(), conversation, answer))
                    .is_err()
                {
                    break;
                }
                let body = match result.recv_timeout(Duration::from_secs(5)).unwrap() {
                    Ok(()) => FromPlugin::Ack { of: packet.id },
                    Err(code) => FromPlugin::Error(ErrorBody {
                        of: Some(packet.id),
                        code,
                        message: "Native deletion refused; retry.".into(),
                    }),
                };
                writer
                    .write_all(&encode_line(&Envelope::new(
                        MessageId::new(new_id().unwrap()).unwrap(),
                        body,
                    )))
                    .unwrap();
            }
        }
    });
    receive
}

fn fixture(names: &[&str]) -> (tempfile::TempDir, Arc<Hub>, Store) {
    let dir = tempfile::tempdir().unwrap();
    let agents = names
        .iter()
        .map(|name| AgentEndpoint {
            name: format!("lab/{name}"),
            runtime: "hermes".into(),
            socket: dir.path().join(format!("{name}.sock")),
            token: "token".into(),
        })
        .collect();
    let hub = Arc::new(Hub::new(
        Transport::Tailscale,
        Arc::new(|_| Err("test".into())),
        dir.path().join("app.db"),
        crate::layout::Layout::at(dir.path().join("enclos")),
        vec![7; 32],
        agents,
        Some("alice".into()),
        SILENCE,
    ));
    let store = hub.store().unwrap();
    (dir, hub, store)
}

fn deleting(hub: &Arc<Hub>, id: &str) -> std::thread::JoinHandle<Result<(), ErrorBody>> {
    let hub = Arc::clone(hub);
    let id = ConversationId::new(id).unwrap();
    std::thread::spawn(move || {
        hub.delete_conversation(&hub.store().unwrap(), "alice", &id, "test-device")
    })
}

#[test]
fn native_confirmation_precedes_removal_and_only_the_owners_devices_learn_it() {
    let (dir, hub, store) = fixture(&["main"]);
    let requests = native(&dir.path().join("main.sock"), true);
    store
        .conversation("c-delete", "lab", "main", "alice")
        .unwrap();
    store
        .add("m1", "c-delete", &From::Agent, "history", "reply")
        .unwrap();
    std::fs::create_dir(hub.media()).unwrap();
    std::fs::write(hub.media().join("f1"), b"file").unwrap();
    store
        .add_attachment(
            &StoredAttachment {
                id: "f1".into(),
                conversation: "c-delete".into(),
                name: "a.txt".into(),
                mime: "text/plain".into(),
                size: 4,
            },
            "m1",
        )
        .unwrap();
    let (one, first) = channel();
    let (two, second) = channel();
    let (other, guest) = channel();
    hub.devices.lock().unwrap().extend([
        ("one".into(), ("alice".into(), one, 1)),
        ("two".into(), ("alice".into(), two, 2)),
        ("other".into(), ("bob".into(), other, 3)),
    ]);
    let missing = hub
        .delete_conversation(
            &store,
            "alice",
            &ConversationId::new("missing").unwrap(),
            "test-device",
        )
        .unwrap_err();
    let refused = hub
        .delete_conversation(
            &store,
            "bob",
            &ConversationId::new("c-delete").unwrap(),
            "test-device",
        )
        .unwrap_err();
    assert_eq!(missing, refused);
    let work = deleting(&hub, "c-delete");
    let (request, conversation, answer) = requests.recv_timeout(Duration::from_secs(3)).unwrap();
    assert_eq!(conversation.as_str(), "c-delete");
    assert!(store.conversation_info("c-delete").unwrap().is_some());
    assert!(first.try_recv().is_err());
    assert!(
        !hub.delete_answer("lab/other", 0, Some(&request), Ok(())),
        "another agent cannot acknowledge it"
    );
    answer.send(Ok(())).unwrap();
    work.join().unwrap().unwrap();
    for receiver in [&first, &second] {
        assert!(
            matches!(receiver.recv_timeout(Duration::from_secs(3)).unwrap(), ToDevice::ConversationDeleted { conversation } if conversation.as_str()=="c-delete")
        );
    }
    assert!(guest.try_recv().is_err());
    assert!(store.conversation_info("c-delete").unwrap().is_none());
    assert!(!hub.media().join("f1").exists());
    assert!(
        destination(
            &store,
            Some("alice"),
            "lab/main",
            ConversationId::new("c-delete").unwrap()
        )
        .unwrap()
        .is_none(),
        "late native output is not redirected to Home"
    );
    hub.delete_conversation(
        &store,
        "alice",
        &ConversationId::new("c-delete").unwrap(),
        "test-device",
    )
    .unwrap();
    assert!(
        requests.try_recv().is_err(),
        "retry needs no already-deleted runtime"
    );
    assert_eq!(store.deletions("alice").unwrap(), ["c-delete"]);
}

#[test]
fn partial_group_failure_keeps_history_and_retry_only_contacts_the_remaining_member() {
    let (dir, hub, store) = fixture(&["coder", "main"]);
    let coder = native(&dir.path().join("coder.sock"), true);
    let main = native(&dir.path().join("main.sock"), true);
    store
        .group("g-delete", "lab", &["coder".into(), "main".into()], "alice")
        .unwrap();
    store
        .add(
            "m1",
            "g-delete",
            &From::Member("coder".into()),
            "history",
            "reply",
        )
        .unwrap();
    let work = deleting(&hub, "g-delete");
    coder
        .recv_timeout(Duration::from_secs(3))
        .unwrap()
        .2
        .send(Ok(()))
        .unwrap();
    main.recv_timeout(Duration::from_secs(3))
        .unwrap()
        .2
        .send(Err(ErrorCode::Conflict))
        .unwrap();
    assert_eq!(work.join().unwrap().unwrap_err().code, ErrorCode::Conflict);
    assert!(store.deletions("alice").unwrap().is_empty());
    assert_eq!(store.since("alice", 0).unwrap().len(), 1);
    let retry = deleting(&hub, "g-delete");
    main.recv_timeout(Duration::from_secs(3))
        .unwrap()
        .2
        .send(Ok(()))
        .unwrap();
    retry.join().unwrap().unwrap();
    assert!(coder.try_recv().is_err());
    assert!(store.members("g-delete").unwrap().is_empty());
    assert!(store.since("alice", 0).unwrap().is_empty());
}

#[test]
fn older_plugins_and_home_are_refused_without_locking_or_erasing_the_chat() {
    let (dir, hub, store) = fixture(&["main"]);
    let requests = native(&dir.path().join("main.sock"), false);
    store
        .conversation("c-delete", "lab", "main", "alice")
        .unwrap();
    let error = hub
        .delete_conversation(
            &store,
            "alice",
            &ConversationId::new("c-delete").unwrap(),
            "test-device",
        )
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::Unsupported);
    assert!(!store.deletion_started("c-delete").unwrap());
    assert!(
        store
            .add("m1", "c-delete", &From::Agent, "still usable", "reply")
            .unwrap()
            .is_some()
    );
    assert!(requests.try_recv().is_err());
    store.ensure_home("lab/main", "alice", true).unwrap();
    assert_eq!(
        hub.delete_conversation(
            &store,
            "alice",
            &ConversationId::new("home.lab.main").unwrap(),
            "test-device"
        )
        .unwrap_err()
        .code,
        ErrorCode::NotAllowed
    );
    assert!(store.conversation_info("home.lab.main").unwrap().is_some());
}

#[test]
fn removed_agent_finishes_deletion_but_kept_native_data_requires_its_channel() {
    use crate::model::sandbox::{BackendKind, SandboxRecord, SandboxState};
    use crate::state::StateStore;
    use crate::state::sqlite::SqliteStateStore;
    let (_dir, hub, store) = fixture(&[]);
    std::fs::create_dir_all(hub.layout.data()).unwrap();
    let state = SqliteStateStore::new(
        hub.layout.state_db(),
        hub.layout.state_lock(),
        crate::state::Wait::Command,
    );
    {
        let lock = state.lock().unwrap();
        state.migrate(&lock).unwrap();
        state
            .put(
                &lock,
                &SandboxRecord {
                    name: "lab".parse().unwrap(),
                    backend: BackendKind::Seatbelt,
                    created_from: "minimal".parse().unwrap(),
                    state: SandboxState::Stopped,
                    proxy_port: 41000,
                    runtime: Some(crate::model::runtime::RuntimeKind::Hermes),
                    created_at: jiff::Timestamp::now(),
                },
            )
            .unwrap();
    }
    let profiles = hub.layout.sandbox_home("lab").join(".hermes/profiles");
    std::fs::create_dir_all(&profiles).unwrap();
    store
        .conversation("c-removed", "lab", "gone", "alice")
        .unwrap();
    hub.delete_conversation(
        &store,
        "alice",
        &ConversationId::new("c-removed").unwrap(),
        "phone",
    )
    .unwrap();
    assert!(store.conversation_info("c-removed").unwrap().is_none());
    let folder = profiles.join("kept");
    std::fs::create_dir(&folder).unwrap();
    std::fs::write(folder.join("config.yaml"), "model: auto\n").unwrap();
    store
        .conversation("c-kept", "lab", "kept", "alice")
        .unwrap();
    assert_eq!(
        hub.delete_conversation(
            &store,
            "alice",
            &ConversationId::new("c-kept").unwrap(),
            "phone"
        )
        .unwrap_err()
        .code,
        ErrorCode::AgentUnavailable
    );
    assert!(!store.deletion_started("c-kept").unwrap());
    assert!(store.conversation_info("c-kept").unwrap().is_some());
    // A profile no longer listed by Hermes can still have data on disk.
    std::fs::remove_file(folder.join("config.yaml")).unwrap();
    assert!(!hub.deletion_target_absent("lab/kept"));
    std::fs::remove_dir(&folder).unwrap();
    // A reservation from an earlier failed attempt also completes when its
    // native target is now demonstrably gone.
    store.begin_deletion("c-kept", "alice").unwrap();
    hub.delete_conversation(
        &store,
        "alice",
        &ConversationId::new("c-kept").unwrap(),
        "phone",
    )
    .unwrap();
    assert!(store.conversation_info("c-kept").unwrap().is_none());
}

/// A plugin for `lab/<name>` that has answered the bridge's hello: its
/// connection, to send on and read from.
fn connected(hub: &Arc<Hub>, dir: &Path, name: &str) -> (UnixStream, BufReader<UnixStream>) {
    let listener = UnixListener::bind(dir.join(format!("{name}.sock"))).unwrap();
    let (send, receive) = channel();
    let agent = name.to_owned();
    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut lines = BufReader::new(stream.try_clone().unwrap());
        let mut line = String::new();
        lines.read_line(&mut line).unwrap();
        stream
            .write_all(&encode_line(&Envelope::new(
                MessageId::new("hello").unwrap(),
                FromPlugin::Hello {
                    runtime: "hermes".into(),
                    agent,
                    capabilities: vec![],
                },
            )))
            .unwrap();
        send.send((stream, lines)).unwrap();
    });
    hub.plugin(&format!("lab/{name}")).unwrap();
    receive.recv_timeout(Duration::from_secs(5)).unwrap()
}

/// The bridge's next line to the plugin, `None` when nothing comes in
/// half a second.
fn next_line(lines: &mut BufReader<UnixStream>) -> Option<FromBridge> {
    lines
        .get_ref()
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    let mut line = String::new();
    match lines.read_line(&mut line) {
        Ok(n) if n > 0 => Some(decode_from_bridge(line.as_bytes()).unwrap().body),
        _ => None,
    }
}

/// Whether the bridge ended the connection: the plugin reads its end
/// within 5 seconds, and nothing before it.
fn ended(lines: &mut BufReader<UnixStream>) -> bool {
    lines
        .get_ref()
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    matches!(lines.read_line(&mut String::new()), Ok(0))
}

/// The plugin for `lab/<name>`, connected again once the bridge let its
/// last connection go.
fn reconnected(hub: &Arc<Hub>, dir: &Path, name: &str) -> (UnixStream, BufReader<UnixStream>) {
    let agent = format!("lab/{name}");
    let started = std::time::Instant::now();
    while hub.plugins.lock().unwrap().contains_key(&agent) {
        assert!(started.elapsed() < Duration::from_secs(5), "never let go");
        std::thread::sleep(Duration::from_millis(20));
    }
    std::fs::remove_file(dir.join(format!("{name}.sock"))).unwrap();
    connected(hub, dir, name)
}

/// What a plugin's outbox holds for `conversation`, as message `out-1`.
fn kept_message(conversation: &str) -> Vec<u8> {
    encode_line(&Envelope::new(
        MessageId::new("out-1").unwrap(),
        FromPlugin::MessageOut {
            conversation: ConversationId::new(conversation).unwrap(),
            text: "kept".into(),
            kind: OutKind::Reply,
            reply_to: None,
            attachments: vec![],
        },
    ))
}

#[test]
fn an_agents_message_is_not_acknowledged_while_the_store_cannot_say_whether_its_conversation_is_going()
 {
    let (dir, hub, store) = fixture(&["main"]);
    store.conversation("c-1", "lab", "main", "alice").unwrap();
    let (mut out, mut lines) = connected(&hub, dir.path(), "main");
    // The deletions can no longer be read
    let raw = rusqlite::Connection::open(&hub.store_path).unwrap();
    raw.execute_batch("ALTER TABLE conversation_deletions RENAME TO unreadable")
        .unwrap();
    out.write_all(&kept_message("c-1")).unwrap();
    // Not acknowledged, and the connection ends, so the plugin sends it
    // again soon, after the next connection's hello
    assert!(ended(&mut lines), "acknowledged, or left open");
    raw.execute_batch("ALTER TABLE unreadable RENAME TO conversation_deletions")
        .unwrap();
    let (mut out, mut lines) = reconnected(&hub, dir.path(), "main");
    out.write_all(&kept_message("c-1")).unwrap();
    assert_eq!(
        next_line(&mut lines),
        Some(FromBridge::Ack {
            of: MessageId::new("out-1").unwrap()
        })
    );
    let kept = store.since("alice", 0).unwrap();
    assert_eq!(kept.len(), 1);
    assert_eq!(kept[0].text, "kept");
}

#[test]
fn a_members_message_is_not_acknowledged_or_sent_home_while_the_store_cannot_say_whether_it_is_a_group()
 {
    let (dir, hub, store) = fixture(&["main", "coder"]);
    let members = ["main".to_owned(), "coder".to_owned()];
    store.group("g-1", "lab", &members, "alice").unwrap();
    let (mut out, mut lines) = connected(&hub, dir.path(), "main");
    // The group's members can no longer be read
    let raw = rusqlite::Connection::open(&hub.store_path).unwrap();
    raw.execute_batch("ALTER TABLE members RENAME TO unreadable")
        .unwrap();
    out.write_all(&kept_message("g-1")).unwrap();
    assert!(ended(&mut lines), "acknowledged, or left open");
    raw.execute_batch("ALTER TABLE unreadable RENAME TO members")
        .unwrap();
    let (mut out, mut lines) = reconnected(&hub, dir.path(), "main");
    out.write_all(&kept_message("g-1")).unwrap();
    assert_eq!(
        next_line(&mut lines),
        Some(FromBridge::Ack {
            of: MessageId::new("out-1").unwrap()
        })
    );
    // In the group, as main's, and not in its Home
    let said = store.messages_after("g-1", 0).unwrap();
    assert_eq!(said.len(), 1);
    assert_eq!(
        (&said[0].from, said[0].text.as_str()),
        (&From::Member("main".into()), "kept")
    );
    assert!(store.conversation_info("home.lab.main").unwrap().is_none());
}

#[test]
fn a_message_goes_nowhere_while_the_store_cannot_say_where() {
    let (_dir, _hub, store) = fixture(&[]);
    store.conversation("c-1", "lab", "main", "alice").unwrap();
    let id = || ConversationId::new("c-1").unwrap();
    assert_eq!(
        super::destination(&store, Some("alice"), "lab/main", id()).unwrap(),
        Some(id())
    );
    // Its Home cannot be made: the message would be stored where no
    // device sees it
    store
        .db
        .execute_batch(
            "CREATE TRIGGER refuse BEFORE INSERT ON conversations
             BEGIN SELECT RAISE(ABORT, 'disk full'); END;",
        )
        .unwrap();
    let unknown = ConversationId::new("c-unknown").unwrap();
    assert!(super::destination(&store, Some("alice"), "lab/main", unknown).is_err());
    store.db.execute_batch("DROP TRIGGER refuse").unwrap();
    store
        .db
        .execute_batch("ALTER TABLE conversations RENAME TO unreadable")
        .unwrap();
    assert!(super::destination(&store, Some("alice"), "lab/main", id()).is_err());
}

#[test]
fn a_removed_sandbox_leaves_nothing_to_delete_unless_its_data_was_kept() {
    let (_dir, hub, store) = fixture(&[]);
    // No state database: enclos cannot tell, so the agent is not absent
    assert!(!hub.deletion_target_absent("gone/main"));
    std::fs::create_dir_all(hub.layout.data()).unwrap();
    let state = crate::state::sqlite::SqliteStateStore::new(
        hub.layout.state_db(),
        hub.layout.state_lock(),
        crate::state::Wait::Command,
    );
    {
        use crate::state::StateStore;
        let lock = state.lock().unwrap();
        state.migrate(&lock).unwrap();
    }
    // Removed with its folder: nothing of the agent is left anywhere
    store
        .conversation("c-gone", "gone", "main", "alice")
        .unwrap();
    hub.delete_conversation(
        &store,
        "alice",
        &ConversationId::new("c-gone").unwrap(),
        "phone",
    )
    .unwrap();
    assert!(store.conversation_info("c-gone").unwrap().is_none());
    assert!(store.deletion_started("c-gone").unwrap());
    // Removed with `--keep-data`: the agent's profile is still in its home
    let profile = hub
        .layout
        .sandbox_home("kept")
        .join(".hermes/profiles/main");
    std::fs::create_dir_all(&profile).unwrap();
    std::fs::write(profile.join("config.yaml"), "model: auto\n").unwrap();
    store
        .conversation("c-kept", "kept", "main", "alice")
        .unwrap();
    assert_eq!(
        hub.delete_conversation(
            &store,
            "alice",
            &ConversationId::new("c-kept").unwrap(),
            "phone",
        )
        .unwrap_err()
        .code,
        ErrorCode::AgentUnavailable
    );
    assert!(store.conversation_info("c-kept").unwrap().is_some());
    // Its home kept, the agent's data gone: nothing left to delete
    std::fs::remove_dir_all(&profile).unwrap();
    hub.delete_conversation(
        &store,
        "alice",
        &ConversationId::new("c-kept").unwrap(),
        "phone",
    )
    .unwrap();
    assert!(store.conversation_info("c-kept").unwrap().is_none());
}
