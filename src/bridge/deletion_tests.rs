use super::*;
use enclos_protocol::plugin::decode_from_bridge;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;

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
    std::thread::spawn(move || hub.delete_conversation(&hub.store().unwrap(), "alice", &id))
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
        .delete_conversation(&store, "alice", &ConversationId::new("missing").unwrap())
        .unwrap_err();
    let refused = hub
        .delete_conversation(&store, "bob", &ConversationId::new("c-delete").unwrap())
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
        .is_none(),
        "late native output is not redirected to Home"
    );
    hub.delete_conversation(&store, "alice", &ConversationId::new("c-delete").unwrap())
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
        .delete_conversation(&store, "alice", &ConversationId::new("c-delete").unwrap())
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
            &ConversationId::new("home.lab.main").unwrap()
        )
        .unwrap_err()
        .code,
        ErrorCode::NotAllowed
    );
    assert!(store.conversation_info("home.lab.main").unwrap().is_some());
}
