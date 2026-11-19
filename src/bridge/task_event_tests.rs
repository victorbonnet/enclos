//! A runtime's task events (ADR 0071, proposed; `docs/protocol.md`, Task
//! events): a `message.out` of `kind: task_event` from a plugin is kept with
//! its task, cleaned by the bridge, passed on live and at sync to a device
//! that draws it, and as the runtime's text, a `notify`, to one that does not.

use super::*;
use enclos_protocol::plugin::decode_from_bridge;
use enclos_protocol::task::TaskState;
use enclos_protocol::task_event::{TaskEvent, TaskEventKind};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};

const PING: &str =
    "🛑 [enclos-org] @reviewer Kanban t_a09759c7 routed to TRIAGE — needs a human decision";

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

/// A plugin for `lab/<name>` that has answered the bridge's hello: its
/// connection, and the bridge's hello it read.
fn connected(
    hub: &Arc<Hub>,
    dir: &Path,
    name: &str,
) -> (UnixStream, BufReader<UnixStream>, FromBridge) {
    let listener = UnixListener::bind(dir.join(format!("{name}.sock"))).unwrap();
    let (send, receive) = channel();
    let agent = name.to_owned();
    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut lines = BufReader::new(stream.try_clone().unwrap());
        let mut line = String::new();
        lines.read_line(&mut line).unwrap();
        let hello = decode_from_bridge(line.as_bytes()).unwrap().body;
        stream
            .write_all(&encode_line(&Envelope::new(
                MessageId::new("hello").unwrap(),
                FromPlugin::Hello {
                    runtime: "hermes".into(),
                    agent,
                    capabilities: vec![Capability::TaskEvents],
                },
            )))
            .unwrap();
        send.send((stream, lines, hello)).unwrap();
    });
    hub.plugin(&format!("lab/{name}")).unwrap();
    receive.recv_timeout(Duration::from_secs(5)).unwrap()
}

/// The bridge's next line to the plugin.
fn next_line(lines: &mut BufReader<UnixStream>) -> Option<FromBridge> {
    lines
        .get_ref()
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut line = String::new();
    match lines.read_line(&mut line) {
        Ok(n) if n > 0 => Some(decode_from_bridge(line.as_bytes()).unwrap().body),
        _ => None,
    }
}

fn event() -> TaskEvent {
    TaskEvent {
        task: "t_a09759c7".into(),
        title: "S2a\nreview".into(),
        assignee: Some("reviewer".into()),
        event: TaskEventKind::Triage,
        state: Some(TaskState::Queued),
    }
}

fn sent(id: &str, conversation: &str, kind: OutKind, event: Option<TaskEvent>) -> Vec<u8> {
    encode_line(&Envelope::new(
        MessageId::new(id).unwrap(),
        FromPlugin::MessageOut {
            suggested_replies: vec!["Open it".into()],
            conversation: ConversationId::new(conversation).unwrap(),
            text: PING.into(),
            kind,
            reply_to: None,
            attachments: vec![],
            task_event: event,
        },
    ))
}

/// A device of alice's, connected: what the bridge delivers to it live.
fn device(hub: &Hub) -> std::sync::mpsc::Receiver<ToDevice> {
    let (send, receive) = channel();
    hub.devices
        .lock()
        .unwrap()
        .insert("phone".into(), ("alice".into(), send, 1));
    receive
}

fn live_message(receive: &std::sync::mpsc::Receiver<ToDevice>) -> ConversationMessage {
    loop {
        match receive.recv_timeout(Duration::from_secs(5)).unwrap() {
            ToDevice::Message(m) => return m,
            _ => continue,
        }
    }
}

#[test]
fn the_bridge_tells_the_plugin_it_takes_task_events() {
    let (dir, hub, _store) = fixture(&["main"]);
    let (_out, _lines, hello) = connected(&hub, dir.path(), "main");
    let FromBridge::Hello { capabilities, .. } = hello else {
        panic!("not a hello: {hello:?}");
    };
    assert!(capabilities.contains(&Capability::TaskEvents));
}

#[test]
fn a_task_event_is_kept_with_its_task_cleaned_and_its_assignee_named_in_the_sandbox() {
    let (dir, hub, store) = fixture(&["main"]);
    store.conversation("c-1", "lab", "main", "alice").unwrap();
    let live = device(&hub);
    let (mut out, mut lines, _) = connected(&hub, dir.path(), "main");
    out.write_all(&sent("out-1", "c-1", OutKind::TaskEvent, Some(event())))
        .unwrap();
    assert_eq!(
        next_line(&mut lines),
        Some(FromBridge::Ack {
            of: MessageId::new("out-1").unwrap()
        })
    );
    let kept = store.since("alice", 0).unwrap();
    assert_eq!(kept.len(), 1);
    assert_eq!(kept[0].kind, "task_event");
    assert_eq!(kept[0].text, PING);
    // A line about a task offers no replies.
    assert!(kept[0].suggested_replies.is_empty());
    let expected = TaskEvent {
        title: "S2a review".into(),
        assignee: Some("lab/reviewer".into()),
        ..event()
    };
    assert_eq!(kept[0].task_event.as_ref(), Some(&expected));
    // Live, to a device: the hub's route holds the message whole, and the
    // device's connection (`for_device`) decides what it gets.
    let m = live_message(&live);
    assert_eq!(
        (m.kind.as_str(), m.task_event.as_ref()),
        ("task_event", Some(&expected))
    );
    // At sync, the same.
    let ToDevice::Message(synced) = message_frame(&store, kept[0].clone()).unwrap() else {
        panic!("not a message");
    };
    assert_eq!(synced.task_event.as_ref(), Some(&expected));
}

#[test]
fn a_task_event_without_a_usable_task_is_kept_as_its_text_a_notify() {
    let (dir, hub, store) = fixture(&["main"]);
    store.conversation("c-1", "lab", "main", "alice").unwrap();
    let (mut out, mut lines, _) = connected(&hub, dir.path(), "main");
    let blank = TaskEvent {
        title: " \u{200B}".into(),
        ..event()
    };
    out.write_all(&sent("out-1", "c-1", OutKind::TaskEvent, None))
        .unwrap();
    out.write_all(&sent("out-2", "c-1", OutKind::TaskEvent, Some(blank)))
        .unwrap();
    // A task with another kind of message is not a task event either.
    out.write_all(&sent("out-3", "c-1", OutKind::Notify, Some(event())))
        .unwrap();
    for id in ["out-1", "out-2", "out-3"] {
        assert_eq!(
            next_line(&mut lines),
            Some(FromBridge::Ack {
                of: MessageId::new(id).unwrap()
            })
        );
    }
    let kept = store.since("alice", 0).unwrap();
    assert_eq!(kept.len(), 3);
    for m in kept {
        assert_eq!((m.kind.as_str(), m.text.as_str()), ("notify", PING));
        assert_eq!(m.task_event, None);
    }
}

#[test]
fn a_device_that_does_not_draw_task_events_gets_the_runtimes_text_as_a_notify() {
    let line = ConversationMessage {
        suggested_replies: Vec::new(),
        question: None,
        held_task: None,
        task_event: Some(event()),
        conversation: ConversationId::new("c-1").unwrap(),
        agent: "lab/main".into(),
        from: "agent".into(),
        text: PING.into(),
        kind: "task_event".into(),
        time: 0,
        seq: 7,
        attachments: Vec::new(),
    };
    let ToDevice::Message(drawn) = for_device(ToDevice::Message(line.clone()), true) else {
        panic!("not a message");
    };
    assert_eq!(drawn, line);
    let ToDevice::Message(older) = for_device(ToDevice::Message(line.clone()), false) else {
        panic!("not a message");
    };
    assert_eq!(
        (older.kind.as_str(), older.task_event, older.text.as_str()),
        ("notify", None, PING)
    );
    // Kept without its task (an import, a row the bridge can no longer
    // read): its text, as a notify, even to a device that draws them.
    let bare = ConversationMessage {
        task_event: None,
        ..line.clone()
    };
    let ToDevice::Message(bare) = for_device(ToDevice::Message(bare), true) else {
        panic!("not a message");
    };
    assert_eq!((bare.kind.as_str(), bare.task_event), ("notify", None));
    // Another message passes as it is.
    let reply = ConversationMessage {
        kind: "reply".into(),
        task_event: None,
        ..line
    };
    let ToDevice::Message(same) = for_device(ToDevice::Message(reply.clone()), false) else {
        panic!("not a message");
    };
    assert_eq!(same, reply);
}

#[test]
fn a_task_event_in_a_group_ends_no_turn_and_is_given_to_no_member() {
    let (dir, hub, store) = fixture(&["main", "coder"]);
    let members = ["main".to_owned(), "coder".to_owned()];
    store.group("g-1", "lab", &members, "alice").unwrap();
    let (mut out, mut lines, _) = connected(&hub, dir.path(), "main");
    out.write_all(&sent("out-1", "g-1", OutKind::TaskEvent, Some(event())))
        .unwrap();
    assert_eq!(
        next_line(&mut lines),
        Some(FromBridge::Ack {
            of: MessageId::new("out-1").unwrap()
        })
    );
    let said = store.messages_after("g-1", 0).unwrap();
    assert_eq!(said.len(), 1);
    assert_eq!(
        (&said[0].from, said[0].kind.as_str()),
        (&From::Member("main".into()), "task_event")
    );
    // No news for the other member: a line about a task is not something
    // a member said.
    assert!(!store.news_for("g-1", "coder", 0).unwrap());
}
