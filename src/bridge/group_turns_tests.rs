//! The bridge's group routing, with stand-in plugins for its members: the
//! checks of `group.new` and `group.stop`, which messages enter a group,
//! and which replies end, keep or drop a turn.

use super::*;
use enclos_protocol::plugin::{ErrorCode, decode_from_bridge};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::time::Instant;

const ALICE: &str = "alice@example.com";
const BOB: &str = "bob@example.com";

/// A hub serving `<sandbox>/<agent>` for each of `names`, each with its
/// plugin's socket in `dir` (`<agent>.sock` for `lab`, else
/// `<sandbox>-<agent>.sock`).
fn hub(dir: &Path, names: &[&str]) -> Arc<Hub> {
    let agents = names
        .iter()
        .map(|name| {
            let (sandbox, agent) = name.split_once('/').unwrap();
            let file = if sandbox == "lab" {
                format!("{agent}.sock")
            } else {
                format!("{sandbox}-{agent}.sock")
            };
            AgentEndpoint {
                name: (*name).to_owned(),
                runtime: "hermes".to_owned(),
                socket: dir.join(file),
                token: "t0ken".to_owned(),
            }
        })
        .collect();
    Arc::new(Hub::new(
        Transport::Tailscale,
        Arc::new(|_: &str| Err("no transport in this test".to_owned())),
        dir.join("bridge.db"),
        crate::layout::Layout::at(dir.join("enclos")),
        vec![7; 32],
        agents,
        Some(ALICE.to_owned()),
        SILENCE,
    ))
}

fn send(out: &mut std::os::unix::net::UnixStream, id: &str, body: FromPlugin) {
    let _ = out.write_all(&encode_line(&Envelope::new(
        MessageId::new(id).unwrap(),
        body,
    )));
}

/// A stand-in plugin for `lab/<name>`: answers the `hello` after `delay`,
/// sends `first`, then answers each `message.in` as `answer` says. The
/// `message.in`s it gets come out of the returned receiver.
fn member(
    dir: &Path,
    name: &str,
    delay: Duration,
    first: Vec<(&'static str, FromPlugin)>,
    answer: impl Fn(&MessageId, &str) -> Vec<(String, FromPlugin)> + Send + 'static,
) -> Receiver<(MessageId, String)> {
    let listener = UnixListener::bind(dir.join(format!("{name}.sock"))).unwrap();
    let (got, given) = channel();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { return };
            let mut out = stream.try_clone().unwrap();
            let mut lines = BufReader::new(stream);
            let mut line = Vec::new();
            if lines.read_until(b'\n', &mut line).unwrap_or(0) == 0 {
                continue;
            }
            std::thread::sleep(delay);
            send(
                &mut out,
                &new_id().unwrap(),
                FromPlugin::Hello {
                    runtime: "hermes".into(),
                    agent: "x".into(),
                    capabilities: Vec::new(),
                },
            );
            for (id, body) in &first {
                send(&mut out, id, body.clone());
            }
            loop {
                line.clear();
                if lines.read_until(b'\n', &mut line).unwrap_or(0) == 0 {
                    break;
                }
                let Ok(message) = decode_from_bridge(&line) else {
                    continue;
                };
                if let FromBridge::MessageIn { text, .. } = message.body {
                    let _ = got.send((message.id.clone(), text.clone()));
                    for (id, body) in answer(&message.id, &text) {
                        send(&mut out, &id, body);
                    }
                }
            }
        }
    });
    given
}

fn says(group: &str, text: &str, kind: OutKind, reply_to: Option<&MessageId>) -> FromPlugin {
    FromPlugin::MessageOut {
        conversation: ConversationId::new(group).unwrap(),
        text: text.to_owned(),
        kind,
        reply_to: reply_to.cloned(),
        attachments: Vec::new(),
    }
}

/// Waits up to 5 seconds for `done`.
fn until(done: impl Fn() -> bool) {
    let started = Instant::now();
    while !done() {
        assert!(started.elapsed() < Duration::from_secs(5), "never came");
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn state(hub: &Hub, store: &Store, id: &str) -> GroupState {
    hub.group_state(store, id).unwrap()
}

fn turn_of(hub: &Hub, store: &Store, id: &str, member: &str) -> Option<String> {
    state(hub, store, id)
        .members
        .into_iter()
        .find(|m| m.agent == format!("lab/{member}"))
        .and_then(|m| m.turn)
}

/// Group `g-1` of `lab/main` and `lab/coder`, Alice's.
fn group(hub: &Hub, store: &Store) {
    let members = ["lab/main".to_owned(), "lab/coder".to_owned()];
    assert_eq!(
        new_group(hub, store, ALICE, "g-1", &members, None),
        Ok(Ok(()))
    );
}

/// The person's message in group `id`, as `send` takes it.
fn person_says(hub: &Arc<Hub>, store: &Store, id: &str, message: &str, text: &str) {
    let seq = store
        .add(
            message,
            id,
            &From::Person(ALICE.to_owned()),
            text,
            "message",
        )
        .unwrap()
        .unwrap();
    hub.group_said(store, id, seq, text);
}

#[test]
fn a_group_is_two_to_six_known_agents_of_one_sandbox_each_once() {
    let dir = tempfile::tempdir().unwrap();
    let names = [
        "lab/main",
        "lab/coder",
        "lab/writer",
        "lab/a",
        "lab/b",
        "lab/c",
        "lab/d",
        "other/main",
    ];
    let hub = hub(dir.path(), &names);
    let store = hub.store().unwrap();
    let list = |m: &[&str]| m.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
    for members in [
        list(&["lab/main"]),
        list(&names[..7]),
        list(&["lab/main", "other/main"]),
        list(&["lab/main", "lab/ghost"]),
        list(&["lab/main", "lab/main"]),
        list(&["lab/main", "coder"]),
        Vec::new(),
    ] {
        let made = new_group(&hub, &store, ALICE, "g-1", &members, None).unwrap();
        assert!(made.is_err(), "{members:?}");
    }
    assert_eq!(store.conversation_of("g-1").unwrap(), None);
    let two = list(&["lab/main", "lab/coder"]);
    assert!(
        new_group(&hub, &store, ALICE, "home.lab.main", &two, None)
            .unwrap()
            .is_err()
    );
    // Not over a conversation that exists.
    store.conversation("c-1", "lab", "main", ALICE).unwrap();
    assert!(
        new_group(&hub, &store, ALICE, "c-1", &two, None)
            .unwrap()
            .is_err()
    );

    let six = list(&names[1..7]);
    assert_eq!(
        new_group(&hub, &store, ALICE, "g-6", &six, Some("Six".into())),
        Ok(Ok(()))
    );
    assert_eq!(
        new_group(&hub, &store, ALICE, "g-1", &two, None),
        Ok(Ok(()))
    );
    // The same again, its answer lost: answered with the group as it is.
    let (alice, to_alice) = channel();
    hub.devices
        .lock()
        .unwrap()
        .insert("d-1".into(), (ALICE.into(), alice, 1));
    assert_eq!(
        new_group(&hub, &store, ALICE, "g-1", &two, None),
        Ok(Ok(()))
    );
    assert!(matches!(
        to_alice.try_recv(),
        Ok(ToDevice::Conversation(c)) if c.conversation.as_str() == "g-1"
    ));
    // Another person's, or other members: refused.
    assert!(
        new_group(&hub, &store, BOB, "g-1", &two, None)
            .unwrap()
            .is_err()
    );
    let other = list(&["lab/main", "lab/writer"]);
    assert!(
        new_group(&hub, &store, ALICE, "g-1", &other, None)
            .unwrap()
            .is_err()
    );
    assert_eq!(group_of(&store, "g-1").unwrap().1, ["main", "coder"]);
}

/// Group `g-1` with `main`'s turn running, sent as `s-1`.
fn running(hub: &Hub, store: &Store) {
    group(hub, store);
    let handles = ["main".to_owned(), "coder".to_owned()];
    let mut d = Discussion::new(1, "hello", &handles);
    let (member, direct) = d.next_turn(&handles, |_| true).unwrap();
    let turn = turn_id("g-1", 1, 0, &member);
    store
        .turn(
            &turn,
            "g-1",
            1,
            0,
            &member,
            "running",
            Some("s-1"),
            Some(1),
            None,
        )
        .unwrap();
    d.started(&member, turn, "s-1".into(), 1, direct);
    hub.groups.lock().unwrap().insert("g-1".into(), d);
}

#[test]
fn only_the_owner_stops_a_group() {
    let dir = tempfile::tempdir().unwrap();
    let hub = hub(dir.path(), &["lab/main", "lab/coder"]);
    let store = hub.store().unwrap();
    running(&hub, &store);
    stop_group(&hub, &store, BOB, "g-1").unwrap();
    assert_eq!(state(&hub, &store, "g-1").state, "working");
    stop_group(&hub, &store, ALICE, "g-1").unwrap();
    assert_eq!(state(&hub, &store, "g-1").state, "stopped");
}

#[test]
fn a_reply_after_stop_and_the_answer_to_stop_are_dropped() {
    let dir = tempfile::tempdir().unwrap();
    let hub = hub(dir.path(), &["lab/main", "lab/coder"]);
    let store = hub.store().unwrap();
    running(&hub, &store);
    hub.group_stop(&store, "g-1");
    let reply = |member, to: Option<&str>, kind| {
        hub.group_reply(&store, "g-1", member, to, "x", false, kind)
    };
    assert_eq!(reply("main", Some("s-1"), "reply"), None);
    hub.stops.lock().unwrap().insert("stop-1".into());
    assert_eq!(reply("main", Some("stop-1"), "reply"), None);
    // What a member says on its own is kept.
    assert_eq!(reply("main", None, "notify"), Some(false));
}

#[test]
fn a_late_reply_after_a_restart_is_kept_for_its_own_turn_only() {
    let dir = tempfile::tempdir().unwrap();
    let hub = hub(dir.path(), &["lab/main", "lab/coder"]);
    let store = hub.store().unwrap();
    running(&hub, &store);
    // The bridge starts again: nothing in memory, the turn in the database.
    hub.groups.lock().unwrap().clear();
    hub.restarted(&store);
    let s = state(&hub, &store, "g-1");
    assert_eq!(
        (s.state.as_str(), s.reason.as_deref()),
        ("failed", Some("bridge_restarted"))
    );
    assert_eq!(
        turn_of(&hub, &store, "g-1", "main").as_deref(),
        Some("failed")
    );
    let status = |store: &Store| store.turn_sent("s-1", "g-1", "main").unwrap().unwrap().1;
    // Another member answering main's turn message does not end main's turn.
    assert_eq!(
        hub.group_reply(&store, "g-1", "coder", Some("s-1"), "mine", false, "reply"),
        Some(false)
    );
    assert_eq!(status(&store), "failed");
    assert_eq!(
        hub.group_reply(&store, "g-1", "main", Some("s-1"), "done", false, "reply"),
        Some(false)
    );
    assert_eq!(status(&store), "replied");
    // group.state says so too.
    assert_eq!(
        turn_of(&hub, &store, "g-1", "main").as_deref(),
        Some("replied")
    );
    // Its further messages for that turn are what it said, kept (one sent
    // again under the same id is the store's to drop); a pass is not.
    assert_eq!(
        hub.group_reply(
            &store,
            "g-1",
            "main",
            Some("s-1"),
            "and more",
            false,
            "reply"
        ),
        Some(false)
    );
    assert_eq!(
        hub.group_reply(&store, "g-1", "main", Some("s-1"), "(pass)", false, "reply"),
        None
    );
    assert_eq!(status(&store), "replied");
}

#[test]
fn a_members_messages_after_the_reply_that_ended_its_turn_are_kept() {
    let dir = tempfile::tempdir().unwrap();
    let hub = hub(dir.path(), &["lab/main", "lab/coder"]);
    let store = hub.store().unwrap();
    running(&hub, &store);
    assert_eq!(
        hub.group_reply(
            &store,
            "g-1",
            "main",
            Some("s-1"),
            "here it is",
            false,
            "reply"
        ),
        Some(true)
    );
    // Hermes sends a reply's files after its text, answering the same
    // message: kept, ending no other turn.
    assert_eq!(
        hub.group_reply(&store, "g-1", "main", Some("s-1"), "", true, "reply"),
        Some(false)
    );
    assert_eq!(
        hub.group_reply(
            &store,
            "g-1",
            "main",
            Some("s-1"),
            "and a note for @coder",
            false,
            "reply"
        ),
        Some(false)
    );
    let turn = store.turn_sent("s-1", "g-1", "main").unwrap().unwrap();
    assert_eq!(turn.1, "replied");
    // The note's mention asks coder for a turn in the next round, as the
    // reply's own would.
    assert_eq!(hub.groups.lock().unwrap()["g-1"].next, ["coder"]);
}

#[test]
fn every_message_a_member_sends_for_its_turn_is_stored_and_its_turn_ends_once() {
    let dir = tempfile::tempdir().unwrap();
    let hub = hub(dir.path(), &["lab/main", "lab/coder"]);
    let store = hub.store().unwrap();
    group(&hub, &store);
    // main answers its turn with its text, sends it again under the same
    // id (its ack lost), then a second message for the same turn, as
    // Hermes sends a reply's files after its text.
    let to_main = member(dir.path(), "main", Duration::ZERO, Vec::new(), |sent, _| {
        let first = new_id().unwrap();
        vec![
            (
                first.clone(),
                says("g-1", "here it is", OutKind::Reply, Some(sent)),
            ),
            (first, says("g-1", "here it is", OutKind::Reply, Some(sent))),
            (
                new_id().unwrap(),
                says("g-1", "and the chart", OutKind::Reply, Some(sent)),
            ),
        ]
    });
    let to_coder = member(
        dir.path(),
        "coder",
        Duration::ZERO,
        Vec::new(),
        |sent, _| {
            vec![(
                new_id().unwrap(),
                says("g-1", "thanks", OutKind::Reply, Some(sent)),
            )]
        },
    );
    person_says(&hub, &store, "g-1", "p-1", "hello");
    to_main.recv_timeout(Duration::from_secs(5)).unwrap();
    to_coder.recv_timeout(Duration::from_secs(5)).unwrap();
    let said = |store: &Store| -> Vec<(From, String)> {
        store
            .messages_after("g-1", 0)
            .unwrap()
            .into_iter()
            .map(|m| (m.from, m.text))
            .collect()
    };
    until(|| said(&store).len() == 4 && state(&hub, &store, "g-1").state == "settled");
    let said = said(&store);
    // The one sent again is dropped: each of main's messages is stored once.
    for text in ["here it is", "and the chart"] {
        let main = (From::Member("main".into()), text.to_owned());
        assert_eq!(said.iter().filter(|m| **m == main).count(), 1, "{said:?}");
    }
    assert!(
        said.contains(&(From::Member("coder".into()), "thanks".into())),
        "{said:?}"
    );
    // One turn each: main's second message ended no other.
    assert!(to_main.recv_timeout(Duration::from_millis(300)).is_err());
    assert_eq!(
        turn_of(&hub, &store, "g-1", "main").as_deref(),
        Some("replied")
    );
    assert_eq!(
        turn_of(&hub, &store, "g-1", "coder").as_deref(),
        Some("replied")
    );
}

#[test]
fn a_reply_that_is_only_a_file_ends_its_turn_and_is_kept() {
    let dir = tempfile::tempdir().unwrap();
    let hub = hub(dir.path(), &["lab/main", "lab/coder"]);
    let store = hub.store().unwrap();
    running(&hub, &store);
    // No text, one file: the member's reply, not a pass.
    assert_eq!(
        hub.group_reply(&store, "g-1", "main", Some("s-1"), "", true, "reply"),
        Some(true)
    );
    let turn = store.turn_sent("s-1", "g-1", "main").unwrap().unwrap();
    assert_eq!(turn.1, "replied");
    // No text and no file is a pass, dropped.
    running(&hub, &store);
    assert_eq!(
        hub.group_reply(&store, "g-1", "main", Some("s-1"), "", false, "reply"),
        None
    );
}

#[test]
fn a_persons_message_sent_during_a_turn_reaches_that_member_next() {
    let dir = tempfile::tempdir().unwrap();
    let hub = hub(dir.path(), &["lab/main", "lab/coder"]);
    let store = hub.store().unwrap();
    group(&hub, &store);
    // main answers its first turn only once the test says so, by then
    // after the person's second message; any later turn at once.
    let (go, wait) = channel::<()>();
    let wait = Mutex::new(wait);
    let to_main = member(
        dir.path(),
        "main",
        Duration::ZERO,
        Vec::new(),
        move |sent, prompt| {
            let text = if prompt.contains("@main first") {
                let _ = wait.lock().unwrap().recv_timeout(Duration::from_secs(5));
                "the first answer"
            } else {
                "the second answer"
            };
            vec![(
                new_id().unwrap(),
                says("g-1", text, OutKind::Reply, Some(sent)),
            )]
        },
    );
    person_says(&hub, &store, "g-1", "p-1", "@main first");
    let (_, first) = to_main.recv_timeout(Duration::from_secs(5)).unwrap();
    assert!(first.contains("@main first"), "{first}");
    // Sent while main's first turn runs: it waits for that turn.
    person_says(&hub, &store, "g-1", "p-2", "@main second");
    go.send(()).unwrap();
    // The reply came after the second message; main is still given it,
    // without its own reply.
    let (_, second) = to_main.recv_timeout(Duration::from_secs(5)).unwrap();
    assert!(second.contains("@main second"), "{second}");
    assert!(!second.contains("the first answer"), "{second}");
    until(|| state(&hub, &store, "g-1").state == "settled");
    assert_eq!(
        turn_of(&hub, &store, "g-1", "main").as_deref(),
        Some("replied")
    );
}

#[test]
fn only_a_members_message_enters_the_group() {
    let dir = tempfile::tempdir().unwrap();
    let hub = hub(dir.path(), &["lab/main", "lab/coder", "lab/writer"]);
    let store = hub.store().unwrap();
    group(&hub, &store);
    let _writer = member(
        dir.path(),
        "writer",
        Duration::ZERO,
        vec![("w-1", says("g-1", "sneaked in", OutKind::Notify, None))],
        |_, _| Vec::new(),
    );
    let _main = member(
        dir.path(),
        "main",
        Duration::ZERO,
        vec![("m-1", says("g-1", "build is green", OutKind::Notify, None))],
        |_, _| Vec::new(),
    );
    hub.plugin("lab/writer").unwrap();
    hub.plugin("lab/main").unwrap();
    let texts = |id: &str| -> Vec<(From, String)> {
        store
            .messages_after(id, 0)
            .unwrap()
            .into_iter()
            .map(|m| (m.from, m.text))
            .collect()
    };
    until(|| texts("home.lab.writer").len() == 1 && texts("g-1").len() == 1);
    assert_eq!(
        texts("g-1"),
        [(From::Member("main".into()), "build is green".into())]
    );
    assert_eq!(
        texts("home.lab.writer"),
        [(From::Agent, "sneaked in".into())]
    );
}

#[test]
fn a_reply_the_store_had_already_still_ends_the_turn() {
    let dir = tempfile::tempdir().unwrap();
    let hub = hub(dir.path(), &["lab/main", "lab/coder"]);
    let store = hub.store().unwrap();
    group(&hub, &store);
    // main answers with the id of a message the bridge stored before.
    let to_main = member(dir.path(), "main", Duration::ZERO, Vec::new(), |sent, _| {
        vec![("p-1".into(), says("g-1", "hi", OutKind::Reply, Some(sent)))]
    });
    let to_coder = member(
        dir.path(),
        "coder",
        Duration::ZERO,
        Vec::new(),
        |sent, _| {
            vec![(
                new_id().unwrap(),
                says("g-1", "done", OutKind::Reply, Some(sent)),
            )]
        },
    );
    person_says(&hub, &store, "g-1", "p-1", "hello");
    let (_, prompt) = to_main.recv_timeout(Duration::from_secs(5)).unwrap();
    assert!(prompt.contains("User (alice): hello"), "{prompt}");
    to_coder.recv_timeout(Duration::from_secs(5)).unwrap();
    until(|| state(&hub, &store, "g-1").state == "settled");
    assert_eq!(
        turn_of(&hub, &store, "g-1", "main").as_deref(),
        Some("replied")
    );
    assert_eq!(
        turn_of(&hub, &store, "g-1", "coder").as_deref(),
        Some("replied")
    );
}

#[test]
fn a_turn_its_plugin_cannot_take_fails_at_once() {
    let dir = tempfile::tempdir().unwrap();
    let hub = hub(dir.path(), &["lab/main", "lab/coder"]);
    let store = hub.store().unwrap();
    group(&hub, &store);
    let _main = member(dir.path(), "main", Duration::ZERO, Vec::new(), |sent, _| {
        vec![(
            new_id().unwrap(),
            FromPlugin::Error(ErrorBody {
                of: Some(sent.clone()),
                code: ErrorCode::BadMessage,
                message: "longer than 1 MiB".into(),
            }),
        )]
    });
    let to_coder = member(dir.path(), "coder", Duration::ZERO, Vec::new(), |_, _| {
        Vec::new()
    });
    person_says(&hub, &store, "g-1", "p-1", "hello");
    to_coder.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(
        turn_of(&hub, &store, "g-1", "main").as_deref(),
        Some("failed")
    );
    assert_eq!(
        turn_of(&hub, &store, "g-1", "coder").as_deref(),
        Some("working")
    );
}

#[test]
fn a_second_advance_while_a_turn_is_sent_sends_no_turn_of_its_own() {
    let dir = tempfile::tempdir().unwrap();
    let hub = hub(dir.path(), &["lab/main", "lab/coder"]);
    let store = hub.store().unwrap();
    group(&hub, &store);
    // main takes its time to connect; it never answers.
    let to_main = member(
        dir.path(),
        "main",
        Duration::from_millis(600),
        Vec::new(),
        |_, _| Vec::new(),
    );
    let to_coder = member(dir.path(), "coder", Duration::ZERO, Vec::new(), |_, _| {
        Vec::new()
    });
    let first = {
        let hub = Arc::clone(&hub);
        std::thread::spawn(move || {
            let store = hub.store().unwrap();
            person_says(&hub, &store, "g-1", "p-1", "hello");
        })
    };
    std::thread::sleep(Duration::from_millis(200));
    // A member's reply lands meanwhile, say: the group is busy.
    hub.advance(&store, "g-1");
    first.join().unwrap();
    to_main.recv_timeout(Duration::from_secs(5)).unwrap();
    assert!(to_coder.recv_timeout(Duration::from_millis(800)).is_err());
    assert_eq!(
        turn_of(&hub, &store, "g-1", "main").as_deref(),
        Some("working")
    );
    assert_eq!(
        turn_of(&hub, &store, "g-1", "coder").as_deref(),
        Some("queued")
    );
}
