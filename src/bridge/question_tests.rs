use super::super::super::store::{MAX_PENDING_PER_AGENT, MAX_PENDING_PER_CONVERSATION};
use super::*;
use enclos_protocol::plugin::decode_from_bridge;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};

const OWNER: &str = "owner@example.com";
const AGENT: &str = "lab/coder";

/// The bridge's key for runtime-approval decisions in these tests: its
/// scalar is no secret.
fn approval_key() -> enclos_protocol::decision::DecisionKey {
    enclos_protocol::decision::DecisionKey::from_bytes(&[7u8; 32]).unwrap()
}

struct Native {
    output: UnixStream,
    input: BufReader<UnixStream>,
}

impl Native {
    fn send(&mut self, id: &str, body: FromPlugin) {
        self.output
            .write_all(&encode_line(&Envelope::new(
                MessageId::new(id).unwrap(),
                body,
            )))
            .unwrap();
    }
    fn receive(&mut self) -> Envelope<FromBridge> {
        let mut line = vec![];
        self.input.read_until(b'\n', &mut line).unwrap();
        decode_from_bridge(&line).unwrap()
    }
    fn ack(&mut self, of: &str) {
        assert_eq!(
            self.receive().body,
            FromBridge::Ack {
                of: MessageId::new(of).unwrap()
            }
        );
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
    let hub = Arc::new(
        Hub::new(
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
        )
        .with_approval_key(approval_key()),
    );
    let store = hub.store().unwrap();
    store.conversation("owned", "lab", "coder", OWNER).unwrap();
    store
        .conversation("foreign", "lab", "coder", "guest@example.com")
        .unwrap();
    store
        .conversation("other-agent", "lab", "helper", OWNER)
        .unwrap();
    store
        .group("group", "lab", &["coder".into(), "helper".into()], OWNER)
        .unwrap();
    let (device, rx) = phone(&hub, &store, "phone", OWNER);
    (dir, hub, store, device, rx)
}

fn phone(hub: &Hub, store: &Store, id: &str, person: &str) -> (Device, Receiver<ToDevice>) {
    let device = Device {
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
    };
    store.add_device(&device).unwrap();
    let (tx, rx) = channel();
    hub.devices
        .lock()
        .unwrap()
        .insert(id.into(), (person.into(), tx, 0));
    (device, rx)
}

fn native(hub: &Arc<Hub>, capabilities: Vec<Capability>) -> Native {
    let listener = UnixListener::bind(&hub.agents[0].socket).unwrap();
    let (tx, rx) = channel();
    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut line = vec![];
        reader.read_until(b'\n', &mut line).unwrap();
        let FromBridge::Hello {
            token,
            capabilities: bridge_caps,
            ..
        } = decode_from_bridge(&line).unwrap().body
        else {
            panic!("hello first")
        };
        assert_eq!(token, "secret");
        assert!(bridge_caps.contains(&Capability::Questions));
        assert!(bridge_caps.contains(&Capability::RuntimeApprovals));
        stream
            .write_all(&encode_line(&Envelope::new(
                MessageId::new("hello").unwrap(),
                FromPlugin::Hello {
                    runtime: "hermes".into(),
                    agent: "coder".into(),
                    capabilities,
                },
            )))
            .unwrap();
        tx.send(Native {
            output: stream,
            input: reader,
        })
        .unwrap();
    });
    hub.plugin(AGENT).unwrap();
    rx.recv_timeout(Duration::from_secs(2)).unwrap()
}

fn definition(id: &str) -> QuestionDefinition {
    QuestionDefinition {
        id: QuestionId::new(id).unwrap(),
        text: "Que choisir ?".into(),
        choices: vec!["Résultats 🤖".into(), "Classement".into()],
        multiple: true,
        approval: None,
    }
}

fn next(rx: &Receiver<ToDevice>) -> ToDevice {
    rx.recv_timeout(Duration::from_secs(2)).unwrap()
}
fn ask(native: &mut Native, rx: &Receiver<ToDevice>, definition: &QuestionDefinition) {
    ask_with(native, rx, definition, "ask");
}

/// [`ask`], with the ask message's own `id`, for a test that asks more than once.
fn ask_with(
    native: &mut Native,
    rx: &Receiver<ToDevice>,
    definition: &QuestionDefinition,
    id: &str,
) {
    native.send(
        id,
        FromPlugin::QuestionAsk {
            conversation: ConversationId::new("owned").unwrap(),
            question: definition.clone(),
        },
    );
    native.ack(id);
    assert!(
        matches!(next(rx), ToDevice::Question { question } if question.definition == *definition && question.state == QuestionState::Pending)
    );
    assert!(
        matches!(next(rx), ToDevice::Message(message) if message.question.as_ref() == Some(&definition.id) && message.kind == if definition.approval.is_some() { "runtime_approval" } else { "question" })
    );
}

#[test]
fn a_question_brings_its_archived_conversation_back_first() {
    let (_dir, hub, store, _device, rx) = fixture();
    assert_eq!(
        store.set_archived("owned", OWNER, true).unwrap(),
        Some(true)
    );
    let mut native = native(&hub, vec![Capability::Questions]);
    let definition = definition("q-archived");
    native.send(
        "ask",
        FromPlugin::QuestionAsk {
            conversation: ConversationId::new("owned").unwrap(),
            question: definition.clone(),
        },
    );
    native.ack("ask");
    // The conversation's metadata, unarchived, comes before the question.
    assert!(
        matches!(next(&rx), ToDevice::Conversation(info) if info.conversation.as_str() == "owned" && !info.archived)
    );
    assert!(
        matches!(next(&rx), ToDevice::Question { question } if question.definition == definition)
    );
    assert!(!store.conversation_info("owned").unwrap().unwrap().archived);
}

#[test]
fn native_socket_answer_requires_exact_receipt_and_keeps_history_in_order() {
    let (_dir, hub, store, device, rx) = fixture();
    let mut native = native(&hub, vec![Capability::Questions]);
    let definition = definition("q-1");
    ask(&mut native, &rx, &definition);
    let original = MessageId::new("app-answer").unwrap();
    let answer = QuestionAnswer::Choices {
        indices: vec![1, 0],
    };
    hub.question_answer(
        &store,
        &device,
        OWNER,
        original.clone(),
        AnswerRequest {
            question: definition.id.clone(),
            revision: 0,
            answer: answer.clone(),
        },
    )
    .unwrap();
    let request = native.receive();
    assert_eq!(
        request.body,
        FromBridge::QuestionAnswer {
            conversation: ConversationId::new("owned").unwrap(),
            question: definition.id.clone(),
            answer: QuestionAnswer::Choices {
                indices: vec![0, 1]
            },
            // An ordinary question's answer carries no authority: unsigned.
            signed: None,
        }
    );
    assert!(rx.try_recv().is_err());
    native.send(
        "watcher",
        FromPlugin::QuestionUpdate {
            question: definition.id.clone(),
            state: QuestionState::Answered,
            answer: Some(answer.clone()),
            of: None,
        },
    );
    native.ack("watcher");
    assert!(matches!(next(&rx), ToDevice::Question { question } if question.revision == 1));
    assert!(matches!(next(&rx), ToDevice::Message(message) if message.kind == "status"));
    assert!(
        rx.try_recv().is_err(),
        "broadcast is not a successful RPC receipt"
    );
    native.send(
        "receipt",
        FromPlugin::QuestionUpdate {
            question: definition.id.clone(),
            state: QuestionState::Answered,
            answer: Some(answer.clone()),
            of: Some(request.id.clone()),
        },
    );
    native.ack("receipt");
    assert!(matches!(next(&rx), ToDevice::Question { .. }));
    assert!(matches!(next(&rx), ToDevice::Message(message) if message.kind == "status"));
    let receipt = next(&rx);
    assert!(
        matches!(&receipt, ToDevice::QuestionResult { of, question } if of == &original && question.revision == 1 && question.answer == Some(QuestionAnswer::Choices { indices: vec![0,1] }))
    );
    assert_eq!(store.since(OWNER, 0).unwrap().len(), 2);
    // The same packet returns only its stored receipt and never becomes a normal turn.
    hub.question_answer(
        &store,
        &device,
        OWNER,
        original,
        AnswerRequest {
            question: definition.id.clone(),
            revision: 0,
            answer,
        },
    )
    .unwrap();
    assert_eq!(next(&rx), receipt);
    assert!(
        native.input.fill_buf().is_err(),
        "no second native answer or message.in"
    );
}

#[test]
fn two_phones_first_native_answer_wins_and_other_people_cannot_control_it() {
    let (_dir, hub, store, device, rx) = fixture();
    let mut native = native(&hub, vec![Capability::Questions]);
    let definition = definition("q-1");
    ask(&mut native, &rx, &definition);
    let (second, second_rx) = phone(&hub, &store, "phone-2", OWNER);
    let (guest, guest_rx) = phone(&hub, &store, "guest", "guest@example.com");
    for question in [definition.id.clone(), QuestionId::new("missing").unwrap()] {
        let error = hub
            .question_answer(
                &store,
                &guest,
                "guest@example.com",
                MessageId::new("foreign").unwrap(),
                AnswerRequest {
                    question,
                    revision: 0,
                    answer: QuestionAnswer::Skip,
                },
            )
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::NotFound);
        assert_eq!(error.message, "No such question.");
    }
    hub.question_answer(
        &store,
        &device,
        OWNER,
        MessageId::new("first").unwrap(),
        AnswerRequest {
            question: definition.id.clone(),
            revision: 0,
            answer: QuestionAnswer::Choices { indices: vec![0] },
        },
    )
    .unwrap();
    let first = native.receive();
    hub.question_answer(
        &store,
        &second,
        OWNER,
        MessageId::new("second").unwrap(),
        AnswerRequest {
            question: definition.id.clone(),
            revision: 0,
            answer: QuestionAnswer::Skip,
        },
    )
    .unwrap();
    let second_request = native.receive();
    native.send(
        "winner",
        FromPlugin::QuestionUpdate {
            question: definition.id.clone(),
            state: QuestionState::Skipped,
            answer: None,
            of: Some(second_request.id),
        },
    );
    native.ack("winner");
    assert!(
        matches!(next(&rx), ToDevice::Question { question } if question.state == QuestionState::Skipped)
    );
    next(&rx);
    assert!(
        matches!(next(&rx), ToDevice::Error(error) if error.of.as_ref().map(MessageId::as_str) == Some("first") && error.code == ErrorCode::Conflict)
    );
    next(&second_rx);
    next(&second_rx);
    assert!(
        matches!(next(&second_rx), ToDevice::QuestionResult { of, .. } if of.as_str() == "second")
    );
    assert!(guest_rx.try_recv().is_err());
    // A late losing reply cannot overwrite the immutable terminal state.
    native.send(
        "late",
        FromPlugin::QuestionUpdate {
            question: definition.id.clone(),
            state: QuestionState::Answered,
            answer: Some(QuestionAnswer::Choices { indices: vec![0] }),
            of: Some(first.id),
        },
    );
    native.ack("late");
    assert_eq!(
        store.question(&definition.id).unwrap().unwrap().info.state,
        QuestionState::Skipped
    );
    assert_eq!(store.since(OWNER, 0).unwrap().len(), 2);
}

#[test]
fn stale_revisions_errors_timeout_and_connection_fencing_never_resend_or_fabricate_receipts() {
    let (_dir, hub, store, device, rx) = fixture();
    let mut native = native(&hub, vec![Capability::Questions]);
    let definition = definition("q-1");
    ask(&mut native, &rx, &definition);
    let error = hub
        .question_answer(
            &store,
            &device,
            OWNER,
            MessageId::new("stale").unwrap(),
            AnswerRequest {
                question: definition.id.clone(),
                revision: 10,
                answer: QuestionAnswer::Skip,
            },
        )
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::Conflict);
    assert!(matches!(next(&rx), ToDevice::Question { .. }));
    let original = MessageId::new("request").unwrap();
    hub.question_answer(
        &store,
        &device,
        OWNER,
        original.clone(),
        AnswerRequest {
            question: definition.id.clone(),
            revision: 0,
            answer: QuestionAnswer::Skip,
        },
    )
    .unwrap();
    let request = native.receive();
    let epoch = hub.questions.lock().unwrap().connections[AGENT].clone();
    let update = |of| {
        hub.question_update(
            &store,
            Origin {
                agent: AGENT,
                connection: "old-connection",
            },
            Update {
                question: definition.id.clone(),
                state: QuestionState::Skipped,
                answer: None,
                of: Some(MessageId::clone(of)),
            },
            &MessageId::new("stale-update").unwrap(),
        )
    };
    assert!(update(&request.id).is_err());
    assert!(rx.try_recv().is_err());
    hub.question_error(
        &store,
        Origin {
            agent: "lab/helper",
            connection: &epoch,
        },
        failure(request.id.clone(), ErrorCode::NotFound, "not yours"),
    );
    assert!(rx.try_recv().is_err());
    native.send(
        "native-error",
        FromPlugin::Error(failure(
            request.id.clone(),
            ErrorCode::BadMessage,
            "The saved native entry is no longer pending.",
        )),
    );
    assert!(
        matches!(next(&rx), ToDevice::Error(error) if error.of == Some(original.clone()) && error.code == ErrorCode::BadMessage)
    );
    assert_eq!(
        store.question(&definition.id).unwrap().unwrap().info.state,
        QuestionState::Pending
    );
    hub.question_answer(
        &store,
        &device,
        OWNER,
        original.clone(),
        AnswerRequest {
            question: definition.id.clone(),
            revision: 0,
            answer: QuestionAnswer::Skip,
        },
    )
    .unwrap();
    assert!(matches!(next(&rx), ToDevice::Error(error) if error.of == Some(original)));
    let timeout = MessageId::new("timeout").unwrap();
    hub.question_answer(
        &store,
        &device,
        OWNER,
        timeout.clone(),
        AnswerRequest {
            question: definition.id.clone(),
            revision: 0,
            answer: QuestionAnswer::Skip,
        },
    )
    .unwrap();
    let timed = native.receive();
    hub.questions
        .lock()
        .unwrap()
        .pending
        .get_mut(timed.id.as_str())
        .unwrap()
        .started = Instant::now() - TIMEOUT;
    hub.expire_questions(&store);
    assert!(
        matches!(next(&rx), ToDevice::Error(error) if error.of == Some(timeout.clone()) && error.message.contains("unknown") && error.code == ErrorCode::Unconfirmed)
    );
    native.send(
        "late-timeout",
        FromPlugin::QuestionUpdate {
            question: definition.id.clone(),
            state: QuestionState::Skipped,
            answer: None,
            of: Some(timed.id),
        },
    );
    native.ack("late-timeout");
    next(&rx);
    next(&rx);
    assert!(
        rx.try_recv().is_err(),
        "a timed out RPC has no late success receipt"
    );
    hub.question_answer(
        &store,
        &device,
        OWNER,
        timeout.clone(),
        AnswerRequest {
            question: definition.id,
            revision: 0,
            answer: QuestionAnswer::Skip,
        },
    )
    .unwrap();
    assert!(matches!(next(&rx), ToDevice::Error(error) if error.of == Some(timeout)));
}

#[test]
fn revoked_devices_and_wrong_request_payloads_cannot_reuse_an_answer_receipt() {
    let (_dir, hub, store, device, rx) = fixture();
    let mut native = native(&hub, vec![Capability::Questions]);
    let definition = definition("q-1");
    ask(&mut native, &rx, &definition);
    let original = MessageId::new("answer").unwrap();
    hub.question_answer(
        &store,
        &device,
        OWNER,
        original.clone(),
        AnswerRequest {
            question: definition.id.clone(),
            revision: 0,
            answer: QuestionAnswer::Skip,
        },
    )
    .unwrap();
    let request = native.receive();
    let error = hub
        .question_answer(
            &store,
            &device,
            OWNER,
            original.clone(),
            AnswerRequest {
                question: definition.id.clone(),
                revision: 0,
                answer: QuestionAnswer::Text {
                    text: "different".into(),
                },
            },
        )
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::Conflict);
    store.remove_device(&device.id).unwrap();
    native.send(
        "resolved",
        FromPlugin::QuestionUpdate {
            question: definition.id.clone(),
            state: QuestionState::Skipped,
            answer: None,
            of: Some(request.id),
        },
    );
    native.ack("resolved");
    assert!(rx.try_recv().is_err());
    assert_eq!(
        hub.question_answer(
            &store,
            &device,
            OWNER,
            original,
            AnswerRequest {
                question: definition.id,
                revision: 0,
                answer: QuestionAnswer::Skip
            }
        )
        .unwrap_err()
        .code,
        ErrorCode::NotFound
    );
}

#[test]
fn reconnect_reconciles_only_this_agents_pending_questions_in_bounded_batches() {
    let (_dir, hub, store, _device, _rx) = fixture();
    // An agent's pending questions fit one sync batch.
    const { assert!(MAX_PENDING_PER_AGENT as usize <= MAX_SYNC_QUESTIONS) };
    for index in 0..MAX_PENDING_PER_AGENT {
        let conversation = format!("c-{}", index / MAX_PENDING_PER_CONVERSATION);
        store
            .conversation(&conversation, "lab", "coder", OWNER)
            .unwrap();
        store
            .ask_question(
                AGENT,
                &ConversationId::new(conversation).unwrap(),
                &definition(&format!("q-{index}")),
                &format!("ask-{index}"),
                Some(OWNER),
            )
            .unwrap();
    }
    let other = definition("other");
    store
        .ask_question(
            "lab/helper",
            &ConversationId::new("other-agent").unwrap(),
            &other,
            "other-ask",
            Some(OWNER),
        )
        .unwrap();
    let mut native = native(&hub, vec![Capability::Questions]);
    let FromBridge::QuestionSync { questions: first } = native.receive().body else {
        panic!("sync")
    };
    assert_eq!(first.len() as i64, MAX_PENDING_PER_AGENT);
    assert!(!first.contains(&other.id));
    // One more is refused, with an error the channel turns into text.
    native.send(
        "over",
        FromPlugin::QuestionAsk {
            conversation: ConversationId::new("owned").unwrap(),
            question: definition("over"),
        },
    );
    assert!(
        matches!(native.receive().body, FromBridge::Error(error) if error.of.as_ref().map(MessageId::as_str) == Some("over") && error.code == ErrorCode::BadMessage)
    );
    native.ack("over");
    assert!(store.question(&definition("over").id).unwrap().is_none());
    native.send(
        "restart-expiry",
        FromPlugin::QuestionUpdate {
            question: first[0].clone(),
            state: QuestionState::Expired,
            answer: None,
            of: None,
        },
    );
    native.ack("restart-expiry");
    assert_eq!(
        store.question(&first[0]).unwrap().unwrap().info.state,
        QuestionState::Expired
    );
    assert_eq!(
        store.pending_questions(AGENT).unwrap().len() as i64,
        MAX_PENDING_PER_AGENT - 1
    );
}

#[test]
fn a_channel_without_questions_expires_the_cards_it_left() {
    let (_dir, hub, store, _device, rx) = fixture();
    let mut channel = native(&hub, vec![Capability::Questions]);
    let definition = definition("q-1");
    ask(&mut channel, &rx, &definition);
    drop(channel);
    let closed = Instant::now();
    while hub.plugins.lock().unwrap().contains_key(AGENT) {
        assert!(
            closed.elapsed() < Duration::from_secs(2),
            "the bridge saw the close"
        );
        std::thread::yield_now();
    }
    // The channel comes back without the capability (its runtime lost the
    // native API, say): nothing could answer the card any more.
    std::fs::remove_file(&hub.agents[0].socket).unwrap();
    let _native = native(&hub, vec![]);
    assert!(
        matches!(next(&rx), ToDevice::Question { question } if question.definition.id == definition.id && question.state == QuestionState::Expired)
    );
    assert!(
        matches!(next(&rx), ToDevice::Message(message) if message.kind == "status" && message.text == "Question expired.")
    );
    assert!(store.pending_questions(AGENT).unwrap().is_empty());
}

#[test]
fn an_ask_the_bridge_cannot_save_is_refused_so_the_channel_sends_text() {
    let (_dir, hub, _store, _device, _rx) = fixture();
    let mut channel = native(&hub, vec![Capability::Questions]);
    // The database fails the ask's transaction (as a full disk would).
    rusqlite::Connection::open(&hub.store_path)
        .unwrap()
        .execute_batch(
            "CREATE TRIGGER full BEFORE INSERT ON questions BEGIN SELECT RAISE(ABORT, 'disk full'); END;",
        )
        .unwrap();
    channel.send(
        "ask",
        FromPlugin::QuestionAsk {
            conversation: ConversationId::new("owned").unwrap(),
            question: definition("q-1"),
        },
    );
    assert!(
        matches!(channel.receive().body, FromBridge::Error(error) if error.of.as_ref().map(MessageId::as_str) == Some("ask"))
    );
    channel.ack("ask");
}

#[test]
fn questions_no_channel_can_answer_expire_on_the_bridge() {
    let (_dir, hub, store, device, rx) = fixture();
    let owned = ConversationId::new("owned").unwrap();
    let old = definition("old");
    let recent = definition("recent");
    store
        .ask_question(AGENT, &owned, &old, "old-ask", None)
        .unwrap();
    store
        .ask_question(AGENT, &owned, &recent, "recent-ask", None)
        .unwrap();
    // An agent enclos no longer serves: no channel will ever answer.
    let gone = definition("gone");
    store
        .ask_question(
            "lab/helper",
            &ConversationId::new("other-agent").unwrap(),
            &gone,
            "gone-ask",
            None,
        )
        .unwrap();
    store
        .backdate_message("old-ask", now() - UNCONNECTED_LIFETIME_SECONDS - 1)
        .unwrap();
    hub.expire_questions(&store);
    let state = |q: &QuestionDefinition| store.question(&q.id).unwrap().unwrap().info.state;
    assert_eq!(state(&old), QuestionState::Expired);
    assert_eq!(state(&recent), QuestionState::Pending);
    assert_eq!(state(&gone), QuestionState::Expired);
    let mut seen = vec![];
    while let Ok(message) = rx.try_recv() {
        seen.push(message);
    }
    assert!(seen.iter().any(|m| matches!(m, ToDevice::Question { question } if question.definition.id == old.id && question.state == QuestionState::Expired)));
    // A connected channel is trusted to say: its old question stays.
    let mut native = native(&hub, vec![Capability::Questions]);
    let _sync = native.receive();
    store
        .backdate_message("recent-ask", now() - UNCONNECTED_LIFETIME_SECONDS - 1)
        .unwrap();
    hub.questions.lock().unwrap().swept = None;
    hub.expire_questions(&store);
    assert_eq!(state(&recent), QuestionState::Pending);
    // The sweep runs once a minute, not every second.
    store
        .ask_question(AGENT, &owned, &definition("later"), "later-ask", None)
        .unwrap();
    hub.questions.lock().unwrap().connections.clear();
    store
        .backdate_message("later-ask", now() - UNCONNECTED_LIFETIME_SECONDS - 1)
        .unwrap();
    hub.expire_questions(&store);
    assert_eq!(state(&definition("later")), QuestionState::Pending);
    let _ = device;
}

#[test]
fn not_sent_and_unconfirmed_answers_have_distinct_codes_and_one_person_cannot_starve_another() {
    let (_dir, hub, store, device, rx) = fixture();
    let question = definition("q-1");
    store
        .ask_question(
            AGENT,
            &ConversationId::new("owned").unwrap(),
            &question,
            "ask",
            None,
        )
        .unwrap();
    let request = |id: &str| {
        hub.question_answer(
            &store,
            &device,
            OWNER,
            MessageId::new(id).unwrap(),
            AnswerRequest {
                question: question.id.clone(),
                revision: 0,
                answer: QuestionAnswer::Skip,
            },
        )
    };
    // No channel: nothing was sent, answering again is safe.
    assert_eq!(
        request("offline").unwrap_err().code,
        ErrorCode::AgentUnavailable
    );
    let mut native = native(&hub, vec![Capability::Questions]);
    let _sync = native.receive();
    // This person's answers in flight are capped; it says nothing was sent.
    let connection = hub.questions.lock().unwrap().connections[AGENT].clone();
    for index in 0..MAX_PENDING_PER_PERSON {
        hub.questions.lock().unwrap().pending.insert(
            format!("busy-{index}"),
            Pending {
                device: device.id.clone(),
                person: OWNER.into(),
                agent: AGENT.into(),
                connection: connection.clone(),
                original: MessageId::new(format!("busy-{index}")).unwrap(),
                request: AnswerRequest {
                    question: QuestionId::new(format!("busy-{index}")).unwrap(),
                    revision: 0,
                    answer: QuestionAnswer::Skip,
                },
                started: Instant::now(),
            },
        );
    }
    let busy = request("busy").unwrap_err();
    assert_eq!(busy.code, ErrorCode::AgentUnavailable);
    assert!(busy.message.contains("Nothing was sent"));
    // Another person's answer still goes through.
    store
        .conversation("guest-c", "lab", "coder", "guest@example.com")
        .unwrap();
    let theirs = definition("theirs");
    store
        .ask_question(
            AGENT,
            &ConversationId::new("guest-c").unwrap(),
            &theirs,
            "theirs-ask",
            None,
        )
        .unwrap();
    let (guest, _guest_rx) = phone(&hub, &store, "guest", "guest@example.com");
    hub.question_answer(
        &store,
        &guest,
        "guest@example.com",
        MessageId::new("guest-answer").unwrap(),
        AnswerRequest {
            question: theirs.id.clone(),
            revision: 0,
            answer: QuestionAnswer::Skip,
        },
    )
    .unwrap();
    assert!(
        matches!(native.receive().body, FromBridge::QuestionAnswer { question, .. } if question == theirs.id)
    );
    // Sent, then the channel goes: the outcome is unknown.
    hub.questions
        .lock()
        .unwrap()
        .pending
        .retain(|key, _| !key.starts_with("busy-"));
    request("sent").unwrap();
    let _sent = native.receive();
    drop(native);
    assert!(
        matches!(next(&rx), ToDevice::Error(error) if error.of.as_ref().map(MessageId::as_str) == Some("sent") && error.code == ErrorCode::Unconfirmed)
    );
}

#[test]
fn only_a_matched_device_answer_reads_as_the_persons_in_history() {
    let (_dir, hub, store, device, rx) = fixture();
    let mut native = native(&hub, vec![Capability::Questions]);
    let first = definition("q-1");
    ask(&mut native, &rx, &first);
    hub.question_answer(
        &store,
        &device,
        OWNER,
        MessageId::new("answer").unwrap(),
        AnswerRequest {
            question: first.id.clone(),
            revision: 0,
            answer: QuestionAnswer::Choices { indices: vec![1] },
        },
    )
    .unwrap();
    let request = native.receive();
    native.send(
        "answered",
        FromPlugin::QuestionUpdate {
            question: first.id.clone(),
            state: QuestionState::Answered,
            answer: Some(QuestionAnswer::Choices { indices: vec![1] }),
            of: Some(request.id),
        },
    );
    native.ack("answered");
    assert!(matches!(next(&rx), ToDevice::Question { question } if question.confirmed));
    assert!(matches!(next(&rx), ToDevice::Message(m) if m.text == "Answered: Classement"));
    assert!(matches!(next(&rx), ToDevice::QuestionResult { question, .. } if question.confirmed));
    // The agent claims an answer nobody sent: the history says whose claim it is.
    native.send(
        "ask-2",
        FromPlugin::QuestionAsk {
            conversation: ConversationId::new("owned").unwrap(),
            question: definition("q-2"),
        },
    );
    native.ack("ask-2");
    next(&rx);
    next(&rx);
    native.send(
        "claimed",
        FromPlugin::QuestionUpdate {
            question: definition("q-2").id,
            state: QuestionState::Answered,
            answer: Some(QuestionAnswer::Text {
                text: "Delete everything".into(),
            }),
            of: None,
        },
    );
    native.ack("claimed");
    // The card, too, shows it as the agent's report, not the person's choice.
    assert!(
        matches!(next(&rx), ToDevice::Question { question } if question.state == QuestionState::Answered && !question.confirmed)
    );
    assert!(
        matches!(next(&rx), ToDevice::Message(m) if m.text == "Answered, as the agent reports: Delete everything")
    );
}

#[test]
fn large_unicode_question_frames_and_readable_history_remain_below_noise_budget() {
    let (_dir, hub, store, _device, rx) = fixture();
    let mut native = native(&hub, vec![Capability::Questions]);
    let mut definition = definition("q-large");
    definition.text = "🤖".repeat(3000);
    definition.choices = vec!["🧪".repeat(2500), "Other".into()];
    definition.validate().unwrap();
    ask(&mut native, &rx, &definition);
    // Replay through the real router to inspect every live frame without duplicating history.
    native.send(
        "ask-replay",
        FromPlugin::QuestionAsk {
            conversation: ConversationId::new("owned").unwrap(),
            question: definition.clone(),
        },
    );
    native.ack("ask-replay");
    for frame in [next(&rx), next(&rx)] {
        assert!(bounded(&frame));
    }
    native.send(
        "text-answer",
        FromPlugin::QuestionUpdate {
            question: definition.id.clone(),
            state: QuestionState::Answered,
            answer: Some(QuestionAnswer::Text {
                text: "é".repeat(3500),
            }),
            of: None,
        },
    );
    native.ack("text-answer");
    for frame in [next(&rx), next(&rx)] {
        assert!(bounded(&frame));
    }
    assert_eq!(store.since(OWNER, 0).unwrap().len(), 2);
    let mut invalid = definition;
    invalid.id = QuestionId::new("too-big").unwrap();
    invalid.text = "🤖".repeat(7000);
    native.send(
        "oversized",
        FromPlugin::QuestionAsk {
            conversation: ConversationId::new("owned").unwrap(),
            question: invalid.clone(),
        },
    );
    assert!(
        matches!(native.receive().body, FromBridge::Error(error) if error.code == ErrorCode::BadMessage)
    );
    native.ack("oversized");
    assert!(store.question(&invalid.id).unwrap().is_none());
}

#[test]
fn encrypted_device_sync_refreshes_pending_past_since_and_joins_current_terminal_state() {
    use enclos_protocol::device::decode_to_device;
    use enclos_protocol::noise::{Initiator, Responder, generate_keypair};
    let (_dir, hub, store, device, rx) = fixture();
    let mut definition = definition("pending-before-since");
    definition.text = "🤖".repeat(3000);
    let introduced = store
        .ask_question(
            AGENT,
            &ConversationId::new("owned").unwrap(),
            &definition,
            "introduction",
            Some(OWNER),
        )
        .unwrap()
        .message
        .unwrap()
        .seq;
    store
        .ask_question(
            AGENT,
            &ConversationId::new("foreign").unwrap(),
            &super::tests::definition("foreign-question"),
            "foreign-introduction",
            Some(OWNER),
        )
        .unwrap();
    let bridge_key = generate_keypair().unwrap();
    let device_key = generate_keypair().unwrap();
    let mut initiator = Initiator::new(&device_key.private, &bridge_key.public).unwrap();
    let mut responder = Responder::new(&bridge_key.private).unwrap();
    responder.read_hello(&initiator.hello().unwrap()).unwrap();
    let (answer, bridge_session) = responder.answer().unwrap();
    let mut device_session = initiator.finish(&answer).unwrap();
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
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
        run_session(&server_hub, &store, &mut link, &device, OWNER, &rx)
    });
    let stream = TcpStream::connect(address).unwrap();
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
            assert!(encoded.len() <= enclos_protocol::noise::MAX_NOISE_MESSAGE);
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
    let pending = sync(introduced);
    assert!(pending.iter().any(|message| matches!(message, ToDevice::Question { question } if question.definition.id == definition.id && question.state == QuestionState::Pending)));
    assert!(
        !pending
            .iter()
            .any(|message| matches!(message, ToDevice::Message(_))),
        "no history was introduced after since"
    );
    assert!(!pending.iter().any(|message| matches!(message, ToDevice::Question { question } if question.definition.id.as_str() == "foreign-question")));
    store
        .settle_question(
            AGENT,
            &definition.id,
            Settlement::reported(
                QuestionState::Answered,
                Some(QuestionAnswer::Text {
                    text: "Gégé Commit".into(),
                }),
            ),
            "settled-offline",
        )
        .unwrap();
    let incremental = sync(introduced);
    let status = incremental
        .iter()
        .position(
            |message| matches!(message, ToDevice::Message(message) if message.kind == "status"),
        )
        .unwrap();
    assert!(
        matches!(&incremental[status-1], ToDevice::Question { question } if question.state == QuestionState::Answered && question.revision == 1)
    );
    let all = sync(0);
    for (index, message) in all.iter().enumerate() {
        if let ToDevice::Message(message) = message
            && message.question.as_ref() == Some(&definition.id)
        {
            assert!(
                matches!(&all[index-1], ToDevice::Question { question } if question.state == QuestionState::Answered && question.revision == 1)
            );
        }
    }
    socket.close(None).unwrap();
    assert_eq!(thread.join().unwrap(), Err("closed".into()));
}

fn approval_definition(id: &str, smart_denied: bool) -> QuestionDefinition {
    use enclos_protocol::question::{RuntimeApprovalAction as Action, RuntimeApprovalDefinition};
    QuestionDefinition {
        id: QuestionId::new(id).unwrap(),
        text: "Allow this command?".into(),
        choices: vec![],
        multiple: false,
        approval: Some(RuntimeApprovalDefinition {
            command: "npm install --ignore-scripts".into(),
            reason: "Install the project's dependencies.".into(),
            actions: if smart_denied {
                vec![Action::Once, Action::Deny]
            } else {
                vec![Action::Once, Action::Session, Action::Always, Action::Deny]
            },
            smart_denied,
            patterns: if smart_denied {
                vec![]
            } else {
                vec!["package install scripts".into()]
            },
        }),
    }
}

fn approval(action: enclos_protocol::question::RuntimeApprovalAction) -> QuestionAnswer {
    QuestionAnswer::Approval { action }
}

#[test]
fn runtime_approval_uses_its_own_capability_exact_receipt_and_scope_history() {
    use enclos_protocol::question::RuntimeApprovalAction as Action;
    let (_dir, hub, store, device, rx) = fixture();
    let mut native = native(&hub, vec![Capability::RuntimeApprovals]);
    let definition = approval_definition("command-1", false);
    ask(&mut native, &rx, &definition);
    let history = store.since(OWNER, 0).unwrap();
    assert_eq!(history[0].kind, "runtime_approval");
    assert!(history[0].text.contains("npm install --ignore-scripts"));
    assert!(
        history[0]
            .text
            .contains("Install the project's dependencies.")
    );
    // Its actions, and no typed command: none is passed on (ADR 0060).
    assert!(history[0].text.contains("Allow for session"));
    assert!(!history[0].text.contains("/approve") && !history[0].text.contains("/deny"));
    let original = MessageId::new("allow-session").unwrap();
    hub.question_answer(
        &store,
        &device,
        OWNER,
        original.clone(),
        AnswerRequest {
            question: definition.id.clone(),
            revision: 0,
            answer: approval(Action::Session),
        },
    )
    .unwrap();
    let request = native.receive();
    let FromBridge::QuestionAnswer {
        conversation,
        question,
        answer,
        signed: Some(signed),
    } = request.body.clone()
    else {
        panic!(
            "a runtime approval's decision goes signed: {:?}",
            request.body
        )
    };
    assert_eq!(
        (conversation.as_str(), &question, &answer),
        ("owned", &definition.id, &approval(Action::Session))
    );
    // Signed by the bridge's key over this exact decision: this request,
    // this approval of this agent, this action, command, reason and scope.
    let shown = definition.approval.as_ref().unwrap();
    let decision = enclos_protocol::decision::Decision {
        agent: AGENT,
        conversation: "owned",
        question: definition.id.as_str(),
        request: request.id.as_str(),
        action: "session",
        command: &shown.command,
        reason: &shown.reason,
        patterns: &shown.patterns,
    };
    assert!((signed.at - now()).abs() <= 5);
    let public = approval_key().public();
    assert_eq!(
        enclos_protocol::decision::check(&public, &decision, &signed, now()),
        Ok(())
    );
    let wider = enclos_protocol::decision::Decision {
        action: "always",
        ..decision
    };
    assert!(enclos_protocol::decision::check(&public, &wider, &signed, now()).is_err());
    assert!(rx.try_recv().is_err());
    native.send(
        "watcher",
        FromPlugin::QuestionUpdate {
            question: definition.id.clone(),
            state: QuestionState::Answered,
            answer: Some(approval(Action::Session)),
            of: None,
        },
    );
    native.ack("watcher");
    assert!(
        matches!(next(&rx), ToDevice::Question { question } if question.answer == Some(approval(Action::Session)))
    );
    assert!(
        matches!(next(&rx), ToDevice::Message(message) if message.kind == "status" && message.text.contains("runtime session") && !message.text.contains("executed"))
    );
    assert!(
        rx.try_recv().is_err(),
        "native metadata alone is never a receipt"
    );
    native.send(
        "receipt",
        FromPlugin::QuestionUpdate {
            question: definition.id.clone(),
            state: QuestionState::Answered,
            answer: Some(approval(Action::Session)),
            of: Some(request.id),
        },
    );
    native.ack("receipt");
    next(&rx);
    next(&rx);
    assert!(
        matches!(next(&rx), ToDevice::QuestionResult { of, question } if of == original && question.answer == Some(approval(Action::Session)) && question.revision == 1)
    );
    assert_eq!(store.since(OWNER, 0).unwrap().len(), 2);
}

#[test]
fn runtime_approval_decisions_require_known_host_person_and_current_conversation_owner() {
    use enclos_protocol::question::RuntimeApprovalAction as Action;
    let (_dir, hub, store, device, _rx) = fixture();
    let mut native = native(
        &hub,
        vec![Capability::Questions, Capability::RuntimeApprovals],
    );
    let owned = approval_definition("owned-approval", false);
    let foreign = approval_definition("guest-approval", false);
    store
        .ask_question(
            AGENT,
            &ConversationId::new("owned").unwrap(),
            &owned,
            "owned-intro",
            Some(OWNER),
        )
        .unwrap();
    store
        .ask_question(
            AGENT,
            &ConversationId::new("foreign").unwrap(),
            &foreign,
            "foreign-intro",
            // As if its owner were the host's person when it was asked: the
            // bridge still refuses its answers now that they are not.
            Some("guest@example.com"),
        )
        .unwrap();
    let (guest, _guest_rx) = phone(&hub, &store, "guest-phone", "guest@example.com");
    for (caller, person, question) in [
        (&guest, "guest@example.com", &foreign.id),
        (&guest, "guest@example.com", &owned.id),
        (&device, OWNER, &foreign.id),
    ] {
        let error = hub
            .question_answer(
                &store,
                caller,
                person,
                MessageId::new("unauthorized").unwrap(),
                AnswerRequest {
                    question: question.clone(),
                    revision: 0,
                    answer: approval(Action::Deny),
                },
            )
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::NotFound);
        assert_eq!(error.message, "No such question.");
    }
    let ordinary = definition("guest-question");
    store
        .ask_question(
            AGENT,
            &ConversationId::new("foreign").unwrap(),
            &ordinary,
            "ordinary-intro",
            Some(OWNER),
        )
        .unwrap();
    hub.question_answer(
        &store,
        &guest,
        "guest@example.com",
        MessageId::new("guest-answer").unwrap(),
        AnswerRequest {
            question: ordinary.id.clone(),
            revision: 0,
            answer: QuestionAnswer::Skip,
        },
    )
    .unwrap();
    assert!(
        matches!(native.receive().body, FromBridge::QuestionAnswer { question, answer: QuestionAnswer::Skip, .. } if question == ordinary.id)
    );
    for host in [None, Some("another-person@example.com".to_owned())] {
        let (_dir, hub, store, device, _rx) = fixture();
        set_host(&hub, host.as_deref());
        let definition = approval_definition("unknown-host", false);
        store
            .ask_question(
                AGENT,
                &ConversationId::new("owned").unwrap(),
                &definition,
                "approval-intro",
                Some(OWNER),
            )
            .unwrap();
        assert_eq!(
            hub.question_answer(
                &store,
                &device,
                OWNER,
                MessageId::new("decision").unwrap(),
                AnswerRequest {
                    question: definition.id,
                    revision: 0,
                    answer: approval(Action::Once)
                }
            )
            .unwrap_err()
            .code,
            ErrorCode::NotFound
        );
    }
}

#[test]
fn runtime_approval_rejects_unoffered_or_generic_answers_before_native_dispatch() {
    use enclos_protocol::question::RuntimeApprovalAction as Action;
    let (_dir, hub, store, device, rx) = fixture();
    let mut native = native(&hub, vec![Capability::RuntimeApprovals]);
    let definition = approval_definition("once-only", true);
    ask(&mut native, &rx, &definition);
    for (index, answer) in [
        approval(Action::Session),
        approval(Action::Always),
        QuestionAnswer::Skip,
        QuestionAnswer::Choices { indices: vec![0] },
        QuestionAnswer::Text {
            text: "/approve always".into(),
        },
    ]
    .into_iter()
    .enumerate()
    {
        let error = hub
            .question_answer(
                &store,
                &device,
                OWNER,
                MessageId::new(format!("bad-{index}")).unwrap(),
                AnswerRequest {
                    question: definition.id.clone(),
                    revision: 0,
                    answer,
                },
            )
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::BadMessage);
    }
    assert!(hub.questions.lock().unwrap().pending.is_empty());
    hub.question_answer(
        &store,
        &device,
        OWNER,
        MessageId::new("deny").unwrap(),
        AnswerRequest {
            question: definition.id.clone(),
            revision: 0,
            answer: approval(Action::Deny),
        },
    )
    .unwrap();
    let request = native.receive();
    assert!(matches!(
        request.body,
        FromBridge::QuestionAnswer {
            answer: QuestionAnswer::Approval {
                action: Action::Deny
            },
            ..
        }
    ));
    store.remove_device(&device.id).unwrap();
    native.send(
        "denied",
        FromPlugin::QuestionUpdate {
            question: definition.id.clone(),
            state: QuestionState::Answered,
            answer: Some(approval(Action::Deny)),
            of: Some(request.id),
        },
    );
    native.ack("denied");
    assert!(
        rx.try_recv().is_err(),
        "a revoked phone receives neither command metadata nor a receipt"
    );
    assert_eq!(
        store.question(&definition.id).unwrap().unwrap().info.answer,
        Some(approval(Action::Deny))
    );
}

#[test]
fn questions_capability_does_not_authorize_runtime_approval_controls_or_introductions() {
    use enclos_protocol::question::RuntimeApprovalAction as Action;
    let (_dir, hub, store, device, rx) = fixture();
    let mut native = native(&hub, vec![Capability::Questions]);
    let definition = approval_definition("not-supported", false);
    native.send(
        "unsupported-intro",
        FromPlugin::QuestionAsk {
            conversation: ConversationId::new("owned").unwrap(),
            question: definition.clone(),
        },
    );
    assert!(
        matches!(native.receive().body, FromBridge::Error(error) if error.code == ErrorCode::BadMessage)
    );
    native.ack("unsupported-intro");
    assert!(store.question(&definition.id).unwrap().is_none());
    assert!(rx.try_recv().is_err());
    store
        .ask_question(
            AGENT,
            &ConversationId::new("owned").unwrap(),
            &definition,
            "saved-intro",
            Some(OWNER),
        )
        .unwrap();
    let error = hub
        .question_answer(
            &store,
            &device,
            OWNER,
            MessageId::new("unsupported-answer").unwrap(),
            AnswerRequest {
                question: definition.id,
                revision: 0,
                answer: approval(Action::Once),
            },
        )
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::Unsupported);
    let ordinary = super::tests::definition("ordinary");
    ask(&mut native, &rx, &ordinary);
    assert_eq!(
        hub.question_answer(
            &store,
            &device,
            OWNER,
            MessageId::new("wrong-kind").unwrap(),
            AnswerRequest {
                question: ordinary.id,
                revision: 0,
                answer: approval(Action::Once)
            }
        )
        .unwrap_err()
        .code,
        ErrorCode::BadMessage
    );
}

#[test]
fn runtime_approval_native_race_stale_origin_and_resolved_external_state_never_invent_success() {
    use enclos_protocol::question::RuntimeApprovalAction as Action;
    let (_dir, hub, store, device, rx) = fixture();
    let mut native = native(&hub, vec![Capability::RuntimeApprovals]);
    let definition = approval_definition("race", false);
    ask(&mut native, &rx, &definition);
    let (second, second_rx) = phone(&hub, &store, "second-phone", OWNER);
    hub.question_answer(
        &store,
        &device,
        OWNER,
        MessageId::new("allow").unwrap(),
        AnswerRequest {
            question: definition.id.clone(),
            revision: 0,
            answer: approval(Action::Once),
        },
    )
    .unwrap();
    let first = native.receive();
    hub.question_answer(
        &store,
        &second,
        OWNER,
        MessageId::new("deny").unwrap(),
        AnswerRequest {
            question: definition.id.clone(),
            revision: 0,
            answer: approval(Action::Deny),
        },
    )
    .unwrap();
    let second_request = native.receive();
    let epoch = hub.questions.lock().unwrap().connections[AGENT].clone();
    assert!(
        hub.question_update(
            &store,
            questions::Origin {
                agent: "lab/helper",
                connection: &epoch
            },
            questions::Update {
                question: definition.id.clone(),
                state: QuestionState::Answered,
                answer: Some(approval(Action::Always)),
                of: Some(first.id.clone())
            },
            &MessageId::new("wrong-origin").unwrap()
        )
        .is_err()
    );
    native.send(
        "deny-wins",
        FromPlugin::QuestionUpdate {
            question: definition.id.clone(),
            state: QuestionState::Answered,
            answer: Some(approval(Action::Deny)),
            of: Some(second_request.id),
        },
    );
    native.ack("deny-wins");
    next(&rx);
    next(&rx);
    assert!(matches!(next(&rx), ToDevice::Error(error) if error.code == ErrorCode::Conflict));
    next(&second_rx);
    next(&second_rx);
    assert!(
        matches!(next(&second_rx), ToDevice::QuestionResult { question, .. } if question.answer == Some(approval(Action::Deny)))
    );
    native.send(
        "late-allow",
        FromPlugin::QuestionUpdate {
            question: definition.id.clone(),
            state: QuestionState::Answered,
            answer: Some(approval(Action::Once)),
            of: Some(first.id),
        },
    );
    native.ack("late-allow");
    assert_eq!(
        store.question(&definition.id).unwrap().unwrap().info.answer,
        Some(approval(Action::Deny))
    );
    let (_dir, hub, store, device, rx) = fixture();
    let mut native = super::tests::native(&hub, vec![Capability::RuntimeApprovals]);
    let definition = approval_definition("resolved-elsewhere", false);
    ask(&mut native, &rx, &definition);
    hub.question_answer(
        &store,
        &device,
        OWNER,
        MessageId::new("allow").unwrap(),
        AnswerRequest {
            question: definition.id.clone(),
            revision: 0,
            answer: approval(Action::Always),
        },
    )
    .unwrap();
    let _request = native.receive();
    native.send(
        "external",
        FromPlugin::QuestionUpdate {
            question: definition.id.clone(),
            state: QuestionState::Resolved,
            answer: None,
            of: None,
        },
    );
    native.ack("external");
    assert!(
        matches!(next(&rx), ToDevice::Question { question } if question.state == QuestionState::Resolved && question.answer.is_none())
    );
    assert!(
        matches!(next(&rx), ToDevice::Message(message) if message.text == "Runtime approval resolved in the runtime.")
    );
    assert!(matches!(next(&rx), ToDevice::Error(error) if error.code == ErrorCode::Conflict));
    assert_eq!(store.since(OWNER, 0).unwrap().len(), 2);
}

#[test]
fn deny_only_runtime_gate_cannot_be_upgraded_to_allow_once() {
    use enclos_protocol::question::RuntimeApprovalAction as Action;
    let (_dir, hub, store, device, rx) = fixture();
    let mut native = native(&hub, vec![Capability::RuntimeApprovals]);
    let mut definition = approval_definition("deny-only", true);
    definition.approval.as_mut().unwrap().actions = vec![Action::Deny];
    ask(&mut native, &rx, &definition);
    let error = hub
        .question_answer(
            &store,
            &device,
            OWNER,
            MessageId::new("allow-once").unwrap(),
            AnswerRequest {
                question: definition.id.clone(),
                revision: 0,
                answer: approval(Action::Once),
            },
        )
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::BadMessage);
    hub.question_answer(
        &store,
        &device,
        OWNER,
        MessageId::new("deny").unwrap(),
        AnswerRequest {
            question: definition.id,
            revision: 0,
            answer: approval(Action::Deny),
        },
    )
    .unwrap();
    assert!(matches!(
        native.receive().body,
        FromBridge::QuestionAnswer {
            answer: QuestionAnswer::Approval {
                action: Action::Deny
            },
            ..
        }
    ));
}

#[test]
fn newline_heavy_command_is_preserved_in_bounded_native_and_legacy_history_frames() {
    let (_dir, hub, store, _device, rx) = fixture();
    let mut native = native(&hub, vec![Capability::RuntimeApprovals]);
    let mut definition = approval_definition("multiline-command", false);
    let command = format!("{}echo complete", "\n".repeat(11_000));
    definition.approval.as_mut().unwrap().command = command.clone();
    definition.validate().unwrap();
    ask(&mut native, &rx, &definition);
    native.send(
        "replay",
        FromPlugin::QuestionAsk {
            conversation: ConversationId::new("owned").unwrap(),
            question: definition.clone(),
        },
    );
    native.ack("replay");
    for message in [next(&rx), next(&rx)] {
        assert!(bounded(&message));
    }
    let history = store.since(OWNER, 0).unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].kind, "runtime_approval");
    assert!(history[0].text.contains(&command));
}

#[test]
fn typed_approval_commands_are_read_as_the_runtime_reads_them() {
    for text in [
        "/approve",
        "  /approve always",
        "/APPROVE session",
        "/approve@enclos_bot all",
        "/deny",
        "/Deny because no",
        "@file:/tmp/x.txt\n/approve always",
        "@IMAGE:/tmp/a.png\n@url:https://example.com\n  /deny all",
        "\n\t/approve",
        // Python's `lstrip` and `split`, which Hermes uses, take U+001C to
        // U+001F for whitespace.
        "\u{1F}/approve always",
        "/approve\u{1F}always",
        "\u{1C}\u{1D}\u{1E}/deny",
        "@file:/tmp/x\n\u{1F}/approve",
        // No approval for the rest of the session, or none at all.
        "/yolo",
        "/YOLO@enclos_bot",
        "/approvals off",
    ] {
        assert!(super::typed_approval(text), "{text:?}");
    }
    for text in [
        "approve",
        "please /approve",
        "/approved",
        "/approve/x",
        "/denyall",
        "",
        "   ",
        "\u{200B}/approve",
        "/sethome",
    ] {
        assert!(!super::typed_approval(text), "{text:?}");
    }
}

type DeviceSend = Box<dyn FnMut(&str, FromDevice) -> Option<ToDevice>>;

/// An encrypted device session with the bridge, run on a thread: `send`
/// returns the bridge's next message, if one comes in half a second.
fn device_session(
    hub: &Arc<Hub>,
    device: Device,
    person: &'static str,
    rx: Receiver<ToDevice>,
) -> (DeviceSend, std::thread::JoinHandle<Result<(), String>>) {
    use enclos_protocol::device::decode_to_device;
    use enclos_protocol::noise::{Initiator, Responder, generate_keypair};
    let bridge_key = generate_keypair().unwrap();
    let device_key = generate_keypair().unwrap();
    let mut initiator = Initiator::new(&device_key.private, &bridge_key.public).unwrap();
    let mut responder = Responder::new(&bridge_key.private).unwrap();
    responder.read_hello(&initiator.hello().unwrap()).unwrap();
    let (answer, bridge_session) = responder.answer().unwrap();
    let mut device_noise = initiator.finish(&answer).unwrap();
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let address = listener.local_addr().unwrap();
    let server_hub = Arc::clone(hub);
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
        run_session(&server_hub, &store, &mut link, &device, person, &rx)
    });
    let stream = TcpStream::connect(address).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    let (mut socket, _) = tungstenite::client(format!("ws://{address}"), stream).unwrap();
    let send = move |id: &str, body: FromDevice| {
        let message = encode_line(&Envelope::new(MessageId::new(id).unwrap(), body));
        socket
            .send(Message::Binary(
                device_noise.encrypt(&message).unwrap().into(),
            ))
            .unwrap();
        match socket.read() {
            Ok(Message::Binary(encoded)) => Some(
                decode_to_device(&device_noise.decrypt(&encoded).unwrap())
                    .unwrap()
                    .body,
            ),
            _ => None,
        }
    };
    (Box::new(send), thread)
}

#[test]
fn no_one_can_type_a_runtime_approval() {
    let (_dir, hub, store, device, rx) = fixture();
    let mut native = native(&hub, vec![Capability::RuntimeApprovals]);
    let (guest, guest_rx) = phone(&hub, &store, "guest-phone", "guest@example.com");
    let (mut guest_send, _guest) = device_session(&hub, guest, "guest@example.com", guest_rx);
    for (index, text) in [
        "/approve always",
        "@file:/tmp/x\n/DENY all",
        "\u{1F}/approve always",
        "/approve\u{1F}always",
        "/yolo",
        "/approvals off",
    ]
    .into_iter()
    .enumerate()
    {
        let id = format!("typed-{index}");
        let reply = guest_send(
            &id,
            FromDevice::MessageSend {
                conversation: ConversationId::new("foreign").unwrap(),
                text: text.into(),
            },
        );
        assert!(
            matches!(&reply, Some(ToDevice::Error(error)) if error.code == ErrorCode::NotAllowed
                && error.of.as_ref().map(MessageId::as_str) == Some(id.as_str())),
            "{reply:?}"
        );
    }
    assert!(
        store.since("guest@example.com", 0).unwrap().is_empty(),
        "a refused approval is neither stored nor relayed"
    );
    // The guest's ordinary message still reaches the runtime, and nothing before it did.
    guest_send(
        "hello",
        FromDevice::MessageSend {
            conversation: ConversationId::new("foreign").unwrap(),
            text: "hello".into(),
        },
    );
    assert!(
        matches!(native.receive().body, FromBridge::MessageIn { text, person, host, .. } if text == "hello" && person.as_str() == "guest@example.com" && host == Some(false))
    );
    // The host's person's typed approval is refused too: a message carries
    // no proof of its person the plugin could check (ADR 0060).
    let (mut host_send, _host) = device_session(&hub, device, OWNER, rx);
    for (index, text) in ["/approve", "/yolo"].into_iter().enumerate() {
        let id = format!("host-typed-{index}");
        let reply = host_send(
            &id,
            FromDevice::MessageSend {
                conversation: ConversationId::new("owned").unwrap(),
                text: text.into(),
            },
        );
        assert!(
            matches!(&reply, Some(ToDevice::Error(error)) if error.code == ErrorCode::NotAllowed
                && error.message.contains("buttons")),
            "{reply:?}"
        );
    }
    host_send(
        "host-hello",
        FromDevice::MessageSend {
            conversation: ConversationId::new("owned").unwrap(),
            text: "hello".into(),
        },
    );
    assert!(
        matches!(native.receive().body, FromBridge::MessageIn { text, host, .. } if text == "hello" && host == Some(true))
    );
}

#[test]
fn an_approval_nobody_may_answer_is_refused_so_the_runtime_denies_it() {
    let (_dir, hub, store, _device, rx) = fixture();
    let (_guest, guest_rx) = phone(&hub, &store, "guest-phone", "guest@example.com");
    let mut native = native(&hub, vec![Capability::RuntimeApprovals]);
    let definition = approval_definition("guest-approval", false);
    native.send(
        "guest-ask",
        FromPlugin::QuestionAsk {
            conversation: ConversationId::new("foreign").unwrap(),
            question: definition.clone(),
        },
    );
    // `not_allowed`: the channel denies it at once rather than leave the
    // runtime waiting out its timeout on a card no device shows.
    assert!(
        matches!(native.receive().body, FromBridge::Error(error) if error.code == ErrorCode::NotAllowed
            && error.of.as_ref().map(MessageId::as_str) == Some("guest-ask"))
    );
    native.ack("guest-ask");
    assert!(store.question(&definition.id).unwrap().is_none());
    assert!(store.since("guest@example.com", 0).unwrap().is_empty());
    assert!(guest_rx.try_recv().is_err());
    assert!(rx.try_recv().is_err());
    // In the host's person's own conversation it is a card, with no typed command.
    let definition = approval_definition("host-approval", false);
    ask(&mut native, &rx, &definition);
    let text = &store.since(OWNER, 0).unwrap()[0].text;
    assert!(
        !text.contains("/approve") && text.contains("Always allow"),
        "{text}"
    );
    assert!(text.contains("every command matching: package install scripts"));
    assert!(!hub.shows_question("guest@example.com", &definition));
    assert!(hub.shows_question(OWNER, &definition));
    assert!(hub.shows_question("guest@example.com", &super::tests::definition("ordinary")));
}

#[test]
fn runtime_approvals_are_capped_per_conversation_and_per_agent() {
    use super::super::super::store::{
        MAX_PENDING_APPROVALS_PER_AGENT, MAX_PENDING_APPROVALS_PER_CONVERSATION,
    };
    let (_dir, hub, store, _device, rx) = fixture();
    let mut native = native(&hub, vec![Capability::RuntimeApprovals]);
    for index in 0..MAX_PENDING_APPROVALS_PER_CONVERSATION {
        ask_with(
            &mut native,
            &rx,
            &approval_definition(&format!("a-{index}"), false),
            &format!("ask-{index}"),
        );
    }
    native.send(
        "over",
        FromPlugin::QuestionAsk {
            conversation: ConversationId::new("owned").unwrap(),
            question: approval_definition("a-over", false),
        },
    );
    assert!(
        matches!(native.receive().body, FromBridge::Error(error) if error.code == ErrorCode::BadMessage
            && error.of.as_ref().map(MessageId::as_str) == Some("over"))
    );
    native.ack("over");
    assert!(
        store
            .question(&approval_definition("a-over", false).id)
            .unwrap()
            .is_none()
    );
    // An ordinary question is not one of them.
    ask_with(&mut native, &rx, &definition("q-ordinary"), "ask-ordinary");
    // Across conversations, the agent's own cap.
    for asked in MAX_PENDING_APPROVALS_PER_CONVERSATION..=MAX_PENDING_APPROVALS_PER_AGENT {
        let id = format!("c-{asked}");
        store.conversation(&id, "lab", "coder", OWNER).unwrap();
        native.send(
            &id,
            FromPlugin::QuestionAsk {
                conversation: ConversationId::new(id.clone()).unwrap(),
                question: approval_definition(&format!("{id}-a"), false),
            },
        );
        if asked == MAX_PENDING_APPROVALS_PER_AGENT {
            assert!(matches!(native.receive().body, FromBridge::Error(_)));
            native.ack(&id);
            break;
        }
        native.ack(&id);
        next(&rx);
        next(&rx);
    }
    assert_eq!(
        store.pending_approvals(AGENT).unwrap().len() as i64,
        MAX_PENDING_APPROVALS_PER_AGENT
    );
}

#[test]
fn a_channel_without_runtime_approvals_expires_the_approvals_it_left() {
    let (_dir, hub, store, _device, rx) = fixture();
    let mut channel = native(
        &hub,
        vec![Capability::RuntimeApprovals, Capability::Questions],
    );
    let approval = approval_definition("approval", false);
    ask(&mut channel, &rx, &approval);
    let question = definition("question");
    ask_with(&mut channel, &rx, &question, "ask-question");
    drop(channel);
    let closed = Instant::now();
    while hub.plugins.lock().unwrap().contains_key(AGENT) {
        assert!(
            closed.elapsed() < Duration::from_secs(2),
            "the bridge saw the close"
        );
        std::thread::yield_now();
    }
    std::fs::remove_file(&hub.agents[0].socket).unwrap();
    let _channel = native(&hub, vec![Capability::Questions]);
    assert!(
        matches!(next(&rx), ToDevice::Question { question } if question.definition.id == approval.id && question.state == QuestionState::Expired)
    );
    assert!(
        matches!(next(&rx), ToDevice::Message(message) if message.kind == "status" && message.text == "Runtime approval expired.")
    );
    assert!(store.pending_approvals(AGENT).unwrap().is_empty());
    // Its ordinary question, which the channel can still answer, stays.
    assert_eq!(store.pending_questions(AGENT).unwrap(), [question.id]);
}

#[test]
fn an_approval_the_agent_reports_is_not_read_as_the_persons_decision() {
    use enclos_protocol::question::RuntimeApprovalAction as Action;
    let (_dir, hub, store, _device, rx) = fixture();
    let mut native = native(&hub, vec![Capability::RuntimeApprovals]);
    let definition = approval_definition("claimed", false);
    ask(&mut native, &rx, &definition);
    // No device asked for it: a channel says the person always allowed it.
    native.send(
        "claimed",
        FromPlugin::QuestionUpdate {
            question: definition.id.clone(),
            state: QuestionState::Answered,
            answer: Some(approval(Action::Always)),
            of: None,
        },
    );
    native.ack("claimed");
    next(&rx);
    let ToDevice::Message(message) = next(&rx) else {
        panic!("history")
    };
    assert_eq!(
        message.text,
        "Runtime approval: always allowed by this runtime, as the agent reports."
    );
    assert_eq!(store.since(OWNER, 0).unwrap()[1].text, message.text);
}

#[test]
fn approval_history_reveals_hidden_characters_in_the_command() {
    let (_dir, hub, store, _device, rx) = fixture();
    let mut native = native(&hub, vec![Capability::RuntimeApprovals]);
    let mut definition = approval_definition("hidden", false);
    definition.approval.as_mut().unwrap().command = "ls #\u{202E}fr- mr".into();
    ask(&mut native, &rx, &definition);
    let text = &store.since(OWNER, 0).unwrap()[0].text;
    assert!(text.contains("ls #⟨U+202E⟩fr- mr"), "{text}");
    assert!(!text.contains('\u{202E}'));
    assert!(text.contains("outside ASCII"));
}

/// Names `host` the host's person in the bridge's database, or nobody.
fn set_host(hub: &Hub, host: Option<&str>) {
    let store = hub.store().unwrap();
    match host {
        Some(person) => store.set_host(person).unwrap(),
        None => {
            rusqlite::Connection::open(&hub.store_path)
                .unwrap()
                .execute("DELETE FROM settings WHERE name = 'host_person'", [])
                .unwrap();
        }
    }
}
