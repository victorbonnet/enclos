use super::super::super::store::{MAX_PENDING_PER_AGENT, MAX_PENDING_PER_CONVERSATION};
use super::*;
use enclos_protocol::plugin::decode_from_bridge;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};

const OWNER: &str = "owner@example.com";
const AGENT: &str = "lab/coder";

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
    let hub = Arc::new(Hub {
        transport: Transport::Tailscale,
        store_path: dir.path().join("app.db"),
        layout: crate::layout::Layout::at(dir.path().join("enclos")),
        bridge_private: vec![],
        agents: vec![AgentEndpoint {
            name: AGENT.into(),
            runtime: "hermes".into(),
            socket: dir.path().join("plugin.sock"),
            token: "secret".into(),
        }],
        host: Some(OWNER.into()),
        plugins: Mutex::new(HashMap::new()),
        routines: Mutex::new(Default::default()),
        questions: Mutex::new(Default::default()),
        commands: Mutex::new(HashMap::new()),
        groups: Mutex::new(HashMap::new()),
        stops: Mutex::new(Default::default()),
        devices: Mutex::new(HashMap::new()),
    });
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
    };
    store.add_device(&device).unwrap();
    let (tx, rx) = channel();
    hub.devices
        .lock()
        .unwrap()
        .insert(id.into(), (person.into(), tx));
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
    }
}

fn next(rx: &Receiver<ToDevice>) -> ToDevice {
    rx.recv_timeout(Duration::from_secs(2)).unwrap()
}
fn ask(native: &mut Native, rx: &Receiver<ToDevice>, definition: &QuestionDefinition) {
    native.send(
        "ask",
        FromPlugin::QuestionAsk {
            conversation: ConversationId::new("owned").unwrap(),
            question: definition.clone(),
        },
    );
    native.ack("ask");
    assert!(
        matches!(next(rx), ToDevice::Question { question } if question.definition == *definition && question.state == QuestionState::Pending)
    );
    assert!(
        matches!(next(rx), ToDevice::Message(message) if message.question.as_ref() == Some(&definition.id) && message.kind == "question")
    );
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
            }
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
            answer: answer,
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
                    question: question,
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
fn questions_no_channel_can_answer_expire_on_the_bridge() {
    let (_dir, hub, store, device, rx) = fixture();
    let owned = ConversationId::new("owned").unwrap();
    let old = definition("old");
    let recent = definition("recent");
    store.ask_question(AGENT, &owned, &old, "old-ask").unwrap();
    store
        .ask_question(AGENT, &owned, &recent, "recent-ask")
        .unwrap();
    // An agent enclos no longer serves: no channel will ever answer.
    let gone = definition("gone");
    store
        .ask_question(
            "lab/helper",
            &ConversationId::new("other-agent").unwrap(),
            &gone,
            "gone-ask",
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
        .ask_question(AGENT, &owned, &definition("later"), "later-ask")
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
    next(&rx);
    assert!(matches!(next(&rx), ToDevice::Message(m) if m.text == "Answered: Classement"));
    assert!(matches!(next(&rx), ToDevice::QuestionResult { .. }));
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
    next(&rx);
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
