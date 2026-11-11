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
        matches!(next(rx), ToDevice::Message(message) if message.question.as_ref() == Some(&definition.id) && message.kind == if definition.approval.is_some() { "runtime_approval" } else { "question" })
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
        definition.id.clone(),
        0,
        answer.clone(),
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
        definition.id.clone(),
        0,
        answer,
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
                question,
                0,
                QuestionAnswer::Skip,
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
        definition.id.clone(),
        0,
        QuestionAnswer::Choices { indices: vec![0] },
    )
    .unwrap();
    let first = native.receive();
    hub.question_answer(
        &store,
        &second,
        OWNER,
        MessageId::new("second").unwrap(),
        definition.id.clone(),
        0,
        QuestionAnswer::Skip,
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
            definition.id.clone(),
            10,
            QuestionAnswer::Skip,
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
        definition.id.clone(),
        0,
        QuestionAnswer::Skip,
    )
    .unwrap();
    let request = native.receive();
    let epoch = hub.questions.lock().unwrap().connections[AGENT].clone();
    let update = |of| {
        hub.question_update(
            &store,
            AGENT,
            "old-connection",
            &definition.id,
            QuestionState::Skipped,
            None,
            Some(of),
            &MessageId::new("stale-update").unwrap(),
        )
    };
    assert!(update(&request.id).is_err());
    assert!(rx.try_recv().is_err());
    hub.question_error(
        &store,
        "lab/helper",
        &epoch,
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
        definition.id.clone(),
        0,
        QuestionAnswer::Skip,
    )
    .unwrap();
    assert!(matches!(next(&rx), ToDevice::Error(error) if error.of == Some(original)));
    let timeout = MessageId::new("timeout").unwrap();
    hub.question_answer(
        &store,
        &device,
        OWNER,
        timeout.clone(),
        definition.id.clone(),
        0,
        QuestionAnswer::Skip,
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
        matches!(next(&rx), ToDevice::Error(error) if error.of == Some(timeout.clone()) && error.message.contains("unknown"))
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
        definition.id,
        0,
        QuestionAnswer::Skip,
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
        definition.id.clone(),
        0,
        QuestionAnswer::Skip,
    )
    .unwrap();
    let request = native.receive();
    let error = hub
        .question_answer(
            &store,
            &device,
            OWNER,
            original.clone(),
            definition.id.clone(),
            0,
            QuestionAnswer::Text {
                text: "different".into(),
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
            definition.id,
            0,
            QuestionAnswer::Skip
        )
        .unwrap_err()
        .code,
        ErrorCode::NotFound
    );
}

#[test]
fn reconnect_reconciles_only_this_agents_pending_questions_in_bounded_batches() {
    let (_dir, hub, store, _device, _rx) = fixture();
    for index in 0..130 {
        let definition = definition(&format!("q-{index}"));
        store
            .ask_question(
                AGENT,
                &ConversationId::new("owned").unwrap(),
                &definition,
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
    let first = native.receive();
    let second = native.receive();
    let FromBridge::QuestionSync { questions: first } = first.body else {
        panic!("sync")
    };
    let FromBridge::QuestionSync { questions: second } = second.body else {
        panic!("sync")
    };
    assert_eq!(first.len(), 128);
    assert_eq!(second.len(), 2);
    assert!(!first.contains(&other.id));
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
    assert_eq!(store.pending_questions(AGENT).unwrap().len(), 129);
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
            QuestionState::Answered,
            Some(QuestionAnswer::Text {
                text: "Gégé Commit".into(),
            }),
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
    for command in ["/approve", "/approve session", "/approve always", "/deny"] {
        assert!(history[0].text.contains(command));
    }
    let original = MessageId::new("allow-session").unwrap();
    hub.question_answer(
        &store,
        &device,
        OWNER,
        original.clone(),
        definition.id.clone(),
        0,
        approval(Action::Session),
    )
    .unwrap();
    let request = native.receive();
    assert_eq!(
        request.body,
        FromBridge::QuestionAnswer {
            conversation: ConversationId::new("owned").unwrap(),
            question: definition.id.clone(),
            answer: approval(Action::Session)
        }
    );
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
            Some(OWNER),
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
                question.clone(),
                0,
                approval(Action::Deny),
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
        ordinary.id.clone(),
        0,
        QuestionAnswer::Skip,
    )
    .unwrap();
    assert!(
        matches!(native.receive().body, FromBridge::QuestionAnswer { question, answer: QuestionAnswer::Skip, .. } if question == ordinary.id)
    );
    for host in [None, Some("another-person@example.com".to_owned())] {
        let (_dir, mut hub, store, device, _rx) = fixture();
        Arc::get_mut(&mut hub).unwrap().host = host;
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
                definition.id,
                0,
                approval(Action::Once)
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
                definition.id.clone(),
                0,
                answer,
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
        definition.id.clone(),
        0,
        approval(Action::Deny),
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
            definition.id,
            0,
            approval(Action::Once),
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
            ordinary.id,
            0,
            approval(Action::Once)
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
        definition.id.clone(),
        0,
        approval(Action::Once),
    )
    .unwrap();
    let first = native.receive();
    hub.question_answer(
        &store,
        &second,
        OWNER,
        MessageId::new("deny").unwrap(),
        definition.id.clone(),
        0,
        approval(Action::Deny),
    )
    .unwrap();
    let second_request = native.receive();
    let epoch = hub.questions.lock().unwrap().connections[AGENT].clone();
    assert!(
        hub.question_update(
            &store,
            "lab/helper",
            &epoch,
            &definition.id,
            QuestionState::Answered,
            Some(approval(Action::Always)),
            Some(&first.id),
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
        definition.id.clone(),
        0,
        approval(Action::Always),
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
            definition.id.clone(),
            0,
            approval(Action::Once),
        )
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::BadMessage);
    hub.question_answer(
        &store,
        &device,
        OWNER,
        MessageId::new("deny").unwrap(),
        definition.id,
        0,
        approval(Action::Deny),
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
fn only_the_hosts_person_can_type_a_runtime_approval() {
    let (_dir, hub, store, device, rx) = fixture();
    let mut native = native(&hub, vec![Capability::RuntimeApprovals]);
    let (guest, guest_rx) = phone(&hub, &store, "guest-phone", "guest@example.com");
    let (mut guest_send, _guest) = device_session(&hub, guest, "guest@example.com", guest_rx);
    for (index, text) in ["/approve always", "@file:/tmp/x\n/DENY all"]
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
        matches!(native.receive().body, FromBridge::MessageIn { text, person, .. } if text == "hello" && person.as_str() == "guest@example.com")
    );
    // The host's person's typed approval is passed on unchanged.
    let (mut host_send, _host) = device_session(&hub, device, OWNER, rx);
    host_send(
        "host-approve",
        FromDevice::MessageSend {
            conversation: ConversationId::new("owned").unwrap(),
            text: "/approve".into(),
        },
    );
    assert!(
        matches!(native.receive().body, FromBridge::MessageIn { text, .. } if text == "/approve")
    );
}

#[test]
fn an_unknown_host_passes_on_no_typed_runtime_approval() {
    let (_dir, mut hub, _store, _device, _rx) = fixture();
    assert!(!hub.refuses_typed_approval(OWNER, "/approve"));
    assert!(hub.refuses_typed_approval("guest@example.com", "/approve"));
    assert!(!hub.refuses_typed_approval("guest@example.com", "approve this plan"));
    Arc::get_mut(&mut hub).unwrap().host = None;
    assert!(hub.refuses_typed_approval(OWNER, "/deny"));
}

#[test]
fn approval_history_names_typed_commands_only_in_the_hosts_conversations() {
    let (_dir, hub, store, _device, _rx) = fixture();
    let mut native = native(&hub, vec![Capability::RuntimeApprovals]);
    for (conversation, owner, typed) in [
        ("owned", OWNER, true),
        ("foreign", "guest@example.com", false),
    ] {
        let definition = approval_definition(&format!("approval-{conversation}"), false);
        native.send(
            conversation,
            FromPlugin::QuestionAsk {
                conversation: ConversationId::new(conversation).unwrap(),
                question: definition.clone(),
            },
        );
        native.ack(conversation);
        let text = store
            .since(owner, 0)
            .unwrap()
            .into_iter()
            .find(|m| m.question.as_ref() == Some(&definition.id))
            .unwrap()
            .text;
        assert_eq!(text.contains("/approve always"), typed, "{text}");
        assert!(text.contains("npm install --ignore-scripts"));
        assert!(text.contains("every command matching: package install scripts"));
    }
}

#[test]
fn a_guest_reads_an_approval_without_receiving_its_controls() {
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
    native.ack("guest-ask");
    let ToDevice::Message(message) = next(&guest_rx) else {
        panic!("the guest gets the readable history, not the approval metadata")
    };
    assert_eq!(message.kind, "runtime_approval");
    assert!(message.text.contains("Only the host's person"));
    assert!(guest_rx.try_recv().is_err());
    assert!(
        rx.try_recv().is_err(),
        "the host does not own this conversation"
    );
    assert!(!hub.shows_question("guest@example.com", &definition));
    assert!(hub.shows_question(OWNER, &definition));
    assert!(hub.shows_question("guest@example.com", &super::tests::definition("ordinary")));
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
