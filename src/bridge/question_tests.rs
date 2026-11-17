use super::super::super::store::{MAX_PENDING_PER_AGENT, MAX_PENDING_PER_CONVERSATION};
use super::*;
use crate::bridge::server::open_items::ReminderRef;
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
    let listener = UnixListener::bind(&hub.agents()[0].socket).unwrap();
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
        // Without it, a plugin sends no usage (docs/protocol.md, Usage).
        assert!(bridge_caps.contains(&Capability::Usage));
        assert!(bridge_caps.contains(&Capability::AgentUsage));
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

#[test]
fn an_expired_information_question_stays_open_without_reentering_native_answer_delivery() {
    let (_dir, hub, store, phone, rx) = fixture();
    let q = definition("late-reply");
    store
        .ask_question(
            AGENT,
            &ConversationId::new("owned").unwrap(),
            &q,
            "ask-late",
            Some(OWNER),
        )
        .unwrap();
    store
        .settle_question(
            AGENT,
            &q.id,
            Settlement::reported(QuestionState::Expired, None),
            "expire-late",
        )
        .unwrap();
    let foreign = definition("foreign-late");
    store
        .ask_question(
            AGENT,
            &ConversationId::new("foreign").unwrap(),
            &foreign,
            "ask-foreign",
            Some(OWNER),
        )
        .unwrap();
    let frames = hub.open_item_frames(&store, OWNER).unwrap();
    let ToDevice::OpenItems {
        items,
        reset,
        complete,
        ..
    } = &frames[0]
    else {
        panic!("snapshot")
    };
    assert!(*reset && *complete);
    assert_eq!(items.len(), 1);
    assert!(items[0].expired);
    assert_eq!(items[0].id, "late-reply");
    assert_eq!(items[0].summary, q.text);
    assert_eq!(store.pending_questions_for(OWNER).unwrap().len(), 0);
    assert!(
        hub.question_answer(
            &store,
            &phone,
            OWNER,
            MessageId::new("late-answer").unwrap(),
            AnswerRequest {
                question: q.id.clone(),
                revision: 1,
                answer: QuestionAnswer::Choices { indices: vec![0] }
            }
        )
        .is_err()
    );
    assert!(store.pending("lab", "coder").unwrap().is_empty());
    assert_eq!(
        store.question(&q.id).unwrap().unwrap().info.state,
        QuestionState::Expired
    );
    assert!(
        rx.try_iter()
            .all(|f| !matches!(f, ToDevice::QuestionResult { .. }))
    );
}

#[test]
fn a_late_answer_never_revives_an_expired_runtime_approval() {
    let (_dir, hub, store, phone, _rx) = fixture();
    let mut q = definition("expired-command");
    q.choices.clear();
    q.multiple = false;
    q.approval = Some(enclos_protocol::question::RuntimeApprovalDefinition {
        command: "touch approved".into(),
        reason: "Test gate".into(),
        actions: vec![
            enclos_protocol::question::RuntimeApprovalAction::Once,
            enclos_protocol::question::RuntimeApprovalAction::Deny,
        ],
        smart_denied: false,
        patterns: vec![],
    });
    store
        .ask_question(
            AGENT,
            &ConversationId::new("owned").unwrap(),
            &q,
            "ask-command",
            Some(OWNER),
        )
        .unwrap();
    store
        .settle_question(
            AGENT,
            &q.id,
            Settlement::reported(QuestionState::Expired, None),
            "expire-command",
        )
        .unwrap();
    assert!(
        hub.open_item_frames(&store, OWNER)
            .unwrap()
            .iter()
            .all(|f| matches!(f, ToDevice::OpenItems { items, .. } if items.is_empty()))
    );
    assert!(
        hub.question_answer(
            &store,
            &phone,
            OWNER,
            MessageId::new("expired-allow").unwrap(),
            AnswerRequest {
                question: q.id.clone(),
                revision: 1,
                answer: QuestionAnswer::Approval {
                    action: enclos_protocol::question::RuntimeApprovalAction::Once
                },
            }
        )
        .is_err()
    );
    assert!(store.pending("lab", "coder").unwrap().is_empty());
    assert_eq!(
        store.question(&q.id).unwrap().unwrap().info.state,
        QuestionState::Expired
    );
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

fn usage(conversation: &str, input: u64) -> FromPlugin {
    FromPlugin::Usage(enclos_protocol::usage::CallUsage {
        conversation: ConversationId::new(conversation).unwrap(),
        model: Some("gpt".into()),
        background: false,
        calls: 1,
        tokens: enclos_protocol::usage::UsageTokens {
            input: Some(input),
            ..Default::default()
        },
    })
}

#[test]
fn usage_from_a_plugin_reaches_its_conversations_owner_alone_and_counts_for_a_group_member() {
    let (_dir, hub, store, _device, rx) = fixture();
    let (_guest, guest) = phone(&hub, &store, "guest-phone", "guest@example.com");
    let mut native = native(&hub, vec![Capability::Usage]);
    native.send("u1", usage("owned", 10));
    let ToDevice::Usage(update) = next(&rx) else {
        panic!("usage")
    };
    assert_eq!(update.call.conversation.as_str(), "owned");
    assert_eq!(update.total.tokens.input, Some(10));
    // The agent's conversation of another person goes to that person.
    native.send("u2", usage("foreign", 5));
    assert!(
        matches!(next(&guest), ToDevice::Usage(u) if u.call.conversation.as_str() == "foreign")
    );
    // Another agent's conversation takes nothing from this one's plugin,
    // and a group counts its member's calls under the member: what reaches
    // the owner next is the group's.
    native.send("u3", usage("other-agent", 99));
    native.send("u4", usage("group", 7));
    assert!(
        matches!(next(&rx), ToDevice::Usage(u) if u.call.conversation.as_str() == "group" && u.total.tokens.input == Some(7))
    );
    assert_eq!(store.usage("other-agent").unwrap(), None);
    let window = store.usage_since(OWNER, 0, false).unwrap();
    assert_eq!(window.len(), 1, "{window:?}");
    assert_eq!(window[0].0, "lab/coder");
    assert_eq!(window[0].1.tokens.input, Some(17));
    assert!(rx.try_recv().is_err() && guest.try_recv().is_err());
}

#[test]
fn an_agents_calls_outside_the_app_count_under_it_for_the_hosts_person() {
    let (_dir, hub, store, _device, rx) = fixture();
    let mut native = native(&hub, vec![Capability::Usage, Capability::AgentUsage]);
    // Its hello said it reports them: the bridge keeps that.
    assert_eq!(store.outside_reporters().unwrap(), [AGENT]);
    native.send(
        "a1",
        FromPlugin::AgentUsage(enclos_protocol::usage::AgentCallUsage {
            source: Some("cron".into()),
            model: None,
            background: false,
            calls: 3,
            tokens: enclos_protocol::usage::UsageTokens {
                input: Some(1_000),
                ..Default::default()
            },
        }),
    );
    // Read in order: once the next report reached the owner, this one is in.
    native.send("u1", usage("owned", 10));
    assert!(matches!(next(&rx), ToDevice::Usage(_)));
    let host = store.usage_since(OWNER, 0, true).unwrap();
    assert_eq!(host.len(), 1, "{host:?}");
    assert_eq!(host[0].0, AGENT);
    assert_eq!(host[0].1.calls, 4);
    assert_eq!(host[0].1.tokens.input, Some(1_010));
    // Without them, the conversations' alone.
    let own = store.usage_since(OWNER, 0, false).unwrap();
    assert_eq!(own[0].1.tokens.input, Some(10));
}

/// A push service that records the tokens it is asked to send to.
struct Recorder(std::sync::mpsc::Sender<(String, i64, String)>);

impl super::super::super::push::PushService for Recorder {
    fn send(
        &mut self,
        token: &str,
        payload: &super::super::super::push::Payload,
    ) -> Option<super::super::super::push::Outcome> {
        use base64::Engine as _;
        let sealed = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&payload.preview)
            .unwrap();
        let preview = enclos_protocol::preview::open(
            &super::super::super::push::test_push_key(),
            &enclos_protocol::preview::PushFields {
                host: &payload.host,
                seq: payload.seq,
            },
            &sealed,
        )
        .unwrap();
        let _ = self.0.send((
            token.to_owned(),
            payload.seq,
            String::from_utf8(preview).unwrap(),
        ));
        Some(super::super::super::push::Outcome::Sent)
    }
}

#[test]
fn a_question_asked_while_its_owner_is_away_reaches_them_as_a_push() {
    let dir = tempfile::tempdir().unwrap();
    let (sent, pushed) = channel();
    let pusher = super::super::super::push::Pusher::start(
        Box::new(Recorder(sent)),
        "mac".into(),
        dir.path().join("app.db"),
    );
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
        .with_approval_key(approval_key())
        .with_push(pusher, "mac".into()),
    );
    let store = hub.store().unwrap();
    store.conversation("owned", "lab", "coder", OWNER).unwrap();
    // Paired, with a push token, and not connected.
    store
        .add_device(&Device {
            id: "phone".into(),
            name: "phone".into(),
            person: OWNER.into(),
            noise_key: vec![1; 32],
            device_key: vec![],
            push_key: super::super::super::push::test_push_key(),
            push_token: Some("token-phone".into()),
            paired: now(),
            seen: None,
            node: None,
        })
        .unwrap();
    let mut native = native(&hub, vec![Capability::Questions, Capability::HeldTasks]);
    native.send(
        "ask",
        FromPlugin::QuestionAsk {
            conversation: ConversationId::new("owned").unwrap(),
            question: definition("q-away"),
        },
    );
    native.ack("ask");
    let (token, seq, preview) = pushed.recv_timeout(Duration::from_secs(5)).unwrap();
    assert!(preview.contains("Needs you:"));
    assert_eq!(token, "token-phone");
    assert_eq!(seq, store.newest_seq().unwrap());

    // Answered: its status line is not pushed, nor is the same ask sent
    // again by the channel once it is closed.
    native.send(
        "answered",
        FromPlugin::QuestionUpdate {
            question: definition("q-away").id,
            state: QuestionState::Answered,
            answer: Some(QuestionAnswer::Choices { indices: vec![0] }),
            of: None,
        },
    );
    native.ack("answered");
    native.send(
        "ask-again",
        FromPlugin::QuestionAsk {
            conversation: ConversationId::new("owned").unwrap(),
            question: definition("q-away"),
        },
    );
    native.ack("ask-again");
    // Waited for apart: the worker keeps the newest of pushes that wait
    // together, which would hide one here.
    assert!(pushed.recv_timeout(Duration::from_millis(500)).is_err());
    // The next push is the next question's, and nothing came before it.
    native.send(
        "next",
        FromPlugin::QuestionAsk {
            conversation: ConversationId::new("owned").unwrap(),
            question: definition("q-next"),
        },
    );
    native.ack("next");
    let (_, next, _) = pushed.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(next, store.newest_seq().unwrap());
    assert!(next > seq);
    assert!(pushed.try_recv().is_err());
    let held = serde_json::from_value(serde_json::json!({"task":"push-held","title":"Review delivery","reason":"Decision needed","since":1,"revision":"r1","resume":"Resume"})).unwrap();
    native.send("held-push", FromPlugin::HeldTasks { tasks: vec![held] });
    native.ack("held-push");
    let (_, held_seq, preview) = pushed.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(held_seq, store.newest_seq().unwrap());
    assert!(preview.contains("Needs you: Review delivery"));
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
    std::fs::remove_file(&hub.agents()[0].socket).unwrap();
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
            FromDevice::Sync {
                since,
                open_items: false,
            },
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
    // Another host's person (none recorded, while devices are paired, is
    // not a state the store keeps: it names the first device's person)
    {
        let host = Some("another-person@example.com".to_owned());
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
    std::fs::remove_file(&hub.agents()[0].socket).unwrap();
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

#[test]
fn an_answer_the_bridge_cannot_check_answers_internal_not_not_found() {
    let (_dir, hub, store, device, _rx) = fixture();
    rusqlite::Connection::open(&hub.store_path)
        .unwrap()
        .execute_batch("DROP TABLE devices; CREATE TABLE devices (broken INTEGER);")
        .unwrap();
    let error = hub
        .question_answer(
            &store,
            &device,
            OWNER,
            MessageId::new("answer").unwrap(),
            AnswerRequest {
                question: QuestionId::new("q-1").unwrap(),
                revision: 0,
                answer: QuestionAnswer::Skip,
            },
        )
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::Internal);
}

#[test]
fn closing_an_expired_reminder_preserves_native_state_and_survives_reopen() {
    let (_dir, hub, store, device, _rx) = fixture();
    let q = definition("close-q");
    store
        .ask_question(
            AGENT,
            &ConversationId::new("owned").unwrap(),
            &q,
            "ask-close",
            Some(OWNER),
        )
        .unwrap();
    assert!(
        store
            .close_expired_question(&q.id, 0, OWNER, "early-close")
            .is_err()
    );
    store
        .settle_question(
            AGENT,
            &q.id,
            Settlement::reported(QuestionState::Expired, None),
            "expire-close",
        )
        .unwrap();
    let before = store.question(&q.id).unwrap().unwrap();
    assert!(
        store
            .close_expired_question(&q.id, 0, OWNER, "stale-close")
            .is_err()
    );
    assert!(
        store
            .close_expired_question(&q.id, 1, "guest@example.com", "foreign-close")
            .is_err()
    );
    assert!(matches!(
        hub.question_close(
            &store,
            &device,
            OWNER,
            MessageId::new("close").unwrap(),
            q.id.clone(),
            1
        )
        .unwrap(),
        ToDevice::QuestionClosed { .. }
    ));
    // A lost receipt can be retried; neither native state nor history changes.
    assert!(
        store
            .close_expired_question(&q.id, 1, OWNER, "close-again")
            .is_ok()
    );
    assert_eq!(
        before,
        hub.store().unwrap().question(&q.id).unwrap().unwrap()
    );
    assert!(
        hub.store()
            .unwrap()
            .open_questions_for(OWNER)
            .unwrap()
            .is_empty()
    );
    assert!(store.pending("lab", "coder").unwrap().is_empty());
}

#[test]
fn open_item_snapshots_are_person_scoped_bounded_and_fail_visibly() {
    let (_dir, hub, store, _device, _rx) = fixture();
    for i in 0..49 {
        let id = format!("many-{i}");
        let conversation = format!("conversation-{i}");
        store
            .conversation(&conversation, "lab", "coder", OWNER)
            .unwrap();
        let mut q = definition(&id);
        q.text = "\"".repeat(300);
        store
            .ask_question(
                AGENT,
                &ConversationId::new(conversation).unwrap(),
                &q,
                &format!("ask-{i}"),
                Some(OWNER),
            )
            .unwrap();
        store
            .settle_question(
                AGENT,
                &q.id,
                Settlement::reported(QuestionState::Expired, None),
                &format!("expire-{i}"),
            )
            .unwrap();
    }
    let frames = hub.open_item_frames(&store, OWNER).unwrap();
    assert_eq!(frames.len(), 3);
    let mut total = 0;
    for (i, frame) in frames.iter().enumerate() {
        let ToDevice::OpenItems {
            revision,
            reset,
            complete,
            unavailable,
            items,
        } = frame
        else {
            panic!("snapshot")
        };
        assert_eq!(*revision, 1);
        assert_eq!(*reset, i == 0);
        assert_eq!(*complete, i == 2);
        assert!(!unavailable);
        assert!(items.len() <= 24);
        total += items.len();
        assert!(
            encode_line(&Envelope::new(
                MessageId::new("00000000-0000-0000-0000-000000000000").unwrap(),
                frame.clone()
            ))
            .len()
                <= enclos_protocol::device::MAX_DEVICE_MESSAGE
        );
    }
    assert_eq!(total, 49);
    assert!(
        matches!(&hub.open_item_frames(&store, "guest@example.com").unwrap()[0], ToDevice::OpenItems { revision: 1, items, .. } if items.is_empty())
    );
    store.db.execute("DROP TABLE questions", []).unwrap();
    assert!(
        matches!(&hub.open_item_frames(&store, OWNER).unwrap()[0], ToDevice::OpenItems { revision: 2, unavailable: true, items, .. } if items.is_empty())
    );
}

#[test]
fn the_index_combines_canonical_requests_without_sharing_host_person_authority() {
    use enclos_protocol::open_items::OpenItemKind;
    let (_dir, hub, store, _device, _rx) = fixture();
    set_host(&hub, Some(OWNER));
    for (id, definition) in [
        ("ordinary", definition("ordinary")),
        ("command", approval_definition("command", false)),
    ] {
        store
            .ask_question(
                AGENT,
                &ConversationId::new("owned").unwrap(),
                &definition,
                &format!("ask-{id}"),
                Some(OWNER),
            )
            .unwrap();
    }
    let task = serde_json::from_value(serde_json::json!({"task":"held", "title":"Review", "reason":"Choose the next step", "since":1, "revision":"hold-1", "resume":"Review with Director", "resumable":false})).unwrap();
    store.report_held_tasks(AGENT, "owned", &[task]).unwrap();
    let policy = serde_json::from_value(serde_json::json!({"request":"policy", "sandbox":"lab", "agent":AGENT, "access":{"kind":"network", "target":"example.com:443"}, "scope":"resolved.example.com:443", "action":"Allow the download?", "time":2, "state":"pending", "change":"", "restart":false, "revision":"r1", "available":false})).unwrap();
    store.create_approval(&policy).unwrap();
    let frames = hub.open_item_frames(&store, OWNER).unwrap();
    assert!(frames.iter().any(|frame| matches!(frame, ToDevice::OpenItems { items, .. } if items.iter().any(|item| item.kind == OpenItemKind::PolicyRequest && item.summary == "Connect to resolved.example.com:443"))));
    let kinds = |person| {
        hub.open_item_frames(&store, person)
            .unwrap()
            .into_iter()
            .flat_map(|frame| match frame {
                ToDevice::OpenItems { items, .. } => items,
                _ => panic!("snapshot"),
            })
            .map(|item| item.kind)
            .collect::<Vec<_>>()
    };
    let all = kinds(OWNER);
    assert_eq!(all.len(), 4);
    for kind in [
        OpenItemKind::Question,
        OpenItemKind::RuntimeApproval,
        OpenItemKind::HeldTask,
        OpenItemKind::PolicyRequest,
    ] {
        assert!(all.contains(&kind));
    }
    assert!(kinds("guest@example.com").is_empty());
    // Changing the host's person removes host-wide controls, while owned ordinary questions remain.
    set_host(&hub, Some("guest@example.com"));
    assert_eq!(kinds(OWNER), [OpenItemKind::Question]);
}

#[test]
fn live_open_item_snapshots_require_opt_in_and_current_person_pairing() {
    let (_dir, hub, store, device, rx) = fixture();
    let (_guest, guest_rx) = phone(&hub, &store, "guest", "guest@example.com");
    let q = definition("snapshot-live");
    store
        .ask_question(
            AGENT,
            &ConversationId::new("owned").unwrap(),
            &q,
            "ask-live",
            Some(OWNER),
        )
        .unwrap();
    hub.publish_open_items(&store, OWNER);
    assert!(rx.try_recv().is_err());
    hub.open_item_devices
        .lock()
        .unwrap()
        .extend([device.id.clone(), "guest".to_owned()]);
    hub.publish_open_items(&store, OWNER);
    assert!(
        matches!(next(&rx), ToDevice::OpenItems { complete: true, items, .. } if items.len() == 1)
    );
    assert!(guest_rx.try_recv().is_err());
    store
        .settle_question(
            AGENT,
            &q.id,
            Settlement::reported(
                QuestionState::Answered,
                Some(QuestionAnswer::Choices { indices: vec![0] }),
            ),
            "answer-live",
        )
        .unwrap();
    hub.publish_open_items(&store, OWNER);
    assert!(
        matches!(next(&rx), ToDevice::OpenItems { complete: true, items, .. } if items.is_empty())
    );
    store.remove_device(&device.id).unwrap();
    hub.publish_open_items(&store, OWNER);
    assert!(rx.try_recv().is_err());
}

#[test]
fn outdated_expired_approvals_do_not_hide_current_or_expired_information_questions() {
    let (_dir, hub, store, _device, _rx) = fixture();
    let ordinary = definition("still-needs-you");
    let approval = approval_definition("old-expired-approval", false);
    for (id, q) in [("ordinary-index", &ordinary), ("approval-index", &approval)] {
        store
            .ask_question(
                AGENT,
                &ConversationId::new("owned").unwrap(),
                q,
                id,
                Some(OWNER),
            )
            .unwrap();
    }
    store
        .settle_question(
            AGENT,
            &approval.id,
            Settlement::reported(QuestionState::Expired, None),
            "expire-approval-index",
        )
        .unwrap();
    let mut historical = serde_json::to_value(&approval).unwrap();
    historical["approval"]["actions"] = serde_json::json!(["once", "session", "always", "deny"]);
    historical["approval"]["patterns"] = serde_json::json!([]);
    store
        .db
        .execute(
            "UPDATE questions SET definition=?2 WHERE id=?1",
            rusqlite::params![approval.id.as_str(), historical.to_string()],
        )
        .unwrap();
    for expired in [false, true] {
        if expired {
            store
                .settle_question(
                    AGENT,
                    &ordinary.id,
                    Settlement::reported(QuestionState::Expired, None),
                    "expire-ordinary-index",
                )
                .unwrap();
        }
        let frames = hub.open_item_frames(&store, OWNER).unwrap();
        assert!(
            matches!(&frames[0],ToDevice::OpenItems { unavailable:false,items,.. } if items.len()==1 && items[0].id==ordinary.id.as_str() && items[0].expired==expired)
        );
    }
}

#[test]
fn dismissing_a_reminder_persists_without_answering_or_resuming_the_request() {
    use enclos_protocol::open_items::OpenItemKind;
    let (_dir, hub, store, phone, _rx) = fixture();
    set_host(&hub, Some(OWNER));
    let q = definition("dismiss-only");
    store
        .ask_question(
            AGENT,
            &ConversationId::new("owned").unwrap(),
            &q,
            "ask-dismiss",
            Some(OWNER),
        )
        .unwrap();
    let before = store.question(&q.id).unwrap().unwrap();
    let item = hub
        .open_item_frames(&store, OWNER)
        .unwrap()
        .into_iter()
        .find_map(|f| {
            if let ToDevice::OpenItems { items, .. } = f {
                items.into_iter().find(|i| i.id == q.id.as_str())
            } else {
                None
            }
        })
        .unwrap();
    let mut swapped = phone.clone();
    swapped.noise_key = vec![55];
    assert_eq!(
        hub.dismiss_open_item(
            &store,
            &swapped,
            OWNER,
            MessageId::new("wrong-keys").unwrap(),
            ReminderRef {
                kind: item.kind,
                id: &item.id,
                agent: item.agent.as_deref(),
                version: &item.version
            }
        )
        .unwrap_err()
        .code,
        ErrorCode::NotFound
    );
    assert_eq!(
        hub.dismiss_open_item(
            &store,
            &phone,
            OWNER,
            MessageId::new("stale-dismiss").unwrap(),
            ReminderRef {
                kind: item.kind,
                id: &item.id,
                agent: item.agent.as_deref(),
                version: "stale"
            }
        )
        .unwrap_err()
        .code,
        ErrorCode::Conflict
    );
    for (kind, agent) in [
        (OpenItemKind::HeldTask, item.agent.as_deref()),
        (item.kind, Some("lab/helper")),
    ] {
        assert_eq!(
            hub.dismiss_open_item(
                &store,
                &phone,
                OWNER,
                MessageId::new("wrong-source").unwrap(),
                ReminderRef {
                    kind,
                    id: &item.id,
                    agent,
                    version: &item.version
                }
            )
            .unwrap_err()
            .code,
            ErrorCode::NotFound
        );
    }
    assert!(matches!(
        hub.dismiss_open_item(
            &store,
            &phone,
            OWNER,
            MessageId::new("dismiss").unwrap(),
            ReminderRef {
                kind: item.kind,
                id: &item.id,
                agent: item.agent.as_deref(),
                version: &item.version
            }
        )
        .unwrap(),
        ToDevice::OpenItemDismissed {
            kind: OpenItemKind::Question,
            ..
        }
    ));
    assert_eq!(store.question(&q.id).unwrap().unwrap(), before);
    assert!(store.pending("lab", "coder").unwrap().is_empty());
    let restarted = Hub::new(
        Transport::Tailscale,
        Arc::new(|_: &str| Err("no transport".into())),
        hub.store_path.clone(),
        hub.layout.clone(),
        vec![],
        hub.agents().to_vec(),
        Some(OWNER.into()),
        SILENCE,
    );
    let reopened = restarted.store().unwrap();
    assert!(
        restarted
            .open_item_frames(&reopened, OWNER)
            .unwrap()
            .into_iter()
            .all(|f| matches!(f,ToDevice::OpenItems {items,..} if items.is_empty()))
    );
    store
        .settle_question(
            AGENT,
            &q.id,
            Settlement::reported(QuestionState::Expired, None),
            "expire-dismissed",
        )
        .unwrap();
    assert!(
        hub.open_item_frames(&store, OWNER)
            .unwrap()
            .into_iter()
            .all(|f| matches!(f,ToDevice::OpenItems {items,..} if items.is_empty()))
    );
}

#[test]
fn held_reminders_can_be_dismissed_without_resume_and_return_only_when_updated() {
    let (_dir, hub, store, device, _rx) = fixture();
    set_host(&hub, Some(OWNER));
    let task: enclos_protocol::held_task::HeldTask=serde_json::from_value(serde_json::json!({"task":"held-dismiss","title":"Review","reason":"Needs a decision","since":1,"revision":"hold-1","resume":"Review task","resumable":false})).unwrap();
    store
        .report_held_tasks(AGENT, "owned", std::slice::from_ref(&task))
        .unwrap();
    let frames = hub.open_item_frames(&store, OWNER).unwrap();
    let item = frames
        .into_iter()
        .find_map(|f| {
            if let ToDevice::OpenItems { items, .. } = f {
                items.into_iter().next()
            } else {
                None
            }
        })
        .unwrap();
    let before = store.held_task(AGENT, "held-dismiss").unwrap().unwrap();
    let (guest, _) = phone(&hub, &store, "dismiss-foreign", "guest@example.com");
    assert_eq!(
        hub.dismiss_open_item(
            &store,
            &guest,
            "guest@example.com",
            MessageId::new("foreign-dismiss").unwrap(),
            ReminderRef {
                kind: item.kind,
                id: &item.id,
                agent: item.agent.as_deref(),
                version: &item.version
            }
        )
        .unwrap_err()
        .code,
        ErrorCode::NotFound
    );
    hub.dismiss_open_item(
        &store,
        &device,
        OWNER,
        MessageId::new("held-dismiss").unwrap(),
        ReminderRef {
            kind: item.kind,
            id: &item.id,
            agent: item.agent.as_deref(),
            version: &item.version,
        },
    )
    .unwrap();
    assert_eq!(
        store.held_task(AGENT, "held-dismiss").unwrap().unwrap(),
        before
    );
    assert!(
        hub.open_item_frames(&store, OWNER)
            .unwrap()
            .into_iter()
            .all(|f| matches!(f,ToDevice::OpenItems {items,..} if items.is_empty()))
    );
    let mut changed = task;
    changed.reason = "A new decision is needed".into();
    changed.revision = enclos_protocol::HeldTaskRevision::new("hold-2").unwrap();
    store.report_held_tasks(AGENT, "owned", &[changed]).unwrap();
    assert!(hub.open_item_frames(&store,OWNER).unwrap().into_iter().any(|f|matches!(f,ToDevice::OpenItems {items,..} if items.len()==1 && items[0].version != item.version)));
}

#[test]
fn dismissing_runtime_and_policy_reminders_does_not_decide_either_request() {
    let (_dir, hub, store, phone, _rx) = fixture();
    set_host(&hub, Some(OWNER));
    let q = approval_definition("dismiss-runtime", false);
    store
        .ask_question(
            AGENT,
            &ConversationId::new("owned").unwrap(),
            &q,
            "ask-runtime",
            Some(OWNER),
        )
        .unwrap();
    let policy = serde_json::from_value(serde_json::json!({"request":"dismiss-policy", "sandbox":"lab", "agent":AGENT, "access":{"kind":"network", "target":"example.com:443"}, "scope":"example.com:443", "action":"Connect?", "time":2, "state":"pending", "change":"", "restart":false, "revision":"r1", "available":false})).unwrap();
    store.create_approval(&policy).unwrap();
    let before_q = store.question(&q.id).unwrap().unwrap();
    let before_p = store.approvals().unwrap();
    for frame in hub.open_item_frames(&store, OWNER).unwrap() {
        if let ToDevice::OpenItems { items, .. } = frame {
            for item in items {
                for retry in 0..2 {
                    hub.dismiss_open_item(
                        &store,
                        &phone,
                        OWNER,
                        MessageId::new(format!("dismiss-{}-{retry}", item.id)).unwrap(),
                        ReminderRef {
                            kind: item.kind,
                            id: &item.id,
                            agent: item.agent.as_deref(),
                            version: &item.version,
                        },
                    )
                    .unwrap();
                }
            }
        }
    }
    assert_eq!(store.question(&q.id).unwrap().unwrap(), before_q);
    assert_eq!(
        serde_json::to_value(store.approvals().unwrap()).unwrap(),
        serde_json::to_value(before_p).unwrap()
    );
    assert!(store.pending("lab", "coder").unwrap().is_empty());
    assert!(
        hub.open_item_frames(&store, OWNER)
            .unwrap()
            .into_iter()
            .all(|f| matches!(f,ToDevice::OpenItems{items,..} if items.is_empty()))
    );
}

#[test]
fn policy_generations_resurface_and_source_deletion_reclaims_reminders() {
    use enclos_protocol::open_items::OpenItemKind;
    let (_dir, hub, store, phone, _rx) = fixture();
    set_host(&hub, Some(OWNER));
    let q = definition("cleanup-q");
    store
        .ask_question(
            AGENT,
            &ConversationId::new("owned").unwrap(),
            &q,
            "ask-cleanup",
            Some(OWNER),
        )
        .unwrap();
    let task: enclos_protocol::held_task::HeldTask = serde_json::from_value(serde_json::json!({"task":"cleanup-t","title":"Review","reason":"Decision","since":1,"revision":"r1","resume":"Resume"})).unwrap();
    store.report_held_tasks(AGENT, "owned", &[task]).unwrap();
    let policy = serde_json::from_value(serde_json::json!({"request":"cleanup-p", "sandbox":"lab", "agent":AGENT, "access":{"kind":"network", "target":"example.com:443"}, "scope":"example.com:443", "action":"Connect?", "time":2, "state":"pending", "change":"", "restart":false, "revision":"r1", "available":false})).unwrap();
    store.create_approval(&policy).unwrap();
    for frame in hub.open_item_frames(&store, OWNER).unwrap() {
        if let ToDevice::OpenItems { items, .. } = frame {
            for item in items {
                hub.dismiss_open_item(
                    &store,
                    &phone,
                    OWNER,
                    MessageId::new(format!("cleanup-{}", item.id)).unwrap(),
                    ReminderRef {
                        kind: item.kind,
                        id: &item.id,
                        agent: item.agent.as_deref(),
                        version: &item.version,
                    },
                )
                .unwrap();
            }
        }
    }
    let db = rusqlite::Connection::open(&hub.store_path).unwrap();
    db.execute("UPDATE approvals SET state='failed', body=json_set(body,'$.state','failed','$.revision','r2') WHERE id='cleanup-p'",[]).unwrap();
    assert!(hub.open_item_frames(&store,OWNER).unwrap().into_iter().any(|f| matches!(f,ToDevice::OpenItems{items,..} if items.len()==1 && items[0].kind==OpenItemKind::PolicyRequest && items[0].version.contains("r2"))));
    db.execute("DELETE FROM questions WHERE id='cleanup-q'", [])
        .unwrap();
    db.execute("DELETE FROM held_tasks WHERE task='cleanup-t'", [])
        .unwrap();
    db.execute("DELETE FROM approvals WHERE id='cleanup-p'", [])
        .unwrap();
    assert_eq!(
        db.query_row("SELECT COUNT(*) FROM open_item_dismissals", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        0
    );
}

#[test]
fn review_unreadable_expired_questions_and_cards_do_not_hide_other_requests() {
    let (_dir, hub, store, _device, _rx) = fixture();
    set_host(&hub, Some(OWNER));
    for id in ["review-good", "review-corrupt"] {
        let q = definition(id);
        store
            .ask_question(
                AGENT,
                &ConversationId::new("owned").unwrap(),
                &q,
                &format!("ask-{id}"),
                Some(OWNER),
            )
            .unwrap();
    }
    store
        .db
        .execute(
            "UPDATE questions SET state='expired',definition='not json' WHERE id='review-corrupt'",
            [],
        )
        .unwrap();
    let task = serde_json::from_value(serde_json::json!({"task":"review-corrupt-card","title":"Review","reason":"Decision","since":1,"revision":"v1","resume":"Review"})).unwrap();
    store.report_held_tasks(AGENT, "owned", &[task]).unwrap();
    store
        .db
        .execute(
            "UPDATE held_tasks SET body='not json' WHERE task='review-corrupt-card'",
            [],
        )
        .unwrap();
    let frames = hub.open_item_frames(&store, OWNER).unwrap();
    assert!(
        matches!(&frames[0],ToDevice::OpenItems{unavailable:false,items,..} if items.len()==1 && items[0].id=="review-good")
    );
    store.db.execute("DROP TABLE questions", []).unwrap();
    assert!(matches!(
        &hub.open_item_frames(&store, OWNER).unwrap()[0],
        ToDevice::OpenItems {
            unavailable: true,
            ..
        }
    ));
}

#[test]
fn review_expired_discovery_has_a_recent_count_bound() {
    let (_dir, hub, store, _device, _rx) = fixture();
    for n in 0..260 {
        let q = definition(&format!("review-expired-{n}"));
        store
            .ask_question(
                AGENT,
                &ConversationId::new("owned").unwrap(),
                &q,
                &format!("ask-review-{n}"),
                Some(OWNER),
            )
            .unwrap();
        store
            .settle_question(
                AGENT,
                &q.id,
                Settlement::reported(QuestionState::Expired, None),
                &format!("expire-review-{n}"),
            )
            .unwrap();
    }
    let q = definition("review-ancient");
    store
        .ask_question(
            AGENT,
            &ConversationId::new("owned").unwrap(),
            &q,
            "ask-review-ancient",
            Some(OWNER),
        )
        .unwrap();
    store
        .settle_question(
            AGENT,
            &q.id,
            Settlement::reported(QuestionState::Expired, None),
            "expire-review-ancient",
        )
        .unwrap();
    store.db.execute("UPDATE messages SET at=1 WHERE id=(SELECT ask_message FROM questions WHERE id='review-ancient')",[]).unwrap();
    let rows = store.open_questions_for(OWNER).unwrap();
    assert_eq!(rows.len(), 256);
    assert!(
        rows.iter()
            .all(|q| q.info.definition.id.as_str() != "review-ancient")
    );
    assert_eq!(
        hub.open_item_frames(&store, OWNER)
            .unwrap()
            .into_iter()
            .map(|f| match f {
                ToDevice::OpenItems { items, .. } => items.len(),
                _ => 0,
            })
            .sum::<usize>(),
        256
    );
}

#[test]
fn encrypted_session_subscribes_before_synced_and_delivers_dismissal_receipts() {
    use enclos_protocol::device::decode_to_device;
    use enclos_protocol::noise::{Initiator, Responder, Session, generate_keypair};
    fn send(
        socket: &mut tungstenite::WebSocket<TcpStream>,
        session: &mut Session,
        id: &str,
        body: FromDevice,
    ) {
        let bytes = encode_line(&Envelope::new(MessageId::new(id).unwrap(), body));
        socket
            .send(Message::Binary(session.encrypt(&bytes).unwrap().into()))
            .unwrap();
    }
    fn read(socket: &mut tungstenite::WebSocket<TcpStream>, session: &mut Session) -> ToDevice {
        let Message::Binary(bytes) = socket.read().unwrap() else {
            panic!("encrypted message")
        };
        decode_to_device(&session.decrypt(&bytes).unwrap())
            .unwrap()
            .body
    }
    let (_dir, hub, store, device, rx) = fixture();
    let phone = device.clone();
    let expired = definition("wire-expired");
    store
        .ask_question(
            AGENT,
            &ConversationId::new("owned").unwrap(),
            &expired,
            "wire-ask",
            Some(OWNER),
        )
        .unwrap();
    store
        .settle_question(
            AGENT,
            &expired.id,
            Settlement::reported(QuestionState::Expired, None),
            "wire-expire",
        )
        .unwrap();
    let pending = definition("wire-pending");
    store
        .ask_question(
            AGENT,
            &ConversationId::new("owned").unwrap(),
            &pending,
            "wire-pending-ask",
            Some(OWNER),
        )
        .unwrap();
    let since = store.newest_seq().unwrap();
    let bridge_key = generate_keypair().unwrap();
    let device_key = generate_keypair().unwrap();
    let mut initiator = Initiator::new(&device_key.private, &bridge_key.public).unwrap();
    let mut responder = Responder::new(&bridge_key.private).unwrap();
    responder.read_hello(&initiator.hello().unwrap()).unwrap();
    let (answer, bridge_session) = responder.answer().unwrap();
    let mut session = initiator.finish(&answer).unwrap();
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let address = listener.local_addr().unwrap();
    let server_hub = Arc::clone(&hub);
    let worker = std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let mut link = Link {
            socket: tungstenite::accept(stream).unwrap(),
            session: bridge_session,
            heard: std::time::Instant::now(),
        };
        run_session(
            &server_hub,
            &server_hub.store().unwrap(),
            &mut link,
            &device,
            OWNER,
            &rx,
        )
    });
    let stream = TcpStream::connect(address).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let (mut socket, _) = tungstenite::client(format!("ws://{address}"), stream).unwrap();
    send(
        &mut socket,
        &mut session,
        "legacy-sync",
        FromDevice::Sync {
            since,
            open_items: false,
        },
    );
    loop {
        let frame = read(&mut socket, &mut session);
        assert!(!matches!(&frame, ToDevice::OpenItems { .. }));
        assert!(
            !matches!(&frame,ToDevice::Question{question} if question.definition.id==expired.id)
        );
        if matches!(frame, ToDevice::Synced { .. }) {
            break;
        }
    }
    assert!(!hub.open_item_devices.lock().unwrap().contains(&phone.id));
    send(
        &mut socket,
        &mut session,
        "opt-in",
        FromDevice::Sync {
            since,
            open_items: true,
        },
    );
    let mut saw_expired = false;
    let mut item = None;
    loop {
        let frame = read(&mut socket, &mut session);
        match frame {
            ToDevice::Question { question } if question.definition.id == expired.id => {
                saw_expired = true
            }
            ToDevice::OpenItems {
                items, complete, ..
            } => {
                assert!(complete);
                item = items.into_iter().find(|i| i.id == pending.id.as_str());
            }
            ToDevice::Synced { .. } => {
                assert!(
                    saw_expired && item.is_some(),
                    "metadata and complete discovery precede Synced"
                );
                break;
            }
            _ => {}
        }
    }
    assert!(hub.open_item_devices.lock().unwrap().contains(&phone.id));
    let item = item.unwrap();
    send(
        &mut socket,
        &mut session,
        "wire-dismiss",
        FromDevice::OpenItemDismiss {
            kind: item.kind,
            item: item.id.clone(),
            agent: item.agent,
            version: item.version.clone(),
        },
    );
    assert!(
        matches!(read(&mut socket,&mut session),ToDevice::OpenItemDismissed{of,version,..} if of.as_str()=="wire-dismiss" && version==item.version)
    );
    assert!(
        matches!(read(&mut socket,&mut session),ToDevice::OpenItems{complete:true,items,..} if items.iter().all(|i|i.id!=pending.id.as_str()))
    );
    assert_eq!(
        store.question(&pending.id).unwrap().unwrap().info.state,
        QuestionState::Pending
    );
    hub.publish_open_items(&store, OWNER);
    assert!(matches!(
        read(&mut socket, &mut session),
        ToDevice::OpenItems { complete: true, .. }
    ));
    socket.close(None).unwrap();
    assert_eq!(worker.join().unwrap(), Err("closed".into()));
}

#[test]
fn held_reminder_ids_are_scoped_by_creator_even_when_runtime_generations_match() {
    let (_dir, hub, store, phone, _rx) = fixture();
    set_host(&hub, Some(OWNER));
    let task:enclos_protocol::held_task::HeldTask=serde_json::from_value(serde_json::json!({"task":"app/t_same","title":"Review","reason":"Decision","since":1,"revision":"r1","resume":"Resume"})).unwrap();
    store
        .report_held_tasks(AGENT, "owned", std::slice::from_ref(&task))
        .unwrap();
    store
        .report_held_tasks("lab/helper", "other-agent", &[task])
        .unwrap();
    let items: Vec<_> = hub
        .open_item_frames(&store, OWNER)
        .unwrap()
        .into_iter()
        .flat_map(|f| match f {
            ToDevice::OpenItems { items, .. } => items,
            _ => vec![],
        })
        .collect();
    assert_eq!(items.len(), 2);
    let item = items
        .iter()
        .find(|i| i.agent.as_deref() == Some(AGENT))
        .unwrap();
    hub.dismiss_open_item(
        &store,
        &phone,
        OWNER,
        MessageId::new("scoped-dismiss").unwrap(),
        ReminderRef {
            kind: item.kind,
            id: &item.id,
            agent: item.agent.as_deref(),
            version: &item.version,
        },
    )
    .unwrap();
    assert!(hub.open_item_frames(&store,OWNER).unwrap().into_iter().any(|f|matches!(f,ToDevice::OpenItems{items,..} if items.len()==1 && items[0].agent.as_deref()==Some("lab/helper"))));
}
