//! The plugin leg's fixtures in tests/fixtures/plugin/, which the runtimes'
//! plugins read in their own tests too: each decodes, and encodes back to the
//! same JSON.

use enclos_protocol::plugin::{
    Capability, ErrorCode, FromBridge, FromPlugin, OutKind, ToolPhase, decode_from_bridge,
    decode_from_plugin,
};
use enclos_protocol::{DecodeError, Envelope, MAX_MESSAGE_BYTES, encode_line};

const FROM_BRIDGE: &[(&str, &str)] = &[
    (
        "hello",
        include_str!("fixtures/plugin/from_bridge_hello.json"),
    ),
    (
        "message_in",
        include_str!("fixtures/plugin/from_bridge_message_in.json"),
    ),
    ("ack", include_str!("fixtures/plugin/from_bridge_ack.json")),
    (
        "conversation_rename",
        include_str!("fixtures/plugin/from_bridge_conversation_rename.json"),
    ),
    (
        "hello_home",
        include_str!("fixtures/plugin/from_bridge_hello_home.json"),
    ),
    (
        "routine_create",
        include_str!("fixtures/plugin/from_bridge_routine_create.json"),
    ),
    (
        "conversation_delete",
        include_str!("fixtures/plugin/from_bridge_conversation_delete.json"),
    ),
];

const FROM_PLUGIN: &[(&str, &str)] = &[
    (
        "hello",
        include_str!("fixtures/plugin/from_plugin_hello.json"),
    ),
    (
        "message_out_reply",
        include_str!("fixtures/plugin/from_plugin_message_out_reply.json"),
    ),
    (
        "message_out_notify",
        include_str!("fixtures/plugin/from_plugin_message_out_notify.json"),
    ),
    (
        "typing",
        include_str!("fixtures/plugin/from_plugin_typing.json"),
    ),
    (
        "error",
        include_str!("fixtures/plugin/from_plugin_error.json"),
    ),
    (
        "conversation_title",
        include_str!("fixtures/plugin/from_plugin_conversation_title.json"),
    ),
    (
        "tool_start",
        include_str!("fixtures/plugin/from_plugin_tool_start.json"),
    ),
    (
        "tool_end",
        include_str!("fixtures/plugin/from_plugin_tool_end.json"),
    ),
    (
        "message_out_image",
        include_str!("fixtures/plugin/from_plugin_message_out_image.json"),
    ),
    (
        "message_out_status",
        include_str!("fixtures/plugin/from_plugin_message_out_status.json"),
    ),
    (
        "commands",
        include_str!("fixtures/plugin/from_plugin_commands.json"),
    ),
    (
        "message_out_html",
        include_str!("fixtures/plugin/from_plugin_message_out_html.json"),
    ),
    (
        "routine_response",
        include_str!("fixtures/plugin/from_plugin_routine_response.json"),
    ),
];

fn json(bytes: &[u8]) -> serde_json::Value {
    serde_json::from_slice(bytes).expect("valid JSON")
}

fn assert_round_trip<B: serde::Serialize>(name: &str, fixture: &str, message: &Envelope<B>) {
    let line = encode_line(message);
    assert_eq!(
        line.last(),
        Some(&b'\n'),
        "{name}: a line ends with a line break"
    );
    assert!(
        !line[..line.len() - 1].contains(&b'\n'),
        "{name}: no line break inside"
    );
    assert_eq!(
        json(&line),
        json(fixture.as_bytes()),
        "{name}: encodes back to the fixture"
    );
}

#[test]
fn every_fixture_from_the_bridge_round_trips() {
    for (name, fixture) in FROM_BRIDGE {
        let message =
            decode_from_bridge(fixture.trim().as_bytes()).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_round_trip(name, fixture, &message);
    }
}

#[test]
fn every_fixture_from_a_plugin_round_trips() {
    for (name, fixture) in FROM_PLUGIN {
        let message =
            decode_from_plugin(fixture.trim().as_bytes()).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_round_trip(name, fixture, &message);
    }
}

#[test]
fn a_message_reads_as_its_fields_say() {
    let message = decode_from_bridge(FROM_BRIDGE[1].1.as_bytes()).unwrap();
    let FromBridge::MessageIn {
        conversation,
        person,
        text,
        host,
    } = message.body
    else {
        panic!("not a message.in: {:?}", message.body);
    };
    assert_eq!(conversation.as_str(), "c-42");
    assert_eq!(person.as_str(), "alice@example.com");
    assert_eq!(text, "What's the weather in Paris?");
    assert_eq!(
        host, None,
        "a message.in without host comes from an older bridge"
    );

    let message = decode_from_plugin(FROM_PLUGIN[2].1.as_bytes()).unwrap();
    let FromPlugin::MessageOut { kind, reply_to, .. } = message.body else {
        panic!("not a message.out: {:?}", message.body);
    };
    assert_eq!(kind, OutKind::Notify);
    assert_eq!(reply_to, None);

    let fixture = |name: &str| FROM_PLUGIN.iter().find(|(n, _)| *n == name).unwrap().1;

    // The commands a person may type, each with what it does and what follows it.
    let message = decode_from_plugin(fixture("commands").as_bytes()).unwrap();
    let FromPlugin::Commands { commands } = message.body else {
        panic!("not commands: {:?}", message.body);
    };
    assert_eq!(
        commands
            .iter()
            .map(|c| (c.name.as_str(), c.args.as_deref()))
            .collect::<Vec<_>>(),
        [
            ("new", Some("[name]")),
            ("model", Some("[model] [--provider name] [--global]")),
            ("stop", None)
        ]
    );

    // The runtime about itself: a status, to the agent's Home.
    let message = decode_from_plugin(fixture("message_out_status").as_bytes()).unwrap();
    let FromPlugin::MessageOut {
        kind, conversation, ..
    } = message.body
    else {
        panic!("not a message.out: {:?}", message.body);
    };
    assert_eq!(
        (kind, conversation.as_str()),
        (OutKind::Status, "home.lab.main")
    );

    // The bridge's hello names the agent's Home; an older one, without it, still reads.
    let hello_home = FROM_BRIDGE
        .iter()
        .find(|(name, _)| *name == "hello_home")
        .unwrap()
        .1;
    let message = decode_from_bridge(hello_home.as_bytes()).unwrap();
    let FromBridge::Hello { home, .. } = message.body else {
        panic!("not a hello: {:?}", message.body);
    };
    assert_eq!(home.as_ref().map(|h| h.as_str()), Some("home.lab.main"));
    let FromBridge::Hello { home, .. } = decode_from_bridge(FROM_BRIDGE[0].1.as_bytes())
        .unwrap()
        .body
    else {
        panic!("not a hello");
    };
    assert_eq!(home, None);

    let message = decode_from_plugin(FROM_PLUGIN[4].1.as_bytes()).unwrap();
    let FromPlugin::Error(error) = message.body else {
        panic!("not an error: {:?}", message.body);
    };
    assert_eq!(error.code, ErrorCode::AgentUnavailable);

    let message = decode_from_bridge(FROM_BRIDGE[3].1.as_bytes()).unwrap();
    let FromBridge::Rename {
        conversation,
        title,
    } = message.body
    else {
        panic!("not a conversation.rename: {:?}", message.body);
    };
    assert_eq!(
        (conversation.as_str(), title.as_str()),
        ("c-42", "Weather in Paris")
    );

    let message = decode_from_plugin(FROM_PLUGIN[5].1.as_bytes()).unwrap();
    let FromPlugin::Title { title, .. } = message.body else {
        panic!("not a conversation.title: {:?}", message.body);
    };
    assert_eq!(title, "Paris weather this week");

    let message = decode_from_plugin(FROM_PLUGIN[6].1.as_bytes()).unwrap();
    let FromPlugin::Tool(start) = message.body else {
        panic!("not a tool: {:?}", message.body);
    };
    assert_eq!(
        (start.phase, start.label.as_deref(), start.ok),
        (ToolPhase::Start, Some("weather Paris this week"), None)
    );
    let message = decode_from_plugin(FROM_PLUGIN[7].1.as_bytes()).unwrap();
    let FromPlugin::Tool(end) = message.body else {
        panic!("not a tool: {:?}", message.body);
    };
    assert_eq!(
        (end.call, end.phase, end.ok, end.duration_ms),
        (start.call, ToolPhase::End, Some(true), Some(1840))
    );

    let message = decode_from_plugin(FROM_PLUGIN[8].1.as_bytes()).unwrap();
    let FromPlugin::MessageOut { attachments, .. } = message.body else {
        panic!("not a message.out: {:?}", message.body);
    };
    assert_eq!(attachments.len(), 1);
    assert_eq!(
        (
            attachments[0].mime.as_str(),
            attachments[0].name.as_str(),
            attachments[0].size
        ),
        ("image/png", "unicorn.png", 1_962_976)
    );
}

#[test]
fn unknown_fields_and_capabilities_are_ignored() {
    // `notify`, which older plugins announce and every runtime now has, reads as unknown too.
    let line = br#"{"v":1,"id":"m1","type":"hello","runtime":"hermes","agent":"main","capabilities":["notify","typing","teleport"],"later":true}"#;
    let message = decode_from_plugin(line).unwrap();
    let FromPlugin::Hello { capabilities, .. } = message.body else {
        panic!("not a hello: {:?}", message.body);
    };
    assert_eq!(
        capabilities,
        vec![Capability::Unknown, Capability::Typing, Capability::Unknown]
    );
}

#[test]
fn an_unknown_type_is_told_apart_from_a_bad_message() {
    let unknown = decode_from_plugin(br#"{"v":1,"id":"m1","type":"message.edit","text":"x"}"#);
    assert_eq!(
        unknown,
        Err(DecodeError::UnknownType {
            id: Some("m1".to_owned()),
            kind: "message.edit".to_owned()
        })
    );
    let bad =
        decode_from_plugin(br#"{"v":1,"id":"m2","type":"message.out","text":"no conversation"}"#);
    assert!(
        matches!(bad, Err(DecodeError::Bad { id: Some(ref id), .. }) if id == "m2"),
        "{bad:?}"
    );
}

#[test]
fn other_versions_wrong_ids_and_oversized_messages_are_refused() {
    assert_eq!(
        decode_from_bridge(br#"{"v":2,"id":"m1","type":"ack","of":"m0"}"#),
        Err(DecodeError::Version {
            id: Some("m1".to_owned()),
            v: 2
        })
    );
    assert_eq!(
        decode_from_bridge(br#"{"v":2,"type":"ack","of":"m0"}"#),
        Err(DecodeError::Version { id: None, v: 2 })
    );
    assert!(matches!(
        decode_from_bridge(br#"{"id":"m1","type":"ack","of":"m0"}"#),
        Err(DecodeError::Bad { .. })
    ));
    assert!(matches!(
        decode_from_bridge(br#"{"v":1,"id":"","type":"ack","of":"m0"}"#),
        Err(DecodeError::Bad { .. })
    ));
    assert!(matches!(
        decode_from_bridge(br#"{"v":1,"id":"m1","type":"message.in","conversation":"c\u0000","person":"p","text":"t"}"#),
        Err(DecodeError::Bad { .. })
    ));
    assert!(matches!(
        decode_from_bridge(b"[1,2]"),
        Err(DecodeError::NotJson(_))
    ));
    let big = vec![b' '; MAX_MESSAGE_BYTES + 1];
    assert_eq!(decode_from_bridge(&big), Err(DecodeError::TooBig));
}

#[test]
fn names_and_error_text_from_the_sandbox_hold_no_control_character() {
    let hello = |runtime: &str, agent: &str| {
        format!(
            r#"{{"v":1,"id":"m1","type":"hello","runtime":{},"agent":{},"capabilities":[]}}"#,
            serde_json::to_string(runtime).unwrap(),
            serde_json::to_string(agent).unwrap()
        )
    };
    assert!(decode_from_plugin(hello("hermes", "main").as_bytes()).is_ok());
    let long = "a".repeat(129);
    for (runtime, agent) in [
        ("hermes\u{1b}[2J", "main"),
        ("hermes", "main\n"),
        ("", "main"),
        ("hermes", ""),
        (long.as_str(), "main"),
    ] {
        assert!(
            matches!(
                decode_from_plugin(hello(runtime, agent).as_bytes()),
                Err(DecodeError::Bad { .. })
            ),
            "{runtime:?} {agent:?}"
        );
    }

    let error = |message: &str| {
        format!(
            r#"{{"v":1,"id":"m1","type":"error","code":"bad_message","message":{}}}"#,
            serde_json::to_string(message).unwrap()
        )
    };
    assert!(decode_from_plugin(error("A line over 1 MiB.").as_bytes()).is_ok());
    assert!(decode_from_plugin(error("").as_bytes()).is_ok());
    for message in ["red \u{1b}[31m", "two\nlines", "bell \u{7}"] {
        assert!(
            matches!(
                decode_from_plugin(error(message).as_bytes()),
                Err(DecodeError::Bad { .. })
            ),
            "{message:?}"
        );
        assert!(
            matches!(
                decode_from_bridge(error(message).as_bytes()),
                Err(DecodeError::Bad { .. })
            ),
            "{message:?}"
        );
    }
}
