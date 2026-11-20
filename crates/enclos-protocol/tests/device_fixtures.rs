//! The device leg's fixtures in tests/fixtures/device/, which the app reads
//! in its own tests too: each decodes, and encodes back to the same JSON.

use enclos_protocol::device::{FromDevice, ToDevice, decode_from_device, decode_to_device};
use enclos_protocol::held_task::HeldTaskState;

const TO_DEVICE: &[(&str, &str)] = &[
    (
        "held_task",
        include_str!("fixtures/device/to_device_held_task.json"),
    ),
    (
        "held_task_result",
        include_str!("fixtures/device/to_device_held_task_result.json"),
    ),
    (
        "message_held_task",
        include_str!("fixtures/device/to_device_message_held_task.json"),
    ),
    (
        "held_task_answered",
        include_str!("fixtures/device/to_device_held_task_answered.json"),
    ),
    (
        "task_detail",
        include_str!("fixtures/device/to_device_task_detail.json"),
    ),
    (
        "to_device_open_item_dismissed",
        include_str!("fixtures/device/to_device_open_item_dismissed.json"),
    ),
    (
        "to_device_question_closed",
        include_str!("fixtures/device/to_device_question_closed.json"),
    ),
    (
        "to_device_open_items",
        include_str!("fixtures/device/to_device_open_items.json"),
    ),
    (
        "to_device_open_items_unavailable",
        include_str!("fixtures/device/to_device_open_items_unavailable.json"),
    ),
    (
        "to_device_message_suggested_replies",
        include_str!("fixtures/device/to_device_message_suggested_replies.json"),
    ),
    (
        "to_device_message_task_event",
        include_str!("fixtures/device/to_device_message_task_event.json"),
    ),
    (
        "model_options",
        include_str!("fixtures/device/to_device_model_options.json"),
    ),
    (
        "model_models",
        include_str!("fixtures/device/to_device_model_models.json"),
    ),
];

const FROM_DEVICE: &[(&str, &str)] = &[
    (
        "held_task_resume",
        include_str!("fixtures/device/from_device_held_task_resume.json"),
    ),
    (
        "held_task_answer",
        include_str!("fixtures/device/from_device_held_task_answer.json"),
    ),
    (
        "task_get",
        include_str!("fixtures/device/from_device_task_get.json"),
    ),
    (
        "from_device_sync_open_items",
        include_str!("fixtures/device/from_device_sync_open_items.json"),
    ),
    (
        "from_device_held_task_get",
        include_str!("fixtures/device/from_device_held_task_get.json"),
    ),
    (
        "from_device_open_item_dismiss",
        include_str!("fixtures/device/from_device_open_item_dismiss.json"),
    ),
    (
        "from_device_question_close",
        include_str!("fixtures/device/from_device_question_close.json"),
    ),
    (
        "model_models",
        include_str!("fixtures/device/from_device_model_models.json"),
    ),
    (
        "model_set",
        include_str!("fixtures/device/from_device_model_set.json"),
    ),
];

fn json(bytes: &[u8]) -> serde_json::Value {
    serde_json::from_slice(bytes).expect("valid JSON")
}

#[test]
fn every_fixture_to_a_device_round_trips() {
    for (name, fixture) in TO_DEVICE {
        let message =
            decode_to_device(fixture.trim().as_bytes()).unwrap_or_else(|e| panic!("{name}: {e}"));
        let encoded = serde_json::to_vec(&message).unwrap();
        assert_eq!(json(&encoded), json(fixture.as_bytes()), "{name}");
    }
}

#[test]
fn every_fixture_from_a_device_round_trips() {
    for (name, fixture) in FROM_DEVICE {
        let message =
            decode_from_device(fixture.trim().as_bytes()).unwrap_or_else(|e| panic!("{name}: {e}"));
        let encoded = serde_json::to_vec(&message).unwrap();
        assert_eq!(json(&encoded), json(fixture.as_bytes()), "{name}");
    }
}

#[test]
fn the_fixtures_read_as_their_fields_say() {
    let ToDevice::HeldTask { held_task } = decode_to_device(TO_DEVICE[0].1.trim().as_bytes())
        .unwrap()
        .body
    else {
        panic!("a card");
    };
    assert_eq!(
        (held_task.state, held_task.revision),
        (HeldTaskState::Held, 0)
    );
    let ToDevice::Message(message) = decode_to_device(TO_DEVICE[2].1.trim().as_bytes())
        .unwrap()
        .body
    else {
        panic!("a message");
    };
    assert_eq!(message.held_task.unwrap().as_str(), held_task.task.as_str());
    let FromDevice::HeldTaskResume { revision, .. } =
        decode_from_device(FROM_DEVICE[0].1.trim().as_bytes())
            .unwrap()
            .body
    else {
        panic!("a resume");
    };
    assert_eq!(revision, held_task.revision);
}

#[test]
fn a_task_event_reads_as_its_task_and_an_older_message_has_none() {
    let fixture = |name: &str| {
        TO_DEVICE
            .iter()
            .find(|(n, _)| *n == name)
            .unwrap_or_else(|| panic!("no fixture {name}"))
            .1
    };
    let ToDevice::Message(line) =
        decode_to_device(fixture("to_device_message_task_event").trim().as_bytes())
            .unwrap()
            .body
    else {
        panic!("a message");
    };
    let event = line.task_event.expect("a task event");
    assert_eq!(
        (
            line.kind.as_str(),
            event.task.as_str(),
            event.assignee.as_deref()
        ),
        ("task_event", "t_a09759c7", Some("lab/reviewer"))
    );
    let ToDevice::Message(older) = decode_to_device(
        fixture("to_device_message_suggested_replies")
            .trim()
            .as_bytes(),
    )
    .unwrap()
    .body
    else {
        panic!("a message");
    };
    assert_eq!(older.task_event, None);
}
