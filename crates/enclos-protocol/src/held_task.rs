//! Held tasks (ADR 0066, proposed; `docs/protocol.md`, Held tasks):
//! background work an agent's runtime started that has stopped and waits
//! for a person before it runs again (a blocked task on Hermes's kanban
//! board). The runtime keeps the task; the bridge keeps a card for it in
//! the Home of the agent that started it; the host's person may resume it
//! with the runtime's own operation, unless the runtime reports it not
//! `resumable`, when the card says what to do outside the app instead.

use serde::{Deserialize, Serialize};

use crate::ids::{ConversationId, HeldTaskId, HeldTaskRevision};
use crate::visible;

/// The most held tasks one agent's plugin reports at once: every sync
/// sends each held card, so their number stays bounded.
pub const MAX_HELD_TASKS: usize = 32;
/// A title's length once the bridge has cut it, in characters; one line.
pub const MAX_TITLE_CHARS: usize = 200;
/// Why it is held, in characters; lines allowed.
pub const MAX_REASON_CHARS: usize = 1_000;
/// Its last error, in characters; lines allowed.
pub const MAX_ERROR_CHARS: usize = 2_000;
/// What resuming does for this runtime, or for a task that is not
/// `resumable` the optional instruction for outside the app, in
/// characters; one line.
pub const MAX_RESUME_CHARS: usize = 200;

/// What a card says when the runtime gave no reason.
pub const NO_REASON: &str = "Waiting for a person.";

/// One held task, as the plugin reads it from its runtime's own state
/// (never from the text of the runtime's notifications).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeldTask {
    /// The runtime's id for the task.
    pub task: HeldTaskId,
    pub title: String,
    /// The agent doing the work, as the runtime names it, when it is not
    /// the one that started it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assignee: Option<String>,
    /// Why it is held, in the runtime's words.
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    /// Since when it is held, in seconds since the Unix epoch.
    pub since: i64,
    /// The runtime's opaque revision of this hold: a resume names it, and
    /// the plugin refuses (`conflict`) one that is no longer current when
    /// it checks. Not the bridge's card revision, a number.
    pub revision: HeldTaskRevision,
    /// What resuming does for this runtime, one line ("Runs it again with
    /// a fresh retry budget."); for a task that cannot be resumed from the
    /// app, what a person does instead.
    pub resume: String,
    /// Whether the app may offer to resume it: false for a task the runtime
    /// holds but does not resume this way, which the bridge refuses
    /// (`unsupported`) before asking the plugin. A JSON boolean; absent,
    /// as from an older plugin, it reads as true.
    #[serde(default = "resumable")]
    pub resumable: bool,
}

/// `resumable` where a plugin, bridge or card did not say.
fn resumable() -> bool {
    true
}

impl HeldTask {
    /// The task as a person may read it: hidden characters dropped
    /// ([`crate::visible`]), each field cut to its bound, a blank title
    /// read as the task's id and a blank reason as [`NO_REASON`]. The
    /// bridge applies it to what the plugin, in the sandbox, sent, rather
    /// than trust the plugin's own cut.
    pub fn normalized(self) -> Self {
        let title = cut(&one_line(&self.title), MAX_TITLE_CHARS);
        let reason = cut(&visible::stripped(&self.reason, true), MAX_REASON_CHARS);
        Self {
            title: if title.is_empty() {
                self.task.as_str().to_owned()
            } else {
                title
            },
            assignee: self
                .assignee
                .map(|name| cut(&one_line(&name), MAX_ASSIGNEE_CHARS))
                .filter(|name| !name.is_empty()),
            reason: if reason.is_empty() {
                NO_REASON.to_owned()
            } else {
                reason
            },
            last_error: self
                .last_error
                .map(|error| cut(&visible::stripped(&error, true), MAX_ERROR_CHARS))
                .filter(|error| !error.is_empty()),
            resume: cut(&one_line(&self.resume), MAX_RESUME_CHARS),
            ..self
        }
    }
}

/// An assignee's name, in characters.
const MAX_ASSIGNEE_CHARS: usize = 64;

/// `text` on one line: each run of white space, line breaks and tabs
/// included, read as one space ("Fix build\nthen deploy" stays two
/// words), then without hidden characters.
fn one_line(text: &str) -> String {
    let spaced: String = text
        .chars()
        .map(|c| if c.is_whitespace() { ' ' } else { c })
        .collect();
    visible::stripped(
        &spaced
            .split(' ')
            .filter(|w| !w.is_empty())
            .collect::<Vec<_>>()
            .join(" "),
        false,
    )
}

/// `text` trimmed and cut to `max` characters.
fn cut(text: &str, max: usize) -> String {
    text.trim()
        .chars()
        .take(max)
        .collect::<String>()
        .trim_end()
        .to_owned()
}

/// Checks a plugin's `held_tasks`: at most [`MAX_HELD_TASKS`], each task
/// once, and ids and revisions with no hidden character, so the one a
/// device sends back is the one the runtime gave. (The id rule itself is
/// checked when the message is decoded.)
pub fn check_snapshot(tasks: &[HeldTask]) -> Result<(), String> {
    if tasks.len() > MAX_HELD_TASKS {
        return Err(format!("more than {MAX_HELD_TASKS} held tasks"));
    }
    let mut seen = std::collections::HashSet::new();
    for task in tasks {
        if visible::has_hidden(task.task.as_str(), false) {
            return Err("a task id holds a hidden character".into());
        }
        if visible::has_hidden(task.revision.as_str(), false) {
            return Err("a task revision holds a hidden character".into());
        }
        if !seen.insert(task.task.as_str()) {
            return Err(format!("task {} is listed twice", task.task));
        }
    }
    Ok(())
}

/// A plugin's `held_tasks` as the bridge may keep them: [`check_snapshot`]
/// first, which refuses the whole list, then each task
/// [`HeldTask::normalized`]. The one way in, so a card is never stored
/// unchecked or uncut.
pub fn accept(tasks: Vec<HeldTask>) -> Result<Vec<HeldTask>, String> {
    check_snapshot(&tasks)?;
    Ok(tasks.into_iter().map(HeldTask::normalized).collect())
}

/// Where a card is. `held` is the only state eligible for a Resume, and
/// a held card offers one only when it is also `resumable`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HeldTaskState {
    /// The runtime holds the task: waiting for a person.
    Held,
    /// A paired device resumed it, and the runtime confirmed.
    Resumed,
    /// The runtime no longer holds it: it runs again, finished or went
    /// away, wherever that happened.
    Released,
    /// The agent's channel stopped reporting held tasks, so the card can no
    /// longer tell.
    Expired,
    /// A state a newer bridge sent: shown without a Resume.
    #[serde(other)]
    Unknown,
}

/// A held task's card, as a device sees it: in the Home conversation of
/// the agent that started the work.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeldTaskInfo {
    /// The agent that started the work, `sandbox/agent`.
    pub agent: String,
    /// That agent's Home.
    pub conversation: ConversationId,
    pub task: HeldTaskId,
    pub title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assignee: Option<String>,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    pub since: i64,
    pub resume: String,
    /// The task's own `resumable`: a card that is false shows how to go on
    /// instead of a Resume. Absent, as from an older bridge, it reads as true.
    #[serde(default = "resumable")]
    pub resumable: bool,
    pub state: HeldTaskState,
    /// The bridge's revision of the card, advanced on every change: a
    /// device keeps the highest it saw, and a resume names it.
    pub revision: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::{FromDevice, ToDevice, decode_from_device, decode_to_device};
    use crate::plugin::{FromBridge, FromPlugin, decode_from_bridge, decode_from_plugin};
    use crate::{Envelope, MessageId, Person};

    fn task(id: &str) -> HeldTask {
        HeldTask {
            task: HeldTaskId::new(id).unwrap(),
            title: "Write the report".into(),
            assignee: Some("writer".into()),
            reason: "Gave up after 3 failures".into(),
            last_error: Some("rate limited".into()),
            since: 1_763_000_000,
            revision: HeldTaskRevision::new("e:42").unwrap(),
            resume: "Runs it again with a fresh retry budget.".into(),
            resumable: true,
        }
    }

    #[test]
    fn the_plugin_leg_round_trips() {
        let snapshot = Envelope::new(
            MessageId::new("h1").unwrap(),
            FromPlugin::HeldTasks {
                tasks: vec![task("t_1"), task("t_2")],
            },
        );
        let line = serde_json::to_vec(&snapshot).unwrap();
        assert_eq!(decode_from_plugin(&line).unwrap(), snapshot);

        let resumed = Envelope::new(
            MessageId::new("h2").unwrap(),
            FromPlugin::HeldTaskResumed {
                of: MessageId::new("r1").unwrap(),
            },
        );
        let line = serde_json::to_vec(&resumed).unwrap();
        assert_eq!(decode_from_plugin(&line).unwrap(), resumed);

        let resume = Envelope::new(
            MessageId::new("r1").unwrap(),
            FromBridge::HeldTaskResume {
                task: HeldTaskId::new("t_1").unwrap(),
                revision: HeldTaskRevision::new("e:42").unwrap(),
                person: Person::new("alice@example.com").unwrap(),
                device: "d1".into(),
            },
        );
        let line = serde_json::to_vec(&resume).unwrap();
        assert_eq!(decode_from_bridge(&line).unwrap(), resume);
        // The wire form the plugin reads.
        let json: serde_json::Value = serde_json::from_slice(&line).unwrap();
        assert_eq!(json["type"], "held_task.resume");
        assert_eq!(json["task"], "t_1");
        assert_eq!(json["revision"], "e:42");
    }

    #[test]
    fn an_empty_snapshot_is_one_with_no_held_task() {
        let decoded =
            decode_from_plugin(br#"{"v":1,"id":"h","type":"held_tasks","tasks":[]}"#).unwrap();
        assert_eq!(decoded.body, FromPlugin::HeldTasks { tasks: vec![] });
        // `tasks` is required: an absent list is not "none held".
        assert!(decode_from_plugin(br#"{"v":1,"id":"h","type":"held_tasks"}"#).is_err());
    }

    #[test]
    fn the_device_leg_round_trips() {
        let info = HeldTaskInfo {
            agent: "lab/main".into(),
            conversation: ConversationId::new("home.lab.main").unwrap(),
            task: HeldTaskId::new("t_1").unwrap(),
            title: "Write the report".into(),
            assignee: None,
            reason: NO_REASON.into(),
            last_error: None,
            since: 1_763_000_000,
            resume: String::new(),
            resumable: true,
            state: HeldTaskState::Held,
            revision: 3,
        };
        for body in [
            ToDevice::HeldTask {
                held_task: info.clone(),
            },
            ToDevice::HeldTaskResult {
                of: MessageId::new("r1").unwrap(),
                held_task: info.clone(),
            },
        ] {
            let frame = Envelope::new(MessageId::new("b1").unwrap(), body);
            let bytes = serde_json::to_vec(&frame).unwrap();
            assert_eq!(decode_to_device(&bytes).unwrap(), frame);
        }
        let resume = Envelope::new(
            MessageId::new("r1").unwrap(),
            FromDevice::HeldTaskResume {
                agent: "lab/main".into(),
                task: HeldTaskId::new("t_1").unwrap(),
                revision: 3,
            },
        );
        let bytes = serde_json::to_vec(&resume).unwrap();
        assert_eq!(decode_from_device(&bytes).unwrap(), resume);
        // A resume names the card's revision: one without is refused.
        assert!(
            decode_from_device(
                br#"{"v":1,"id":"r","type":"held_task.resume","agent":"lab/main","task":"t_1"}"#
            )
            .is_err()
        );
    }

    /// `resumable` as each leg carries it after a decode and an encode:
    /// what an older plugin, bridge or card omits reads as true, and a
    /// false survives.
    #[test]
    fn whether_a_held_task_can_be_resumed_survives_each_leg() {
        let task = |resumable: Option<serde_json::Value>| {
            let mut task = serde_json::json!({"task":"t_1","title":"t","reason":"r","since":1,
                "revision":"e:42","resume":""});
            if let Some(value) = resumable {
                task["resumable"] = value;
            }
            task
        };
        let card = |resumable: Option<serde_json::Value>| {
            let mut card = serde_json::json!({"agent":"lab/main","conversation":"home.lab.main",
                "task":"t_1","title":"t","reason":"r","since":1,"resume":"","state":"held",
                "revision":3});
            if let Some(value) = resumable {
                card["resumable"] = value;
            }
            card
        };
        for (given, read) in [
            (None, true),
            (Some(true.into()), true),
            (Some(false.into()), false),
        ] {
            let line = serde_json::json!({"v":1,"id":"h","type":"held_tasks",
                "tasks":[task(given.clone())]});
            let decoded = decode_from_plugin(line.to_string().as_bytes()).unwrap();
            let again: serde_json::Value = serde_json::to_value(&decoded).unwrap();
            assert_eq!(
                again["tasks"][0]["resumable"], read,
                "plugin leg, given {given:?}"
            );

            for line in [
                serde_json::json!({"v":1,"id":"b","type":"held_task","held_task":card(given.clone())}),
                serde_json::json!({"v":1,"id":"b","type":"held_task.result","of":"r1",
                    "held_task":card(given.clone())}),
            ] {
                let decoded = decode_to_device(line.to_string().as_bytes()).unwrap();
                let again: serde_json::Value = serde_json::to_value(&decoded).unwrap();
                assert_eq!(again["held_task"]["resumable"], read, "{line}");
            }
        }
    }

    /// Present, `resumable` is a JSON boolean: nothing else reads as one,
    /// and none reads as the default.
    #[test]
    fn a_resumable_that_is_not_a_boolean_is_refused_on_each_leg() {
        for bad in [
            serde_json::Value::Null,
            "false".into(),
            "true".into(),
            0.into(),
            1.into(),
            0.5.into(),
            serde_json::json!([]),
            serde_json::json!({}),
        ] {
            let line = serde_json::json!({"v":1,"id":"h","type":"held_tasks","tasks":[{
                "task":"t_1","title":"t","reason":"r","since":1,"revision":"e:42","resume":"",
                "resumable":bad}]});
            assert!(
                decode_from_plugin(line.to_string().as_bytes()).is_err(),
                "{line}"
            );
            let card = serde_json::json!({"agent":"lab/main","conversation":"home.lab.main",
                "task":"t_1","title":"t","reason":"r","since":1,"resume":"","state":"held",
                "revision":3,"resumable":bad});
            for line in [
                serde_json::json!({"v":1,"id":"b","type":"held_task","held_task":card.clone()}),
                serde_json::json!({"v":1,"id":"b","type":"held_task.result","of":"r1",
                    "held_task":card.clone()}),
            ] {
                assert!(
                    decode_to_device(line.to_string().as_bytes()).is_err(),
                    "{line}"
                );
            }
        }
    }

    #[test]
    fn a_state_from_a_newer_bridge_reads_as_unknown() {
        let state: HeldTaskState = serde_json::from_str(r#""cancelled""#).unwrap();
        assert_eq!(state, HeldTaskState::Unknown);
        let state: HeldTaskState = serde_json::from_str(r#""released""#).unwrap();
        assert_eq!(state, HeldTaskState::Released);
    }

    #[test]
    fn normalizing_drops_hidden_characters_and_cuts_each_field() {
        let held = HeldTask {
            title: format!("  Deploy\u{202E}lmth.exe {}\n", "x".repeat(300)),
            assignee: Some("\u{200B}".into()),
            reason: "line one\nline two\u{0007}".into(),
            last_error: Some(" ".into()),
            resume: "Runs again\u{2028}now".into(),
            ..task("t_1")
        }
        .normalized();
        assert!(held.title.starts_with("Deploylmth.exe x"));
        assert_eq!(held.title.chars().count(), MAX_TITLE_CHARS);
        assert!(!visible::has_hidden(&held.title, false));
        assert_eq!(held.assignee, None);
        assert_eq!(held.reason, "line one\nline two");
        assert_eq!(held.last_error, None);
        // A line break in a one-line field is a space, not a join.
        assert_eq!(held.resume, "Runs again now");
        let lines = HeldTask {
            title: "Fix build\nthen\r\n\tdeploy".into(),
            assignee: Some(format!("{}\nb", "a".repeat(80))),
            ..task("t_1")
        }
        .normalized();
        assert_eq!(lines.title, "Fix build then deploy");
        assert_eq!(lines.assignee.unwrap().chars().count(), MAX_ASSIGNEE_CHARS);

        let blank = HeldTask {
            title: "\u{200B} ".into(),
            reason: "\u{2066}".into(),
            ..task("t_9")
        }
        .normalized();
        assert_eq!(blank.title, "t_9");
        assert_eq!(blank.reason, NO_REASON);

        let long = HeldTask {
            reason: "é".repeat(MAX_REASON_CHARS + 5),
            last_error: Some("e".repeat(MAX_ERROR_CHARS + 5)),
            ..task("t_2")
        }
        .normalized();
        assert_eq!(long.reason.chars().count(), MAX_REASON_CHARS);
        assert_eq!(long.last_error.unwrap().chars().count(), MAX_ERROR_CHARS);
    }

    #[test]
    fn a_snapshot_is_bounded_and_names_each_task_once() {
        assert!(check_snapshot(&[task("a"), task("b")]).is_ok());
        assert!(check_snapshot(&[task("a"), task("a")]).is_err());
        let many: Vec<_> = (0..=MAX_HELD_TASKS)
            .map(|n| task(&format!("t{n}")))
            .collect();
        assert!(check_snapshot(&many).is_err());
        assert!(check_snapshot(&many[..MAX_HELD_TASKS]).is_ok());
        assert!(check_snapshot(&[task("t\u{200B}1")]).is_err());
        let hidden = HeldTask {
            revision: HeldTaskRevision::new("e\u{202E}1").unwrap(),
            ..task("a")
        };
        assert!(check_snapshot(&[hidden]).is_err());
        // An empty, controlled or too long revision is refused when decoded.
        for revision in [
            String::new(),
            "e\n1".into(),
            "r".repeat(crate::ids::MAX_ID_BYTES + 1),
        ] {
            assert!(HeldTaskRevision::new(revision.clone()).is_err());
            let line = serde_json::json!({"v":1,"id":"h","type":"held_tasks","tasks":[{
                "task":"a","title":"t","reason":"r","since":1,"revision":revision,"resume":""}]});
            assert!(decode_from_plugin(line.to_string().as_bytes()).is_err());
        }
    }

    #[test]
    fn accept_checks_the_whole_list_then_cuts_each_task() {
        assert!(accept(vec![task("a"), task("a")]).is_err());
        let kept = accept(vec![HeldTask {
            title: "Deploy\nnow\u{202E}".into(),
            ..task("a")
        }])
        .unwrap();
        assert_eq!(kept[0].title, "Deploy now");
    }

    #[test]
    fn the_capability_is_named_held_tasks_on_the_wire() {
        assert_eq!(
            serde_json::to_value(crate::plugin::Capability::HeldTasks).unwrap(),
            "held_tasks"
        );
        let read: crate::plugin::Capability = serde_json::from_str(r#""held_tasks""#).unwrap();
        assert_eq!(read, crate::plugin::Capability::HeldTasks);
    }

    #[test]
    fn the_largest_card_fits_one_device_message() {
        // The widest JSON per character: 4 bytes for a character outside
        // the Basic Multilingual Plane, which serde_json does not escape
        // (an escaped quote or line break is 2); an id's 128 bytes are
        // widest as quotes, 256 once escaped.
        let wide = |n: usize| "\u{1F600}".repeat(n);
        let quotes = || "\"".repeat(crate::ids::MAX_ID_BYTES);
        // Both values of `resumable`: `false` is the wider by one byte.
        let lengths = [true, false].map(|resumable| {
            let info = HeldTaskInfo {
                agent: format!("{}/{}", "\"".repeat(63), "\"".repeat(64)),
                conversation: ConversationId::new(quotes()).unwrap(),
                task: HeldTaskId::new(quotes()).unwrap(),
                title: wide(MAX_TITLE_CHARS),
                assignee: Some(wide(MAX_ASSIGNEE_CHARS)),
                reason: wide(MAX_REASON_CHARS),
                last_error: Some(wide(MAX_ERROR_CHARS)),
                since: i64::MIN,
                resume: wide(MAX_RESUME_CHARS),
                resumable,
                state: HeldTaskState::Released,
                revision: u64::MAX,
            };
            let frame = Envelope::new(
                MessageId::new(quotes()).unwrap(),
                ToDevice::HeldTaskResult {
                    of: MessageId::new(quotes()).unwrap(),
                    held_task: info,
                },
            );
            let line = crate::encode_line(&frame);
            assert!(
                line.len() <= crate::device::MAX_DEVICE_MESSAGE,
                "resumable {resumable}: {} bytes",
                line.len()
            );
            line.len()
        });
        assert_eq!(lengths[1], lengths[0] + 1);
    }
}
