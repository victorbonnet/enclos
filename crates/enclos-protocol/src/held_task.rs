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

/// An ask's decision, in characters; one line (ADR 0073).
pub const MAX_DECISION_CHARS: usize = 120;
/// What is blocked, in characters; lines allowed.
pub const MAX_BLOCKED_CHARS: usize = 400;
/// The most choices an ask offers.
pub const MAX_CHOICES: usize = 4;
/// One choice, in characters; one line.
pub const MAX_CHOICE_CHARS: usize = 80;
/// What an answered card says the person answered, in characters; one line.
pub const MAX_ANSWER_CHARS: usize = 200;
/// A typed answer, in characters; lines allowed.
pub const MAX_ANSWER_TEXT_CHARS: usize = 2_000;
/// What an answered card says when the agent reports the person answered
/// in the conversation (`settled`).
pub const ANSWERED_IN_CONVERSATION: &str = "Answered in the conversation.";
/// What an answered card says when the person asked the agent to look.
pub const ASKED_THE_AGENT: &str = "Asked the agent to look into it.";

/// What the agent that started a held task wrote for the person when it
/// handed the hold to them (ADR 0073, proposed): the card shows it first,
/// and the person answers it from the app.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeldTaskAsk {
    /// The decision, as one question.
    pub decision: String,
    /// What is stopped and why, in plain words.
    #[serde(default)]
    pub blocked: String,
    /// Up to [`MAX_CHOICES`] answers, each saying what happens; none asks
    /// for a free answer.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub choices: Vec<String>,
    /// The index of the choice the agent recommends.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recommended: Option<u32>,
    /// The agent says the person answered (in the conversation): only on
    /// the plugin leg; a device's card never carries it.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub settled: bool,
    /// When the agent asked, as the plugin counts it (an opaque number): a
    /// new value is a new question even in the same words, so an agent
    /// asking again after an answer is told apart from the same list sent
    /// again. Only on the plugin leg.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asked: Option<i64>,
}

impl HeldTaskAsk {
    /// The ask as a person may read it, or `None` when its decision is
    /// blank: the decision and each choice on one line and cut, `blocked`
    /// cut with its lines kept, a blank choice or one reading as an earlier
    /// one dropped, the first [`MAX_CHOICES`] kept, and `recommended`
    /// following its choice (dropped with it).
    pub fn normalized(self) -> Option<Self> {
        let decision = cut(&one_line(&self.decision), MAX_DECISION_CHARS);
        if decision.is_empty() {
            return None;
        }
        let mut choices: Vec<String> = Vec::new();
        let mut recommended = None;
        for (index, choice) in self.choices.iter().enumerate() {
            if choices.len() == MAX_CHOICES {
                break;
            }
            let choice = cut(&one_line(choice), MAX_CHOICE_CHARS);
            let bare = visible::bare(&choice);
            if choice.is_empty() || choices.iter().any(|kept| visible::bare(kept) == bare) {
                continue;
            }
            if self.recommended == u32::try_from(index).ok() {
                recommended = u32::try_from(choices.len()).ok();
            }
            choices.push(choice);
        }
        Some(Self {
            decision,
            blocked: cut(&visible::stripped(&self.blocked, true), MAX_BLOCKED_CHARS),
            choices,
            recommended,
            settled: self.settled,
            asked: self.asked,
        })
    }

    /// The ask as a device reads it: without what only the plugin leg
    /// carries (`settled`, `asked`).
    pub fn for_device(self) -> Self {
        Self {
            settled: false,
            asked: None,
            ..self
        }
    }

    /// The same question, whether or not the agent says it was answered:
    /// what tells an agent asking again from a mere `settled`.
    pub fn same_question(&self, other: &Self) -> bool {
        Self {
            settled: false,
            ..self.clone()
        } == Self {
            settled: false,
            ..other.clone()
        }
    }

    /// The ask as readable text, for a history message and an older app.
    pub fn text(&self, title: &str) -> String {
        let mut text = self.decision.clone();
        if !self.blocked.is_empty() {
            text.push('\n');
            text.push_str(&self.blocked);
        }
        for (index, choice) in self.choices.iter().enumerate() {
            text.push_str(&format!("\n{}. {choice}", index + 1));
            if self.recommended == u32::try_from(index).ok() {
                text.push_str(" (recommended)");
            }
        }
        text.push_str(&format!("\nHeld task: {title}"));
        text
    }
}

/// A person's answer to a held card (`held_task.answer`, ADR 0073).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum HeldTaskAnswer {
    /// One of the card's `ask` choices, by its zero-based index.
    Choice { index: u32 },
    /// A typed answer.
    Text { text: String },
    /// Ask the agent to look into the task and say what it needs.
    Agent,
}

/// What an answer becomes: the person's message to the agent, and what
/// the answered card says the person answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnswerMessage {
    pub text: String,
    pub answer: String,
}

impl HeldTaskAnswer {
    /// The message `card`'s answer sends the agent, and the card's
    /// `answer`; `Err` says why the answer does not fit the card (a choice
    /// it does not offer, a text outside its rule).
    pub fn message(&self, card: &HeldTaskInfo) -> Result<AnswerMessage, String> {
        let about = match &card.ask {
            Some(ask) => format!(
                "About held task {} \"{}\": {}",
                card.task, card.title, ask.decision
            ),
            None => format!("About held task {} \"{}\"", card.task, card.title),
        };
        let (said, answer) = match self {
            Self::Choice { index } => {
                let choice = card
                    .ask
                    .as_ref()
                    .and_then(|ask| ask.choices.get(usize::try_from(*index).ok()?))
                    .ok_or("This card offers no such choice.")?;
                (format!("{about}\nMy answer: {choice}"), choice.clone())
            }
            Self::Text { text } => {
                let text = text.trim();
                if text.is_empty() {
                    return Err("An answer cannot be blank.".into());
                }
                if text.chars().count() > MAX_ANSWER_TEXT_CHARS {
                    return Err(format!(
                        "An answer holds at most {MAX_ANSWER_TEXT_CHARS} characters."
                    ));
                }
                if visible::has_hidden(text, true) {
                    return Err("An answer cannot hold a hidden character.".into());
                }
                let first = text.lines().next().unwrap_or_default();
                (
                    format!("{about}\nMy answer: {text}"),
                    cut(&one_line(first), MAX_ANSWER_CHARS),
                )
            }
            Self::Agent => (
                format!(
                    "About held task {} \"{}\": look into it and tell me what you need from me.",
                    card.task, card.title
                ),
                ASKED_THE_AGENT.to_owned(),
            ),
        };
        Ok(AnswerMessage { text: said, answer })
    }

    /// The answer's kind, as the audit log names it.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Choice { .. } => "choice",
            Self::Text { .. } => "text",
            Self::Agent => "agent",
        }
    }
}

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
    /// What the agent wrote for the person when it handed this hold to
    /// them (ADR 0073), if it did.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ask: Option<HeldTaskAsk>,
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
            ask: self.ask.and_then(HeldTaskAsk::normalized),
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
    /// The runtime still holds it, and the person answered (ADR 0073): it
    /// waits on the agent.
    Answered,
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
    /// What the agent wrote for the person (ADR 0073), never `settled`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ask: Option<HeldTaskAsk>,
    /// On an `answered` card, what the person answered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub answer: Option<String>,
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
            ask: None,
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
            ask: None,
            answer: None,
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
                // The agent's ask and the person's answer at their widest
                // (ADR 0073).
                ask: Some(HeldTaskAsk {
                    decision: wide(MAX_DECISION_CHARS),
                    blocked: wide(MAX_BLOCKED_CHARS),
                    choices: vec![wide(MAX_CHOICE_CHARS); MAX_CHOICES],
                    recommended: Some(u32::MAX),
                    settled: false,
                    asked: None,
                }),
                answer: Some(wide(MAX_ANSWER_CHARS)),
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

    fn ask(choices: &[&str], recommended: Option<u32>) -> HeldTaskAsk {
        HeldTaskAsk {
            decision: "Allow one more hour to fix Hermes backups?".into(),
            blocked: "Both reviews found that chat text can stop a backup.".into(),
            choices: choices.iter().map(|c| (*c).to_owned()).collect(),
            recommended,
            settled: false,
            asked: None,
        }
    }

    #[test]
    fn an_ask_is_cut_and_its_recommended_choice_follows_it() {
        let kept = HeldTaskAsk {
            decision: format!("Allow\none more {}?", "x".repeat(200)),
            blocked: "line one\nline two\u{0007}".into(),
            ..ask(
                &[
                    "",
                    "Keep paused",
                    "Keep\u{200B} paused",
                    "Allow one fix",
                    "A",
                    "B",
                    "C",
                ],
                Some(3),
            )
        }
        .normalized()
        .unwrap();
        assert!(kept.decision.starts_with("Allow one more x"));
        assert_eq!(kept.decision.chars().count(), MAX_DECISION_CHARS);
        assert_eq!(kept.blocked, "line one\nline two");
        // The blank and the one reading as an earlier one are dropped,
        // then the first four kept; the recommended one moves with them.
        assert_eq!(kept.choices, ["Keep paused", "Allow one fix", "A", "B"]);
        assert_eq!(kept.recommended, Some(1));

        // Recommending a dropped choice, or one that does not exist, recommends none.
        let dropped = ask(&["Keep paused", "Keep paused"], Some(1))
            .normalized()
            .unwrap();
        assert_eq!(dropped.choices, ["Keep paused"]);
        assert_eq!(dropped.recommended, None);
        assert_eq!(ask(&["A"], Some(7)).normalized().unwrap().recommended, None);
        let hundred = "c".repeat(100);
        let long = ask(&[hundred.as_str()], None).normalized().unwrap();
        assert_eq!(long.choices[0].chars().count(), MAX_CHOICE_CHARS);

        // A blank decision drops the whole ask, and the task keeps its card.
        let blank = HeldTaskAsk {
            decision: " \u{200B}\n".into(),
            ..ask(&["A"], None)
        };
        assert_eq!(blank.normalized(), None);
        let task = HeldTask {
            ask: Some(HeldTaskAsk {
                decision: "\u{2066}".into(),
                ..ask(&[], None)
            }),
            ..task("t_1")
        }
        .normalized();
        assert_eq!(task.ask, None);
    }

    #[test]
    fn settled_alone_is_the_same_question() {
        let asked = ask(&["A", "B"], Some(0));
        let settled = HeldTaskAsk {
            settled: true,
            ..asked.clone()
        };
        assert!(asked.same_question(&settled));
        // Asked again in the same words: another question.
        assert!(!asked.same_question(&HeldTaskAsk {
            asked: Some(2),
            ..asked.clone()
        }));
        assert!(!asked.same_question(&ask(&["A", "C"], Some(0))));
        assert!(!asked.same_question(&ask(&["A", "B"], Some(1))));
    }

    fn card(ask: Option<HeldTaskAsk>) -> HeldTaskInfo {
        HeldTaskInfo {
            agent: "lab/main".into(),
            conversation: ConversationId::new("home.lab.main").unwrap(),
            task: HeldTaskId::new("t_1").unwrap(),
            title: "Fix backups".into(),
            assignee: None,
            reason: "r".into(),
            last_error: None,
            since: 1,
            resume: String::new(),
            resumable: false,
            ask,
            answer: None,
            state: HeldTaskState::Held,
            revision: 3,
        }
    }

    #[test]
    fn an_answer_reads_on_its_own_and_names_its_task() {
        let asked = card(Some(ask(&["Keep paused", "Allow one fix"], Some(1))));
        let choice = HeldTaskAnswer::Choice { index: 1 }.message(&asked).unwrap();
        assert_eq!(
            choice.text,
            "About held task t_1 \"Fix backups\": Allow one more hour to fix Hermes backups?\nMy answer: Allow one fix"
        );
        assert_eq!(choice.answer, "Allow one fix");

        let text = HeldTaskAnswer::Text {
            text: "  Allow it,\nbut only tests.  ".into(),
        }
        .message(&asked)
        .unwrap();
        assert!(
            text.text
                .ends_with("\nMy answer: Allow it,\nbut only tests.")
        );
        assert_eq!(text.answer, "Allow it,");

        let unasked = card(None);
        let look = HeldTaskAnswer::Agent.message(&unasked).unwrap();
        assert_eq!(
            look.text,
            "About held task t_1 \"Fix backups\": look into it and tell me what you need from me."
        );
        assert_eq!(look.answer, ASKED_THE_AGENT);
        let typed = HeldTaskAnswer::Text { text: "Go".into() }
            .message(&unasked)
            .unwrap();
        assert_eq!(
            typed.text,
            "About held task t_1 \"Fix backups\"\nMy answer: Go"
        );
    }

    #[test]
    fn an_answer_that_does_not_fit_its_card_is_refused() {
        let asked = card(Some(ask(&["A"], None)));
        assert!(HeldTaskAnswer::Choice { index: 1 }.message(&asked).is_err());
        assert!(
            HeldTaskAnswer::Choice { index: 0 }
                .message(&card(None))
                .is_err()
        );
        for bad in [
            " \n ".to_owned(),
            "a".repeat(MAX_ANSWER_TEXT_CHARS + 1),
            "yes\u{202E}".to_owned(),
            "yes\rno".to_owned(),
        ] {
            assert!(
                HeldTaskAnswer::Text { text: bad.clone() }
                    .message(&asked)
                    .is_err(),
                "{bad:?}"
            );
        }
        assert!(
            HeldTaskAnswer::Text {
                text: "a".repeat(MAX_ANSWER_TEXT_CHARS)
            }
            .message(&asked)
            .is_ok()
        );
    }

    #[test]
    fn the_ask_and_the_answer_round_trip_on_each_leg() {
        let snapshot = Envelope::new(
            MessageId::new("h1").unwrap(),
            FromPlugin::HeldTasks {
                tasks: vec![HeldTask {
                    ask: Some(HeldTaskAsk {
                        settled: true,
                        ..ask(&["A", "B"], Some(0))
                    }),
                    ..task("t_1")
                }],
            },
        );
        let line = serde_json::to_vec(&snapshot).unwrap();
        assert_eq!(decode_from_plugin(&line).unwrap(), snapshot);
        let json: serde_json::Value = serde_json::from_slice(&line).unwrap();
        assert_eq!(json["tasks"][0]["ask"]["settled"], true);
        assert_eq!(json["tasks"][0]["ask"]["recommended"], 0);
        // `settled` is a JSON boolean, and absent reads as false.
        let mut bad = json.clone();
        bad["tasks"][0]["ask"]["settled"] = "true".into();
        assert!(decode_from_plugin(bad.to_string().as_bytes()).is_err());
        let mut absent = json;
        absent["tasks"][0]["ask"]
            .as_object_mut()
            .unwrap()
            .remove("settled");
        let FromPlugin::HeldTasks { tasks } = decode_from_plugin(absent.to_string().as_bytes())
            .unwrap()
            .body
        else {
            panic!("a list");
        };
        assert!(!tasks[0].ask.as_ref().unwrap().settled);

        let answered = HeldTaskInfo {
            answer: Some("A".into()),
            state: HeldTaskState::Answered,
            ..card(Some(ask(&["A", "B"], Some(0))))
        };
        let frame = Envelope::new(
            MessageId::new("b1").unwrap(),
            ToDevice::HeldTask {
                held_task: answered,
            },
        );
        let bytes = serde_json::to_vec(&frame).unwrap();
        assert_eq!(decode_to_device(&bytes).unwrap(), frame);
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["held_task"]["state"], "answered");
        assert!(json["held_task"]["ask"].get("settled").is_none());

        for answer in [
            HeldTaskAnswer::Choice { index: 1 },
            HeldTaskAnswer::Text { text: "Go".into() },
            HeldTaskAnswer::Agent,
        ] {
            let request = Envelope::new(
                MessageId::new("a1").unwrap(),
                FromDevice::HeldTaskAnswer {
                    agent: "lab/main".into(),
                    task: HeldTaskId::new("t_1").unwrap(),
                    revision: 3,
                    answer,
                },
            );
            let bytes = serde_json::to_vec(&request).unwrap();
            assert_eq!(decode_from_device(&bytes).unwrap(), request);
        }
        let agent = br#"{"v":1,"id":"a","type":"held_task.answer","agent":"lab/main","task":"t_1","revision":3,"answer":{"kind":"agent"}}"#;
        assert!(decode_from_device(agent).is_ok());
        // An answer names the card's revision and a known kind.
        let bad: [&[u8]; 3] = [
            br#"{"v":1,"id":"a","type":"held_task.answer","agent":"lab/main","task":"t_1","answer":{"kind":"agent"}}"#,
            br#"{"v":1,"id":"a","type":"held_task.answer","agent":"lab/main","task":"t_1","revision":3,"answer":{"kind":"maybe"}}"#,
            br#"{"v":1,"id":"a","type":"held_task.answer","agent":"lab/main","task":"t_1","revision":3,"answer":{"kind":"choice"}}"#,
        ];
        for bad in bad {
            assert!(decode_from_device(bad).is_err());
        }
    }
}
