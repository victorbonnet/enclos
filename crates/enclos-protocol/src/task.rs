//! Tasks and agent activity: work an agent does outside a conversation's
//! answer, and what it is doing right now, as its runtime reports them
//! (`docs/protocol.md`, Tasks and agent activity; ADR 0068, proposed).
//!
//! Neither carries authority. Every field comes from the sandbox, so the
//! bridge cleans and cuts it itself ([`Task::cleaned`],
//! [`Activity::cleaned`]) rather than rely on the plugin's.

use serde::{Deserialize, Serialize};

use crate::ConversationId;

/// The most characters of a task's title the bridge keeps.
pub const MAX_TITLE_CHARS: usize = 120;
/// The most characters of a task's summary the bridge keeps.
pub const MAX_SUMMARY_CHARS: usize = 500;
/// The most tasks a `tasks` list carries, and the bridge keeps per sandbox.
pub const MAX_TASKS: usize = 100;
/// How long the bridge keeps a task after it saw it end, in seconds.
pub const ENDED_RETENTION_SECS: i64 = 3 * 24 * 3600;
/// The most entries of an `agent.activity`.
pub const MAX_DOING: usize = 16;

/// Where a task is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskState {
    Queued,
    Running,
    /// It waits for someone: a person, or another task.
    Blocked,
    Done,
    Failed,
    Cancelled,
}

impl TaskState {
    /// Whether the task has ended: done, failed or cancelled.
    pub fn ended(self) -> bool {
        matches!(self, Self::Done | Self::Failed | Self::Cancelled)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Running => "running",
            Self::Blocked => "blocked",
            Self::Done => "done",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }
}

/// A task, as the assignee's plugin reports it and the bridge passes it on.
///
/// On the plugin leg `assignee` and `asked_by` are agent names in the
/// runtime (`engineer`); on the device leg the bridge makes them
/// `<sandbox>/<agent>`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Task {
    /// The runtime's id, unique in the sandbox.
    pub id: String,
    pub title: String,
    pub assignee: String,
    /// The agent that asked for it, as the runtime claims it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asked_by: Option<String>,
    /// Where it was asked for, when the runtime knows.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conversation: Option<ConversationId>,
    pub state: TaskState,
    /// When it entered its current state, in seconds since the Unix epoch.
    pub since: i64,
    /// A short result, once it has ended.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
}

/// Why the bridge refuses a task.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TaskError {
    #[error("a task's id is empty, longer than 128 bytes, or holds a hidden character")]
    Id,
    #[error("a task's title is blank")]
    Title,
}

/// `text` on one line, without hidden characters, trimmed and cut to
/// `chars` characters: what a person reads of a field from the sandbox.
pub fn one_line(text: &str, chars: usize) -> String {
    let flat: String = text
        .chars()
        .map(|c| match c {
            '\n' | '\r' | '\u{2028}' | '\u{2029}' | '\u{85}' | '\u{0B}' | '\u{0C}' | '\t' => ' ',
            c => c,
        })
        .collect();
    let visible = crate::visible::stripped(&flat, false);
    let mut out = String::new();
    let mut space = false;
    for c in visible.trim().chars() {
        if c == ' ' {
            space = true;
            continue;
        }
        if space && !out.is_empty() {
            out.push(' ');
        }
        space = false;
        out.push(c);
    }
    out.chars()
        .take(chars)
        .collect::<String>()
        .trim_end()
        .to_owned()
}

/// A name the sandbox claims (`asked_by`), cleaned to the id rule: one
/// line, no hidden character, at most 128 bytes; `None` when nothing is left.
fn name(text: &str) -> Option<String> {
    let mut out = one_line(text, crate::ids::MAX_ID_BYTES);
    while out.len() > crate::ids::MAX_ID_BYTES {
        out.pop();
    }
    (!out.is_empty()).then_some(out)
}

impl Task {
    /// The task as the bridge keeps it: its text cleaned and cut, its id
    /// checked by the routine id rule. `now` bounds `since`.
    pub fn cleaned(self, now: i64) -> Result<Task, TaskError> {
        if !crate::routine::valid_id(&self.id) {
            return Err(TaskError::Id);
        }
        let title = one_line(&self.title, MAX_TITLE_CHARS);
        if title.is_empty() {
            return Err(TaskError::Title);
        }
        Ok(Task {
            title,
            asked_by: self.asked_by.as_deref().and_then(name),
            summary: self
                .summary
                .as_deref()
                .map(|s| one_line(s, MAX_SUMMARY_CHARS))
                .filter(|s| !s.is_empty()),
            since: self.since.clamp(0, now.max(0)),
            ..self
        })
    }
}

/// One thing an agent is doing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Doing {
    /// Working on an answer in this conversation.
    Answering { conversation: ConversationId },
    /// One of its routines runs, by the runtime's id.
    Routine { routine: String },
    /// It works on this task, by the runtime's id.
    Task { task: String },
    /// A kind a later version added: left out.
    #[serde(other)]
    Unknown,
}

/// What an agent is doing, whole: empty when it is idle.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Activity {
    #[serde(default)]
    pub doing: Vec<Doing>,
    /// When this list began, in seconds since the Unix epoch.
    #[serde(default)]
    pub since: i64,
}

impl Activity {
    /// The activity as the bridge keeps it: unknown kinds and ids that
    /// break the routine id rule left out, at most [`MAX_DOING`] entries
    /// without repeats, `since` no later than `now`. `mine` tells whether
    /// a conversation is the agent's own.
    pub fn cleaned(self, now: i64, mine: impl Fn(&ConversationId) -> bool) -> Activity {
        let mut doing: Vec<Doing> = Vec::new();
        for entry in self.doing {
            let keep = match &entry {
                Doing::Answering { conversation } => mine(conversation),
                Doing::Routine { routine: id } | Doing::Task { task: id } => {
                    crate::routine::valid_id(id)
                }
                Doing::Unknown => false,
            };
            if keep && !doing.contains(&entry) && doing.len() < MAX_DOING {
                doing.push(entry);
            }
        }
        Activity {
            since: if doing.is_empty() {
                0
            } else {
                self.since.clamp(0, now.max(0))
            },
            doing,
        }
    }

    /// Whether the agent is doing nothing.
    pub fn idle(&self) -> bool {
        self.doing.is_empty()
    }

    /// What `person` may see of it: everything for the host's person, the
    /// answering in their own conversations for anyone else.
    pub fn for_person(&self, host: bool, owns: impl Fn(&ConversationId) -> bool) -> Activity {
        if host {
            return self.clone();
        }
        let doing: Vec<Doing> = self
            .doing
            .iter()
            .filter(|d| matches!(d, Doing::Answering { conversation } if owns(conversation)))
            .cloned()
            .collect();
        Activity {
            since: if doing.is_empty() { 0 } else { self.since },
            doing,
        }
    }

    /// The kinds it is doing, once each, in a fixed order: what `enclos
    /// status` prints.
    pub fn kinds(&self) -> Vec<&'static str> {
        ["answering", "routine", "task"]
            .into_iter()
            .filter(|kind| {
                self.doing.iter().any(|d| {
                    matches!(
                        (d, *kind),
                        (Doing::Answering { .. }, "answering")
                            | (Doing::Routine { .. }, "routine")
                            | (Doing::Task { .. }, "task")
                    )
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn task(id: &str, title: &str) -> Task {
        Task {
            id: id.into(),
            title: title.into(),
            assignee: "engineer".into(),
            asked_by: Some("lead".into()),
            conversation: None,
            state: TaskState::Running,
            since: 100,
            summary: None,
        }
    }

    #[test]
    fn a_task_round_trips_with_its_optional_fields_left_out() {
        let t = task("t_1", "Fix the login page");
        let json = serde_json::to_string(&t).unwrap();
        assert_eq!(
            json,
            r#"{"id":"t_1","title":"Fix the login page","assignee":"engineer","asked_by":"lead","state":"running","since":100}"#
        );
        assert_eq!(serde_json::from_str::<Task>(&json).unwrap(), t);
    }

    #[test]
    fn a_state_outside_the_set_does_not_decode() {
        let json = r#"{"id":"t","title":"x","assignee":"a","state":"archived","since":0}"#;
        assert!(serde_json::from_str::<Task>(json).is_err());
    }

    #[test]
    fn cleaning_puts_text_on_one_line_without_hidden_characters_and_cuts_it() {
        let mut t = task("t_1", "Fix\nthe\u{202E} login\u{200B}  page");
        t.summary = Some("x".repeat(2000));
        t.asked_by = Some("le\u{2066}ad\r\n".into());
        t.since = i64::MAX;
        let c = t.cleaned(1_000).unwrap();
        assert_eq!(c.title, "Fix the login page");
        assert_eq!(c.summary.unwrap().chars().count(), MAX_SUMMARY_CHARS);
        assert_eq!(c.asked_by.as_deref(), Some("lead"));
        assert_eq!(c.since, 1_000);
        let long = task("t", &"é".repeat(500)).cleaned(0).unwrap();
        assert_eq!(long.title.chars().count(), MAX_TITLE_CHARS);
    }

    #[test]
    fn a_blank_title_or_a_bad_id_is_refused() {
        assert_eq!(task("t", " \u{200B}\n").cleaned(0), Err(TaskError::Title));
        assert_eq!(task("", "x").cleaned(0), Err(TaskError::Id));
        assert_eq!(task("t\u{202E}", "x").cleaned(0), Err(TaskError::Id));
        assert_eq!(task(&"t".repeat(129), "x").cleaned(0), Err(TaskError::Id));
    }

    #[test]
    fn an_empty_summary_or_name_is_left_out() {
        let mut t = task("t", "x");
        t.summary = Some("\u{200B}".into());
        t.asked_by = Some(" ".into());
        let c = t.cleaned(0).unwrap();
        assert_eq!(c.summary, None);
        assert_eq!(c.asked_by, None);
    }

    fn conversation(id: &str) -> ConversationId {
        ConversationId::new(id).unwrap()
    }

    #[test]
    fn activity_round_trips_and_an_unknown_kind_reads_as_unknown() {
        let json = r#"{"doing":[{"kind":"answering","conversation":"c1"},{"kind":"task","task":"t1"},{"kind":"dreaming","about":"x"}],"since":5}"#;
        let a: Activity = serde_json::from_str(json).unwrap();
        assert_eq!(a.doing[2], Doing::Unknown);
        let cleaned = a.cleaned(10, |_| true);
        assert_eq!(
            serde_json::to_string(&cleaned).unwrap(),
            r#"{"doing":[{"kind":"answering","conversation":"c1"},{"kind":"task","task":"t1"}],"since":5}"#
        );
    }

    #[test]
    fn cleaning_activity_keeps_the_agents_own_conversations_and_valid_ids_only() {
        let a = Activity {
            doing: vec![
                Doing::Answering {
                    conversation: conversation("mine"),
                },
                Doing::Answering {
                    conversation: conversation("theirs"),
                },
                Doing::Routine {
                    routine: "r\u{202E}".into(),
                },
                Doing::Task { task: "t1".into() },
                Doing::Task { task: "t1".into() },
            ],
            since: 99,
        };
        let c = a.cleaned(50, |c| c.as_str() == "mine");
        assert_eq!(
            c.doing,
            vec![
                Doing::Answering {
                    conversation: conversation("mine")
                },
                Doing::Task { task: "t1".into() }
            ]
        );
        assert_eq!(c.since, 50);
        let many = Activity {
            doing: (0..40)
                .map(|i| Doing::Task {
                    task: format!("t{i}"),
                })
                .collect(),
            since: 1,
        };
        assert_eq!(many.cleaned(9, |_| true).doing.len(), MAX_DOING);
        assert_eq!(
            Activity {
                doing: vec![],
                since: 7
            }
            .cleaned(9, |_| true)
            .since,
            0
        );
    }

    #[test]
    fn another_person_sees_only_answering_in_their_own_conversations() {
        let a = Activity {
            doing: vec![
                Doing::Answering {
                    conversation: conversation("theirs"),
                },
                Doing::Answering {
                    conversation: conversation("hosts"),
                },
                Doing::Task { task: "t1".into() },
            ],
            since: 3,
        };
        let seen = a.for_person(false, |c| c.as_str() == "theirs");
        assert_eq!(
            seen.doing,
            vec![Doing::Answering {
                conversation: conversation("theirs")
            }]
        );
        assert!(a.for_person(false, |_| false).idle());
        assert_eq!(a.for_person(true, |_| false), a);
        assert_eq!(a.kinds(), vec!["answering", "task"]);
    }

    #[test]
    fn the_plugin_leg_messages_decode() {
        use crate::plugin::{FromPlugin, decode_from_plugin};
        let activity = br#"{"v":1,"type":"agent.activity","id":"m1","doing":[{"kind":"task","task":"t1"}],"since":4}"#;
        assert_eq!(
            decode_from_plugin(activity).unwrap().body,
            FromPlugin::Activity(Activity {
                doing: vec![Doing::Task { task: "t1".into() }],
                since: 4
            })
        );
        let idle = br#"{"v":1,"type":"agent.activity","id":"m2","doing":[]}"#;
        assert_eq!(
            decode_from_plugin(idle).unwrap().body,
            FromPlugin::Activity(Activity::default())
        );
        let update = br#"{"v":1,"type":"task.update","id":"m3","task":{"id":"t1","title":"x","assignee":"engineer","state":"queued","since":1}}"#;
        assert!(matches!(
            decode_from_plugin(update).unwrap().body,
            FromPlugin::TaskUpdate { task } if task.state == TaskState::Queued
        ));
        let list = br#"{"v":1,"type":"tasks","id":"m4","tasks":[]}"#;
        assert_eq!(
            decode_from_plugin(list).unwrap().body,
            FromPlugin::Tasks { tasks: vec![] }
        );
        let hello = br#"{"v":1,"type":"hello","id":"m5","runtime":"hermes","agent":"main","capabilities":["activity","tasks"]}"#;
        assert!(matches!(
            decode_from_plugin(hello).unwrap().body,
            FromPlugin::Hello { capabilities, .. }
                if capabilities == [crate::plugin::Capability::Activity, crate::plugin::Capability::Tasks]
        ));
    }

    #[test]
    fn the_device_leg_messages_round_trip() {
        use crate::device::{ToDevice, decode_to_device};
        use crate::{Envelope, MessageId, encode_line};
        let mut t = task("t1", "Fix it");
        t.assignee = "lab/engineer".into();
        for body in [
            ToDevice::AgentActivity {
                agent: "lab/engineer".into(),
                activity: Activity {
                    doing: vec![Doing::Task { task: "t1".into() }],
                    since: 2,
                },
            },
            ToDevice::Task { task: t },
            ToDevice::TaskRemoved {
                agent: "lab/engineer".into(),
                task: "t1".into(),
            },
        ] {
            let message = Envelope {
                v: 1,
                id: MessageId::new("d1").unwrap(),
                body: body.clone(),
            };
            let line = encode_line(&message);
            assert_eq!(
                decode_to_device(&line[..line.len() - 1]).unwrap().body,
                body
            );
        }
    }
}
