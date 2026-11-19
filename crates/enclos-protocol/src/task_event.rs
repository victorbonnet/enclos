//! Task events (ADR 0071, proposed; `docs/protocol.md`, Task events): a
//! change of a task that its runtime announces to a conversation (Hermes's
//! kanban notifier pings the conversation that asked for the task). The
//! plugin sends it as a `message.out` of `kind: "task_event"` that keeps
//! the runtime's text, and this, read from the runtime's state: a device
//! draws it as one line about the task, never as the agent talking.
//!
//! It carries no authority: every field comes from the sandbox, so the
//! bridge cleans and cuts it itself ([`TaskEvent::cleaned`]).

use serde::{Deserialize, Deserializer, Serialize};

use crate::task::{MAX_TITLE_CHARS, TaskState, one_line};

/// What happened to the task.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskEventKind {
    /// It stopped for someone: a person, or the agent that asked for it.
    Blocked,
    /// Its runtime stopped retrying it.
    GaveUp,
    /// Its worker stopped unexpectedly; the runtime retries it.
    Crashed,
    /// It ran past its time limit; the runtime retries it.
    TimedOut,
    Done,
    /// It is ready for review.
    Review,
    /// A review asked for changes.
    ChangesRequested,
    /// The runtime sent it to triage (Hermes's loop breaker, after repeated
    /// blocks).
    Triage,
    /// Another change of its status; also what a receiver reads for a kind
    /// a later version adds.
    #[serde(other)]
    Changed,
}

/// A change of a task, as the plugin read it from its runtime's state.
///
/// On the plugin leg `assignee` is the agent's name in its runtime
/// (`engineer`); on the device leg the bridge makes it `<sandbox>/<agent>`,
/// as a [`crate::task::Task`]'s.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskEvent {
    /// The runtime's id of the task, as a `task` and `task.get` name it.
    pub task: String,
    pub title: String,
    /// The agent doing it, when it has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assignee: Option<String>,
    pub event: TaskEventKind,
    /// Where the task is now, when the runtime says; a state the receiver
    /// does not know reads as none.
    #[serde(
        default,
        deserialize_with = "lenient_state",
        skip_serializing_if = "Option::is_none"
    )]
    pub state: Option<TaskState>,
}

fn lenient_state<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<TaskState>, D::Error> {
    let value = Option::<serde_json::Value>::deserialize(deserializer)?;
    Ok(value.and_then(|v| serde_json::from_value(v).ok()))
}

/// Why the bridge does not take a task event: it keeps the message's text
/// as an ordinary `notify` instead.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TaskEventError {
    #[error("a task event's task id is empty, longer than 128 bytes, or holds a hidden character")]
    Task,
    #[error("a task event's title is blank")]
    Title,
}

impl TaskEvent {
    /// The event as the bridge keeps it and a device gets it: its task id
    /// checked by the routine id rule, its title on one line without hidden
    /// characters and cut to [`MAX_TITLE_CHARS`], and its assignee, a name
    /// in the runtime, written `<sandbox>/<agent>`, left out when it would
    /// not be a name a device takes.
    pub fn cleaned(self, sandbox: &str) -> Result<TaskEvent, TaskEventError> {
        if !crate::routine::valid_id(&self.task) {
            return Err(TaskEventError::Task);
        }
        let title = one_line(&self.title, MAX_TITLE_CHARS);
        if title.is_empty() {
            return Err(TaskEventError::Title);
        }
        let assignee = self
            .assignee
            .as_deref()
            .map(|a| one_line(a, crate::routine::MAX_ID_BYTES))
            .filter(|a| !a.is_empty() && !a.contains('/'))
            .map(|a| format!("{sandbox}/{a}"))
            .filter(|a| crate::routine::valid_id(a));
        Ok(TaskEvent {
            title,
            assignee,
            ..self
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event() -> TaskEvent {
        TaskEvent {
            task: "t_a09759c7".into(),
            title: "S2a".into(),
            assignee: Some("reviewer".into()),
            event: TaskEventKind::Triage,
            state: Some(TaskState::Queued),
        }
    }

    #[test]
    fn it_round_trips_with_its_optional_fields_left_out() {
        let json = serde_json::to_string(&event()).unwrap();
        assert_eq!(
            json,
            r#"{"task":"t_a09759c7","title":"S2a","assignee":"reviewer","event":"triage","state":"queued"}"#
        );
        assert_eq!(serde_json::from_str::<TaskEvent>(&json).unwrap(), event());
        let bare = TaskEvent {
            assignee: None,
            state: None,
            event: TaskEventKind::ChangesRequested,
            ..event()
        };
        let json = serde_json::to_string(&bare).unwrap();
        assert_eq!(
            json,
            r#"{"task":"t_a09759c7","title":"S2a","event":"changes_requested"}"#
        );
        assert_eq!(serde_json::from_str::<TaskEvent>(&json).unwrap(), bare);
    }

    #[test]
    fn a_kind_or_a_state_a_later_version_adds_reads_as_a_change_and_no_state() {
        let later: TaskEvent = serde_json::from_str(
            r#"{"task":"t","title":"x","event":"reopened","state":"archived"}"#,
        )
        .unwrap();
        assert_eq!((later.event, later.state), (TaskEventKind::Changed, None));
        let null: TaskEvent =
            serde_json::from_str(r#"{"task":"t","title":"x","event":"done","state":null}"#)
                .unwrap();
        assert_eq!(null.state, None);
    }

    #[test]
    fn every_kind_has_its_wire_name() {
        for (kind, name) in [
            (TaskEventKind::Blocked, "blocked"),
            (TaskEventKind::GaveUp, "gave_up"),
            (TaskEventKind::Crashed, "crashed"),
            (TaskEventKind::TimedOut, "timed_out"),
            (TaskEventKind::Done, "done"),
            (TaskEventKind::Review, "review"),
            (TaskEventKind::ChangesRequested, "changes_requested"),
            (TaskEventKind::Triage, "triage"),
            (TaskEventKind::Changed, "changed"),
        ] {
            assert_eq!(serde_json::to_value(kind).unwrap(), name);
            assert_eq!(
                serde_json::from_value::<TaskEventKind>(name.into()).unwrap(),
                kind
            );
        }
    }

    #[test]
    fn cleaning_names_the_assignee_in_its_sandbox_and_puts_the_title_on_one_line() {
        let mut e = event();
        e.title = "Fix\nthe\u{202E} login\u{200B}  page".into();
        let c = e.cleaned("lab").unwrap();
        assert_eq!(c.title, "Fix the login page");
        assert_eq!(c.assignee.as_deref(), Some("lab/reviewer"));
        let long = TaskEvent {
            title: "é".repeat(500),
            ..event()
        };
        assert_eq!(
            long.cleaned("lab").unwrap().title.chars().count(),
            MAX_TITLE_CHARS
        );
    }

    #[test]
    fn an_assignee_that_would_not_be_a_name_is_left_out() {
        for assignee in ["", " \u{200B}", "other/reviewer", &"a".repeat(200)] {
            let e = TaskEvent {
                assignee: Some(assignee.into()),
                ..event()
            };
            assert_eq!(e.cleaned("lab").unwrap().assignee, None, "{assignee:?}");
        }
    }

    #[test]
    fn a_bad_task_id_or_a_blank_title_is_refused() {
        for task in ["", "t\u{202E}", &"t".repeat(129)] {
            let e = TaskEvent {
                task: task.into(),
                ..event()
            };
            assert_eq!(e.cleaned("lab"), Err(TaskEventError::Task));
        }
        let e = TaskEvent {
            title: " \u{200B}\n".into(),
            ..event()
        };
        assert_eq!(e.cleaned("lab"), Err(TaskEventError::Title));
    }
}
