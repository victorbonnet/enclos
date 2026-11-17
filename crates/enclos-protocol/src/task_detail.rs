//! A task's detail: its body, the tasks it relates to, its comments and its
//! history, as the assignee's runtime holds them (`docs/protocol.md`, Task
//! details; issue #318). A device asks for it with `task.get` when a person
//! opens a task; the bridge passes it on and keeps none of it.
//!
//! It is reported, like a [`Task`](crate::task::Task): nothing here
//! changes the task. Every field comes from the sandbox, so the bridge
//! cleans and cuts it itself ([`TaskDetail::cleaned`]).

use serde::{Deserialize, Serialize};

use crate::task::{TaskState, one_line};

/// The most characters of a task's body a `task.detail` carries.
pub const MAX_BODY_CHARS: usize = 4_000;
/// The most comments a `task.detail` carries: the newest.
pub const MAX_COMMENTS: usize = 20;
/// The most characters of one comment's text.
pub const MAX_COMMENT_CHARS: usize = 1_000;
/// The most characters of a comment's author, as the runtime names it.
pub const MAX_AUTHOR_CHARS: usize = 64;
/// The most related tasks a `task.detail` carries.
pub const MAX_RELATED: usize = 20;
/// The most entries of a task's history a `task.detail` carries: the newest.
pub const MAX_HISTORY: usize = 30;
/// The most characters of a history entry's text.
pub const MAX_HISTORY_TEXT_CHARS: usize = 300;
/// The most bytes a [`TaskDetail`] takes once encoded: with its envelope,
/// well within one Noise transport message (65,519 bytes of plaintext).
pub const MAX_DETAIL_BYTES: usize = 56 * 1024;

/// What the runtime holds of a task beyond what [`Task`](crate::task::Task)
/// says.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct TaskDetail {
    /// What the task asks, in full: lines kept.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    /// The tasks it waits for and the tasks that wait for it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub related: Vec<RelatedTask>,
    /// The newest comments, oldest first.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub comments: Vec<TaskComment>,
    /// How many comments the task has, `comments` being the newest of them.
    #[serde(default)]
    pub comments_total: u32,
    /// What happened to it, oldest first: the newest entries.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub history: Vec<HistoryEntry>,
}

/// How a related task stands to this one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Relation {
    /// This task waits for it.
    Parent,
    /// It waits for this task.
    Child,
}

/// A task this one waits for, or that waits for it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelatedTask {
    /// The runtime's id.
    pub id: String,
    pub title: String,
    pub relation: Relation,
    /// Where it is; absent when the runtime says nothing the protocol
    /// knows (Hermes: archived).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<TaskState>,
    /// The agent doing it: its name in the runtime on the plugin leg,
    /// `sandbox/agent` on the device leg.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assignee: Option<String>,
}

/// A comment on the task, by an agent or a person, as the runtime keeps it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskComment {
    /// Who wrote it, as the runtime names them (a Hermes profile).
    pub author: String,
    /// On the device leg, `sandbox/agent` when `author` names an agent the
    /// host serves: the app shows that agent's name and photo.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<String>,
    /// When, in seconds since the Unix epoch.
    pub time: i64,
    /// What it says: lines kept.
    pub text: String,
}

/// What a history entry records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoryKind {
    /// Someone asked for it (`by`).
    Created,
    /// An attempt at it: from `time` until `until`, with its `outcome`
    /// once it ended, and its summary or error as `text`.
    Attempt,
    /// It stopped to wait for someone; `text` says why.
    Blocked,
    /// It may go on.
    Unblocked,
    /// Its work waits for a review.
    Review,
    /// It ended, done.
    Done,
    /// A kind a later version added: left out.
    #[serde(other)]
    Unknown,
}

/// How an attempt ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Completed,
    /// It stopped to wait for someone.
    Blocked,
    Crashed,
    TimedOut,
    /// The runtime stopped retrying it.
    GaveUp,
    /// It could not start.
    Failed,
    /// The runtime took it back, to run again.
    Stopped,
    /// An end a later version names.
    #[serde(other)]
    Other,
}

/// One thing that happened to the task.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryEntry {
    pub kind: HistoryKind,
    /// When, in seconds since the Unix epoch.
    pub time: i64,
    /// For an attempt that ended: when.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until: Option<i64>,
    /// For an attempt that ended: how.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<Outcome>,
    /// The agent that did it: its name in the runtime on the plugin leg,
    /// `sandbox/agent` on the device leg.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub by: Option<String>,
    /// One line about it: an attempt's summary or error, why it blocked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
}

/// `text` without hidden characters, its lines kept: line and paragraph
/// separators made newlines, tabs spaces, the ends of lines trimmed, blank
/// lines in a row made one, and cut to `chars` characters. What a person
/// reads of a longer text from the sandbox: a task's body, a comment.
pub fn paragraphs(text: &str, chars: usize) -> String {
    let unified: String = text
        .replace("\r\n", "\n")
        .chars()
        .map(|c| match c {
            '\r' | '\u{2028}' | '\u{2029}' | '\u{85}' | '\u{0B}' | '\u{0C}' => '\n',
            '\t' => ' ',
            c => c,
        })
        .collect();
    let visible = crate::visible::stripped(&unified, true);
    let mut out = String::new();
    let mut blank = false;
    for line in visible.split('\n') {
        let line = line.trim_end();
        if line.trim().is_empty() {
            blank = true;
            continue;
        }
        if !out.is_empty() {
            out.push_str(if blank { "\n\n" } else { "\n" });
        }
        blank = false;
        out.push_str(line);
    }
    out.chars()
        .take(chars)
        .collect::<String>()
        .trim_end()
        .to_owned()
}

/// A runtime's name for an agent (`engineer`) written `sandbox/engineer`:
/// one line, nothing hidden, no `/` of its own, and within the id rule's
/// 128 bytes; `None` otherwise. The rule of a task's `asked_by`.
pub fn address(sandbox: &str, name: &str) -> Option<String> {
    let name = one_line(name, crate::ids::MAX_ID_BYTES);
    if name.is_empty() || name.contains('/') {
        return None;
    }
    let address = format!("{sandbox}/{name}");
    (address.len() <= crate::ids::MAX_ID_BYTES).then_some(address)
}

impl TaskDetail {
    /// The detail as the bridge passes it to a device: its text cleaned and
    /// cut, at most [`MAX_RELATED`] related tasks with ids by the routine id
    /// rule, the newest [`MAX_COMMENTS`] comments and [`MAX_HISTORY`]
    /// entries, entries of a kind it does not know left out, names made
    /// `sandbox/agent` (a comment's `agent` only when `serves` says the host
    /// serves that agent), times no later than `now`, and the whole within
    /// [`MAX_DETAIL_BYTES`], the oldest history and comments given up first.
    pub fn cleaned(self, now: i64, sandbox: &str, serves: impl Fn(&str) -> bool) -> TaskDetail {
        let now = now.max(0);
        let at = |t: i64| t.clamp(0, now);
        let body = self
            .body
            .as_deref()
            .map(|b| paragraphs(b, MAX_BODY_CHARS))
            .filter(|b| !b.is_empty());
        let related: Vec<RelatedTask> = self
            .related
            .into_iter()
            .filter(|r| crate::routine::valid_id(&r.id))
            .filter_map(|r| {
                let title = one_line(&r.title, crate::task::MAX_TITLE_CHARS);
                (!title.is_empty()).then(|| RelatedTask {
                    title,
                    assignee: r.assignee.as_deref().and_then(|a| address(sandbox, a)),
                    ..r
                })
            })
            .take(MAX_RELATED)
            .collect();
        let mut comments: Vec<TaskComment> = self
            .comments
            .into_iter()
            .filter_map(|c| {
                let text = paragraphs(&c.text, MAX_COMMENT_CHARS);
                let author = one_line(&c.author, MAX_AUTHOR_CHARS);
                if text.is_empty() || author.is_empty() {
                    return None;
                }
                let agent = address(sandbox, &author).filter(|a| serves(a));
                Some(TaskComment {
                    author,
                    agent,
                    time: at(c.time),
                    text,
                })
            })
            .collect();
        let received = comments.len() as u32;
        let extra = comments.len().saturating_sub(MAX_COMMENTS);
        comments.drain(..extra);
        let mut history: Vec<HistoryEntry> = self
            .history
            .into_iter()
            .filter(|e| e.kind != HistoryKind::Unknown)
            .map(|e| {
                let time = at(e.time);
                HistoryEntry {
                    time,
                    until: e.until.map(|u| at(u).max(time)),
                    by: e.by.as_deref().and_then(|b| address(sandbox, b)),
                    text: e
                        .text
                        .as_deref()
                        .map(|t| one_line(t, MAX_HISTORY_TEXT_CHARS))
                        .filter(|t| !t.is_empty()),
                    ..e
                }
            })
            .collect();
        let extra = history.len().saturating_sub(MAX_HISTORY);
        history.drain(..extra);
        let comments_total = self.comments_total.max(received);
        let mut detail = TaskDetail {
            body,
            related,
            comments,
            comments_total,
            history,
        };
        detail.fit(MAX_DETAIL_BYTES);
        detail
    }

    /// Gives up the oldest history entries, then the oldest comments, then
    /// related tasks, then the body's end, until it encodes within `bytes`.
    fn fit(&mut self, bytes: usize) {
        let size = |d: &TaskDetail| serde_json::to_vec(d).map(|v| v.len()).unwrap_or(usize::MAX);
        while size(self) > bytes {
            if !self.history.is_empty() {
                self.history.remove(0);
            } else if !self.comments.is_empty() {
                self.comments.remove(0);
            } else if self.related.pop().is_some() {
            } else if let Some(body) = &mut self.body {
                let keep = body.chars().count() / 2;
                *body = body
                    .chars()
                    .take(keep)
                    .collect::<String>()
                    .trim_end()
                    .to_owned();
                if body.is_empty() {
                    self.body = None;
                }
            } else {
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn comment(author: &str, text: &str, time: i64) -> TaskComment {
        TaskComment {
            author: author.into(),
            agent: None,
            time,
            text: text.into(),
        }
    }

    fn entry(kind: HistoryKind, time: i64) -> HistoryEntry {
        HistoryEntry {
            kind,
            time,
            until: None,
            outcome: None,
            by: None,
            text: None,
        }
    }

    #[test]
    fn paragraphs_keep_lines_and_drop_what_hides() {
        assert_eq!(
            paragraphs("One\r\ntwo\u{202E}\u{2028}\n\n\n\tthree  \n", 100),
            "One\ntwo\n\n three"
        );
        assert_eq!(paragraphs("\n \u{200B}\n", 100), "");
        assert_eq!(paragraphs(&"é".repeat(50), 10).chars().count(), 10);
    }

    #[test]
    fn an_address_follows_the_asked_by_rule() {
        assert_eq!(address("lab", "engineer").as_deref(), Some("lab/engineer"));
        assert_eq!(address("lab", "a/b"), None);
        assert_eq!(address("lab", " \u{200B}"), None);
        assert_eq!(address("lab", &"x".repeat(125)), None);
    }

    #[test]
    fn a_detail_round_trips_with_its_empty_parts_left_out() {
        let empty = TaskDetail::default();
        assert_eq!(
            serde_json::to_string(&empty).unwrap(),
            r#"{"comments_total":0}"#
        );
        let json = r#"{"body":"Fix it\nthen test","related":[{"id":"t_2","title":"Review","relation":"child","state":"queued","assignee":"lab/reviewer"}],"comments":[{"author":"lead","agent":"lab/lead","time":5,"text":"Go"}],"comments_total":3,"history":[{"kind":"attempt","time":6,"until":9,"outcome":"timed_out","by":"lab/engineer","text":"no answer"}]}"#;
        let detail: TaskDetail = serde_json::from_str(json).unwrap();
        assert_eq!(serde_json::to_string(&detail).unwrap(), json);
    }

    #[test]
    fn an_unknown_kind_or_outcome_reads_without_failing() {
        let detail: TaskDetail = serde_json::from_str(
            r#"{"history":[{"kind":"teleported","time":1},{"kind":"attempt","time":2,"outcome":"vanished"}]}"#,
        )
        .unwrap();
        assert_eq!(detail.history[0].kind, HistoryKind::Unknown);
        assert_eq!(detail.history[1].outcome, Some(Outcome::Other));
        let cleaned = detail.cleaned(10, "lab", |_| false);
        assert_eq!(cleaned.history.len(), 1);
    }

    #[test]
    fn cleaning_cuts_and_names_what_the_sandbox_sent() {
        let detail = TaskDetail {
            body: Some(format!("Do\u{202E} it\n\n\n{}", "x".repeat(5_000))),
            related: vec![
                RelatedTask {
                    id: "t\u{202E}".into(),
                    title: "hidden id".into(),
                    relation: Relation::Parent,
                    state: None,
                    assignee: None,
                },
                RelatedTask {
                    id: "t_2".into(),
                    title: " \u{200B}".into(),
                    relation: Relation::Child,
                    state: None,
                    assignee: None,
                },
                RelatedTask {
                    id: "t_3".into(),
                    title: "Review\nit".into(),
                    relation: Relation::Child,
                    state: Some(TaskState::Queued),
                    assignee: Some("reviewer".into()),
                },
            ],
            comments: (0..25)
                .map(|i| {
                    comment(
                        if i % 2 == 0 { "lead" } else { "victor" },
                        &format!("c{i}"),
                        i,
                    )
                })
                .chain([comment("lead", "\u{200B}", 30), comment("", "orphan", 31)])
                .collect(),
            comments_total: 2,
            history: (0..40)
                .map(|_| HistoryEntry {
                    by: Some("engineer".into()),
                    until: Some(0),
                    text: Some("a\nb".into()),
                    ..entry(HistoryKind::Attempt, i64::MAX)
                })
                .collect(),
        };
        let c = detail.cleaned(100, "lab", |a| a == "lab/lead");
        let body = c.body.unwrap();
        assert!(body.starts_with("Do it\n\nxxx"));
        assert_eq!(body.chars().count(), MAX_BODY_CHARS);
        assert_eq!(c.related.len(), 1);
        assert_eq!(c.related[0].title, "Review it");
        assert_eq!(c.related[0].assignee.as_deref(), Some("lab/reviewer"));
        assert_eq!(c.comments.len(), MAX_COMMENTS);
        assert_eq!(c.comments.first().unwrap().text, "c5");
        // At least the 25 it sent, whatever it claimed.
        assert_eq!(c.comments_total, 25);
        let lead = c.comments.iter().find(|c| c.author == "lead").unwrap();
        assert_eq!(lead.agent.as_deref(), Some("lab/lead"));
        let person = c.comments.iter().find(|c| c.author == "victor").unwrap();
        assert_eq!(person.agent, None);
        assert_eq!(c.history.len(), MAX_HISTORY);
        let first = &c.history[0];
        assert_eq!((first.time, first.until), (100, Some(100)));
        assert_eq!(first.by.as_deref(), Some("lab/engineer"));
        assert_eq!(first.text.as_deref(), Some("a b"));
    }

    #[test]
    fn a_detail_too_large_for_a_frame_gives_up_its_oldest_parts_first() {
        // Four bytes a character: 20 comments of 1,000 are 80 KB alone.
        let wide = "𝕏".repeat(MAX_COMMENT_CHARS);
        let detail = TaskDetail {
            body: Some("𝕏".repeat(MAX_BODY_CHARS)),
            comments: (0..20).map(|i| comment("lead", &wide, i)).collect(),
            comments_total: 20,
            history: (0..30)
                .map(|i| HistoryEntry {
                    text: Some("𝕏".repeat(MAX_HISTORY_TEXT_CHARS)),
                    ..entry(HistoryKind::Blocked, i)
                })
                .collect(),
            ..Default::default()
        };
        let c = detail.cleaned(100, "lab", |_| true);
        assert!(serde_json::to_vec(&c).unwrap().len() <= MAX_DETAIL_BYTES);
        assert!(c.history.is_empty());
        assert!(!c.comments.is_empty() && c.comments.len() < 20);
        assert_eq!(c.comments.last().unwrap().time, 19);
        assert_eq!(c.comments_total, 20);
        assert_eq!(c.body.unwrap().chars().count(), MAX_BODY_CHARS);
    }
}
