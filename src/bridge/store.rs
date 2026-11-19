//! The bridge's conversations and messages, in its own SQLite database
//! beside enclos's state (`app.db`). Every conversation has an owner and
//! every message a person or the agent (ADR 0043, proposed), and `seq`
//! orders all of a host's messages, so a device catches up from one number
//! (`docs/protocol.md`, sync).

use std::path::Path;

use enclos_protocol::usage::{
    MAX_POINTS, MAX_SCOPED_SERIES, MAX_SERIES, SandboxTotal, UsageCost, UsagePoint, UsageSeries,
    UsageTokens, UsageTotal,
};
use rusqlite::{Connection, OptionalExtension, params};

#[path = "deletion_store.rs"]
mod deletion_store;
#[path = "forget_store.rs"]
mod forget_store;
pub use forget_store::{Forget, setup_home};
#[path = "held_task_store.rs"]
mod held_task_store;
pub use held_task_store::{HeldTaskChange, StoredHeldTask, held_text};
#[path = "question_store.rs"]
mod question_store;
#[path = "task_store.rs"]
mod task_store;
pub use question_store::{
    MAX_PENDING_APPROVALS_PER_AGENT, MAX_PENDING_APPROVALS_PER_CONVERSATION, MAX_PENDING_PER_AGENT,
    MAX_PENDING_PER_CONVERSATION, QuestionChange, QuestionStoreError, Settlement, StoredQuestion,
};
pub use task_store::{TaskChanges, TaskKey, bridge_runs, hold_live, live_path};

/// Who wrote a message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum From {
    Person(String),
    Agent,
    /// A member of a group, by its name in the group's sandbox.
    Member(String),
}

/// One stored message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub suggested_replies: Vec<String>,
    pub question: Option<enclos_protocol::QuestionId>,
    /// The held task this message is about: a card of its conversation's agent.
    pub held_task: Option<enclos_protocol::HeldTaskId>,
    pub seq: i64,
    pub id: String,
    pub conversation: String,
    pub from: From,
    pub text: String,
    /// `reply` or `notify` for the agent's; `message` for a person's.
    pub kind: String,
    /// When the bridge stored it, in seconds since the Unix epoch.
    pub at: i64,
}

/// The columns [`message_row`] reads, in its order.
const MESSAGE_COLUMNS: &str = "SELECT seq, id, conversation, person, text, kind, at, speaker, question, held_task, suggested_replies FROM messages";

fn message_row(row: &rusqlite::Row) -> rusqlite::Result<Message> {
    let person: Option<String> = row.get(3)?;
    let speaker: Option<String> = row.get(7)?;
    Ok(Message {
        suggested_replies: row
            .get::<_, Option<String>>(10)?
            .and_then(|s| serde_json::from_str::<Vec<String>>(&s).ok())
            .filter(|r| enclos_protocol::suggested_replies::validate(r))
            .unwrap_or_default(),
        held_task: row
            .get::<_, Option<String>>(9)?
            .map(|id| {
                enclos_protocol::HeldTaskId::new(id).map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(
                        9,
                        rusqlite::types::Type::Text,
                        Box::new(e),
                    )
                })
            })
            .transpose()?,
        question: row
            .get::<_, Option<String>>(8)?
            .map(|id| {
                enclos_protocol::QuestionId::new(id).map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(
                        8,
                        rusqlite::types::Type::Text,
                        Box::new(e),
                    )
                })
            })
            .transpose()?,
        seq: row.get(0)?,
        id: row.get(1)?,
        conversation: row.get(2)?,
        from: match (person, speaker) {
            (Some(p), _) => From::Person(p),
            (None, Some(m)) => From::Member(m),
            (None, None) => From::Agent,
        },
        text: row.get(4)?,
        kind: row.get(5)?,
        at: row.get(6)?,
    })
}

/// A conversation, with its name when it has one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Conversation {
    pub id: String,
    pub sandbox: String,
    pub agent: String,
    pub title: Option<String>,
    /// [`BY_AGENT`] or [`BY_PERSON`], when it has a name.
    pub titled_by: Option<String>,
    /// The `seq` of the last message its owner read, on any device.
    pub read: Option<i64>,
    /// Hidden from active lists until its owner explicitly restores it.
    pub archived: bool,
    /// Monotonic metadata order, independent of message `seq`.
    pub revision: u64,
}

fn conversation_row(row: &rusqlite::Row) -> rusqlite::Result<Conversation> {
    let revision: i64 = row.get(7)?;
    Ok(Conversation {
        id: row.get(0)?,
        sandbox: row.get(1)?,
        agent: row.get(2)?,
        title: row.get(3)?,
        titled_by: row.get(4)?,
        read: row.get(5)?,
        archived: row.get(6)?,
        revision: revision
            .try_into()
            .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(7, revision))?,
    })
}

/// A file of a message; its bytes are in the bridge's media folder, under its id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredAttachment {
    pub id: String,
    pub conversation: String,
    pub mime: String,
    pub name: String,
    pub size: i64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StoredAvatar {
    pub revision: i64,
    pub version: Option<String>,
    pub image: Option<Vec<u8>>,
}

/// A policy request with the last instant its lifecycle already handled,
/// in the network log's millisecond precision. This metadata stays on the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalHistory {
    pub approval: enclos_protocol::approval::Approval,
    pub through_ms: i64,
}

/// A conversation named by its runtime.
pub const BY_AGENT: &str = "agent";
/// A conversation named by its owner.
pub const BY_PERSON: &str = "person";

/// The id of agent `<sandbox>/<agent>`'s first Home conversation, where
/// what has no conversation of its own goes (ADR 0044). Fixed, so the
/// bridge and the runtime, which `runtime configure` tells, agree on it
/// without asking; without `:` or `/`, which runtimes put in their own
/// keys. An agent made again after it was forgotten gets another
/// ([`Store::home_of`], ADR 0067, proposed).
pub fn home_id(agent: &str) -> String {
    format!("home.{}", agent.replace('/', "."))
}

/// Whether conversation `id` is an agent's Home: a device's own ids are UUIDs.
pub fn is_home(id: &str) -> bool {
    id.starts_with("home.")
}

/// The longest name a conversation keeps, in characters.
pub const MAX_TITLE_CHARS: usize = 100;

/// A conversation's name as the bridge keeps it, whoever gave it: on one
/// line, without hidden characters ([`enclos_protocol::visible`]), and at
/// most [`MAX_TITLE_CHARS`]. The plugin's own cut runs in the sandbox, so
/// the bridge does not rely on it: a name sent to devices must fit one
/// Noise message, and must not read as another conversation's.
pub fn conversation_title(text: &str) -> String {
    let one_line: String = text
        .chars()
        .map(|c| if c.is_whitespace() { ' ' } else { c })
        .collect();
    let visible = enclos_protocol::visible::stripped(&one_line, false);
    let words: Vec<&str> = visible.split_whitespace().collect();
    visible_within(&words.join(" "), MAX_TITLE_CHARS)
}

/// The most characters of a message a push's preview holds
/// (`docs/protocol.md`, Notifications).
pub const MAX_PREVIEW_CHARS: usize = 120;

/// What a push's preview shows of `text`: one line, without hidden
/// characters, of at most [`MAX_PREVIEW_CHARS`]. The app takes the
/// markdown's marks out itself.
pub fn preview_text(text: &str) -> String {
    let one_line: String = text
        .chars()
        .map(|c| if c.is_whitespace() { ' ' } else { c })
        .collect();
    let visible = enclos_protocol::visible::stripped(&one_line, false);
    let words: Vec<&str> = visible.split_whitespace().collect();
    visible_within(&words.join(" "), MAX_PREVIEW_CHARS)
}

/// `text`, without hidden characters, cut to at most `max` characters and
/// trimmed: stripped again after each cut, since a cut can leave a joiner
/// last, where [`enclos_protocol::visible`] calls it hidden, until nothing
/// changes. What it returns is its own result again.
fn visible_within(text: &str, max: usize) -> String {
    let mut kept = enclos_protocol::visible::stripped(text, false)
        .trim()
        .to_owned();
    loop {
        let cut: String = kept.chars().take(max).collect();
        let again = enclos_protocol::visible::stripped(&cut, false)
            .trim()
            .to_owned();
        if again == kept {
            return kept;
        }
        kept = again;
    }
}

/// The longest media type an attachment keeps, in bytes: RFC 6838 bounds a
/// type and a subtype at 127 characters each.
pub const MAX_MIME_BYTES: usize = 255;

/// The longest name an attachment keeps, in characters.
pub const MAX_ATTACHMENT_NAME_CHARS: usize = 120;

/// An attachment's media type as the bridge keeps it, whoever gave it: a
/// plain `type/subtype` of at most [`MAX_MIME_BYTES`], in lower case, and
/// `application/octet-stream` for anything else. Its own result again.
pub fn attachment_mime(mime: &str) -> String {
    let plain = mime.len() <= MAX_MIME_BYTES
        && mime.split_once('/').is_some_and(|(t, s)| {
            !t.is_empty()
                && !s.is_empty()
                && mime
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || "/.+-".contains(c))
        });
    if plain {
        mime.to_ascii_lowercase()
    } else {
        "application/octet-stream".to_owned()
    }
}

/// An attachment's name as the bridge keeps it, whoever gave it: without
/// its folders and hidden characters, which would make a file read as
/// another type or another line on the artefact card, the viewer and the
/// Share sheet, and at most [`MAX_ATTACHMENT_NAME_CHARS`]; `fallback`, kept
/// the same way, when nothing is left, and `file` when nothing is left of
/// that either. Its own result again.
pub fn attachment_name(name: &str, fallback: &str) -> String {
    [name, fallback, "file"]
        .into_iter()
        .map(|n| {
            visible_within(
                n.rsplit(['/', '\\']).next().unwrap_or_default(),
                MAX_ATTACHMENT_NAME_CHARS,
            )
        })
        .find(|n| !n.is_empty())
        .unwrap_or_default()
}

pub struct Store {
    pub(super) db: Connection,
}

fn attachment_row(row: &rusqlite::Row) -> rusqlite::Result<StoredAttachment> {
    Ok(StoredAttachment {
        id: row.get(0)?,
        conversation: row.get(1)?,
        mime: row.get(2)?,
        name: row.get(3)?,
        size: row.get(4)?,
    })
}

/// A window's usage: each agent's total (`<sandbox>/<agent>`, sorted), and
/// the series of those that used the most.
pub type UsageWindow = (Vec<(String, UsageTotal)>, Vec<UsageSeries>);

/// The model and model provider a usage report names (issue #343), kept
/// with each hour's usage so that the bridge prices it. Either may be
/// unsaid.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Served<'a> {
    pub model: Option<&'a str>,
    pub provider: Option<&'a str>,
}

/// The most models, each with its model provider, one agent's usage keeps
/// apart in one hour of one conversation, or of its calls outside the app:
/// past them, a report counts under neither, so that what an agent reports
/// cannot grow the tables past this many rows an hour.
pub const MODELS_AN_HOUR: i64 = 8;

/// Which agents a usage window covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope<'a> {
    /// Every agent.
    Host,
    /// The agents of one sandbox.
    Sandbox(&'a str),
    /// One agent of one sandbox.
    Agent { sandbox: &'a str, agent: &'a str },
}

impl Scope<'_> {
    /// Whether it covers `agent`, named `<sandbox>/<agent>`.
    pub fn covers(&self, agent: &str) -> bool {
        match self {
            Scope::Host => true,
            Scope::Sandbox(sandbox) => agent.split_once('/').is_some_and(|(s, _)| s == *sandbox),
            Scope::Agent { sandbox, agent: a } => agent
                .split_once('/')
                .is_some_and(|(s, rest)| s == *sandbox && rest == *a),
        }
    }
}

/// What a usage window is of.
#[derive(Debug, Clone, Copy)]
pub struct WindowAsk<'a> {
    /// The person whose conversations count; every person's, for the
    /// host's own CLI.
    pub owner: Option<&'a str>,
    /// Unix seconds: from the hour that holds it.
    pub since: i64,
    /// Whether the agents' calls outside app conversations count too.
    pub outside: bool,
    /// A bucket in seconds and the asker's offset from UTC, for series.
    pub series: Option<(u32, i32)>,
    pub scope: Scope<'a>,
    /// Whether to give the scope's usage over time, every agent of it
    /// summed, with its cost: needs `series`.
    pub sum: bool,
}

/// A usage window, priced.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Window {
    /// Each agent's total and its cost, sorted by `<sandbox>/<agent>`.
    pub agents: Vec<(String, UsageTotal, UsageCost)>,
    /// Each sandbox's, sorted by name.
    pub sandboxes: Vec<SandboxTotal>,
    /// The series of the agents that used the most ([`MAX_SERIES`], or
    /// [`MAX_SCOPED_SERIES`] for a scope other than the host).
    pub series: Vec<UsageSeries>,
    /// With `sum`: the scope's buckets that saw a call, every agent summed,
    /// each with its cost, oldest first, all of them.
    pub sum: Vec<UsagePoint>,
}

/// One hour of one agent's usage of one model through one model provider.
struct HourRow {
    agent: String,
    hour: i64,
    model: String,
    provider: String,
    counts: UsageTotal,
}

/// A text column's value as a report named it: none when empty.
fn said(text: &str) -> Option<&str> {
    (!text.is_empty()).then_some(text)
}

/// The start of the bucket of `bucket` seconds that holds `hour`, for an
/// asker `offset` seconds from UTC: a day starts at its midnight, an hour at
/// the hour whatever the offset, as usage is kept by UTC hour.
fn bucket_of(hour: i64, bucket: i64, offset: i64) -> i64 {
    let offset = match bucket >= 86_400 {
        true => offset,
        false => 0,
    };
    (hour.saturating_mul(3600) + offset).div_euclid(bucket) * bucket - offset
}

/// Whether a bucket's tokens were counted at all: none when the runtime
/// counted no token, which is not 0.
fn point_tokens(b: &UsageTotal) -> Option<u64> {
    [
        b.tokens.input,
        b.tokens.output,
        b.tokens.cache_read,
        b.tokens.cache_write,
    ]
    .iter()
    .any(Option::is_some)
    .then(|| b.tokens.total())
}

/// How many days the agents' usage outside app conversations is kept: past
/// the longest window a device asks for (30 days), with a margin.
pub const AGENT_USAGE_DAYS: i64 = 35;

/// One usage bucket's counts, read from columns `at` on of `row`. A
/// negative one, which the table's checks refuse, is an error, never 0.
fn usage_row(row: &rusqlite::Row, at: usize) -> rusqlite::Result<UsageTotal> {
    let count = |i: usize| -> rusqlite::Result<Option<u64>> {
        row.get::<_, Option<i64>>(at + i)?
            .map(|n| {
                u64::try_from(n).map_err(|_| rusqlite::Error::IntegralValueOutOfRange(at + i, n))
            })
            .transpose()
    };
    Ok(UsageTotal {
        calls: count(0)?.unwrap_or(0),
        tokens: UsageTokens {
            input: count(1)?,
            output: count(2)?,
            cache_read: count(3)?,
            cache_write: count(4)?,
            reasoning: count(5)?,
        },
    })
}

/// The sum of two usage totals, each count stopping at the most it can hold.
fn plus(a: UsageTotal, b: UsageTotal) -> UsageTotal {
    UsageTotal {
        calls: a.calls.saturating_add(b.calls),
        tokens: a.tokens.plus(b.tokens),
    }
}

/// A conversation's usage total over all its buckets, read in `db` (a
/// connection or a transaction of one). Summed here, not in SQL, whose
/// `SUM` fails past the largest integer.
fn usage_in(db: &Connection, conversation: &str) -> rusqlite::Result<Option<UsageTotal>> {
    let mut query = db.prepare(
        "SELECT calls, input, output, cache_read, cache_write, reasoning
         FROM usage_hours WHERE conversation = ?1",
    )?;
    let rows = query.query_map(params![conversation], |row| usage_row(row, 0))?;
    let mut total = None;
    for row in rows {
        total = Some(plus(total.unwrap_or_default(), row?));
    }
    Ok(total)
}

/// Keeps each hour's usage by model and model provider too (issue #343),
/// so that the bridge prices it: each usage table is made again with both
/// in its key, its rows copied with neither said (`''`). Appended to the
/// released tables, as [`migrate_approval_cutoffs`] is, and in one
/// transaction that looks again, as another process opening the database
/// may have made the change meanwhile.
fn migrate_usage_models(db: &Connection) -> rusqlite::Result<()> {
    fn has_model(db: &Connection, table: &str) -> rusqlite::Result<bool> {
        db.query_row(
            &format!("SELECT COUNT(*) FROM pragma_table_info('{table}') WHERE name = 'model'"),
            [],
            |r| r.get::<_, i64>(0),
        )
        .map(|n| n > 0)
    }
    if has_model(db, "usage_hours")? && has_model(db, "agent_usage_hours")? {
        return Ok(());
    }
    let tx = rusqlite::Transaction::new_unchecked(db, rusqlite::TransactionBehavior::Immediate)?;
    let counts = "calls INTEGER NOT NULL CHECK(calls >= 0),
        input INTEGER CHECK(input >= 0),
        output INTEGER CHECK(output >= 0),
        cache_read INTEGER CHECK(cache_read >= 0),
        cache_write INTEGER CHECK(cache_write >= 0),
        reasoning INTEGER CHECK(reasoning >= 0)";
    let columns = "calls, input, output, cache_read, cache_write, reasoning";
    if !has_model(&tx, "usage_hours")? {
        tx.execute_batch(&format!(
            "CREATE TABLE usage_hours_by_model (
                conversation TEXT NOT NULL REFERENCES conversations(id),
                agent TEXT NOT NULL,
                hour INTEGER NOT NULL CHECK(hour >= 0),
                model TEXT NOT NULL DEFAULT '',
                provider TEXT NOT NULL DEFAULT '',
                {counts},
                PRIMARY KEY (conversation, agent, hour, model, provider)
             );
             INSERT INTO usage_hours_by_model (conversation, agent, hour, {columns})
                 SELECT conversation, agent, hour, {columns} FROM usage_hours;
             DROP TABLE usage_hours;
             ALTER TABLE usage_hours_by_model RENAME TO usage_hours;"
        ))?;
    }
    if !has_model(&tx, "agent_usage_hours")? {
        tx.execute_batch(&format!(
            "CREATE TABLE agent_usage_hours_by_model (
                agent TEXT NOT NULL,
                hour INTEGER NOT NULL CHECK(hour >= 0),
                model TEXT NOT NULL DEFAULT '',
                provider TEXT NOT NULL DEFAULT '',
                {counts},
                PRIMARY KEY (agent, hour, model, provider)
             );
             INSERT INTO agent_usage_hours_by_model (agent, hour, {columns})
                 SELECT agent, hour, {columns} FROM agent_usage_hours;
             DROP TABLE agent_usage_hours;
             ALTER TABLE agent_usage_hours_by_model RENAME TO agent_usage_hours;"
        ))?;
    }
    tx.commit()
}

/// Brings a database made by an earlier bridge up to [`SCHEMA`]: columns
/// added since, which `CREATE TABLE IF NOT EXISTS` does not add.
fn upgrade(db: &Connection) -> rusqlite::Result<()> {
    // Through `add_column`, which another process opening the database at
    // the same moment does not trip up.
    for (column, kind) in [
        ("title", "TEXT"),
        ("titled_by", "TEXT"),
        ("read", "INTEGER"),
        ("archived", "INTEGER NOT NULL DEFAULT 0"),
        (
            "revision",
            "INTEGER NOT NULL DEFAULT 0 CHECK(typeof(revision) = 'integer' AND revision >= 0)",
        ),
    ] {
        add_column(db, "conversations", column, kind)?;
    }
    // A group's agent messages say which member spoke (ADR 0045, proposed).
    add_column(db, "messages", "speaker", "TEXT")?;
    add_column(db, "messages", "question", "TEXT")?;
    // A history line about a held task names it (ADR 0066, proposed).
    add_column(db, "messages", "held_task", "TEXT")?;
    add_column(db, "messages", "suggested_replies", "TEXT")?;
    // A question's owner is its conversation's, read from there: the copy
    // an earlier build kept went stale when a Home was claimed.
    let mut query = db.prepare("SELECT name FROM pragma_table_info('questions')")?;
    let columns = query
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    if columns.iter().any(|c| c == "owner") {
        // Dropped meanwhile by another process opening it, as in add_column
        match db.execute_batch("ALTER TABLE questions DROP COLUMN owner") {
            Err(rusqlite::Error::SqliteFailure(_, Some(why)))
                if why.starts_with("no such column") => {}
            other => other?,
        }
    }
    add_column(db, "questions", "confirmed", "INTEGER NOT NULL DEFAULT 0")?;
    // Home is never archived (ADR 0049): a Home archived by a development
    // build from before that rule is restored, with a new revision so a
    // device that saw it archived takes the change.
    db.execute(
        "UPDATE conversations SET archived = 0, revision = revision + 1
         WHERE archived != 0 AND substr(id, 1, 5) = 'home.'",
        [],
    )?;
    keep_attachment_details(db)?;
    Ok(())
}

/// The `settings` row that says [`keep_attachment_details`] has run.
const ATTACHMENT_DETAILS_KEPT: &str = "attachment_details_kept";

/// Brings the attachments stored before their details were bounded within
/// [`attachment_mime`] and [`attachment_name`]: a media type too long to
/// reach a device stored as it came would end every sync of its owner.
/// Once per database, recorded in `settings`; a second process opening it
/// meanwhile finds every row kept already and changes nothing.
fn keep_attachment_details(db: &Connection) -> rusqlite::Result<()> {
    let done = db
        .query_row(
            "SELECT 1 FROM settings WHERE name = ?1",
            params![ATTACHMENT_DETAILS_KEPT],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if done {
        return Ok(());
    }
    let tx = rusqlite::Transaction::new_unchecked(db, rusqlite::TransactionBehavior::Immediate)?;
    let rows = tx
        .prepare("SELECT id, mime, name FROM attachments")?
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    for (id, mime, name) in rows {
        let (kept_mime, kept_name) = (attachment_mime(&mime), attachment_name(&name, ""));
        if (&kept_mime, &kept_name) != (&mime, &name) {
            tx.execute(
                "UPDATE attachments SET mime = ?1, name = ?2 WHERE id = ?3",
                params![kept_mime, kept_name, id],
            )?;
        }
    }
    tx.execute(
        "INSERT OR IGNORE INTO settings (name, value) VALUES (?1, '1')",
        params![ATTACHMENT_DETAILS_KEPT],
    )?;
    tx.commit()
}

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS questions (
    id TEXT PRIMARY KEY,
    conversation TEXT NOT NULL REFERENCES conversations(id),
    agent TEXT NOT NULL,
    definition TEXT NOT NULL,
    state TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK(typeof(revision)='integer' AND revision>=0),
    answer TEXT,
    confirmed INTEGER NOT NULL DEFAULT 0,
    ask_message TEXT NOT NULL UNIQUE
);
-- A held task's card (ADR 0066, proposed): `body` is the task as its
-- plugin last reported it, normalized, with the runtime's revision.
CREATE TABLE IF NOT EXISTS held_tasks (
    agent TEXT NOT NULL,
    task TEXT NOT NULL,
    conversation TEXT NOT NULL REFERENCES conversations(id),
    body TEXT NOT NULL,
    state TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK(typeof(revision)='integer' AND revision>=0),
    PRIMARY KEY (agent, task)
);
CREATE TABLE IF NOT EXISTS agent_names (agent TEXT PRIMARY KEY, revision INTEGER NOT NULL CHECK(typeof(revision) = 'integer' AND revision >= 0), display_name TEXT);
CREATE TABLE IF NOT EXISTS agent_avatars (agent TEXT PRIMARY KEY, revision INTEGER NOT NULL CHECK(revision>=0), version TEXT, image BLOB);
CREATE TABLE IF NOT EXISTS approvals (id TEXT PRIMARY KEY, body TEXT NOT NULL, state TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS approval_marks (name TEXT PRIMARY KEY, at INTEGER NOT NULL);
-- A policy request's scope as closed under the policy active when it was
-- closed, which the request's own id may not name (ADR 0054).
CREATE TABLE IF NOT EXISTS closed_scopes (key TEXT PRIMARY KEY);
CREATE TABLE IF NOT EXISTS conversations (
    id TEXT PRIMARY KEY,
    sandbox TEXT NOT NULL,
    agent TEXT NOT NULL,
    owner TEXT NOT NULL,
    created INTEGER NOT NULL,
    title TEXT,
    titled_by TEXT,
    read INTEGER,
    archived INTEGER NOT NULL DEFAULT 0,
    revision INTEGER NOT NULL DEFAULT 0 CHECK(typeof(revision) = 'integer' AND revision >= 0)
);
CREATE TABLE IF NOT EXISTS messages (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    id TEXT NOT NULL UNIQUE,
    conversation TEXT NOT NULL REFERENCES conversations(id),
    person TEXT,
    text TEXT NOT NULL,
    kind TEXT NOT NULL,
    at INTEGER NOT NULL,
    question TEXT,
    held_task TEXT,
    suggested_replies TEXT
);
CREATE TABLE IF NOT EXISTS open_item_dismissals (person TEXT NOT NULL, kind TEXT NOT NULL, agent TEXT NOT NULL, item TEXT NOT NULL, version TEXT NOT NULL, request TEXT NOT NULL, PRIMARY KEY(person,kind,agent,item), UNIQUE(person,request));
-- Reminder state follows its source through deletion/agent forgetting.
CREATE TRIGGER IF NOT EXISTS delete_question_reminders AFTER DELETE ON questions BEGIN
 DELETE FROM open_item_dismissals WHERE kind IN ('question','runtime_approval') AND item=OLD.id;
END;
CREATE TRIGGER IF NOT EXISTS delete_held_reminders AFTER DELETE ON held_tasks BEGIN
 DELETE FROM open_item_dismissals WHERE kind='held_task' AND agent=OLD.agent AND item=OLD.task;
END;
CREATE TRIGGER IF NOT EXISTS delete_policy_reminders AFTER DELETE ON approvals BEGIN
 DELETE FROM open_item_dismissals WHERE kind='policy_request' AND item=OLD.id;
END;
CREATE TABLE IF NOT EXISTS question_closures (question TEXT NOT NULL REFERENCES questions(id) ON DELETE CASCADE, person TEXT NOT NULL, request TEXT NOT NULL, PRIMARY KEY(question,person), UNIQUE(person,request));
CREATE TABLE IF NOT EXISTS attachments (
    id TEXT PRIMARY KEY,
    message TEXT NOT NULL,
    conversation TEXT NOT NULL REFERENCES conversations(id),
    mime TEXT NOT NULL,
    name TEXT NOT NULL,
    size INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS devices (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    person TEXT NOT NULL,
    noise_key BLOB NOT NULL UNIQUE,
    device_key BLOB NOT NULL,
    push_key BLOB NOT NULL,
    push_token TEXT,
    paired INTEGER NOT NULL,
    seen INTEGER
);
CREATE TABLE IF NOT EXISTS pairings (
    code BLOB PRIMARY KEY,
    expires INTEGER NOT NULL,
    used INTEGER NOT NULL DEFAULT 0,
    request_name TEXT,
    request_person TEXT,
    decision TEXT
);
CREATE TABLE IF NOT EXISTS members (
    conversation TEXT NOT NULL REFERENCES conversations(id),
    agent TEXT NOT NULL,
    position INTEGER NOT NULL,
    seen INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (conversation, agent)
);
CREATE TABLE IF NOT EXISTS turns (
    id TEXT PRIMARY KEY,
    conversation TEXT NOT NULL REFERENCES conversations(id),
    source INTEGER NOT NULL,
    round INTEGER NOT NULL,
    agent TEXT NOT NULL,
    status TEXT NOT NULL,
    sent TEXT,
    seen INTEGER,
    error TEXT,
    at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS usage_hours (
    conversation TEXT NOT NULL REFERENCES conversations(id),
    agent TEXT NOT NULL,
    hour INTEGER NOT NULL CHECK(hour >= 0),
    calls INTEGER NOT NULL CHECK(calls >= 0),
    input INTEGER CHECK(input >= 0),
    output INTEGER CHECK(output >= 0),
    cache_read INTEGER CHECK(cache_read >= 0),
    cache_write INTEGER CHECK(cache_write >= 0),
    reasoning INTEGER CHECK(reasoning >= 0),
    PRIMARY KEY (conversation, agent, hour)
);
CREATE TABLE IF NOT EXISTS agent_usage_hours (
    agent TEXT NOT NULL,
    hour INTEGER NOT NULL CHECK(hour >= 0),
    calls INTEGER NOT NULL CHECK(calls >= 0),
    input INTEGER CHECK(input >= 0),
    output INTEGER CHECK(output >= 0),
    cache_read INTEGER CHECK(cache_read >= 0),
    cache_write INTEGER CHECK(cache_write >= 0),
    reasoning INTEGER CHECK(reasoning >= 0),
    PRIMARY KEY (agent, hour)
);
CREATE TABLE IF NOT EXISTS agent_usage_reporters (agent TEXT PRIMARY KEY);
CREATE TABLE IF NOT EXISTS log (
    at INTEGER NOT NULL,
    device TEXT,
    person TEXT,
    event TEXT NOT NULL,
    reason TEXT
);
CREATE TABLE IF NOT EXISTS conversation_deletions (
    id TEXT PRIMARY KEY, owner TEXT NOT NULL, targets TEXT NOT NULL, done INTEGER NOT NULL DEFAULT 0
);
CREATE TRIGGER IF NOT EXISTS deleted_conversation_new BEFORE INSERT ON conversations
WHEN EXISTS (SELECT 1 FROM conversation_deletions WHERE id = NEW.id)
BEGIN SELECT RAISE(ABORT, 'conversation deleted'); END;
CREATE TRIGGER IF NOT EXISTS deleted_conversation_message BEFORE INSERT ON messages
WHEN EXISTS (SELECT 1 FROM conversation_deletions WHERE id = NEW.conversation)
BEGIN SELECT RAISE(ABORT, 'conversation deletion pending'); END;
CREATE TRIGGER IF NOT EXISTS deleted_conversation_attachment BEFORE INSERT ON attachments
WHEN EXISTS (SELECT 1 FROM conversation_deletions WHERE id = NEW.conversation)
BEGIN SELECT RAISE(ABORT, 'conversation deletion pending'); END;
CREATE TRIGGER IF NOT EXISTS deleted_conversation_question BEFORE INSERT ON questions
WHEN EXISTS (SELECT 1 FROM conversation_deletions WHERE id = NEW.conversation)
BEGIN SELECT RAISE(ABORT, 'conversation deletion pending'); END;
CREATE TABLE IF NOT EXISTS homes (
    agent TEXT PRIMARY KEY,
    id TEXT UNIQUE
);
CREATE TABLE IF NOT EXISTS settings (
    name TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS tasks (
    sandbox TEXT NOT NULL,
    id TEXT NOT NULL,
    agent TEXT NOT NULL,
    body TEXT NOT NULL,
    ended INTEGER,
    PRIMARY KEY (sandbox, id)
);
CREATE TABLE IF NOT EXISTS agent_activity (agent TEXT PRIMARY KEY, body TEXT NOT NULL);
";

/// The `settings` row naming the host's person (ADR 0044).
const HOST_PERSON: &str = "host_person";

/// Columns added after the first version of the database, which an older
/// `app.db` gets when it is opened.
const ADDED_COLUMNS: &[(&str, &str, &str)] = &[
    // `<device>/<its envelope id>` for a device's message, so a message
    // sent again is known (`docs/protocol.md`, Messages: ids drop
    // duplicates).
    ("messages", "origin", "TEXT"),
    // 1 while a person's message has not reached the agent's plugin.
    ("messages", "pending", "INTEGER NOT NULL DEFAULT 0"),
    // The transport's id of the node the device was paired from.
    ("devices", "node", "TEXT"),
    ("pairings", "request_node", "TEXT"),
    ("pairings", "request_node_id", "TEXT"),
    // The device a pairing made, for the terminal's audit entry.
    ("pairings", "device", "TEXT"),
    // Why the last push to the device failed (ADR 0065, proposed); none
    // once one goes through.
    ("devices", "push_failure", "TEXT"),
];

/// How many lines of its log the bridge keeps: refused callers write
/// there, so it must not grow without end.
const LOG_KEPT: i64 = 10_000;

fn add_column(
    db: &Connection,
    table: &str,
    column: &str,
    declaration: &str,
) -> rusqlite::Result<()> {
    let mut query = db.prepare(&format!("SELECT name FROM pragma_table_info('{table}')"))?;
    let columns = query
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    if !columns.iter().any(|c| c == column) {
        // Another process opening the database at the same moment (`app
        // serve` and `app pair`) may add it between the look and the change
        match db.execute_batch(&format!(
            "ALTER TABLE {table} ADD COLUMN {column} {declaration}"
        )) {
            Err(rusqlite::Error::SqliteFailure(_, Some(why)))
                if why.starts_with("duplicate column name") => {}
            other => other?,
        }
    }
    Ok(())
}

/// Appended independently of the released tables, so older bridges still
/// read and insert their three-column approval rows. Legacy rows retain
/// only their creation time as a known lower bound; no decision time is invented.
fn migrate_approval_cutoffs(db: &Connection) -> rusqlite::Result<()> {
    db.execute_batch(
        "CREATE TABLE IF NOT EXISTS approval_cutoffs (
            request TEXT PRIMARY KEY REFERENCES approvals(id) ON DELETE CASCADE,
            through_ms INTEGER NOT NULL CHECK(typeof(through_ms)='integer')
        );",
    )
}

fn record_approval_cutoff(db: &Connection, request: &str) -> rusqlite::Result<()> {
    db.execute(
        "INSERT INTO approval_cutoffs VALUES (?1,?2) ON CONFLICT(request) DO UPDATE SET through_ms=MAX(approval_cutoffs.through_ms,excluded.through_ms)",
        params![request, crate::model::now().as_millisecond()],
    )?;
    Ok(())
}

/// What became of a device's message given to [`Store::add_from_device`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Added {
    /// Stored, with its place in the order.
    New(i64),
    /// Sent before: stored then, and not again.
    Again,
}

/// What a plugin's `ack` did ([`Store::delivered`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Acked {
    /// A message of the agent's own, now the runtime's.
    Delivered,
    /// Nothing pending under that id: an ack of something else, such as a
    /// rename, or one given again.
    Nothing,
    /// A message still pending for another agent, which it left as it was.
    NotItsOwn,
}

/// A person's message still to give the agent's plugin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pending {
    /// The id it goes to the plugin with, the same on every try.
    pub id: String,
    pub conversation: String,
    pub person: String,
    pub text: String,
}

/// A paired device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Device {
    pub id: String,
    pub name: String,
    pub person: String,
    pub noise_key: Vec<u8>,
    pub device_key: Vec<u8>,
    pub push_key: Vec<u8>,
    pub push_token: Option<String>,
    pub paired: i64,
    pub seen: Option<i64>,
    /// The transport's id of the node it was paired from; `None` for a
    /// device paired before the bridge recorded it, which is refused.
    pub node: Option<String>,
}

/// One line of the bridge's log: a connection, a disconnection, a refusal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogLine {
    pub at: i64,
    pub device: Option<String>,
    pub person: Option<String>,
    pub event: String,
    pub reason: Option<String>,
}

/// A pairing request the terminal is asked to confirm.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingRequest {
    pub name: String,
    pub person: String,
    /// The node it comes from, by name, for the terminal.
    pub node: String,
    /// The node's id, stored with the device.
    pub node_id: String,
}

/// A stored name revision, which the table keeps nonnegative.
fn name_revision(row: &rusqlite::Row, column: usize) -> rusqlite::Result<u64> {
    let revision: i64 = row.get(column)?;
    u64::try_from(revision).map_err(|_| rusqlite::Error::IntegralValueOutOfRange(column, revision))
}

impl Store {
    /// The host's shared display name, or the stable identifier at revision zero.
    pub fn agent_name(
        &self,
        agent: &str,
    ) -> rusqlite::Result<enclos_protocol::agent_name::NameMetadata> {
        self.db
            .query_row(
                "SELECT revision,display_name FROM agent_names WHERE agent=?1",
                [agent],
                |row| {
                    Ok(enclos_protocol::agent_name::NameMetadata {
                        revision: name_revision(row, 0)?,
                        display_name: row.get(1)?,
                    })
                },
            )
            .optional()
            .map(|name| name.unwrap_or_default())
    }

    pub fn agent_name_metadata(
        &self,
    ) -> rusqlite::Result<
        std::collections::HashMap<String, enclos_protocol::agent_name::NameMetadata>,
    > {
        let mut query = self
            .db
            .prepare("SELECT agent,revision,display_name FROM agent_names")?;
        query
            .query_map([], |row| {
                Ok((
                    row.get(0)?,
                    enclos_protocol::agent_name::NameMetadata {
                        revision: name_revision(row, 1)?,
                        display_name: row.get(2)?,
                    },
                ))
            })?
            .collect()
    }

    /// Compare-and-set, metadata and audit entry commit together; a clear retains its revision.
    pub fn set_agent_name(
        &self,
        agent: &str,
        expected: u64,
        display_name: Option<&str>,
        by: (&str, &str),
    ) -> rusqlite::Result<Option<enclos_protocol::agent_name::NameMetadata>> {
        let tx = rusqlite::Transaction::new_unchecked(
            &self.db,
            rusqlite::TransactionBehavior::Immediate,
        )?;
        let current = tx
            .query_row(
                "SELECT revision,display_name FROM agent_names WHERE agent=?1",
                [agent],
                |row| {
                    Ok(enclos_protocol::agent_name::NameMetadata {
                        revision: name_revision(row, 0)?,
                        display_name: row.get(1)?,
                    })
                },
            )
            .optional()?
            .unwrap_or_default();
        if current.revision != expected {
            return Ok(None);
        }
        if current.display_name.as_deref() == display_name {
            return Ok(Some(current));
        }
        // SQLite's integers end at i64::MAX: the revision after it is refused.
        let stored = current
            .revision
            .checked_add(1)
            .and_then(|r| i64::try_from(r).ok())
            .ok_or(rusqlite::Error::InvalidQuery)?;
        let next = enclos_protocol::agent_name::NameMetadata {
            revision: current.revision + 1,
            display_name: display_name.map(str::to_owned),
        };
        tx.execute("INSERT INTO agent_names (agent,revision,display_name) VALUES (?1,?2,?3) ON CONFLICT(agent) DO UPDATE SET revision=excluded.revision,display_name=excluded.display_name", params![agent,stored,next.display_name])?;
        tx.execute(
            "INSERT INTO log(at,device,person,event,reason) VALUES (?1,?2,?3,'agent.name.set',?4)",
            params![
                now(),
                by.0,
                by.1,
                format!("{agent} revision {}", next.revision)
            ],
        )?;
        tx.commit()?;
        Ok(Some(next))
    }

    /// Restores portable presentation in one transaction; revisions belong to this host.
    pub fn import_presentation(
        &self,
        agent: &str,
        display_name: Option<&str>,
        image: Option<&[u8]>,
    ) -> rusqlite::Result<()> {
        let tx = rusqlite::Transaction::new_unchecked(
            &self.db,
            rusqlite::TransactionBehavior::Immediate,
        )?;
        let revision = |table: &str| -> rusqlite::Result<i64> {
            let current: i64 = tx
                .query_row(
                    &format!("SELECT revision FROM {table} WHERE agent=?1"),
                    [agent],
                    |r| r.get(0),
                )
                .optional()?
                .unwrap_or(0);
            current
                .checked_add(1)
                .filter(|n| *n > 0)
                .ok_or(rusqlite::Error::InvalidQuery)
        };
        let name_revision = revision("agent_names")?;
        let image_revision = revision("agent_avatars")?;
        tx.execute("INSERT INTO agent_names(agent,revision,display_name) VALUES (?1,?2,?3) ON CONFLICT(agent) DO UPDATE SET revision=excluded.revision,display_name=excluded.display_name", params![agent,name_revision,display_name])?;
        tx.execute("INSERT INTO agent_avatars(agent,revision,version,image) VALUES (?1,?2,?3,?4) ON CONFLICT(agent) DO UPDATE SET revision=excluded.revision,version=excluded.version,image=excluded.image", params![agent,image_revision,image.map(crate::policy::sha256_hex),image])?;
        for (event, revision) in [
            ("agent.name.set", name_revision),
            ("agent.avatar.set", image_revision),
        ] {
            tx.execute(
                "INSERT INTO log(at,device,person,event,reason) VALUES (?1,NULL,NULL,?2,?3)",
                params![
                    now(),
                    event,
                    format!("{agent} revision {revision} imported by host")
                ],
            )?;
        }
        tx.execute("DELETE FROM log WHERE rowid NOT IN (SELECT rowid FROM log ORDER BY rowid DESC LIMIT ?1)",[LOG_KEPT])?;
        tx.commit()
    }

    /// The shared photo, or revision zero before the first edit.
    pub fn avatar(&self, agent: &str) -> rusqlite::Result<StoredAvatar> {
        self.db
            .query_row(
                "SELECT revision,version,image FROM agent_avatars WHERE agent=?1",
                [agent],
                |r| {
                    Ok(StoredAvatar {
                        revision: r.get(0)?,
                        version: r.get(1)?,
                        image: r.get(2)?,
                    })
                },
            )
            .optional()
            .map(|a| a.unwrap_or_default())
    }
    pub fn avatar_metadata(
        &self,
    ) -> rusqlite::Result<std::collections::HashMap<String, enclos_protocol::avatar::AvatarMetadata>>
    {
        let mut q = self
            .db
            .prepare("SELECT agent,revision,version FROM agent_avatars")?;
        q.query_map([], |r| {
            Ok((
                r.get(0)?,
                enclos_protocol::avatar::AvatarMetadata {
                    revision: r.get(1)?,
                    version: r.get(2)?,
                },
            ))
        })?
        .collect()
    }
    /// The revision guard and device log commit with the image; removal retains a tombstone.
    pub fn set_avatar(
        &self,
        agent: &str,
        expected: i64,
        image: Option<&[u8]>,
        by: (&str, &str),
    ) -> rusqlite::Result<Option<StoredAvatar>> {
        // Immediate: the write lock is taken (waiting out the busy timeout)
        // before the revision is read, so a plugin thread writing meanwhile
        // cannot make the later write fail at once with SQLITE_BUSY.
        let tx = rusqlite::Transaction::new_unchecked(
            &self.db,
            rusqlite::TransactionBehavior::Immediate,
        )?;
        let revision: i64 = tx
            .query_row(
                "SELECT revision FROM agent_avatars WHERE agent=?1",
                [agent],
                |r| r.get(0),
            )
            .optional()?
            .unwrap_or(0);
        if revision != expected {
            return Ok(None);
        }
        let next = StoredAvatar {
            revision: revision
                .checked_add(1)
                .ok_or(rusqlite::Error::InvalidQuery)?,
            version: image.map(crate::policy::sha256_hex),
            image: image.map(<[u8]>::to_vec),
        };
        tx.execute("INSERT INTO agent_avatars VALUES (?1,?2,?3,?4) ON CONFLICT(agent) DO UPDATE SET revision=excluded.revision,version=excluded.version,image=excluded.image",params![agent,next.revision,next.version,next.image])?;
        tx.execute("INSERT INTO log(at,device,person,event,reason) VALUES (?1,?2,?3,'agent.avatar.set',?4)",params![now(),by.0,by.1,format!("{agent} revision {}",next.revision)])?;
        tx.commit()?;
        Ok(Some(next))
    }
    /// All accepted records, without the inbox history window, for active-grant provenance.
    pub fn accepted_access(&self) -> rusqlite::Result<Vec<enclos_protocol::approval::Approval>> {
        let mut q = self
            .db
            .prepare("SELECT body FROM approvals WHERE state='approved'")?;
        let rows = q
            .query_map([], |r| r.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows.into_iter()
            .map(|body| {
                serde_json::from_str(&body)
                    .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))
            })
            .collect()
    }
    pub fn recover_approvals(&self) -> rusqlite::Result<()> {
        for mut a in self.approvals()? {
            if a.state == "applying" {
                a.state = "failed".into();
                a.reason = Some("The bridge stopped during this decision. Review the active policy on the host; the action was not replayed.".into());
                self.put_approval(&a)?;
            }
        }
        Ok(())
    }
    pub fn approvals(&self) -> rusqlite::Result<Vec<enclos_protocol::approval::Approval>> {
        let mut q = self
            .db
            .prepare("SELECT body, state FROM approvals WHERE state IN ('pending','applying','failed') OR rowid IN (SELECT rowid FROM approvals ORDER BY rowid DESC LIMIT 200) ORDER BY rowid DESC")?;
        let rows = q
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows.into_iter()
            .map(|(s, state)| {
                let mut a: enclos_protocol::approval::Approval = serde_json::from_str(&s)
                    .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
                a.state = state;
                Ok(a)
            })
            .collect()
    }
    /// `sandbox`'s requests that can account for refusals at `from_ms` or
    /// later, beyond the inbox's history window. Pending and applying
    /// requests remain relevant however long they have waited. A completed
    /// request covers retries through its completion, rather than creation.
    pub fn approval_history_since(
        &self,
        sandbox: &str,
        from_ms: i64,
    ) -> rusqlite::Result<Vec<ApprovalHistory>> {
        let mut q = self.db.prepare(
            "WITH history AS (
                SELECT a.body, a.state,
                    MAX(COALESCE(c.through_ms, CAST(json_extract(a.body, '$.time') AS INTEGER)*1000),
                        CAST(json_extract(a.body, '$.time') AS INTEGER)*1000) AS through_ms
                FROM approvals a LEFT JOIN approval_cutoffs c ON c.request=a.id
                WHERE json_extract(a.body, '$.sandbox')=?1
            )
            SELECT body, state, through_ms FROM history
            WHERE state IN ('pending','applying') OR through_ms>=?2",
        )?;
        let rows = q
            .query_map(rusqlite::params![sandbox, from_ms], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, i64>(2)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows.into_iter()
            .map(|(s, state, through_ms)| {
                let mut a: enclos_protocol::approval::Approval = serde_json::from_str(&s)
                    .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
                a.state = state;
                Ok(ApprovalHistory {
                    approval: a,
                    through_ms,
                })
            })
            .collect()
    }
    /// Since when, in seconds, proxy refusals become policy requests: the
    /// first time this bridge collected them, so the network log's history
    /// from before the bridge never floods the inbox.
    pub fn refusals_since(&self) -> rusqlite::Result<i64> {
        self.db.execute(
            "INSERT OR IGNORE INTO approval_marks VALUES ('refusals', ?1)",
            [now()],
        )?;
        self.db.query_row(
            "SELECT at FROM approval_marks WHERE name='refusals'",
            [],
            |r| r.get(0),
        )
    }

    pub fn approval(
        &self,
        id: &str,
    ) -> rusqlite::Result<Option<enclos_protocol::approval::Approval>> {
        let row: Option<(String, String)> = self
            .db
            .query_row("SELECT body,state FROM approvals WHERE id=?1", [id], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .optional()?;
        row.map(|(body, state)| {
            let mut a: enclos_protocol::approval::Approval = serde_json::from_str(&body)
                .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
            a.state = state;
            Ok(a)
        })
        .transpose()
    }
    pub fn create_approval(
        &self,
        a: &enclos_protocol::approval::Approval,
    ) -> rusqlite::Result<bool> {
        let body = serde_json::to_string(a)
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
        let tx = self.db.unchecked_transaction()?;
        let created = tx.execute(
            "INSERT OR IGNORE INTO approvals VALUES (?1,?2,?3)",
            params![a.request, body, a.state],
        )? == 1;
        if created {
            tx.execute(
                "DELETE FROM approval_cutoffs WHERE request=?1",
                [&a.request],
            )?;
        }
        tx.commit()?;
        Ok(created)
    }
    /// A failed request asked again: pending, with `a`'s fresh preview.
    pub fn reopen_approval(
        &self,
        a: &enclos_protocol::approval::Approval,
    ) -> rusqlite::Result<bool> {
        let body = serde_json::to_string(a)
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
        let tx = self.db.unchecked_transaction()?;
        let changed = tx.execute(
            "UPDATE approvals SET body=?2,state='pending' WHERE id=?1 AND state='failed'",
            params![a.request, body],
        )? == 1;
        if changed {
            tx.execute(
                "DELETE FROM approval_cutoffs WHERE request=?1",
                [&a.request],
            )?;
        }
        tx.commit()?;
        Ok(changed)
    }
    /// Reclassify a pending diagnostic notification without granting or denying access.
    pub fn dismiss_probe(
        &self,
        a: &enclos_protocol::approval::Approval,
    ) -> rusqlite::Result<Option<enclos_protocol::approval::Approval>> {
        let mut closed = a.clone();
        closed.state = "diagnostic".into();
        closed.available = false;
        closed.revision.clear();
        closed.change = "Enclos diagnostic probe; no policy change is needed.".into();
        closed.reason =
            Some("This attempt comes from the built-in network probe, not agent work.".into());
        let body = serde_json::to_string(&closed)
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
        let tx = self.db.unchecked_transaction()?;
        let changed = tx.execute(
            "UPDATE approvals SET body=?2,state='diagnostic' WHERE id=?1 AND state='pending' AND body=?3",
            params![a.request, body, serde_json::to_string(a).map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?],
        )? == 1;
        if changed {
            record_approval_cutoff(&tx, &a.request)?;
        }
        tx.commit()?;
        Ok(changed.then_some(closed))
    }
    pub fn put_approval(&self, a: &enclos_protocol::approval::Approval) -> rusqlite::Result<()> {
        let body = serde_json::to_string(a)
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
        let tx = self.db.unchecked_transaction()?;
        let changed = tx.execute(
            "UPDATE approvals SET body=?2,state=?3 WHERE id=?1 AND state='applying'",
            params![a.request, body, a.state],
        )? == 1;
        if changed && matches!(a.state.as_str(), "approved" | "denied" | "failed") {
            record_approval_cutoff(&tx, &a.request)?;
        }
        tx.commit()
    }
    pub fn refresh_approval(
        &self,
        a: &enclos_protocol::approval::Approval,
    ) -> rusqlite::Result<bool> {
        let body = serde_json::to_string(a)
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
        Ok(self.db.execute(
            "UPDATE approvals SET body=?2 WHERE id=?1 AND state='pending'",
            params![a.request, body],
        )? == 1)
    }
    /// Exactly one device claims a pending decision, including after reconnect.
    pub fn claim_approval(&self, id: &str) -> rusqlite::Result<bool> {
        Ok(self.db.execute(
            "UPDATE approvals SET state='applying' WHERE id=?1 AND state='pending'",
            [id],
        )? == 1)
    }

    /// Closes attention only. The original request and policy decision stay intact.
    /// The first write races with claim_approval; only one transition can win.
    /// It closes only from `expected`, the state the caller checked: a
    /// request that changed since (an application that failed just after
    /// the check) is not closed without being checked again. `scope` is the
    /// request's scope keyed under the policy active now, which stays closed
    /// with it ([`Store::scope_closed`]).
    pub fn close_approval(
        &self,
        id: &str,
        expected: &str,
        scope: &str,
        device: &str,
        person: &str,
    ) -> rusqlite::Result<bool> {
        let tx = self.db.unchecked_transaction()?;
        let changed = tx.execute(
            "UPDATE approvals SET state='closed' WHERE id=?1 AND state=?2 AND state IN ('pending','failed')",
            [id, expected],
        )? == 1;
        if changed {
            tx.execute(
                "INSERT INTO log (at,device,person,event,reason) VALUES (?1,?2,?3,'approval.closed',?4)",
                params![now(), device, person, id],
            )?;
            tx.execute("INSERT OR IGNORE INTO closed_scopes VALUES (?1)", [scope])?;
            record_approval_cutoff(&tx, id)?;
        }
        tx.commit()?;
        Ok(changed)
    }

    /// Whether a request for scope `key` (a scope keyed under a policy) was
    /// closed while that policy was active.
    pub fn scope_closed(&self, key: &str) -> rusqlite::Result<bool> {
        self.db.query_row(
            "SELECT EXISTS(SELECT 1 FROM closed_scopes WHERE key=?1)",
            [key],
            |r| r.get(0),
        )
    }

    /// Opens the database at `path`, made for the user alone (`0600`): it
    /// holds every conversation, and later each device's keys.
    pub fn open(path: &Path) -> rusqlite::Result<Store> {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let to_sqlite = |e: std::io::Error| rusqlite::Error::ToSqlConversionFailure(Box::new(e));
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(path)
            .map_err(to_sqlite)?;
        // One made before, with the default mode
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(to_sqlite)?;
        let db = Connection::open(path)?;
        db.busy_timeout(std::time::Duration::from_secs(5))?;
        db.execute_batch(SCHEMA)?;
        upgrade(&db)?;
        for (table, column, declaration) in ADDED_COLUMNS {
            add_column(&db, table, column, declaration)?;
        }
        migrate_approval_cutoffs(&db)?;
        migrate_usage_models(&db)?;
        db.execute_batch(
            "CREATE UNIQUE INDEX IF NOT EXISTS messages_origin ON messages(origin);
             CREATE INDEX IF NOT EXISTS messages_pending ON messages(pending) WHERE pending = 1;
             CREATE INDEX IF NOT EXISTS messages_conversation ON messages(conversation, seq);",
        )?;
        // A database whose devices were paired before the host's person
        // was kept: the first of them names it, as it would have, so the
        // next device paired, another person's perhaps, does not (ADR 0044)
        db.execute(
            "INSERT OR IGNORE INTO settings (name, value)
             SELECT ?1, person FROM devices ORDER BY paired, rowid LIMIT 1",
            params![HOST_PERSON],
        )?;
        Ok(Store { db })
    }

    /// All of the person's conversations, archived included, the oldest first.
    pub fn conversations(&self, owner: &str) -> rusqlite::Result<Vec<Conversation>> {
        let mut query = self.db.prepare(
            "SELECT id, sandbox, agent, title, titled_by, read, archived, revision FROM conversations WHERE owner = ?1 ORDER BY created, id",
        )?;
        let rows = query.query_map(params![owner], conversation_row)?;
        rows.collect()
    }

    /// An owner's direct conversations with agent `agent` of `sandbox`,
    /// groups left out, oldest first: in one query.
    pub fn direct_conversations(
        &self,
        owner: &str,
        sandbox: &str,
        agent: &str,
    ) -> rusqlite::Result<Vec<Conversation>> {
        let mut query = self.db.prepare(
            "SELECT c.id, c.sandbox, c.agent, c.title, c.titled_by, c.read, c.archived, c.revision
             FROM conversations c
             WHERE c.owner = ?1 AND c.sandbox = ?2 AND c.agent = ?3
               AND NOT EXISTS (SELECT 1 FROM members m WHERE m.conversation = c.id)
             ORDER BY c.created, c.id",
        )?;
        let rows = query.query_map(params![owner, sandbox, agent], conversation_row)?;
        rows.collect()
    }

    /// Archives or restores an owner's conversation. `None` means unknown,
    /// owned by someone else, or an attempt to archive Home; `Some` says
    /// whether the flag changed. A legacy archived Home may be restored.
    /// Content, routing, read positions and running work are untouched.
    pub fn set_archived(
        &self,
        id: &str,
        owner: &str,
        archived: bool,
    ) -> rusqlite::Result<Option<bool>> {
        if archived && is_home(id) {
            return Ok(None);
        }
        let tx = rusqlite::Transaction::new_unchecked(
            &self.db,
            rusqlite::TransactionBehavior::Immediate,
        )?;
        let current = tx
            .query_row(
                "SELECT archived FROM conversations WHERE id = ?1 AND owner = ?2",
                params![id, owner],
                |row| row.get::<_, bool>(0),
            )
            .optional()?;
        if let Some(current) = current {
            let changed = current != archived;
            if changed {
                tx.execute(
                    "UPDATE conversations SET archived = ?3, revision = revision + 1 WHERE id = ?1 AND owner = ?2",
                    params![id, owner, archived],
                )?;
            }
            tx.commit()?;
            Ok(Some(changed))
        } else {
            Ok(None)
        }
    }

    /// Restores conversation `id` to the active Inbox because something in
    /// it now waits for the person (an agent's question, a command
    /// approval), whoever archived it; whether it was archived. Replies and
    /// notices never call this (ADR 0049).
    pub fn unarchive_for_request(&self, id: &str) -> rusqlite::Result<bool> {
        let changed = self.db.execute(
            "UPDATE conversations SET archived = 0, revision = revision + 1 WHERE id = ?1 AND archived",
            params![id],
        )?;
        Ok(changed == 1)
    }

    /// Its owner read conversation `id` up to message `seq`; whether that
    /// moved how far it was read. It only moves forward, and never past the
    /// conversation's newest message.
    pub fn mark_read(&self, id: &str, seq: i64) -> rusqlite::Result<bool> {
        let changed = self.db.execute(
            "UPDATE conversations SET read = ?2, revision = revision + 1 WHERE id = ?1
             AND (read IS NULL OR read < ?2)
             AND ?2 <= (SELECT COALESCE(MAX(seq), 0) FROM messages WHERE conversation = ?1)",
            params![id, seq],
        )?;
        Ok(changed == 1)
    }

    /// Names a conversation, saying who named it ([`BY_AGENT`] or
    /// [`BY_PERSON`]); whether its name changed. The person's name replaces
    /// any, and an empty one clears it, so the runtime may name it again;
    /// the runtime's never replaces the person's. The name is kept as
    /// [`conversation_title`] gives it.
    pub fn name(&self, id: &str, title: &str, by: &str) -> rusqlite::Result<bool> {
        let title = conversation_title(title);
        let title = title.as_str();
        let changed = match (by, title.is_empty()) {
            (BY_PERSON, true) => self.db.execute(
                "UPDATE conversations SET title = NULL, titled_by = NULL, revision = revision + 1 WHERE id = ?1 AND title IS NOT NULL",
                params![id],
            )?,
            (BY_PERSON, false) => self.db.execute(
                "UPDATE conversations SET title = ?2, titled_by = ?3, revision = revision + 1 WHERE id = ?1
                 AND (title IS NOT ?2 OR titled_by IS NOT ?3)",
                params![id, title, BY_PERSON],
            )?,
            (_, true) => 0,
            _ => self.db.execute(
                "UPDATE conversations SET title = ?2, titled_by = ?3, revision = revision + 1 WHERE id = ?1
                 AND titled_by IS NOT ?4 AND title IS NOT ?2",
                params![id, title, by, BY_PERSON],
            )?,
        };
        Ok(changed == 1)
    }

    /// Records a file of message `message` (by the message's id).
    pub fn add_attachment(&self, a: &StoredAttachment, message: &str) -> rusqlite::Result<()> {
        self.db.execute(
            "INSERT OR IGNORE INTO attachments (id, message, conversation, mime, name, size) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![a.id, message, a.conversation, a.mime, a.name, a.size],
        )?;
        Ok(())
    }

    /// The files of a message, by the message's id, in the order they came.
    pub fn attachments_of(&self, message: &str) -> rusqlite::Result<Vec<StoredAttachment>> {
        let mut query = self.db.prepare(
            "SELECT id, conversation, mime, name, size FROM attachments WHERE message = ?1 ORDER BY rowid",
        )?;
        let rows = query.query_map(params![message], attachment_row)?;
        rows.collect()
    }

    /// A file, by its id.
    pub fn attachment(&self, id: &str) -> rusqlite::Result<Option<StoredAttachment>> {
        self.db
            .query_row(
                "SELECT id, conversation, mime, name, size FROM attachments WHERE id = ?1",
                params![id],
                attachment_row,
            )
            .optional()
    }

    /// Adds `agent`'s report of `calls` model calls in `conversation`, at
    /// `at` (Unix seconds), naming neither model nor model provider, to
    /// that hour's usage: [`Store::add_usage_by`].
    pub fn add_usage(
        &self,
        conversation: &str,
        agent: &str,
        at: i64,
        calls: u32,
        tokens: UsageTokens,
    ) -> rusqlite::Result<UsageTotal> {
        self.add_usage_by(conversation, agent, at, Served::default(), calls, tokens)
    }

    /// Adds `agent`'s report of `calls` model calls in `conversation`, at
    /// `at` (Unix seconds), of the model and model provider it names, to
    /// that hour's usage, and returns the conversation's new total: in one
    /// write, so two reports at once both count. Each count is bounded
    /// first ([`UsageTokens::bounded`]); a sum that would not fit is kept
    /// at the most it can hold. Past [`MODELS_AN_HOUR`] models in the hour,
    /// it counts under neither.
    pub fn add_usage_by(
        &self,
        conversation: &str,
        agent: &str,
        at: i64,
        served: Served<'_>,
        calls: u32,
        tokens: UsageTokens,
    ) -> rusqlite::Result<UsageTotal> {
        let tx = rusqlite::Transaction::new_unchecked(
            &self.db,
            rusqlite::TransactionBehavior::Immediate,
        )?;
        let hour = at.max(0) / 3600;
        let (mut model, mut provider) = (
            served.model.unwrap_or_default(),
            served.provider.unwrap_or_default(),
        );
        let (known, kept): (bool, i64) = tx.query_row(
            "SELECT COALESCE(SUM(model = ?4 AND provider = ?5), 0), COUNT(*)
             FROM usage_hours WHERE conversation = ?1 AND agent = ?2 AND hour = ?3",
            params![conversation, agent, hour, model, provider],
            |row| Ok((row.get::<_, i64>(0)? > 0, row.get(1)?)),
        )?;
        if !known && kept >= MODELS_AN_HOUR {
            (model, provider) = ("", "");
        }
        let before = tx
            .query_row(
                "SELECT calls, input, output, cache_read, cache_write, reasoning
                 FROM usage_hours WHERE conversation = ?1 AND agent = ?2 AND hour = ?3
                     AND model = ?4 AND provider = ?5",
                params![conversation, agent, hour, model, provider],
                |row| usage_row(row, 0),
            )
            .optional()?
            .unwrap_or_default();
        let bucket = plus(
            before,
            UsageTotal {
                calls: u64::from(calls),
                tokens: tokens.bounded(),
            },
        );
        let stored = |n: Option<u64>| n.map(|n| i64::try_from(n).unwrap_or(i64::MAX));
        let t = bucket.tokens;
        tx.execute(
            "INSERT INTO usage_hours
                 (conversation, agent, hour, model, provider,
                  calls, input, output, cache_read, cache_write, reasoning)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
             ON CONFLICT(conversation, agent, hour, model, provider) DO UPDATE SET
                 calls = excluded.calls, input = excluded.input, output = excluded.output,
                 cache_read = excluded.cache_read, cache_write = excluded.cache_write,
                 reasoning = excluded.reasoning",
            params![
                conversation,
                agent,
                hour,
                model,
                provider,
                stored(Some(bucket.calls)),
                stored(t.input),
                stored(t.output),
                stored(t.cache_read),
                stored(t.cache_write),
                stored(t.reasoning)
            ],
        )?;
        let total = usage_in(&tx, conversation)?.unwrap_or_default();
        tx.commit()?;
        Ok(total)
    }

    /// What a conversation used, as its plugins reported it; `None` before
    /// the first report.
    pub fn usage(&self, conversation: &str) -> rusqlite::Result<Option<UsageTotal>> {
        usage_in(&self.db, conversation)
    }

    /// Adds `agent`'s (`<sandbox>/<agent>`) report of `calls` model calls
    /// outside any app conversation, naming neither model nor model
    /// provider: [`Store::add_agent_usage_by`].
    pub fn add_agent_usage(
        &self,
        agent: &str,
        at: i64,
        calls: u32,
        tokens: UsageTokens,
    ) -> rusqlite::Result<()> {
        self.add_agent_usage_by(agent, at, Served::default(), calls, tokens)
    }

    /// Adds `agent`'s (`<sandbox>/<agent>`) report of `calls` model calls
    /// outside any app conversation, at `at` (Unix seconds), of the model
    /// and model provider it names, to that hour's usage: in one write,
    /// bounded and saturating as [`Store::add_usage_by`]. Whatever the
    /// plugin says the calls came from, at most [`MODELS_AN_HOUR`] rows an
    /// agent an hour, and none older than [`AGENT_USAGE_DAYS`]: what an
    /// agent sends cannot grow the table past that.
    pub fn add_agent_usage_by(
        &self,
        agent: &str,
        at: i64,
        served: Served<'_>,
        calls: u32,
        tokens: UsageTokens,
    ) -> rusqlite::Result<()> {
        let tx = rusqlite::Transaction::new_unchecked(
            &self.db,
            rusqlite::TransactionBehavior::Immediate,
        )?;
        let hour = at.max(0) / 3600;
        let (mut model, mut provider) = (
            served.model.unwrap_or_default(),
            served.provider.unwrap_or_default(),
        );
        let (known, kept): (bool, i64) = tx.query_row(
            "SELECT COALESCE(SUM(model = ?3 AND provider = ?4), 0), COUNT(*)
             FROM agent_usage_hours WHERE agent = ?1 AND hour = ?2",
            params![agent, hour, model, provider],
            |row| Ok((row.get::<_, i64>(0)? > 0, row.get(1)?)),
        )?;
        if !known && kept >= MODELS_AN_HOUR {
            (model, provider) = ("", "");
        }
        let before = tx
            .query_row(
                "SELECT calls, input, output, cache_read, cache_write, reasoning
                 FROM agent_usage_hours WHERE agent = ?1 AND hour = ?2
                     AND model = ?3 AND provider = ?4",
                params![agent, hour, model, provider],
                |row| usage_row(row, 0),
            )
            .optional()?
            .unwrap_or_default();
        let bucket = plus(
            before,
            UsageTotal {
                calls: u64::from(calls),
                tokens: tokens.bounded(),
            },
        );
        let stored = |n: Option<u64>| n.map(|n| i64::try_from(n).unwrap_or(i64::MAX));
        let t = bucket.tokens;
        tx.execute(
            "INSERT INTO agent_usage_hours
                 (agent, hour, model, provider,
                  calls, input, output, cache_read, cache_write, reasoning)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
             ON CONFLICT(agent, hour, model, provider) DO UPDATE SET
                 calls = excluded.calls, input = excluded.input, output = excluded.output,
                 cache_read = excluded.cache_read, cache_write = excluded.cache_write,
                 reasoning = excluded.reasoning",
            params![
                agent,
                hour,
                model,
                provider,
                stored(Some(bucket.calls)),
                stored(t.input),
                stored(t.output),
                stored(t.cache_read),
                stored(t.cache_write),
                stored(t.reasoning)
            ],
        )?;
        tx.execute(
            "DELETE FROM agent_usage_hours WHERE hour < ?1",
            params![hour - AGENT_USAGE_DAYS * 24],
        )?;
        tx.commit()
    }

    /// Records whether `agent`'s plugin reports its calls outside app
    /// conversations (`agent_usage`), as its last `hello` said.
    pub fn set_reports_outside(&self, agent: &str, reports: bool) -> rusqlite::Result<()> {
        match reports {
            true => self.db.execute(
                "INSERT OR IGNORE INTO agent_usage_reporters (agent) VALUES (?1)",
                params![agent],
            ),
            false => self.db.execute(
                "DELETE FROM agent_usage_reporters WHERE agent = ?1",
                params![agent],
            ),
        }
        .map(|_| ())
    }

    /// The agents whose plugin last said it reports its calls outside app
    /// conversations, sorted.
    pub fn outside_reporters(&self) -> rusqlite::Result<Vec<String>> {
        let mut query = self
            .db
            .prepare("SELECT agent FROM agent_usage_reporters ORDER BY agent")?;
        let rows = query.query_map([], |row| row.get(0))?;
        rows.collect()
    }

    /// Every hour of usage from the hour that holds `since` (Unix seconds)
    /// on, by agent (`<sandbox>/<agent>`), hour, model and model provider:
    /// in `owner`'s conversations (every person's without one), and, with
    /// `outside`, the agents' calls outside any app conversation, which
    /// only the host's person sees. Summed in SQL; a sum past what SQLite
    /// holds is said, not wrapped.
    fn usage_hours(
        &self,
        owner: Option<&str>,
        since: i64,
        outside: bool,
    ) -> rusqlite::Result<Vec<HourRow>> {
        let from = since.max(0) / 3600;
        let sums = "SUM(calls), SUM(input), SUM(output), SUM(cache_read), SUM(cache_write), SUM(reasoning)";
        let mut query = self.db.prepare(&format!(
            "SELECT agent, hour, model, provider, {sums} FROM (
                 SELECT c.sandbox || '/' || u.agent AS agent, u.hour AS hour, u.model AS model,
                        u.provider AS provider, u.calls AS calls, u.input AS input,
                        u.output AS output, u.cache_read AS cache_read,
                        u.cache_write AS cache_write, u.reasoning AS reasoning
                 FROM usage_hours u JOIN conversations c ON c.id = u.conversation
                 WHERE (?1 IS NULL OR c.owner = ?1) AND u.hour >= ?2
                 UNION ALL
                 SELECT agent, hour, model, provider, calls, input, output, cache_read,
                        cache_write, reasoning
                 FROM agent_usage_hours WHERE ?3 AND hour >= ?2
             ) GROUP BY agent, hour, model, provider"
        ))?;
        let rows = query.query_map(params![owner, from, outside], |row| {
            Ok(HourRow {
                agent: row.get(0)?,
                hour: row.get(1)?,
                model: row.get(2)?,
                provider: row.get(3)?,
                counts: usage_row(row, 4)?,
            })
        })?;
        rows.collect()
    }

    /// What each agent used from the hour that holds `since` (Unix
    /// seconds) on, as `(<sandbox>/<agent>, total)`, sorted by agent: in
    /// `owner`'s conversations, and with `outside` its calls outside them
    /// too. The bridge keeps usage by the hour, so a window starts on the
    /// hour.
    pub fn usage_since(
        &self,
        owner: &str,
        since: i64,
        outside: bool,
    ) -> rusqlite::Result<Vec<(String, UsageTotal)>> {
        Ok(self.usage_window(owner, since, outside, None)?.0)
    }

    /// [`Store::usage_since`] and, with `series` (a bucket in seconds and
    /// the device's offset from UTC), each agent's usage over time:
    /// [`Store::usage_report`] for every agent, without its costs.
    pub fn usage_window(
        &self,
        owner: &str,
        since: i64,
        outside: bool,
        series: Option<(u32, i32)>,
    ) -> rusqlite::Result<UsageWindow> {
        let window = self.usage_report(
            &WindowAsk {
                owner: Some(owner),
                since,
                outside,
                series,
                scope: Scope::Host,
                sum: false,
            },
            &crate::pricing::PriceList::bundled(),
        )?;
        Ok((
            window
                .agents
                .into_iter()
                .map(|(agent, total, _)| (agent, total))
                .collect(),
            window.series,
        ))
    }

    /// What the agents `ask` covers used over its window, priced with
    /// `prices` (issue #343): each agent's total and cost, each sandbox's,
    /// and, with a series asked for, the usage over time of each of the
    /// agents that used the most tokens ([`MAX_SERIES`], or
    /// [`MAX_SCOPED_SERIES`] for one sandbox or agent), its buckets that saw
    /// a call, the latest [`MAX_POINTS`], oldest first; and with `sum`, the
    /// scope's, every agent summed, each bucket with its cost. A day starts
    /// at the asker's midnight; an hour at the hour, whatever the offset,
    /// as the bridge keeps usage by UTC hour. Each hour of each model is
    /// priced as the list says now, so a corrected price applies to past
    /// usage too.
    pub fn usage_report(
        &self,
        ask: &WindowAsk<'_>,
        prices: &crate::pricing::PriceList,
    ) -> rusqlite::Result<Window> {
        use std::collections::BTreeMap;
        let hours: Vec<(HourRow, UsageCost)> = self
            .usage_hours(ask.owner, ask.since, ask.outside)?
            .into_iter()
            .filter(|h| ask.scope.covers(&h.agent))
            .map(|h| {
                let cost = prices.cost(said(&h.provider), said(&h.model), h.counts.tokens.into());
                (h, cost)
            })
            .collect();
        let mut agents = BTreeMap::<String, (UsageTotal, UsageCost)>::new();
        let mut sandboxes = BTreeMap::<String, (UsageTotal, UsageCost)>::new();
        for (h, cost) in &hours {
            let sandbox = h.agent.split_once('/').map_or(h.agent.as_str(), |(s, _)| s);
            let agent = agents.entry(h.agent.clone()).or_default();
            *agent = (plus(agent.0, h.counts), agent.1.plus(*cost));
            let sandbox = sandboxes.entry(sandbox.to_owned()).or_default();
            *sandbox = (plus(sandbox.0, h.counts), sandbox.1.plus(*cost));
        }
        let mut window = Window {
            agents: agents
                .into_iter()
                .map(|(agent, (total, cost))| (agent, total, cost))
                .collect(),
            sandboxes: sandboxes
                .into_iter()
                .map(|(sandbox, (total, cost))| SandboxTotal {
                    sandbox,
                    total,
                    cost,
                })
                .collect(),
            ..Window::default()
        };
        let Some((bucket, offset)) = ask.series else {
            return Ok(window);
        };
        let bucket = i64::from(bucket.max(1));
        let offset = i64::from(offset);
        let mut by_agent = BTreeMap::<String, BTreeMap<i64, UsageTotal>>::new();
        let mut summed = BTreeMap::<i64, (UsageTotal, UsageCost)>::new();
        for (h, cost) in &hours {
            let at = bucket_of(h.hour, bucket, offset);
            let point = by_agent
                .entry(h.agent.clone())
                .or_default()
                .entry(at)
                .or_default();
            *point = plus(*point, h.counts);
            if ask.sum {
                let point = summed.entry(at).or_default();
                *point = (plus(point.0, h.counts), point.1.plus(*cost));
            }
        }
        let mut series: Vec<(u64, UsageSeries)> = by_agent
            .into_iter()
            .map(|(agent, buckets)| {
                let total = buckets
                    .values()
                    .fold(0u64, |a, b| a.saturating_add(b.tokens.total()));
                let mut points: Vec<UsagePoint> = buckets
                    .into_iter()
                    .map(|(at, b)| UsagePoint {
                        at: u64::try_from(at).unwrap_or(0),
                        calls: b.calls,
                        tokens: point_tokens(&b),
                        cost: None,
                    })
                    .collect();
                let cut = points.len().saturating_sub(MAX_POINTS);
                points.drain(..cut);
                (total, UsageSeries { agent, points })
            })
            .collect();
        // The heaviest first, then by name, so ties read the same each time.
        series.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.agent.cmp(&b.1.agent)));
        let most = match ask.scope {
            Scope::Host => MAX_SERIES,
            _ => MAX_SCOPED_SERIES,
        };
        window.series = series.into_iter().take(most).map(|(_, s)| s).collect();
        window.sum = summed
            .into_iter()
            .map(|(at, (b, cost))| UsagePoint {
                at: u64::try_from(at).unwrap_or(0),
                calls: b.calls,
                tokens: point_tokens(&b),
                cost: Some(cost),
            })
            .collect();
        Ok(window)
    }

    /// [`Store::usage_window`]'s series alone.
    #[cfg(test)]
    pub fn usage_series(
        &self,
        owner: &str,
        since: i64,
        outside: bool,
        bucket: u32,
        offset: i32,
    ) -> rusqlite::Result<Vec<UsageSeries>> {
        Ok(self
            .usage_window(owner, since, outside, Some((bucket, offset)))?
            .1)
    }

    /// A known conversation, with its name.
    pub fn conversation_info(&self, id: &str) -> rusqlite::Result<Option<Conversation>> {
        self.db
            .query_row(
                "SELECT id, sandbox, agent, title, titled_by, read, archived, revision FROM conversations WHERE id = ?1",
                params![id],
                conversation_row,
            )
            .optional()
    }

    /// Records a conversation, owned by `owner`; one already known keeps
    /// its owner and agent, which are returned.
    pub fn conversation(
        &self,
        id: &str,
        sandbox: &str,
        agent: &str,
        owner: &str,
    ) -> rusqlite::Result<(String, String, String)> {
        self.db.execute(
            "INSERT OR IGNORE INTO conversations (id, sandbox, agent, owner, created) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![id, sandbox, agent, owner, now()],
        )?;
        self.db.query_row(
            "SELECT sandbox, agent, owner FROM conversations WHERE id = ?1",
            params![id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
    }

    /// Makes the Home conversation of `agent` (`<sandbox>/<agent>`), owned
    /// by `owner` (`""`: nobody yet) and named Home, so the runtime's names
    /// do not replace it. With `host` true, `owner` is the host's person
    /// ([`Store::host_person`]), and takes Home from anyone else. Otherwise
    /// `owner` takes it only when it has no owner. Whether it was made or
    /// changed owner.
    pub fn ensure_home(&self, agent: &str, owner: &str, host: bool) -> rusqlite::Result<bool> {
        let Some((sandbox, name)) = agent.split_once('/') else {
            return Ok(false);
        };
        let Some(id) = self.home_of(agent)? else {
            // Forgotten, and not set up again: it has no Home.
            return Ok(false);
        };
        if let Some((s, a, _)) = self.conversation_of(&id)? {
            // Not this agent's: a device chose the id, before the bridge
            // kept `home.` for itself. It is not Home, and keeps its owner.
            if (s.as_str(), a.as_str()) != (sandbox, name) {
                return Ok(false);
            }
            if owner.is_empty() {
                return Ok(false);
            }
            let changed = if host {
                self.db.execute(
                    "UPDATE conversations SET owner = ?2, archived = 0, revision = revision + 1 WHERE id = ?1 AND owner != ?2",
                    params![id, owner],
                )?
            } else {
                self.db.execute(
                    "UPDATE conversations SET owner = ?2, archived = 0, revision = revision + 1 WHERE id = ?1 AND owner = ''",
                    params![id, owner],
                )?
            };
            return Ok(changed == 1);
        }
        self.conversation(&id, sandbox, name, owner)?;
        self.name(&id, "Home", BY_PERSON)?;
        Ok(true)
    }

    /// Stores a message once: a second with the same id is a duplicate
    /// (delivery is at least once) and gets `None`.
    pub fn add(
        &self,
        id: &str,
        conversation: &str,
        from: &From,
        text: &str,
        kind: &str,
    ) -> rusqlite::Result<Option<i64>> {
        let (person, speaker) = match from {
            From::Person(p) => (Some(p.as_str()), None),
            From::Agent => (None, None),
            From::Member(m) => (None, Some(m.as_str())),
        };
        let added = self.db.execute(
            "INSERT OR IGNORE INTO messages (id, conversation, person, text, kind, at, speaker) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![id, conversation, person, text, kind, now(), speaker],
        )?;
        Ok((added == 1).then(|| self.db.last_insert_rowid()))
    }

    /// Stores the pieces of one text, each with its id, and its `files`
    /// with the first piece, all or none: when the first id is known
    /// already the whole text is a duplicate, and `None` comes back; else
    /// each piece's `seq`.
    pub fn add_pieces(
        &self,
        pieces: &[(String, String)],
        conversation: &str,
        from: &From,
        kind: &str,
        files: &[StoredAttachment],
    ) -> rusqlite::Result<Option<Vec<i64>>> {
        self.add_pieces_with_replies(pieces, conversation, from, kind, files, &[])
    }

    pub fn add_pieces_with_replies(
        &self,
        pieces: &[(String, String)],
        conversation: &str,
        from: &From,
        kind: &str,
        files: &[StoredAttachment],
        replies: &[String],
    ) -> rusqlite::Result<Option<Vec<i64>>> {
        let transaction = self.db.unchecked_transaction()?;
        let mut seqs = Vec::new();
        for (id, text) in pieces {
            match self.add(id, conversation, from, text, kind)? {
                Some(seq) => seqs.push(seq),
                None if seqs.is_empty() => return Ok(None),
                None => return Err(rusqlite::Error::StatementChangedRows(0)),
            }
        }
        if let Some((first, _)) = pieces.first() {
            for file in files {
                self.add_attachment(file, first)?;
            }
        }
        if let Some((last, _)) = pieces.last()
            && !replies.is_empty()
            && enclos_protocol::suggested_replies::validate(replies)
        {
            self.db.execute(
                "UPDATE messages SET suggested_replies=?2 WHERE id=?1",
                params![
                    last,
                    serde_json::to_string(replies).expect("strings serialize")
                ],
            )?;
        }
        transaction.commit()?;
        Ok(Some(seqs))
    }

    /// Whether a file with this id is recorded.
    pub fn has_attachment(&self, id: &str) -> rusqlite::Result<bool> {
        self.db.query_row(
            "SELECT EXISTS (SELECT 1 FROM attachments WHERE id = ?1)",
            params![id],
            |row| row.get(0),
        )
    }

    /// Whether a message with this id is stored.
    pub fn has_message(&self, id: &str) -> rusqlite::Result<bool> {
        self.db.query_row(
            "SELECT EXISTS (SELECT 1 FROM messages WHERE id = ?1)",
            params![id],
            |row| row.get(0),
        )
    }

    /// Stores a person's message from a device, as pending for the agent,
    /// once: `origin` names the device and its id for the message, and a
    /// message with an `origin` known already is [`Added::Again`].
    pub fn add_from_device(
        &self,
        origin: &str,
        id: &str,
        conversation: &str,
        person: &str,
        text: &str,
    ) -> rusqlite::Result<Added> {
        let added = self.db.execute(
            "INSERT OR IGNORE INTO messages (id, origin, pending, conversation, person, text, kind, at) VALUES (?1, ?2, 1, ?3, ?4, ?5, 'message', ?6)",
            params![id, origin, conversation, person, text, now()],
        )?;
        Ok(match added {
            1 => Added::New(self.db.last_insert_rowid()),
            _ => Added::Again,
        })
    }

    /// A person's message in a group, from a device, as
    /// [`Store::add_from_device`] stores one, but given to no plugin: the
    /// bridge runs the group's turns itself.
    pub fn add_to_group(
        &self,
        origin: &str,
        id: &str,
        conversation: &str,
        person: &str,
        text: &str,
    ) -> rusqlite::Result<Added> {
        let added = self.db.execute(
            "INSERT OR IGNORE INTO messages (id, origin, pending, conversation, person, text, kind, at) VALUES (?1, ?2, 0, ?3, ?4, ?5, 'message', ?6)",
            params![id, origin, conversation, person, text, now()],
        )?;
        Ok(match added {
            1 => Added::New(self.db.last_insert_rowid()),
            _ => Added::Again,
        })
    }

    /// The messages still to give `sandbox`/`agent`'s plugin, oldest first.
    pub fn pending(&self, sandbox: &str, agent: &str) -> rusqlite::Result<Vec<Pending>> {
        let mut query = self.db.prepare(
            "SELECT m.id, m.conversation, m.person, m.text FROM messages m
             JOIN conversations c ON c.id = m.conversation
             WHERE m.pending = 1 AND c.sandbox = ?1 AND c.agent = ?2
             AND NOT EXISTS (SELECT 1 FROM conversation_deletions d WHERE d.id = c.id) ORDER BY m.seq",
        )?;
        let rows = query.query_map(params![sandbox, agent], |row| {
            Ok(Pending {
                id: row.get(0)?,
                conversation: row.get(1)?,
                person: row.get(2)?,
                text: row.get(3)?,
            })
        })?;
        rows.collect()
    }

    /// The agents with messages still to give them, as `(sandbox, agent)`.
    pub fn agents_with_pending(&self) -> rusqlite::Result<Vec<(String, String)>> {
        let mut query = self.db.prepare(
            "SELECT DISTINCT c.sandbox, c.agent FROM messages m
             JOIN conversations c ON c.id = m.conversation WHERE m.pending = 1",
        )?;
        let rows = query.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;
        rows.collect()
    }

    /// The plugin of `agent` (`<sandbox>/<agent>`) acknowledged message
    /// `id`: it is the runtime's now. Only a message of one of that agent's
    /// own conversations: another agent's plugin cannot mark it delivered.
    pub fn delivered(&self, id: &str, agent: &str) -> rusqlite::Result<Acked> {
        let Some((sandbox, name)) = agent.split_once('/') else {
            return Err(rusqlite::Error::InvalidParameterName(format!(
                "{agent} is not <sandbox>/<agent>"
            )));
        };
        let marked = self.db.execute(
            "UPDATE messages SET pending = 0 WHERE id = ?1 AND pending = 1 AND conversation IN
             (SELECT id FROM conversations WHERE sandbox = ?2 AND agent = ?3)",
            params![id, sandbox, name],
        )?;
        if marked > 0 {
            return Ok(Acked::Delivered);
        }
        let others = self
            .db
            .query_row(
                "SELECT 1 FROM messages WHERE id = ?1 AND pending = 1",
                params![id],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        Ok(if others {
            Acked::NotItsOwn
        } else {
            Acked::Nothing
        })
    }

    /// The messages of `owner`'s conversations after `since`, in order.
    pub fn since(&self, owner: &str, since: i64) -> rusqlite::Result<Vec<Message>> {
        let mut query = self.db.prepare(
            "SELECT m.seq, m.id, m.conversation, m.person, m.text, m.kind, m.at, m.speaker, m.question, m.held_task, m.suggested_replies FROM messages m
             JOIN conversations c ON c.id = m.conversation
             WHERE c.owner = ?1 AND m.seq > ?2 ORDER BY m.seq",
        )?;
        let rows = query.query_map(params![owner, since], message_row)?;
        rows.collect()
    }

    /// The newest `seq` of any stored message, 0 when there is none.
    pub fn newest_seq(&self) -> rusqlite::Result<i64> {
        self.db
            .query_row("SELECT COALESCE(MAX(seq), 0) FROM messages", [], |row| {
                row.get(0)
            })
    }

    /// The messages of conversation `id` after `since`, in order.
    pub fn messages_after(&self, id: &str, since: i64) -> rusqlite::Result<Vec<Message>> {
        let mut query = self.db.prepare(
            "SELECT seq, id, conversation, person, text, kind, at, speaker, question, held_task, suggested_replies FROM messages
             WHERE conversation = ?1 AND seq > ?2 ORDER BY seq",
        )?;
        let rows = query.query_map(params![id, since], message_row)?;
        rows.collect()
    }

    /// The newest `at_most` of conversation `id`'s messages after `since`,
    /// oldest first: a turn's prompt holds only so many, however long a
    /// member has not been given any.
    pub fn newest_after(
        &self,
        id: &str,
        since: i64,
        at_most: usize,
    ) -> rusqlite::Result<Vec<Message>> {
        let mut query = self.db.prepare(
            "SELECT seq, id, conversation, person, text, kind, at, speaker, question, held_task, suggested_replies FROM messages
             WHERE conversation = ?1 AND seq > ?2 ORDER BY seq DESC LIMIT ?3",
        )?;
        let rows = query.query_map(params![id, since, at_most as i64], message_row)?;
        let mut newest = rows.collect::<rusqlite::Result<Vec<_>>>()?;
        newest.reverse();
        Ok(newest)
    }

    /// The `seq` of conversation `id`'s newest message; 0 with none.
    pub fn newest(&self, id: &str) -> rusqlite::Result<i64> {
        self.db.query_row(
            "SELECT COALESCE(MAX(seq), 0) FROM messages WHERE conversation = ?1",
            params![id],
            |row| row.get(0),
        )
    }

    /// Records group `id` of `sandbox`'s agents `members` (their names in
    /// it, in the group's order), owned by `owner`: a conversation whose
    /// agent is empty, and a member row for each. One already known keeps
    /// its owner and members, which are returned.
    pub fn group(
        &self,
        id: &str,
        sandbox: &str,
        members: &[String],
        owner: &str,
    ) -> rusqlite::Result<(String, Vec<String>)> {
        // Publish a complete member list and its revision together, including
        // when two devices try to create the same group at once.
        let tx = rusqlite::Transaction::new_unchecked(
            &self.db,
            rusqlite::TransactionBehavior::Immediate,
        )?;
        let (made_in, agent, owner) = self.conversation(id, sandbox, "", owner)?;
        // Another conversation with this id gets no members
        let known = made_in != sandbox || !agent.is_empty() || !self.members(id)?.is_empty();
        let mut changed = false;
        for (position, agent) in members.iter().enumerate().filter(|_| !known) {
            changed |= tx.execute(
                "INSERT OR IGNORE INTO members (conversation, agent, position) VALUES (?1, ?2, ?3)",
                params![id, agent, position as i64],
            )? != 0;
        }
        if changed {
            tx.execute(
                "UPDATE conversations SET revision = revision + 1 WHERE id = ?1",
                [id],
            )?;
        }
        let result = (
            owner,
            self.members(id)?.into_iter().map(|(a, _)| a).collect(),
        );
        tx.commit()?;
        Ok(result)
    }

    /// A group's members, in its order, each with the `seq` of the last of
    /// the group's messages it was given; none for a conversation that is
    /// not a group.
    pub fn members(&self, id: &str) -> rusqlite::Result<Vec<(String, i64)>> {
        let mut query = self
            .db
            .prepare("SELECT agent, seen FROM members WHERE conversation = ?1 ORDER BY position")?;
        let rows = query.query_map(params![id], |row| Ok((row.get(0)?, row.get(1)?)))?;
        rows.collect()
    }

    /// Whether group `id` holds, after `since`, a message to give member
    /// `agent`: one that is neither its own nor a runtime's `status` line.
    pub fn news_for(&self, id: &str, agent: &str, since: i64) -> rusqlite::Result<bool> {
        self.db.query_row(
            "SELECT EXISTS (SELECT 1 FROM messages WHERE conversation = ?1 AND seq > ?2
             AND kind != 'status' AND (person IS NOT NULL OR speaker IS NULL OR speaker != ?3))",
            params![id, since, agent],
            |row| row.get(0),
        )
    }

    /// Member `agent` of group `id` has been given its messages up to `seq`.
    pub fn saw(&self, id: &str, agent: &str, seq: i64) -> rusqlite::Result<()> {
        self.db.execute(
            "UPDATE members SET seen = MAX(seen, ?3) WHERE conversation = ?1 AND agent = ?2",
            params![id, agent, seq],
        )?;
        Ok(())
    }

    /// Records turn `id`, or moves it to `status`; with the plugin message
    /// it was `sent` as, the `seen` position it was given, and an `error`.
    #[allow(clippy::too_many_arguments)]
    pub fn turn(
        &self,
        id: &str,
        conversation: &str,
        source: i64,
        round: u32,
        agent: &str,
        status: &str,
        sent: Option<&str>,
        seen: Option<i64>,
        error: Option<&str>,
    ) -> rusqlite::Result<()> {
        self.db.execute(
            "INSERT INTO turns (id, conversation, source, round, agent, status, sent, seen, error, at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
             ON CONFLICT(id) DO UPDATE SET status = ?6, sent = COALESCE(?7, sent),
               seen = COALESCE(?8, seen), error = COALESCE(?9, error), at = ?10",
            params![id, conversation, source, round, agent, status, sent, seen, error, now()],
        )?;
        Ok(())
    }

    /// Moves a recorded turn to `status`, with an `error` when it failed.
    pub fn turn_status(&self, id: &str, status: &str, error: Option<&str>) -> rusqlite::Result<()> {
        self.db.execute(
            "UPDATE turns SET status = ?2, error = COALESCE(?3, error), at = ?4 WHERE id = ?1",
            params![id, status, error, now()],
        )?;
        Ok(())
    }

    /// The turns left running when the bridge stopped: `(id, conversation, agent)`.
    pub fn running_turns(&self) -> rusqlite::Result<Vec<(String, String, String)>> {
        let mut query = self
            .db
            .prepare("SELECT id, conversation, agent FROM turns WHERE status = 'running'")?;
        let rows = query.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?;
        rows.collect()
    }

    /// The turn of member `agent` in group `conversation` sent to it as
    /// plugin message `sent`: `(id, status, seen)`.
    pub fn turn_sent(
        &self,
        sent: &str,
        conversation: &str,
        agent: &str,
    ) -> rusqlite::Result<Option<(String, String, Option<i64>)>> {
        self.db
            .query_row(
                "SELECT id, status, seen FROM turns WHERE sent = ?1 AND conversation = ?2 AND agent = ?3",
                params![sent, conversation, agent],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
    }

    /// A known conversation's sandbox, agent and owner.
    pub fn conversation_of(&self, id: &str) -> rusqlite::Result<Option<(String, String, String)>> {
        self.db
            .query_row(
                "SELECT sandbox, agent, owner FROM conversations WHERE id = ?1",
                params![id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
    }

    /// The owner of a conversation, if it is known.
    pub fn owner(&self, conversation: &str) -> rusqlite::Result<Option<String>> {
        self.db
            .query_row(
                "SELECT owner FROM conversations WHERE id = ?1",
                params![conversation],
                |row| row.get(0),
            )
            .optional()
    }
}

impl Store {
    fn device_from(row: &rusqlite::Row<'_>) -> rusqlite::Result<Device> {
        Ok(Device {
            id: row.get(0)?,
            name: row.get(1)?,
            person: row.get(2)?,
            noise_key: row.get(3)?,
            device_key: row.get(4)?,
            push_key: row.get(5)?,
            push_token: row.get(6)?,
            paired: row.get(7)?,
            seen: row.get(8)?,
            node: row.get(9)?,
        })
    }

    const DEVICE_COLUMNS: &'static str =
        "id, name, person, noise_key, device_key, push_key, push_token, paired, seen, node";

    /// The host's person (ADR 0044): the person of the first device paired
    /// at the host's terminal, or the one `enclos app host` named since.
    /// `None` until a device is paired.
    pub fn host_person(&self) -> rusqlite::Result<Option<String>> {
        self.db
            .query_row(
                "SELECT value FROM settings WHERE name = ?1",
                params![HOST_PERSON],
                |row| row.get(0),
            )
            .optional()
    }

    /// Names `person` the host's person when nobody is yet: the first
    /// device paired does. Whether they now are, by this call.
    pub fn claim_host(&self, person: &str) -> rusqlite::Result<bool> {
        Ok(self.db.execute(
            "INSERT OR IGNORE INTO settings (name, value) VALUES (?1, ?2)",
            params![HOST_PERSON, person],
        )? == 1)
    }

    /// Names `person` the host's person in place of anyone before, and
    /// gives them every agent's Home, with what it holds.
    pub fn set_host(&self, person: &str) -> rusqlite::Result<()> {
        let transaction = self.db.unchecked_transaction()?;
        transaction.execute(
            "INSERT INTO settings (name, value) VALUES (?1, ?2)
             ON CONFLICT(name) DO UPDATE SET value = excluded.value",
            params![HOST_PERSON, person],
        )?;
        transaction.execute(
            // Not `LIKE`, which ignores case: `Home.x` is a device's. Unarchived:
            // the new owner did not archive it
            "UPDATE conversations SET owner = ?1, archived = 0, revision = revision + 1 WHERE substr(id, 1, 5) = 'home.'",
            params![person],
        )?;
        transaction.commit()
    }

    pub fn add_device(&self, device: &Device) -> rusqlite::Result<()> {
        self.db.execute(
            "INSERT INTO devices (id, name, person, noise_key, device_key, push_key, push_token, paired, seen, node) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                device.id,
                device.name,
                device.person,
                device.noise_key,
                device.device_key,
                device.push_key,
                device.push_token,
                device.paired,
                device.seen,
                device.node
            ],
        )?;
        Ok(())
    }

    pub fn device_by_noise_key(&self, key: &[u8]) -> rusqlite::Result<Option<Device>> {
        self.db
            .query_row(
                &format!(
                    "SELECT {} FROM devices WHERE noise_key = ?1",
                    Self::DEVICE_COLUMNS
                ),
                params![key],
                Self::device_from,
            )
            .optional()
    }

    /// A paired device by its id; `None` once it is unpaired.
    pub fn device(&self, id: &str) -> rusqlite::Result<Option<Device>> {
        self.db
            .query_row(
                &format!("SELECT {} FROM devices WHERE id = ?1", Self::DEVICE_COLUMNS),
                params![id],
                Self::device_from,
            )
            .optional()
    }

    pub fn devices(&self) -> rusqlite::Result<Vec<Device>> {
        let mut query = self.db.prepare(&format!(
            "SELECT {} FROM devices ORDER BY person, paired",
            Self::DEVICE_COLUMNS
        ))?;
        let rows = query.query_map([], Self::device_from)?;
        rows.collect()
    }

    /// Removes a device; whether there was one.
    pub fn remove_device(&self, id: &str) -> rusqlite::Result<bool> {
        Ok(self
            .db
            .execute("DELETE FROM devices WHERE id = ?1", params![id])?
            == 1)
    }

    pub fn device_seen(&self, id: &str) -> rusqlite::Result<()> {
        self.db.execute(
            "UPDATE devices SET seen = ?2 WHERE id = ?1",
            params![id, now()],
        )?;
        Ok(())
    }

    /// Keeps the push token a device gave, in place of its last: a new
    /// token has not failed yet, while the same one given again (a device
    /// gives it at each connection) keeps why it last failed.
    pub fn set_push_token(&self, id: &str, token: &str) -> rusqlite::Result<()> {
        self.db.execute(
            "UPDATE devices SET push_failure = CASE WHEN push_token IS ?2 THEN push_failure END, push_token = ?2 WHERE id = ?1",
            params![id, token],
        )?;
        Ok(())
    }

    /// Forgets a device's push token, when it is still `token`: one the
    /// device gave since stays. Whether it was forgotten.
    pub fn drop_push_token(&self, id: &str, token: &str) -> rusqlite::Result<bool> {
        Ok(self.db.execute(
            "UPDATE devices SET push_token = NULL, push_failure = NULL WHERE id = ?1 AND push_token = ?2",
            params![id, token],
        )? == 1)
    }

    /// Why the last push to a device failed; `None` when it went through,
    /// or none was tried.
    pub fn push_failure(&self, id: &str) -> rusqlite::Result<Option<String>> {
        Ok(self
            .db
            .query_row(
                "SELECT push_failure FROM devices WHERE id = ?1",
                params![id],
                |row| row.get(0),
            )
            .optional()?
            .flatten())
    }

    pub fn set_push_failure(&self, id: &str, why: Option<&str>) -> rusqlite::Result<()> {
        self.db.execute(
            "UPDATE devices SET push_failure = ?2 WHERE id = ?1",
            params![id, why],
        )?;
        Ok(())
    }

    /// Forgets why each device's last push failed: the key it failed with
    /// was replaced or removed.
    pub fn clear_push_failures(&self) -> rusqlite::Result<()> {
        self.db
            .execute("UPDATE devices SET push_failure = NULL", [])?;
        Ok(())
    }

    pub fn log(
        &self,
        device: Option<&str>,
        person: Option<&str>,
        event: &str,
        reason: Option<&str>,
    ) -> rusqlite::Result<()> {
        self.db.execute(
            "INSERT INTO log (at, device, person, event, reason) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![now(), device, person, event, reason],
        )?;
        self.db.execute(
            "DELETE FROM log WHERE rowid <= ?1",
            params![self.db.last_insert_rowid() - LOG_KEPT],
        )?;
        Ok(())
    }

    /// The last `limit` lines of the log, oldest first.
    pub fn log_lines(&self, limit: i64) -> rusqlite::Result<Vec<LogLine>> {
        let mut query = self.db.prepare(
            "SELECT at, device, person, event, reason FROM (SELECT rowid, * FROM log ORDER BY rowid DESC LIMIT ?1) ORDER BY rowid",
        )?;
        let rows = query.query_map(params![limit], |row| {
            Ok(LogLine {
                at: row.get(0)?,
                device: row.get(1)?,
                person: row.get(2)?,
                event: row.get(3)?,
                reason: row.get(4)?,
            })
        })?;
        rows.collect()
    }

    /// Records a one-time pairing code, valid until `expires`.
    pub fn add_pairing(&self, code: &[u8], expires: i64) -> rusqlite::Result<()> {
        self.db.execute(
            "INSERT INTO pairings (code, expires) VALUES (?1, ?2)",
            params![code, expires],
        )?;
        Ok(())
    }

    /// Takes the code for a request: `false` when it is unknown, used or
    /// expired. Using it once is all it gets, whatever the answer.
    pub fn use_pairing(&self, code: &[u8], request: &PairingRequest) -> rusqlite::Result<bool> {
        Ok(self.db.execute(
            "UPDATE pairings SET used = 1, request_name = ?2, request_person = ?3, request_node = ?4, request_node_id = ?5 WHERE code = ?1 AND used = 0 AND expires >= ?6",
            params![code, request.name, request.person, request.node, request.node_id, now()],
        )? == 1)
    }

    /// The codes still waiting to be used, for the bridge to try a proof
    /// against.
    pub fn open_pairings(&self) -> rusqlite::Result<Vec<Vec<u8>>> {
        let mut query = self
            .db
            .prepare("SELECT code FROM pairings WHERE used = 0 AND expires >= ?1")?;
        let rows = query.query_map(params![now()], |row| row.get(0))?;
        rows.collect()
    }

    /// The request made with `code`, once a device has used it.
    pub fn pairing_request(&self, code: &[u8]) -> rusqlite::Result<Option<PairingRequest>> {
        self.db
            .query_row(
                "SELECT request_name, request_person, request_node, request_node_id FROM pairings WHERE code = ?1 AND used = 1",
                params![code],
                |row| {
                    Ok(PairingRequest {
                        name: row.get(0)?,
                        person: row.get(1)?,
                        node: row.get::<_, Option<String>>(2)?.unwrap_or_default(),
                        node_id: row.get::<_, Option<String>>(3)?.unwrap_or_default(),
                    })
                },
            )
            .optional()
    }

    /// The first word on a pairing: the terminal's answer (`accept` or
    /// `decline`), or the bridge's `gone` when the device left before it;
    /// whether this one was first.
    pub fn decide_pairing(&self, code: &[u8], decision: &str) -> rusqlite::Result<bool> {
        Ok(self.db.execute(
            "UPDATE pairings SET decision = ?2 WHERE code = ?1 AND decision IS NULL",
            params![code, decision],
        )? == 1)
    }

    /// What became of an accepted pairing, for the terminal: `paired` once
    /// the device has its answer, with the device's id, or `gone` when it
    /// left before.
    pub fn settle_pairing(
        &self,
        code: &[u8],
        outcome: &str,
        device: Option<&str>,
    ) -> rusqlite::Result<()> {
        self.db.execute(
            "UPDATE pairings SET decision = ?2, device = ?3 WHERE code = ?1 AND decision = 'accept'",
            params![code, outcome, device],
        )?;
        Ok(())
    }

    /// The device a settled pairing made.
    pub fn paired_device(&self, code: &[u8]) -> rusqlite::Result<Option<String>> {
        Ok(self
            .db
            .query_row(
                "SELECT device FROM pairings WHERE code = ?1",
                params![code],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()?
            .flatten())
    }

    pub fn pairing_decision(&self, code: &[u8]) -> rusqlite::Result<Option<String>> {
        Ok(self
            .db
            .query_row(
                "SELECT decision FROM pairings WHERE code = ?1",
                params![code],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()?
            .flatten())
    }
}

pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

#[cfg(test)]
impl Store {
    pub fn set_refusals_since(&self, at: i64) -> rusqlite::Result<()> {
        self.db.execute(
            "INSERT INTO approval_marks (name, at) VALUES ('refusals', ?1) ON CONFLICT(name) DO UPDATE SET at=excluded.at",
            [at],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cutoff_request(id: &str, state: &str) -> enclos_protocol::approval::Approval {
        enclos_protocol::approval::Approval {
            request: id.into(),
            sandbox: "lab".into(),
            agent: String::new(),
            conversation: None,
            access: enclos_protocol::approval::Access {
                kind: enclos_protocol::approval::AccessKind::Network,
                target: "example.com".into(),
                private: false,
            },
            action: "Connect to example.com".into(),
            time: 10,
            state: state.into(),
            change: String::new(),
            scope: "example.com".into(),
            restart: false,
            revision: "revision".into(),
            available: true,
            reason: None,
        }
    }

    fn stored_cutoff(store: &Store, id: &str) -> Option<i64> {
        store
            .db
            .query_row(
                "SELECT through_ms FROM approval_cutoffs WHERE request=?1",
                [id],
                |row| row.get(0),
            )
            .optional()
            .unwrap()
    }

    #[test]
    fn approval_cutoffs_persist_completion_precision_without_changing_the_wire_request() {
        let folder = tempfile::tempdir().unwrap();
        let path = folder.path().join("app.db");
        let store = Store::open(&path).unwrap();
        for state in ["approved", "denied", "failed", "closed", "diagnostic"] {
            let mut request = cutoff_request(state, "pending");
            store.create_approval(&request).unwrap();
            let before = crate::model::now().as_millisecond();
            match state {
                "closed" => assert!(
                    store
                        .close_approval(state, "pending", "scope", "phone", "owner")
                        .unwrap()
                ),
                "diagnostic" => assert!(store.dismiss_probe(&request).unwrap().is_some()),
                _ => {
                    assert!(store.claim_approval(state).unwrap());
                    request.state = state.into();
                    store.put_approval(&request).unwrap();
                }
            }
            let after = crate::model::now().as_millisecond();
            let through_ms = stored_cutoff(&store, state).unwrap();
            assert!((before..=after).contains(&through_ms));
            let reopened = Store::open(&path).unwrap();
            let history = reopened.approval_history_since("lab", through_ms).unwrap();
            let entry = history
                .iter()
                .find(|h| h.approval.request == state)
                .unwrap();
            assert_eq!(entry.through_ms, through_ms);
            assert_eq!(entry.approval.state, state);
            assert_eq!(entry.approval.time, 10, "display time stays at creation");
            assert!(
                reopened
                    .approval_history_since("lab", through_ms + 1)
                    .unwrap()
                    .iter()
                    .all(|h| h.approval.request != state)
            );
            let wire = serde_json::to_value(&entry.approval).unwrap();
            assert!(wire.get("through_ms").is_none());
        }
    }

    #[test]
    fn approval_cutoff_history_keeps_waiting_requests_and_legacy_creation_boundaries() {
        let folder = tempfile::tempdir().unwrap();
        let path = folder.path().join("app.db");
        // The released schema has no cutoff table, and older clients use
        // a positional insert into the unchanged three-column table.
        let db = Connection::open(&path).unwrap();
        db.execute_batch(SCHEMA).unwrap();
        let legacy = cutoff_request("legacy", "denied");
        db.execute(
            "INSERT INTO approvals VALUES (?1,?2,?3)",
            params![
                legacy.request,
                serde_json::to_string(&legacy).unwrap(),
                legacy.state
            ],
        )
        .unwrap();
        drop(db);
        let store = Store::open(&path).unwrap();
        assert_eq!(stored_cutoff(&store, "legacy"), None);
        let history = store.approval_history_since("lab", 10_000).unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].through_ms, 10_000);
        assert!(
            store
                .approval_history_since("lab", 10_001)
                .unwrap()
                .is_empty()
        );
        for id in ["pending", "applying"] {
            store
                .create_approval(&cutoff_request(id, "pending"))
                .unwrap();
        }
        assert!(store.claim_approval("applying").unwrap());
        let reopened = Store::open(&path).unwrap();
        let mut waiting: Vec<_> = reopened
            .approval_history_since("lab", 20_000)
            .unwrap()
            .into_iter()
            .map(|h| (h.approval.request, h.through_ms))
            .collect();
        waiting.sort();
        assert_eq!(
            waiting,
            [
                ("applying".to_owned(), 10_000),
                ("pending".to_owned(), 10_000)
            ]
        );
        assert_eq!(stored_cutoff(&reopened, "legacy"), None);
        let columns: i64 = reopened
            .db
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('approvals')",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(columns, 3);
        // Repeated opens and a legacy writer neither invent a cutoff nor
        // require a changed Approval body.
        reopened
            .create_approval(&cutoff_request("older-writer", "denied"))
            .unwrap();
        assert_eq!(
            Store::open(&path)
                .unwrap()
                .approval_history_since("lab", 0)
                .unwrap()
                .len(),
            4
        );
    }

    #[test]
    fn approval_cutoffs_change_only_with_successful_lifecycle_transitions() {
        let folder = tempfile::tempdir().unwrap();
        let store = Store::open(&folder.path().join("app.db")).unwrap();
        let mut request = cutoff_request("r1", "pending");
        store.create_approval(&request).unwrap();
        assert!(store.claim_approval("r1").unwrap());
        request.state = "failed".into();
        store.put_approval(&request).unwrap();
        assert!(stored_cutoff(&store, "r1").is_some());
        store
            .db
            .execute(
                "UPDATE approval_cutoffs SET through_ms=10003 WHERE request='r1'",
                [],
            )
            .unwrap();
        store.put_approval(&request).unwrap();
        store.recover_approvals().unwrap();
        assert!(
            !store
                .close_approval("r1", "pending", "scope", "phone", "owner")
                .unwrap()
        );
        assert!(store.dismiss_probe(&request).unwrap().is_none());
        assert_eq!(stored_cutoff(&store, "r1"), Some(10_003));
        assert_eq!(
            store.approval_history_since("lab", 10_003).unwrap()[0].through_ms,
            10_003
        );
        assert!(
            store
                .approval_history_since("lab", 10_004)
                .unwrap()
                .is_empty()
        );

        request.state = "pending".into();
        request.time = 20;
        assert!(store.reopen_approval(&request).unwrap());
        assert_eq!(stored_cutoff(&store, "r1"), None);
        assert!(!store.reopen_approval(&request).unwrap());
        assert!(store.claim_approval("r1").unwrap());
        store.recover_approvals().unwrap();
        assert_eq!(store.approval("r1").unwrap().unwrap().state, "failed");
        assert!(stored_cutoff(&store, "r1").is_some());
        assert!(
            store
                .close_approval("r1", "failed", "scope", "phone", "owner")
                .unwrap()
        );
        let closed_at = stored_cutoff(&store, "r1");
        assert!(!store.reopen_approval(&request).unwrap());
        assert!(
            !store
                .close_approval("r1", "failed", "scope", "phone", "owner")
                .unwrap()
        );
        assert_eq!(stored_cutoff(&store, "r1"), closed_at);
    }

    #[test]
    fn approval_cutoffs_reset_on_reimport_but_survive_a_duplicate_creation() {
        let folder = tempfile::tempdir().unwrap();
        let store = Store::open(&folder.path().join("app.db")).unwrap();
        let mut request = cutoff_request("r1", "pending");
        assert!(store.create_approval(&request).unwrap());
        assert!(store.claim_approval("r1").unwrap());
        request.state = "failed".into();
        store.put_approval(&request).unwrap();
        let cutoff = stored_cutoff(&store, "r1");
        assert!(cutoff.is_some());
        request.state = "pending".into();
        assert!(!store.create_approval(&request).unwrap());
        assert_eq!(stored_cutoff(&store, "r1"), cutoff);
        // An older writer may remove a request with foreign-key checks off.
        store.db.pragma_update(None, "foreign_keys", "OFF").unwrap();
        store
            .db
            .execute("DELETE FROM approvals WHERE id='r1'", [])
            .unwrap();
        assert_eq!(stored_cutoff(&store, "r1"), cutoff);
        assert!(store.create_approval(&request).unwrap());
        assert_eq!(stored_cutoff(&store, "r1"), None);
    }

    #[test]
    fn approval_cutoff_storage_failure_rolls_back_the_lifecycle_transition() {
        let folder = tempfile::tempdir().unwrap();
        let store = Store::open(&folder.path().join("app.db")).unwrap();
        let mut request = cutoff_request("decision", "pending");
        store.create_approval(&request).unwrap();
        assert!(store.claim_approval("decision").unwrap());
        store.db.execute_batch("CREATE TRIGGER reject_cutoff BEFORE INSERT ON approval_cutoffs BEGIN SELECT RAISE(ABORT, 'fixture cutoff failure'); END;").unwrap();
        request.state = "denied".into();
        assert!(store.put_approval(&request).is_err());
        assert_eq!(
            store.approval("decision").unwrap().unwrap().state,
            "applying"
        );
        assert_eq!(stored_cutoff(&store, "decision"), None);
        store
            .create_approval(&cutoff_request("close", "pending"))
            .unwrap();
        assert!(
            store
                .close_approval("close", "pending", "scope", "phone", "owner")
                .is_err()
        );
        assert_eq!(store.approval("close").unwrap().unwrap().state, "pending");
        assert!(!store.scope_closed("scope").unwrap());
        assert!(store.log_lines(10).unwrap().is_empty());
        let probe = cutoff_request("probe", "pending");
        store.create_approval(&probe).unwrap();
        assert!(store.dismiss_probe(&probe).is_err());
        assert_eq!(store.approval("probe").unwrap().unwrap().state, "pending");
    }

    #[test]
    fn a_group_keeps_its_members_their_positions_and_who_said_what() {
        let folder = tempfile::tempdir().unwrap();
        let store = Store::open(&folder.path().join("app.db")).unwrap();
        let owner = "victor@example.com";
        let members = vec!["main".to_owned(), "coder".to_owned()];
        let (o, m) = store.group("g-1", "lab", &members, owner).unwrap();
        assert_eq!((o.as_str(), m.clone()), (owner, members.clone()));
        // Known already: keeps its owner and members.
        assert_eq!(
            store.group("g-1", "lab", &["x".into()], "other").unwrap(),
            (owner.to_owned(), members)
        );
        assert!(store.members("c-none").unwrap().is_empty());
        let you = store
            .add(
                "p-1",
                "g-1",
                &From::Person(owner.into()),
                "@all hi",
                "message",
            )
            .unwrap()
            .unwrap();
        let said = store
            .add(
                "a-1",
                "g-1",
                &From::Member("coder".into()),
                "hello",
                "reply",
            )
            .unwrap()
            .unwrap();
        assert_eq!(store.newest("g-1").unwrap(), said);
        let after: Vec<From> = store
            .messages_after("g-1", you)
            .unwrap()
            .into_iter()
            .map(|m| m.from)
            .collect();
        assert_eq!(after, [From::Member("coder".into())]);
        assert_eq!(
            store.since(owner, 0).unwrap()[1].from,
            From::Member("coder".into())
        );
        // Positions only move forward.
        store.saw("g-1", "main", said).unwrap();
        store.saw("g-1", "main", you).unwrap();
        assert_eq!(store.members("g-1").unwrap()[0], ("main".to_owned(), said));
    }

    #[test]
    fn a_members_news_is_what_others_said_after_its_position() {
        let folder = tempfile::tempdir().unwrap();
        let store = Store::open(&folder.path().join("app.db")).unwrap();
        let members = ["main".to_owned(), "coder".to_owned()];
        store.group("g-1", "lab", &members, "alice").unwrap();
        let add = |id: &str, from: From, kind: &str| {
            store.add(id, "g-1", &from, "x", kind).unwrap().unwrap()
        };
        let asked = add("p-1", From::Person("alice".into()), "message");
        assert!(store.news_for("g-1", "main", 0).unwrap());
        assert!(!store.news_for("g-1", "main", asked).unwrap());
        // Its own words and a runtime's status line are no news to it.
        let own = add("m-1", From::Member("main".into()), "reply");
        add("m-2", From::Member("main".into()), "status");
        assert!(!store.news_for("g-1", "main", asked).unwrap());
        assert!(store.news_for("g-1", "coder", asked).unwrap());
        add("c-1", From::Member("coder".into()), "reply");
        assert!(store.news_for("g-1", "main", own).unwrap());
    }

    #[test]
    fn turns_are_kept_with_what_they_were_sent_as() {
        let folder = tempfile::tempdir().unwrap();
        let store = Store::open(&folder.path().join("app.db")).unwrap();
        store
            .group("g-1", "lab", &["main".into(), "coder".into()], "v")
            .unwrap();
        store
            .turn("t-1", "g-1", 1, 0, "main", "queued", None, None, None)
            .unwrap();
        store
            .turn(
                "t-1",
                "g-1",
                1,
                0,
                "main",
                "running",
                Some("sent-1"),
                Some(4),
                None,
            )
            .unwrap();
        assert_eq!(
            store.running_turns().unwrap(),
            [("t-1".to_owned(), "g-1".to_owned(), "main".to_owned())]
        );
        store
            .turn_status("t-1", "failed", Some("the bridge restarted"))
            .unwrap();
        assert!(store.running_turns().unwrap().is_empty());
        assert_eq!(
            store.turn_sent("sent-1", "g-1", "main").unwrap(),
            Some(("t-1".to_owned(), "failed".to_owned(), Some(4)))
        );
        assert_eq!(store.turn_sent("sent-2", "g-1", "main").unwrap(), None);
        // Another member's turn, or another group's, is not this one.
        assert_eq!(store.turn_sent("sent-1", "g-1", "coder").unwrap(), None);
        assert_eq!(store.turn_sent("sent-1", "g-2", "main").unwrap(), None);
    }

    #[test]
    fn a_database_from_before_groups_gets_their_tables_and_speakers() {
        let folder = tempfile::tempdir().unwrap();
        let path = folder.path().join("app.db");
        {
            let db = Connection::open(&path).unwrap();
            db.execute_batch(
                "CREATE TABLE conversations (id TEXT PRIMARY KEY, sandbox TEXT NOT NULL,
                 agent TEXT NOT NULL, owner TEXT NOT NULL, created INTEGER NOT NULL);
                 CREATE TABLE messages (seq INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT NOT NULL UNIQUE,
                 conversation TEXT NOT NULL, person TEXT, text TEXT NOT NULL, kind TEXT NOT NULL, at INTEGER NOT NULL);
                 INSERT INTO conversations VALUES ('c-1', 'lab', 'main', 'v', 1);
                 INSERT INTO messages (id, conversation, person, text, kind, at) VALUES ('m-1', 'c-1', NULL, 'hi', 'reply', 1);",
            )
            .unwrap();
        }
        let store = Store::open(&path).unwrap();
        assert!(!store.conversation_info("c-1").unwrap().unwrap().archived);
        assert_eq!(store.conversation_info("c-1").unwrap().unwrap().revision, 0);
        assert_eq!(store.set_archived("c-1", "v", true).unwrap(), Some(true));
        assert_eq!(store.since("v", 0).unwrap()[0].from, From::Agent);
        store
            .group("g-1", "lab", &["main".into(), "coder".into()], "v")
            .unwrap();
        assert_eq!(store.members("g-1").unwrap().len(), 2);
    }

    #[test]
    fn archiving_is_owned_persistent_and_preserves_the_conversation() {
        let folder = tempfile::tempdir().unwrap();
        let path = folder.path().join("app.db");
        let store = Store::open(&path).unwrap();
        let owner = "victor@example.com";
        store.conversation("c-1", "lab", "main", owner).unwrap();
        store.name("c-1", "Keep this history", BY_PERSON).unwrap();
        let seq = store
            .add("m-1", "c-1", &From::Agent, "first reply", "reply")
            .unwrap()
            .unwrap();
        store.mark_read("c-1", seq).unwrap();
        let file = StoredAttachment {
            id: "a-1".into(),
            conversation: "c-1".into(),
            mime: "text/html".into(),
            name: "report.html".into(),
            size: 123,
        };
        store.add_attachment(&file, "m-1").unwrap();
        let before = store.conversation_info("c-1").unwrap().unwrap();
        assert_eq!(
            store.set_archived("c-1", "someone-else", true).unwrap(),
            None
        );
        assert_eq!(store.set_archived("missing", owner, true).unwrap(), None);
        assert_eq!(
            store.conversation_info("c-1").unwrap(),
            Some(before.clone())
        );
        assert_eq!(store.set_archived("c-1", owner, true).unwrap(), Some(true));
        assert_eq!(store.set_archived("c-1", owner, true).unwrap(), Some(false));
        assert_eq!(
            store.conversation_info("c-1").unwrap(),
            Some(Conversation {
                archived: true,
                revision: before.revision + 1,
                ..before.clone()
            })
        );
        // A reply, a repeated creation and a reconnect never restore it implicitly.
        store
            .add("m-2", "c-1", &From::Agent, "later reply", "notify")
            .unwrap();
        store
            .conversation("c-1", "other", "replacement", "someone-else")
            .unwrap();
        drop(store);
        let store = Store::open(&path).unwrap();
        assert_eq!(
            store.conversation_info("c-1").unwrap(),
            Some(Conversation {
                archived: true,
                revision: before.revision + 1,
                ..before.clone()
            })
        );
        assert_eq!(
            store.conversations(owner).unwrap().len(),
            1,
            "sync includes archived metadata"
        );
        assert!(store.conversations("someone-else").unwrap().is_empty());
        assert_eq!(store.since(owner, 0).unwrap().len(), 2);
        assert_eq!(
            store.messages_after("c-1", 0).unwrap()[0].text,
            "first reply"
        );
        assert_eq!(store.attachments_of("m-1").unwrap(), [file]);
        assert_eq!(store.set_archived("c-1", owner, false).unwrap(), Some(true));
        assert_eq!(
            store.set_archived("c-1", owner, false).unwrap(),
            Some(false)
        );
        assert_eq!(
            store.conversation_info("c-1").unwrap(),
            Some(Conversation {
                revision: before.revision + 2,
                ..before
            })
        );
    }

    #[test]
    fn metadata_revisions_advance_only_with_committed_changes() {
        let folder = tempfile::tempdir().unwrap();
        let path = folder.path().join("app.db");
        let first = Store::open(&path).unwrap();
        let second = Store::open(&path).unwrap();
        first.conversation("c-1", "lab", "main", "owner").unwrap();
        let revision = |store: &Store| store.conversation_info("c-1").unwrap().unwrap().revision;
        assert_eq!(revision(&first), 0);
        first.name("c-1", "Before", BY_AGENT).unwrap();
        assert_eq!(revision(&second), 1);
        first.name("c-1", "Before", BY_AGENT).unwrap();
        assert_eq!(
            revision(&second),
            1,
            "repeated metadata is not another revision"
        );
        second.set_archived("c-1", "owner", true).unwrap();
        assert_eq!(revision(&first), 2);
        second.set_archived("c-1", "owner", true).unwrap();
        second.set_archived("c-1", "other", false).unwrap();
        assert_eq!(revision(&first), 2);
        first.set_archived("c-1", "owner", false).unwrap();
        first.name("c-1", "After", BY_PERSON).unwrap();
        assert_eq!(revision(&second), 4);
        let seq = first
            .add("m-1", "c-1", &From::Agent, "hello", "reply")
            .unwrap()
            .unwrap();
        assert_eq!(revision(&second), 4, "messages have their own sequence");
        second.mark_read("c-1", seq).unwrap();
        assert_eq!(revision(&first), 5);
        second.mark_read("c-1", seq).unwrap();
        first
            .name("c-1", "Agent cannot replace the person's name", BY_AGENT)
            .unwrap();
        assert_eq!(revision(&first), 5);
        first.name("c-1", "", BY_PERSON).unwrap();
        assert_eq!(
            revision(&second),
            6,
            "clearing a title changes metadata too"
        );
        drop(first);
        drop(second);
        assert_eq!(revision(&Store::open(&path).unwrap()), 6);
    }

    #[test]
    fn home_owner_claim_and_group_creation_publish_new_metadata_revisions() {
        let folder = tempfile::tempdir().unwrap();
        let store = Store::open(&folder.path().join("app.db")).unwrap();
        store.ensure_home("lab/main", "", false).unwrap();
        let home = home_id("lab/main");
        assert_eq!(store.conversation_info(&home).unwrap().unwrap().revision, 1);
        store.ensure_home("lab/main", "owner", false).unwrap();
        assert_eq!(store.conversation_info(&home).unwrap().unwrap().revision, 2);
        store.ensure_home("lab/main", "other", false).unwrap();
        assert_eq!(store.conversation_info(&home).unwrap().unwrap().revision, 2);
        // The host's person, once the transport names them, takes it back
        store.ensure_home("lab/main", "host", true).unwrap();
        assert_eq!(store.conversation_info(&home).unwrap().unwrap().revision, 3);
        store.ensure_home("lab/main", "host", true).unwrap();
        assert_eq!(store.conversation_info(&home).unwrap().unwrap().revision, 3);
        store
            .group("g-1", "lab", &["main".into(), "coder".into()], "owner")
            .unwrap();
        assert_eq!(store.conversation_info("g-1").unwrap().unwrap().revision, 1);
        store
            .group("g-1", "lab", &["other".into()], "owner")
            .unwrap();
        assert_eq!(store.conversation_info("g-1").unwrap().unwrap().revision, 1);
        assert_eq!(store.members("g-1").unwrap().len(), 2);
    }

    #[test]
    fn metadata_revision_overflow_cannot_change_the_metadata() {
        let folder = tempfile::tempdir().unwrap();
        let store = Store::open(&folder.path().join("app.db")).unwrap();
        store.conversation("c-1", "lab", "main", "owner").unwrap();
        assert!(
            store
                .db
                .execute(
                    "UPDATE conversations SET revision = -1 WHERE id = 'c-1'",
                    []
                )
                .is_err()
        );
        store
            .db
            .execute(
                "UPDATE conversations SET revision = ?1 WHERE id = 'c-1'",
                [i64::MAX],
            )
            .unwrap();
        let before = store.conversation_info("c-1").unwrap();
        assert!(store.name("c-1", "must not appear", BY_PERSON).is_err());
        assert!(store.set_archived("c-1", "owner", true).is_err());
        assert_eq!(store.conversation_info("c-1").unwrap(), before);
    }

    #[test]
    fn home_archive_is_refused_and_an_archived_home_is_restored_on_open() {
        let folder = tempfile::tempdir().unwrap();
        let path = folder.path().join("app.db");
        let store = Store::open(&path).unwrap();
        let owner = "owner@example.com";
        let home = home_id("lab/main");
        store.ensure_home("lab/main", owner, false).unwrap();
        store.name(&home, "Agent notices", BY_PERSON).unwrap();
        store
            .add("notice", &home, &From::Agent, "scheduled result", "notify")
            .unwrap();
        let before = store.conversation_info(&home).unwrap().unwrap();
        let route = store.conversation_of(&home).unwrap();
        assert_eq!(store.set_archived(&home, owner, true).unwrap(), None);
        assert_eq!(store.conversation_info(&home).unwrap().unwrap(), before);
        assert_eq!(
            store.set_archived(&home, owner, false).unwrap(),
            Some(false)
        );

        // A development build from before the rule could archive Home:
        // opening the database restores it, once, with a new revision.
        store
            .db
            .execute(
                "UPDATE conversations SET archived = 1 WHERE id = ?1",
                [&home],
            )
            .unwrap();
        assert_eq!(
            store.set_archived(&home, "another person", false).unwrap(),
            None
        );
        let store = Store::open(&path).unwrap();
        let restored = store.conversation_info(&home).unwrap().unwrap();
        assert!(!restored.archived);
        assert_eq!(restored.revision, before.revision + 1);
        assert_eq!(restored.title, before.title);
        assert_eq!(store.conversation_of(&home).unwrap(), route);
        assert_eq!(
            store.messages_after(&home, 0).unwrap()[0].text,
            "scheduled result"
        );
        assert_eq!(
            Store::open(&path)
                .unwrap()
                .conversation_info(&home)
                .unwrap()
                .unwrap(),
            restored,
            "only an archived Home is changed"
        );

        // A regular conversation called Home is still an ordinary conversation.
        store
            .conversation("c-home-title", "lab", "main", owner)
            .unwrap();
        store.name("c-home-title", "Home", BY_PERSON).unwrap();
        assert_eq!(
            store.set_archived("c-home-title", owner, true).unwrap(),
            Some(true)
        );
    }

    #[test]
    fn archived_groups_keep_their_routing_and_running_work() {
        let folder = tempfile::tempdir().unwrap();
        let store = Store::open(&folder.path().join("app.db")).unwrap();
        let owner = "victor@example.com";
        store
            .group("g-1", "lab", &["main".into(), "coder".into()], owner)
            .unwrap();
        store
            .turn(
                "t-1",
                "g-1",
                1,
                0,
                "main",
                "running",
                Some("sent-1"),
                Some(4),
                None,
            )
            .unwrap();
        store.saw("g-1", "main", 4).unwrap();
        let members = store.members("g-1").unwrap();
        let turns = store.running_turns().unwrap();
        let route = store.conversation_of("g-1").unwrap();
        assert_eq!(store.set_archived("g-1", owner, true).unwrap(), Some(true));
        assert_eq!(store.members("g-1").unwrap(), members);
        assert_eq!(store.running_turns().unwrap(), turns);
        assert_eq!(store.conversation_of("g-1").unwrap(), route);
        store
            .add(
                "g-reply",
                "g-1",
                &From::Member("main".into()),
                "still working",
                "reply",
            )
            .unwrap();
        assert!(store.conversation_info("g-1").unwrap().unwrap().archived);
        assert_eq!(store.set_archived("g-1", owner, false).unwrap(), Some(true));
        assert!(!store.conversation_info("g-1").unwrap().unwrap().archived);
    }

    #[test]
    fn the_persons_name_wins_over_the_runtimes() {
        let folder = tempfile::tempdir().unwrap();
        let store = Store::open(&folder.path().join("app.db")).unwrap();
        let owner = "victor@example.com";
        store.conversation("c-1", "lab", "main", owner).unwrap();
        let title = |s: &Store| {
            let c = s.conversation_info("c-1").unwrap().unwrap();
            (c.title, c.titled_by)
        };
        assert_eq!(title(&store), (None, None));
        // The runtime names it, and renames it.
        assert!(store.name("c-1", "Weather", BY_AGENT).unwrap());
        assert!(!store.name("c-1", "Weather", BY_AGENT).unwrap());
        assert!(store.name("c-1", "Paris weather", BY_AGENT).unwrap());
        // The person's name replaces it, and the runtime's no longer does.
        assert!(store.name("c-1", " Trip ", BY_PERSON).unwrap());
        assert!(!store.name("c-1", "Paris weather", BY_AGENT).unwrap());
        assert_eq!(title(&store), (Some("Trip".into()), Some(BY_PERSON.into())));
        // Cleared by the person: the runtime may name it again.
        assert!(store.name("c-1", "", BY_PERSON).unwrap());
        assert_eq!(title(&store), (None, None));
        assert!(store.name("c-1", "Paris weather", BY_AGENT).unwrap());
        assert_eq!(
            store.conversations(owner).unwrap()[0].title.as_deref(),
            Some("Paris weather")
        );
        assert!(store.conversations("someone@else").unwrap().is_empty());
    }

    #[test]
    fn how_far_a_conversation_was_read_only_moves_forward_to_its_messages() {
        let folder = tempfile::tempdir().unwrap();
        let store = Store::open(&folder.path().join("app.db")).unwrap();
        let owner = "victor@example.com";
        store.conversation("c-1", "lab", "main", owner).unwrap();
        store.conversation("c-2", "lab", "main", owner).unwrap();
        let read = |s: &Store| s.conversation_info("c-1").unwrap().unwrap().read;
        // Nothing to read yet.
        assert!(!store.mark_read("c-1", 1).unwrap());
        assert_eq!(read(&store), None);
        let hi = store
            .add("m-1", "c-1", &From::Person(owner.into()), "hi", "message")
            .unwrap()
            .unwrap();
        let other = store
            .add("m-2", "c-2", &From::Agent, "elsewhere", "reply")
            .unwrap()
            .unwrap();
        let answer = store
            .add("m-3", "c-1", &From::Agent, "hello", "reply")
            .unwrap()
            .unwrap();
        assert!(store.mark_read("c-1", hi).unwrap());
        assert_eq!(read(&store), Some(hi));
        // Not past its newest message, even to another conversation's seq beyond it.
        assert!(!store.mark_read("c-1", answer + 1).unwrap());
        assert!(other < answer);
        assert!(store.mark_read("c-1", answer).unwrap());
        // Not backwards, and once only.
        assert!(!store.mark_read("c-1", hi).unwrap());
        assert!(!store.mark_read("c-1", answer).unwrap());
        assert_eq!(store.conversations(owner).unwrap()[0].read, Some(answer));
    }

    #[test]
    fn a_name_is_kept_on_one_visible_line_of_at_most_100_characters() {
        let folder = tempfile::tempdir().unwrap();
        let store = Store::open(&folder.path().join("app.db")).unwrap();
        store
            .conversation("c-1", "lab", "main", "victor@example.com")
            .unwrap();
        let title = |s: &Store| s.conversation_info("c-1").unwrap().unwrap().title;
        // An agent's name far above one Noise message is cut.
        assert!(store.name("c-1", &"w".repeat(70_000), BY_AGENT).unwrap());
        assert_eq!(title(&store), Some("w".repeat(MAX_TITLE_CHARS)));
        // A person's too.
        assert!(store.name("c-1", &"p".repeat(500), BY_PERSON).unwrap());
        assert_eq!(title(&store), Some("p".repeat(MAX_TITLE_CHARS)));
        // Lines are joined and hidden characters dropped: a name cannot read
        // as another one.
        let tricky = "Trip\n to\u{2028}Paris \u{202E}fdp.exe\u{200B}";
        assert!(store.name("c-1", tricky, BY_PERSON).unwrap());
        assert_eq!(title(&store), Some("Trip to Paris fdp.exe".into()));
        // A name made of hidden characters only is no name.
        assert!(store.name("c-1", "\u{202E}\u{2066}\n", BY_PERSON).unwrap());
        assert_eq!(title(&store), None);
        // Joined emoji and Persian spelling are kept.
        let kept = "\u{0645}\u{06CC}\u{200C}\u{0647} \u{2764}\u{FE0F}";
        assert_eq!(conversation_title(kept), kept);
    }

    #[test]
    fn a_database_from_an_earlier_bridge_gains_the_name_columns() {
        let folder = tempfile::tempdir().unwrap();
        let path = folder.path().join("app.db");
        {
            let db = Connection::open(&path).unwrap();
            db.execute_batch(
                "CREATE TABLE conversations (id TEXT PRIMARY KEY, sandbox TEXT NOT NULL,
                 agent TEXT NOT NULL, owner TEXT NOT NULL, created INTEGER NOT NULL);
                 INSERT INTO conversations VALUES ('c-1', 'lab', 'main', 'victor@example.com', 1);",
            )
            .unwrap();
        }
        let store = Store::open(&path).unwrap();
        assert!(store.name("c-1", "Weather", BY_AGENT).unwrap());
        assert_eq!(store.conversation_info("c-1").unwrap().unwrap().read, None);
        // Opening it again changes nothing.
        drop(store);
        let store = Store::open(&path).unwrap();
        assert_eq!(
            store
                .conversation_info("c-1")
                .unwrap()
                .unwrap()
                .title
                .as_deref(),
            Some("Weather")
        );
    }

    #[test]
    fn the_database_is_the_users_alone() {
        use std::os::unix::fs::PermissionsExt;
        let folder = tempfile::tempdir().unwrap();
        let path = folder.path().join("app.db");
        Store::open(&path).unwrap();
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&path), 0o600);
        // One made before with another mode is made the user's alone too
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        Store::open(&path).unwrap();
        assert_eq!(mode(&path), 0o600);
    }

    #[test]
    fn messages_keep_their_order_owner_and_are_stored_once() {
        let folder = tempfile::tempdir().unwrap();
        let store = Store::open(&folder.path().join("app.db")).unwrap();
        let owner = "victor@example.com";
        assert_eq!(
            store.conversation("c-1", "lab", "main", owner).unwrap(),
            ("lab".into(), "main".into(), owner.into())
        );
        // Known already: its owner does not change.
        assert_eq!(
            store
                .conversation("c-1", "lab", "scout", "alice@example.com")
                .unwrap()
                .2,
            owner
        );
        store
            .conversation("c-2", "lab", "main", "alice@example.com")
            .unwrap();
        let first = store
            .add("m-1", "c-1", &From::Person(owner.into()), "hi", "message")
            .unwrap()
            .unwrap();
        assert_eq!(
            store
                .add("m-1", "c-1", &From::Agent, "again", "reply")
                .unwrap(),
            None
        );
        store
            .add("m-2", "c-1", &From::Agent, "hello", "reply")
            .unwrap()
            .unwrap();
        store
            .add("m-3", "c-2", &From::Agent, "not yours", "notify")
            .unwrap()
            .unwrap();
        let mine = store.since(owner, 0).unwrap();
        assert_eq!(
            mine.iter().map(|m| m.text.as_str()).collect::<Vec<_>>(),
            ["hi", "hello"]
        );
        assert_eq!(mine[1].from, From::Agent);
        // The time it was stored, which a sync gives the device.
        assert!(mine.iter().all(|m| (now() - m.at).abs() < 60));
        assert_eq!(store.since(owner, first).unwrap().len(), 1);
        assert_eq!(
            store.owner("c-2").unwrap().as_deref(),
            Some("alice@example.com")
        );
        assert_eq!(store.owner("c-9").unwrap(), None);
    }

    #[test]
    fn a_device_message_is_stored_once_and_pending_until_delivered() {
        let folder = tempfile::tempdir().unwrap();
        let store = Store::open(&folder.path().join("app.db")).unwrap();
        let owner = "victor@example.com";
        store.conversation("c-1", "lab", "main", owner).unwrap();
        store.conversation("c-2", "lab", "scout", owner).unwrap();
        let first = store
            .add_from_device("d-1/m-1", "b-1", "c-1", owner, "hi")
            .unwrap();
        assert!(matches!(first, Added::New(_)));
        // The same envelope again, whatever id the bridge would give it
        assert_eq!(
            store
                .add_from_device("d-1/m-1", "b-2", "c-1", owner, "hi")
                .unwrap(),
            Added::Again
        );
        // Another device may use the same envelope id
        assert!(matches!(
            store
                .add_from_device("d-2/m-1", "b-3", "c-2", owner, "yo")
                .unwrap(),
            Added::New(_)
        ));
        assert_eq!(store.since(owner, 0).unwrap().len(), 2);
        let pending = store.pending("lab", "main").unwrap();
        assert_eq!(
            pending,
            [Pending {
                id: "b-1".into(),
                conversation: "c-1".into(),
                person: owner.into(),
                text: "hi".into(),
            }]
        );
        assert_eq!(
            store.agents_with_pending().unwrap().len(),
            2,
            "both agents wait"
        );
        // Another agent's plugin cannot mark it delivered
        assert_eq!(
            store.delivered("b-1", "lab/scout").unwrap(),
            Acked::NotItsOwn
        );
        assert_eq!(store.pending("lab", "main").unwrap().len(), 1);
        assert_eq!(
            store.delivered("b-1", "lab/main").unwrap(),
            Acked::Delivered
        );
        assert!(store.pending("lab", "main").unwrap().is_empty());
        // Given again, or of something that was never pending
        assert_eq!(store.delivered("b-1", "lab/main").unwrap(), Acked::Nothing);
        assert!(store.delivered("b-1", "no-slash").is_err());
        assert_eq!(
            store.agents_with_pending().unwrap(),
            [("lab".to_owned(), "scout".to_owned())]
        );
    }

    #[test]
    fn a_text_in_pieces_is_stored_whole_or_not_at_all() {
        let folder = tempfile::tempdir().unwrap();
        let store = Store::open(&folder.path().join("app.db")).unwrap();
        store
            .conversation("c-1", "lab", "main", "victor@example.com")
            .unwrap();
        let pieces = [
            ("a-1".to_owned(), "one".to_owned()),
            ("a-2".to_owned(), "two".to_owned()),
        ];
        let seqs = store
            .add_pieces(&pieces, "c-1", &From::Agent, "reply", &[])
            .unwrap()
            .unwrap();
        assert_eq!(seqs.len(), 2);
        assert!(seqs[0] < seqs[1]);
        // The plugin sent it again: a duplicate, nothing more stored
        let again = [
            ("a-1".to_owned(), "one".to_owned()),
            ("a-3".to_owned(), "two".to_owned()),
        ];
        assert_eq!(
            store
                .add_pieces(&again, "c-1", &From::Agent, "reply", &[])
                .unwrap(),
            None
        );
        assert_eq!(store.since("victor@example.com", 0).unwrap().len(), 2);
    }

    #[test]
    fn suggested_replies_are_atomic_with_the_last_piece_and_survive_reopen() {
        let folder = tempfile::tempdir().unwrap();
        let path = folder.path().join("app.db");
        let store = Store::open(&path).unwrap();
        store.conversation("c", "lab", "main", "owner").unwrap();
        let pieces = [
            ("first".into(), "A short explanation".into()),
            ("last".into(), "Choose a next step".into()),
        ];
        let replies = vec!["Fix Inbox filters".into(), "Keep paused".into()];
        assert!(
            store
                .add_pieces_with_replies(&pieces, "c", &From::Agent, "reply", &[], &replies)
                .unwrap()
                .is_some()
        );
        assert!(
            store
                .add_pieces_with_replies(
                    &pieces,
                    "c",
                    &From::Agent,
                    "reply",
                    &[],
                    &["Changed".into()]
                )
                .unwrap()
                .is_none()
        );
        drop(store);
        let restored = Store::open(&path).unwrap();
        let messages = restored.messages_after("c", 0).unwrap();
        assert!(messages[0].suggested_replies.is_empty());
        assert_eq!(messages[1].suggested_replies, replies);
    }

    #[test]
    fn the_log_keeps_its_newest_lines_only() {
        let folder = tempfile::tempdir().unwrap();
        let store = Store::open(&folder.path().join("app.db")).unwrap();
        for n in 0..LOG_KEPT + 5 {
            store
                .log(None, None, "refused", Some(&n.to_string()))
                .unwrap();
        }
        let lines = store.log_lines(LOG_KEPT * 2).unwrap();
        assert_eq!(lines.len() as i64, LOG_KEPT);
        assert_eq!(lines[0].reason.as_deref(), Some("5"));
        assert_eq!(
            lines.last().unwrap().reason.as_deref(),
            Some((LOG_KEPT + 4).to_string().as_str())
        );
    }

    #[test]
    fn opening_it_from_two_places_at_once_adds_each_column_once() {
        for _ in 0..20 {
            let folder = tempfile::tempdir().unwrap();
            let path = folder.path().join("app.db");
            let opens: Vec<_> = (0..4)
                .map(|_| {
                    let path = path.clone();
                    std::thread::spawn(move || Store::open(&path).map(|_| ()))
                })
                .collect();
            for open in opens {
                // "database is locked" is the other way two opens can meet;
                // it is not this test's
                match open.join().unwrap() {
                    Ok(()) => {}
                    Err(rusqlite::Error::SqliteFailure(e, _))
                        if e.code == rusqlite::ErrorCode::DatabaseBusy => {}
                    Err(e) => panic!("{e}"),
                }
            }
        }
    }

    #[test]
    fn an_older_database_gets_the_new_columns() {
        let folder = tempfile::tempdir().unwrap();
        let path = folder.path().join("app.db");
        // The first version's tables, with a device in them
        let db = Connection::open(&path).unwrap();
        db.execute_batch(SCHEMA).unwrap();
        db.execute(
            "INSERT INTO devices (id, name, person, noise_key, device_key, push_key, paired) VALUES ('d-1', 'Pixel', 'v@example.com', x'01', x'02', x'03', 1)",
            [],
        )
        .unwrap();
        drop(db);
        let store = Store::open(&path).unwrap();
        let device = store.device("d-1").unwrap().unwrap();
        assert_eq!(device.node, None);
        // Opening it again changes nothing
        drop(store);
        Store::open(&path).unwrap();
    }

    #[test]
    fn a_pairing_takes_the_first_word_and_then_its_outcome() {
        let folder = tempfile::tempdir().unwrap();
        let store = Store::open(&folder.path().join("app.db")).unwrap();
        let decision = |s: &Store, code: &[u8]| s.pairing_decision(code).unwrap();
        // Accepted, then the device got its answer.
        store.add_pairing(b"one", now() + 300).unwrap();
        assert!(store.decide_pairing(b"one", "accept").unwrap());
        assert!(!store.decide_pairing(b"one", "decline").unwrap());
        store.settle_pairing(b"one", "paired", Some("d-1")).unwrap();
        assert_eq!(decision(&store, b"one").as_deref(), Some("paired"));
        assert_eq!(store.paired_device(b"one").unwrap().as_deref(), Some("d-1"));
        // The device left first: the terminal's answer comes too late.
        store.add_pairing(b"two", now() + 300).unwrap();
        assert!(store.decide_pairing(b"two", "gone").unwrap());
        assert!(!store.decide_pairing(b"two", "accept").unwrap());
        assert_eq!(decision(&store, b"two").as_deref(), Some("gone"));
        // An outcome settles an accepted pairing only.
        store.add_pairing(b"three", now() + 300).unwrap();
        assert!(store.decide_pairing(b"three", "decline").unwrap());
        store
            .settle_pairing(b"three", "paired", Some("d-3"))
            .unwrap();
        assert_eq!(store.paired_device(b"three").unwrap(), None);
        assert_eq!(decision(&store, b"three").as_deref(), Some("decline"));
    }

    #[test]
    fn an_agents_home_is_made_once_named_home_for_its_owner() {
        let folder = tempfile::tempdir().unwrap();
        let store = Store::open(&folder.path().join("app.db")).unwrap();
        assert_eq!(home_id("lab/main"), "home.lab.main");
        assert!(is_home("home.lab.main") && !is_home("a47e17c0-eaad-4d1d-8853-56aa0b69e1e2"));
        assert!(
            store
                .ensure_home("lab/main", "victor@example.com", true)
                .unwrap()
        );
        assert!(
            !store
                .ensure_home("lab/main", "victor@example.com", true)
                .unwrap()
        );
        // Once: a second person, who is not the host, does not take it.
        assert!(
            !store
                .ensure_home("lab/main", "alice@example.com", false)
                .unwrap()
        );
        assert_eq!(
            store.owner("home.lab.main").unwrap().as_deref(),
            Some("victor@example.com")
        );
        let home = store.conversation_info("home.lab.main").unwrap().unwrap();
        assert_eq!(
            (home.sandbox.as_str(), home.agent.as_str()),
            ("lab", "main")
        );
        assert_eq!(
            (home.title.as_deref(), home.titled_by.as_deref()),
            (Some("Home"), Some(BY_PERSON))
        );
        // The runtime's name for its session does not replace Home.
        assert!(
            !store
                .name("home.lab.main", "Gateway notices", BY_AGENT)
                .unwrap()
        );
        assert!(
            !store
                .ensure_home("no-slash", "victor@example.com", true)
                .unwrap()
        );
        // Made before anyone was known: the first person takes it, once.
        assert!(store.ensure_home("lab/scout", "", false).unwrap());
        assert_eq!(store.owner("home.lab.scout").unwrap().as_deref(), Some(""));
        assert!(
            store
                .ensure_home("lab/scout", "alice@example.com", false)
                .unwrap()
        );
        assert!(
            !store
                .ensure_home("lab/scout", "victor@example.com", false)
                .unwrap()
        );
        assert_eq!(
            store.owner("home.lab.scout").unwrap().as_deref(),
            Some("alice@example.com")
        );
        // Given as the host's person's, Home is theirs.
        assert!(
            store
                .ensure_home("lab/scout", "victor@example.com", true)
                .unwrap()
        );
        assert_eq!(
            store.owner("home.lab.scout").unwrap().as_deref(),
            Some("victor@example.com")
        );
        assert!(!store.ensure_home("lab/scout", "", false).unwrap());
    }

    #[test]
    fn the_first_person_named_is_the_host_until_another_is_set() {
        let folder = tempfile::tempdir().unwrap();
        let path = folder.path().join("app.db");
        let store = Store::open(&path).unwrap();
        assert_eq!(store.host_person().unwrap(), None);
        assert!(store.claim_host("victor@example.com").unwrap());
        // A second device's person does not take it.
        assert!(!store.claim_host("alice@example.com").unwrap());
        assert_eq!(
            Store::open(&path)
                .unwrap()
                .host_person()
                .unwrap()
                .as_deref(),
            Some("victor@example.com")
        );
        // Set: the host's person, with every agent's Home, and no other
        // conversation.
        store
            .ensure_home("lab/main", "victor@example.com", true)
            .unwrap();
        store.ensure_home("lab/scout", "", false).unwrap();
        store
            .conversation("c-1", "lab", "main", "victor@example.com")
            .unwrap();
        store.set_host("alice@example.com").unwrap();
        assert_eq!(
            store.host_person().unwrap().as_deref(),
            Some("alice@example.com")
        );
        for (id, owner) in [
            ("home.lab.main", "alice@example.com"),
            ("home.lab.scout", "alice@example.com"),
            ("c-1", "victor@example.com"),
        ] {
            assert_eq!(store.owner(id).unwrap().as_deref(), Some(owner), "{id}");
        }
    }

    #[test]
    fn home_taken_by_the_hosts_person_is_not_archived_for_them() {
        let folder = tempfile::tempdir().unwrap();
        let store = Store::open(&folder.path().join("app.db")).unwrap();
        store
            .ensure_home("lab/main", "guest@example.com", false)
            .unwrap();
        store
            .set_archived("home.lab.main", "guest@example.com", true)
            .unwrap();
        store
            .ensure_home("lab/main", "victor@example.com", true)
            .unwrap();
        let home = store
            .conversations("victor@example.com")
            .unwrap()
            .into_iter()
            .find(|c| c.id == "home.lab.main")
            .unwrap();
        assert!(!home.archived);
    }

    #[test]
    fn a_device_chosen_id_is_never_a_home() {
        let folder = tempfile::tempdir().unwrap();
        let store = Store::open(&folder.path().join("app.db")).unwrap();
        // `LIKE` would take this one: it ignores case
        store
            .conversation("Home.lab.main", "lab", "main", "bob@example.com")
            .unwrap();
        // Made by a device before the bridge kept `home.`, for another agent
        store
            .conversation("home.lab.scout", "lab", "main", "bob@example.com")
            .unwrap();
        assert!(
            !store
                .ensure_home("lab/scout", "victor@example.com", true)
                .unwrap()
        );
        store.set_host("victor@example.com").unwrap();
        assert_eq!(
            store.owner("Home.lab.main").unwrap().as_deref(),
            Some("bob@example.com")
        );
        assert_eq!(
            store
                .conversation_of("home.lab.scout")
                .unwrap()
                .map(|c| c.0),
            Some("lab".to_owned())
        );
    }

    #[test]
    fn devices_paired_before_the_host_was_kept_name_it() {
        let folder = tempfile::tempdir().unwrap();
        let path = folder.path().join("app.db");
        let store = Store::open(&path).unwrap();
        for (id, person, paired) in [
            ("d-2", "alice@example.com", 20),
            ("d-1", "victor@example.com", 10),
        ] {
            store
                .add_device(&Device {
                    id: id.to_owned(),
                    name: "Pixel".to_owned(),
                    person: person.to_owned(),
                    noise_key: vec![paired as u8; 32],
                    device_key: vec![2; 32],
                    push_key: vec![3; 32],
                    push_token: None,
                    paired,
                    seen: None,
                    node: None,
                })
                .unwrap();
        }
        // As a database from before the setting
        store
            .db
            .execute("DELETE FROM settings WHERE name = ?1", params![HOST_PERSON])
            .unwrap();
        let store = Store::open(&path).unwrap();
        assert_eq!(
            store.host_person().unwrap().as_deref(),
            Some("victor@example.com")
        );
        // So the next device's person does not become it
        assert!(!store.claim_host("bob@example.com").unwrap());
    }

    #[test]
    fn a_database_from_before_models_keeps_its_usage_under_no_model() {
        let folder = tempfile::tempdir().unwrap();
        let path = folder.path().join("app.db");
        {
            let store = Store::open(&path).unwrap();
            store.conversation("c-1", "lab", "main", "alice").unwrap();
            // The tables as the bridge of 0.5 made them, with a row each.
            store
                .db
                .execute_batch(
                    "DROP TABLE usage_hours; DROP TABLE agent_usage_hours;
                     CREATE TABLE usage_hours (
                         conversation TEXT NOT NULL REFERENCES conversations(id),
                         agent TEXT NOT NULL, hour INTEGER NOT NULL CHECK(hour >= 0),
                         calls INTEGER NOT NULL CHECK(calls >= 0), input INTEGER, output INTEGER,
                         cache_read INTEGER, cache_write INTEGER, reasoning INTEGER,
                         PRIMARY KEY (conversation, agent, hour));
                     CREATE TABLE agent_usage_hours (
                         agent TEXT NOT NULL, hour INTEGER NOT NULL CHECK(hour >= 0),
                         calls INTEGER NOT NULL CHECK(calls >= 0), input INTEGER, output INTEGER,
                         cache_read INTEGER, cache_write INTEGER, reasoning INTEGER,
                         PRIMARY KEY (agent, hour));
                     INSERT INTO usage_hours VALUES ('c-1', 'main', 500000, 2, 10, 1, NULL, NULL, NULL);
                     INSERT INTO agent_usage_hours VALUES ('lab/main', 500000, 3, 7, NULL, NULL, NULL, NULL);",
                )
                .unwrap();
        }
        let store = Store::open(&path).unwrap();
        // Opened again by another process: nothing left to do.
        Store::open(&path).unwrap();
        let totals = store.usage_since("alice", 0, true).unwrap();
        assert_eq!(totals.len(), 1);
        assert_eq!(totals[0].1.calls, 5);
        assert_eq!(totals[0].1.tokens.input, Some(17));
        assert_eq!(totals[0].1.tokens.output, Some(1));
        let unsaid: i64 = store
            .db
            .query_row(
                "SELECT COUNT(*) FROM usage_hours WHERE model = '' AND provider = ''",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(unsaid, 1);
        // A report naming its model is kept apart from the old row.
        store
            .add_usage_by(
                "c-1",
                "main",
                500_000 * 3600,
                Served {
                    model: Some("gpt-5.5"),
                    provider: Some("openai"),
                },
                1,
                UsageTokens {
                    input: Some(1),
                    ..UsageTokens::default()
                },
            )
            .unwrap();
        let rows: i64 = store
            .db
            .query_row("SELECT COUNT(*) FROM usage_hours", [], |r| r.get(0))
            .unwrap();
        assert_eq!(rows, 2);
    }

    #[test]
    fn past_eight_models_an_hour_a_report_counts_under_none() {
        let folder = tempfile::tempdir().unwrap();
        let store = Store::open(&folder.path().join("app.db")).unwrap();
        store.conversation("c-1", "lab", "main", "alice").unwrap();
        let one = UsageTokens {
            input: Some(1),
            ..UsageTokens::default()
        };
        let models: Vec<String> = (0..12).map(|i| format!("m{i}")).collect();
        for model in &models {
            let served = Served {
                model: Some(model.as_str()),
                provider: Some("nous"),
            };
            store
                .add_usage_by("c-1", "main", 3_600, served, 1, one)
                .unwrap();
            store
                .add_agent_usage_by("lab/main", 3_600, served, 1, one)
                .unwrap();
        }
        // A model already kept still counts under its own name.
        store
            .add_usage_by(
                "c-1",
                "main",
                3_600,
                Served {
                    model: Some("m0"),
                    provider: Some("nous"),
                },
                1,
                one,
            )
            .unwrap();
        for table in ["usage_hours", "agent_usage_hours"] {
            let count = |sql: &str| -> i64 {
                store
                    .db
                    .query_row(&format!("SELECT {sql} FROM {table}"), [], |r| r.get(0))
                    .unwrap()
            };
            assert_eq!(count("COUNT(*)"), MODELS_AN_HOUR + 1, "{table}");
            assert_eq!(count("SUM(model = '')"), 1, "{table}");
        }
        assert_eq!(store.usage("c-1").unwrap().unwrap().calls, 13);
    }

    #[test]
    fn a_window_prices_each_model_sums_each_sandbox_and_gives_a_scopes_sum_over_time() {
        let folder = tempfile::tempdir().unwrap();
        let store = Store::open(&folder.path().join("app.db")).unwrap();
        store.conversation("c-a", "lab", "main", "alice").unwrap();
        store.conversation("c-b", "lab", "scout", "alice").unwrap();
        store.conversation("c-c", "work", "main", "alice").unwrap();
        let million = UsageTokens {
            input: Some(1_000_000),
            output: Some(0),
            ..UsageTokens::default()
        };
        let opus = Served {
            model: Some("claude-opus-5-5"),
            provider: Some("anthropic"),
        };
        let codex = Served {
            model: Some("gpt-5.5"),
            provider: Some("openai-codex"),
        };
        let day = 86_400;
        store
            .add_usage_by("c-a", "main", day, opus, 1, million)
            .unwrap();
        store
            .add_usage_by("c-a", "main", 2 * day, codex, 1, million)
            .unwrap();
        store
            .add_usage_by("c-b", "scout", 2 * day, Served::default(), 1, million)
            .unwrap();
        store
            .add_usage_by("c-c", "main", 2 * day, opus, 1, million)
            .unwrap();
        let prices = crate::pricing::PriceList::bundled();
        let opus_cost = prices.cost(opus.provider, opus.model, million.into());
        assert!(opus_cost.usd_micros > 0);
        let ask = |scope, series, sum| WindowAsk {
            owner: Some("alice"),
            since: 0,
            outside: false,
            series,
            scope,
            sum,
        };
        let host = store
            .usage_report(&ask(Scope::Host, None, false), &prices)
            .unwrap();
        let names: Vec<&str> = host.agents.iter().map(|(a, _, _)| a.as_str()).collect();
        assert_eq!(names, ["lab/main", "lab/scout", "work/main"]);
        assert_eq!(host.agents[0].2.usd_micros, opus_cost.usd_micros);
        assert_eq!(host.agents[0].2.included, 1_000_000);
        // A report naming no model: unpriced.
        assert_eq!(host.agents[1].2.unpriced, 1_000_000);
        let lab = &host.sandboxes[0];
        assert_eq!(lab.sandbox, "lab");
        assert_eq!(lab.total.calls, 3);
        assert_eq!(
            (lab.cost.usd_micros, lab.cost.included, lab.cost.unpriced),
            (opus_cost.usd_micros, 1_000_000, 1_000_000)
        );
        assert_eq!(host.sandboxes[1].sandbox, "work");
        assert!(host.sum.is_empty() && host.series.is_empty());
        // One sandbox, by the day: its agents and its sum, priced.
        let lab = store
            .usage_report(
                &ask(Scope::Sandbox("lab"), Some((86_400, 0)), true),
                &prices,
            )
            .unwrap();
        assert_eq!(lab.agents.len(), 2);
        assert_eq!(lab.sandboxes.len(), 1);
        let at: Vec<u64> = lab.sum.iter().map(|p| p.at).collect();
        assert_eq!(at, [86_400, 2 * 86_400]);
        assert_eq!(lab.sum[0].cost, Some(opus_cost));
        let second = lab.sum[1].cost.unwrap();
        assert_eq!(
            (second.usd_micros, second.included, second.unpriced),
            (0, 1_000_000, 1_000_000)
        );
        assert_eq!(lab.sum[1].tokens, Some(2_000_000));
        assert!(
            lab.series
                .iter()
                .all(|s| s.points.iter().all(|p| p.cost.is_none()))
        );
        // One agent.
        let main = store
            .usage_report(
                &ask(
                    Scope::Agent {
                        sandbox: "work",
                        agent: "main",
                    },
                    Some((86_400, 0)),
                    true,
                ),
                &prices,
            )
            .unwrap();
        assert_eq!(main.agents.len(), 1);
        assert_eq!(main.agents[0].0, "work/main");
        assert_eq!(main.sum.len(), 1);
        // Every person's, for the host's own CLI.
        store.conversation("c-d", "lab", "main", "bob").unwrap();
        store
            .add_usage_by("c-d", "main", day, opus, 1, million)
            .unwrap();
        let all = store
            .usage_report(
                &WindowAsk {
                    owner: None,
                    ..ask(Scope::Host, None, false)
                },
                &prices,
            )
            .unwrap();
        assert_eq!(all.agents[0].1.calls, 3);
        let own = store
            .usage_report(&ask(Scope::Host, None, false), &prices)
            .unwrap();
        assert_eq!(own.agents[0].1.calls, 2);
    }

    #[test]
    fn a_scope_covers_its_sandbox_or_its_agent_alone() {
        assert!(Scope::Host.covers("lab/main"));
        assert!(Scope::Sandbox("lab").covers("lab/main"));
        assert!(!Scope::Sandbox("lab").covers("labs/main"));
        assert!(!Scope::Sandbox("la").covers("lab/main"));
        let main = Scope::Agent {
            sandbox: "lab",
            agent: "main",
        };
        assert!(main.covers("lab/main"));
        assert!(!main.covers("lab/mainly") && !main.covers("work/main"));
    }
}
