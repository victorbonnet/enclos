//! The bridge's conversations and messages, in its own SQLite database
//! beside enclos's state (`app.db`). Every conversation has an owner and
//! every message a person or the agent (ADR 0043, proposed), and `seq`
//! orders all of a host's messages, so a device catches up from one number
//! (`docs/protocol.md`, sync).

use std::path::Path;

use rusqlite::{Connection, OptionalExtension, params};

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

fn message_row(row: &rusqlite::Row) -> rusqlite::Result<Message> {
    let person: Option<String> = row.get(3)?;
    let speaker: Option<String> = row.get(7)?;
    Ok(Message {
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

/// A conversation named by its runtime.
pub const BY_AGENT: &str = "agent";
/// A conversation named by its owner.
pub const BY_PERSON: &str = "person";

/// The id of agent `<sandbox>/<agent>`'s Home conversation, where what has
/// no conversation of its own goes (ADR 0044). Fixed, so the bridge and the
/// runtime, which `runtime configure` tells, agree on it without asking;
/// without `:` or `/`, which runtimes put in their own keys.
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
    let cut: String = words.join(" ").chars().take(MAX_TITLE_CHARS).collect();
    cut.trim_end().to_owned()
}

pub struct Store {
    db: Connection,
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
    Ok(())
}

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS agent_avatars (agent TEXT PRIMARY KEY, revision INTEGER NOT NULL CHECK(revision>=0), version TEXT, image BLOB);
CREATE TABLE IF NOT EXISTS approvals (id TEXT PRIMARY KEY, body TEXT NOT NULL, state TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS approval_marks (name TEXT PRIMARY KEY, at INTEGER NOT NULL);
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
    at INTEGER NOT NULL
);
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
CREATE TABLE IF NOT EXISTS log (
    at INTEGER NOT NULL,
    device TEXT,
    person TEXT,
    event TEXT NOT NULL,
    reason TEXT
);
";

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

/// What became of a device's message given to [`Store::add_from_device`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Added {
    /// Stored, with its place in the order.
    New(i64),
    /// Sent before: stored then, and not again.
    Again,
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

impl Store {
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
    /// Every policy request, decided ones too, beyond the inbox's window.
    pub fn all_approvals(&self) -> rusqlite::Result<Vec<enclos_protocol::approval::Approval>> {
        let mut q = self.db.prepare("SELECT body, state FROM approvals")?;
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
        Ok(self.db.execute(
            "INSERT OR IGNORE INTO approvals VALUES (?1,?2,?3)",
            params![a.request, body, a.state],
        )? == 1)
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
        Ok((self.db.execute(
            "UPDATE approvals SET body=?2,state='diagnostic' WHERE id=?1 AND state='pending' AND body=?3",
            params![a.request, body, serde_json::to_string(a).map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?],
        )? == 1)
            .then_some(closed))
    }
    pub fn put_approval(&self, a: &enclos_protocol::approval::Approval) -> rusqlite::Result<()> {
        let body = serde_json::to_string(a)
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
        self.db.execute(
            "UPDATE approvals SET body=?2,state=?3 WHERE id=?1 AND state='applying'",
            params![a.request, body, a.state],
        )?;
        Ok(())
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
        db.execute_batch(
            "CREATE UNIQUE INDEX IF NOT EXISTS messages_origin ON messages(origin);
             CREATE INDEX IF NOT EXISTS messages_pending ON messages(pending) WHERE pending = 1;",
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

    /// Archives or restores an owner's conversation. `None` means unknown or
    /// owned by someone else; `Some` says whether the flag changed. Content,
    /// routing, read positions and running work are untouched.
    pub fn set_archived(
        &self,
        id: &str,
        owner: &str,
        archived: bool,
    ) -> rusqlite::Result<Option<bool>> {
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
    /// do not replace it. With `host` true, `owner` is the host's person as
    /// the transport names them, and takes Home from anyone else (a person
    /// it went to while the host was not known). Otherwise `owner` takes it
    /// only when it has no owner. Whether it was made or changed owner.
    pub fn ensure_home(&self, agent: &str, owner: &str, host: bool) -> rusqlite::Result<bool> {
        let Some((sandbox, name)) = agent.split_once('/') else {
            return Ok(false);
        };
        let id = home_id(agent);
        if self.conversation_of(&id)?.is_some() {
            if owner.is_empty() {
                return Ok(false);
            }
            let changed = if host {
                self.db.execute(
                    "UPDATE conversations SET owner = ?2, revision = revision + 1 WHERE id = ?1 AND owner != ?2",
                    params![id, owner],
                )?
            } else {
                self.db.execute(
                    "UPDATE conversations SET owner = ?2, revision = revision + 1 WHERE id = ?1 AND owner = ''",
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

    /// Stores the pieces of one text, each with its id, all or none: when
    /// the first id is known already the whole text is a duplicate, and
    /// `None` comes back; else each piece's `seq`.
    pub fn add_pieces(
        &self,
        pieces: &[(String, String)],
        conversation: &str,
        from: &From,
        kind: &str,
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
        transaction.commit()?;
        Ok(Some(seqs))
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

    /// The messages still to give `sandbox`/`agent`'s plugin, oldest first.
    pub fn pending(&self, sandbox: &str, agent: &str) -> rusqlite::Result<Vec<Pending>> {
        let mut query = self.db.prepare(
            "SELECT m.id, m.conversation, m.person, m.text FROM messages m
             JOIN conversations c ON c.id = m.conversation
             WHERE m.pending = 1 AND c.sandbox = ?1 AND c.agent = ?2 ORDER BY m.seq",
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

    /// The plugin acknowledged message `id`: it is the runtime's now.
    pub fn delivered(&self, id: &str) -> rusqlite::Result<()> {
        self.db
            .execute("UPDATE messages SET pending = 0 WHERE id = ?1", params![id])?;
        Ok(())
    }

    /// The messages of `owner`'s conversations after `since`, in order.
    pub fn since(&self, owner: &str, since: i64) -> rusqlite::Result<Vec<Message>> {
        let mut query = self.db.prepare(
            "SELECT m.seq, m.id, m.conversation, m.person, m.text, m.kind, m.at, m.speaker FROM messages m
             JOIN conversations c ON c.id = m.conversation
             WHERE c.owner = ?1 AND m.seq > ?2 ORDER BY m.seq",
        )?;
        let rows = query.query_map(params![owner, since], message_row)?;
        rows.collect()
    }

    /// The messages of conversation `id` after `since`, in order.
    pub fn messages_after(&self, id: &str, since: i64) -> rusqlite::Result<Vec<Message>> {
        let mut query = self.db.prepare(
            "SELECT seq, id, conversation, person, text, kind, at, speaker FROM messages
             WHERE conversation = ?1 AND seq > ?2 ORDER BY seq",
        )?;
        let rows = query.query_map(params![id, since], message_row)?;
        rows.collect()
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
        let (_, _, owner) = self.conversation(id, sandbox, "", owner)?;
        let known = !self.members(id)?.is_empty();
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

    pub fn set_push_token(&self, id: &str, token: &str) -> rusqlite::Result<()> {
        self.db.execute(
            "UPDATE devices SET push_token = ?2 WHERE id = ?1",
            params![id, token],
        )?;
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
mod tests {
    use super::*;

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
    fn archived_groups_and_home_keep_their_routing_and_running_work() {
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
        store.ensure_home("lab/main", owner, false).unwrap();
        let home = home_id("lab/main");
        assert_eq!(store.set_archived(&home, owner, true).unwrap(), Some(true));
        store.ensure_home("lab/main", owner, false).unwrap();
        store
            .add(
                "home-notify",
                &home,
                &From::Agent,
                "scheduled result",
                "notify",
            )
            .unwrap();
        let info = store.conversation_info(&home).unwrap().unwrap();
        assert!(info.archived);
        assert_eq!(info.title.as_deref(), Some("Home"));
        assert_eq!(store.owner(&home).unwrap().as_deref(), Some(owner));
        assert_eq!(
            store.messages_after(&home, 0).unwrap()[0].text,
            "scheduled result"
        );
        for id in ["g-1", home.as_str()] {
            assert_eq!(store.set_archived(id, owner, false).unwrap(), Some(true));
            assert!(!store.conversation_info(id).unwrap().unwrap().archived);
        }
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
        store.delivered("b-1").unwrap();
        assert!(store.pending("lab", "main").unwrap().is_empty());
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
            .add_pieces(&pieces, "c-1", &From::Agent, "reply")
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
                .add_pieces(&again, "c-1", &From::Agent, "reply")
                .unwrap(),
            None
        );
        assert_eq!(store.since("victor@example.com", 0).unwrap().len(), 2);
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
        // Once the transport names the host's person, Home is theirs.
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
}
