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
}

fn conversation_row(row: &rusqlite::Row) -> rusqlite::Result<Conversation> {
    Ok(Conversation {
        id: row.get(0)?,
        sandbox: row.get(1)?,
        agent: row.get(2)?,
        title: row.get(3)?,
        titled_by: row.get(4)?,
        read: row.get(5)?,
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
    let mut query = db.prepare("SELECT name FROM pragma_table_info('conversations')")?;
    let columns = query
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    for (column, kind) in [
        ("title", "TEXT"),
        ("titled_by", "TEXT"),
        ("read", "INTEGER"),
    ] {
        if !columns.iter().any(|c| c == column) {
            db.execute_batch(&format!(
                "ALTER TABLE conversations ADD COLUMN {column} {kind}"
            ))?;
        }
    }
    // A group's agent messages say which member spoke (ADR 0045, proposed).
    let mut query = db.prepare("SELECT name FROM pragma_table_info('messages')")?;
    let columns = query
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    if !columns.iter().any(|c| c == "speaker") {
        db.execute_batch("ALTER TABLE messages ADD COLUMN speaker TEXT")?;
    }
    Ok(())
}

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS agent_avatars (agent TEXT PRIMARY KEY, revision INTEGER NOT NULL CHECK(revision>=0), version TEXT, image BLOB);
CREATE TABLE IF NOT EXISTS approvals (id TEXT PRIMARY KEY, body TEXT NOT NULL, state TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS conversations (
    id TEXT PRIMARY KEY,
    sandbox TEXT NOT NULL,
    agent TEXT NOT NULL,
    owner TEXT NOT NULL,
    created INTEGER NOT NULL,
    title TEXT,
    titled_by TEXT,
    read INTEGER
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

    pub fn open(path: &Path) -> rusqlite::Result<Store> {
        let db = Connection::open(path)?;
        db.busy_timeout(std::time::Duration::from_secs(5))?;
        db.execute_batch(SCHEMA)?;
        upgrade(&db)?;
        Ok(Store { db })
    }

    /// The person's conversations, the oldest first.
    pub fn conversations(&self, owner: &str) -> rusqlite::Result<Vec<Conversation>> {
        let mut query = self.db.prepare(
            "SELECT id, sandbox, agent, title, titled_by, read FROM conversations WHERE owner = ?1 ORDER BY created, id",
        )?;
        let rows = query.query_map(params![owner], conversation_row)?;
        rows.collect()
    }

    /// Its owner read conversation `id` up to message `seq`; whether that
    /// moved how far it was read. It only moves forward, and never past the
    /// conversation's newest message.
    pub fn mark_read(&self, id: &str, seq: i64) -> rusqlite::Result<bool> {
        let changed = self.db.execute(
            "UPDATE conversations SET read = ?2 WHERE id = ?1
             AND (read IS NULL OR read < ?2)
             AND ?2 <= (SELECT COALESCE(MAX(seq), 0) FROM messages WHERE conversation = ?1)",
            params![id, seq],
        )?;
        Ok(changed == 1)
    }

    /// Names a conversation, saying who named it ([`BY_AGENT`] or
    /// [`BY_PERSON`]); whether its name changed. The person's name replaces
    /// any, and an empty one clears it, so the runtime may name it again;
    /// the runtime's never replaces the person's.
    pub fn name(&self, id: &str, title: &str, by: &str) -> rusqlite::Result<bool> {
        let title = title.trim();
        let changed = match (by, title.is_empty()) {
            (BY_PERSON, true) => self.db.execute(
                "UPDATE conversations SET title = NULL, titled_by = NULL WHERE id = ?1 AND title IS NOT NULL",
                params![id],
            )?,
            (BY_PERSON, false) => self.db.execute(
                "UPDATE conversations SET title = ?2, titled_by = ?3 WHERE id = ?1
                 AND (title IS NOT ?2 OR titled_by IS NOT ?3)",
                params![id, title, BY_PERSON],
            )?,
            (_, true) => 0,
            _ => self.db.execute(
                "UPDATE conversations SET title = ?2, titled_by = ?3 WHERE id = ?1
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
                "SELECT id, sandbox, agent, title, titled_by, read FROM conversations WHERE id = ?1",
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
    /// by `owner` and named Home by them, so the runtime's names do not
    /// replace it; one already there keeps its owner, unless it had none
    /// (made before anyone was known), which `owner` then takes. Whether it
    /// was made.
    pub fn ensure_home(&self, agent: &str, owner: &str) -> rusqlite::Result<bool> {
        let Some((sandbox, name)) = agent.split_once('/') else {
            return Ok(false);
        };
        let id = home_id(agent);
        if self.conversation_of(&id)?.is_some() {
            if !owner.is_empty() {
                self.db.execute(
                    "UPDATE conversations SET owner = ?2 WHERE id = ?1 AND owner = ''",
                    params![id, owner],
                )?;
            }
            return Ok(false);
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
        let (_, _, owner) = self.conversation(id, sandbox, "", owner)?;
        let known = !self.members(id)?.is_empty();
        for (position, agent) in members.iter().enumerate().filter(|_| !known) {
            self.db.execute(
                "INSERT OR IGNORE INTO members (conversation, agent, position) VALUES (?1, ?2, ?3)",
                params![id, agent, position as i64],
            )?;
        }
        Ok((
            owner,
            self.members(id)?.into_iter().map(|(a, _)| a).collect(),
        ))
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

    /// The turn sent to a member as plugin message `sent`: `(id, status, seen)`.
    pub fn turn_sent(&self, sent: &str) -> rusqlite::Result<Option<(String, String, Option<i64>)>> {
        self.db
            .query_row(
                "SELECT id, status, seen FROM turns WHERE sent = ?1",
                params![sent],
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
        })
    }

    const DEVICE_COLUMNS: &'static str =
        "id, name, person, noise_key, device_key, push_key, push_token, paired, seen";

    pub fn add_device(&self, device: &Device) -> rusqlite::Result<()> {
        self.db.execute(
            "INSERT INTO devices (id, name, person, noise_key, device_key, push_key, push_token, paired, seen) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                device.id,
                device.name,
                device.person,
                device.noise_key,
                device.device_key,
                device.push_key,
                device.push_token,
                device.paired,
                device.seen
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
            "UPDATE pairings SET used = 1, request_name = ?2, request_person = ?3 WHERE code = ?1 AND used = 0 AND expires >= ?4",
            params![code, request.name, request.person, now()],
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
                "SELECT request_name, request_person FROM pairings WHERE code = ?1 AND used = 1",
                params![code],
                |row| {
                    Ok(PairingRequest {
                        name: row.get(0)?,
                        person: row.get(1)?,
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
    /// the device has its answer, `gone` when it left before.
    pub fn settle_pairing(&self, code: &[u8], outcome: &str) -> rusqlite::Result<()> {
        self.db.execute(
            "UPDATE pairings SET decision = ?2 WHERE code = ?1 AND decision = 'accept'",
            params![code, outcome],
        )?;
        Ok(())
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
            store.turn_sent("sent-1").unwrap(),
            Some(("t-1".to_owned(), "failed".to_owned(), Some(4)))
        );
        assert_eq!(store.turn_sent("sent-2").unwrap(), None);
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
        assert_eq!(store.since("v", 0).unwrap()[0].from, From::Agent);
        store
            .group("g-1", "lab", &["main".into(), "coder".into()], "v")
            .unwrap();
        assert_eq!(store.members("g-1").unwrap().len(), 2);
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
    fn a_pairing_takes_the_first_word_and_then_its_outcome() {
        let folder = tempfile::tempdir().unwrap();
        let store = Store::open(&folder.path().join("app.db")).unwrap();
        let decision = |s: &Store, code: &[u8]| s.pairing_decision(code).unwrap();
        // Accepted, then the device got its answer.
        store.add_pairing(b"one", now() + 300).unwrap();
        assert!(store.decide_pairing(b"one", "accept").unwrap());
        assert!(!store.decide_pairing(b"one", "decline").unwrap());
        store.settle_pairing(b"one", "paired").unwrap();
        assert_eq!(decision(&store, b"one").as_deref(), Some("paired"));
        // The device left first: the terminal's answer comes too late.
        store.add_pairing(b"two", now() + 300).unwrap();
        assert!(store.decide_pairing(b"two", "gone").unwrap());
        assert!(!store.decide_pairing(b"two", "accept").unwrap());
        assert_eq!(decision(&store, b"two").as_deref(), Some("gone"));
        // An outcome settles an accepted pairing only.
        store.add_pairing(b"three", now() + 300).unwrap();
        assert!(store.decide_pairing(b"three", "decline").unwrap());
        store.settle_pairing(b"three", "paired").unwrap();
        assert_eq!(decision(&store, b"three").as_deref(), Some("decline"));
    }

    #[test]
    fn an_agents_home_is_made_once_named_home_for_its_owner() {
        let folder = tempfile::tempdir().unwrap();
        let store = Store::open(&folder.path().join("app.db")).unwrap();
        assert_eq!(home_id("lab/main"), "home.lab.main");
        assert!(is_home("home.lab.main") && !is_home("a47e17c0-eaad-4d1d-8853-56aa0b69e1e2"));
        assert!(store.ensure_home("lab/main", "victor@example.com").unwrap());
        // Once: a second person does not take it.
        assert!(!store.ensure_home("lab/main", "alice@example.com").unwrap());
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
        assert!(!store.ensure_home("no-slash", "victor@example.com").unwrap());
        // Made before anyone was known: the first person takes it, once.
        assert!(store.ensure_home("lab/scout", "").unwrap());
        assert_eq!(store.owner("home.lab.scout").unwrap().as_deref(), Some(""));
        store.ensure_home("lab/scout", "alice@example.com").unwrap();
        store
            .ensure_home("lab/scout", "victor@example.com")
            .unwrap();
        assert_eq!(
            store.owner("home.lab.scout").unwrap().as_deref(),
            Some("alice@example.com")
        );
    }
}
