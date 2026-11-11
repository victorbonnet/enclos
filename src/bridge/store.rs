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

pub struct Store {
    db: Connection,
}

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS conversations (
    id TEXT PRIMARY KEY,
    sandbox TEXT NOT NULL,
    agent TEXT NOT NULL,
    owner TEXT NOT NULL,
    created INTEGER NOT NULL
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
        db.execute_batch(&format!(
            "ALTER TABLE {table} ADD COLUMN {column} {declaration}"
        ))?;
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
        db.execute_batch(SCHEMA)?;
        for (table, column, declaration) in ADDED_COLUMNS {
            add_column(&db, table, column, declaration)?;
        }
        db.execute_batch(
            "CREATE UNIQUE INDEX IF NOT EXISTS messages_origin ON messages(origin);
             CREATE INDEX IF NOT EXISTS messages_pending ON messages(pending) WHERE pending = 1;",
        )?;
        Ok(Store { db })
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
        let person = match from {
            From::Person(p) => Some(p.as_str()),
            From::Agent => None,
        };
        let added = self.db.execute(
            "INSERT OR IGNORE INTO messages (id, conversation, person, text, kind, at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![id, conversation, person, text, kind, now()],
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
            "SELECT m.seq, m.id, m.conversation, m.person, m.text, m.kind, m.at FROM messages m
             JOIN conversations c ON c.id = m.conversation
             WHERE c.owner = ?1 AND m.seq > ?2 ORDER BY m.seq",
        )?;
        let rows = query.query_map(params![owner, since], |row| {
            let person: Option<String> = row.get(3)?;
            Ok(Message {
                seq: row.get(0)?,
                id: row.get(1)?,
                conversation: row.get(2)?,
                from: person.map_or(From::Agent, From::Person),
                text: row.get(4)?,
                kind: row.get(5)?,
                at: row.get(6)?,
            })
        })?;
        rows.collect()
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
}
