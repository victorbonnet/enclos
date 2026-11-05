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

/// A conversation, with its name when it has one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Conversation {
    pub id: String,
    pub sandbox: String,
    pub agent: String,
    pub title: Option<String>,
    /// [`BY_AGENT`] or [`BY_PERSON`], when it has a name.
    pub titled_by: Option<String>,
}

/// A conversation named by its runtime.
pub const BY_AGENT: &str = "agent";
/// A conversation named by its owner.
pub const BY_PERSON: &str = "person";

pub struct Store {
    db: Connection,
}

/// Brings a database made by an earlier bridge up to [`SCHEMA`]: columns
/// added since, which `CREATE TABLE IF NOT EXISTS` does not add.
fn upgrade(db: &Connection) -> rusqlite::Result<()> {
    let mut query = db.prepare("SELECT name FROM pragma_table_info('conversations')")?;
    let columns = query
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    for (column, kind) in [("title", "TEXT"), ("titled_by", "TEXT")] {
        if !columns.iter().any(|c| c == column) {
            db.execute_batch(&format!(
                "ALTER TABLE conversations ADD COLUMN {column} {kind}"
            ))?;
        }
    }
    Ok(())
}

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS conversations (
    id TEXT PRIMARY KEY,
    sandbox TEXT NOT NULL,
    agent TEXT NOT NULL,
    owner TEXT NOT NULL,
    created INTEGER NOT NULL,
    title TEXT,
    titled_by TEXT
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
    pub fn open(path: &Path) -> rusqlite::Result<Store> {
        let db = Connection::open(path)?;
        db.execute_batch(SCHEMA)?;
        upgrade(&db)?;
        Ok(Store { db })
    }

    /// The person's conversations, the oldest first.
    pub fn conversations(&self, owner: &str) -> rusqlite::Result<Vec<Conversation>> {
        let mut query = self.db.prepare(
            "SELECT id, sandbox, agent, title, titled_by FROM conversations WHERE owner = ?1 ORDER BY created, id",
        )?;
        let rows = query.query_map(params![owner], |row| {
            Ok(Conversation {
                id: row.get(0)?,
                sandbox: row.get(1)?,
                agent: row.get(2)?,
                title: row.get(3)?,
                titled_by: row.get(4)?,
            })
        })?;
        rows.collect()
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

    /// A known conversation, with its name.
    pub fn conversation_info(&self, id: &str) -> rusqlite::Result<Option<Conversation>> {
        self.db
            .query_row(
                "SELECT id, sandbox, agent, title, titled_by FROM conversations WHERE id = ?1",
                params![id],
                |row| {
                    Ok(Conversation {
                        id: row.get(0)?,
                        sandbox: row.get(1)?,
                        agent: row.get(2)?,
                        title: row.get(3)?,
                        titled_by: row.get(4)?,
                    })
                },
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
}
