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

    /// The terminal's answer: `accept` or `decline`.
    pub fn decide_pairing(&self, code: &[u8], decision: &str) -> rusqlite::Result<()> {
        self.db.execute(
            "UPDATE pairings SET decision = ?2 WHERE code = ?1",
            params![code, decision],
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
}
