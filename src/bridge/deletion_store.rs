//! Permanent conversation deletion, including durable retry plans and sync records.
use super::*;

impl Store {
    /// Reserves the id before contacting any runtime. A partial deletion is retried with
    /// the same targets; a completed deletion retains only its id and owner.
    pub fn begin_deletion(&self, id: &str, owner: &str) -> rusqlite::Result<Option<Vec<String>>> {
        let tx = rusqlite::Transaction::new_unchecked(
            &self.db,
            rusqlite::TransactionBehavior::Immediate,
        )?;
        let existing: Option<(String, String)> = tx
            .query_row(
                "SELECT owner, targets FROM conversation_deletions WHERE id=?1",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        if let Some((person, targets)) = existing {
            return if person == owner {
                serde_json::from_str(&targets).map(Some).map_err(json_error)
            } else {
                Ok(None)
            };
        }
        if is_home(id) {
            return Ok(None);
        }
        let routing: Option<(String, String)> = tx
            .query_row(
                "SELECT sandbox, agent FROM conversations WHERE id=?1 AND owner=?2",
                params![id, owner],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let Some((sandbox, agent)) = routing else {
            return Ok(None);
        };
        let mut q =
            tx.prepare("SELECT agent FROM members WHERE conversation=?1 ORDER BY position")?;
        let members = q
            .query_map([id], |r| r.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        drop(q);
        let targets: Vec<String> = if members.is_empty() {
            vec![format!("{sandbox}/{agent}")]
        } else {
            members
                .into_iter()
                .map(|m| format!("{sandbox}/{m}"))
                .collect()
        };
        tx.execute(
            "INSERT INTO conversation_deletions(id,owner,targets) VALUES (?1,?2,?3)",
            params![
                id,
                owner,
                serde_json::to_string(&targets).map_err(json_error)?
            ],
        )?;
        tx.commit()?;
        Ok(Some(targets))
    }

    pub fn deletion_owner(&self, id: &str) -> rusqlite::Result<Option<String>> {
        self.db
            .query_row(
                "SELECT owner FROM conversation_deletions WHERE id=?1",
                [id],
                |r| r.get(0),
            )
            .optional()
    }

    pub fn cancel_deletion(&self, id: &str, owner: &str) -> rusqlite::Result<()> {
        self.db.execute(
            "DELETE FROM conversation_deletions WHERE id=?1 AND owner=?2 AND done=0",
            params![id, owner],
        )?;
        Ok(())
    }

    pub fn deletion_started(&self, id: &str) -> rusqlite::Result<bool> {
        self.db.query_row(
            "SELECT EXISTS(SELECT 1 FROM conversation_deletions WHERE id=?1)",
            [id],
            |r| r.get(0),
        )
    }

    /// Checkpoints one acknowledged target; retry skips already removed native chats.
    pub fn deletion_target_done(&self, id: &str, target: &str) -> rusqlite::Result<()> {
        let tx = rusqlite::Transaction::new_unchecked(
            &self.db,
            rusqlite::TransactionBehavior::Immediate,
        )?;
        let json: String = tx.query_row(
            "SELECT targets FROM conversation_deletions WHERE id=?1",
            [id],
            |r| r.get(0),
        )?;
        let mut targets: Vec<String> = serde_json::from_str(&json).map_err(json_error)?;
        targets.retain(|t| t != target);
        tx.execute(
            "UPDATE conversation_deletions SET targets=?2 WHERE id=?1",
            params![id, serde_json::to_string(&targets).map_err(json_error)?],
        )?;
        tx.commit()
    }

    pub fn deletion_files(&self, id: &str) -> rusqlite::Result<Vec<String>> {
        let mut q = self
            .db
            .prepare("SELECT id FROM attachments WHERE conversation=?1")?;
        q.query_map([id], |r| r.get(0))?.collect()
    }

    /// All runtime targets have acknowledged; remove the bridge's content atomically.
    /// Files are removed first, while their ids are still available for a retry.
    pub fn finish_deletion(
        &self,
        id: &str,
        owner: &str,
        device: &str,
    ) -> rusqlite::Result<Vec<String>> {
        let tx = rusqlite::Transaction::new_unchecked(
            &self.db,
            rusqlite::TransactionBehavior::Immediate,
        )?;
        let ready: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM conversation_deletions WHERE id=?1 AND owner=?2 AND targets='[]')", params![id,owner], |r| r.get(0))?;
        if !ready {
            return Err(rusqlite::Error::InvalidQuery);
        }
        let mut q = tx.prepare("SELECT id FROM attachments WHERE conversation=?1")?;
        let files = q
            .query_map([id], |r| r.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        drop(q);
        for table in ["questions", "turns", "members", "attachments", "messages"] {
            tx.execute(&format!("DELETE FROM {table} WHERE conversation=?1 AND EXISTS (SELECT 1 FROM conversation_deletions WHERE id=?1 AND owner=?2)"), params![id,owner])?;
        }
        tx.execute(
            "DELETE FROM conversations WHERE id=?1 AND owner=?2",
            params![id, owner],
        )?;
        let changed = tx.execute(
            "UPDATE conversation_deletions SET done=1, targets='[]' WHERE id=?1 AND owner=?2 AND done=0",
            params![id, owner],
        )?;
        if changed == 1 {
            tx.execute("INSERT INTO log(at,device,person,event,reason) VALUES (?1,?2,?3,'conversation.delete',?4)", params![now(),device,owner,id])?;
            tx.execute("DELETE FROM log WHERE rowid NOT IN (SELECT rowid FROM log ORDER BY rowid DESC LIMIT ?1)", [LOG_KEPT])?;
        }
        tx.commit()?;
        Ok(files)
    }

    pub fn deletions(&self, owner: &str) -> rusqlite::Result<Vec<String>> {
        let mut q = self.db.prepare(
            "SELECT id FROM conversation_deletions WHERE owner=?1 AND done=1 ORDER BY id",
        )?;
        q.query_map([owner], |r| r.get(0))?.collect()
    }
}

fn json_error(error: serde_json::Error) -> rusqlite::Error {
    rusqlite::Error::ToSqlConversionFailure(Box::new(error))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deletion_is_owned_permanent_and_cannot_be_resurrected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("app.db");
        let store = Store::open(&path).unwrap();
        store
            .conversation("c-delete", "lab", "main", "alice")
            .unwrap();
        store
            .add("m1", "c-delete", &From::Agent, "history", "reply")
            .unwrap();
        store
            .add_attachment(
                &StoredAttachment {
                    id: "f1".into(),
                    conversation: "c-delete".into(),
                    mime: "text/plain".into(),
                    name: "a.txt".into(),
                    size: 1,
                },
                "m1",
            )
            .unwrap();
        assert!(store.begin_deletion("c-delete", "bob").unwrap().is_none());
        assert!(store.begin_deletion("missing", "alice").unwrap().is_none());
        store.ensure_home("lab/main", "alice", true).unwrap();
        assert!(
            store
                .begin_deletion("home.lab.main", "alice")
                .unwrap()
                .is_none()
        );
        assert_eq!(
            store.begin_deletion("c-delete", "alice").unwrap().unwrap(),
            ["lab/main"]
        );
        assert!(
            store
                .finish_deletion("c-delete", "alice", "test-device")
                .is_err(),
            "native confirmation required"
        );
        assert!(
            store
                .add("late", "c-delete", &From::Agent, "late reply", "reply")
                .is_err()
        );
        assert!(
            store
                .add_from_device("phone/m2", "m2", "c-delete", "alice", "late input")
                .is_err()
        );
        store.deletion_target_done("c-delete", "lab/main").unwrap();
        assert_eq!(store.deletion_files("c-delete").unwrap(), ["f1"]);
        store
            .finish_deletion("c-delete", "alice", "test-device")
            .unwrap();
        assert!(store.conversation_info("c-delete").unwrap().is_none());
        assert!(store.since("alice", 0).unwrap().is_empty());
        assert!(store.attachment("f1").unwrap().is_none());
        assert!(
            store
                .conversation("c-delete", "lab", "main", "alice")
                .is_err()
        );
        drop(store);
        let again = Store::open(&path).unwrap();
        assert_eq!(again.deletions("alice").unwrap(), ["c-delete"]);
        assert!(again.deletions("bob").unwrap().is_empty());
        assert!(again.begin_deletion("c-delete", "bob").unwrap().is_none());
        assert!(
            again
                .begin_deletion("c-delete", "alice")
                .unwrap()
                .unwrap()
                .is_empty()
        );
        again
            .finish_deletion("c-delete", "alice", "test-device")
            .unwrap();
        let entries = again.log_lines(100).unwrap();
        let deletions: Vec<_> = entries
            .iter()
            .filter(|line| line.event == "conversation.delete")
            .collect();
        assert_eq!(
            deletions.len(),
            1,
            "idempotent retries create no second audit entry"
        );
        assert_eq!(deletions[0].device.as_deref(), Some("test-device"));
        assert_eq!(deletions[0].person.as_deref(), Some("alice"));
        assert_eq!(deletions[0].reason.as_deref(), Some("c-delete"));
    }

    #[test]
    fn partial_group_deletion_resumes_only_the_remaining_native_chats() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("app.db");
        let store = Store::open(&path).unwrap();
        store
            .group("g-delete", "lab", &["coder".into(), "main".into()], "alice")
            .unwrap();
        store
            .add(
                "m1",
                "g-delete",
                &From::Member("coder".into()),
                "reply",
                "reply",
            )
            .unwrap();
        assert_eq!(
            store.begin_deletion("g-delete", "alice").unwrap().unwrap(),
            ["lab/coder", "lab/main"]
        );
        store.deletion_target_done("g-delete", "lab/coder").unwrap();
        drop(store);
        let again = Store::open(&path).unwrap();
        assert_eq!(
            again.begin_deletion("g-delete", "alice").unwrap().unwrap(),
            ["lab/main"]
        );
        assert_eq!(
            again.since("alice", 0).unwrap().len(),
            1,
            "history stays until every native session was removed"
        );
        again.deletion_target_done("g-delete", "lab/main").unwrap();
        again
            .finish_deletion("g-delete", "alice", "test-device")
            .unwrap();
        assert!(again.members("g-delete").unwrap().is_empty());
        assert!(again.since("alice", 0).unwrap().is_empty());
    }
}
