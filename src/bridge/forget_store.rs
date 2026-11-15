//! Forgetting a removed agent (ADR 0067, proposed): its Home and the direct
//! conversations of one person with it, at once, and the Home id the agent
//! gets if it is made again.
use super::*;

/// Why forgetting an agent changed nothing.
#[derive(Debug)]
pub enum Forget {
    Storage(rusqlite::Error),
    /// The deletion record of this conversation id is another person's:
    /// direct conversations keep their owner, so only a database edited by
    /// hand gets here, and no retry helps.
    OwnedByAnother(String),
}

impl std::convert::From<rusqlite::Error> for Forget {
    fn from(error: rusqlite::Error) -> Self {
        Forget::Storage(error)
    }
}

impl Store {
    /// The id of `agent`'s (`<sandbox>/<agent>`) Home: [`home_id`] until the
    /// agent is forgotten, `None` from then on until `runtime configure
    /// --channel app`, or an import into its name, sets it up again
    /// ([`Store::claim_home`]), and the id claimed then.
    pub fn home_of(&self, agent: &str) -> rusqlite::Result<Option<String>> {
        let row: Option<Option<String>> = self
            .db
            .query_row("SELECT id FROM homes WHERE agent = ?1", [agent], |r| {
                r.get(0)
            })
            .optional()?;
        Ok(match row {
            Some(id) => id,
            None => Some(home_id(agent)),
        })
    }

    /// The Home id of `agent` set up again: when it was forgotten, a new
    /// one the bridge has never used, kept from now on. Devices ignore a
    /// deleted id for good, so a forgotten Home's id is never given again.
    pub fn claim_home(&self, agent: &str) -> rusqlite::Result<String> {
        let tx = rusqlite::Transaction::new_unchecked(
            &self.db,
            rusqlite::TransactionBehavior::Immediate,
        )?;
        let id = match planned_home(&tx, agent)? {
            (id, false) => id,
            (id, true) => {
                tx.execute(
                    "UPDATE homes SET id = ?2 WHERE agent = ?1 AND id IS NULL",
                    params![agent, id],
                )?;
                id
            }
        };
        tx.commit()?;
        Ok(id)
    }

    /// `<sandbox>/<agent>` of each agent `owner` has a direct conversation
    /// or a Home with: those that may be forgotten once removed.
    pub fn forget_candidates(&self, owner: &str) -> rusqlite::Result<Vec<String>> {
        let mut q = self.db.prepare(
            "SELECT DISTINCT sandbox || '/' || agent FROM conversations c
             WHERE owner = ?1 AND NOT EXISTS (SELECT 1 FROM members m WHERE m.conversation = c.id)
             ORDER BY 1",
        )?;
        q.query_map([owner], |r| r.get(0))?.collect()
    }

    /// The attachment files of what forgetting `agent` removes for `owner`:
    /// removed before the rows that name them, so a retry finds them.
    pub fn forget_files(&self, agent: &str, owner: &str) -> rusqlite::Result<Vec<String>> {
        let (sandbox, name) = agent.split_once('/').unwrap_or((agent, ""));
        let mut q = self.db.prepare(&format!(
            "SELECT a.id FROM attachments a WHERE a.conversation IN ({DIRECT})"
        ))?;
        q.query_map(params![sandbox, name, owner], |r| r.get(0))?
            .collect()
    }

    /// Forgets `agent` for `owner`, the host's person: deletes their
    /// direct conversations with it, its Home among them, as a completed
    /// deletion each (ADR 0062, proposed), so every device of theirs drops
    /// them at sync; leaves its groups; and keeps the agent's Home
    /// forgotten until it is set up again. When it deletes any, one
    /// `agent.forget` log entry names the agent and every id; with none
    /// left, it logs nothing. The ids deleted, in order, and the
    /// attachment files the rows named.
    pub fn forget_agent(
        &self,
        agent: &str,
        owner: &str,
        device: &str,
    ) -> Result<(Vec<String>, Vec<String>), Forget> {
        // Not `<sandbox>/<agent>`: no conversation is its.
        let (sandbox, name) = agent.split_once('/').unwrap_or((agent, ""));
        let tx = rusqlite::Transaction::new_unchecked(
            &self.db,
            rusqlite::TransactionBehavior::Immediate,
        )?;
        let ids = {
            let mut q = tx.prepare(&format!("{DIRECT} ORDER BY id"))?;
            q.query_map(params![sandbox, name, owner], |r| r.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?
        };
        let mut files = Vec::new();
        for id in &ids {
            let mut q = tx.prepare("SELECT id FROM attachments WHERE conversation = ?1")?;
            files.extend(
                q.query_map([id], |r| r.get::<_, String>(0))?
                    .collect::<rusqlite::Result<Vec<_>>>()?,
            );
            drop(q);
            // A deletion of it started before, and not finished, is
            // finished by this one: nothing native is left to wait for.
            let recorded = tx.execute(
                "INSERT INTO conversation_deletions (id, owner, targets, done) VALUES (?1, ?2, '[]', 1)
                 ON CONFLICT(id) DO UPDATE SET targets = '[]', done = 1 WHERE owner = excluded.owner",
                params![id, owner],
            )?;
            // Another person's deletion of it: the transaction, dropped,
            // changes nothing.
            if recorded != 1 {
                return Err(Forget::OwnedByAnother(id.clone()));
            }
            for table in [
                "questions",
                "turns",
                "members",
                "attachments",
                "usage_hours",
                "messages",
            ] {
                tx.execute(
                    &format!("DELETE FROM {table} WHERE conversation = ?1"),
                    [id],
                )?;
            }
            tx.execute(
                "DELETE FROM conversations WHERE id = ?1 AND owner = ?2",
                params![id, owner],
            )?;
        }
        tx.execute(
            "INSERT INTO homes (agent, id) VALUES (?1, NULL) ON CONFLICT(agent) DO UPDATE SET id = NULL",
            [agent],
        )?;
        // Its usage outside the app, which only the host's person, who
        // forgets it, sees.
        tx.execute("DELETE FROM agent_usage_hours WHERE agent = ?1", [agent])?;
        tx.execute(
            "DELETE FROM agent_usage_reporters WHERE agent = ?1",
            [agent],
        )?;
        if !ids.is_empty() {
            tx.execute(
                "INSERT INTO log (at, device, person, event, reason) VALUES (?1, ?2, ?3, 'agent.forget', ?4)",
                params![now(), device, owner, format!("{agent}: {}", ids.join(" "))],
            )?;
            tx.execute(
                "DELETE FROM log WHERE rowid NOT IN (SELECT rowid FROM log ORDER BY rowid DESC LIMIT ?1)",
                [LOG_KEPT],
            )?;
        }
        tx.commit()?;
        Ok((ids, files))
    }
}

/// The ids of the direct conversations of `?3` with agent `?2` of sandbox
/// `?1`, its Home among them: with no members, which a group has.
const DIRECT: &str =
    "SELECT id FROM conversations c WHERE sandbox = ?1 AND agent = ?2 AND owner = ?3
    AND NOT EXISTS (SELECT 1 FROM members m WHERE m.conversation = c.id)";

/// `agent`'s Home id, and whether it is a new one to claim: the agent was
/// forgotten, and the next `home.<sandbox>.<agent>.<n>` no conversation,
/// deletion or other Home has used is its. Names hold no dot, so it is no
/// other agent's first Home.
fn planned_home(db: &Connection, agent: &str) -> rusqlite::Result<(String, bool)> {
    let row: Option<Option<String>> = db
        .query_row("SELECT id FROM homes WHERE agent = ?1", [agent], |r| {
            r.get(0)
        })
        .optional()?;
    match row {
        None => Ok((home_id(agent), false)),
        Some(Some(id)) => Ok((id, false)),
        Some(None) => {
            let first = home_id(agent);
            for n in 2u32.. {
                let id = format!("{first}.{n}");
                let used: bool = db.query_row(
                    "SELECT EXISTS (SELECT 1 FROM conversations WHERE id = ?1)
                         OR EXISTS (SELECT 1 FROM conversation_deletions WHERE id = ?1)
                         OR EXISTS (SELECT 1 FROM homes WHERE id = ?1)",
                    [&id],
                    |r| r.get(0),
                )?;
                if !used {
                    return Ok((id, true));
                }
            }
            unreachable!("fewer than 2^32 Homes")
        }
    }
}

/// The Home id `runtime configure --channel app` gives `agent`'s
/// (`<sandbox>/<agent>`) runtime, from the bridge's database at `path`:
/// [`home_id`] while there is none, or the agent was never forgotten;
/// else the one claimed for it ([`Store::claim_home`]). With `claim`
/// false, as in a dry run, nothing is written and no database is made.
pub fn setup_home(path: &Path, agent: &str, claim: bool) -> rusqlite::Result<String> {
    if !path.exists() {
        return Ok(home_id(agent));
    }
    if claim {
        return Store::open(path)?.claim_home(agent);
    }
    let db = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    // As `Store::open` does: the bridge may be writing.
    db.busy_timeout(std::time::Duration::from_secs(5))?;
    // A database from before ADR 0067 has forgotten no agent.
    let known: bool = db.query_row(
        "SELECT EXISTS (SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'homes')",
        [],
        |r| r.get(0),
    )?;
    if !known {
        return Ok(home_id(agent));
    }
    planned_home(&db, agent).map(|(id, _)| id)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("app.db")).unwrap();
        store.claim_host("alice").unwrap();
        (dir, store)
    }

    #[test]
    fn forgetting_deletes_home_and_direct_conversations_but_not_groups_or_others() {
        let (_dir, store) = store();
        assert!(store.ensure_home("lab/coder", "alice", true).unwrap());
        store.conversation("c-1", "lab", "coder", "alice").unwrap();
        store.conversation("c-2", "lab", "coder", "alice").unwrap();
        store.add("m-1", "c-1", &From::Agent, "hi", "text").unwrap();
        // Bob's and another agent's stay.
        store.conversation("c-bob", "lab", "coder", "bob").unwrap();
        store
            .conversation("c-main", "lab", "main", "alice")
            .unwrap();
        assert_eq!(
            store.forget_candidates("alice").unwrap(),
            ["lab/coder", "lab/main"]
        );
        let (ids, files) = store.forget_agent("lab/coder", "alice", "phone").unwrap();
        assert_eq!(ids, ["c-1", "c-2", "home.lab.coder"]);
        assert!(files.is_empty());
        for id in &ids {
            assert!(store.conversation_info(id).unwrap().is_none());
        }
        assert_eq!(
            store.deletions("alice").unwrap(),
            ["c-1", "c-2", "home.lab.coder"]
        );
        assert!(store.conversation_info("c-bob").unwrap().is_some());
        assert!(store.conversation_info("c-main").unwrap().is_some());
        // Its messages are gone, and none comes back under a deleted id.
        assert!(
            store
                .add("m-2", "c-1", &From::Agent, "late", "text")
                .is_err()
        );
        // One entry, naming the agent and every id.
        let reason: String = store
            .db
            .query_row(
                "SELECT reason FROM log WHERE event = 'agent.forget' AND device = 'phone' AND person = 'alice'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(reason, "lab/coder: c-1 c-2 home.lab.coder");
        // Forgotten, it has no Home to make until it is set up again.
        assert_eq!(store.home_of("lab/coder").unwrap(), None);
        assert!(!store.ensure_home("lab/coder", "alice", true).unwrap());
        assert_eq!(store.forget_candidates("alice").unwrap(), ["lab/main"]);
        // Again: nothing left, nothing logged.
        let (again, _) = store.forget_agent("lab/coder", "alice", "phone").unwrap();
        assert!(again.is_empty());
    }

    #[test]
    fn forgetting_leaves_a_group_the_agent_was_in() {
        let (_dir, store) = store();
        store.conversation("g-1", "lab", "coder", "alice").unwrap();
        store
            .db
            .execute_batch(
                "INSERT INTO members (conversation, agent, position) VALUES ('g-1', 'coder', 0), ('g-1', 'main', 1)",
            )
            .unwrap();
        let (ids, _) = store.forget_agent("lab/coder", "alice", "phone").unwrap();
        assert!(ids.is_empty());
        assert!(store.conversation_info("g-1").unwrap().is_some());
    }

    #[test]
    fn forgetting_finishes_a_deletion_left_unfinished() {
        let (_dir, store) = store();
        store.conversation("c-1", "lab", "coder", "alice").unwrap();
        assert_eq!(
            store.begin_deletion("c-1", "alice").unwrap(),
            Some(vec!["lab/coder".to_owned()])
        );
        let (ids, _) = store.forget_agent("lab/coder", "alice", "phone").unwrap();
        assert_eq!(ids, ["c-1"]);
        assert_eq!(store.deletions("alice").unwrap(), ["c-1"]);
    }

    #[test]
    fn another_persons_deletion_of_one_of_them_changes_nothing() {
        let (_dir, store) = store();
        store.ensure_home("lab/coder", "alice", true).unwrap();
        store.conversation("c-1", "lab", "coder", "alice").unwrap();
        store
            .db
            .execute_batch(
                "INSERT INTO conversation_deletions (id, owner, targets) VALUES ('c-1', 'bob', '[]')",
            )
            .unwrap();
        assert!(matches!(
            store.forget_agent("lab/coder", "alice", "phone"),
            Err(Forget::OwnedByAnother(id)) if id == "c-1"
        ));
        assert!(store.conversation_info("home.lab.coder").unwrap().is_some());
        assert_eq!(
            store.home_of("lab/coder").unwrap().as_deref(),
            Some("home.lab.coder")
        );
    }

    #[test]
    fn an_agent_made_again_gets_a_home_id_never_used() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("app.db");
        // No bridge yet: the first Home, nothing made.
        assert_eq!(
            setup_home(&path, "lab/coder", false).unwrap(),
            "home.lab.coder"
        );
        assert_eq!(
            setup_home(&path, "lab/coder", true).unwrap(),
            "home.lab.coder"
        );
        assert!(!path.exists());
        let store = Store::open(&path).unwrap();
        store.claim_host("alice").unwrap();
        store.ensure_home("lab/coder", "alice", true).unwrap();
        assert_eq!(
            setup_home(&path, "lab/coder", true).unwrap(),
            "home.lab.coder"
        );
        store.forget_agent("lab/coder", "alice", "phone").unwrap();
        // `.2` is taken already, by a conversation a device named so.
        store
            .conversation("home.lab.coder.2", "lab", "coder", "alice")
            .unwrap();
        // A dry run names the id it would claim, and writes nothing.
        assert_eq!(
            setup_home(&path, "lab/coder", false).unwrap(),
            "home.lab.coder.3"
        );
        assert_eq!(store.home_of("lab/coder").unwrap(), None);
        assert_eq!(
            setup_home(&path, "lab/coder", true).unwrap(),
            "home.lab.coder.3"
        );
        assert_eq!(
            store.home_of("lab/coder").unwrap().as_deref(),
            Some("home.lab.coder.3")
        );
        assert!(is_home("home.lab.coder.3"));
        // The bridge makes it, as Home, for the host's person.
        assert!(store.ensure_home("lab/coder", "alice", true).unwrap());
        assert_eq!(
            store.owner("home.lab.coder.3").unwrap().as_deref(),
            Some("alice")
        );
        // Forgotten again: another one.
        store.forget_agent("lab/coder", "alice", "phone").unwrap();
        assert_eq!(
            setup_home(&path, "lab/coder", true).unwrap(),
            "home.lab.coder.4"
        );
        // Other agents keep their first.
        assert_eq!(
            store.home_of("lab/main").unwrap().as_deref(),
            Some("home.lab.main")
        );
    }

    #[test]
    fn a_dry_run_reads_a_database_from_before_forgetting() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("app.db");
        Connection::open(&path)
            .unwrap()
            .execute_batch("CREATE TABLE settings (name TEXT PRIMARY KEY, value TEXT NOT NULL)")
            .unwrap();
        assert_eq!(
            setup_home(&path, "lab/coder", false).unwrap(),
            "home.lab.coder"
        );
    }
}
