//! The tasks the bridge keeps and each agent's current activity
//! (`docs/protocol.md`, Tasks and agent activity; ADR 0068, proposed).
use super::*;
use enclos_protocol::task::{Activity, ENDED_RETENTION_SECS, MAX_TASKS, Task};
use std::collections::HashMap;

/// What storing tasks changed, for the devices: the tasks stored anew or
/// changed, the ones dropped (assignee `<sandbox>/<agent>` and id), and how
/// many were refused because the sandbox keeps [`MAX_TASKS`] still going.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct TaskChanges {
    pub stored: Vec<Task>,
    pub removed: Vec<TaskKey>,
    pub full: usize,
}

type Tx<'a> = rusqlite::Transaction<'a>;

/// A task as devices know it: its assignee (`<sandbox>/<agent>`) and id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskKey {
    pub agent: String,
    pub task: String,
}

impl TaskKey {
    pub fn new(agent: impl Into<String>, task: impl Into<String>) -> TaskKey {
        TaskKey {
            agent: agent.into(),
            task: task.into(),
        }
    }
}

impl Store {
    /// Keeps `task` of `sandbox`, its `assignee` already `<sandbox>/<agent>`
    /// and its text cleaned. A task the bridge has not seen ended is
    /// recorded ended now; an ended one is dropped 3 days later.
    pub fn put_task(&self, sandbox: &str, task: &Task, now: i64) -> rusqlite::Result<TaskChanges> {
        let tx = Tx::new_unchecked(&self.db, rusqlite::TransactionBehavior::Immediate)?;
        let mut changes = TaskChanges {
            removed: prune(&tx, now)?,
            ..TaskChanges::default()
        };
        put(&tx, sandbox, task, now, &mut changes)?;
        tx.commit()?;
        Ok(changes)
    }

    /// Makes what the bridge keeps of `agent`'s tasks (`<sandbox>/<agent>`)
    /// the list its plugin sent: a kept task missing from it is dropped,
    /// the runtime no longer having it.
    pub fn replace_tasks(
        &self,
        sandbox: &str,
        agent: &str,
        tasks: &[Task],
        now: i64,
    ) -> rusqlite::Result<TaskChanges> {
        let tx = Tx::new_unchecked(&self.db, rusqlite::TransactionBehavior::Immediate)?;
        let mut changes = TaskChanges {
            removed: prune(&tx, now)?,
            ..TaskChanges::default()
        };
        let kept: Vec<String> = {
            let mut query = tx.prepare("SELECT id FROM tasks WHERE sandbox = ?1 AND agent = ?2")?;
            query
                .query_map(params![sandbox, agent], |r| r.get(0))?
                .collect::<rusqlite::Result<_>>()?
        };
        for id in kept {
            if !tasks.iter().any(|t| t.id == id) {
                tx.execute(
                    "DELETE FROM tasks WHERE sandbox = ?1 AND id = ?2",
                    params![sandbox, id],
                )?;
                changes.removed.push(TaskKey::new(agent, id));
            }
        }
        for task in tasks.iter().take(MAX_TASKS) {
            put(&tx, sandbox, task, now, &mut changes)?;
        }
        tx.commit()?;
        Ok(changes)
    }

    /// Whether the bridge keeps any task of `agent` (`<sandbox>/<agent>`):
    /// read before dropping them, so a plugin's hello takes no write lock
    /// when there is nothing to drop.
    pub fn has_tasks(&self, agent: &str) -> rusqlite::Result<bool> {
        self.db.query_row(
            "SELECT EXISTS (SELECT 1 FROM tasks WHERE agent = ?1)",
            params![agent],
            |r| r.get(0),
        )
    }

    /// Whether the bridge keeps task `id` of `agent` (`<sandbox>/<agent>`):
    /// the only tasks a device may ask the detail of.
    pub fn keeps_task(&self, agent: &str, id: &str) -> rusqlite::Result<bool> {
        self.db.query_row(
            "SELECT EXISTS (SELECT 1 FROM tasks WHERE agent = ?1 AND id = ?2)",
            params![agent, id],
            |r| r.get(0),
        )
    }

    /// Every kept task, the ones still going first, then the most recent.
    /// Drops the ended ones past their 3 days first, returned as in
    /// [`TaskChanges::removed`].
    pub fn tasks(&self, now: i64) -> rusqlite::Result<(Vec<Task>, Vec<TaskKey>)> {
        let tx = Tx::new_unchecked(&self.db, rusqlite::TransactionBehavior::Immediate)?;
        let removed = prune(&tx, now)?;
        let bodies: Vec<String> = {
            let mut query = tx.prepare(
                "SELECT body FROM tasks ORDER BY ended IS NOT NULL, json_extract(body, '$.since') DESC, sandbox, id",
            )?;
            query
                .query_map([], |r| r.get(0))?
                .collect::<rusqlite::Result<_>>()?
        };
        tx.commit()?;
        // A row this bridge did not write (an older one's) is left out.
        let tasks = bodies
            .iter()
            .filter_map(|b| serde_json::from_str(b).ok())
            .collect();
        Ok((tasks, removed))
    }

    /// Records what `agent` is doing, for `enclos status`; idle removes it.
    pub fn set_activity(&self, agent: &str, activity: &Activity) -> rusqlite::Result<()> {
        if activity.idle() {
            self.db.execute(
                "DELETE FROM agent_activity WHERE agent = ?1",
                params![agent],
            )?;
        } else {
            let body = serde_json::to_string(activity).expect("an activity always serializes");
            self.db.execute(
                "INSERT INTO agent_activity (agent, body) VALUES (?1, ?2)
                 ON CONFLICT(agent) DO UPDATE SET body = excluded.body",
                params![agent, body],
            )?;
        }
        Ok(())
    }

    /// Forgets every agent's activity: what a bridge that starts knows of
    /// it is nothing, until each plugin says.
    pub fn clear_activity(&self) -> rusqlite::Result<()> {
        self.db.execute("DELETE FROM agent_activity", [])?;
        Ok(())
    }

    /// What each agent (`<sandbox>/<agent>`) is doing, as the bridge last
    /// recorded it, read without creating or upgrading the database: for
    /// `enclos status`. A database from before activity was kept has none.
    pub(crate) fn read_activity(path: &Path) -> rusqlite::Result<HashMap<String, Activity>> {
        let db = rusqlite::Connection::open_with_flags(
            path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )?;
        let exists: bool = db.query_row(
            "SELECT EXISTS (SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'agent_activity')",
            [],
            |r| r.get(0),
        )?;
        if !exists {
            return Ok(HashMap::new());
        }
        let mut query = db.prepare("SELECT agent, body FROM agent_activity")?;
        let rows = query.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
        let mut out = HashMap::new();
        for row in rows {
            let (agent, body) = row?;
            if let Ok(activity) = serde_json::from_str(&body) {
                out.insert(agent, activity);
            }
        }
        Ok(out)
    }
}

/// The file a running bridge holds a shared lock on, beside its database
/// (`app.db.live`): what tells `enclos status` that the activity recorded
/// is a running bridge's, not a stopped or crashed one's.
pub fn live_path(store: &Path) -> std::path::PathBuf {
    let mut name = store.file_name().unwrap_or_default().to_owned();
    name.push(".live");
    store.with_file_name(name)
}

/// Takes the running bridge's lock ([`live_path`]), held while the
/// returned file is open; `None`, said on stderr, when it cannot.
pub fn hold_live(store: &Path) -> Option<std::fs::File> {
    let path = live_path(store);
    let taken = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&path)
        .and_then(|file| {
            file.try_lock_shared().map_err(std::io::Error::from)?;
            Ok(file)
        });
    match taken {
        Ok(file) => Some(file),
        Err(e) => {
            eprintln!(
                "enclos app: cannot lock {}: `enclos status` will not show what agents are doing: {e}",
                path.display()
            );
            None
        }
    }
}

/// Whether a bridge holds its lock beside the database at `store`: no lock
/// file, or one nobody holds, is no bridge running.
pub fn bridge_runs(store: &Path) -> std::io::Result<bool> {
    let file = match std::fs::File::open(live_path(store)) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e),
    };
    match file.try_lock() {
        Ok(()) => Ok(false),
        Err(std::fs::TryLockError::WouldBlock) => Ok(true),
        Err(std::fs::TryLockError::Error(e)) => Err(e),
    }
}

/// Drops the tasks that ended more than 3 days ago.
fn prune(tx: &Tx, now: i64) -> rusqlite::Result<Vec<TaskKey>> {
    let mut query =
        tx.prepare("DELETE FROM tasks WHERE ended IS NOT NULL AND ended < ?1 RETURNING agent, id")?;
    query
        .query_map(params![now - ENDED_RETENTION_SECS], |r| {
            Ok(TaskKey::new(r.get::<_, String>(0)?, r.get::<_, String>(1)?))
        })?
        .collect()
}

fn put(
    tx: &Tx,
    sandbox: &str,
    task: &Task,
    now: i64,
    changes: &mut TaskChanges,
) -> rusqlite::Result<()> {
    let body = serde_json::to_string(task).expect("a task always serializes");
    let existing: Option<(String, String, Option<i64>)> = tx
        .query_row(
            "SELECT agent, body, ended FROM tasks WHERE sandbox = ?1 AND id = ?2",
            params![sandbox, task.id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?;
    let ended = task
        .state
        .ended()
        .then(|| existing.as_ref().and_then(|e| e.2).unwrap_or(now));
    match &existing {
        Some((_, old, was)) if *old == body && *was == ended => return Ok(()),
        // Given to another agent: devices know it under the one before
        Some((agent, ..)) if *agent != task.assignee => {
            changes
                .removed
                .push(TaskKey::new(agent.clone(), task.id.clone()));
        }
        Some(_) => {}
        None => {
            let count: i64 = tx.query_row(
                "SELECT COUNT(*) FROM tasks WHERE sandbox = ?1",
                params![sandbox],
                |r| r.get(0),
            )?;
            if count >= MAX_TASKS as i64 {
                let oldest: Option<(String, String)> = tx
                    .query_row(
                        "SELECT agent, id FROM tasks WHERE sandbox = ?1 AND ended IS NOT NULL ORDER BY ended, id LIMIT 1",
                        params![sandbox],
                        |r| Ok((r.get(0)?, r.get(1)?)),
                    )
                    .optional()?;
                let Some((agent, id)) = oldest else {
                    changes.full += 1;
                    return Ok(());
                };
                tx.execute(
                    "DELETE FROM tasks WHERE sandbox = ?1 AND id = ?2",
                    params![sandbox, id],
                )?;
                changes.removed.push(TaskKey::new(agent, id));
            }
        }
    }
    tx.execute(
        "INSERT INTO tasks (sandbox, id, agent, body, ended) VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(sandbox, id) DO UPDATE SET agent = excluded.agent, body = excluded.body, ended = excluded.ended",
        params![sandbox, task.id, task.assignee, body, ended],
    )?;
    changes.stored.push(task.clone());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use enclos_protocol::task::{Doing, TaskState};

    fn store() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("app.db")).unwrap();
        (dir, store)
    }

    fn task(id: &str, agent: &str, state: TaskState, since: i64) -> Task {
        Task {
            id: id.into(),
            title: format!("task {id}"),
            assignee: agent.into(),
            asked_by: None,
            conversation: None,
            state,
            since,
            summary: None,
            comments: None,
        }
    }

    fn ids(tasks: &[Task]) -> Vec<&str> {
        tasks.iter().map(|t| t.id.as_str()).collect()
    }

    #[test]
    fn a_task_is_kept_and_an_unchanged_one_changes_nothing() {
        let (_d, s) = store();
        let t = task("t1", "lab/eng", TaskState::Running, 10);
        assert_eq!(ids(&s.put_task("lab", &t, 100).unwrap().stored), ["t1"]);
        assert_eq!(s.put_task("lab", &t, 101).unwrap(), TaskChanges::default());
        let (kept, _) = s.tasks(102).unwrap();
        assert_eq!(kept, vec![t]);
    }

    #[test]
    fn an_ended_task_is_dropped_three_days_after_the_bridge_saw_it_end() {
        let (_d, s) = store();
        s.put_task("lab", &task("t1", "lab/eng", TaskState::Done, 5), 1_000)
            .unwrap();
        // Reported again later, still done: it ended when first seen
        s.put_task("lab", &task("t1", "lab/eng", TaskState::Done, 6), 2_000)
            .unwrap();
        assert_eq!(s.tasks(1_000 + ENDED_RETENTION_SECS).unwrap().0.len(), 1);
        let (kept, removed) = s.tasks(1_001 + ENDED_RETENTION_SECS).unwrap();
        assert!(kept.is_empty());
        assert_eq!(removed, vec![TaskKey::new("lab/eng", "t1")]);
    }

    #[test]
    fn a_full_sandbox_drops_the_task_that_ended_first_then_refuses() {
        let (_d, s) = store();
        for i in 0..MAX_TASKS {
            let state = if i < 2 {
                TaskState::Done
            } else {
                TaskState::Running
            };
            s.put_task(
                "lab",
                &task(&format!("t{i}"), "lab/eng", state, 1),
                i as i64,
            )
            .unwrap();
        }
        // Another sandbox has room of its own
        assert_eq!(
            s.put_task("other", &task("x", "other/eng", TaskState::Queued, 1), 500)
                .unwrap()
                .stored
                .len(),
            1
        );
        let made_room = s
            .put_task("lab", &task("new", "lab/eng", TaskState::Queued, 1), 500)
            .unwrap();
        assert_eq!(made_room.removed, vec![TaskKey::new("lab/eng", "t0")]);
        assert_eq!(ids(&made_room.stored), ["new"]);
        s.put_task("lab", &task("new2", "lab/eng", TaskState::Queued, 1), 500)
            .unwrap();
        let refused = s
            .put_task("lab", &task("new3", "lab/eng", TaskState::Queued, 1), 500)
            .unwrap();
        assert_eq!(refused.full, 1);
        assert!(refused.stored.is_empty());
        // An update of a kept one still goes in
        let update = s
            .put_task("lab", &task("t5", "lab/eng", TaskState::Done, 2), 500)
            .unwrap();
        assert_eq!(ids(&update.stored), ["t5"]);
    }

    #[test]
    fn a_list_replaces_that_agents_tasks_and_no_other_agents() {
        let (_d, s) = store();
        s.put_task("lab", &task("a", "lab/eng", TaskState::Running, 1), 10)
            .unwrap();
        s.put_task("lab", &task("b", "lab/eng", TaskState::Blocked, 1), 10)
            .unwrap();
        s.put_task("lab", &task("c", "lab/ops", TaskState::Running, 1), 10)
            .unwrap();
        let changes = s
            .replace_tasks(
                "lab",
                "lab/eng",
                &[
                    task("b", "lab/eng", TaskState::Done, 2),
                    task("d", "lab/eng", TaskState::Queued, 3),
                ],
                20,
            )
            .unwrap();
        assert_eq!(changes.removed, vec![TaskKey::new("lab/eng", "a")]);
        assert_eq!(ids(&changes.stored), ["b", "d"]);
        let (kept, _) = s.tasks(30).unwrap();
        // Going first, the newest first, then the ended ones
        assert_eq!(ids(&kept), ["d", "c", "b"]);
    }

    #[test]
    fn a_task_given_to_another_agent_is_removed_under_the_first() {
        let (_d, s) = store();
        s.put_task("lab", &task("a", "lab/eng", TaskState::Running, 1), 10)
            .unwrap();
        let moved = s
            .put_task("lab", &task("a", "lab/ops", TaskState::Queued, 2), 11)
            .unwrap();
        assert_eq!(moved.removed, vec![TaskKey::new("lab/eng", "a")]);
        // The first agent's list no longer drops it
        let list = s.replace_tasks("lab", "lab/eng", &[], 12).unwrap();
        assert!(list.removed.is_empty());
        assert_eq!(s.tasks(13).unwrap().0[0].assignee, "lab/ops");
    }

    #[test]
    fn activity_is_recorded_until_idle_and_read_without_writing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("app.db");
        let s = Store::open(&path).unwrap();
        let busy = Activity {
            doing: vec![Doing::Task { task: "t1".into() }],
            since: 4,
        };
        s.set_activity("lab/eng", &busy).unwrap();
        s.set_activity("lab/ops", &busy).unwrap();
        s.set_activity("lab/ops", &Activity::default()).unwrap();
        let read = Store::read_activity(&path).unwrap();
        assert_eq!(read.len(), 1);
        assert_eq!(read["lab/eng"], busy);
        s.clear_activity().unwrap();
        assert!(Store::read_activity(&path).unwrap().is_empty());
    }

    #[test]
    fn a_bridge_runs_while_it_holds_its_lock_and_not_after() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("app.db");
        assert!(!bridge_runs(&path).unwrap());
        let held = hold_live(&path).unwrap();
        assert!(bridge_runs(&path).unwrap());
        // A check does not take the lock from the bridge
        assert!(bridge_runs(&path).unwrap());
        drop(held);
        assert!(!bridge_runs(&path).unwrap());
    }

    #[test]
    fn a_database_from_before_activity_reads_as_no_activity() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("app.db");
        rusqlite::Connection::open(&path)
            .unwrap()
            .execute_batch("CREATE TABLE settings (name TEXT PRIMARY KEY, value TEXT)")
            .unwrap();
        assert!(Store::read_activity(&path).unwrap().is_empty());
    }
}
