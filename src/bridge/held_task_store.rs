//! Held tasks' cards (ADR 0066, proposed; `docs/protocol.md`, Held tasks):
//! one per task an agent's runtime holds, in that agent's Home, with the
//! history messages that say when a task was held and when it no longer is,
//! stored together.
use super::*;
use enclos_protocol::held_task::{HeldTask, HeldTaskInfo, HeldTaskState};
use enclos_protocol::{ConversationId, HeldTaskId, HeldTaskRevision};

/// A card as the bridge keeps it: what a device sees, the runtime's own
/// revision of the hold, which only the plugin is sent, and who sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredHeldTask {
    pub info: HeldTaskInfo,
    pub runtime_revision: HeldTaskRevision,
    pub owner: String,
}

/// A card that changed, and the history message the change added, if any.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeldTaskChange {
    pub card: StoredHeldTask,
    pub message: Option<Message>,
}

const HELD_COLUMNS: &str =
    "SELECT h.agent, h.conversation, h.body, h.state, h.revision, c.owner, h.task
     FROM held_tasks h JOIN conversations c ON c.id = h.conversation";

/// A state a card is stored in: never [`HeldTaskState::Unknown`], which
/// only a device reads, for a state from a newer bridge.
fn state_text(state: HeldTaskState) -> &'static str {
    match state {
        HeldTaskState::Held => "held",
        HeldTaskState::Resumed => "resumed",
        HeldTaskState::Released => "released",
        HeldTaskState::Expired => "expired",
        HeldTaskState::Unknown => unreachable!("the bridge never stores an unknown state"),
    }
}

fn state_of(text: &str) -> Option<HeldTaskState> {
    match text {
        "held" => Some(HeldTaskState::Held),
        "resumed" => Some(HeldTaskState::Resumed),
        "released" => Some(HeldTaskState::Released),
        "expired" => Some(HeldTaskState::Expired),
        _ => None,
    }
}

/// A card row, or why it no longer reads (`Err`): a body or state an
/// earlier build wrote that this one refuses.
type Row = Result<StoredHeldTask, String>;

fn read_card(row: &rusqlite::Row) -> rusqlite::Result<Row> {
    let body: String = row.get(2)?;
    let state: String = row.get(3)?;
    let revision: i64 = row.get(4)?;
    let conversation: String = row.get(1)?;
    let agent: String = row.get(0)?;
    let owner: String = row.get(5)?;
    let task: HeldTask = match serde_json::from_str(&body) {
        Ok(task) => task,
        Err(e) => return Ok(Err(format!("its body does not read: {e}"))),
    };
    let Some(state) = state_of(&state) else {
        return Ok(Err(format!("its state {state:?} is unknown")));
    };
    let (Ok(conversation), Ok(revision)) =
        (ConversationId::new(conversation), u64::try_from(revision))
    else {
        return Ok(Err("its conversation or revision does not read".into()));
    };
    Ok(Ok(StoredHeldTask {
        info: HeldTaskInfo {
            agent,
            conversation,
            task: task.task,
            title: task.title,
            assignee: task.assignee,
            reason: task.reason,
            last_error: task.last_error,
            since: task.since,
            resume: task.resume,
            resumable: task.resumable,
            state,
            revision,
        },
        runtime_revision: task.revision,
        owner,
    }))
}

/// `row`, or `None` for one that no longer reads, said on stderr: one such
/// row is left out of every read rather than failing it, which would end
/// every sync of its owner and refuse every report of its agent. The next
/// report that lists its task writes it again.
fn usable(row: rusqlite::Result<Row>) -> rusqlite::Result<Option<StoredHeldTask>> {
    match row? {
        Ok(card) => Ok(Some(card)),
        Err(why) => {
            eprintln!("enclos app: a held task's card is left out: {why}");
            Ok(None)
        }
    }
}

fn cards(db: &Connection, condition: &str, key: &str) -> rusqlite::Result<Vec<StoredHeldTask>> {
    let mut query = db.prepare(&format!(
        "{HELD_COLUMNS} WHERE {condition} ORDER BY h.rowid"
    ))?;
    let rows = query.query_map([key], read_card)?;
    let mut kept = Vec::new();
    for row in rows {
        kept.extend(usable(row)?);
    }
    Ok(kept)
}

fn card_in(db: &Connection, agent: &str, task: &str) -> rusqlite::Result<Option<StoredHeldTask>> {
    match db
        .query_row(
            &format!("{HELD_COLUMNS} WHERE h.agent = ?1 AND h.task = ?2"),
            params![agent, task],
            read_card,
        )
        .optional()?
    {
        Some(row) => usable(Ok(row)),
        None => Ok(None),
    }
}

/// What a card's first history message says: readable on its own, so an
/// app that does not know held tasks still tells the person.
pub fn held_text(task: &HeldTask) -> String {
    let mut text = format!("Held task: {}\n{}", task.title, task.reason);
    if let Some(assignee) = &task.assignee {
        text.push_str(&format!("\nAssigned to {assignee}."));
    }
    if let Some(error) = &task.last_error {
        text.push_str(&format!("\nLast error: {error}"));
    }
    if !task.resumable {
        // What to do instead, never as a Resume.
        let instead = if task.resume.is_empty() {
            NOT_RESUMABLE
        } else {
            &task.resume
        };
        text.push_str(&format!("\n{instead}"));
    } else if !task.resume.is_empty() {
        text.push_str(&format!("\nResume: {}", task.resume));
    }
    text
}

/// What a card's first message says of a task that cannot be resumed from
/// the app when its runtime says nothing more.
const NOT_RESUMABLE: &str = "This task cannot be resumed from the app.";

/// What the quiet line says when a card leaves `held`.
fn left_text(state: HeldTaskState, title: &str) -> String {
    match state {
        HeldTaskState::Resumed => format!("Resumed from the app: {title}"),
        HeldTaskState::Expired => {
            format!("No longer tracked: {title}. The agent's channel stopped reporting held tasks.")
        }
        _ => format!("No longer held: {title}"),
    }
}

/// Stores a history message of a card and returns it as stored.
fn add_message(
    tx: &Connection,
    conversation: &str,
    task: &HeldTaskId,
    text: &str,
    kind: &str,
) -> rusqlite::Result<Message> {
    let id = new_message_id()?;
    tx.execute(
        "INSERT INTO messages(id, conversation, person, text, kind, at, held_task)
         VALUES (?1, ?2, NULL, ?3, ?4, ?5, ?6)",
        params![id, conversation, text, kind, now(), task.as_str()],
    )?;
    tx.query_row(
        &format!("{MESSAGE_COLUMNS} WHERE id = ?1"),
        params![id],
        message_row,
    )
}

/// A new message id: a UUID, as the bridge's own messages have.
fn new_message_id() -> rusqlite::Result<String> {
    crate::bridge::ids::new_id().map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))
}

/// Moves a card to `state`, one a card leaves `held` for, with its quiet
/// history line.
fn leave(
    tx: &Connection,
    card: &StoredHeldTask,
    state: HeldTaskState,
) -> rusqlite::Result<HeldTaskChange> {
    debug_assert!(matches!(
        state,
        HeldTaskState::Resumed | HeldTaskState::Released | HeldTaskState::Expired
    ));
    let info = &card.info;
    tx.execute(
        "UPDATE held_tasks SET state = ?3, revision = revision + 1 WHERE agent = ?1 AND task = ?2",
        params![info.agent, info.task.as_str(), state_text(state)],
    )?;
    let message = add_message(
        tx,
        info.conversation.as_str(),
        &info.task,
        &left_text(state, &info.title),
        "status",
    )?;
    let card = card_in(tx, &info.agent, info.task.as_str())?
        .ok_or(rusqlite::Error::QueryReturnedNoRows)?;
    Ok(HeldTaskChange {
        card,
        message: Some(message),
    })
}

impl Store {
    /// Agent `agent`'s card for `task`.
    pub fn held_task(&self, agent: &str, task: &str) -> rusqlite::Result<Option<StoredHeldTask>> {
        card_in(&self.db, agent, task)
    }

    /// The card a history message of conversation `conversation` links to.
    pub fn held_task_in(
        &self,
        conversation: &str,
        task: &str,
    ) -> rusqlite::Result<Option<StoredHeldTask>> {
        match self
            .db
            .query_row(
                &format!("{HELD_COLUMNS} WHERE h.conversation = ?1 AND h.task = ?2"),
                params![conversation, task],
                read_card,
            )
            .optional()?
        {
            Some(row) => usable(Ok(row)),
            None => Ok(None),
        }
    }

    /// Every card still `held` in `person`'s conversations, oldest first:
    /// what each sync sends, whatever its `since`.
    pub fn held_tasks_for(&self, person: &str) -> rusqlite::Result<Vec<StoredHeldTask>> {
        cards(&self.db, "c.owner = ?1 AND h.state = 'held'", person)
    }

    /// Takes `tasks`, every task `agent`'s runtime holds now, already
    /// accepted ([`enclos_protocol::held_task::accept`]), into the cards of
    /// `home`, its Home, in one transaction: a task newly held (or held
    /// again) gets a `held` card and its message; a held card whose task
    /// changed is updated with no message; a held card whose task is not
    /// listed is released, with its quiet line. A resumed card listed at
    /// the revision it was resumed at is a report read before the resume,
    /// and changes nothing. The changes, for the devices.
    pub fn report_held_tasks(
        &self,
        agent: &str,
        home: &str,
        tasks: &[HeldTask],
    ) -> rusqlite::Result<Vec<HeldTaskChange>> {
        let tx = rusqlite::Transaction::new_unchecked(
            &self.db,
            rusqlite::TransactionBehavior::Immediate,
        )?;
        let mut changes = Vec::new();
        let mut listed = std::collections::HashSet::new();
        for task in tasks {
            listed.insert(task.task.as_str());
            let body = serde_json::to_string(task)
                .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
            let current = card_in(&tx, agent, task.task.as_str())?;
            let message = match &current {
                // Still held: new details, no new message. Compared as read,
                // so a body an earlier build wrote without a field that now
                // reads as its default is no change.
                Some(card) if card.info.state == HeldTaskState::Held => {
                    let stored: String = tx.query_row(
                        "SELECT body FROM held_tasks WHERE agent = ?1 AND task = ?2",
                        params![agent, task.task.as_str()],
                        |row| row.get(0),
                    )?;
                    if serde_json::from_str::<HeldTask>(&stored).is_ok_and(|stored| stored == *task)
                    {
                        continue;
                    }
                    tx.execute(
                        "UPDATE held_tasks SET body = ?3, revision = revision + 1
                         WHERE agent = ?1 AND task = ?2",
                        params![agent, task.task.as_str(), body],
                    )?;
                    None
                }
                // Read before the resume the runtime confirmed since.
                Some(card)
                    if card.info.state == HeldTaskState::Resumed
                        && card.runtime_revision == task.revision =>
                {
                    continue;
                }
                // Held again after its card left `held`, or first held; a
                // row that no longer reads is written again.
                _ => {
                    tx.execute(
                        "INSERT INTO held_tasks(agent, task, conversation, body, state, revision)
                         VALUES (?1, ?2, ?3, ?4, 'held', 0)
                         ON CONFLICT(agent, task) DO UPDATE SET conversation = excluded.conversation,
                         body = excluded.body, state = 'held', revision = held_tasks.revision + 1",
                        params![agent, task.task.as_str(), home, body],
                    )?;
                    Some(add_message(
                        &tx,
                        home,
                        &task.task,
                        &held_text(task),
                        "notify",
                    )?)
                }
            };
            let card = card_in(&tx, agent, task.task.as_str())?
                .ok_or(rusqlite::Error::QueryReturnedNoRows)?;
            changes.push(HeldTaskChange { card, message });
        }
        for card in cards(&tx, "h.agent = ?1 AND h.state = 'held'", agent)? {
            if !listed.contains(card.info.task.as_str()) {
                changes.push(leave(&tx, &card, HeldTaskState::Released)?);
            }
        }
        tx.commit()?;
        Ok(changes)
    }

    /// The runtime confirmed a device's resume of `task`, sent at the
    /// runtime's revision `sent`: its card is `resumed`, with its line. A
    /// card already released by a report that came first is marked resumed
    /// too, since the person's resume is what ran. A card held again at
    /// another revision meanwhile, or already resumed or expired, or none,
    /// changes nothing (`None`).
    pub fn resume_held_task(
        &self,
        agent: &str,
        task: &str,
        sent: &HeldTaskRevision,
    ) -> rusqlite::Result<Option<HeldTaskChange>> {
        let tx = rusqlite::Transaction::new_unchecked(
            &self.db,
            rusqlite::TransactionBehavior::Immediate,
        )?;
        let Some(card) = card_in(&tx, agent, task)? else {
            return Ok(None);
        };
        let resumable = match card.info.state {
            HeldTaskState::Held => card.runtime_revision == *sent,
            HeldTaskState::Released => true,
            _ => false,
        };
        if !resumable {
            return Ok(None);
        }
        let change = leave(&tx, &card, HeldTaskState::Resumed)?;
        tx.commit()?;
        Ok(Some(change))
    }

    /// `agent`'s channel connected without `held_tasks`: its held cards can
    /// no longer tell, and expire, each with its line.
    pub fn expire_held_tasks(&self, agent: &str) -> rusqlite::Result<Vec<HeldTaskChange>> {
        let tx = rusqlite::Transaction::new_unchecked(
            &self.db,
            rusqlite::TransactionBehavior::Immediate,
        )?;
        let mut changes = Vec::new();
        for card in cards(&tx, "h.agent = ?1 AND h.state = 'held'", agent)? {
            changes.push(leave(&tx, &card, HeldTaskState::Expired)?);
        }
        tx.commit()?;
        Ok(changes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OWNER: &str = "owner@example.com";
    const AGENT: &str = "lab/main";

    fn store() -> (tempfile::TempDir, Store, String) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("app.db")).unwrap();
        store.ensure_home(AGENT, OWNER, true).unwrap();
        (dir, store, home_id(AGENT))
    }

    fn task(id: &str, reason: &str) -> HeldTask {
        HeldTask {
            task: HeldTaskId::new(id).unwrap(),
            title: format!("Task {id}"),
            assignee: None,
            reason: reason.into(),
            last_error: Some("boom".into()),
            since: 1_763_000_000,
            revision: HeldTaskRevision::new("e:1").unwrap(),
            resume: "Runs it again with a fresh retry budget.".into(),
            resumable: true,
        }
    }

    #[test]
    fn a_new_hold_stores_a_card_and_a_readable_message_together() {
        let (_dir, store, home) = store();
        let changes = store
            .report_held_tasks(AGENT, &home, &[task("t1", "Needs a decision")])
            .unwrap();
        assert_eq!(changes.len(), 1);
        let change = &changes[0];
        assert_eq!(change.card.info.state, HeldTaskState::Held);
        assert_eq!(change.card.info.revision, 0);
        assert_eq!(change.card.owner, OWNER);
        assert_eq!(change.card.runtime_revision.as_str(), "e:1");
        let message = change.message.as_ref().unwrap();
        assert_eq!(message.kind, "notify");
        assert_eq!(message.from, From::Agent);
        assert_eq!(message.held_task.as_ref().unwrap().as_str(), "t1");
        assert_eq!(
            message.text,
            "Held task: Task t1\nNeeds a decision\nLast error: boom\nResume: Runs it again with a fresh retry budget."
        );
        // The message is in the Home's history, linked to its card.
        let history = store.since(OWNER, 0).unwrap();
        assert_eq!(history.last().unwrap().held_task, message.held_task);
        assert_eq!(store.held_tasks_for(OWNER).unwrap().len(), 1);
        assert!(
            store
                .held_tasks_for("guest@example.com")
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            store
                .held_task_in(&home, "t1")
                .unwrap()
                .unwrap()
                .info
                .task
                .as_str(),
            "t1"
        );
    }

    #[test]
    fn the_same_report_again_changes_nothing_and_new_details_add_no_message() {
        let (_dir, store, home) = store();
        store
            .report_held_tasks(AGENT, &home, &[task("t1", "first")])
            .unwrap();
        let before = store.newest_seq().unwrap();
        assert!(
            store
                .report_held_tasks(AGENT, &home, &[task("t1", "first")])
                .unwrap()
                .is_empty()
        );
        let changes = store
            .report_held_tasks(AGENT, &home, &[task("t1", "second")])
            .unwrap();
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].card.info.reason, "second");
        assert_eq!(changes[0].card.info.revision, 1);
        assert!(changes[0].message.is_none());
        assert_eq!(store.newest_seq().unwrap(), before);
    }

    /// Only whether it can be resumed changes: the card is updated once
    /// each way, with no new history, and stays as it was through a reopen.
    #[test]
    fn a_change_of_resumable_alone_updates_the_card_once_each_way() {
        let (dir, store, home) = store();
        store
            .report_held_tasks(AGENT, &home, &[task("t1", "r")])
            .unwrap();
        let before = store.newest_seq().unwrap();
        let not_here = HeldTask {
            resumable: false,
            ..task("t1", "r")
        };
        let changes = store
            .report_held_tasks(AGENT, &home, std::slice::from_ref(&not_here))
            .unwrap();
        assert_eq!(changes.len(), 1);
        assert!(!changes[0].card.info.resumable);
        assert_eq!(changes[0].card.info.state, HeldTaskState::Held);
        assert_eq!(changes[0].card.info.revision, 1);
        assert_eq!(changes[0].card.runtime_revision.as_str(), "e:1");
        assert!(changes[0].message.is_none());
        // The same report again changes nothing.
        assert!(
            store
                .report_held_tasks(AGENT, &home, std::slice::from_ref(&not_here))
                .unwrap()
                .is_empty()
        );
        assert_eq!(store.newest_seq().unwrap(), before);
        // As stored.
        drop(store);
        let store = Store::open(&dir.path().join("app.db")).unwrap();
        let card = store.held_task(AGENT, "t1").unwrap().unwrap();
        assert!(!card.info.resumable);
        assert_eq!(card.info.revision, 1);
        assert!(!store.held_tasks_for(OWNER).unwrap()[0].info.resumable);
        // And back.
        let changes = store
            .report_held_tasks(AGENT, &home, &[task("t1", "r")])
            .unwrap();
        assert_eq!(changes.len(), 1);
        assert!(changes[0].card.info.resumable);
        assert_eq!(changes[0].card.info.revision, 2);
        assert!(changes[0].message.is_none());
        assert_eq!(store.newest_seq().unwrap(), before);
    }

    /// A card an earlier bridge stored has no `resumable`: it reads as
    /// true, and the same task reported again is no change.
    #[test]
    fn a_card_stored_without_resumable_reads_as_resumable_and_does_not_change() {
        let (dir, store, home) = store();
        store
            .report_held_tasks(AGENT, &home, &[task("t1", "r")])
            .unwrap();
        let body: String = store
            .db
            .query_row("SELECT body FROM held_tasks WHERE task = 't1'", [], |row| {
                row.get(0)
            })
            .unwrap();
        let mut older: serde_json::Value = serde_json::from_str(&body).unwrap();
        older.as_object_mut().unwrap().remove("resumable");
        store
            .db
            .execute(
                "UPDATE held_tasks SET body = ?1 WHERE task = 't1'",
                params![older.to_string()],
            )
            .unwrap();
        let card = store.held_task(AGENT, "t1").unwrap().unwrap();
        assert!(card.info.resumable);
        assert_eq!(card.info.revision, 0);
        // Read again by a bridge that opens the database afresh, as after
        // an upgrade: the body on disk still has no `resumable`.
        drop(store);
        let store = Store::open(&dir.path().join("app.db")).unwrap();
        let body: String = store
            .db
            .query_row("SELECT body FROM held_tasks WHERE task = 't1'", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert!(!body.contains("resumable"), "{body}");
        let card = store.held_task(AGENT, "t1").unwrap().unwrap();
        assert_eq!(
            (card.info.resumable, card.info.revision, card.info.state),
            (true, 0, HeldTaskState::Held)
        );
        assert!(store.held_tasks_for(OWNER).unwrap()[0].info.resumable);
        let seq = store.newest_seq().unwrap();
        assert!(
            store
                .report_held_tasks(AGENT, &home, &[task("t1", "r")])
                .unwrap()
                .is_empty()
        );
        assert_eq!(store.newest_seq().unwrap(), seq);
        assert_eq!(
            store.held_task(AGENT, "t1").unwrap().unwrap().info.revision,
            0
        );
    }

    /// A task that cannot be resumed from the app says what to do instead,
    /// not as a Resume.
    #[test]
    fn a_task_not_resumable_here_is_introduced_without_a_resume() {
        let (_dir, store, home) = store();
        let changes = store
            .report_held_tasks(
                AGENT,
                &home,
                &[
                    HeldTask {
                        resumable: false,
                        resume: "Decide on the agent's task board.".into(),
                        ..task("t1", "Blocked again")
                    },
                    HeldTask {
                        resumable: false,
                        resume: String::new(),
                        ..task("t2", "Blocked again")
                    },
                ],
            )
            .unwrap();
        let texts: Vec<_> = changes
            .iter()
            .map(|change| change.message.as_ref().unwrap().text.as_str())
            .collect();
        assert_eq!(
            texts,
            [
                "Held task: Task t1\nBlocked again\nLast error: boom\nDecide on the agent's task board.",
                "Held task: Task t2\nBlocked again\nLast error: boom\nThis task cannot be resumed from the app.",
            ]
        );
        assert!(changes.iter().all(|change| !change.card.info.resumable));
    }

    #[test]
    fn a_task_left_out_is_released_and_one_held_again_reopens_its_card() {
        let (_dir, store, home) = store();
        store
            .report_held_tasks(AGENT, &home, &[task("t1", "r"), task("t2", "r")])
            .unwrap();
        let changes = store
            .report_held_tasks(AGENT, &home, &[task("t2", "r")])
            .unwrap();
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].card.info.task.as_str(), "t1");
        assert_eq!(changes[0].card.info.state, HeldTaskState::Released);
        let line = changes[0].message.as_ref().unwrap();
        assert_eq!(line.kind, "status");
        assert_eq!(line.text, "No longer held: Task t1");
        assert_eq!(store.held_tasks_for(OWNER).unwrap().len(), 1);
        // Held again: the same card, back to held, with a new message.
        let changes = store
            .report_held_tasks(AGENT, &home, &[task("t1", "again"), task("t2", "r")])
            .unwrap();
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].card.info.state, HeldTaskState::Held);
        assert_eq!(changes[0].card.info.revision, 2);
        assert_eq!(changes[0].message.as_ref().unwrap().kind, "notify");
        // An empty report releases every held card.
        let changes = store.report_held_tasks(AGENT, &home, &[]).unwrap();
        assert_eq!(changes.len(), 2);
        assert!(store.held_tasks_for(OWNER).unwrap().is_empty());
    }

    #[test]
    fn a_report_names_only_its_own_agents_cards() {
        let (_dir, store, home) = store();
        store.ensure_home("lab/other", OWNER, true).unwrap();
        store
            .report_held_tasks("lab/other", &home_id("lab/other"), &[task("t1", "r")])
            .unwrap();
        // Another agent's empty report leaves this card alone, and the same
        // task id is a different card per agent.
        assert!(
            store
                .report_held_tasks(AGENT, &home, &[])
                .unwrap()
                .is_empty()
        );
        let changes = store
            .report_held_tasks(AGENT, &home, &[task("t1", "r")])
            .unwrap();
        assert_eq!(changes[0].card.info.agent, AGENT);
        assert_eq!(store.held_tasks_for(OWNER).unwrap().len(), 2);
    }

    #[test]
    fn a_resume_marks_the_card_once_and_expiry_ends_the_held_ones() {
        let (_dir, store, home) = store();
        store
            .report_held_tasks(AGENT, &home, &[task("t1", "r"), task("t2", "r")])
            .unwrap();
        let change = store
            .resume_held_task(AGENT, "t1", &rev("e:1"))
            .unwrap()
            .unwrap();
        assert_eq!(change.card.info.state, HeldTaskState::Resumed);
        assert_eq!(
            change.message.unwrap().text,
            "Resumed from the app: Task t1"
        );
        assert!(
            store
                .resume_held_task(AGENT, "t1", &rev("e:1"))
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .resume_held_task(AGENT, "missing", &rev("e:1"))
                .unwrap()
                .is_none()
        );
        // The resumed card is not released by the report that follows.
        let changes = store
            .report_held_tasks(AGENT, &home, &[task("t2", "r")])
            .unwrap();
        assert!(changes.is_empty());
        let expired = store.expire_held_tasks(AGENT).unwrap();
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].card.info.state, HeldTaskState::Expired);
        assert!(
            expired[0]
                .message
                .as_ref()
                .unwrap()
                .text
                .starts_with("No longer tracked: Task t2.")
        );
        assert!(store.expire_held_tasks(AGENT).unwrap().is_empty());
    }

    #[test]
    fn a_resume_confirmed_after_a_release_still_says_the_person_resumed_it() {
        let (_dir, store, home) = store();
        store
            .report_held_tasks(AGENT, &home, &[task("t1", "r")])
            .unwrap();
        store.report_held_tasks(AGENT, &home, &[]).unwrap();
        let change = store
            .resume_held_task(AGENT, "t1", &rev("e:1"))
            .unwrap()
            .unwrap();
        assert_eq!(change.card.info.state, HeldTaskState::Resumed);
    }

    fn rev(revision: &str) -> HeldTaskRevision {
        HeldTaskRevision::new(revision).unwrap()
    }

    fn at(id: &str, revision: &str) -> HeldTask {
        HeldTask {
            revision: rev(revision),
            ..task(id, "r")
        }
    }

    #[test]
    fn a_report_read_before_a_resume_does_not_hold_the_card_again() {
        let (_dir, store, home) = store();
        store
            .report_held_tasks(AGENT, &home, &[at("t1", "e:1")])
            .unwrap();
        store
            .resume_held_task(AGENT, "t1", &rev("e:1"))
            .unwrap()
            .unwrap();
        let before = store.newest_seq().unwrap();
        // The same hold, listed late: nothing changes, nobody is notified.
        assert!(
            store
                .report_held_tasks(AGENT, &home, &[at("t1", "e:1")])
                .unwrap()
                .is_empty()
        );
        assert_eq!(store.newest_seq().unwrap(), before);
        assert_eq!(
            store.held_task(AGENT, "t1").unwrap().unwrap().info.state,
            HeldTaskState::Resumed
        );
        // Held again, at a new revision: a new hold.
        let changes = store
            .report_held_tasks(AGENT, &home, &[at("t1", "e:5")])
            .unwrap();
        assert_eq!(changes[0].card.info.state, HeldTaskState::Held);
        assert_eq!(changes[0].message.as_ref().unwrap().kind, "notify");
    }

    #[test]
    fn a_resume_confirmed_for_an_earlier_hold_does_not_mark_a_newer_one() {
        let (_dir, store, home) = store();
        store
            .report_held_tasks(AGENT, &home, &[at("t1", "e:1")])
            .unwrap();
        // Held at a new revision before the confirmation is handled.
        store
            .report_held_tasks(AGENT, &home, &[at("t1", "e:2")])
            .unwrap();
        assert!(
            store
                .resume_held_task(AGENT, "t1", &rev("e:1"))
                .unwrap()
                .is_none()
        );
        assert_eq!(
            store.held_task(AGENT, "t1").unwrap().unwrap().info.state,
            HeldTaskState::Held
        );
    }

    #[test]
    fn a_card_that_no_longer_reads_is_left_out_and_written_again() {
        let (_dir, store, home) = store();
        store
            .report_held_tasks(AGENT, &home, &[task("t1", "r"), task("t2", "r")])
            .unwrap();
        store
            .db
            .execute(
                "UPDATE held_tasks SET body = '{\"not\":\"a task\"}' WHERE task = 't1'",
                [],
            )
            .unwrap();
        store
            .db
            .execute(
                "UPDATE held_tasks SET state = 'later' WHERE task = 't2'",
                [],
            )
            .unwrap();
        // Neither ends a sync nor a report.
        assert!(store.held_tasks_for(OWNER).unwrap().is_empty());
        assert!(store.held_task(AGENT, "t1").unwrap().is_none());
        assert!(
            store
                .report_held_tasks(AGENT, &home, &[])
                .unwrap()
                .is_empty()
        );
        // Listed again, it is written again, with a revision past the old one.
        let changes = store
            .report_held_tasks(AGENT, &home, &[task("t1", "r")])
            .unwrap();
        assert_eq!(changes[0].card.info.state, HeldTaskState::Held);
        assert_eq!(changes[0].card.info.revision, 1);
        assert_eq!(store.held_tasks_for(OWNER).unwrap().len(), 1);
    }

    #[test]
    fn forgetting_an_agent_removes_its_cards() {
        let (_dir, store, home) = store();
        store
            .report_held_tasks(AGENT, &home, &[task("t1", "r")])
            .unwrap();
        store.forget_agent(AGENT, OWNER, "phone").unwrap();
        assert!(store.held_task(AGENT, "t1").unwrap().is_none());
        let left: i64 = store
            .db
            .query_row("SELECT COUNT(*) FROM held_tasks", [], |r| r.get(0))
            .unwrap();
        assert_eq!(left, 0, "no row is left to come back with a Home");
    }

    #[test]
    fn a_database_from_before_held_tasks_opens_with_its_messages() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("app.db");
        let db = Connection::open(&path).unwrap();
        // The shape enclos 0.5.0 wrote, with no held_task column.
        db.execute_batch(
            "CREATE TABLE conversations (id TEXT PRIMARY KEY, sandbox TEXT NOT NULL,
               agent TEXT NOT NULL, owner TEXT NOT NULL, created INTEGER NOT NULL);
             CREATE TABLE messages (seq INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT NOT NULL UNIQUE,
               conversation TEXT NOT NULL, person TEXT, text TEXT NOT NULL, kind TEXT NOT NULL,
               at INTEGER NOT NULL, question TEXT);
             INSERT INTO conversations VALUES ('c1', 'lab', 'main', 'owner@example.com', 1);
             INSERT INTO messages (id, conversation, person, text, kind, at)
               VALUES ('m1', 'c1', NULL, 'hello', 'reply', 1);",
        )
        .unwrap();
        drop(db);
        let store = Store::open(&path).unwrap();
        let messages = store.since(OWNER, 0).unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].held_task, None);
        assert!(store.held_tasks_for(OWNER).unwrap().is_empty());
    }
}
