//! Held tasks' cards (ADR 0066, proposed; `docs/protocol.md`, Held tasks):
//! one per task an agent's runtime holds, in that agent's Home, with the
//! history messages that say when a task was held and when it no longer is,
//! stored together.
use super::*;
use enclos_protocol::held_task::{HeldTask, HeldTaskInfo, HeldTaskState};
use enclos_protocol::{ConversationId, HeldTaskId};

/// A card as the bridge keeps it: what a device sees, the runtime's own
/// revision of the hold, which only the plugin is sent, and who sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredHeldTask {
    pub info: HeldTaskInfo,
    pub runtime_revision: String,
    pub owner: String,
}

/// A card that changed, and the history message the change added, if any.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeldTaskChange {
    pub card: StoredHeldTask,
    pub message: Option<Message>,
}

const HELD_COLUMNS: &str = "SELECT h.agent, h.conversation, h.body, h.state, h.revision, c.owner
     FROM held_tasks h JOIN conversations c ON c.id = h.conversation";

fn state_text(state: HeldTaskState) -> &'static str {
    match state {
        HeldTaskState::Held => "held",
        HeldTaskState::Resumed => "resumed",
        HeldTaskState::Released => "released",
        HeldTaskState::Expired => "expired",
        HeldTaskState::Unknown => "unknown",
    }
}

fn state_of(text: &str) -> HeldTaskState {
    match text {
        "held" => HeldTaskState::Held,
        "resumed" => HeldTaskState::Resumed,
        "released" => HeldTaskState::Released,
        "expired" => HeldTaskState::Expired,
        _ => HeldTaskState::Unknown,
    }
}

fn conversion(
    column: usize,
    error: impl std::error::Error + Send + Sync + 'static,
) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(column, rusqlite::types::Type::Text, Box::new(error))
}

fn read_card(row: &rusqlite::Row) -> rusqlite::Result<StoredHeldTask> {
    let body: String = row.get(2)?;
    let task: HeldTask = serde_json::from_str(&body).map_err(|e| conversion(2, e))?;
    let revision: i64 = row.get(4)?;
    Ok(StoredHeldTask {
        info: HeldTaskInfo {
            agent: row.get(0)?,
            conversation: ConversationId::new(row.get::<_, String>(1)?)
                .map_err(|e| conversion(1, e))?,
            task: task.task,
            title: task.title,
            assignee: task.assignee,
            reason: task.reason,
            last_error: task.last_error,
            since: task.since,
            resume: task.resume,
            state: state_of(&row.get::<_, String>(3)?),
            revision: revision
                .try_into()
                .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(4, revision))?,
        },
        runtime_revision: task.revision,
        owner: row.get(5)?,
    })
}

fn card_in(db: &Connection, agent: &str, task: &str) -> rusqlite::Result<Option<StoredHeldTask>> {
    db.query_row(
        &format!("{HELD_COLUMNS} WHERE h.agent = ?1 AND h.task = ?2"),
        params![agent, task],
        read_card,
    )
    .optional()
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
    if !task.resume.is_empty() {
        text.push_str(&format!("\nResume: {}", task.resume));
    }
    text
}

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

/// Moves a held card to `state`, with its quiet history line.
fn leave(
    tx: &Connection,
    card: &StoredHeldTask,
    state: HeldTaskState,
) -> rusqlite::Result<HeldTaskChange> {
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
        self.db
            .query_row(
                &format!("{HELD_COLUMNS} WHERE h.conversation = ?1 AND h.task = ?2"),
                params![conversation, task],
                read_card,
            )
            .optional()
    }

    /// Every card still `held` in `person`'s conversations, oldest first:
    /// what each sync sends, whatever its `since`.
    pub fn held_tasks_for(&self, person: &str) -> rusqlite::Result<Vec<StoredHeldTask>> {
        self.db
            .prepare(&format!(
                "{HELD_COLUMNS} WHERE c.owner = ?1 AND h.state = 'held' ORDER BY h.rowid"
            ))?
            .query_map([person], read_card)?
            .collect()
    }

    /// Takes `tasks`, every task `agent`'s runtime holds now, already
    /// checked and normalized, into the cards of `home`, its Home, in one
    /// transaction: a task newly held (or held again) gets a `held` card
    /// and its message; a held card whose task changed is updated with no
    /// message; a held card whose task is not listed is released, with
    /// its quiet line. The changes, for the devices.
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
                // Still held: new details, no new message.
                Some(card) if card.info.state == HeldTaskState::Held => {
                    let stored: String = tx.query_row(
                        "SELECT body FROM held_tasks WHERE agent = ?1 AND task = ?2",
                        params![agent, task.task.as_str()],
                        |row| row.get(0),
                    )?;
                    if stored == body {
                        continue;
                    }
                    tx.execute(
                        "UPDATE held_tasks SET body = ?3, revision = revision + 1
                         WHERE agent = ?1 AND task = ?2",
                        params![agent, task.task.as_str(), body],
                    )?;
                    None
                }
                // Held again after its card left `held`.
                Some(_) => {
                    tx.execute(
                        "UPDATE held_tasks SET body = ?3, state = 'held', revision = revision + 1,
                         conversation = ?4 WHERE agent = ?1 AND task = ?2",
                        params![agent, task.task.as_str(), body, home],
                    )?;
                    Some(add_message(
                        &tx,
                        home,
                        &task.task,
                        &held_text(task),
                        "notify",
                    )?)
                }
                None => {
                    tx.execute(
                        "INSERT INTO held_tasks(agent, task, conversation, body, state, revision)
                         VALUES (?1, ?2, ?3, ?4, 'held', 0)",
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
        let held: Vec<StoredHeldTask> = tx
            .prepare(&format!(
                "{HELD_COLUMNS} WHERE h.agent = ?1 AND h.state = 'held' ORDER BY h.rowid"
            ))?
            .query_map([agent], read_card)?
            .collect::<rusqlite::Result<_>>()?;
        for card in held {
            if !listed.contains(card.info.task.as_str()) {
                changes.push(leave(&tx, &card, HeldTaskState::Released)?);
            }
        }
        tx.commit()?;
        Ok(changes)
    }

    /// The runtime confirmed a device's resume of `task`: its card is
    /// `resumed`, with its line. A card already released by a report that
    /// came first is marked resumed too, since the person's resume is what
    /// ran; one resumed already, or unknown, changes nothing (`None`).
    pub fn resume_held_task(
        &self,
        agent: &str,
        task: &str,
    ) -> rusqlite::Result<Option<HeldTaskChange>> {
        let tx = rusqlite::Transaction::new_unchecked(
            &self.db,
            rusqlite::TransactionBehavior::Immediate,
        )?;
        let Some(card) = card_in(&tx, agent, task)? else {
            return Ok(None);
        };
        if !matches!(
            card.info.state,
            HeldTaskState::Held | HeldTaskState::Released
        ) {
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
        let held: Vec<StoredHeldTask> = tx
            .prepare(&format!(
                "{HELD_COLUMNS} WHERE h.agent = ?1 AND h.state = 'held' ORDER BY h.rowid"
            ))?
            .query_map([agent], read_card)?
            .collect::<rusqlite::Result<_>>()?;
        let mut changes = Vec::new();
        for card in held {
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
            revision: "e:1".into(),
            resume: "Runs it again with a fresh retry budget.".into(),
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
        assert_eq!(change.card.runtime_revision, "e:1");
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
        let change = store.resume_held_task(AGENT, "t1").unwrap().unwrap();
        assert_eq!(change.card.info.state, HeldTaskState::Resumed);
        assert_eq!(
            change.message.unwrap().text,
            "Resumed from the app: Task t1"
        );
        assert!(store.resume_held_task(AGENT, "t1").unwrap().is_none());
        assert!(store.resume_held_task(AGENT, "missing").unwrap().is_none());
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
        let change = store.resume_held_task(AGENT, "t1").unwrap().unwrap();
        assert_eq!(change.card.info.state, HeldTaskState::Resumed);
    }
}
