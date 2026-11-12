//! Atomic question definitions, settlements and their conversation history.
use super::*;
use enclos_protocol::question::{
    QuestionAnswer, QuestionDefinition, QuestionInfo, QuestionState, RuntimeApprovalAction,
};
use enclos_protocol::{ConversationId, QuestionId};

#[derive(Debug, thiserror::Error)]
pub enum QuestionStoreError {
    #[error(transparent)]
    Sql(#[from] rusqlite::Error),
    #[error("The question identity or definition conflicts with an existing question.")]
    Conflict,
    #[error("No such question.")]
    Unknown,
    #[error("{0}")]
    Invalid(String),
    /// Refused for who would answer it, not for what it is.
    #[error("{0}")]
    NotAllowed(String),
}

/// At most this many pending runtime approvals in one conversation, and of
/// one agent across its conversations: each is sent to the host's person's
/// devices at every sync. Hermes holds one at a time in a session, a few
/// with parallel tool calls.
pub const MAX_PENDING_APPROVALS_PER_CONVERSATION: i64 = 4;
pub const MAX_PENDING_APPROVALS_PER_AGENT: i64 = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredQuestion {
    pub info: QuestionInfo,
    pub owner: String,
}

pub struct QuestionChange {
    pub question: StoredQuestion,
    pub message: Option<Message>,
}

/// A question's new state, as its agent's channel or the bridge reports it.
pub struct Settlement {
    pub state: QuestionState,
    pub answer: Option<QuestionAnswer>,
    /// Whether the answer is the one a paired device submitted, matched by
    /// its request: only then does the history say the person answered.
    /// Otherwise it is what the agent reports (a reply in the conversation,
    /// or a plugin that says so), and the history says that.
    pub confirmed: bool,
}

impl Settlement {
    /// A state the agent's channel reports, matched to no device request.
    pub fn reported(state: QuestionState, answer: Option<QuestionAnswer>) -> Self {
        Self {
            state,
            answer,
            confirmed: false,
        }
    }
}

/// At most this many pending questions in one conversation: a runtime asks
/// one at a time there (Hermes presents a batch one by one).
pub const MAX_PENDING_PER_CONVERSATION: i64 = 4;
/// At most this many pending questions of one agent, across its
/// conversations: each is sent to the person's devices at every sync.
pub const MAX_PENDING_PER_AGENT: i64 = 32;

fn json_error(error: impl std::error::Error + Send + Sync + 'static) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(error))
}

/// A question's row: its id, and the question, or why the row no longer
/// reads as one. Rows are checked when they are written; one an earlier
/// build wrote may not pass a rule tightened since, and it is then left
/// out of every read (and said in the log) rather than failing the read,
/// which would end every sync of its owner.
type QuestionRow = (String, Result<StoredQuestion, String>);

fn read_question(row: &rusqlite::Row) -> rusqlite::Result<QuestionRow> {
    let id: String = row.get(0)?;
    let definition: String = row.get(1)?;
    let conversation: String = row.get(2)?;
    let agent: String = row.get(3)?;
    let owner: String = row.get(4)?;
    let state: String = row.get(5)?;
    let revision: i64 = row.get(6)?;
    let answer: Option<String> = row.get(7)?;
    let confirmed: bool = row.get(8)?;
    let parsed = (|| -> Result<StoredQuestion, String> {
        let info = QuestionInfo {
            definition: serde_json::from_str(&definition).map_err(|e| e.to_string())?,
            conversation: ConversationId::new(conversation).map_err(|e| e.to_string())?,
            agent,
            state: serde_json::from_value(serde_json::Value::String(state))
                .map_err(|e| e.to_string())?,
            revision: revision.try_into().map_err(|_| "negative revision")?,
            answer: answer
                .map(|s| serde_json::from_str(&s))
                .transpose()
                .map_err(|e| e.to_string())?,
            confirmed,
        };
        info.validate()?;
        Ok(StoredQuestion { info, owner })
    })();
    Ok((id, parsed))
}

/// The question of a row that still reads as one.
fn usable((id, parsed): QuestionRow) -> Option<StoredQuestion> {
    parsed
        .inspect_err(|e| {
            eprintln!("enclos app: question {id} no longer reads and is left out: {e}")
        })
        .ok()
}

const QUESTION_COLUMNS: &str = "SELECT q.id,q.definition,q.conversation,q.agent,c.owner,q.state,q.revision,q.answer,q.confirmed FROM questions q JOIN conversations c ON c.id=q.conversation";

fn question_in(db: &Connection, id: &str) -> rusqlite::Result<Option<StoredQuestion>> {
    Ok(db
        .query_row(
            &format!("{QUESTION_COLUMNS} WHERE q.id=?1"),
            [id],
            read_question,
        )
        .optional()?
        .and_then(usable))
}

fn history_message(
    db: &Connection,
    question: &str,
    kind: &str,
) -> rusqlite::Result<Option<Message>> {
    db.query_row("SELECT seq,id,conversation,person,text,kind,at,speaker,question FROM messages WHERE question=?1 AND kind=?2 ORDER BY seq DESC LIMIT 1", params![question,kind], message_row).optional()
}

fn origin_conversation(
    db: &Connection,
    origin: &str,
    conversation: &ConversationId,
) -> Result<bool, QuestionStoreError> {
    let (sandbox, target): (String, String) = db
        .query_row(
            "SELECT sandbox,agent FROM conversations WHERE id=?1",
            [conversation.as_str()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?
        .ok_or(QuestionStoreError::Unknown)?;
    let is_member = db
        .query_row(
            "SELECT 1 FROM members WHERE conversation=?1 AND agent=?2",
            params![
                conversation.as_str(),
                origin.split_once('/').map(|(_, a)| a).unwrap_or("")
            ],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if format!("{sandbox}/{target}") != origin
        && !(origin.starts_with(&format!("{sandbox}/")) && is_member)
    {
        return Err(QuestionStoreError::Unknown);
    }
    Ok(is_member)
}

fn state_text(state: &QuestionState) -> String {
    match state {
        QuestionState::Pending => "pending",
        QuestionState::Answered => "answered",
        QuestionState::Skipped => "skipped",
        QuestionState::Expired => "expired",
        QuestionState::Cancelled => "cancelled",
        QuestionState::Resolved => "resolved",
    }
    .into()
}

fn introduction_kind(definition: &QuestionDefinition) -> &'static str {
    if definition.approval.is_some() {
        "runtime_approval"
    } else {
        "question"
    }
}

/// The history line of a settlement. `confirmed`: the answer is the one a
/// paired device submitted, matched by its request; any other is what the
/// agent's channel reports, and an approval says so rather than read as the
/// person's decision.
fn settlement_text(info: &QuestionInfo, confirmed: bool) -> String {
    let lead = if confirmed {
        "Answered"
    } else {
        "Answered, as the agent reports"
    };
    match &info.answer {
        Some(QuestionAnswer::Approval { action }) if confirmed => match action {
            RuntimeApprovalAction::Once => "Runtime approval: allowed once.",
            RuntimeApprovalAction::Session => "Runtime approval: allowed for this runtime session.",
            RuntimeApprovalAction::Always => "Runtime approval: always allowed by this runtime.",
            RuntimeApprovalAction::Deny => "Runtime approval: denied.",
        }
        .into(),
        Some(QuestionAnswer::Approval { action }) => match action {
            RuntimeApprovalAction::Once => "Runtime approval: allowed once, as the agent reports.",
            RuntimeApprovalAction::Session => {
                "Runtime approval: allowed for this runtime session, as the agent reports."
            }
            RuntimeApprovalAction::Always => {
                "Runtime approval: always allowed by this runtime, as the agent reports."
            }
            RuntimeApprovalAction::Deny => "Runtime approval: denied, as the agent reports.",
        }
        .into(),
        Some(QuestionAnswer::Choices { indices }) => format!(
            "{lead}: {}",
            indices
                .iter()
                .map(|i| info.definition.choices[*i as usize].as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ),
        Some(QuestionAnswer::Text { text }) => format!("{lead}: {text}"),
        _ if info.definition.approval.is_some() => match info.state {
            QuestionState::Expired => "Runtime approval expired.",
            QuestionState::Cancelled => "Runtime approval cancelled.",
            QuestionState::Resolved => "Runtime approval resolved in the runtime.",
            _ => "Runtime approval settled.",
        }
        .into(),
        _ => match info.state {
            QuestionState::Skipped => "Question skipped.",
            QuestionState::Expired => "Question expired.",
            QuestionState::Cancelled => "Question cancelled.",
            _ => "Question answered.",
        }
        .into(),
    }
}

impl Store {
    pub fn question(&self, id: &QuestionId) -> rusqlite::Result<Option<StoredQuestion>> {
        question_in(&self.db, id.as_str())
    }

    pub fn pending_questions_for(&self, person: &str) -> rusqlite::Result<Vec<StoredQuestion>> {
        let sql =
            format!("{QUESTION_COLUMNS} WHERE c.owner=?1 AND q.state='pending' ORDER BY q.rowid");
        let rows = self
            .db
            .prepare(&sql)?
            .query_map([person], read_question)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows.into_iter().filter_map(usable).collect())
    }

    /// Every pending question: its agent, id, and when it was asked
    /// (seconds since the epoch), oldest first.
    pub fn pending_questions_by_age(&self) -> rusqlite::Result<Vec<(String, QuestionId, i64)>> {
        let mut query = self.db.prepare(
            "SELECT q.agent, q.id, m.at FROM questions q JOIN messages m ON m.id=q.ask_message
             WHERE q.state='pending' ORDER BY m.at, q.rowid",
        )?;
        query
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    QuestionId::new(row.get::<_, String>(1)?).map_err(json_error)?,
                    row.get(2)?,
                ))
            })?
            .collect()
    }

    /// Tests: message `id` as said at `at`.
    #[cfg(test)]
    pub fn backdate_message(&self, id: &str, at: i64) -> rusqlite::Result<()> {
        self.db
            .execute("UPDATE messages SET at=?2 WHERE id=?1", params![id, at])
            .map(drop)
    }

    pub fn pending_questions(&self, agent: &str) -> rusqlite::Result<Vec<QuestionId>> {
        let mut query = self.db.prepare(
            "SELECT id FROM questions WHERE agent=?1 AND state='pending' ORDER BY rowid",
        )?;
        query
            .query_map([agent], |row| {
                QuestionId::new(row.get::<_, String>(0)?).map_err(json_error)
            })?
            .collect()
    }

    /// The agent's pending runtime approvals, oldest first.
    pub fn pending_approvals(&self, agent: &str) -> rusqlite::Result<Vec<QuestionId>> {
        let mut query = self.db.prepare(
            "SELECT id FROM questions WHERE agent=?1 AND state='pending' AND json_extract(definition,'$.approval') IS NOT NULL ORDER BY rowid",
        )?;
        query
            .query_map([agent], |row| {
                QuestionId::new(row.get::<_, String>(0)?).map_err(json_error)
            })?
            .collect()
    }

    /// Creates the question and its readable introduction. A runtime
    /// approval is refused unless `host`, the host's person, owns the
    /// conversation: no one else decides runtime approvals.
    pub fn ask_question(
        &self,
        origin: &str,
        conversation: &ConversationId,
        definition: &QuestionDefinition,
        message_id: &str,
        host: Option<&str>,
    ) -> Result<QuestionChange, QuestionStoreError> {
        definition.validate().map_err(QuestionStoreError::Invalid)?;
        let kind = introduction_kind(definition);
        let tx = rusqlite::Transaction::new_unchecked(
            &self.db,
            rusqlite::TransactionBehavior::Immediate,
        )?;
        let is_member = origin_conversation(&tx, origin, conversation)?;
        // Who the conversation is: the question's owner, read there.
        let owner: String = tx.query_row(
            "SELECT owner FROM conversations WHERE id=?1",
            [conversation.as_str()],
            |row| row.get(0),
        )?;
        QuestionInfo {
            definition: definition.clone(),
            conversation: conversation.clone(),
            agent: origin.into(),
            state: QuestionState::Pending,
            revision: 0,
            answer: None,
            confirmed: false,
        }
        .validate()
        .map_err(QuestionStoreError::Invalid)?;
        if let Some(current) = question_in(&tx, definition.id.as_str())? {
            if current.info.agent != origin
                || current.info.conversation != *conversation
                || current.info.definition != *definition
            {
                return Err(QuestionStoreError::Conflict);
            }
            let message = history_message(&tx, definition.id.as_str(), kind)?;
            return Ok(QuestionChange {
                question: current,
                message,
            });
        }
        let exists = |sql: &str, key: &str| -> rusqlite::Result<bool> {
            Ok(tx.query_row(sql, [key], |_| Ok(())).optional()?.is_some())
        };
        // A row that no longer reads holds this id: never a second one.
        if exists(
            "SELECT 1 FROM questions WHERE id=?1",
            definition.id.as_str(),
        )? || exists("SELECT 1 FROM messages WHERE id=?1", message_id)?
        {
            return Err(QuestionStoreError::Conflict);
        }
        if definition.approval.is_some() {
            // Nobody could answer it: the host's person does not have this
            // conversation, and no one else decides runtime approvals.
            if host != Some(owner.as_str()) {
                return Err(QuestionStoreError::NotAllowed(
                    "Only the host's person decides runtime approvals, and this conversation is not theirs.".into(),
                ));
            }
            let pending = |sql: &str, key: &str| -> rusqlite::Result<i64> {
                tx.query_row(sql, [key], |r| r.get(0))
            };
            if pending(
                "SELECT COUNT(*) FROM questions WHERE conversation=?1 AND state='pending' AND json_extract(definition,'$.approval') IS NOT NULL",
                conversation.as_str(),
            )? >= MAX_PENDING_APPROVALS_PER_CONVERSATION
                || pending(
                    "SELECT COUNT(*) FROM questions WHERE agent=?1 AND state='pending' AND json_extract(definition,'$.approval') IS NOT NULL",
                    origin,
                )? >= MAX_PENDING_APPROVALS_PER_AGENT
            {
                return Err(QuestionStoreError::Invalid(
                    "Too many runtime approvals are waiting for an answer.".into(),
                ));
            }
        } else {
            let pending = |sql: &str, key: &str| -> rusqlite::Result<i64> {
                tx.query_row(sql, [key], |r| r.get(0))
            };
            if pending(
                "SELECT COUNT(*) FROM questions WHERE conversation=?1 AND state='pending' AND json_extract(definition,'$.approval') IS NULL",
                conversation.as_str(),
            )? >= MAX_PENDING_PER_CONVERSATION
                || pending(
                    "SELECT COUNT(*) FROM questions WHERE agent=?1 AND state='pending' AND json_extract(definition,'$.approval') IS NULL",
                    origin,
                )? >= MAX_PENDING_PER_AGENT
            {
                return Err(QuestionStoreError::Invalid(
                    "Too many questions are waiting for an answer.".into(),
                ));
            }
        }
        let encoded = serde_json::to_string(definition)
            .map_err(|e| QuestionStoreError::Invalid(e.to_string()))?;
        tx.execute("INSERT INTO questions(id,conversation,agent,definition,state,revision,answer,ask_message) VALUES (?1,?2,?3,?4,'pending',0,NULL,?5)", params![definition.id.as_str(),conversation.as_str(),origin,encoded,message_id])?;
        let speaker = is_member.then(|| origin.split_once('/').expect("an agent has a sandbox").1);
        tx.execute("INSERT INTO messages(id,conversation,person,text,kind,at,speaker,question) VALUES (?1,?2,NULL,?3,?4,?5,?6,?7)",params![message_id,conversation.as_str(),definition.fallback_text(),kind,now(),speaker,definition.id.as_str()])?;
        let question =
            question_in(&tx, definition.id.as_str())?.ok_or(QuestionStoreError::Unknown)?;
        let message = history_message(&tx, definition.id.as_str(), kind)?;
        tx.commit()?;
        Ok(QuestionChange { question, message })
    }

    /// Settles a question as its agent's channel reports, matched to no
    /// device request.
    pub fn settle_question(
        &self,
        origin: &str,
        id: &QuestionId,
        settlement: Settlement,
        message_id: &str,
    ) -> Result<QuestionChange, QuestionStoreError> {
        let Settlement {
            state,
            answer,
            confirmed,
        } = settlement;
        let tx = rusqlite::Transaction::new_unchecked(
            &self.db,
            rusqlite::TransactionBehavior::Immediate,
        )?;
        let Some(current) = question_in(&tx, id.as_str())? else {
            // A row that no longer reads can be neither shown nor answered:
            // its agent's terminal update closes it, so that no sync offers
            // it to the channel again.
            if state.is_terminal()
                && tx.execute(
                    "UPDATE questions SET state='expired',revision=revision+1 WHERE id=?1 AND agent=?2 AND state='pending'",
                    params![id.as_str(), origin],
                )? > 0
            {
                tx.commit()?;
            }
            return Err(QuestionStoreError::Unknown);
        };
        if current.info.agent != origin {
            return Err(QuestionStoreError::Unknown);
        }
        let is_member = origin_conversation(&tx, origin, &current.info.conversation)?;
        let mut answer = answer;
        if let Some(QuestionAnswer::Choices { indices }) = &mut answer {
            indices.sort_unstable();
        }
        let mut next = current.clone();
        next.info.state = state;
        next.info.answer = answer;
        next.info.confirmed = confirmed && state.is_terminal();
        next.info.validate().map_err(QuestionStoreError::Invalid)?;
        if current.info.state != QuestionState::Pending {
            if current.info.state != next.info.state || current.info.answer != next.info.answer {
                return Err(QuestionStoreError::Conflict);
            }
            return Ok(QuestionChange {
                question: current,
                message: history_message(&tx, id.as_str(), "status")?,
            });
        }
        if next.info.state == QuestionState::Pending {
            return Ok(QuestionChange {
                question: current,
                message: None,
            });
        }
        next.info.revision = current
            .info
            .revision
            .checked_add(1)
            .filter(|r| *r <= i64::MAX as u64)
            .ok_or_else(|| QuestionStoreError::Invalid("Question revision overflow.".into()))?;
        let answer = next
            .info
            .answer
            .as_ref()
            .map(serde_json::to_string)
            .transpose()
            .map_err(|e| QuestionStoreError::Invalid(e.to_string()))?;
        tx.execute(
            "UPDATE questions SET state=?2,revision=?3,answer=?4,confirmed=?5 WHERE id=?1",
            params![
                id.as_str(),
                state_text(&next.info.state),
                next.info.revision as i64,
                answer,
                next.info.confirmed
            ],
        )?;
        let speaker = is_member.then(|| origin.split_once('/').expect("an agent has a sandbox").1);
        tx.execute("INSERT INTO messages(id,conversation,person,text,kind,at,speaker,question) VALUES (?1,?2,NULL,?3,'status',?4,?5,?6)",params![message_id,next.info.conversation.as_str(),settlement_text(&next.info, confirmed),now(),speaker,id.as_str()])?;
        let message = history_message(&tx, id.as_str(), "status")?;
        tx.commit()?;
        Ok(QuestionChange {
            question: next,
            message,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn definition(id: &str) -> QuestionDefinition {
        QuestionDefinition {
            id: QuestionId::new(id).unwrap(),
            text: "Que choisir ?".into(),
            choices: vec!["Résultats 🤖".into(), "Classement".into()],
            multiple: true,
            approval: None,
        }
    }

    fn fixture() -> (tempfile::TempDir, Store, ConversationId) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("app.db")).unwrap();
        store
            .conversation("owned", "lab", "coder", "owner")
            .unwrap();
        (dir, store, ConversationId::new("owned").unwrap())
    }

    #[test]
    fn native_question_creation_and_settlement_are_atomic_durable_and_idempotent() {
        let (dir, store, conversation) = fixture();
        let definition = definition("q-1");
        let created = store
            .ask_question(
                "lab/coder",
                &conversation,
                &definition,
                "ask-1",
                Some("owner"),
            )
            .unwrap();
        assert_eq!(created.question.info.state, QuestionState::Pending);
        assert_eq!(created.question.info.revision, 0);
        let first = created.message.unwrap();
        assert_eq!(first.kind, "question");
        assert_eq!(first.question, Some(definition.id.clone()));
        assert_eq!(first.text, definition.fallback_text());
        assert_eq!(
            store
                .ask_question(
                    "lab/coder",
                    &conversation,
                    &definition,
                    "ask-replayed",
                    Some("owner")
                )
                .unwrap()
                .message
                .unwrap()
                .seq,
            first.seq
        );
        let change = store
            .settle_question(
                "lab/coder",
                &definition.id,
                Settlement::reported(
                    QuestionState::Answered,
                    Some(QuestionAnswer::Choices {
                        indices: vec![1, 0],
                    }),
                ),
                "settle-1",
            )
            .unwrap();
        assert_eq!(change.question.info.revision, 1);
        assert_eq!(
            change.question.info.answer,
            Some(QuestionAnswer::Choices {
                indices: vec![0, 1]
            })
        );
        assert_eq!(change.message.unwrap().kind, "status");
        let repeated = store
            .settle_question(
                "lab/coder",
                &definition.id,
                Settlement::reported(
                    QuestionState::Answered,
                    Some(QuestionAnswer::Choices {
                        indices: vec![0, 1],
                    }),
                ),
                "settle-replayed",
            )
            .unwrap();
        assert_eq!(repeated.question.info.revision, 1);
        assert!(matches!(
            store.settle_question(
                "lab/coder",
                &definition.id,
                Settlement::reported(QuestionState::Pending, None),
                "reopen"
            ),
            Err(QuestionStoreError::Conflict)
        ));
        assert!(matches!(
            store.settle_question(
                "lab/coder",
                &definition.id,
                Settlement::reported(QuestionState::Skipped, None),
                "replace"
            ),
            Err(QuestionStoreError::Conflict)
        ));
        let messages = store.since("owner", 0).unwrap();
        assert_eq!(messages.len(), 2);
        assert_eq!(store.since("owner", first.seq).unwrap()[0].kind, "status");
        let restored = Store::open(&dir.path().join("app.db")).unwrap();
        assert_eq!(
            restored.question(&definition.id).unwrap().unwrap().info,
            repeated.question.info
        );
        assert!(restored.pending_questions("lab/coder").unwrap().is_empty());
    }

    #[test]
    fn authenticated_origin_and_immutable_definition_cannot_cross_conversations_or_groups() {
        let (_dir, store, conversation) = fixture();
        store
            .conversation("foreign-agent", "lab", "helper", "owner")
            .unwrap();
        store
            .group("group", "lab", &["coder".into(), "helper".into()], "owner")
            .unwrap();
        let definition = definition("q-1");
        assert!(matches!(
            store.ask_question(
                "lab/helper",
                &conversation,
                &definition,
                "foreign",
                Some("owner")
            ),
            Err(QuestionStoreError::Unknown)
        ));
        assert!(store.question(&definition.id).unwrap().is_none());
        store
            .ask_question(
                "lab/coder",
                &conversation,
                &definition,
                "ask",
                Some("owner"),
            )
            .unwrap();
        let mut changed = definition.clone();
        changed.choices.reverse();
        assert!(matches!(
            store.ask_question(
                "lab/coder",
                &conversation,
                &changed,
                "changed",
                Some("owner")
            ),
            Err(QuestionStoreError::Conflict)
        ));
        assert!(matches!(
            store.settle_question(
                "lab/helper",
                &definition.id,
                Settlement::reported(QuestionState::Expired, None),
                "forged"
            ),
            Err(QuestionStoreError::Unknown)
        ));
        let group = ConversationId::new("group").unwrap();
        let definition = definition_with_id("group-q");
        let created = store
            .ask_question(
                "lab/helper",
                &group,
                &definition,
                "group-ask",
                Some("owner"),
            )
            .unwrap();
        assert_eq!(created.message.unwrap().from, From::Member("helper".into()));
        assert!(matches!(
            store.ask_question(
                "other/helper",
                &group,
                &definition_with_id("outsider"),
                "outside",
                Some("owner")
            ),
            Err(QuestionStoreError::Unknown)
        ));
        assert!(matches!(
            store.ask_question(
                "lab/missing",
                &group,
                &definition_with_id("nonmember"),
                "nonmember",
                Some("owner")
            ),
            Err(QuestionStoreError::Unknown)
        ));
    }

    fn definition_with_id(id: &str) -> QuestionDefinition {
        definition(id)
    }

    #[test]
    fn current_conversation_owner_controls_pending_snapshots_including_claimed_home() {
        let (_dir, store, _) = fixture();
        store.ensure_home("lab/coder", "", false).unwrap();
        let home = ConversationId::new(home_id("lab/coder")).unwrap();
        let definition = definition("home-question");
        store
            .ask_question("lab/coder", &home, &definition, "home-ask", Some("owner"))
            .unwrap();
        assert!(store.pending_questions_for("owner").unwrap().is_empty());
        store.ensure_home("lab/coder", "owner", false).unwrap();
        assert_eq!(
            store.question(&definition.id).unwrap().unwrap().owner,
            "owner"
        );
        assert_eq!(store.pending_questions_for("owner").unwrap().len(), 1);
        store
            .db
            .execute(
                "UPDATE conversations SET owner='new-owner' WHERE id=?1",
                [home.as_str()],
            )
            .unwrap();
        assert!(store.pending_questions_for("owner").unwrap().is_empty());
        assert_eq!(store.pending_questions_for("new-owner").unwrap().len(), 1);
    }

    #[test]
    fn failed_settlement_and_revision_overflow_leave_no_status_or_partial_update() {
        let (_dir, store, conversation) = fixture();
        let definition = definition("q-1");
        store
            .ask_question(
                "lab/coder",
                &conversation,
                &definition,
                "ask",
                Some("owner"),
            )
            .unwrap();
        assert!(
            store
                .settle_question(
                    "lab/coder",
                    &definition.id,
                    Settlement::reported(
                        QuestionState::Answered,
                        Some(QuestionAnswer::Choices { indices: vec![999] })
                    ),
                    "invalid"
                )
                .is_err()
        );
        store
            .db
            .execute(
                "UPDATE questions SET revision=?1 WHERE id=?2",
                params![i64::MAX, definition.id.as_str()],
            )
            .unwrap();
        assert!(
            store
                .settle_question(
                    "lab/coder",
                    &definition.id,
                    Settlement::reported(QuestionState::Expired, None),
                    "overflow"
                )
                .is_err()
        );
        assert_eq!(
            store.question(&definition.id).unwrap().unwrap().info.state,
            QuestionState::Pending
        );
        assert_eq!(store.since("owner", 0).unwrap().len(), 1);
        assert_eq!(
            store.pending_questions("lab/coder").unwrap(),
            [definition.id]
        );
    }

    #[test]
    fn opening_an_existing_database_keeps_old_messages_readable_without_question_ids() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("app.db");
        let db = Connection::open(&path).unwrap();
        db.execute_batch("CREATE TABLE messages (seq INTEGER PRIMARY KEY AUTOINCREMENT,id TEXT NOT NULL UNIQUE,conversation TEXT NOT NULL,person TEXT,text TEXT NOT NULL,kind TEXT NOT NULL,at INTEGER NOT NULL,speaker TEXT); INSERT INTO messages(id,conversation,person,text,kind,at) VALUES ('old','owned','owner','unchanged','message',1);").unwrap();
        drop(db);
        let store = Store::open(&path).unwrap();
        store
            .conversation("owned", "lab", "coder", "owner")
            .unwrap();
        assert_eq!(store.messages_after("owned", 0).unwrap()[0].question, None);
        assert_eq!(store.since("owner", 0).unwrap()[0].text, "unchanged");
    }

    #[test]
    fn pending_questions_are_capped_per_conversation_and_per_agent() {
        let (_dir, store, conversation) = fixture();
        for index in 0..MAX_PENDING_PER_CONVERSATION {
            store
                .ask_question(
                    "lab/coder",
                    &conversation,
                    &definition(&format!("q-{index}")),
                    &format!("ask-{index}"),
                    None,
                )
                .unwrap();
        }
        assert!(matches!(
            store.ask_question(
                "lab/coder",
                &conversation,
                &definition("q-over"),
                "over",
                None
            ),
            Err(QuestionStoreError::Invalid(_))
        ));
        assert!(store.question(&definition("q-over").id).unwrap().is_none());
        // A replayed ask is not a new question; a settled one no longer counts.
        store
            .ask_question(
                "lab/coder",
                &conversation,
                &definition("q-0"),
                "ask-0",
                None,
            )
            .unwrap();
        store
            .settle_question(
                "lab/coder",
                &definition("q-0").id,
                Settlement::reported(QuestionState::Expired, None),
                "expired-0",
            )
            .unwrap();
        store
            .ask_question(
                "lab/coder",
                &conversation,
                &definition("q-next"),
                "next",
                None,
            )
            .unwrap();
        // Across conversations, the agent's own cap.
        for asked in MAX_PENDING_PER_CONVERSATION..=MAX_PENDING_PER_AGENT {
            let id = format!("c-{asked}");
            store.conversation(&id, "lab", "coder", "owner").unwrap();
            let conversation = ConversationId::new(id.clone()).unwrap();
            let result = store.ask_question(
                "lab/coder",
                &conversation,
                &definition(&format!("{id}-q")),
                &format!("{id}-ask"),
                None,
            );
            if asked == MAX_PENDING_PER_AGENT {
                assert!(matches!(result, Err(QuestionStoreError::Invalid(_))));
                break;
            }
            result.unwrap();
        }
        assert_eq!(
            store.pending_questions("lab/coder").unwrap().len() as i64,
            MAX_PENDING_PER_AGENT
        );
        // Another agent has its own.
        store
            .conversation("helper-c", "lab", "helper", "owner")
            .unwrap();
        store
            .ask_question(
                "lab/helper",
                &ConversationId::new("helper-c").unwrap(),
                &definition("helper-q"),
                "helper-ask",
                None,
            )
            .unwrap();
    }

    #[test]
    fn old_pending_questions_are_found_by_when_they_were_asked() {
        let (_dir, store, conversation) = fixture();
        let old = definition("old");
        store
            .ask_question("lab/coder", &conversation, &old, "old-ask", None)
            .unwrap();
        store
            .db
            .execute("UPDATE messages SET at=100 WHERE id='old-ask'", [])
            .unwrap();
        store
            .ask_question(
                "lab/coder",
                &conversation,
                &definition("new"),
                "new-ask",
                None,
            )
            .unwrap();
        let pending = store.pending_questions_by_age().unwrap();
        assert_eq!(pending.len(), 2);
        assert_eq!(pending[0], ("lab/coder".to_owned(), old.id.clone(), 100));
        assert!(pending[1].2 > 1000);
        store
            .settle_question(
                "lab/coder",
                &old.id,
                Settlement::reported(QuestionState::Expired, None),
                "old-expired",
            )
            .unwrap();
        assert_eq!(store.pending_questions_by_age().unwrap().len(), 1);
    }

    #[test]
    fn only_a_confirmed_answer_reads_as_the_persons_in_history() {
        let (_dir, store, conversation) = fixture();
        for (id, confirmed, text) in [
            ("confirmed", true, "Answered: Classement"),
            (
                "reported",
                false,
                "Answered, as the agent reports: Classement",
            ),
        ] {
            let mut question = definition(id);
            question.multiple = false;
            store
                .ask_question(
                    "lab/coder",
                    &conversation,
                    &question,
                    &format!("{id}-ask"),
                    None,
                )
                .unwrap();
            let change = store
                .settle_question(
                    "lab/coder",
                    &question.id,
                    Settlement {
                        state: QuestionState::Answered,
                        answer: Some(QuestionAnswer::Choices { indices: vec![1] }),
                        confirmed,
                    },
                    &format!("{id}-settled"),
                )
                .unwrap();
            assert_eq!(change.message.unwrap().text, text);
            // The card can tell them apart too, after a restart as well.
            assert_eq!(change.question.info.confirmed, confirmed);
            assert_eq!(
                store
                    .question(&question.id)
                    .unwrap()
                    .unwrap()
                    .info
                    .confirmed,
                confirmed
            );
        }
    }

    #[test]
    fn a_runtime_answer_the_contract_cannot_carry_is_answered_without_text() {
        let (_dir, store, conversation) = fixture();
        let question = definition("q-1");
        store
            .ask_question("lab/coder", &conversation, &question, "ask", None)
            .unwrap();
        let change = store
            .settle_question(
                "lab/coder",
                &question.id,
                Settlement::reported(QuestionState::Answered, None),
                "answered",
            )
            .unwrap();
        assert_eq!(change.question.info.state, QuestionState::Answered);
        assert_eq!(change.question.info.answer, None);
        assert_eq!(change.message.unwrap().text, "Question answered.");
    }

    #[test]
    fn a_row_that_no_longer_reads_is_left_out_and_closed_not_fatal() {
        let (_dir, store, conversation) = fixture();
        for id in ["old", "new"] {
            store
                .ask_question(
                    "lab/coder",
                    &conversation,
                    &definition(id),
                    &format!("{id}-ask"),
                    None,
                )
                .unwrap();
        }
        // As an earlier build could write it: a tab, refused since.
        store
            .db
            .execute(
                "UPDATE questions SET definition=?1 WHERE id='old'",
                [serde_json::to_string(&QuestionDefinition {
                    text: "Which\tone?".into(),
                    ..definition("old")
                })
                .unwrap()],
            )
            .unwrap();
        let old = QuestionId::new("old").unwrap();
        assert!(store.question(&old).unwrap().is_none());
        let pending = store.pending_questions_for("owner").unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].info.definition.id.as_str(), "new");
        // Its id is never taken by another ask.
        assert!(matches!(
            store.ask_question(
                "lab/coder",
                &conversation,
                &definition("old"),
                "again",
                None
            ),
            Err(QuestionStoreError::Conflict)
        ));
        // Its agent's terminal update closes it: no channel sync offers it again.
        assert_eq!(store.pending_questions("lab/coder").unwrap().len(), 2);
        assert!(matches!(
            store.settle_question(
                "lab/coder",
                &old,
                Settlement::reported(QuestionState::Expired, None),
                "expired"
            ),
            Err(QuestionStoreError::Unknown)
        ));
        assert_eq!(
            store.pending_questions("lab/coder").unwrap(),
            [QuestionId::new("new").unwrap()]
        );
    }

    #[test]
    fn an_earlier_question_table_loses_its_owner_copy_and_gains_confirmed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("app.db");
        let db = Connection::open(&path).unwrap();
        db.execute_batch("CREATE TABLE questions (id TEXT PRIMARY KEY, conversation TEXT NOT NULL, agent TEXT NOT NULL, owner TEXT NOT NULL, definition TEXT NOT NULL, state TEXT NOT NULL, revision INTEGER NOT NULL CHECK(typeof(revision)='integer' AND revision>=0), answer TEXT, ask_message TEXT NOT NULL UNIQUE);").unwrap();
        drop(db);
        let store = Store::open(&path).unwrap();
        store
            .conversation("owned", "lab", "coder", "owner")
            .unwrap();
        let conversation = ConversationId::new("owned").unwrap();
        let question = definition("q-1");
        store
            .ask_question("lab/coder", &conversation, &question, "ask", None)
            .unwrap();
        let stored = store.question(&question.id).unwrap().unwrap();
        assert_eq!(stored.owner, "owner");
        assert!(!stored.info.confirmed);
        drop(store);
        // Opening it again changes nothing more.
        Store::open(&path).unwrap();
    }
}

#[cfg(test)]
mod runtime_approval_tests {
    use super::*;
    use enclos_protocol::question::{RuntimeApprovalAction as Action, RuntimeApprovalDefinition};

    fn definition(id: &str) -> QuestionDefinition {
        QuestionDefinition {
            id: QuestionId::new(id).unwrap(),
            text: "Allow this command?".into(),
            choices: vec![],
            multiple: false,
            approval: Some(RuntimeApprovalDefinition {
                command: "npm install --ignore-scripts".into(),
                reason: "Install dependencies.".into(),
                actions: vec![Action::Once, Action::Session, Action::Always, Action::Deny],
                smart_denied: false,
                patterns: vec!["package install scripts".into()],
                scopes: None,
            }),
        }
    }

    #[test]
    fn runtime_approval_history_replays_and_persists_each_scope_without_claiming_execution() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("app.db");
        let store = Store::open(&path).unwrap();
        store
            .conversation("owned", "lab", "coder", "owner")
            .unwrap();
        let conversation = ConversationId::new("owned").unwrap();
        for (index, (action, expected)) in [
            (Action::Once, "Runtime approval: allowed once."),
            (
                Action::Session,
                "Runtime approval: allowed for this runtime session.",
            ),
            (
                Action::Always,
                "Runtime approval: always allowed by this runtime.",
            ),
            (Action::Deny, "Runtime approval: denied."),
        ]
        .into_iter()
        .enumerate()
        {
            let definition = definition(&format!("approval-{index}"));
            let created = store
                .ask_question(
                    "lab/coder",
                    &conversation,
                    &definition,
                    &format!("ask-{index}"),
                    Some("owner"),
                )
                .unwrap();
            assert_eq!(created.message.as_ref().unwrap().kind, "runtime_approval");
            assert_eq!(
                created.message.as_ref().unwrap().text,
                definition.fallback_text()
            );
            assert_eq!(
                store
                    .ask_question(
                        "lab/coder",
                        &conversation,
                        &definition,
                        &format!("replayed-{index}"),
                        Some("owner")
                    )
                    .unwrap()
                    .message
                    .unwrap()
                    .seq,
                created.message.unwrap().seq
            );
            let settled = store
                .settle_question(
                    "lab/coder",
                    &definition.id,
                    Settlement {
                        state: QuestionState::Answered,
                        answer: Some(QuestionAnswer::Approval { action }),
                        confirmed: true,
                    },
                    &format!("settled-{index}"),
                )
                .unwrap();
            assert_eq!(settled.message.unwrap().text, expected);
            assert_eq!(settled.question.info.revision, 1);
            assert!(
                store
                    .settle_question(
                        "lab/coder",
                        &definition.id,
                        Settlement::reported(QuestionState::Pending, None),
                        "reopen"
                    )
                    .is_err()
            );
            let restored = Store::open(&path)
                .unwrap()
                .question(&definition.id)
                .unwrap()
                .unwrap();
            assert_eq!(
                restored.info.answer,
                Some(QuestionAnswer::Approval { action })
            );
            assert_eq!(restored.info.definition, definition);
        }
        assert_eq!(store.since("owner", 0).unwrap().len(), 8);
    }

    #[test]
    fn runtime_approval_resolved_is_terminal_without_an_invented_scope_or_skipped_state() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("app.db")).unwrap();
        store
            .conversation("owned", "lab", "coder", "owner")
            .unwrap();
        let conversation = ConversationId::new("owned").unwrap();
        let definition = definition("approval");
        store
            .ask_question(
                "lab/coder",
                &conversation,
                &definition,
                "ask",
                Some("owner"),
            )
            .unwrap();
        for answer in [
            QuestionAnswer::Text {
                text: "/approve".into(),
            },
            QuestionAnswer::Skip,
            QuestionAnswer::Choices { indices: vec![0] },
        ] {
            assert!(
                store
                    .settle_question(
                        "lab/coder",
                        &definition.id,
                        Settlement::reported(QuestionState::Answered, Some(answer)),
                        "invalid"
                    )
                    .is_err()
            );
        }
        assert!(
            store
                .settle_question(
                    "lab/coder",
                    &definition.id,
                    Settlement::reported(QuestionState::Skipped, None),
                    "skip"
                )
                .is_err()
        );
        let resolved = store
            .settle_question(
                "lab/coder",
                &definition.id,
                Settlement::reported(QuestionState::Resolved, None),
                "resolved",
            )
            .unwrap();
        assert_eq!(
            resolved.message.unwrap().text,
            "Runtime approval resolved in the runtime."
        );
        assert!(resolved.question.info.answer.is_none());
        assert!(
            store
                .settle_question(
                    "lab/coder",
                    &definition.id,
                    Settlement::reported(
                        QuestionState::Answered,
                        Some(QuestionAnswer::Approval {
                            action: Action::Once
                        })
                    ),
                    "guess-scope"
                )
                .is_err()
        );
        assert_eq!(store.since("owner", 0).unwrap().len(), 2);
        let old: QuestionDefinition = serde_json::from_str(
            r#"{"id":"old-question","text":"Continue?","choices":["Yes","No"],"multiple":false}"#,
        )
        .unwrap();
        assert!(old.approval.is_none());
        assert!(
            QuestionAnswer::Approval {
                action: Action::Once
            }
            .validate(&old)
            .is_err()
        );
    }
}
