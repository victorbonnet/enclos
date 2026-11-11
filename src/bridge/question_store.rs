//! Atomic question definitions, settlements and their conversation history.
use super::*;
use enclos_protocol::question::{QuestionAnswer, QuestionDefinition, QuestionInfo, QuestionState};
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
}

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

fn read_question(row: &rusqlite::Row) -> rusqlite::Result<StoredQuestion> {
    let definition: QuestionDefinition =
        serde_json::from_str(&row.get::<_, String>(0)?).map_err(json_error)?;
    let conversation = ConversationId::new(row.get::<_, String>(1)?).map_err(json_error)?;
    let state: QuestionState =
        serde_json::from_value(serde_json::Value::String(row.get(4)?)).map_err(json_error)?;
    let revision: i64 = row.get(5)?;
    let answer = row
        .get::<_, Option<String>>(6)?
        .map(|s| serde_json::from_str(&s))
        .transpose()
        .map_err(json_error)?;
    let info = QuestionInfo {
        definition,
        conversation,
        agent: row.get(2)?,
        state,
        revision: revision
            .try_into()
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        answer,
    };
    info.validate().map_err(|_| rusqlite::Error::InvalidQuery)?;
    Ok(StoredQuestion {
        info,
        owner: row.get(3)?,
    })
}

const QUESTION_SELECT: &str = "SELECT q.definition,q.conversation,q.agent,c.owner,q.state,q.revision,q.answer FROM questions q JOIN conversations c ON c.id=q.conversation WHERE q.id=?1";

fn question_in(db: &Connection, id: &str) -> rusqlite::Result<Option<StoredQuestion>> {
    db.query_row(QUESTION_SELECT, [id], read_question)
        .optional()
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
) -> Result<(String, bool), QuestionStoreError> {
    let (sandbox, target, owner): (String, String, String) = db
        .query_row(
            "SELECT sandbox,agent,owner FROM conversations WHERE id=?1",
            [conversation.as_str()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
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
    Ok((owner, is_member))
}

fn state_text(state: &QuestionState) -> String {
    match state {
        QuestionState::Pending => "pending",
        QuestionState::Answered => "answered",
        QuestionState::Skipped => "skipped",
        QuestionState::Expired => "expired",
        QuestionState::Cancelled => "cancelled",
    }
    .into()
}

fn settlement_text(info: &QuestionInfo, confirmed: bool) -> String {
    let lead = if confirmed {
        "Answered"
    } else {
        "Answered, as the agent reports"
    };
    match &info.answer {
        Some(QuestionAnswer::Choices { indices }) => format!(
            "{lead}: {}",
            indices
                .iter()
                .map(|i| info.definition.choices[*i as usize].as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ),
        Some(QuestionAnswer::Text { text }) => format!("{lead}: {text}"),
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
        let sql = "SELECT q.definition,q.conversation,q.agent,c.owner,q.state,q.revision,q.answer FROM questions q JOIN conversations c ON c.id=q.conversation WHERE c.owner=?1 AND q.state='pending' ORDER BY q.rowid";
        self.db
            .prepare(sql)?
            .query_map([person], read_question)?
            .collect()
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

    pub fn ask_question(
        &self,
        origin: &str,
        conversation: &ConversationId,
        definition: &QuestionDefinition,
        message_id: &str,
    ) -> Result<QuestionChange, QuestionStoreError> {
        definition.validate().map_err(QuestionStoreError::Invalid)?;
        let tx = rusqlite::Transaction::new_unchecked(
            &self.db,
            rusqlite::TransactionBehavior::Immediate,
        )?;
        let (owner, is_member) = origin_conversation(&tx, origin, conversation)?;
        QuestionInfo {
            definition: definition.clone(),
            conversation: conversation.clone(),
            agent: origin.into(),
            state: QuestionState::Pending,
            revision: 0,
            answer: None,
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
            let message = history_message(&tx, definition.id.as_str(), "question")?;
            return Ok(QuestionChange {
                question: current,
                message,
            });
        }
        if tx
            .query_row("SELECT 1 FROM messages WHERE id=?1", [message_id], |_| {
                Ok(())
            })
            .optional()?
            .is_some()
        {
            return Err(QuestionStoreError::Conflict);
        }
        let pending = |sql: &str, key: &str| -> rusqlite::Result<i64> {
            tx.query_row(sql, [key], |r| r.get(0))
        };
        if pending(
            "SELECT COUNT(*) FROM questions WHERE conversation=?1 AND state='pending'",
            conversation.as_str(),
        )? >= MAX_PENDING_PER_CONVERSATION
            || pending(
                "SELECT COUNT(*) FROM questions WHERE agent=?1 AND state='pending'",
                origin,
            )? >= MAX_PENDING_PER_AGENT
        {
            return Err(QuestionStoreError::Invalid(
                "Too many questions are waiting for an answer.".into(),
            ));
        }
        let encoded = serde_json::to_string(definition)
            .map_err(|e| QuestionStoreError::Invalid(e.to_string()))?;
        tx.execute("INSERT INTO questions(id,conversation,agent,owner,definition,state,revision,answer,ask_message) VALUES (?1,?2,?3,?4,?5,'pending',0,NULL,?6)", params![definition.id.as_str(),conversation.as_str(),origin,owner,encoded,message_id])?;
        let speaker = is_member.then(|| origin.split_once('/').expect("an agent has a sandbox").1);
        tx.execute("INSERT INTO messages(id,conversation,person,text,kind,at,speaker,question) VALUES (?1,?2,NULL,?3,'question',?4,?5,?6)",params![message_id,conversation.as_str(),definition.fallback_text(),now(),speaker,definition.id.as_str()])?;
        let question =
            question_in(&tx, definition.id.as_str())?.ok_or(QuestionStoreError::Unknown)?;
        let message = history_message(&tx, definition.id.as_str(), "question")?;
        tx.commit()?;
        Ok(QuestionChange { question, message })
    }

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
        let current = question_in(&tx, id.as_str())?.ok_or(QuestionStoreError::Unknown)?;
        if current.info.agent != origin {
            return Err(QuestionStoreError::Unknown);
        }
        let (_, is_member) = origin_conversation(&tx, origin, &current.info.conversation)?;
        let mut answer = answer;
        if let Some(QuestionAnswer::Choices { indices }) = &mut answer {
            indices.sort_unstable();
        }
        let mut next = current.clone();
        next.info.state = state;
        next.info.answer = answer;
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
            "UPDATE questions SET state=?2,revision=?3,answer=?4 WHERE id=?1",
            params![
                id.as_str(),
                state_text(&next.info.state),
                next.info.revision as i64,
                answer
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
            .ask_question("lab/coder", &conversation, &definition, "ask-1")
            .unwrap();
        assert_eq!(created.question.info.state, QuestionState::Pending);
        assert_eq!(created.question.info.revision, 0);
        let first = created.message.unwrap();
        assert_eq!(first.kind, "question");
        assert_eq!(first.question, Some(definition.id.clone()));
        assert_eq!(first.text, definition.fallback_text());
        assert_eq!(
            store
                .ask_question("lab/coder", &conversation, &definition, "ask-replayed")
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
            store.ask_question("lab/helper", &conversation, &definition, "foreign"),
            Err(QuestionStoreError::Unknown)
        ));
        assert!(store.question(&definition.id).unwrap().is_none());
        store
            .ask_question("lab/coder", &conversation, &definition, "ask")
            .unwrap();
        let mut changed = definition.clone();
        changed.choices.reverse();
        assert!(matches!(
            store.ask_question("lab/coder", &conversation, &changed, "changed"),
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
            .ask_question("lab/helper", &group, &definition, "group-ask")
            .unwrap();
        assert_eq!(created.message.unwrap().from, From::Member("helper".into()));
        assert!(matches!(
            store.ask_question(
                "other/helper",
                &group,
                &definition_with_id("outsider"),
                "outside"
            ),
            Err(QuestionStoreError::Unknown)
        ));
        assert!(matches!(
            store.ask_question(
                "lab/missing",
                &group,
                &definition_with_id("nonmember"),
                "nonmember"
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
        store.ensure_home("lab/coder", "").unwrap();
        let home = ConversationId::new(home_id("lab/coder")).unwrap();
        let definition = definition("home-question");
        store
            .ask_question("lab/coder", &home, &definition, "home-ask")
            .unwrap();
        assert!(store.pending_questions_for("owner").unwrap().is_empty());
        store.ensure_home("lab/coder", "owner").unwrap();
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
            .ask_question("lab/coder", &conversation, &definition, "ask")
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
                )
                .unwrap();
        }
        assert!(matches!(
            store.ask_question("lab/coder", &conversation, &definition("q-over"), "over"),
            Err(QuestionStoreError::Invalid(_))
        ));
        assert!(store.question(&definition("q-over").id).unwrap().is_none());
        // A replayed ask is not a new question; a settled one no longer counts.
        store
            .ask_question("lab/coder", &conversation, &definition("q-0"), "ask-0")
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
            .ask_question("lab/coder", &conversation, &definition("q-next"), "next")
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
            )
            .unwrap();
    }

    #[test]
    fn old_pending_questions_are_found_by_when_they_were_asked() {
        let (_dir, store, conversation) = fixture();
        let old = definition("old");
        store
            .ask_question("lab/coder", &conversation, &old, "old-ask")
            .unwrap();
        store
            .db
            .execute("UPDATE messages SET at=100 WHERE id='old-ask'", [])
            .unwrap();
        store
            .ask_question("lab/coder", &conversation, &definition("new"), "new-ask")
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
                .ask_question("lab/coder", &conversation, &question, &format!("{id}-ask"))
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
        }
    }
}
