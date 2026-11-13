//! Logical agent-owned history. Import allocates destination-local identifiers
//! and sequences, and never recreates a pending action or a paired identity.
use super::ids::new_id;
use super::store::{Store, home_id, is_home};
use crate::model::secret::SecretValue;
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::OpenOptions;
use std::io::{self, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Credential {
    pub variable: String,
    #[serde(with = "secret")]
    pub value: SecretValue,
}
mod secret {
    use super::*;
    pub fn serialize<S: serde::Serializer>(v: &SecretValue, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(v.expose())
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<SecretValue, D::Error> {
        SecretValue::new(String::deserialize(d)?).map_err(serde::de::Error::custom)
    }
}
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostState {
    pub credentials: Vec<Credential>,
    pub history: History,
    pub source_policy: Option<crate::model::policy::Policy>,
}
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct History {
    pub conversations: Vec<Conversation>,
    pub messages: Vec<Message>,
    pub questions: Vec<Question>,
    pub approvals: Vec<enclos_protocol::approval::Approval>,
    pub attachments: Vec<Attachment>,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Conversation {
    pub id: String,
    pub title: Option<String>,
    pub titled_by: Option<String>,
    pub created: i64,
    pub read: Option<i64>,
    pub archived: bool,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Message {
    pub id: String,
    pub conversation: String,
    pub seq: i64,
    pub person: Option<String>,
    pub text: String,
    pub kind: String,
    pub at: i64,
    pub speaker: Option<String>,
    pub question: Option<String>,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Question {
    pub id: String,
    pub conversation: String,
    pub definition: enclos_protocol::question::QuestionDefinition,
    pub state: enclos_protocol::question::QuestionState,
    pub revision: i64,
    pub answer: Option<enclos_protocol::question::QuestionAnswer>,
    pub ask_message: String,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Attachment {
    pub id: String,
    pub message: String,
    pub conversation: String,
    pub mime: String,
    pub name: String,
    pub data: String,
}

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid agent-owned Enclos data",
    )
}
fn id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 256
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}
impl HostState {
    pub fn validate(&self) -> io::Result<()> {
        let mut variables = BTreeSet::new();
        for c in &self.credentials {
            if !crate::model::secret::is_variable_name(&c.variable)
                || crate::model::secret::reserved_variable(&c.variable)
                || !variables.insert(&c.variable)
            {
                return Err(invalid());
            }
        }
        self.history.validate()
    }
}
impl History {
    pub fn validate(&self) -> io::Result<()> {
        let cs: BTreeSet<_> = self.conversations.iter().map(|c| &c.id).collect();
        let ms: BTreeSet<_> = self.messages.iter().map(|m| &m.id).collect();
        let qs: BTreeSet<_> = self.questions.iter().map(|q| &q.id).collect();
        let as_: BTreeSet<_> = self.attachments.iter().map(|a| &a.id).collect();
        if cs.len() != self.conversations.len()
            || ms.len() != self.messages.len()
            || qs.len() != self.questions.len()
            || as_.len() != self.attachments.len()
            || self.conversations.iter().filter(|c| is_home(&c.id)).count() > 1
        {
            return Err(invalid());
        }
        for c in &self.conversations {
            if !id(&c.id) {
                return Err(invalid());
            }
        }
        let mut last = 0;
        for m in &self.messages {
            if !id(&m.id)
                || !cs.contains(&m.conversation)
                || m.seq <= last
                || m.question.as_ref().is_some_and(|q| !qs.contains(q))
            {
                return Err(invalid());
            }
            last = m.seq;
        }
        for q in &self.questions {
            if !id(&q.id)
                || q.definition.id.as_str() != q.id
                || !cs.contains(&q.conversation)
                || !ms.contains(&q.ask_message)
                || q.revision < 0
            {
                return Err(invalid());
            }
        }
        for a in &self.attachments {
            if !id(&a.id)
                || !ms.contains(&a.message)
                || !cs.contains(&a.conversation)
                || a.data.len() > 25 * 1024 * 1024 * 4 / 3 + 4
            {
                return Err(invalid());
            }
            enclos_protocol::pairing::decode("attachment", &a.data).map_err(|_| invalid())?;
        }
        for a in &self.approvals {
            if a.conversation.as_ref().is_some_and(|c| !cs.contains(c)) {
                return Err(invalid());
            }
        }
        Ok(())
    }
    /// Runtime adapters receive this same map to rebase their own session keys.
    pub fn conversation_map(&self, destination: &str) -> io::Result<BTreeMap<String, String>> {
        self.conversations
            .iter()
            .map(|c| {
                Ok((
                    c.id.clone(),
                    if is_home(&c.id) {
                        home_id(destination)
                    } else {
                        new_id()?
                    },
                ))
            })
            .collect()
    }
}

impl Store {
    /// Reads ownership for a dry run without upgrading or creating a database.
    pub(crate) fn read_host_person(path: &Path) -> rusqlite::Result<Option<String>> {
        let db = rusqlite::Connection::open_with_flags(
            path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )?;
        Self { db }.host_person()
    }

    pub fn export_history(&self, sandbox: &str, agent: &str, media: &Path) -> io::Result<History> {
        let work = || -> Result<History, Box<dyn std::error::Error>> {
            let tx = rusqlite::Transaction::new_unchecked(
                &self.db,
                rusqlite::TransactionBehavior::Deferred,
            )?;
            let mut h = History::default();
            let mut query=tx.prepare("SELECT id,title,titled_by,created,read,archived FROM conversations WHERE sandbox=?1 AND agent=?2 ORDER BY created,id")?;
            h.conversations = query
                .query_map(params![sandbox, agent], |r| {
                    Ok(Conversation {
                        id: r.get(0)?,
                        title: r.get(1)?,
                        titled_by: r.get(2)?,
                        created: r.get(3)?,
                        read: r.get(4)?,
                        archived: r.get(5)?,
                    })
                })?
                .collect::<Result<_, _>>()?;
            for c in &h.conversations {
                let mut q=tx.prepare("SELECT id,conversation,seq,person,text,kind,at,speaker,question FROM messages WHERE conversation=?1 ORDER BY seq")?;
                h.messages.extend(
                    q.query_map([&c.id], |r| {
                        Ok(Message {
                            id: r.get(0)?,
                            conversation: r.get(1)?,
                            seq: r.get(2)?,
                            person: r.get(3)?,
                            text: r.get(4)?,
                            kind: r.get(5)?,
                            at: r.get(6)?,
                            speaker: r.get(7)?,
                            question: r.get(8)?,
                        })
                    })?
                    .collect::<Result<Vec<_>, _>>()?,
                );
                let mut q=tx.prepare("SELECT id,conversation,definition,state,revision,answer,ask_message FROM questions WHERE conversation=?1")?;
                for row in q.query_map([&c.id], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, String>(3)?,
                        r.get::<_, i64>(4)?,
                        r.get::<_, Option<String>>(5)?,
                        r.get::<_, String>(6)?,
                    ))
                })? {
                    let (id, conversation, definition, state, revision, answer, ask_message) = row?;
                    h.questions.push(Question {
                        id,
                        conversation,
                        definition: serde_json::from_str(&definition)?,
                        state: serde_json::from_str(&format!("\"{state}\""))?,
                        revision,
                        answer: answer.map(|s| serde_json::from_str(&s)).transpose()?,
                        ask_message,
                    });
                }
                let mut q=tx.prepare("SELECT id,message,conversation,mime,name,size FROM attachments WHERE conversation=?1")?;
                for row in q.query_map([&c.id], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, String>(3)?,
                        r.get::<_, String>(4)?,
                        r.get::<_, i64>(5)?,
                    ))
                })? {
                    let (aid, message, conversation, mime, name, size) = row?;
                    if !id(&aid) || !(0..=25 * 1024 * 1024).contains(&size) {
                        return Err(invalid().into());
                    }
                    let file = OpenOptions::new()
                        .read(true)
                        .custom_flags(
                            (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits()
                                as i32,
                        )
                        .open(media.join(&aid))?;
                    if !file.metadata()?.is_file() {
                        return Err(invalid().into());
                    }
                    let mut bytes = Vec::new();
                    file.take(25 * 1024 * 1024 + 1).read_to_end(&mut bytes)?;
                    if bytes.len() as i64 != size {
                        return Err(invalid().into());
                    }
                    h.attachments.push(Attachment {
                        id: aid,
                        message,
                        conversation,
                        mime,
                        name,
                        data: enclos_protocol::pairing::encode(&bytes),
                    });
                }
            }
            let address = format!("{sandbox}/{agent}");
            let mut q = tx.prepare("SELECT body FROM approvals")?;
            for row in q.query_map([], |r| r.get::<_, String>(0))? {
                let approval: enclos_protocol::approval::Approval = serde_json::from_str(&row?)?;
                if approval.sandbox == sandbox
                    && (approval.agent == address || approval.agent == agent)
                    && approval
                        .conversation
                        .as_ref()
                        .is_none_or(|c| h.conversations.iter().any(|x| &x.id == c))
                {
                    h.approvals.push(approval);
                }
            }
            h.messages.sort_by_key(|m| m.seq);
            h.validate()?;
            Ok(h)
        };
        work().map_err(|_| {
            io::Error::other("cannot export complete app history or one of its attachments")
        })
    }

    pub fn import_history(
        &self,
        h: &History,
        destination: &str,
        conversations: &BTreeMap<String, String>,
        media: &Path,
    ) -> io::Result<()> {
        h.validate()?;
        let (sandbox, agent) = destination.split_once('/').ok_or_else(invalid)?;
        let mut created = Vec::new();
        let work = || -> Result<(), Box<dyn std::error::Error>> {
            let owner = self
                .host_person()?
                .ok_or_else(|| io::Error::other("pair this host before importing app history"))?;
            let tx = rusqlite::Transaction::new_unchecked(
                &self.db,
                rusqlite::TransactionBehavior::Immediate,
            )?;
            let ids = h
                .messages
                .iter()
                .map(|m| Ok((m.id.clone(), new_id()?)))
                .collect::<io::Result<BTreeMap<_, _>>>()?;
            let questions = h
                .questions
                .iter()
                .map(|q| Ok((q.id.clone(), new_id()?)))
                .collect::<io::Result<BTreeMap<_, _>>>()?;
            for c in &h.conversations {
                let dest = conversations.get(&c.id).ok_or_else(invalid)?;
                let exists:Option<(String,String,String,i64)>=tx.query_row("SELECT sandbox,agent,owner,(SELECT count(*) FROM messages WHERE conversation=?1) FROM conversations WHERE id=?1",[dest],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional()?;
                if exists
                    .is_some_and(|(s, a, o, n)| s != sandbox || a != agent || o != owner || n != 0)
                {
                    return Err(io::Error::other("destination app history already exists").into());
                }
                tx.execute("INSERT INTO conversations(id,sandbox,agent,owner,created,title,titled_by,archived,revision) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,1) ON CONFLICT(id) DO UPDATE SET title=excluded.title,titled_by=excluded.titled_by,archived=excluded.archived,revision=conversations.revision+1",params![dest,sandbox,agent,owner,c.created,c.title,c.titled_by,c.archived && !is_home(dest)])?;
            }
            let mut sequences = BTreeMap::new();
            for m in &h.messages {
                tx.execute("INSERT INTO messages(id,conversation,person,text,kind,at,speaker,question,pending) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,0)",params![ids[&m.id],conversations[&m.conversation],m.person,m.text,m.kind,m.at,m.speaker,m.question.as_ref().map(|q| &questions[q])])?;
                sequences.insert(m.seq, tx.last_insert_rowid());
            }
            for c in &h.conversations {
                let read = c
                    .read
                    .and_then(|r| sequences.range(..=r).next_back().map(|(_, seq)| *seq));
                tx.execute(
                    "UPDATE conversations SET read=?1 WHERE id=?2",
                    params![read, conversations[&c.id]],
                )?;
            }
            for q in &h.questions {
                let mut definition = q.definition.clone();
                definition.id = enclos_protocol::QuestionId::new(questions[&q.id].clone())?;
                let state = if q.state.is_terminal() {
                    q.state
                } else {
                    enclos_protocol::question::QuestionState::Expired
                };
                tx.execute("INSERT INTO questions(id,conversation,agent,definition,state,revision,answer,confirmed,ask_message) VALUES (?1,?2,?3,?4,?5,?6,?7,1,?8)",params![questions[&q.id],conversations[&q.conversation],destination,serde_json::to_string(&definition)?,serde_json::to_value(state)?.as_str().ok_or_else(invalid)?,q.revision,q.answer.as_ref().map(serde_json::to_string).transpose()?,ids[&q.ask_message]])?;
            }
            for a in &h.approvals {
                let mut a = a.clone();
                a.request = new_id()?;
                a.sandbox = sandbox.into();
                a.agent = destination.into();
                a.conversation = a.conversation.as_ref().map(|c| conversations[c].clone());
                a.state = "closed".into();
                a.available = false;
                a.reason = Some("Imported history; no access grant was restored".into());
                tx.execute(
                    "INSERT INTO approvals(id,body,state) VALUES (?1,?2,'closed')",
                    params![a.request, serde_json::to_string(&a)?],
                )?;
            }
            std::fs::create_dir_all(media)?;
            for a in &h.attachments {
                let aid = new_id()?;
                let path = media.join(&aid);
                let mut file = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&path)?;
                created.push(path);
                let bytes = enclos_protocol::pairing::decode("attachment", &a.data)?;
                file.write_all(&bytes)?;
                tx.execute("INSERT INTO attachments(id,message,conversation,mime,name,size) VALUES (?1,?2,?3,?4,?5,?6)",params![aid,ids[&a.message],conversations[&a.conversation],a.mime,a.name,bytes.len() as i64])?;
            }
            tx.commit()?;
            Ok(())
        };
        let mut work = work;
        let result = work();
        if result.is_err() {
            for p in created {
                let _ = std::fs::remove_file(p);
            }
        }
        result.map_err(|_| {
            io::Error::other("cannot restore app history; no history transaction committed")
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bridge::store::{From, StoredAttachment};
    fn source(dir: &Path) -> (Store, History) {
        let store = Store::open(&dir.join("source.db")).unwrap();
        store.set_host("source-person").unwrap();
        store
            .ensure_home("old/main", "source-person", true)
            .unwrap();
        let home = home_id("old/main");
        store
            .add(
                "source-message",
                &home,
                &From::Person("source-person".into()),
                "original chat",
                "message",
            )
            .unwrap();
        store
            .add(
                "question-message",
                &home,
                &From::Agent,
                "a pending question",
                "reply",
            )
            .unwrap();
        let definition =
            serde_json::json!({"id":"source-question","text":"Keep this question?","choices":[]});
        store.db.execute("INSERT INTO questions(id,conversation,agent,definition,state,revision,ask_message) VALUES ('source-question',?1,'old/main',?2,'pending',0,'question-message')",params![home,definition.to_string()]).unwrap();
        store
            .db
            .execute(
                "UPDATE messages SET question='source-question' WHERE id='question-message'",
                [],
            )
            .unwrap();
        let media = dir.join("source-media");
        std::fs::create_dir(&media).unwrap();
        std::fs::write(media.join("source-file"), b"attachment bytes").unwrap();
        store
            .add_attachment(
                &StoredAttachment {
                    id: "source-file".into(),
                    conversation: home.clone(),
                    mime: "text/plain".into(),
                    name: "report.txt".into(),
                    size: 16,
                },
                "source-message",
            )
            .unwrap();
        let approval = serde_json::json!({"request":"source-request","sandbox":"old","agent":"old/main","conversation":home,"access":{"kind":"network","target":"example.com:443"},"action":"fetch","time":1,"state":"approved","change":"allow network","scope":"example.com:443","restart":false,"revision":"x","available":true});
        store
            .db
            .execute(
                "INSERT INTO approvals VALUES ('source-request',?1,'approved')",
                [approval.to_string()],
            )
            .unwrap();
        let history = store.export_history("old", "main", &media).unwrap();
        (store, history)
    }
    #[test]
    fn history_moves_between_hosts_without_replaying_actions_or_replacing_destination_identity() {
        let dir = tempfile::tempdir().unwrap();
        let (_source, history) = source(dir.path());
        let dest = Store::open(&dir.path().join("dest.db")).unwrap();
        dest.set_host("destination-person").unwrap();
        dest.conversation("existing", "new", "other", "destination-person")
            .unwrap();
        dest.add(
            "existing-message",
            "existing",
            &From::Agent,
            "keep destination",
            "reply",
        )
        .unwrap();
        let map = history.conversation_map("new/renamed").unwrap();
        let media = dir.path().join("dest-media");
        dest.import_history(&history, "new/renamed", &map, &media)
            .unwrap();
        assert_eq!(
            dest.host_person().unwrap().as_deref(),
            Some("destination-person")
        );
        assert_eq!(
            dest.db
                .query_row("SELECT count(*) FROM devices", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            0
        );
        let home = home_id("new/renamed");
        let convo = dest.conversation_info(&home).unwrap().unwrap();
        assert_eq!(convo.agent, "renamed");
        assert_eq!(
            dest.db
                .query_row(
                    "SELECT owner FROM conversations WHERE id=?1",
                    [&home],
                    |r| r.get::<_, String>(0)
                )
                .unwrap(),
            "destination-person"
        );
        let messages = dest.messages_after(&home, 0).unwrap();
        assert_eq!(messages.len(), 2);
        assert!(messages[0].seq > 1);
        assert_eq!(messages[0].text, "original chat");
        assert_ne!(messages[0].id, "source-message");
        let (state, confirmed): (String, i64) = dest
            .db
            .query_row("SELECT state,confirmed FROM questions", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
        assert_eq!(state, "expired");
        assert_eq!(confirmed, 1);
        let body: String = dest
            .db
            .query_row("SELECT body FROM approvals", [], |r| r.get(0))
            .unwrap();
        let approval: enclos_protocol::approval::Approval = serde_json::from_str(&body).unwrap();
        assert_eq!(approval.state, "closed");
        assert!(!approval.available);
        assert_eq!(approval.sandbox, "new");
        assert_eq!(approval.agent, "new/renamed");
        let attachment = dest.attachments_of(&messages[0].id).unwrap().pop().unwrap();
        assert_eq!(
            std::fs::read(media.join(&attachment.id)).unwrap(),
            b"attachment bytes"
        );
        assert_eq!(
            dest.messages_after("existing", 0).unwrap()[0].text,
            "keep destination"
        );
        assert!(
            dest.import_history(&history, "new/renamed", &map, &media)
                .is_err()
        );
        assert_eq!(dest.messages_after(&home, 0).unwrap().len(), 2);
    }
    #[test]
    fn missing_attachments_and_invalid_links_refuse_a_complete_export() {
        let dir = tempfile::tempdir().unwrap();
        let (source, mut history) = source(dir.path());
        std::fs::remove_file(dir.path().join("source-media/source-file")).unwrap();
        assert!(
            source
                .export_history("old", "main", &dir.path().join("source-media"))
                .is_err()
        );
        history.attachments[0].id = "../escape".into();
        assert!(history.validate().is_err());
    }
    #[test]
    fn credentials_reject_reserved_variables_and_debug_redacts_values() {
        let secret = "never-appear-in-debug";
        let mut state = HostState {
            credentials: vec![Credential {
                variable: "PATH".into(),
                value: SecretValue::new(secret.into()).unwrap(),
            }],
            ..Default::default()
        };
        assert!(state.validate().is_err());
        state.credentials[0].variable = "API_TOKEN".into();
        assert!(state.validate().is_ok());
        assert!(!format!("{state:?}").contains(secret));
    }
}
