//! The bridge's service (ADR 0042, proposed; `docs/protocol.md`, The
//! device leg): a WebSocket listener on the host's loopback, which its
//! transport puts on the person's network (`tailscale serve`, the only one
//! for now). Each connection is a Noise session with a paired device, or
//! one that is pairing; each agent's app channel is a plugin connection the
//! bridge keeps open.
//!
//! Who calls is what the transport says, in its login header: the bridge
//! listens on loopback only, where nothing else of the network reaches it.
//! A connection without that header is refused.

#[cfg(test)]
#[path = "server_tests.rs"]
mod tests;

#[path = "agent_names.rs"]
mod agent_names;
#[path = "approvals.rs"]
mod approvals;
#[path = "avatars.rs"]
mod avatars;
#[path = "policy.rs"]
mod policy;
#[path = "questions.rs"]
mod questions;
#[path = "routines.rs"]
mod routines;

use std::collections::HashMap;
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use enclos_protocol::device::{
    ATTACHMENT_CHUNK, AgentInfo, Attachment, ConversationInfo, ConversationMessage, FromDevice,
    GroupState, MemberTurn, ToDevice, commands_for_devices, decode_from_device,
};
use enclos_protocol::noise::{Responder, Session};
use enclos_protocol::pairing::{check_proof, check_signature, decode, encode};
use enclos_protocol::plugin::{
    Capability, Command, FromBridge, FromPlugin, OutAttachment, OutKind,
};
use enclos_protocol::{ConversationId, Envelope, MessageId, Person, encode_line};
use tungstenite::handshake::server::{Request, Response};
use tungstenite::{Message, WebSocket};

use super::groups::{
    Discussion, Ended, MAX_MEMBERS, MAX_ROUNDS, MIN_MEMBERS, Said, TURN_TIMEOUT, prompt, turn_id,
};
use super::ids::{new_id, random_bytes};
use super::plugin::{PluginWriter, connect};
use super::store::{
    BY_AGENT, BY_PERSON, Conversation, Device, From, PairingRequest, Store, StoredAttachment,
    home_id, is_home, now,
};
use super::transport::Transport;

/// How long a pairing waits for the terminal's answer.
const PAIRING_WAIT: Duration = Duration::from_secs(120);

/// One agent the bridge serves, with what opens its app channel.
#[derive(Clone)]
pub struct AgentEndpoint {
    /// `<sandbox>/<agent>`.
    pub name: String,
    pub runtime: String,
    pub socket: std::path::PathBuf,
    pub token: String,
}

/// What every connection shares.
struct Hub {
    transport: Transport,
    store_path: std::path::PathBuf,
    layout: crate::layout::Layout,
    bridge_private: Vec<u8>,
    agents: Vec<AgentEndpoint>,
    /// The person the host belongs to, on the transport: whose the agents'
    /// Home conversations are. Unknown, the first person who connects.
    host: Option<String>,
    /// Open plugin connections, by agent.
    plugins: Mutex<HashMap<String, (PluginWriter, Vec<Capability>)>>,
    routines: Mutex<routines::RoutineRequests>,
    questions: Mutex<questions::QuestionRequests>,
    /// The commands each agent's plugin last listed, as devices get them:
    /// kept while the bridge runs, the plugin connected or not.
    commands: Mutex<HashMap<String, Vec<Command>>>,
    /// Each group's discussion, while one runs or since the last ended
    /// (ADR 0045, proposed); its turns are also in the database.
    groups: Mutex<HashMap<String, Discussion>>,
    /// The `/stop` messages the bridge sent members: the runtime's answer
    /// to one (Hermes: "Stopped") is not the member speaking in the group.
    stops: Mutex<std::collections::HashSet<String>>,
    /// Connected devices: who they speak for, and where to send.
    devices: Mutex<HashMap<String, (String, Sender<ToDevice>)>>,
}

impl Hub {
    fn store(&self) -> Result<Store, String> {
        Store::open(&self.store_path).map_err(|e| format!("cannot open the bridge's database: {e}"))
    }

    /// Where the bridge keeps the files of messages, by attachment id:
    /// beside its database.
    fn media(&self) -> std::path::PathBuf {
        self.store_path.with_file_name("app-media")
    }

    /// Sends `message` to every connected device of `person`.
    fn deliver(&self, person: &str, message: ToDevice) {
        let devices = self.devices.lock().expect("not poisoned");
        for (owner, sender) in devices.values() {
            if owner == person {
                let _ = sender.send(message.clone());
            }
        }
    }

    /// Sends `message` to every connected device: what any person who may
    /// reach every agent needs, such as an agent's commands.
    fn deliver_all(&self, message: ToDevice) {
        let devices = self.devices.lock().expect("not poisoned");
        for (_, sender) in devices.values() {
            let _ = sender.send(message.clone());
        }
    }

    /// Opens, in the background, the plugin connections that are not open:
    /// the bridge learns each agent's capabilities and commands without
    /// waiting for a first message. One that cannot open is left for later.
    fn open_plugins(self: &Arc<Hub>) {
        let hub = Arc::clone(self);
        std::thread::spawn(move || {
            for agent in &hub.agents {
                let open = hub
                    .plugins
                    .lock()
                    .expect("not poisoned")
                    .contains_key(&agent.name);
                if !open {
                    let _ = hub.plugin(&agent.name);
                }
            }
        });
    }

    /// The person said `text` (message `seq`) in group `id`: a discussion
    /// starts, or waits for the running turn.
    fn group_said(self: &Arc<Hub>, store: &Store, id: &str, seq: i64, text: &str) {
        let Some((_, handles)) = group_of(store, id) else {
            return;
        };
        {
            let mut groups = self.groups.lock().expect("not poisoned");
            match groups.get_mut(id) {
                Some(d) if d.running.is_some() => d.wait_for(seq, text),
                _ => {
                    groups.insert(id.to_owned(), Discussion::new(seq, text, &handles));
                }
            }
        }
        self.advance(store, id);
    }

    /// Starts group `id`'s next turn, if one is due: the member is sent the
    /// group's messages it has not seen, under the group's id. A member
    /// that cannot be reached fails its turn, and the next goes on.
    fn advance(self: &Arc<Hub>, store: &Store, id: &str) {
        let Some((sandbox, handles)) = group_of(store, id) else {
            return;
        };
        let owner = store.owner(id).ok().flatten().unwrap_or_default();
        let title = store
            .conversation_info(id)
            .ok()
            .flatten()
            .and_then(|c| c.title)
            .unwrap_or_else(|| handles.join(", "));
        loop {
            let mut groups = self.groups.lock().expect("not poisoned");
            let Some(d) = groups.get_mut(id) else { return };
            // A newer message of the person's waited for the turn that ran.
            if d.running.is_none()
                && let Some((seq, text)) = d.pending.take()
            {
                *d = Discussion::new(seq, &text, &handles);
            }
            let seen: HashMap<String, i64> =
                store.members(id).unwrap_or_default().into_iter().collect();
            let newest = store.newest(id).unwrap_or(0);
            let next = d.next_turn(&handles, |m| seen.get(m).copied().unwrap_or(0) < newest);
            let Some((member, direct)) = next else {
                drop(groups);
                self.deliver_group_state(store, id);
                return;
            };
            let (source, round) = (d.source, d.round);
            let turn = turn_id(id, source, round, &member);
            drop(groups);
            let unseen = store
                .messages_after(id, seen.get(&member).copied().unwrap_or(0))
                .unwrap_or_default();
            let said: Vec<Said> = unseen
                .iter()
                .filter(|m| m.kind != "status")
                .map(|m| Said {
                    member: match &m.from {
                        From::Member(a) => Some(a.as_str()),
                        _ => None,
                    },
                    person: match &m.from {
                        From::Person(p) => p.split('@').next().unwrap_or(p),
                        _ => "",
                    },
                    text: &m.text,
                })
                .collect();
            let others: Vec<String> = handles.iter().filter(|h| **h != member).cloned().collect();
            let text = prompt(&title, &member, &others, &said, direct);
            let sent = self.send_to(&format!("{sandbox}/{member}"), id, &owner, &text);
            let _ = store.turn(
                &turn, id, source, round, &member, "queued", None, None, None,
            );
            let mut groups = self.groups.lock().expect("not poisoned");
            let Some(d) = groups.get_mut(id) else { return };
            match sent {
                // Still the same discussion: the turn runs.
                Ok(sent) if d.source == source && d.state == "working" && d.running.is_none() => {
                    let _ = store.turn(
                        &turn,
                        id,
                        source,
                        round,
                        &member,
                        "running",
                        Some(sent.as_str()),
                        Some(newest),
                        None,
                    );
                    let _ = store.saw(id, &member, newest);
                    d.started(&member, turn, sent.as_str().to_owned(), newest, direct);
                    drop(groups);
                    self.deliver_group_state(store, id);
                    return;
                }
                // Stopped or replaced meanwhile: its reply will be dropped.
                Ok(_) => {
                    let _ = store.turn_status(&turn, "cancelled", None);
                    return;
                }
                Err(e) => {
                    let _ = store.turn_status(&turn, "failed", Some(&e));
                    d.turns.insert(member, "failed".to_owned());
                }
            }
        }
    }

    /// A message of `member`'s to group `id`: `Some(true)` for the reply
    /// that ends its running turn, to keep, then go on; `Some(false)` for
    /// one to keep (what it says before its reply, or on its own); `None`
    /// for one to drop (a pass, or the reply to a turn that was stopped).
    fn group_reply(
        self: &Arc<Hub>,
        store: &Store,
        id: &str,
        member: &str,
        reply_to: Option<&str>,
        text: &str,
        kind: &str,
    ) -> Option<bool> {
        let (_, handles) = group_of(store, id)?;
        let mut groups = self.groups.lock().expect("not poisoned");
        if let Some(d) = groups.get_mut(id)
            && let Some(run) = &d.running
            && run.member == member
            && reply_to == Some(run.sent.as_str())
        {
            let turn = run.turn.clone();
            let ended = d.replied(text, &handles);
            drop(groups);
            return match ended {
                Ended::Replied => {
                    let _ = store.turn_status(&turn, "replied", None);
                    Some(true)
                }
                Ended::Passed => {
                    let _ = store.turn_status(&turn, "passed", None);
                    self.advance(store, id);
                    None
                }
                Ended::Failed(why) => {
                    let _ = store.turn_status(&turn, "failed", Some(&why));
                    self.advance(store, id);
                    None
                }
            };
        }
        drop(groups);
        // The runtime's answer to the bridge's /stop: the "Stopped" line says it.
        if reply_to.is_some_and(|r| self.stops.lock().expect("not poisoned").remove(r)) {
            return None;
        }
        // A reply to no running turn of its: kept only when its turn failed
        // because the bridge restarted (the plugin sent it again since).
        if kind == "reply"
            && let Some(sent) = reply_to
        {
            return match store.turn_sent(sent) {
                Ok(Some((turn, status, _))) if status == "failed" => {
                    let _ = store.turn_status(&turn, "replied", None);
                    Some(false)
                }
                Ok(Some(_)) => None,
                // Not a turn's: the member answered on its own.
                _ => Some(false),
            };
        }
        Some(false)
    }

    /// The person stopped group `id`'s discussion: what is queued is
    /// cancelled, and the running member is sent `/stop`.
    fn group_stop(self: &Arc<Hub>, store: &Store, id: &str) {
        let Some((sandbox, _)) = group_of(store, id) else {
            return;
        };
        let running = self
            .groups
            .lock()
            .expect("not poisoned")
            .get_mut(id)
            .and_then(Discussion::stop);
        if let Some(run) = running {
            let _ = store.turn_status(&run.turn, "cancelled", None);
            let owner = store.owner(id).ok().flatten().unwrap_or_default();
            if let Ok(sent) =
                self.send_to(&format!("{sandbox}/{}", run.member), id, &owner, "/stop")
            {
                self.stops
                    .lock()
                    .expect("not poisoned")
                    .insert(sent.as_str().to_owned());
            }
        }
        self.deliver_group_state(store, id);
    }

    /// Fails the turns that ran longer than [`TURN_TIMEOUT`], and goes on.
    fn expire_turns(self: &Arc<Hub>, store: &Store) {
        let late: Vec<(String, String)> = self
            .groups
            .lock()
            .expect("not poisoned")
            .iter_mut()
            .filter_map(|(id, d)| {
                let run = d
                    .running
                    .as_ref()
                    .filter(|r| r.started.elapsed() > TURN_TIMEOUT)?;
                let turn = run.turn.clone();
                d.failed();
                Some((id.clone(), turn))
            })
            .collect();
        for (id, turn) in late {
            let _ = store.turn_status(&turn, "failed", Some("no reply in 15 minutes"));
            self.advance(store, &id);
        }
    }

    /// Where group `id`'s discussion is; settled, with no turns, before the first.
    fn group_state(&self, store: &Store, id: &str) -> Option<GroupState> {
        let (sandbox, handles) = group_of(store, id)?;
        let groups = self.groups.lock().expect("not poisoned");
        let d = groups.get(id);
        Some(GroupState {
            conversation: ConversationId::new(id).ok()?,
            state: d.map_or("settled".to_owned(), |d| d.state.clone()),
            round: d.map_or(0, |d| d.round),
            max_rounds: MAX_ROUNDS,
            members: handles
                .iter()
                .map(|h| MemberTurn {
                    agent: format!("{sandbox}/{h}"),
                    turn: d.and_then(|d| d.turns.get(h).cloned()),
                })
                .collect(),
            reason: d.and_then(|d| d.reason.clone()),
        })
    }

    /// Sends where group `id`'s discussion is to its owner's devices.
    fn deliver_group_state(&self, store: &Store, id: &str) {
        if let (Some(state), Ok(Some(owner))) = (self.group_state(store, id), store.owner(id)) {
            self.deliver(&owner, ToDevice::GroupState(state));
        }
    }

    /// Sends `text` to `agent`'s plugin as `person`'s message in
    /// `conversation`, opening the plugin connection if it is not; the
    /// plugin message's id.
    fn send_to(
        self: &Arc<Hub>,
        agent: &str,
        conversation: &str,
        person: &str,
        text: &str,
    ) -> Result<MessageId, String> {
        self.plugin(agent)?;
        let conversation = ConversationId::new(conversation).map_err(|e| e.to_string())?;
        let person = Person::new(person).map_err(|e| e.to_string())?;
        let mut plugins = self.plugins.lock().expect("not poisoned");
        let (writer, _) = plugins
            .get_mut(agent)
            .ok_or_else(|| format!("{agent}'s app channel closed"))?;
        writer
            .message(&conversation, &person, text)
            .map_err(|e| e.to_string())
    }

    /// Sends conversation `id`, with its name and how far it was read, to
    /// every connected device of `person`: after either changed.
    fn deliver_conversation(&self, store: &Store, person: &str, id: &str) {
        if let Ok(Some(c)) = store.conversation_info(id)
            && let Some(info) = conversation_info(store, c)
        {
            self.deliver(person, ToDevice::Conversation(info));
        }
    }

    /// The agent's plugin connection, opened if it is not; its reader runs
    /// in a thread of its own, storing what the agent says and passing it
    /// on to the conversation's owner.
    fn plugin(self: &Arc<Hub>, agent: &str) -> Result<(), String> {
        let mut plugins = self.plugins.lock().expect("not poisoned");
        if plugins.contains_key(agent) {
            return Ok(());
        }
        let endpoint = self
            .agents
            .iter()
            .find(|a| a.name == agent)
            .ok_or_else(|| format!("no agent {agent} with an app channel"))?;
        let (hello, mut reader, mut writer) =
            connect(&endpoint.socket, &endpoint.token, &home_id(agent))
                .map_err(|e| e.to_string())?;
        if hello.capabilities.contains(&Capability::Approval)
            && let Some((sandbox, _)) = agent.split_once('/')
            && let Ok(name) = sandbox.parse()
            && let Ok(text) = crate::engine::Engine::open(self.layout.clone()).access_context(&name)
        {
            let _ = writer.send(FromBridge::PolicyContext { text });
        }
        let mut acks = writer.try_clone().map_err(|e| e.to_string())?;
        let routine_connection = self.routine_connected(agent);
        self.question_connected(agent, &routine_connection);
        if (hello.capabilities.contains(&Capability::Questions)
            || hello.capabilities.contains(&Capability::RuntimeApprovals))
            && let Ok(store) = self.store()
        {
            self.sync_questions(&store, agent, &mut writer)?;
        }
        plugins.insert(agent.to_owned(), (writer, hello.capabilities));
        let hub = Arc::clone(self);
        let agent = agent.to_owned();
        // Where the plugin puts the files the agent sends: beside its socket.
        let inbox = endpoint.socket.with_file_name("media");
        std::thread::spawn(move || {
            let store = match hub.store() {
                Ok(store) => store,
                Err(e) => return eprintln!("enclos app: {e}"),
            };
            loop {
                let message = match reader.receive() {
                    Ok(Some(message)) => message,
                    Ok(None) => break,
                    Err(e) => {
                        eprintln!("enclos app: {agent}: {e}");
                        break;
                    }
                };
                match message.body {
                    FromPlugin::RoutineResponse(reply) => {
                        hub.routine_response(&store, &agent, &routine_connection, reply);
                    }
                    FromPlugin::Error(error) => {
                        hub.question_error(&store, &agent, &routine_connection, error.clone());
                        hub.routine_error(&store, &agent, &routine_connection, error);
                    }
                    FromPlugin::QuestionAsk {
                        conversation,
                        question,
                    } => {
                        let result = hub.question_ask(
                            &store,
                            &agent,
                            &routine_connection,
                            &conversation,
                            &question,
                            &message.id,
                        );
                        questions::acknowledge_question(&mut acks, &message.id, result);
                    }
                    FromPlugin::QuestionUpdate {
                        question,
                        state,
                        answer,
                        of,
                    } => {
                        let result = hub.question_update(
                            &store,
                            &agent,
                            &routine_connection,
                            &question,
                            state,
                            answer,
                            of.as_ref(),
                            &message.id,
                        );
                        questions::acknowledge_question(&mut acks, &message.id, result);
                    }
                    FromPlugin::MessageOut {
                        conversation,
                        text,
                        kind,
                        attachments,
                        reply_to,
                    } => {
                        let kind = match kind {
                            OutKind::Reply => "reply",
                            OutKind::Notify => "notify",
                            OutKind::Status => "status",
                        };
                        // A group this agent is a member of: its reply may end
                        // its turn, or pass, or come too late to be kept.
                        let member = agent
                            .split_once('/')
                            .map(|(_, n)| n.to_owned())
                            .unwrap_or_default();
                        let group =
                            group_of(&store, conversation.as_str()).filter(|(sandbox, handles)| {
                                agent.starts_with(&format!("{sandbox}/"))
                                    && handles.contains(&member)
                            });
                        let mut ends_turn = false;
                        if group.is_some() {
                            match hub.group_reply(
                                &store,
                                conversation.as_str(),
                                &member,
                                reply_to.as_ref().map(|r| r.as_str()),
                                &text,
                                kind,
                            ) {
                                Some(ends) => ends_turn = ends,
                                None => {
                                    let _ = acks.ack(&message.id);
                                    continue;
                                }
                            }
                        }
                        // A conversation the bridge does not know, or another
                        // agent's: the runtime's home channel as it was, or a
                        // chat gone. It goes to this agent's Home, not nowhere.
                        let own = group.is_some()
                            || matches!(
                                store.conversation_of(conversation.as_str()),
                                Ok(Some((sandbox, name, _))) if format!("{sandbox}/{name}") == agent
                            );
                        let conversation = if own {
                            conversation
                        } else {
                            let _ = store.ensure_home(&agent, hub.host.as_deref().unwrap_or(""));
                            match ConversationId::new(home_id(&agent)) {
                                Ok(home) => home,
                                Err(_) => continue,
                            }
                        };
                        let from = if group.is_some() {
                            From::Member(member.clone())
                        } else {
                            From::Agent
                        };
                        let stored = store.add(
                            message.id.as_str(),
                            conversation.as_str(),
                            &from,
                            &text,
                            kind,
                        );
                        // A message stored once: its files taken once too.
                        let files = match stored {
                            Ok(Some(_)) => attachments
                                .iter()
                                .filter_map(|a| {
                                    take_attachment(&inbox, &hub.media(), conversation.as_str(), a)
                                        .inspect_err(|e| eprintln!("enclos app: {agent}: an attachment is left out: {e}"))
                                        .ok()
                                })
                                .filter(|a| store.add_attachment(a, message.id.as_str()).is_ok())
                                .map(attachment_info)
                                .collect(),
                            _ => Vec::new(),
                        };
                        if let Ok(Some(seq)) = stored
                            && let Ok(Some(owner)) = store.owner(conversation.as_str())
                        {
                            hub.deliver(
                                &owner,
                                ToDevice::Message(ConversationMessage {
                                    question: None,
                                    conversation: conversation.clone(),
                                    agent: agent.clone(),
                                    from: "agent".to_owned(),
                                    text,
                                    kind: kind.to_owned(),
                                    time: now(),
                                    seq,
                                    attachments: files,
                                }),
                            );
                        }
                        if stored.is_ok() {
                            let _ = acks.ack(&message.id);
                        }
                        // The member's reply ended its turn: it has seen its own
                        // message, and the next turn starts.
                        if ends_turn && let Ok(Some(seq)) = stored {
                            let _ = store.saw(conversation.as_str(), &member, seq);
                            hub.advance(&store, conversation.as_str());
                        }
                    }
                    FromPlugin::Typing { conversation, on } => {
                        if let Ok(Some(owner)) = store.owner(conversation.as_str()) {
                            hub.deliver(&owner, ToDevice::Typing { conversation, on });
                        }
                    }
                    // The runtime's name for one of this agent's own
                    // conversations: kept unless the person named it.
                    FromPlugin::Title {
                        conversation,
                        title,
                    } => {
                        let id = conversation.as_str();
                        let mine = matches!(
                            store.conversation_info(id),
                            Ok(Some(c)) if format!("{}/{}", c.sandbox, c.agent) == agent
                        );
                        if mine
                            && let Ok(true) = store.name(id, &title, BY_AGENT)
                            && let Ok(Some(owner)) = store.owner(id)
                        {
                            hub.deliver_conversation(&store, &owner, id);
                        }
                    }
                    // The commands a person may type to the agent: kept,
                    // and passed on to every device.
                    FromPlugin::Commands { commands } => {
                        let commands = commands_for_devices(commands);
                        hub.commands
                            .lock()
                            .expect("not poisoned")
                            .insert(agent.clone(), commands.clone());
                        hub.deliver_all(ToDevice::Commands {
                            agent: agent.clone(),
                            commands,
                        });
                    }
                    // A tool the agent runs, for one of its own agent's
                    // conversations: passed on live, not kept.
                    FromPlugin::ApprovalRequest {
                        conversation,
                        access,
                        action,
                    } => {
                        // The endpoint, not the plugin's text, names its sandbox and agent.
                        let id = conversation.as_str();
                        if store.conversation_info(id).ok().flatten().is_some_and(|c| {
                            format!("{}/{}", c.sandbox, c.agent) == agent
                                || store
                                    .members(id)
                                    .unwrap_or_default()
                                    .iter()
                                    .any(|(m, _)| format!("{}/{m}", c.sandbox) == agent)
                        }) {
                            match hub.request_access(&store, &agent, Some(id), access, &action) {
                                Ok(()) => {
                                    let _ = acks.send(FromBridge::Ack { of: message.id });
                                }
                                Err(e) => {
                                    eprintln!(
                                        "enclos app: could not save {agent}'s policy request: {e}"
                                    );
                                }
                            }
                        } else {
                            let _ =
                                acks.send(FromBridge::Error(enclos_protocol::plugin::ErrorBody {
                                    of: Some(message.id.clone()),
                                    code: enclos_protocol::plugin::ErrorCode::NotAllowed,
                                    message:
                                        "A policy request must name a conversation of this agent."
                                            .into(),
                                }));
                            let _ = acks.send(FromBridge::Ack { of: message.id });
                        }
                    }
                    FromPlugin::Tool(step) => {
                        if let Ok(Some(c)) = store.conversation_info(step.conversation.as_str())
                            && format!("{}/{}", c.sandbox, c.agent) == agent
                            && let Ok(Some(owner)) = store.owner(step.conversation.as_str())
                        {
                            hub.deliver(&owner, ToDevice::Tool(step));
                        }
                    }
                    _ => {}
                }
            }
            // Closed: the next message to this agent opens it again.
            hub.question_disconnected(&store, &agent, &routine_connection);
            hub.routine_disconnected(&store, &agent, &routine_connection);
            hub.plugins.lock().expect("not poisoned").remove(&agent);
        });
        Ok(())
    }
}

/// Serves on `127.0.0.1:port` until the process ends.
pub fn serve(
    transport: Transport,
    port: u16,
    store_path: std::path::PathBuf,
    layout: crate::layout::Layout,
    bridge_private: Vec<u8>,
    agents: Vec<AgentEndpoint>,
) -> std::io::Result<()> {
    let listener = TcpListener::bind(("127.0.0.1", port))?;
    let host = transport.host_person();
    let hub = Arc::new(Hub {
        transport,
        store_path,
        layout,
        bridge_private,
        agents,
        host,
        plugins: Mutex::new(HashMap::new()),
        routines: Mutex::new(Default::default()),
        questions: Mutex::new(Default::default()),
        commands: Mutex::new(HashMap::new()),
        groups: Mutex::new(HashMap::new()),
        stops: Mutex::new(std::collections::HashSet::new()),
        devices: Mutex::new(HashMap::new()),
    });
    // Each agent's Home, the host's person's, before anything is sent to it.
    {
        let hub = Arc::clone(&hub);
        std::thread::spawn(move || {
            let Ok(store) = hub.store() else { return };
            loop {
                std::thread::sleep(Duration::from_secs(1));
                hub.expire_routines(&store);
                hub.expire_questions(&store);
            }
        });
    }
    if let (Some(host), Ok(store)) = (hub.host.as_deref(), hub.store()) {
        for agent in &hub.agents {
            let _ = store.ensure_home(&agent.name, host);
        }
    }
    // Turns left running when the bridge stopped: failed, unless the
    // member's reply comes yet (ADR 0045).
    if let Ok(store) = hub.store() {
        for (turn, _, _) in store.running_turns().unwrap_or_default() {
            let _ = store.turn_status(&turn, "failed", Some("the bridge restarted"));
        }
    }
    {
        let hub = Arc::clone(&hub);
        std::thread::spawn(move || {
            let Ok(store) = hub.store() else { return };
            loop {
                std::thread::sleep(Duration::from_secs(30));
                hub.expire_turns(&store);
            }
        });
    }
    if let Ok(store) = hub.store() {
        let _ = store.recover_approvals();
        let _ = hub.dismiss_probe_requests(&store);
    }
    {
        let hub = Arc::clone(&hub);
        std::thread::spawn(move || {
            loop {
                if let Ok(store) = hub.store()
                    && let Err(e) = hub.collect_refusals(&store)
                {
                    eprintln!("enclos app approvals: {e}");
                }
                // A policy restart closes the plugin sockets. Reopen them so cron
                // work, too, gets fresh policy knowledge without a phone reconnect.
                for agent in &hub.agents {
                    let _ = hub.plugin(&agent.name);
                }
                std::thread::sleep(Duration::from_secs(3));
            }
        });
    }
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let hub = Arc::clone(&hub);
        std::thread::spawn(move || {
            // The pairing page, for a browser; anything else is a device's
            // WebSocket. A caller that sends nothing gives up the thread.
            if stream
                .set_read_timeout(Some(Duration::from_secs(30)))
                .is_err()
            {
                return;
            }
            if super::page::requested(&stream) {
                let _ = super::page::serve(stream);
                return;
            }
            match connection(&hub, stream) {
                // The device hung up: the app closed or replaced its
                // connection. `enclos app log` has who and when.
                Err(e) if e == "closed" => eprintln!("enclos app: a device disconnected"),
                Err(e) => eprintln!("enclos app: a connection ended: {e}"),
                Ok(()) => {}
            }
        });
    }
    Ok(())
}

/// What a device's connection is once the handshake is done.
struct Link {
    socket: WebSocket<TcpStream>,
    session: Session,
}

impl Link {
    fn send(&mut self, body: ToDevice) -> Result<(), String> {
        let id = MessageId::new(new_id().map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
        let plain = encode_line(&Envelope::new(id, body));
        let sealed = self.session.encrypt(&plain).map_err(|e| e.to_string())?;
        self.socket
            .send(Message::Binary(sealed.into()))
            .map_err(|e| e.to_string())
    }

    /// The next message, `None` while nothing came in time.
    fn receive(&mut self) -> Result<Option<Envelope<FromDevice>>, String> {
        match self.socket.read() {
            Ok(Message::Binary(bytes)) => {
                let plain = self.session.decrypt(&bytes).map_err(|e| e.to_string())?;
                decode_from_device(&plain)
                    .map(Some)
                    .map_err(|e| e.to_string())
            }
            Ok(Message::Close(_)) => Err("closed".to_owned()),
            Ok(_) => Ok(None),
            Err(tungstenite::Error::Io(e))
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                Ok(None)
            }
            Err(e) => Err(e.to_string()),
        }
    }
}

fn binary(socket: &mut WebSocket<TcpStream>) -> Result<Vec<u8>, String> {
    loop {
        match socket.read().map_err(|e| e.to_string())? {
            Message::Binary(bytes) => return Ok(bytes.to_vec()),
            Message::Close(_) => return Err("closed".to_owned()),
            _ => {}
        }
    }
}

// The handshake callback's error is tungstenite's `ErrorResponse`, a whole
// HTTP response: its size is set by the `Callback` trait, not by us.
#[allow(clippy::result_large_err)]
fn connection(hub: &Arc<Hub>, stream: TcpStream) -> Result<(), String> {
    let store = hub.store()?;
    let mut login: Option<String> = None;
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .map_err(|e| e.to_string())?;
    let mut socket = tungstenite::accept_hdr(stream, |request: &Request, response: Response| {
        login = request
            .headers()
            .get(hub.transport.login_header())
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        Ok(response)
    })
    .map_err(|e| e.to_string())?;
    let refuse = |device: Option<&str>, person: Option<&str>, why: &str| {
        let _ = store.log(device, person, "refused", Some(why));
        why.to_owned()
    };
    let Some(person) = login else {
        return Err(refuse(None, None, hub.transport.no_login()));
    };
    let mut responder = Responder::new(&hub.bridge_private).map_err(|e| e.to_string())?;
    let hello = binary(&mut socket)?;
    let noise_key = responder
        .read_hello(&hello)
        .map_err(|e| refuse(None, Some(&person), &format!("handshake: {e}")))?;
    let (answer, session) = responder.answer().map_err(|e| e.to_string())?;
    socket
        .send(Message::Binary(answer.into()))
        .map_err(|e| e.to_string())?;
    let mut link = Link { socket, session };
    let known = store
        .device_by_noise_key(&noise_key)
        .map_err(|e| e.to_string())?;
    let first = loop {
        if let Some(message) = link.receive()? {
            break message;
        }
    };
    let device = match (first.body, known) {
        (FromDevice::Auth { device, sig }, Some(known)) if known.id == device => {
            let sig = decode("sig", &sig).map_err(|e| e.to_string())?;
            if check_signature(&known.device_key, link.session.handshake_hash(), &sig).is_err() {
                return Err(refuse(
                    Some(&known.id),
                    Some(&person),
                    "the device's signature does not hold",
                ));
            }
            if known.person != person {
                return Err(refuse(
                    Some(&known.id),
                    Some(&person),
                    &format!("the device is {}'s, and {person} is calling", known.person),
                ));
            }
            known
        }
        (FromDevice::Auth { .. }, _) => {
            return Err(refuse(None, Some(&person), "an unknown device"));
        }
        (
            FromDevice::PairRequest {
                name,
                device_key,
                proof,
                push,
            },
            None,
        ) => {
            let device = pair(
                &store, &mut link, &person, &noise_key, name, device_key, proof, push,
            )?;
            let _ = store.log(Some(&device.id), Some(&person), "paired", None);
            device
        }
        _ => {
            return Err(refuse(
                None,
                Some(&person),
                "the first message is neither auth nor a pairing request",
            ));
        }
    };
    link.send(ToDevice::Authenticated {
        person: person.clone(),
        capabilities: vec!["approval.close".into()],
    })?;
    let _ = store.device_seen(&device.id);
    let _ = store.log(Some(&device.id), Some(&person), "connected", None);
    // The agents' Homes, made at start when the transport names the host's
    // person; else this person's, the first to connect.
    for agent in &hub.agents {
        let _ = store.ensure_home(&agent.name, hub.host.as_deref().unwrap_or(&person));
    }
    let (sender, outbox) = channel();
    hub.devices
        .lock()
        .expect("not poisoned")
        .insert(device.id.clone(), (person.clone(), sender));
    link.socket
        .get_ref()
        .set_read_timeout(Some(Duration::from_millis(200)))
        .map_err(|e| e.to_string())?;
    let ended = run_session(hub, &store, &mut link, &device, &person, &outbox);
    hub.devices.lock().expect("not poisoned").remove(&device.id);
    let _ = store.device_seen(&device.id);
    let _ = store.log(
        Some(&device.id),
        Some(&person),
        "disconnected",
        ended.as_ref().err().map(String::as_str),
    );
    ended
}

#[allow(clippy::too_many_arguments)]
fn pair(
    store: &Store,
    link: &mut Link,
    person: &str,
    noise_key: &[u8],
    name: String,
    device_key: String,
    proof: String,
    push: Option<enclos_protocol::device::PushToken>,
) -> Result<Device, String> {
    let refused = |link: &mut Link, why: &str| -> String {
        let _ = link.send(ToDevice::PairRefused {
            reason: why.to_owned(),
        });
        let _ = store.log(None, Some(person), "refused", Some(why));
        why.to_owned()
    };
    let proof = decode("proof", &proof).map_err(|e| e.to_string())?;
    let device_key = decode("device_key", &device_key).map_err(|e| e.to_string())?;
    let codes = store.open_pairings().map_err(|e| e.to_string())?;
    let hash = link.session.handshake_hash().to_vec();
    let Some(code) = codes
        .into_iter()
        .find(|code| check_proof(code, &hash, &proof).is_ok())
    else {
        return Err(refused(link, "bad_proof"));
    };
    let request = PairingRequest {
        name: name.clone(),
        person: person.to_owned(),
    };
    if !store
        .use_pairing(&code, &request)
        .map_err(|e| e.to_string())?
    {
        return Err(refused(link, "used"));
    }
    let waited = std::time::Instant::now();
    let decision = loop {
        if let Some(decision) = store.pairing_decision(&code).map_err(|e| e.to_string())? {
            break decision;
        }
        if waited.elapsed() > PAIRING_WAIT {
            return Err(refused(link, "expired"));
        }
        std::thread::sleep(Duration::from_millis(500));
    };
    if decision != "accept" {
        return Err(refused(link, "declined"));
    }
    let device = Device {
        id: new_id().map_err(|e| e.to_string())?,
        name,
        person: person.to_owned(),
        noise_key: noise_key.to_vec(),
        device_key,
        push_key: random_bytes(32).map_err(|e| e.to_string())?,
        push_token: push.map(|p| p.token),
        paired: now(),
        seen: None,
    };
    store.add_device(&device).map_err(|e| e.to_string())?;
    link.send(ToDevice::PairAccepted {
        device: device.id.clone(),
        push_key: encode(&device.push_key),
    })?;
    Ok(device)
}

fn run_session(
    hub: &Arc<Hub>,
    store: &Store,
    link: &mut Link,
    device: &Device,
    person: &str,
    outbox: &Receiver<ToDevice>,
) -> Result<(), String> {
    loop {
        while let Ok(message) = outbox.try_recv() {
            link.send(message)?;
        }
        let Some(message) = link.receive()? else {
            continue;
        };
        match message.body {
            FromDevice::AgentNameGet { agent } => {
                match hub.get_agent_name(store, device, person, &agent, message.id.to_string()) {
                    Ok(name) => link.send(name)?,
                    Err(error) => link.send(ToDevice::Error(error))?,
                }
            }
            FromDevice::AgentNameSet(edit) => {
                match hub.set_agent_name(store, device, person, &edit, message.id.to_string()) {
                    Ok(name) => link.send(name)?,
                    Err(error) => {
                        if error.code == enclos_protocol::plugin::ErrorCode::Conflict
                            && let Ok(ToDevice::AgentName(mut current)) = hub.get_agent_name(
                                store,
                                device,
                                person,
                                &edit.agent,
                                message.id.to_string(),
                            )
                        {
                            current.of.clear();
                            link.send(ToDevice::AgentName(current))?;
                        }
                        link.send(ToDevice::Error(error))?;
                    }
                }
            }
            FromDevice::QuestionAnswer {
                question,
                revision,
                answer,
            } => {
                if let Err(error) = hub.question_answer(
                    store, device, person, message.id, question, revision, answer,
                ) {
                    link.send(ToDevice::Error(error))?;
                }
            }
            FromDevice::RoutineRequest { agent, request } => {
                if let Err(error) =
                    hub.routine_request(store, device, person, &agent, message.id, request)
                {
                    link.send(ToDevice::Error(error))?;
                }
            }
            FromDevice::AgentAvatarGet { agent } => {
                match hub.get_avatar(store, device, person, &agent, message.id.to_string()) {
                    Ok(photo) => link.send(photo)?,
                    Err(e) => link.send(ToDevice::Error(enclos_protocol::plugin::ErrorBody {
                        of: Some(message.id),
                        code: enclos_protocol::plugin::ErrorCode::NotAllowed,
                        message: e,
                    }))?,
                }
            }
            FromDevice::AgentAvatarSet(edit) => {
                match hub.set_agent_avatar(store, device, person, &edit, message.id.to_string()) {
                    Ok(photo) => link.send(photo)?,
                    Err(e) => {
                        if let Ok(current) =
                            hub.get_avatar(store, device, person, &edit.agent, String::new())
                        {
                            link.send(current)?;
                        }
                        link.send(ToDevice::Error(enclos_protocol::plugin::ErrorBody {
                            of: Some(message.id),
                            code: enclos_protocol::plugin::ErrorCode::NotAllowed,
                            message: e,
                        }))?;
                    }
                }
            }
            FromDevice::SandboxPolicyGet { sandbox } => {
                let result = hub
                    .policy_authority(store, device, person, &sandbox)
                    .and_then(|name| hub.managed_policy(store, &name));
                match result {
                    Ok(mut state) => {
                        state.of = message.id.to_string();
                        link.send(ToDevice::SandboxPolicy(state))?;
                    }
                    Err(e) => link.send(ToDevice::Error(enclos_protocol::plugin::ErrorBody {
                        of: Some(message.id),
                        code: enclos_protocol::plugin::ErrorCode::NotAllowed,
                        message: e,
                    }))?,
                }
            }
            FromDevice::SandboxPolicyPreview {
                sandbox,
                base,
                change,
            } => {
                let result = hub
                    .policy_authority(store, device, person, &sandbox)
                    .and_then(|name| {
                        crate::engine::Engine::open(hub.layout.clone())
                            .mobile_policy_preview(&name, &base, &change)
                            .map_err(|e| e.to_string())
                    });
                match result {
                    Ok(mut preview) => {
                        preview.of = message.id.to_string();
                        link.send(ToDevice::SandboxPolicyPreview(preview))?;
                    }
                    Err(e) => link.send(ToDevice::Error(enclos_protocol::plugin::ErrorBody {
                        of: Some(message.id),
                        code: enclos_protocol::plugin::ErrorCode::NotAllowed,
                        message: e,
                    }))?,
                }
            }
            FromDevice::SandboxPolicyApply { sandbox, edit } => {
                let result = hub
                    .policy_authority(store, device, person, &sandbox)
                    .and_then(|name| hub.apply_managed_policy(store, device, person, &name, &edit));
                match result {
                    Ok(mut state) => {
                        state.of = message.id.to_string();
                        link.send(ToDevice::SandboxPolicy(state))?;
                    }
                    Err(e) => link.send(ToDevice::Error(enclos_protocol::plugin::ErrorBody {
                        of: Some(message.id),
                        code: enclos_protocol::plugin::ErrorCode::NotAllowed,
                        message: e,
                    }))?,
                }
            }
            FromDevice::ApprovalDecide {
                request,
                revision,
                approve,
            } => {
                let answer = hub.decide_access(store, device, person, &request, &revision, approve);
                if let Err(e) = answer {
                    link.send(ToDevice::Error(enclos_protocol::plugin::ErrorBody {
                        of: Some(message.id),
                        code: enclos_protocol::plugin::ErrorCode::NotAllowed,
                        message: e,
                    }))?;
                } else {
                    link.send(ToDevice::Ack { of: message.id })?;
                }
            }
            FromDevice::ApprovalClose { request } => {
                match hub.close_access(store, device, person, &request) {
                    Ok(()) => link.send(ToDevice::Ack { of: message.id })?,
                    Err(e) => link.send(ToDevice::Error(enclos_protocol::plugin::ErrorBody {
                        of: Some(message.id),
                        code: enclos_protocol::plugin::ErrorCode::NotAllowed,
                        message: e,
                    }))?,
                }
            }
            FromDevice::Agents => {
                let photos = store.avatar_metadata().map_err(|e| e.to_string())?;
                let names = store.agent_name_metadata().map_err(|e| e.to_string())?;
                let plugins = hub.plugins.lock().expect("not poisoned");
                let agents = hub
                    .agents
                    .iter()
                    .map(|a| AgentInfo {
                        display_name: names.get(&a.name).and_then(|n| n.display_name.clone()),
                        name_revision: names.get(&a.name).map(|n| n.revision).unwrap_or(0),
                        can_edit_name: hub.host.as_deref() == Some(person),
                        avatar: photos.get(&a.name).cloned().unwrap_or_default(),
                        can_edit_avatar: hub.host.as_deref() == Some(person),
                        agent: a.name.clone(),
                        runtime: a.runtime.clone(),
                        capabilities: plugins
                            .get(&a.name)
                            .map(|(_, c)| c.clone())
                            .unwrap_or_default(),
                        abilities: vec!["read".to_owned(), "chat".to_owned()],
                    })
                    .collect();
                drop(plugins);
                match agent_names::agent_inventory_messages(agents) {
                    Ok(messages) => {
                        for message in messages {
                            link.send(message)?;
                        }
                    }
                    Err(reason) => {
                        link.send(ToDevice::Error(enclos_protocol::plugin::ErrorBody {
                            of: Some(message.id),
                            code: enclos_protocol::plugin::ErrorCode::BadMessage,
                            message: reason,
                        }))?;
                        continue;
                    }
                }
                // Each agent's commands, as far as the bridge knows them;
                // the others come once their plugin connects.
                let known: Vec<(String, Vec<Command>)> = hub
                    .commands
                    .lock()
                    .expect("not poisoned")
                    .iter()
                    .map(|(agent, commands)| (agent.clone(), commands.clone()))
                    .collect();
                for (agent, commands) in known {
                    link.send(ToDevice::Commands { agent, commands })?;
                }
                hub.open_plugins();
            }
            FromDevice::ConversationNew {
                conversation,
                agent,
            } => {
                let Some((sandbox, name)) = agent.split_once('/') else {
                    continue;
                };
                // A Home is the bridge's to make, for the host's person.
                if !hub.agents.iter().any(|a| a.name == agent) || is_home(conversation.as_str()) {
                    continue;
                }
                store
                    .conversation(conversation.as_str(), sandbox, name, person)
                    .map_err(|e| e.to_string())?;
                // The person's other devices learn of it too.
                hub.deliver_conversation(store, person, conversation.as_str());
            }
            FromDevice::GroupNew {
                conversation,
                members,
                title,
            } => {
                let id = conversation.as_str();
                // Two to six known agents of one sandbox, each once (ADR 0045).
                let mut sandbox = None;
                let mut names: Vec<String> = Vec::new();
                for m in &members {
                    let Some((s, n)) = m.split_once('/') else {
                        continue;
                    };
                    if hub.agents.iter().any(|a| &a.name == m)
                        && sandbox.get_or_insert(s.to_owned()) == s
                        && !names.iter().any(|x| x == n)
                    {
                        names.push(n.to_owned());
                    }
                }
                let Some(sandbox) = sandbox else { continue };
                if names.len() != members.len()
                    || !(MIN_MEMBERS..=MAX_MEMBERS).contains(&names.len())
                    || is_home(id)
                    || store
                        .conversation_of(id)
                        .map_err(|e| e.to_string())?
                        .is_some()
                {
                    link.send(ToDevice::Error(enclos_protocol::plugin::ErrorBody {
                        of: Some(message.id),
                        code: enclos_protocol::plugin::ErrorCode::BadMessage,
                        message: format!(
                            "a group has {MIN_MEMBERS} to {MAX_MEMBERS} agents of one sandbox, each once"
                        ),
                    }))?;
                    continue;
                }
                store
                    .group(id, &sandbox, &names, person)
                    .map_err(|e| e.to_string())?;
                let name = title
                    .filter(|t| !t.trim().is_empty())
                    .unwrap_or_else(|| names.join(", "));
                store
                    .name(id, &name, BY_PERSON)
                    .map_err(|e| e.to_string())?;
                hub.deliver_conversation(store, person, id);
                hub.deliver_group_state(store, id);
            }
            FromDevice::GroupStop { conversation } => {
                if store
                    .owner(conversation.as_str())
                    .map_err(|e| e.to_string())?
                    .as_deref()
                    == Some(person)
                {
                    hub.group_stop(store, conversation.as_str());
                }
            }
            FromDevice::MessageSend { conversation, text } => {
                send(hub, store, link, person, &conversation, message.id, &text)?;
            }
            FromDevice::ConversationRename {
                conversation,
                title,
            } => {
                rename(hub, store, person, &conversation, &title)?;
            }
            // How far the owner read: kept, and sent to all their devices,
            // so a message read on one is not unread on another.
            FromDevice::ConversationRead { conversation, seq } => {
                let id = conversation.as_str();
                if store.owner(id).map_err(|e| e.to_string())?.as_deref() == Some(person)
                    && store.mark_read(id, seq).map_err(|e| e.to_string())?
                {
                    hub.deliver_conversation(store, person, id);
                }
            }
            FromDevice::ConversationArchive {
                conversation,
                archived,
            } => match archive_conversation(hub, store, person, conversation.as_str(), archived) {
                Ok(info) => {
                    // Canonical metadata precedes the Ack, including retries.
                    // Revisions let devices discard older queued broadcasts.
                    link.send(ToDevice::Conversation(info))?;
                    link.send(ToDevice::Ack { of: message.id })?;
                }
                Err(e) => link.send(ToDevice::Error(enclos_protocol::plugin::ErrorBody {
                    of: Some(message.id),
                    code: enclos_protocol::plugin::ErrorCode::NotAllowed,
                    message: e,
                }))?,
            },
            FromDevice::Sync { since } => {
                if hub.host.as_deref() == Some(person) {
                    hub.dismiss_probe_requests(store)?;
                    for a in store.approvals().map_err(|e| e.to_string())? {
                        link.send(ToDevice::Approval(a))?;
                    }
                }
                // Every conversation first, archived or active, named or empty,
                // then the messages. Metadata does not depend on `since`.
                for c in store.conversations(person).map_err(|e| e.to_string())? {
                    if let Some(info) = conversation_info(store, c) {
                        link.send(ToDevice::Conversation(info))?;
                    }
                }
                // Pending cards must refresh even when their introduction predates `since`.
                for question in store
                    .pending_questions_for(person)
                    .map_err(|e| e.to_string())?
                {
                    link.send(ToDevice::Question {
                        question: question.info,
                    })?;
                }
                let mut last = since;
                // Where each group's discussion is, before its messages.
                for c in store.conversations(person).map_err(|e| e.to_string())? {
                    if let Some(state) = hub.group_state(store, &c.id) {
                        link.send(ToDevice::GroupState(state))?;
                    }
                }
                for m in store.since(person, since).map_err(|e| e.to_string())? {
                    let agent = message_agent(store, &m.conversation, &m.from);
                    last = m.seq;
                    let attachments = store
                        .attachments_of(&m.id)
                        .map_err(|e| e.to_string())?
                        .into_iter()
                        .map(attachment_info)
                        .collect();
                    if let Some(question) = &m.question
                        && let Some(current) =
                            store.question(question).map_err(|e| e.to_string())?
                        && current.owner == person
                    {
                        link.send(ToDevice::Question {
                            question: current.info,
                        })?;
                    }
                    link.send(ToDevice::Message(ConversationMessage {
                        question: m.question,
                        conversation: ConversationId::new(m.conversation)
                            .map_err(|e| e.to_string())?,
                        agent,
                        from: match m.from {
                            From::Agent | From::Member(_) => "agent".to_owned(),
                            From::Person(p) => p,
                        },
                        text: m.text,
                        kind: m.kind,
                        // When it was said, not when it is synced.
                        time: m.at,
                        seq: m.seq,
                        attachments,
                    }))?;
                }
                link.send(ToDevice::Synced { seq: last })?;
            }
            FromDevice::AttachmentGet { attachment, offset } => {
                send_attachment(hub, store, link, person, &attachment, offset, message.id)?;
            }
            FromDevice::PushTokenUpdate(push) => {
                store
                    .set_push_token(&device.id, &push.token)
                    .map_err(|e| e.to_string())?;
            }
            // The person forgot this host on the device: unpaired, as
            // `enclos app unpair` does, then the connection ends. The
            // conversations stay, the person's.
            FromDevice::DeviceForget => {
                store.remove_device(&device.id).map_err(|e| e.to_string())?;
                let _ = store.log(
                    Some(&device.id),
                    Some(person),
                    "unpaired",
                    Some("forgotten on the device"),
                );
                link.send(ToDevice::Ack { of: message.id })?;
                let _ = link.socket.close(None);
                let _ = link.socket.flush();
                return Ok(());
            }
            _ => {}
        }
    }
}

/// The largest file the bridge takes from a plugin.
const MAX_ATTACHMENT_BYTES: u64 = 25 * 1024 * 1024;

/// Moves a file the agent sends from the plugin's `media` folder (in the
/// sandbox home) into the bridge's own, under a new id. The plugin runs in
/// the sandbox: only a plain file name of that folder is taken, opened
/// without following a link, and only a regular file of at most
/// [`MAX_ATTACHMENT_BYTES`].
fn take_attachment(
    inbox: &std::path::Path,
    media: &std::path::Path,
    conversation: &str,
    a: &OutAttachment,
) -> Result<StoredAttachment, String> {
    use rustix::fs::{Mode, OFlags};
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
    let plain = !a.file.is_empty()
        && a.file.len() <= 200
        && !a.file.starts_with('.')
        && a.file
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'));
    if !plain {
        return Err(format!(
            "{:?} is not a file name of the media folder",
            a.file
        ));
    }
    let from = inbox.join(&a.file);
    let fd = rustix::fs::open(
        &from,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| format!("{}: {e}", from.display()))?;
    let mut source = std::fs::File::from(fd);
    let meta = source.metadata().map_err(|e| e.to_string())?;
    if !meta.is_file() {
        return Err(format!("{} is not a file", from.display()));
    }
    if meta.len() > MAX_ATTACHMENT_BYTES {
        return Err(format!("{} is larger than 25 MiB", from.display()));
    }
    let id = new_id().map_err(|e| e.to_string())?;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(media)
        .map_err(|e| e.to_string())?;
    let mut target = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(media.join(&id))
        .map_err(|e| e.to_string())?;
    let size = std::io::copy(&mut source, &mut target).map_err(|e| e.to_string())?;
    let _ = std::fs::remove_file(&from);
    let typed = a.mime.split_once('/').is_some_and(|(t, s)| {
        !t.is_empty()
            && !s.is_empty()
            && a.mime
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "/.+-".contains(c))
    });
    let name = a.name.rsplit(['/', '\\']).next().unwrap_or_default().trim();
    Ok(StoredAttachment {
        id,
        conversation: conversation.to_owned(),
        mime: if typed {
            a.mime.to_ascii_lowercase()
        } else {
            "application/octet-stream".to_owned()
        },
        name: if name.is_empty() {
            a.file.clone()
        } else {
            name.chars().take(120).collect()
        },
        size: size as i64,
    })
}

/// The bytes of an attachment from `offset`, at most [`ATTACHMENT_CHUNK`],
/// for the owner of its conversation; anyone else, or an unknown id, gets
/// an `error` and nothing of it.
fn send_attachment(
    hub: &Arc<Hub>,
    store: &Store,
    link: &mut Link,
    person: &str,
    id: &str,
    offset: u64,
    asked: MessageId,
) -> Result<(), String> {
    use std::io::{Read, Seek, SeekFrom};
    let refuse = |link: &mut Link, why: &str| {
        link.send(ToDevice::Error(enclos_protocol::plugin::ErrorBody {
            of: Some(asked.clone()),
            code: enclos_protocol::plugin::ErrorCode::NotAllowed,
            message: why.to_owned(),
        }))
    };
    let Some(a) = store.attachment(id).map_err(|e| e.to_string())? else {
        return refuse(link, "no such attachment");
    };
    if store
        .owner(&a.conversation)
        .map_err(|e| e.to_string())?
        .as_deref()
        != Some(person)
    {
        return refuse(link, "no such attachment");
    }
    // The id is the bridge's own (a UUID), never a path from a device.
    let Ok(mut file) = std::fs::File::open(hub.media().join(&a.id)) else {
        return refuse(link, "the attachment's file is gone");
    };
    let size = file.metadata().map_err(|e| e.to_string())?.len();
    let mut chunk = vec![0; ATTACHMENT_CHUNK.min(size.saturating_sub(offset) as usize)];
    file.seek(SeekFrom::Start(offset))
        .map_err(|e| e.to_string())?;
    file.read_exact(&mut chunk).map_err(|e| e.to_string())?;
    link.send(ToDevice::AttachmentData {
        attachment: a.id,
        offset,
        size,
        data: encode(&chunk),
    })
}

/// A file as a device sees it.
fn attachment_info(a: StoredAttachment) -> Attachment {
    Attachment {
        id: a.id,
        mime: a.mime,
        name: a.name,
        size: a.size.max(0) as u64,
    }
}

/// A conversation for a device: `None` for an id the protocol refuses.
fn conversation_info(store: &Store, c: Conversation) -> Option<ConversationInfo> {
    let members: Vec<String> = store
        .members(&c.id)
        .unwrap_or_default()
        .into_iter()
        .map(|(a, _)| format!("{}/{a}", c.sandbox))
        .collect();
    Some(ConversationInfo {
        home: is_home(&c.id),
        // A group's agent is its sandbox; its members say who is in it.
        agent: if members.is_empty() {
            format!("{}/{}", c.sandbox, c.agent)
        } else {
            c.sandbox.clone()
        },
        conversation: ConversationId::new(c.id).ok()?,
        title: c.title,
        titled_by: c.titled_by,
        read: c.read,
        archived: c.archived,
        revision: c.revision,
        members,
    })
}

/// Archive is bridge metadata, independent of every runtime's session lifecycle.
fn archive_conversation(
    hub: &Hub,
    store: &Store,
    person: &str,
    id: &str,
    archived: bool,
) -> Result<ConversationInfo, String> {
    if archived
        && is_home(id)
        && store.owner(id).map_err(|e| e.to_string())?.as_deref() == Some(person)
    {
        return Err("Home cannot be archived".into());
    }
    let changed = store
        .set_archived(id, person, archived)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "no such conversation".to_owned())?;
    if changed {
        hub.deliver_conversation(store, person, id);
    }
    store
        .conversation_info(id)
        .map_err(|e| e.to_string())?
        .and_then(|c| conversation_info(store, c))
        .ok_or_else(|| "no such conversation".to_owned())
}

/// A group's sandbox and its members' handles, in its order; none for a
/// conversation that is not a group.
fn group_of(store: &Store, id: &str) -> Option<(String, Vec<String>)> {
    let members = store.members(id).ok()?;
    if members.is_empty() {
        return None;
    }
    let (sandbox, _, _) = store.conversation_of(id).ok()??;
    Some((sandbox, members.into_iter().map(|(a, _)| a).collect()))
}

/// A message's `agent` for a device: the conversation's agent, a group
/// member's `sandbox/agent` for what it said, and the group's sandbox for
/// the person's message in a group.
fn message_agent(store: &Store, conversation: &str, from: &From) -> String {
    match (store.conversation_of(conversation), from) {
        (Ok(Some((s, _, _))), From::Member(m)) => format!("{s}/{m}"),
        (Ok(Some((s, a, _))), _) if a.is_empty() => s,
        (Ok(Some((s, a, _))), _) => format!("{s}/{a}"),
        _ => String::new(),
    }
}

/// The person names one of their conversations (or clears its name): stored,
/// sent to their devices, and passed to the agent's plugin, so the runtime
/// keeps the name and names it no more. A plugin that cannot be reached
/// changes nothing: the bridge's name is the one the app shows.
fn rename(
    hub: &Arc<Hub>,
    store: &Store,
    person: &str,
    conversation: &ConversationId,
    title: &str,
) -> Result<(), String> {
    let Some((sandbox, agent, owner)) = store
        .conversation_of(conversation.as_str())
        .map_err(|e| e.to_string())?
    else {
        return Ok(());
    };
    if owner != person {
        return Ok(());
    }
    if !store
        .name(conversation.as_str(), title, BY_PERSON)
        .map_err(|e| e.to_string())?
    {
        return Ok(());
    }
    hub.deliver_conversation(store, person, conversation.as_str());
    let name = format!("{sandbox}/{agent}");
    if hub.plugin(&name).is_ok() {
        let mut plugins = hub.plugins.lock().expect("not poisoned");
        if let Some((writer, _)) = plugins.get_mut(&name) {
            let _ = writer.send(FromBridge::Rename {
                conversation: conversation.clone(),
                title: title.trim().to_owned(),
            });
        }
    }
    Ok(())
}

/// A person's message: stored, passed to the agent's plugin, and echoed
/// to the person's devices with its place in the order.
fn send(
    hub: &Arc<Hub>,
    store: &Store,
    link: &mut Link,
    person: &str,
    conversation: &ConversationId,
    id: MessageId,
    text: &str,
) -> Result<(), String> {
    let Some((sandbox, agent, owner)) = store
        .conversation_of(conversation.as_str())
        .map_err(|e| e.to_string())?
    else {
        return Ok(());
    };
    if owner != person {
        return Ok(());
    }
    if group_of(store, conversation.as_str()).is_some() {
        let stored = store
            .add(
                id.as_str(),
                conversation.as_str(),
                &From::Person(person.to_owned()),
                text,
                "message",
            )
            .map_err(|e| e.to_string())?;
        if let Some(seq) = stored {
            hub.deliver(
                person,
                ToDevice::Message(ConversationMessage {
                    question: None,
                    conversation: conversation.clone(),
                    agent: sandbox,
                    from: person.to_owned(),
                    text: text.to_owned(),
                    kind: "message".to_owned(),
                    time: now(),
                    seq,
                    attachments: Vec::new(),
                }),
            );
            hub.group_said(store, conversation.as_str(), seq, text);
        }
        return Ok(());
    }
    let name = format!("{sandbox}/{agent}");
    if let Err(e) = hub.plugin(&name) {
        let _ = link.send(ToDevice::Error(enclos_protocol::plugin::ErrorBody {
            of: Some(id),
            code: enclos_protocol::plugin::ErrorCode::AgentUnavailable,
            message: e,
        }));
        return Ok(());
    }
    let person_id = Person::new(person).map_err(|e| e.to_string())?;
    let sent = {
        let mut plugins = hub.plugins.lock().expect("not poisoned");
        let (writer, _) = plugins.get_mut(&name).expect("just opened");
        writer.message(conversation, &person_id, text)
    };
    let sent = sent.map_err(|e| e.to_string())?;
    if let Some(seq) = store
        .add(
            sent.as_str(),
            conversation.as_str(),
            &From::Person(person.to_owned()),
            text,
            "message",
        )
        .map_err(|e| e.to_string())?
    {
        hub.deliver(
            person,
            ToDevice::Message(ConversationMessage {
                question: None,
                conversation: conversation.clone(),
                agent: name,
                from: person.to_owned(),
                text: text.to_owned(),
                kind: "message".to_owned(),
                time: now(),
                seq,
                attachments: Vec::new(),
            }),
        );
    }
    Ok(())
}
