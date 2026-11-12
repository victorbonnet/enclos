//! The bridge's service (ADR 0042, proposed; `docs/protocol.md`, The
//! device leg): a WebSocket listener on the host's loopback, which its
//! transport puts on the person's network (`tailscale serve`, the only one
//! for now). Each connection is a Noise session with a paired device, or
//! one that is pairing; each agent's app channel is a plugin connection the
//! bridge keeps open.
//!
//! Who calls is what the transport says, in its login and address
//! headers: the bridge listens on loopback only, where nothing else of the
//! network reaches it. A connection without them is refused, and so is one
//! whose person or node is not the device's own (`docs/protocol.md`,
//! Handshake).
//!
//! A person's message is stored before it goes to the agent, and stays
//! pending until the plugin acknowledges it: while the agent cannot be
//! reached, the bridge tries again, with the same id, until it can.

#[cfg(test)]
#[path = "server_tests.rs"]
mod tests;

#[path = "approvals.rs"]
mod approvals;
#[path = "group_turns.rs"]
mod group_turns;
#[path = "policy.rs"]
mod policy;

use std::collections::{HashMap, HashSet};
use std::net::{TcpListener, TcpStream};
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use enclos_protocol::device::{
    ATTACHMENT_CHUNK, AgentInfo, Attachment, ConversationInfo, ConversationMessage, FromDevice,
    GroupState, MemberTurn, ToDevice, commands_for_devices, decode_from_device, split_text,
};
use enclos_protocol::noise::{MAX_NOISE_MESSAGE, Responder, Session};
use enclos_protocol::pairing::{Signed, check_proof, check_signature, decode, encode};
use enclos_protocol::plugin::{
    Capability, Command, ErrorBody, ErrorCode, FromBridge, FromPlugin, OutAttachment, OutKind,
    ToolStep,
};
use enclos_protocol::{ConversationId, Envelope, MessageId, Person, encode_line};
use tungstenite::handshake::server::{Request, Response};
use tungstenite::protocol::WebSocketConfig;
use tungstenite::{Message, WebSocket};

use super::groups::{
    Discussion, Ended, MAX_MEMBERS, MAX_ROUNDS, MIN_MEMBERS, Said, TURN_TIMEOUT, prompt, turn_id,
};
use super::ids::{new_id, random_bytes};
use super::pace::Pace;
use super::plugin::{PluginWriter, connect};
use super::store::{
    Added, BY_AGENT, BY_PERSON, Conversation, Device, From, PairingRequest, Store,
    StoredAttachment, conversation_title, home_id, is_home, now,
};
use super::text::plain;
use super::transport::{Caller, Transport, caller_address};
use crate::runtime::home::{open_folder, open_home};

/// How long a pairing waits for the terminal's answer.
const PAIRING_WAIT: Duration = Duration::from_secs(120);

/// How often the bridge tries again to give pending messages to agents.
const RETRY: Duration = Duration::from_secs(10);

/// How long a caller has, from connecting, to send its first message
/// (`auth` or `pair.request`).
const HANDSHAKE: Duration = Duration::from_secs(30);

/// Connections not yet authenticated at once: any login of the tailnet
/// gets that far, so they are few, and a caller past them is closed.
const MAX_WAITING: usize = 16;

/// How long a device's session goes on with nothing from it, not even a
/// ping (the enclos app pings every 30 s): a phone that changed network
/// or slept rarely says goodbye.
const SILENCE: Duration = Duration::from_secs(75);

/// Refusals the log keeps per caller address and minute; past them, that
/// address's connections are closed unlogged and unexamined.
const REFUSALS_PER_MINUTE: u32 = 10;

/// The longest device name the bridge keeps.
const NAME_CHARS: usize = 64;

/// Who is at an address, as the transport says.
type Whois = Arc<dyn Fn(&str) -> Result<Caller, String> + Send + Sync>;

/// One agent the bridge serves, with what opens its app channel.
#[derive(Clone)]
pub struct AgentEndpoint {
    /// `<sandbox>/<agent>`.
    pub name: String,
    pub runtime: String,
    pub socket: std::path::PathBuf,
    pub token: String,
}

/// An open plugin connection.
struct Plugin {
    capabilities: Vec<Capability>,
    /// Tells this connection from a later one to the same agent.
    generation: u64,
    /// Its writing side, locked apart from the other plugins: a plugin
    /// that does not read holds only those writing to it.
    out: Arc<Mutex<PluginOut>>,
}

/// What the bridge writes to a plugin, and what it gave it already.
struct PluginOut {
    writer: PluginWriter,
    /// The pending messages given to it already.
    sent: HashSet<String>,
}

/// What every connection shares.
struct Hub {
    transport: Transport,
    whois: Whois,
    store_path: std::path::PathBuf,
    layout: crate::layout::Layout,
    bridge_private: Vec<u8>,
    agents: Vec<AgentEndpoint>,
    /// Open plugin connections, by agent.
    plugins: Mutex<HashMap<String, Plugin>>,
    /// One lock per agent, held while its plugin connection opens, never
    /// with `plugins`: a plugin slow to answer its `hello` holds up the
    /// callers that need that agent, not the bridge.
    opening: HashMap<String, Mutex<()>>,
    /// Whether a pass of [`Hub::open_plugins`] runs: one at a time.
    opening_all: AtomicBool,
    /// The commands each agent's plugin last listed, as devices get them:
    /// kept while the bridge runs, the plugin connected or not, until it
    /// connects again without the `commands` capability.
    commands: Mutex<HashMap<String, Vec<Command>>>,
    /// Each group's discussion, while one runs or since the last ended
    /// (ADR 0045, proposed); its turns are also in the database.
    groups: Mutex<HashMap<String, Discussion>>,
    /// The `/stop` messages the bridge sent members: the runtime's answer
    /// to one (Hermes: "Stopped") is not the member speaking in the group.
    stops: Mutex<std::collections::HashSet<String>>,
    /// How fast each agent may have its messages stored, kept across its
    /// plugin's connections.
    paces: Mutex<HashMap<String, Pace>>,
    generations: AtomicU64,
    /// Connected devices: who they speak for, where to send, and which
    /// connection that is (a phone that reconnects has two for a while).
    devices: Mutex<HashMap<String, Route>>,
    /// Connections not yet authenticated.
    waiting: AtomicUsize,
    /// Refusals logged per caller address in the current minute.
    refusals: Mutex<HashMap<String, (i64, u32)>>,
    silence: Duration,
}

/// Where a connected device's messages go: the person it speaks for, its
/// session's outbox, and that connection's number.
type Route = (String, Sender<ToDevice>, u64);

/// A place among the connections not yet authenticated, given back when
/// dropped.
struct Waiting(Arc<Hub>);

impl Drop for Waiting {
    fn drop(&mut self) {
        self.0.waiting.fetch_sub(1, Ordering::Relaxed);
    }
}

impl Hub {
    /// Returns once `agent` may have one more message stored ([`Pace`]):
    /// at once in a burst, else after a wait, in which its plugin's
    /// connection is not read.
    fn pace(&self, agent: &str) {
        loop {
            let wait = {
                let mut paces = self.paces.lock().expect("not poisoned");
                let now = std::time::Instant::now();
                match paces
                    .entry(agent.to_owned())
                    .or_insert_with(|| Pace::new(now))
                    .take(now)
                {
                    Ok(()) => return,
                    Err(wait) => wait,
                }
            };
            std::thread::sleep(wait);
        }
    }

    // Each is one thing the bridge is given at start; tests pass their own
    #[allow(clippy::too_many_arguments)]
    fn new(
        transport: Transport,
        whois: Whois,
        store_path: std::path::PathBuf,
        layout: crate::layout::Layout,
        bridge_private: Vec<u8>,
        agents: Vec<AgentEndpoint>,
        host: Option<String>,
        silence: Duration,
    ) -> Hub {
        // `host`: a person to name the host's person if the database names
        // none yet, as a first pairing would (tests); `serve` names none.
        if let Some(host) = &host
            && let Ok(store) = Store::open(&store_path)
        {
            let _ = store.claim_host(host);
        }
        let opening = agents
            .iter()
            .map(|a| (a.name.clone(), Mutex::new(())))
            .collect();
        Hub {
            transport,
            whois,
            store_path,
            layout,
            bridge_private,
            agents,
            plugins: Mutex::new(HashMap::new()),
            opening,
            opening_all: AtomicBool::new(false),
            commands: Mutex::new(HashMap::new()),
            paces: Mutex::new(HashMap::new()),
            groups: Mutex::new(HashMap::new()),
            stops: Mutex::new(HashSet::new()),
            generations: AtomicU64::new(0),
            devices: Mutex::new(HashMap::new()),
            waiting: AtomicUsize::new(0),
            refusals: Mutex::new(HashMap::new()),
            silence,
        }
    }

    fn store(&self) -> Result<Store, String> {
        Store::open(&self.store_path).map_err(|e| format!("cannot open the bridge's database: {e}"))
    }

    /// The host's person (ADR 0044): named by the first device paired at
    /// the host's terminal, or by `enclos app host` since, and kept in the
    /// bridge's database, never taken from the transport. `None` until a
    /// device is paired.
    fn known_host(&self) -> Option<String> {
        self.store().ok()?.host_person().ok().flatten()
    }

    /// Gives each agent's Home to the host's person, made if need be and
    /// taken from anyone else. Nothing while no device has named them: a
    /// Home made meanwhile has no owner, and keeps what comes for it.
    fn ensure_homes(&self, store: &Store) {
        let Ok(Some(host)) = store.host_person() else {
            return;
        };
        for agent in &self.agents {
            if let Ok(true) = store.ensure_home(&agent.name, &host, true) {
                eprintln!(
                    "enclos app: {}'s Home is {host}'s, the host's person",
                    agent.name
                );
            }
        }
    }

    /// Where the bridge keeps the files of messages, by attachment id:
    /// beside its database.
    fn media(&self) -> std::path::PathBuf {
        self.store_path.with_file_name("app-media")
    }

    /// Sends `message` to every connected device of `person`.
    fn deliver(&self, person: &str, message: ToDevice) {
        let devices = self.devices.lock().expect("not poisoned");
        for (owner, sender, _) in devices.values() {
            if owner == person {
                let _ = sender.send(message.clone());
            }
        }
    }

    /// Sends `message` to every connected device: what any person who may
    /// reach every agent needs, such as an agent's commands.
    ///
    /// Every paired person may reach every agent today. Once who sees
    /// which agent is limited (ADR 0043), this needs the same filter as
    /// `agents.list`, or an agent's commands reach people it is not shared
    /// with.
    fn deliver_all(&self, message: ToDevice) {
        let devices = self.devices.lock().expect("not poisoned");
        for (_, sender, _) in devices.values() {
            let _ = sender.send(message.clone());
        }
    }

    /// What a device asking for the agents is sent: the list, then each
    /// agent's commands as far as the bridge knows them; the others come
    /// once their plugin connects.
    fn agents_answer(&self) -> Vec<ToDevice> {
        let plugins = self.plugins.lock().expect("not poisoned");
        let agents = self
            .agents
            .iter()
            .map(|a| AgentInfo {
                agent: a.name.clone(),
                runtime: a.runtime.clone(),
                capabilities: plugins
                    .get(&a.name)
                    .map(|p| p.capabilities.clone())
                    .unwrap_or_default(),
                abilities: vec!["read".to_owned(), "chat".to_owned()],
            })
            .collect();
        drop(plugins);
        let mut answer = vec![ToDevice::AgentsList { agents }];
        let commands = self.commands.lock().expect("not poisoned");
        for (agent, commands) in commands.iter() {
            answer.push(ToDevice::Commands {
                agent: agent.clone(),
                commands: commands.clone(),
            });
        }
        answer
    }

    /// Opens, in the background, the plugin connections that are not open:
    /// the bridge learns each agent's capabilities and commands without
    /// waiting for a first message. One that cannot open is left for later.
    /// While a pass runs, another is not started: a plugin slow to answer
    /// does not gather a thread per request.
    fn open_plugins(self: &Arc<Hub>) {
        if self.opening_all.swap(true, Ordering::SeqCst) {
            return;
        }
        /// Ends the pass, whatever ends its thread.
        struct Done(Arc<Hub>);
        impl Drop for Done {
            fn drop(&mut self) {
                self.0.opening_all.store(false, Ordering::SeqCst);
            }
        }
        let done = Done(Arc::clone(self));
        std::thread::spawn(move || {
            for agent in &done.0.agents {
                let _ = done.0.plugin(&agent.name);
            }
        });
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
        let open = |hub: &Hub| {
            hub.plugins
                .lock()
                .expect("not poisoned")
                .contains_key(agent)
        };
        if open(self) {
            return Ok(());
        }
        let generation = self.generations.fetch_add(1, Ordering::Relaxed);
        let endpoint = self
            .agents
            .iter()
            .find(|a| a.name == agent)
            .ok_or_else(|| format!("no agent {agent} with an app channel"))?;
        // One opening at a time for this agent, and none with the map of
        // connections locked: the plugin listens in the sandbox, and may
        // take its time over the `hello`.
        let _opening = self
            .opening
            .get(agent)
            .map(|m| m.lock().expect("not poisoned"));
        if open(self) {
            return Ok(());
        }
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
        let lists_commands = hello.capabilities.contains(&Capability::Commands);
        {
            let mut plugins = self.plugins.lock().expect("not poisoned");
            if plugins.contains_key(agent) {
                // Opened meanwhile: the plugin takes one bridge connection
                // at a time, and that one is it
                writer.shutdown();
                return Ok(());
            }
            plugins.insert(
                agent.to_owned(),
                Plugin {
                    capabilities: hello.capabilities,
                    generation,
                    out: Arc::new(Mutex::new(PluginOut {
                        writer,
                        sent: HashSet::new(),
                    })),
                },
            );
        }
        // A plugin that no longer lists its commands: the ones it listed
        // before are offered no more.
        let dropped = !lists_commands
            && self
                .commands
                .lock()
                .expect("not poisoned")
                .remove(agent)
                .is_some();
        if dropped {
            self.deliver_all(ToDevice::Commands {
                agent: agent.to_owned(),
                commands: Vec::new(),
            });
        }
        let hub = Arc::clone(self);
        let agent = agent.to_owned();
        // The plugin puts the files the agent sends in the sandbox home.
        let home = sandbox_home(&endpoint.socket);
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
                    FromPlugin::MessageOut {
                        conversation,
                        text,
                        kind,
                        attachments,
                        reply_to,
                    } => {
                        // Every runtime may send on its own: past a burst,
                        // at a pace, so that a loop fills neither the
                        // database nor the devices' queues.
                        hub.pace(&agent);
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
                        let conversation = if group.is_some() {
                            Some(conversation)
                        } else {
                            let host = hub.known_host();
                            destination(&store, host.as_deref(), &agent, conversation)
                        };
                        let Some(conversation) = conversation else {
                            // Not stored, and acknowledged all the same: sent
                            // again, it would fail again at every connection.
                            let _ = acks.ack(&message.id);
                            continue;
                        };
                        let from = if group.is_some() {
                            From::Member(member.clone())
                        } else {
                            From::Agent
                        };
                        let whole = ConversationMessage {
                            conversation: conversation.clone(),
                            agent: agent.clone(),
                            from: "agent".to_owned(),
                            text,
                            kind: kind.to_owned(),
                            time: now(),
                            seq: 0,
                            attachments: Vec::new(),
                        };
                        // Unacknowledged, the plugin sends it again
                        let stored = hub.store_agent_text(
                            &store,
                            &message.id,
                            whole,
                            &attachments,
                            &home,
                            &from,
                        );
                        match &stored {
                            Ok(_) => {
                                let _ = acks.ack(&message.id);
                            }
                            Err(e) => eprintln!("enclos app: {agent}: {e}"),
                        }
                        // The member's reply ended its turn: it has seen its own
                        // message, and the next turn starts.
                        // The turn ended whatever the store made of the
                        // reply (an id it had already, or a failure): the
                        // discussion goes on all the same.
                        if ends_turn {
                            if let Ok(Some(seq)) = stored {
                                let _ = store.saw(conversation.as_str(), &member, seq);
                            }
                            hub.advance(&store, conversation.as_str());
                        }
                    }
                    FromPlugin::Ack { of } => {
                        let _ = store.delivered(of.as_str());
                    }
                    FromPlugin::Typing { conversation, on } => {
                        // Only in this agent's own conversations
                        if let Ok(Some((sandbox, with, owner))) =
                            store.conversation_of(conversation.as_str())
                            && format!("{sandbox}/{with}") == agent
                        {
                            hub.deliver(&owner, ToDevice::Typing { conversation, on });
                        }
                    }
                    // The runtime's name for one of this agent's own
                    // conversations: kept unless the person named it, cut
                    // and cleaned in `Store::name` (`conversation_title`).
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
                        if approvals::speaks_in(&store, &agent, id) {
                            // Refused or not, the plugin is answered, so its outbox
                            // does not send the same request again forever.
                            if let Err(e) =
                                hub.request_access(&store, &agent, Some(id), access, &action)
                            {
                                eprintln!("enclos app: {agent}'s policy request: {e}");
                                let _ = acks.send(FromBridge::Error(
                                    enclos_protocol::plugin::ErrorBody {
                                        of: Some(message.id.clone()),
                                        code: enclos_protocol::plugin::ErrorCode::NotAllowed,
                                        message: e,
                                    },
                                ));
                            }
                            let _ = acks.send(FromBridge::Ack { of: message.id });
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
                        if let Some((owner, step)) = tool_step(&store, &agent, step) {
                            hub.deliver(&owner, ToDevice::Tool(step));
                        }
                    }
                    // The plugin could not take a message of the bridge's
                    // (a line too long for it): a group turn sent as that
                    // message fails now, not after 15 minutes.
                    FromPlugin::Error(ErrorBody {
                        of: Some(of),
                        message,
                        ..
                    }) => {
                        let why = format!("the member's app channel refused the turn: {message}");
                        hub.fail_turns(&store, &agent, Some(of.as_str()), &why);
                    }
                    _ => {}
                }
            }
            // Closed: the next message to this agent opens it again. A group
            // turn it was running gets no reply on this connection.
            let mut plugins = hub.plugins.lock().expect("not poisoned");
            if plugins.get(&agent).map(|p| p.generation) == Some(generation) {
                plugins.remove(&agent);
            }
            drop(plugins);
            hub.fail_turns(&store, &agent, None, "the member's app channel closed");
        });
        Ok(())
    }

    /// Stores an agent's text, in as many messages as the device leg needs
    /// (`docs/protocol.md`, Framing), and passes them on to the
    /// conversation's owner. A text stored already is not stored again.
    fn store_agent_text(
        &self,
        store: &Store,
        id: &MessageId,
        whole: ConversationMessage,
        attachments: &[OutAttachment],
        home: &Path,
        from: &From,
    ) -> Result<Option<i64>, String> {
        // Measured with its files' details, which the first piece carries
        let measured = ConversationMessage {
            attachments: attachments
                .iter()
                .map(|a| Attachment {
                    id: "f".repeat(36),
                    mime: a.mime.clone(),
                    name: a.name.clone(),
                    size: a.size,
                })
                .collect(),
            ..whole.clone()
        };
        let pieces = pieces(id, &measured)?;
        let conversation = whole.conversation.as_str();
        let Some(seqs) = store
            .add_pieces(&pieces, conversation, from, &whole.kind)
            .map_err(|e| e.to_string())?
        else {
            return Ok(None);
        };
        let last = seqs.last().copied();
        // A message stored once: its files taken once too, with its first
        // piece, whose id is the plugin's
        let mut files = take_attachments(
            store,
            home,
            &self.media(),
            &whole.agent,
            conversation,
            id.as_str(),
            attachments,
        );
        if let Some(owner) = store.owner(conversation).map_err(|e| e.to_string())? {
            for ((_, text), seq) in pieces.into_iter().zip(seqs) {
                self.deliver(
                    &owner,
                    ToDevice::Message(ConversationMessage {
                        text,
                        seq,
                        attachments: std::mem::take(&mut files),
                        ..whole.clone()
                    }),
                );
            }
        }
        Ok(last)
    }

    /// Gives `agent`'s plugin the messages still pending for it, opening
    /// its connection if it is not open, each with the id it was stored
    /// with: the plugin drops one it has had already.
    fn forward(self: &Arc<Hub>, store: &Store, agent: &str) -> Result<(), String> {
        let (sandbox, name) = agent
            .split_once('/')
            .ok_or_else(|| format!("no agent {agent}"))?;
        let pending = store.pending(sandbox, name).map_err(|e| e.to_string())?;
        if pending.is_empty() {
            return Ok(());
        }
        self.plugin(agent)?;
        // The plugins lock is let go before writing: a write waits for the
        // plugin to read, up to the plugin leg's write timeout
        let (out, generation) = {
            let plugins = self.plugins.lock().expect("not poisoned");
            let Some(plugin) = plugins.get(agent) else {
                return Err(format!("{agent}'s app channel closed"));
            };
            (Arc::clone(&plugin.out), plugin.generation)
        };
        let mut plugin = out.lock().expect("not poisoned");
        for message in pending {
            if plugin.sent.contains(&message.id) {
                continue;
            }
            let body = FromBridge::MessageIn {
                conversation: ConversationId::new(message.conversation)
                    .map_err(|e| e.to_string())?,
                person: Person::new(message.person).map_err(|e| e.to_string())?,
                text: message.text,
            };
            let id = MessageId::new(message.id.clone()).map_err(|e| e.to_string())?;
            if let Err(e) = plugin.writer.send_as(&id, body) {
                // Ended: the next try opens a new one
                plugin.writer.shutdown();
                drop(plugin);
                let mut plugins = self.plugins.lock().expect("not poisoned");
                if plugins.get(agent).map(|p| p.generation) == Some(generation) {
                    plugins.remove(agent);
                }
                return Err(e.to_string());
            }
            plugin.sent.insert(message.id);
        }
        Ok(())
    }
}

/// `message`'s text in pieces that each fit on the device leg, with the id
/// to store each with: `id` for the first, a new one for each other.
pub fn pieces(
    id: &MessageId,
    message: &ConversationMessage,
) -> Result<Vec<(String, String)>, String> {
    split_text(message)
        .into_iter()
        .enumerate()
        .map(|(n, text)| {
            let piece_id = match n {
                0 => id.as_str().to_owned(),
                _ => new_id().map_err(|e| e.to_string())?,
            };
            Ok((piece_id, text))
        })
        .collect()
}

/// The longest tool label passed on, in characters, before its hidden
/// characters are written out.
const MAX_TOOL_LABEL_CHARS: usize = 120;
/// The longest tool name passed on, in characters, likewise.
const MAX_TOOL_NAME_CHARS: usize = 64;
/// The longest call id passed on, in characters.
const MAX_TOOL_CALL_CHARS: usize = 128;

/// A tool step from `agent`'s plugin as the bridge passes it on, with the
/// person to send it to: `None` unless its conversation is one of `agent`'s
/// own. The plugin's cuts run in the sandbox, so the bridge makes its own:
/// each field on one line and short, so the step fits one Noise message,
/// and the label and name with their hidden characters written out
/// ([`enclos_protocol::visible::revealed`]), so what the person reads is
/// what ran.
fn tool_step(store: &Store, agent: &str, step: ToolStep) -> Option<(String, ToolStep)> {
    let c = store.conversation_info(step.conversation.as_str()).ok()??;
    if format!("{}/{}", c.sandbox, c.agent) != agent {
        return None;
    }
    let owner = store.owner(step.conversation.as_str()).ok()??;
    let cut = |text: &str, max: usize| -> String {
        let words: Vec<&str> = text.split_whitespace().collect();
        words.join(" ").chars().take(max).collect()
    };
    let shown = |text: &str, max: usize| enclos_protocol::visible::revealed(&cut(text, max));
    Some((
        owner,
        ToolStep {
            call: cut(&step.call, MAX_TOOL_CALL_CHARS),
            name: shown(&step.name, MAX_TOOL_NAME_CHARS),
            label: step
                .label
                .as_deref()
                .map(|l| shown(l, MAX_TOOL_LABEL_CHARS)),
            ..step
        },
    ))
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
    if let Ok(store) = Store::open(&store_path)
        && let Ok(None) = store.host_person()
    {
        eprintln!(
            "enclos app: no device is paired yet: the first one paired with `enclos app pair` names the host's person, whose each agent's Home is"
        );
    }
    let hub = Arc::new(Hub::new(
        transport,
        Arc::new(move |address: &str| transport.whois(address)),
        store_path,
        layout,
        bridge_private,
        agents,
        None,
        SILENCE,
    ));
    serve_on(listener, hub, RETRY);
    Ok(())
}

/// Tries every `retry` to give agents the messages pending for them, and
/// serves `listener`'s connections; returns once the listener fails.
fn serve_on(listener: TcpListener, hub: Arc<Hub>, retry: Duration) {
    let retrying = Arc::clone(&hub);
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(retry);
            let Ok(store) = retrying.store() else {
                continue;
            };
            for (sandbox, agent) in store.agents_with_pending().unwrap_or_default() {
                // Still unreachable: the next round tries again
                let _ = retrying.forward(&store, &format!("{sandbox}/{agent}"));
            }
        }
    });
    // Each agent's Home, the host's person's, before anything is sent to it.
    if let Ok(store) = hub.store() {
        hub.ensure_homes(&store);
    }
    // Turns left running when the bridge stopped: failed, and their
    // discussions ended (ADR 0045).
    if let Ok(store) = hub.store() {
        hub.restarted(&store);
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
        if hub.waiting.fetch_add(1, Ordering::Relaxed) >= MAX_WAITING {
            // Too many callers mid-handshake: closed, as the stream drops
            hub.waiting.fetch_sub(1, Ordering::Relaxed);
            continue;
        }
        let waiting = Waiting(Arc::clone(&hub));
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
            match connection(&hub, stream, waiting) {
                // The device hung up, or went away (a phone that locks, sleeps
                // or changes network rarely says goodbye): how connections
                // end, not an error. `enclos app log` has who, when and how.
                Err(e) if e == CLOSED || e == GONE || e == SILENT || e == UNPAIRED => {}
                Err(e) => eprintln!("enclos app: a connection ended: {e}"),
                Ok(()) => {}
            }
        });
    }
}

/// The device closed the connection.
const CLOSED: &str = "closed";
/// The device went away without closing it: reset, or just gone.
const GONE: &str = "went away without closing the connection";
/// The device was unpaired while it was connected.
const UNPAIRED: &str = "unpaired";
/// Nothing came from the device, not even a ping, for [`SILENCE`].
const SILENT: &str = "silent for too long";
/// The caller sent no first message within [`HANDSHAKE`].
const TOO_SLOW: &str = "no first message in time";

/// Why reading or writing a device's connection failed: [`GONE`] when the
/// device is simply no longer there, else the error itself.
fn ended(e: tungstenite::Error) -> String {
    use std::io::ErrorKind::{BrokenPipe, ConnectionAborted, ConnectionReset, UnexpectedEof};
    use tungstenite::error::ProtocolError::ResetWithoutClosingHandshake;
    match e {
        tungstenite::Error::Protocol(ResetWithoutClosingHandshake)
        | tungstenite::Error::ConnectionClosed
        | tungstenite::Error::AlreadyClosed => GONE.to_owned(),
        tungstenite::Error::Io(io)
            if matches!(
                io.kind(),
                ConnectionReset | BrokenPipe | ConnectionAborted | UnexpectedEof
            ) =>
        {
            GONE.to_owned()
        }
        e => e.to_string(),
    }
}

/// What a device's connection is once the handshake is done.
struct Link {
    socket: WebSocket<TcpStream>,
    session: Session,
    /// When the device last sent anything, a ping included.
    heard: std::time::Instant,
}

impl Link {
    fn send(&mut self, body: ToDevice) -> Result<(), String> {
        let id = MessageId::new(new_id().map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
        let plain = encode_line(&Envelope::new(id, body));
        let sealed = self.session.encrypt(&plain).map_err(|e| e.to_string())?;
        self.socket
            .send(Message::Binary(sealed.into()))
            .map_err(ended)
    }

    /// The next message, `None` while nothing came in time.
    fn receive(&mut self) -> Result<Option<Envelope<FromDevice>>, String> {
        let read = self.socket.read();
        if read.is_ok() {
            self.heard = std::time::Instant::now();
        }
        match read {
            Ok(Message::Binary(bytes)) => {
                let plain = self.session.decrypt(&bytes).map_err(|e| e.to_string())?;
                decode_from_device(&plain)
                    .map(Some)
                    .map_err(|e| e.to_string())
            }
            Ok(Message::Close(_)) => Err(CLOSED.to_owned()),
            Ok(_) => Ok(None),
            Err(tungstenite::Error::Io(e))
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                Ok(None)
            }
            Err(e) => Err(ended(e)),
        }
    }
}

/// The next binary message, before `deadline`.
fn binary(
    socket: &mut WebSocket<TcpStream>,
    deadline: std::time::Instant,
) -> Result<Vec<u8>, String> {
    loop {
        if std::time::Instant::now() > deadline {
            return Err(TOO_SLOW.to_owned());
        }
        match socket.read() {
            Ok(Message::Binary(bytes)) => return Ok(bytes.to_vec()),
            Ok(Message::Close(_)) => return Err(CLOSED.to_owned()),
            Ok(_) => {}
            Err(tungstenite::Error::Io(e))
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(e) => return Err(ended(e)),
        }
    }
}

impl Hub {
    /// Whether a refusal of a caller at `address` is still logged this
    /// minute; past [`REFUSALS_PER_MINUTE`], its connections are closed
    /// without a line in the log or a question to the transport.
    fn may_refuse_aloud(&self, address: &str) -> bool {
        let minute = now() / 60;
        let mut refusals = self.refusals.lock().expect("not poisoned");
        if refusals.len() > 1024 {
            refusals.retain(|_, (m, _)| *m == minute);
        }
        let (m, count) = refusals.entry(address.to_owned()).or_insert((minute, 0));
        if *m != minute {
            *m = minute;
            *count = 0;
        }
        *count += 1;
        *count <= REFUSALS_PER_MINUTE
    }

    fn over_refusals(&self, address: &str) -> bool {
        let minute = now() / 60;
        self.refusals
            .lock()
            .expect("not poisoned")
            .get(address)
            .is_some_and(|(m, count)| *m == minute && *count >= REFUSALS_PER_MINUTE)
    }
}

// The handshake callback's error is tungstenite's `ErrorResponse`, a whole
// HTTP response: its size is set by the `Callback` trait, not by us.
#[allow(clippy::result_large_err)]
fn connection(hub: &Arc<Hub>, stream: TcpStream, waiting: Waiting) -> Result<(), String> {
    let deadline = std::time::Instant::now() + HANDSHAKE;
    let store = hub.store()?;
    let mut login: Option<String> = None;
    let mut address: Option<String> = None;
    // Each read waits at most this long, so the deadline is looked at
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| e.to_string())?;
    // No device-leg message is larger than one Noise message
    let limits = WebSocketConfig::default()
        .max_message_size(Some(MAX_NOISE_MESSAGE))
        .max_frame_size(Some(MAX_NOISE_MESSAGE));
    let accepted = tungstenite::accept_hdr_with_config(
        stream,
        |request: &Request, response: Response| {
            let header = |name: &str| {
                request
                    .headers()
                    .get(name)
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_owned)
            };
            login = header(hub.transport.login_header());
            address = header(hub.transport.address_header()).and_then(|a| caller_address(&a));
            Ok(response)
        },
        Some(limits),
    );
    let mut socket = accepted.map_err(|e| e.to_string())?;
    let at = address.clone().unwrap_or_else(|| "no address".to_owned());
    if hub.over_refusals(&at) {
        return Err(format!("{at} was refused too often this minute"));
    }
    let refuse = |device: Option<&str>, person: Option<&str>, why: &str| {
        if hub.may_refuse_aloud(&at) {
            let _ = store.log(device, person, "refused", Some(why));
        }
        why.to_owned()
    };
    let (Some(person), Some(address)) = (login, address) else {
        return Err(refuse(None, None, hub.transport.no_login()));
    };
    let caller = (hub.whois)(&address)
        .map_err(|e| refuse(None, Some(&person), &format!("cannot tell who calls: {e}")))?;
    if caller.login != person {
        return Err(refuse(
            None,
            Some(&person),
            &format!(
                "{} says {} calls from {}",
                hub.transport, caller.login, caller.node
            ),
        ));
    }
    let mut responder = Responder::new(&hub.bridge_private).map_err(|e| e.to_string())?;
    let hello = binary(&mut socket, deadline).map_err(|e| match e.as_str() {
        TOO_SLOW => refuse(None, Some(&person), TOO_SLOW),
        _ => e,
    })?;
    let noise_key = responder
        .read_hello(&hello)
        .map_err(|e| refuse(None, Some(&person), &format!("handshake: {e}")))?;
    let (answer, session) = responder.answer().map_err(|e| e.to_string())?;
    socket.send(Message::Binary(answer.into())).map_err(ended)?;
    let mut link = Link {
        socket,
        session,
        heard: std::time::Instant::now(),
    };
    let known = store
        .device_by_noise_key(&noise_key)
        .map_err(|e| e.to_string())?;
    let first = loop {
        if std::time::Instant::now() > deadline {
            return Err(refuse(None, Some(&person), TOO_SLOW));
        }
        if let Some(message) = link.receive()? {
            break message;
        }
    };
    let device = match (first.body, known) {
        (FromDevice::Auth { device, sig }, Some(known)) if known.id == device => {
            let sig = decode("sig", &sig).map_err(|e| e.to_string())?;
            if check_signature(
                &known.device_key,
                Signed::Auth,
                link.session.handshake_hash(),
                &sig,
            )
            .is_err()
            {
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
            match &known.node {
                Some(node) if *node == caller.node_id => {}
                Some(_) => {
                    return Err(refuse(
                        Some(&known.id),
                        Some(&person),
                        &format!(
                            "the device was paired from another node, and {} is calling",
                            caller.node
                        ),
                    ));
                }
                None => {
                    return Err(refuse(
                        Some(&known.id),
                        Some(&person),
                        "the device was paired before the bridge recorded its node: unpair it and pair it again",
                    ));
                }
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
                sig,
                push,
            },
            None,
        ) => {
            let device = pair(
                &store, &mut link, &caller, &noise_key, name, device_key, proof, sig, push,
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
    })?;
    // Authenticated: no longer among the callers that are few at once
    drop(waiting);
    let _ = store.device_seen(&device.id);
    let _ = store.log(Some(&device.id), Some(&person), "connected", None);
    hub.ensure_homes(&store);
    let (sender, outbox) = channel();
    let this = hub.generations.fetch_add(1, Ordering::Relaxed);
    hub.devices
        .lock()
        .expect("not poisoned")
        .insert(device.id.clone(), (person.clone(), sender, this));
    link.socket
        .get_ref()
        .set_read_timeout(Some(Duration::from_millis(200)))
        .map_err(|e| e.to_string())?;
    let ended = run_session(hub, &store, &mut link, &device, &person, &outbox);
    {
        // Only this connection's route: the device may have connected again
        let mut devices = hub.devices.lock().expect("not poisoned");
        if devices.get(&device.id).map(|d| d.2) == Some(this) {
            devices.remove(&device.id);
        }
    }
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
    caller: &Caller,
    noise_key: &[u8],
    name: String,
    device_key: String,
    proof: String,
    sig: String,
    push: Option<enclos_protocol::device::PushToken>,
) -> Result<Device, String> {
    let person = caller.login.as_str();
    // Shown at the terminal that decides, and in `app devices`
    let name = plain(&name, NAME_CHARS, "unnamed device");
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
    // The device holds the key it asks to pair: checked before the code is
    // used, so a request that fails here leaves it for the real device
    let sig = decode("sig", &sig).map_err(|e| e.to_string())?;
    if check_signature(&device_key, Signed::Pair, &hash, &sig).is_err() {
        return Err(refused(link, "bad_signature"));
    }
    let request = PairingRequest {
        name: name.clone(),
        person: person.to_owned(),
        node: caller.node.clone(),
        node_id: caller.node_id.clone(),
    };
    if !store
        .use_pairing(&code, &request)
        .map_err(|e| e.to_string())?
    {
        return Err(refused(link, "used"));
    }
    // While the person decides in the terminal, the device's connection is
    // read: that answers its pings (an app drops a connection that does not
    // answer them within its interval, 30 s for the enclos app), and shows
    // when it left, which the terminal is then told.
    link.socket
        .get_ref()
        .set_read_timeout(Some(Duration::from_millis(500)))
        .map_err(|e| e.to_string())?;
    let waited = std::time::Instant::now();
    let decision = loop {
        if let Some(decision) = store.pairing_decision(&code).map_err(|e| e.to_string())? {
            break decision;
        }
        if waited.elapsed() > PAIRING_WAIT {
            return Err(refused(link, "expired"));
        }
        let left = match link.socket.read() {
            Ok(Message::Close(_)) => true,
            // A ping counts as hearing from it: the person may take longer
            // to answer than a session may stay silent
            Ok(_) => {
                link.heard = std::time::Instant::now();
                false
            }
            Err(tungstenite::Error::Io(e))
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                false
            }
            Err(_) => true,
        };
        // The pong a ping asked for goes out now, not with the next message.
        if left || link.socket.flush().is_err() {
            let _ = store.decide_pairing(&code, "gone");
            let _ = store.log(
                None,
                Some(person),
                "refused",
                Some("the device left before the answer"),
            );
            return Err("the device left before the answer".to_owned());
        }
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
        node: Some(caller.node_id.clone()),
    };
    store.add_device(&device).map_err(|e| e.to_string())?;
    // A device that does not get its answer has no id to come back with:
    // it is not kept, and the terminal is told.
    if let Err(e) = link.send(ToDevice::PairAccepted {
        device: device.id.clone(),
        push_key: encode(&device.push_key),
    }) {
        let _ = store.remove_device(&device.id);
        let _ = store.settle_pairing(&code, "gone", None);
        let _ = store.log(
            None,
            Some(person),
            "refused",
            Some("the device left before the answer"),
        );
        return Err(e);
    }
    // The first device paired at the host's terminal names the host's
    // person (ADR 0044), before the terminal reads it.
    if let Ok(true) = store.claim_host(person) {
        eprintln!("enclos app: {person} is the host's person: each agent's Home is theirs");
    }
    let _ = store.settle_pairing(&code, "paired", Some(&device.id));
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
        if link.heard.elapsed() > hub.silence {
            return Err(SILENT.to_owned());
        }
        // Unpaired since the last message: it gets nothing more
        if store
            .device(&device.id)
            .map_err(|e| e.to_string())?
            .is_none_or(|d| d.noise_key != device.noise_key)
        {
            let _ = link.socket.close(None);
            let _ = link.socket.flush();
            return Err(UNPAIRED.to_owned());
        }
        while let Ok(message) = outbox.try_recv() {
            link.send(message)?;
        }
        let Some(message) = link.receive()? else {
            continue;
        };
        match message.body {
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
            FromDevice::Agents => {
                for answer in hub.agents_answer() {
                    link.send(answer)?;
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
                let made = group_turns::new_group(
                    hub,
                    store,
                    person,
                    conversation.as_str(),
                    &members,
                    title,
                )?;
                if let Err(why) = made {
                    link.send(ToDevice::Error(ErrorBody {
                        of: Some(message.id),
                        code: enclos_protocol::plugin::ErrorCode::BadMessage,
                        message: why,
                    }))?;
                }
            }
            FromDevice::GroupStop { conversation } => {
                group_turns::stop_group(hub, store, person, conversation.as_str())?;
            }
            FromDevice::MessageSend { conversation, text } => {
                if let Some(answer) = send(hub, store, device, &conversation, message.id, text)? {
                    // After the echo, which the outbox holds
                    while let Ok(message) = outbox.try_recv() {
                        link.send(message)?;
                    }
                    link.send(answer)?;
                }
            }
            FromDevice::ConversationRename {
                conversation,
                title,
            } => {
                rename(hub, store, person, &conversation, &title)?;
            }
            FromDevice::ConversationRead { conversation, seq } => {
                read(hub, store, person, &conversation, seq)?;
            }
            FromDevice::Sync { since } => {
                if hub.known_host().as_deref() == Some(person) {
                    // A log that cannot be read must not end the device's session.
                    if let Err(e) = hub.dismiss_probe_requests(store) {
                        eprintln!("enclos app approvals: {e}");
                    }
                    for a in store.approvals().map_err(|e| e.to_string())? {
                        link.send(ToDevice::Approval(a))?;
                    }
                }
                // Every conversation first, named or empty, then the messages.
                for c in store.conversations(person).map_err(|e| e.to_string())? {
                    if let Some(info) = conversation_info(store, c) {
                        link.send(ToDevice::Conversation(info))?;
                    }
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
                    link.send(ToDevice::Message(ConversationMessage {
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
                forget(store, device, person)?;
                // Unpaired whether or not the answer reaches the device: a
                // failure to send it is not why the connection ended.
                let _ = link.send(ToDevice::Ack { of: message.id });
                let _ = link.socket.close(None);
                let _ = link.socket.flush();
                return Ok(());
            }
            _ => {}
        }
    }
}

/// The person forgot this host on `device`: its row goes, so its keys
/// open no connection again ("an unknown device"), and the log says so.
fn forget(store: &Store, device: &Device, person: &str) -> Result<(), String> {
    store.remove_device(&device.id).map_err(|e| e.to_string())?;
    let _ = store.log(
        Some(&device.id),
        Some(person),
        "unpaired",
        Some("forgotten on the device"),
    );
    Ok(())
}

/// The largest file the bridge takes from a plugin.
const MAX_ATTACHMENT_BYTES: u64 = 25 * 1024 * 1024;

/// The most files the bridge takes from one message.
const MAX_ATTACHMENTS: usize = 10;

/// Where the plugin puts the files the agent sends, under the sandbox
/// home: `.enclos-app/media`, beside its socket
/// (`Layout::agent_app_socket`).
const INBOX: [&str; 2] = [".enclos-app", "media"];

/// The sandbox home of an agent's app socket, which is
/// `<sandbox home>/.enclos-app/<agent>.sock`.
fn sandbox_home(socket: &Path) -> PathBuf {
    socket
        .ancestors()
        .nth(2)
        .map(Path::to_owned)
        .unwrap_or_default()
}

/// The plugin's `media` folder, opened from the sandbox home one folder at
/// a time without following a link at any of them: the sandbox may put a
/// link to a host folder in place of `.enclos-app` or `media`, and the
/// bridge, which runs outside the sandbox, must not read or remove what is
/// there.
fn open_inbox(home: &Path) -> Result<OwnedFd, String> {
    let mut dir = open_home(home).map_err(|e| e.to_string())?;
    let mut shown = "~".to_owned();
    for name in INBOX {
        shown = format!("{shown}/{name}");
        dir = open_folder(&dir, name, &shown)
            .map_err(|e| e.to_string())?
            .ok_or_else(|| format!("{shown}: no such folder"))?;
    }
    Ok(dir)
}

/// The files of an agent's message, once it is stored: each taken from the
/// plugin's `media` folder under `home` ([`take_attachment`]) and recorded
/// with the message, at most [`MAX_ATTACHMENTS`]. One that cannot be is
/// left out, said on stderr, and leaves no file in `media`.
fn take_attachments(
    store: &Store,
    home: &Path,
    media: &Path,
    agent: &str,
    conversation: &str,
    message: &str,
    attachments: &[OutAttachment],
) -> Vec<Attachment> {
    if attachments.len() > MAX_ATTACHMENTS {
        eprintln!(
            "enclos app: {agent}: a message carries {} files, the first {MAX_ATTACHMENTS} are taken",
            attachments.len()
        );
    }
    attachments
        .iter()
        .take(MAX_ATTACHMENTS)
        .filter_map(|a| {
            let taken = take_attachment(home, media, conversation, a)
                .inspect_err(|e| eprintln!("enclos app: {agent}: an attachment is left out: {e}"))
                .ok()?;
            if let Err(e) = store.add_attachment(&taken, message) {
                eprintln!("enclos app: {agent}: an attachment is left out: cannot record it: {e}");
                let _ = std::fs::remove_file(media.join(&taken.id));
                return None;
            }
            Some(attachment_info(taken))
        })
        .collect()
}

/// Copies `source` into the new file `to`, and its size: no more than `max`
/// bytes are copied, and a source found longer leaves no file and is an
/// error, as is any failure.
fn copy_at_most(source: impl std::io::Read, to: &Path, max: u64) -> Result<u64, String> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut target = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(to)
        .map_err(|e| e.to_string())?;
    let copied = std::io::copy(&mut source.take(max + 1), &mut target);
    drop(target);
    match copied {
        Ok(size) if size <= max => Ok(size),
        Ok(_) => {
            let _ = std::fs::remove_file(to);
            Err(format!("longer than {max} bytes"))
        }
        Err(e) => {
            let _ = std::fs::remove_file(to);
            Err(e.to_string())
        }
    }
}

/// Moves a file the agent sends from the plugin's `media` folder (in the
/// sandbox `home`) into the bridge's own, under a new id. The plugin runs
/// in the sandbox: the folder is opened without following a link
/// ([`open_inbox`]); in it, only a plain file name is taken, opened without
/// following a link and without waiting (a named pipe would block), and
/// only a regular file with no other link to it, of at most
/// [`MAX_ATTACHMENT_BYTES`], copied no further than that limit even while
/// it grows. The plugin's copy is then removed through the same folder.
fn take_attachment(
    home: &Path,
    media: &Path,
    conversation: &str,
    a: &OutAttachment,
) -> Result<StoredAttachment, String> {
    use rustix::fs::{AtFlags, Mode, OFlags};
    use std::os::unix::fs::DirBuilderExt;
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
    let inbox = open_inbox(home)?;
    let from = format!("~/{}/{}", INBOX.join("/"), a.file);
    let fd = rustix::fs::openat(
        &inbox,
        a.file.as_str(),
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| format!("{from}: {e}"))?;
    let opened = rustix::fs::fstat(&fd).map_err(|e| format!("{from}: {e}"))?;
    if !rustix::fs::FileType::from_raw_mode(opened.st_mode).is_file() {
        return Err(format!("{from} is not a file"));
    }
    // A second link may be one to a host file the sandbox could not read.
    if opened.st_nlink != 1 {
        return Err(format!("{from} has other links to it"));
    }
    if opened.st_size < 0 || opened.st_size as u64 > MAX_ATTACHMENT_BYTES {
        return Err(format!("{from} is larger than 25 MiB"));
    }
    let source = std::fs::File::from(fd);
    let id = new_id().map_err(|e| e.to_string())?;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(media)
        .map_err(|e| e.to_string())?;
    // The sandbox may write on while the bridge reads.
    let size = copy_at_most(source, &media.join(&id), MAX_ATTACHMENT_BYTES)
        .map_err(|e| format!("{from}: {e}"))?;
    // The plugin's copy, through the same folder, and only while its name
    // is still the file that was read.
    if let Ok(now) = rustix::fs::statat(&inbox, a.file.as_str(), AtFlags::SYMLINK_NOFOLLOW)
        && (now.st_dev, now.st_ino) == (opened.st_dev, opened.st_ino)
    {
        let _ = rustix::fs::unlinkat(&inbox, a.file.as_str(), AtFlags::empty());
    }
    let typed = a.mime.split_once('/').is_some_and(|(t, s)| {
        !t.is_empty()
            && !s.is_empty()
            && a.mime
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "/.+-".contains(c))
    });
    // Shown and shared under this name: without the characters that would
    // make it read as another (`U+202E` before `fdp.exe`).
    let name = enclos_protocol::visible::stripped(
        a.name.rsplit(['/', '\\']).next().unwrap_or_default(),
        false,
    );
    let name = name.trim();
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

/// How far `person` read `conversation`: kept, and sent to all their
/// devices, so a message read on one is not unread on another. Only the
/// conversation's owner moves it; anyone else changes and learns nothing.
fn read(
    hub: &Hub,
    store: &Store,
    person: &str,
    conversation: &ConversationId,
    seq: i64,
) -> Result<(), String> {
    let id = conversation.as_str();
    if store.owner(id).map_err(|e| e.to_string())?.as_deref() == Some(person)
        && store.mark_read(id, seq).map_err(|e| e.to_string())?
    {
        hub.deliver_conversation(store, person, id);
    }
    Ok(())
}

/// Where `agent`'s message for `conversation` is kept: there, when it is
/// one of `agent`'s own; else (a conversation the bridge does not know, or
/// another agent's: the runtime's home channel as it was, or a chat gone)
/// `agent`'s Home, made if need be (ADR 0044), not nowhere. `None`, said on
/// stderr, when Home's id is not one the protocol takes.
fn destination(
    store: &Store,
    host: Option<&str>,
    agent: &str,
    conversation: ConversationId,
) -> Option<ConversationId> {
    let own = matches!(
        store.conversation_of(conversation.as_str()),
        Ok(Some((sandbox, name, _))) if format!("{sandbox}/{name}") == agent
    );
    if own {
        return Some(conversation);
    }
    let home = ConversationId::new(home_id(agent))
        .inspect_err(|e| {
            eprintln!(
                "enclos app: {agent}: a message for no conversation of its own is dropped: its Home's id is refused ({e})"
            );
        })
        .ok()?;
    let _ = store.ensure_home(agent, host.unwrap_or(""), host.is_some());
    Some(home)
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
        members,
    })
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
/// changes nothing: the bridge's name is the one the app shows. The name is
/// cut and cleaned as [`conversation_title`] says, wherever it goes.
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
        // Written outside the plugins lock, as in forward
        let out = {
            let plugins = hub.plugins.lock().expect("not poisoned");
            plugins.get(&name).map(|plugin| Arc::clone(&plugin.out))
        };
        if let Some(out) = out {
            let _ = out
                .lock()
                .expect("not poisoned")
                .writer
                .send(FromBridge::Rename {
                    conversation: conversation.clone(),
                    title: conversation_title(title),
                });
        }
    }
    Ok(())
}

/// A person's message: stored once, echoed to the person's devices with
/// its place in the order, and given to the agent's plugin, now or once it
/// can be reached. What to answer the device, if anything.
fn send(
    hub: &Arc<Hub>,
    store: &Store,
    device: &Device,
    conversation: &ConversationId,
    id: MessageId,
    text: String,
) -> Result<Option<ToDevice>, String> {
    let person = device.person.as_str();
    let Some((sandbox, agent, owner)) = store
        .conversation_of(conversation.as_str())
        .map_err(|e| e.to_string())?
    else {
        return Ok(None);
    };
    if owner != person {
        return Ok(None);
    }
    if group_of(store, conversation.as_str()).is_some() {
        let stored = store
            .add(
                id.as_str(),
                conversation.as_str(),
                &From::Person(person.to_owned()),
                &text,
                "message",
            )
            .map_err(|e| e.to_string())?;
        if let Some(seq) = stored {
            hub.deliver(
                person,
                ToDevice::Message(ConversationMessage {
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
            hub.group_said(store, conversation.as_str(), seq, &text);
        }
        return Ok(None);
    }
    let name = format!("{sandbox}/{agent}");
    let echo = ConversationMessage {
        conversation: conversation.clone(),
        agent: name.clone(),
        from: person.to_owned(),
        text,
        kind: "message".to_owned(),
        time: now(),
        seq: 0,
        attachments: Vec::new(),
    };
    // The app refuses one this long before it is sent (`docs/protocol.md`,
    // Framing): its echo would not fit in one message
    if split_text(&echo).len() > 1 {
        return Ok(Some(ToDevice::Error(ErrorBody {
            of: Some(id),
            code: ErrorCode::BadMessage,
            message: "longer than one message on the device leg holds".to_owned(),
        })));
    }
    let origin = format!("{}/{}", device.id, id.as_str());
    let stored_as = new_id().map_err(|e| e.to_string())?;
    // Sent again (the device did not hear back): stored the first time,
    // and given to the agent once, by its first id
    if let Added::New(seq) = store
        .add_from_device(
            &origin,
            &stored_as,
            conversation.as_str(),
            person,
            &echo.text,
        )
        .map_err(|e| e.to_string())?
    {
        hub.deliver(
            person,
            ToDevice::Message(ConversationMessage { seq, ..echo }),
        );
    }
    Ok(hub.forward(store, &name).err().map(|e| {
        ToDevice::Error(ErrorBody {
            of: Some(id),
            code: ErrorCode::AgentUnavailable,
            message: format!(
                "{e}: the message is kept, and goes to the agent once it can be reached"
            ),
        })
    }))
}

#[cfg(test)]
mod connection_end_tests {
    use super::*;
    use enclos_protocol::device::decode_to_device;
    use enclos_protocol::noise::{Initiator, generate_keypair};
    use enclos_protocol::plugin::ToolPhase;
    use enclos_protocol::plugin::decode_from_bridge;
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::{Signature, SigningKey};
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::{Path, PathBuf};
    use tungstenite::client::IntoClientRequest;

    const PERSON: &str = "victor@example.com";
    const TOKEN: &str = "t0ken";

    /// A bridge on a free port of the loopback, serving `lab/main`, whose
    /// plugin listens at `<folder>/main.sock`, with the transport's WhoIs
    /// answering `node`.
    struct Bridge {
        port: u16,
        public: Vec<u8>,
        store: PathBuf,
        socket: PathBuf,
        /// The node `whois` names.
        node: Arc<Mutex<String>>,
        /// The login `whois` names.
        whois_login: Arc<Mutex<String>>,
    }

    fn bridge(folder: &Path) -> Bridge {
        bridge_with(folder, SILENCE)
    }

    fn bridge_with(folder: &Path, silence: Duration) -> Bridge {
        let keys = generate_keypair().unwrap();
        let node = Arc::new(Mutex::new("n-pixel".to_owned()));
        let whois_login = Arc::new(Mutex::new(PERSON.to_owned()));
        let (answer, login) = (Arc::clone(&node), Arc::clone(&whois_login));
        let whois: Whois = Arc::new(move |address: &str| {
            assert_eq!(address, "100.64.0.9");
            Ok(Caller {
                login: login.lock().unwrap().clone(),
                node_id: answer.lock().unwrap().clone(),
                node: "pixel".to_owned(),
            })
        });
        let socket = folder.join("main.sock");
        let store = folder.join("app.db");
        let hub = Arc::new(Hub::new(
            Transport::Tailscale,
            whois,
            store.clone(),
            crate::layout::Layout::at(folder.join("enclos")),
            keys.private.to_vec(),
            vec![AgentEndpoint {
                name: "lab/main".to_owned(),
                runtime: "hermes".to_owned(),
                socket: socket.clone(),
                token: TOKEN.to_owned(),
            }],
            None,
            silence,
        ));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || serve_on(listener, hub, Duration::from_millis(100)));
        Bridge {
            port,
            public: keys.public,
            store,
            socket,
            node,
            whois_login,
        }
    }

    /// A paired device, as the store keeps it, and its private keys.
    struct Phone {
        id: String,
        noise_private: Vec<u8>,
        signing: SigningKey,
    }

    fn paired(bridge: &Bridge, node: &str) -> Phone {
        let noise = generate_keypair().unwrap();
        let signing = SigningKey::from_slice(&[7u8; 32]).unwrap();
        let id = new_id().unwrap();
        Store::open(&bridge.store)
            .unwrap()
            .add_device(&Device {
                id: id.clone(),
                name: "Pixel".to_owned(),
                person: PERSON.to_owned(),
                noise_key: noise.public,
                device_key: signing
                    .verifying_key()
                    .to_sec1_point(false)
                    .as_ref()
                    .to_vec(),
                push_key: vec![0; 32],
                push_token: None,
                paired: now(),
                seen: None,
                node: Some(node.to_owned()),
            })
            .unwrap();
        Phone {
            id,
            noise_private: noise.private.to_vec(),
            signing,
        }
    }

    /// The device's side of one connection.
    struct PhoneLink {
        socket: WebSocket<TcpStream>,
        session: Session,
    }

    impl PhoneLink {
        fn send(&mut self, id: &str, body: FromDevice) {
            let plain = encode_line(&Envelope::new(MessageId::new(id).unwrap(), body));
            let sealed = self.session.encrypt(&plain).unwrap();
            self.socket.send(Message::Binary(sealed.into())).unwrap();
        }

        /// The next message, `None` once the bridge closed the connection.
        /// A conversation's details (`conversation`, sent when one starts
        /// or is named) are passed over: these tests are about messages.
        fn receive(&mut self) -> Option<ToDevice> {
            loop {
                match self.socket.read() {
                    Ok(Message::Binary(bytes)) => {
                        let plain = self.session.decrypt(&bytes).unwrap();
                        match decode_to_device(&plain).unwrap().body {
                            ToDevice::Conversation(_) => continue,
                            body => return Some(body),
                        }
                    }
                    Ok(Message::Close(_)) => return None,
                    Ok(_) => {}
                    Err(tungstenite::Error::Io(e))
                        if e.kind() == std::io::ErrorKind::WouldBlock
                            || e.kind() == std::io::ErrorKind::TimedOut =>
                    {
                        panic!("nothing from the bridge in time")
                    }
                    Err(_) => return None,
                }
            }
        }
    }

    /// A WebSocket to the bridge, with the headers `tailscale serve` adds
    /// for `login`.
    fn websocket(bridge: &Bridge, login: &str) -> WebSocket<TcpStream> {
        let stream = TcpStream::connect(("127.0.0.1", bridge.port)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut request = format!("ws://127.0.0.1:{}/", bridge.port)
            .into_client_request()
            .unwrap();
        request
            .headers_mut()
            .insert("Tailscale-User-Login", login.parse().unwrap());
        request
            .headers_mut()
            .insert("X-Forwarded-For", "100.64.0.9".parse().unwrap());
        tungstenite::client(request, stream).unwrap().0
    }

    /// The Noise handshake as `login`, with the device's static key; `None`
    /// when the bridge closes the connection before answering.
    fn handshake(bridge: &Bridge, noise_private: &[u8], login: &str) -> Option<PhoneLink> {
        let mut socket = websocket(bridge, login);
        let mut initiator = Initiator::new(noise_private, &bridge.public).unwrap();
        socket
            .send(Message::Binary(initiator.hello().unwrap().into()))
            .ok()?;
        let answer = binary(
            &mut socket,
            std::time::Instant::now() + Duration::from_secs(5),
        )
        .ok()?;
        let session = initiator.finish(&answer).unwrap();
        Some(PhoneLink { socket, session })
    }

    /// Connects through the transport's headers and authenticates; the
    /// bridge's first answer, `authenticated` or `None` when it refused.
    fn connect(bridge: &Bridge, phone: &Phone) -> (PhoneLink, Option<ToDevice>) {
        connect_as(bridge, phone, PERSON)
    }

    fn connect_as(bridge: &Bridge, phone: &Phone, login: &str) -> (PhoneLink, Option<ToDevice>) {
        let mut device = handshake(bridge, &phone.noise_private, login).expect("no handshake");
        let signature: Signature = phone
            .signing
            .sign(&Signed::Auth.message(device.session.handshake_hash()));
        device.send(
            "auth-1",
            FromDevice::Auth {
                device: phone.id.clone(),
                sig: encode(signature.to_der().as_bytes()),
            },
        );
        let first = device.receive();
        (device, first)
    }

    /// A stand-in plugin at `socket`: answers each bridge's hello, keeps
    /// every message it gets as `(id, text)`, and acknowledges it. To
    /// `long`, the agent answers with 150,000 characters.
    fn plugin(socket: &Path) -> Arc<Mutex<Vec<(String, String)>>> {
        let listener = UnixListener::bind(socket).unwrap();
        let got = Arc::new(Mutex::new(Vec::new()));
        let kept = Arc::clone(&got);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let stream = stream.unwrap();
                let mut out = stream.try_clone().unwrap();
                let mut lines = BufReader::new(stream);
                let mut answer = |body: FromPlugin| {
                    let id = MessageId::new(new_id().unwrap()).unwrap();
                    out.write_all(&encode_line(&Envelope::new(id, body)))
                        .unwrap();
                };
                let mut line = Vec::new();
                while lines.read_until(b'\n', &mut line).unwrap_or(0) > 0 {
                    let message = decode_from_bridge(&line).unwrap();
                    line.clear();
                    match message.body {
                        FromBridge::Hello { .. } => answer(FromPlugin::Hello {
                            runtime: "hermes".into(),
                            agent: "main".into(),
                            capabilities: vec![],
                        }),
                        FromBridge::MessageIn {
                            text, conversation, ..
                        } => {
                            let long = text == "long";
                            kept.lock()
                                .unwrap()
                                .push((message.id.as_str().to_owned(), text));
                            answer(FromPlugin::Ack { of: message.id });
                            if long {
                                answer(FromPlugin::MessageOut {
                                    conversation,
                                    text: "é".repeat(150_000),
                                    kind: OutKind::Reply,
                                    reply_to: None,
                                    attachments: vec![],
                                });
                            }
                        }
                        _ => {}
                    }
                }
            }
        });
        got
    }

    fn start_conversation(device: &mut PhoneLink) {
        device.send(
            "new-1",
            FromDevice::ConversationNew {
                conversation: ConversationId::new("c-1").unwrap(),
                agent: "lab/main".to_owned(),
            },
        );
    }

    fn say(device: &mut PhoneLink, id: &str, text: &str) {
        device.send(
            id,
            FromDevice::MessageSend {
                conversation: ConversationId::new("c-1").unwrap(),
                text: text.to_owned(),
            },
        );
    }

    /// Waits up to 5 s for `done`.
    fn eventually(mut done: impl FnMut() -> bool) -> bool {
        for _ in 0..50 {
            if done() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        false
    }

    /// What `enclos app pair` does at the terminal: waits for the request
    /// made with `code`, then answers it.
    fn terminal(
        store: &Path,
        code: &'static [u8],
        answer: &'static str,
    ) -> std::thread::JoinHandle<PairingRequest> {
        let store = store.to_owned();
        std::thread::spawn(move || {
            let store = Store::open(&store).unwrap();
            for _ in 0..100 {
                if let Some(request) = store.pairing_request(code).unwrap() {
                    store.decide_pairing(code, answer).unwrap();
                    return request;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            panic!("no pairing request");
        })
    }

    /// A new device asking to pair with `code`, named `name`: the bridge's
    /// answer, `None` when it closed the connection instead.
    fn ask_to_pair(
        bridge: &Bridge,
        code: &[u8],
        name: &str,
    ) -> (Option<PhoneLink>, Option<ToDevice>) {
        ask_to_pair_signed(bridge, code, name, Signed::Pair, PERSON)
    }

    /// [`ask_to_pair`], its signature made for `purpose`, from `login`.
    fn ask_to_pair_signed(
        bridge: &Bridge,
        code: &[u8],
        name: &str,
        purpose: Signed,
        login: &str,
    ) -> (Option<PhoneLink>, Option<ToDevice>) {
        let noise = generate_keypair().unwrap();
        let signing = SigningKey::from_slice(&[9u8; 32]).unwrap();
        let Some(mut device) = handshake(bridge, &noise.private, login) else {
            return (None, None);
        };
        let proof = enclos_protocol::pairing::proof(code, device.session.handshake_hash());
        device.send(
            "pair-1",
            FromDevice::PairRequest {
                name: name.to_owned(),
                device_key: encode(signing.verifying_key().to_sec1_point(false).as_ref()),
                proof: encode(&proof),
                sig: {
                    let signature: Signature =
                        signing.sign(&purpose.message(device.session.handshake_hash()));
                    encode(signature.to_der().as_bytes())
                },
                push: None,
            },
        );
        let answer = device.receive();
        (Some(device), answer)
    }

    #[test]
    fn a_pairing_request_signed_for_another_purpose_is_refused_and_leaves_its_code() {
        let folder = tempfile::tempdir().unwrap();
        let bridge = bridge(folder.path());
        let store = Store::open(&bridge.store).unwrap();
        store.add_pairing(b"code-1", now() + 300).unwrap();
        // An `auth` signature of the same session does not prove a pairing
        let (_, answer) = ask_to_pair_signed(&bridge, b"code-1", "Pixel", Signed::Auth, PERSON);
        assert_eq!(
            answer,
            Some(ToDevice::PairRefused {
                reason: "bad_signature".into()
            })
        );
        assert_eq!(store.pairing_request(b"code-1").unwrap(), None);
        assert!(store.devices().unwrap().is_empty());
    }

    #[test]
    fn an_accepted_pairing_stores_the_device_its_node_and_a_plain_name() {
        let folder = tempfile::tempdir().unwrap();
        let bridge = bridge(folder.path());
        let store = Store::open(&bridge.store).unwrap();
        store.add_pairing(b"code-1", now() + 300).unwrap();
        let terminal = terminal(&bridge.store, b"code-1", "accept");
        // A name that would redraw the terminal's question
        let (device, answer) = ask_to_pair(&bridge, b"code-1", "Pixel\r\x1b[2KAccept?\u{202e}");
        let Some(ToDevice::PairAccepted { device: id, .. }) = answer else {
            panic!("not accepted: {answer:?}");
        };
        let asked = terminal.join().unwrap();
        assert_eq!(
            (
                asked.name.as_str(),
                asked.node.as_str(),
                asked.node_id.as_str()
            ),
            ("Pixel [2KAccept?", "pixel", "n-pixel")
        );
        assert!(matches!(
            device.unwrap().receive(),
            Some(ToDevice::Authenticated { .. })
        ));
        let stored = store.device(&id).unwrap().unwrap();
        assert_eq!(stored.node.as_deref(), Some("n-pixel"));
        assert_eq!(stored.name, "Pixel [2KAccept?");
        assert!(eventually(|| store
            .paired_device(b"code-1")
            .unwrap()
            .as_deref()
            == Some(id.as_str())));
    }

    #[test]
    fn the_first_device_paired_names_the_hosts_person_whatever_the_transport_says() {
        let folder = tempfile::tempdir().unwrap();
        let bridge = bridge(folder.path());
        let store = Store::open(&bridge.store).unwrap();
        // Connecting names nobody: no Home is given yet.
        let phone = paired(&bridge, "n-pixel");
        let (_connected, first) = connect(&bridge, &phone);
        assert!(matches!(first, Some(ToDevice::Authenticated { .. })));
        assert_eq!(store.host_person().unwrap(), None);
        assert_eq!(store.owner("home.lab.main").unwrap(), None);
        // The first paired at the terminal is the host's person, whoever
        // the transport says the host belongs to, and has Home.
        *bridge.whois_login.lock().unwrap() = "alice@example.com".to_owned();
        store.add_pairing(b"code-1", now() + 300).unwrap();
        let terminal_1 = terminal(&bridge.store, b"code-1", "accept");
        let (device, answer) = ask_to_pair_signed(
            &bridge,
            b"code-1",
            "Pixel",
            Signed::Pair,
            "alice@example.com",
        );
        assert!(
            matches!(answer, Some(ToDevice::PairAccepted { .. })),
            "{answer:?}"
        );
        terminal_1.join().unwrap();
        assert!(matches!(
            device.unwrap().receive(),
            Some(ToDevice::Authenticated { .. })
        ));
        assert_eq!(
            store.host_person().unwrap().as_deref(),
            Some("alice@example.com")
        );
        assert!(eventually(|| store
            .owner("home.lab.main")
            .unwrap()
            .as_deref()
            == Some("alice@example.com")));
        // A person paired after does not take it.
        *bridge.whois_login.lock().unwrap() = PERSON.to_owned();
        store.add_pairing(b"code-2", now() + 300).unwrap();
        let terminal_2 = terminal(&bridge.store, b"code-2", "accept");
        let (_, answer) = ask_to_pair(&bridge, b"code-2", "Phone");
        assert!(
            matches!(answer, Some(ToDevice::PairAccepted { .. })),
            "{answer:?}"
        );
        terminal_2.join().unwrap();
        assert_eq!(
            store.host_person().unwrap().as_deref(),
            Some("alice@example.com")
        );
        assert_eq!(
            store.owner("home.lab.main").unwrap().as_deref(),
            Some("alice@example.com")
        );
    }

    #[test]
    fn a_declined_pairing_stores_nothing() {
        let folder = tempfile::tempdir().unwrap();
        let bridge = bridge(folder.path());
        let store = Store::open(&bridge.store).unwrap();
        store.add_pairing(b"code-1", now() + 300).unwrap();
        let terminal = terminal(&bridge.store, b"code-1", "decline");
        let (_, answer) = ask_to_pair(&bridge, b"code-1", "Pixel");
        terminal.join().unwrap();
        assert_eq!(
            answer,
            Some(ToDevice::PairRefused {
                reason: "declined".into()
            })
        );
        assert!(store.devices().unwrap().is_empty());
    }

    #[test]
    fn a_wrong_used_or_expired_code_is_refused() {
        let folder = tempfile::tempdir().unwrap();
        let bridge = bridge(folder.path());
        let store = Store::open(&bridge.store).unwrap();
        store.add_pairing(b"open", now() + 300).unwrap();
        store.add_pairing(b"used", now() + 300).unwrap();
        let request = PairingRequest {
            name: "other".into(),
            person: PERSON.into(),
            node: "pixel".into(),
            node_id: "n-pixel".into(),
        };
        assert!(store.use_pairing(b"used", &request).unwrap());
        store.add_pairing(b"expired", now() - 1).unwrap();
        for code in [&b"wrong"[..], b"used", b"expired"] {
            let (_, answer) = ask_to_pair(&bridge, code, "Pixel");
            assert_eq!(
                answer,
                Some(ToDevice::PairRefused {
                    reason: "bad_proof".into()
                }),
                "{}",
                String::from_utf8_lossy(code)
            );
        }
        assert!(store.devices().unwrap().is_empty());
        // The open code is still there for its device
        assert_eq!(store.open_pairings().unwrap(), [b"open".to_vec()]);
    }

    fn refusal(bridge: &Bridge) -> String {
        let store = Store::open(&bridge.store).unwrap();
        let mut reason = None;
        assert!(eventually(|| {
            reason = store
                .log_lines(10)
                .unwrap()
                .into_iter()
                .rfind(|l| l.event == "refused")
                .and_then(|l| l.reason);
            reason.is_some()
        }));
        reason.unwrap()
    }

    #[test]
    fn a_signature_by_another_key_is_refused() {
        let folder = tempfile::tempdir().unwrap();
        let bridge = bridge(folder.path());
        let mut phone = paired(&bridge, "n-pixel");
        phone.signing = SigningKey::from_slice(&[8u8; 32]).unwrap();
        let (_, first) = connect(&bridge, &phone);
        assert_eq!(first, None);
        assert_eq!(refusal(&bridge), "the device's signature does not hold");
    }

    #[test]
    fn a_login_the_transport_does_not_confirm_is_refused() {
        let folder = tempfile::tempdir().unwrap();
        let bridge = bridge(folder.path());
        let phone = paired(&bridge, "n-pixel");
        // The header says victor; WhoIs says the address is mallory's
        *bridge.whois_login.lock().unwrap() = "mallory@example.com".to_owned();
        assert!(handshake(&bridge, &phone.noise_private, PERSON).is_none());
        assert!(refusal(&bridge).contains("mallory@example.com calls from"));
    }

    #[test]
    fn a_device_used_under_another_login_is_refused() {
        let folder = tempfile::tempdir().unwrap();
        let bridge = bridge(folder.path());
        let phone = paired(&bridge, "n-pixel");
        *bridge.whois_login.lock().unwrap() = "alice@example.com".to_owned();
        let (_, first) = connect_as(&bridge, &phone, "alice@example.com");
        assert_eq!(first, None);
        assert_eq!(
            refusal(&bridge),
            format!("the device is {PERSON}'s, and alice@example.com is calling")
        );
    }

    #[test]
    fn refusals_past_the_limit_are_closed_unlogged() {
        let folder = tempfile::tempdir().unwrap();
        let bridge = bridge(folder.path());
        *bridge.whois_login.lock().unwrap() = "mallory@example.com".to_owned();
        let noise = generate_keypair().unwrap();
        for _ in 0..REFUSALS_PER_MINUTE + 5 {
            assert!(handshake(&bridge, &noise.private, PERSON).is_none());
        }
        let store = Store::open(&bridge.store).unwrap();
        let refused = store
            .log_lines(100)
            .unwrap()
            .iter()
            .filter(|l| l.event == "refused")
            .count();
        // Unless the minute turned while it ran
        assert!(
            (REFUSALS_PER_MINUTE as usize..=REFUSALS_PER_MINUTE as usize * 2).contains(&refused),
            "{refused}"
        );
    }

    #[test]
    fn callers_mid_handshake_are_few_and_a_large_frame_ends_one() {
        let folder = tempfile::tempdir().unwrap();
        let bridge = bridge(folder.path());
        let phone = paired(&bridge, "n-pixel");
        // Callers that connect and say nothing
        let quiet: Vec<_> = (0..MAX_WAITING)
            .map(|_| websocket(&bridge, PERSON))
            .collect();
        std::thread::sleep(Duration::from_millis(200));
        // One more is closed at once
        let stream = TcpStream::connect(("127.0.0.1", bridge.port)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let request = format!("ws://127.0.0.1:{}/", bridge.port)
            .into_client_request()
            .unwrap();
        assert!(tungstenite::client(request, stream).is_err());
        // Once they leave, the device gets in
        drop(quiet);
        std::thread::sleep(Duration::from_millis(500));
        assert!(matches!(
            connect(&bridge, &phone).1,
            Some(ToDevice::Authenticated { .. })
        ));
        // A frame larger than any device-leg message ends the connection
        let mut device = handshake(&bridge, &phone.noise_private, PERSON).unwrap();
        let _ = device
            .socket
            .send(Message::Binary(vec![0; MAX_NOISE_MESSAGE + 1].into()));
        assert_eq!(device.receive(), None);
    }

    #[test]
    fn a_device_that_reconnects_keeps_getting_its_messages() {
        let folder = tempfile::tempdir().unwrap();
        let bridge = bridge(folder.path());
        let _got = plugin(&bridge.socket);
        let phone = paired(&bridge, "n-pixel");
        // The phone changed network: B opens while A is still there
        let (mut first, _) = connect(&bridge, &phone);
        start_conversation(&mut first);
        let (mut second, _) = connect(&bridge, &phone);
        // A ends: B's route stays
        let _ = first.socket.close(None);
        let _ = first.socket.flush();
        drop(first);
        std::thread::sleep(Duration::from_millis(500));
        say(&mut second, "m-1", "still there?");
        assert!(matches!(
            second.receive(),
            Some(ToDevice::Message(ref m)) if m.text == "still there?"
        ));
    }

    #[test]
    fn a_plugin_that_never_answers_holds_no_other_device() {
        let folder = tempfile::tempdir().unwrap();
        let bridge = bridge(folder.path());
        // An agent that takes the connection and says nothing
        let listener = UnixListener::bind(&bridge.socket).unwrap();
        let _held = std::thread::spawn(move || {
            let held: Vec<_> = listener.incoming().take(2).collect();
            std::thread::sleep(Duration::from_secs(30));
            drop(held);
        });
        let phone = paired(&bridge, "n-pixel");
        let (mut waiting, _) = connect(&bridge, &phone);
        start_conversation(&mut waiting);
        // Its session waits for the plugin's hello, up to 10 s
        say(&mut waiting, "m-1", "hello?");
        std::thread::sleep(Duration::from_millis(300));
        // Another session is answered meanwhile
        let (mut other, _) = connect(&bridge, &phone);
        let started = std::time::Instant::now();
        other.send("a-1", FromDevice::Agents);
        loop {
            match other.receive() {
                Some(ToDevice::AgentsList { agents }) => {
                    assert_eq!(agents.len(), 1);
                    break;
                }
                Some(_) => {}
                None => panic!("closed"),
            }
        }
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "{:?}",
            started.elapsed()
        );
    }

    #[test]
    fn a_silent_device_is_let_go() {
        let folder = tempfile::tempdir().unwrap();
        let bridge = bridge_with(folder.path(), Duration::from_millis(500));
        let phone = paired(&bridge, "n-pixel");
        let (mut device, _) = connect(&bridge, &phone);
        // Nothing from the device, not even a ping
        assert_eq!(device.receive(), None);
        let store = Store::open(&bridge.store).unwrap();
        assert!(eventually(|| store.log_lines(10).unwrap().iter().any(
            |l| l.event == "disconnected" && l.reason.as_deref() == Some(SILENT)
        )));
    }

    /// A stand-in plugin at `socket` that answers the bridge's hello, then
    /// does `then` with the connection; it takes up to two connections.
    fn plugin_that(
        socket: &Path,
        then: impl Fn(BufReader<UnixStream>, UnixStream) + Send + Sync + 'static,
    ) {
        let listener = UnixListener::bind(socket).unwrap();
        std::thread::spawn(move || {
            for stream in listener.incoming().take(2) {
                let stream = stream.unwrap();
                let mut out = stream.try_clone().unwrap();
                let mut lines = BufReader::new(stream);
                let mut line = Vec::new();
                lines.read_until(b'\n', &mut line).unwrap();
                let id = MessageId::new(new_id().unwrap()).unwrap();
                let hello = FromPlugin::Hello {
                    runtime: "hermes".into(),
                    agent: "main".into(),
                    capabilities: vec![],
                };
                out.write_all(&encode_line(&Envelope::new(id, hello)))
                    .unwrap();
                then(lines, out);
            }
        });
    }

    #[test]
    fn a_plugin_that_never_reads_holds_no_other_device() {
        let folder = tempfile::tempdir().unwrap();
        let bridge = bridge(folder.path());
        // An agent that says hello, then reads nothing more
        plugin_that(&bridge.socket, |lines, out| {
            std::thread::sleep(Duration::from_secs(30));
            drop((lines, out));
        });
        let phone = paired(&bridge, "n-pixel");
        let (mut writing, _) = connect(&bridge, &phone);
        start_conversation(&mut writing);
        // Larger than the socket's buffers: the write waits for the plugin
        say(&mut writing, "m-1", &"a".repeat(40_000));
        std::thread::sleep(Duration::from_millis(500));
        let (mut other, _) = connect(&bridge, &phone);
        let started = std::time::Instant::now();
        other.send("a-1", FromDevice::Agents);
        while !matches!(other.receive(), Some(ToDevice::AgentsList { .. })) {}
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "{:?}",
            started.elapsed()
        );
    }

    #[test]
    fn typing_reaches_a_device_only_for_the_agents_own_conversations() {
        let folder = tempfile::tempdir().unwrap();
        let bridge = bridge(folder.path());
        let store = Store::open(&bridge.store).unwrap();
        // The person's conversation with another agent
        store
            .conversation("c-other", "lab", "other", PERSON)
            .unwrap();
        // On the person's message, lab/main says it types in both
        plugin_that(&bridge.socket, |mut lines, mut out| {
            let mut line = Vec::new();
            while lines.read_until(b'\n', &mut line).unwrap_or(0) > 0 {
                let message = decode_from_bridge(&line).unwrap();
                line.clear();
                if let FromBridge::MessageIn { .. } = message.body {
                    for conversation in ["c-other", "c-1"] {
                        let id = MessageId::new(new_id().unwrap()).unwrap();
                        let typing = FromPlugin::Typing {
                            conversation: ConversationId::new(conversation).unwrap(),
                            on: true,
                        };
                        out.write_all(&encode_line(&Envelope::new(id, typing)))
                            .unwrap();
                    }
                }
            }
        });
        let phone = paired(&bridge, "n-pixel");
        let (mut device, _) = connect(&bridge, &phone);
        start_conversation(&mut device);
        say(&mut device, "m-1", "hello");
        let typing = loop {
            match device.receive() {
                Some(ToDevice::Typing { conversation, .. }) => break conversation,
                Some(_) => {}
                None => panic!("closed"),
            }
        };
        assert_eq!(typing.as_str(), "c-1");
    }

    #[test]
    fn a_device_that_pings_while_the_person_decides_stays_connected() {
        let folder = tempfile::tempdir().unwrap();
        // The person answers later than a session may stay silent
        let bridge = bridge_with(folder.path(), Duration::from_millis(1500));
        let store = Store::open(&bridge.store).unwrap();
        store.add_pairing(b"code-1", now() + 300).unwrap();
        let path = bridge.store.clone();
        let terminal = std::thread::spawn(move || {
            let store = Store::open(&path).unwrap();
            while store.pairing_request(b"code-1").unwrap().is_none() {
                std::thread::sleep(Duration::from_millis(50));
            }
            std::thread::sleep(Duration::from_secs(3));
            store.decide_pairing(b"code-1", "accept").unwrap();
        });
        let noise = generate_keypair().unwrap();
        let signing = SigningKey::from_slice(&[9u8; 32]).unwrap();
        let mut device = handshake(&bridge, &noise.private, PERSON).unwrap();
        let proof = enclos_protocol::pairing::proof(b"code-1", device.session.handshake_hash());
        device.send(
            "pair-1",
            FromDevice::PairRequest {
                name: "Pixel".to_owned(),
                device_key: encode(signing.verifying_key().to_sec1_point(false).as_ref()),
                proof: encode(&proof),
                sig: {
                    let signature: Signature =
                        signing.sign(&Signed::Pair.message(device.session.handshake_hash()));
                    encode(signature.to_der().as_bytes())
                },
                push: None,
            },
        );
        // Pings, as the app does, until the answer comes
        let stream = device.socket.get_ref().try_clone().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        let answer = loop {
            device
                .socket
                .send(Message::Ping(Vec::new().into()))
                .unwrap();
            match device.socket.read() {
                Ok(Message::Binary(bytes)) => {
                    let plain = device.session.decrypt(&bytes).unwrap();
                    break decode_to_device(&plain).unwrap().body;
                }
                Ok(Message::Close(_)) => panic!("closed"),
                Ok(_) => {}
                Err(tungstenite::Error::Io(e))
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) => {}
                Err(e) => panic!("{e}"),
            }
        };
        terminal.join().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        assert!(
            matches!(answer, ToDevice::PairAccepted { .. }),
            "{answer:?}"
        );
        assert!(matches!(
            device.receive(),
            Some(ToDevice::Authenticated { .. })
        ));
        // Its session goes on
        device.send("a-1", FromDevice::Agents);
        loop {
            match device.receive() {
                Some(ToDevice::AgentsList { .. }) => break,
                Some(_) => {}
                None => panic!("the new device's session ended"),
            }
        }
    }

    #[test]
    fn a_message_sent_twice_reaches_the_agent_once() {
        let folder = tempfile::tempdir().unwrap();
        let bridge = bridge(folder.path());
        let got = plugin(&bridge.socket);
        let phone = paired(&bridge, "n-pixel");
        let (mut device, first) = connect(&bridge, &phone);
        assert!(matches!(first, Some(ToDevice::Authenticated { .. })));
        start_conversation(&mut device);
        // The device did not hear back, and sends the same message again
        say(&mut device, "m-1", "hi");
        say(&mut device, "m-1", "hi");
        say(&mut device, "m-2", "and then");
        assert!(eventually(|| got.lock().unwrap().len() >= 2));
        std::thread::sleep(Duration::from_millis(300));
        let got = got.lock().unwrap().clone();
        assert_eq!(
            got.iter().map(|(_, t)| t.as_str()).collect::<Vec<_>>(),
            ["hi", "and then"]
        );
        // The echoes: one per message
        let echoes: Vec<_> = (0..2).map(|_| device.receive().unwrap()).collect();
        assert!(
            matches!(&echoes[..], [ToDevice::Message(a), ToDevice::Message(b)] if a.text == "hi" && b.text == "and then"),
            "{echoes:?}"
        );
        let store = Store::open(&bridge.store).unwrap();
        assert_eq!(store.since(PERSON, 0).unwrap().len(), 2);
        assert!(eventually(|| store
            .pending("lab", "main")
            .unwrap()
            .is_empty()));
    }

    #[test]
    fn a_long_answer_reaches_the_device_in_messages_that_fit() {
        let folder = tempfile::tempdir().unwrap();
        let bridge = bridge(folder.path());
        let _got = plugin(&bridge.socket);
        let phone = paired(&bridge, "n-pixel");
        let (mut device, _) = connect(&bridge, &phone);
        start_conversation(&mut device);
        say(&mut device, "m-1", "long");
        let mut text = String::new();
        let mut seqs = Vec::new();
        while text.chars().count() < 150_000 {
            match device.receive().unwrap() {
                ToDevice::Message(m) if m.from == "agent" => {
                    seqs.push(m.seq);
                    text.push_str(&m.text);
                }
                _ => {}
            }
        }
        assert_eq!(text, "é".repeat(150_000));
        assert!(seqs.len() > 1);
        assert!(seqs.windows(2).all(|w| w[0] < w[1]), "{seqs:?}");
        // As stored: a sync gives the same pieces
        let stored = Store::open(&bridge.store)
            .unwrap()
            .since(PERSON, 0)
            .unwrap();
        assert_eq!(stored.len(), 1 + seqs.len());
    }

    #[test]
    fn a_message_waits_for_its_agent() {
        let folder = tempfile::tempdir().unwrap();
        let bridge = bridge(folder.path());
        let phone = paired(&bridge, "n-pixel");
        let (mut device, _) = connect(&bridge, &phone);
        start_conversation(&mut device);
        // No plugin listens: the sandbox is stopped
        say(&mut device, "m-1", "are you there?");
        let echo = device.receive().unwrap();
        assert!(matches!(echo, ToDevice::Message(ref m) if m.text == "are you there?"));
        let Some(ToDevice::Error(error)) = device.receive() else {
            panic!("no error");
        };
        assert_eq!(error.code, ErrorCode::AgentUnavailable);
        assert_eq!(error.of.unwrap().as_str(), "m-1");
        // The agent is back: it gets the message, once
        let got = plugin(&bridge.socket);
        assert!(eventually(|| !got.lock().unwrap().is_empty()));
        let store = Store::open(&bridge.store).unwrap();
        assert!(eventually(|| store
            .pending("lab", "main")
            .unwrap()
            .is_empty()));
        std::thread::sleep(Duration::from_millis(300));
        let got = got.lock().unwrap().clone();
        assert_eq!(got.len(), 1, "{got:?}");
        assert_eq!(got[0].1, "are you there?");
    }

    #[test]
    fn an_unpaired_device_is_cut_off_at_once() {
        let folder = tempfile::tempdir().unwrap();
        let bridge = bridge(folder.path());
        let got = plugin(&bridge.socket);
        let phone = paired(&bridge, "n-pixel");
        let (mut device, _) = connect(&bridge, &phone);
        start_conversation(&mut device);
        let store = Store::open(&bridge.store).unwrap();
        assert!(store.remove_device(&phone.id).unwrap());
        // The connection ends without another word from the device
        assert_eq!(device.receive(), None);
        // What it sends after is not the agent's
        let _ = device.socket.send(Message::Binary(vec![0; 32].into()));
        std::thread::sleep(Duration::from_millis(300));
        assert!(got.lock().unwrap().is_empty());
        let log = store.log_lines(10).unwrap();
        assert!(
            log.iter()
                .any(|l| l.event == "disconnected" && l.reason.as_deref() == Some(UNPAIRED)),
            "{log:?}"
        );
        // And it cannot come back
        let (_, first) = connect(&bridge, &phone);
        assert_eq!(first, None);
    }

    #[test]
    fn a_device_forgotten_on_one_connection_loses_its_others() {
        let folder = tempfile::tempdir().unwrap();
        let bridge = bridge(folder.path());
        let phone = paired(&bridge, "n-pixel");
        // A connection left half open, and the one the device reconnected on
        let (mut old, _) = connect(&bridge, &phone);
        let (mut new, _) = connect(&bridge, &phone);
        new.send("forget-1", FromDevice::DeviceForget);
        assert!(matches!(new.receive(), Some(ToDevice::Ack { .. })));
        assert_eq!(new.receive(), None);
        // The other one ends too, with nothing more from the bridge
        assert_eq!(old.receive(), None);
        let (_, first) = connect(&bridge, &phone);
        assert_eq!(first, None);
    }

    #[test]
    fn a_device_from_another_node_is_refused() {
        let folder = tempfile::tempdir().unwrap();
        let bridge = bridge(folder.path());
        let phone = paired(&bridge, "n-pixel");
        // Its keys, used from another node of the same person
        *bridge.node.lock().unwrap() = "n-laptop".to_owned();
        let (_, first) = connect(&bridge, &phone);
        assert_eq!(first, None);
        let log = Store::open(&bridge.store).unwrap().log_lines(10).unwrap();
        let refused = log.iter().find(|l| l.event == "refused").unwrap();
        assert!(
            refused.reason.as_deref().unwrap().contains("another node"),
            "{refused:?}"
        );
        // From its own node, it gets in
        *bridge.node.lock().unwrap() = "n-pixel".to_owned();
        let (_, first) = connect(&bridge, &phone);
        assert!(matches!(first, Some(ToDevice::Authenticated { .. })));
    }

    fn step(conversation: &str, call: &str, name: &str, label: Option<&str>) -> ToolStep {
        ToolStep {
            conversation: ConversationId::new(conversation).unwrap(),
            call: call.to_owned(),
            name: name.to_owned(),
            label: label.map(str::to_owned),
            phase: ToolPhase::Start,
            ok: None,
            duration_ms: None,
        }
    }

    #[test]
    fn a_tool_step_goes_only_to_the_owner_of_the_agents_own_conversation() {
        let folder = tempfile::tempdir().unwrap();
        let store = Store::open(&folder.path().join("app.db")).unwrap();
        store
            .conversation("c-a", "lab", "a", "alice@example.com")
            .unwrap();
        store
            .conversation("c-b", "lab", "b", "bob@example.com")
            .unwrap();
        let (owner, _) = tool_step(&store, "lab/a", step("c-a", "1", "terminal", None)).unwrap();
        assert_eq!(owner, "alice@example.com");
        // Agent lab/a cannot show a step in a conversation of lab/b, nor in
        // one the bridge does not know.
        assert_eq!(
            tool_step(&store, "lab/a", step("c-b", "1", "terminal", None)),
            None
        );
        assert_eq!(
            tool_step(&store, "lab/a", step("c-x", "1", "terminal", None)),
            None
        );
    }

    #[test]
    fn a_tool_step_is_cut_to_fit_and_shows_its_hidden_characters() {
        let folder = tempfile::tempdir().unwrap();
        let store = Store::open(&folder.path().join("app.db")).unwrap();
        store
            .conversation("c-a", "lab", "a", "alice@example.com")
            .unwrap();
        // Each field far above one Noise message.
        let huge = "x".repeat(70_000);
        let (_, cut) = tool_step(&store, "lab/a", step("c-a", &huge, &huge, Some(&huge))).unwrap();
        assert_eq!(cut.call.chars().count(), MAX_TOOL_CALL_CHARS);
        assert_eq!(cut.name.chars().count(), MAX_TOOL_NAME_CHARS);
        assert_eq!(
            cut.label.as_deref().map(|l| l.chars().count()),
            Some(MAX_TOOL_LABEL_CHARS)
        );
        let sealed = encode_line(&Envelope::new(
            MessageId::new("m-1").unwrap(),
            ToDevice::Tool(cut),
        ));
        assert!(sealed.len() < 2_000);
        // What the person reads is what runs: a reversed tail is written out,
        // and a label stays on one line.
        let (_, shown) = tool_step(
            &store,
            "lab/a",
            step(
                "c-a",
                "1",
                "term\u{200B}inal",
                Some("rm -rf ~/\u{202E}txt.\nls"),
            ),
        )
        .unwrap();
        assert_eq!(shown.name, "term⟨U+200B⟩inal");
        assert_eq!(shown.label.as_deref(), Some("rm -rf ~/⟨U+202E⟩txt. ls"));
    }

    #[test]
    fn a_device_that_goes_away_is_a_disconnection_not_an_error() {
        use std::io::{Error, ErrorKind};
        use tungstenite::error::ProtocolError::ResetWithoutClosingHandshake;
        let gone = [
            tungstenite::Error::Protocol(ResetWithoutClosingHandshake),
            tungstenite::Error::ConnectionClosed,
            tungstenite::Error::Io(Error::from(ErrorKind::ConnectionReset)),
            tungstenite::Error::Io(Error::from(ErrorKind::BrokenPipe)),
            tungstenite::Error::Io(Error::from(ErrorKind::UnexpectedEof)),
        ];
        for e in gone {
            assert_eq!(ended(e), GONE);
        }
        let other = ended(tungstenite::Error::Io(Error::from(
            ErrorKind::PermissionDenied,
        )));
        assert_ne!(other, GONE);
        assert_ne!(other, CLOSED);
    }
}
