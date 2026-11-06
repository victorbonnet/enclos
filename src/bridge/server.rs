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

use std::collections::HashMap;
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use enclos_protocol::device::{
    ATTACHMENT_CHUNK, AgentInfo, Attachment, ConversationInfo, ConversationMessage, FromDevice,
    ToDevice, decode_from_device,
};
use enclos_protocol::noise::{Responder, Session};
use enclos_protocol::pairing::{check_proof, check_signature, decode, encode};
use enclos_protocol::plugin::{Capability, FromBridge, FromPlugin, OutAttachment, OutKind};
use enclos_protocol::{ConversationId, Envelope, MessageId, Person, encode_line};
use tungstenite::handshake::server::{Request, Response};
use tungstenite::{Message, WebSocket};

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
    bridge_private: Vec<u8>,
    agents: Vec<AgentEndpoint>,
    /// The person the host belongs to, on the transport: whose the agents'
    /// Home conversations are. Unknown, the first person who connects.
    host: Option<String>,
    /// Open plugin connections, by agent.
    plugins: Mutex<HashMap<String, (PluginWriter, Vec<Capability>)>>,
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

    /// Sends conversation `id`, with its name and how far it was read, to
    /// every connected device of `person`: after either changed.
    fn deliver_conversation(&self, store: &Store, person: &str, id: &str) {
        if let Ok(Some(c)) = store.conversation_info(id)
            && let Some(info) = conversation_info(c)
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
        let (hello, mut reader, writer) =
            connect(&endpoint.socket, &endpoint.token, &home_id(agent))
                .map_err(|e| e.to_string())?;
        let mut acks = writer.try_clone().map_err(|e| e.to_string())?;
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
                    FromPlugin::MessageOut {
                        conversation,
                        text,
                        kind,
                        attachments,
                        ..
                    } => {
                        let kind = match kind {
                            OutKind::Reply => "reply",
                            OutKind::Notify => "notify",
                            OutKind::Status => "status",
                        };
                        // A conversation the bridge does not know, or another
                        // agent's: the runtime's home channel as it was, or a
                        // chat gone. It goes to this agent's Home, not nowhere.
                        let own = matches!(
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
                        let stored = store.add(
                            message.id.as_str(),
                            conversation.as_str(),
                            &From::Agent,
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
                                    conversation,
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
                    // A tool the agent runs, for one of its own agent's
                    // conversations: passed on live, not kept.
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
    bridge_private: Vec<u8>,
    agents: Vec<AgentEndpoint>,
) -> std::io::Result<()> {
    let listener = TcpListener::bind(("127.0.0.1", port))?;
    let host = transport.host_person();
    let hub = Arc::new(Hub {
        transport,
        store_path,
        bridge_private,
        agents,
        host,
        plugins: Mutex::new(HashMap::new()),
        devices: Mutex::new(HashMap::new()),
    });
    // Each agent's Home, the host's person's, before anything is sent to it.
    if let (Some(host), Ok(store)) = (hub.host.as_deref(), hub.store()) {
        for agent in &hub.agents {
            let _ = store.ensure_home(&agent.name, host);
        }
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
            FromDevice::Agents => {
                let plugins = hub.plugins.lock().expect("not poisoned");
                let agents = hub
                    .agents
                    .iter()
                    .map(|a| AgentInfo {
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
                link.send(ToDevice::AgentsList { agents })?;
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
            FromDevice::Sync { since } => {
                // Every conversation first, named or empty, then the messages.
                for c in store.conversations(person).map_err(|e| e.to_string())? {
                    if let Some(info) = conversation_info(c) {
                        link.send(ToDevice::Conversation(info))?;
                    }
                }
                let mut last = since;
                for m in store.since(person, since).map_err(|e| e.to_string())? {
                    let agent = store
                        .conversation_of(&m.conversation)
                        .map_err(|e| e.to_string())?
                        .map(|(s, a, _)| format!("{s}/{a}"))
                        .unwrap_or_default();
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
                            From::Agent => "agent".to_owned(),
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
fn conversation_info(c: Conversation) -> Option<ConversationInfo> {
    Some(ConversationInfo {
        home: is_home(&c.id),
        conversation: ConversationId::new(c.id).ok()?,
        agent: format!("{}/{}", c.sandbox, c.agent),
        title: c.title,
        titled_by: c.titled_by,
        read: c.read,
    })
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
