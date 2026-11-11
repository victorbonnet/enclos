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

use std::collections::HashMap;
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use enclos_protocol::device::{
    AgentInfo, ConversationInfo, ConversationMessage, FromDevice, ToDevice, decode_from_device,
};
use enclos_protocol::noise::{Responder, Session};
use enclos_protocol::pairing::{check_proof, check_signature, decode, encode};
use enclos_protocol::plugin::{Capability, FromBridge, FromPlugin, OutKind};
use enclos_protocol::{ConversationId, Envelope, MessageId, Person, encode_line};
use tungstenite::handshake::server::{Request, Response};
use tungstenite::{Message, WebSocket};

use super::ids::{new_id, random_bytes};
use super::plugin::{PluginWriter, connect};
use super::store::{
    BY_AGENT, BY_PERSON, Conversation, Device, From, PairingRequest, Store, conversation_title, now,
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
    /// Open plugin connections, by agent.
    plugins: Mutex<HashMap<String, (PluginWriter, Vec<Capability>)>>,
    /// Connected devices: who they speak for, and where to send.
    devices: Mutex<HashMap<String, (String, Sender<ToDevice>)>>,
}

impl Hub {
    fn store(&self) -> Result<Store, String> {
        Store::open(&self.store_path).map_err(|e| format!("cannot open the bridge's database: {e}"))
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

    /// Sends conversation `id`, with its name, to every connected device of
    /// `person`: after its name changed.
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
            connect(&endpoint.socket, &endpoint.token).map_err(|e| e.to_string())?;
        let mut acks = writer.try_clone().map_err(|e| e.to_string())?;
        plugins.insert(agent.to_owned(), (writer, hello.capabilities));
        let hub = Arc::clone(self);
        let agent = agent.to_owned();
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
                        ..
                    } => {
                        let kind = match kind {
                            OutKind::Reply => "reply",
                            OutKind::Notify => "notify",
                        };
                        let stored = store.add(
                            message.id.as_str(),
                            conversation.as_str(),
                            &From::Agent,
                            &text,
                            kind,
                        );
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
    let hub = Arc::new(Hub {
        transport,
        store_path,
        bridge_private,
        agents,
        plugins: Mutex::new(HashMap::new()),
        devices: Mutex::new(HashMap::new()),
    });
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let hub = Arc::clone(&hub);
        std::thread::spawn(move || {
            match connection(&hub, stream) {
                // The device hung up, or went away (a phone that locks, sleeps
                // or changes network rarely says goodbye): how connections
                // end, not an error. `enclos app log` has who, when and how.
                Err(e) if e == CLOSED || e == GONE => {}
                Err(e) => eprintln!("enclos app: a connection ended: {e}"),
                Ok(()) => {}
            }
        });
    }
    Ok(())
}

/// The device closed the connection.
const CLOSED: &str = "closed";
/// The device went away without closing it: reset, or just gone.
const GONE: &str = "went away without closing the connection";

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
        match self.socket.read() {
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

fn binary(socket: &mut WebSocket<TcpStream>) -> Result<Vec<u8>, String> {
    loop {
        match socket.read().map_err(ended)? {
            Message::Binary(bytes) => return Ok(bytes.to_vec()),
            Message::Close(_) => return Err(CLOSED.to_owned()),
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
    socket.send(Message::Binary(answer.into())).map_err(ended)?;
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
            Ok(_) => false,
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
    };
    store.add_device(&device).map_err(|e| e.to_string())?;
    // A device that does not get its answer has no id to come back with:
    // it is not kept, and the terminal is told.
    if let Err(e) = link.send(ToDevice::PairAccepted {
        device: device.id.clone(),
        push_key: encode(&device.push_key),
    }) {
        let _ = store.remove_device(&device.id);
        let _ = store.settle_pairing(&code, "gone");
        let _ = store.log(
            None,
            Some(person),
            "refused",
            Some("the device left before the answer"),
        );
        return Err(e);
    }
    let _ = store.settle_pairing(&code, "paired");
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
                if !hub.agents.iter().any(|a| a.name == agent) {
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
                    }))?;
                }
                link.send(ToDevice::Synced { seq: last })?;
            }
            FromDevice::PushTokenUpdate(push) => {
                store
                    .set_push_token(&device.id, &push.token)
                    .map_err(|e| e.to_string())?;
            }
            _ => {}
        }
    }
}

/// A conversation for a device: `None` for an id the protocol refuses.
fn conversation_info(c: Conversation) -> Option<ConversationInfo> {
    Some(ConversationInfo {
        conversation: ConversationId::new(c.id).ok()?,
        agent: format!("{}/{}", c.sandbox, c.agent),
        title: c.title,
        titled_by: c.titled_by,
    })
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
        let mut plugins = hub.plugins.lock().expect("not poisoned");
        if let Some((writer, _)) = plugins.get_mut(&name) {
            let _ = writer.send(FromBridge::Rename {
                conversation: conversation.clone(),
                title: conversation_title(title),
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
            }),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
