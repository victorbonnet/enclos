//! `enclos app`: the mobile app's side of enclos (ADR 0042, proposed). For
//! now `app chat`, which talks to an agent through its app channel from the
//! terminal, the way the bridge will for a phone.

use std::io::BufRead;

use clap::{Args, Subcommand};
use jiff::Timestamp;
use serde_json::{Value, json};

use super::output;
use super::runtime::ChannelTarget;
use enclos::bridge::ids::{new_id, random_bytes};
use enclos::bridge::keys::{approval_key, bridge_keypair};
use enclos::bridge::plugin::{PluginError, PluginReader, PluginWriter, connect};
use enclos::bridge::provisioning::Host;
use enclos::bridge::server::{self, AgentEndpoint};
use enclos::bridge::store::now;
use enclos::bridge::store::{From, LogLine, Store};
use enclos::bridge::transport::Transport;
use enclos::engine::{Engine, printable_line};
use enclos::error::{Error, Result, exit};
use enclos::model::audit::Actor;
use enclos_protocol::device::ConversationMessage;
use enclos_protocol::pairing::PairLink;
use enclos_protocol::plugin::{FromBridge, FromPlugin, OutKind};
use enclos_protocol::{ConversationId, MessageId, Person};
use qrcode::QrCode;
use qrcode::render::unicode::Dense1x2;

#[derive(Args)]
pub struct AppArgs {
    #[command(subcommand)]
    verb: AppVerb,
}

impl AppArgs {
    /// Whether this is `app serve`, the long-running bridge, whose writes
    /// no person waits on.
    pub fn is_service(&self) -> bool {
        matches!(self.verb, AppVerb::Serve { .. })
    }
}

#[derive(Subcommand)]
enum AppVerb {
    /// Talk to an agent through its app channel, from this terminal: each
    /// line typed is a message, and what the agent says is printed,
    /// including what it sends on its own, such as a cron job's output.
    Chat {
        /// The agent: `home` for the sandbox's built-in agent, or
        /// `home/main`.
        target: ChannelTarget,
        /// The conversation to go on with; a new one when left out.
        #[arg(long)]
        conversation: Option<String>,
    },
    /// Run the bridge in this terminal: it serves paired devices on the
    /// host's loopback, for its transport to put on your network.
    Serve {
        /// The loopback port to listen on.
        #[arg(long, default_value_t = 47100)]
        port: u16,
        /// How devices reach the bridge, and who it says each caller is;
        /// `tailscale`, through `tailscale serve`, is the only one for now.
        #[arg(long, default_value = "tailscale")]
        transport: Transport,
    },
    /// Pair a device: prints a QR code for the enclos app to scan, then
    /// asks you to confirm the device that used it.
    Pair {
        /// The bridge's address on your network; asked of the transport
        /// (`tailscale status`) when left out.
        #[arg(long)]
        url: Option<String>,
        /// How devices reach the bridge: as `app serve --transport`.
        #[arg(long, default_value = "tailscale")]
        transport: Transport,
    },
    /// List the paired devices.
    Devices,
    /// Remove a paired device: it can no longer connect.
    Unpair { device: String },
    /// Show the host's person, whose each agent's Home is: the person of
    /// the first device paired. With a person, make it them instead; they
    /// must have a paired device, and get every Home with what it holds.
    Host { person: Option<String> },
    /// Who can reach the agents, from which devices, and when each was
    /// last seen.
    Status,
    /// The bridge's log: connections, disconnections and refusals.
    Log {
        /// How many lines, the newest last.
        #[arg(short = 'n', default_value_t = 50)]
        lines: i64,
    },
}

pub fn run(engine: &Engine, by: &Actor, args: AppArgs) -> Result<u8> {
    match args.verb {
        AppVerb::Chat {
            target,
            conversation,
        } => chat(engine, by, target, conversation),
        AppVerb::Serve { port, transport } => serve(engine, port, transport),
        AppVerb::Pair { url, transport } => pair(engine, by, url, transport),
        AppVerb::Devices | AppVerb::Status => devices(engine),
        AppVerb::Unpair { device } => unpair(engine, by, &device),
        AppVerb::Host { person } => host(engine, by, person),
        AppVerb::Log { lines } => log(engine, lines),
    }
}

fn failed(what: String) -> Error {
    Error::Session { what }
}

fn open_store(engine: &Engine) -> Result<Store> {
    Store::open(&engine.app_store_path())
        .map_err(|e| failed(format!("cannot open the bridge's database: {e}")))
}

fn serve(engine: &Engine, port: u16, transport: Transport) -> Result<u8> {
    let key = bridge_keypair(&engine.app_key_path())
        .map_err(|e| failed(format!("cannot read or make the bridge's key: {e}")))?;
    let approvals = approval_key(&engine.app_approval_key_path()).map_err(|e| {
        failed(format!(
            "cannot read or make the bridge's key for runtime approvals: {e}"
        ))
    })?;
    let mut agents = Vec::new();
    for (sandbox, agent, runtime) in engine.app_agents()? {
        match engine.app_endpoint(&sandbox, &agent) {
            Ok(endpoint) => agents.push(AgentEndpoint {
                name: format!("{sandbox}/{agent}"),
                runtime,
                socket: endpoint.socket,
                token: endpoint.token.expose().to_owned(),
            }),
            Err(e) => eprintln!("enclos app: {sandbox}/{agent} left out: {e}"),
        }
    }
    eprintln!(
        "The bridge serves {} agent(s) on 127.0.0.1:{port}, through {transport}. Put it on your network with:\n  {}\nthen pair a device with `enclos app pair`. Ctrl-C to stop.",
        agents.len(),
        transport.expose_hint(port)
    );
    for agent in &agents {
        eprintln!("  {}", agent.name);
    }
    let executable = std::env::current_exe().map_err(|e| {
        failed(format!(
            "cannot locate enclos for runtime installation: {e}"
        ))
    })?;
    server::serve(
        transport,
        port,
        engine.app_store_path(),
        engine.app_layout(),
        key.private.to_vec(),
        approvals,
        agents,
        Host::new(engine.app_layout(), executable),
    )
    .map_err(|e| failed(format!("the bridge cannot listen on 127.0.0.1:{port}: {e}")))?;
    Ok(exit::OK)
}

/// The QR code drawn black on bright white when it goes to a terminal: a
/// dark theme would otherwise draw its modules light on dark, which most
/// scanners do not read.
fn terminal_qr(drawn: &str) -> String {
    use std::io::IsTerminal as _;
    if !std::io::stdout().is_terminal() {
        return drawn.to_owned();
    }
    drawn
        .lines()
        .map(|line| format!("\x1b[30;107m{line}\x1b[0m"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn pair(engine: &Engine, by: &Actor, url: Option<String>, transport: Transport) -> Result<u8> {
    let url = url.or_else(|| transport.address()).ok_or_else(|| {
        failed(format!(
            "cannot read the bridge's address from {transport}: give it with --url {}",
            transport.address_form()
        ))
    })?;
    let key = bridge_keypair(&engine.app_key_path())
        .map_err(|e| failed(format!("cannot read or make the bridge's key: {e}")))?;
    let store = open_store(engine)?;
    let host_before = store.host_person().map_err(|e| failed(e.to_string()))?;
    let code = random_bytes(16).map_err(|e| failed(format!("cannot make a code: {e}")))?;
    let expires = now() + 300;
    store
        .add_pairing(&code, expires)
        .map_err(|e| failed(format!("cannot record the code: {e}")))?;
    let host = url
        .trim_start_matches("https://")
        .split('.')
        .next()
        .unwrap_or("host")
        .to_owned();
    let link = PairLink {
        host,
        url: url.clone(),
        key: key.public,
        code: code.clone(),
        expires: expires as u64,
    }
    .to_link()
    .map_err(|e| failed(e.to_string()))?;
    // An https link opens anywhere (a chat, a note); its page hands the
    // enclos:// link to the app. The QR code keeps the enclos:// link, which
    // the app's scanner reads.
    let page = enclos::bridge::page::link_to_page(&url, &link)
        .ok_or_else(|| failed("cannot make the pairing page's link".to_owned()))?;
    let qr = QrCode::new(link.as_bytes())
        .map_err(|e| failed(format!("cannot draw the QR code: {e}")))?;
    println!(
        "{}",
        terminal_qr(&qr.render::<Dense1x2>().quiet_zone(true).build())
    );
    println!("Scan it with the enclos app, or open this link on the phone:\n  {page}");
    println!("or enter this one in the app: {link}");
    println!("It works once, for 5 minutes, while `enclos app serve` runs.");
    let request = loop {
        if let Some(request) = store
            .pairing_request(&code)
            .map_err(|e| failed(e.to_string()))?
        {
            break request;
        }
        if now() > expires {
            return Err(failed(
                "the code expired: run `enclos app pair` again".to_owned(),
            ));
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    };
    if host_before.is_none() {
        println!(
            "It is the first device: {} becomes the host's person, whose each agent's Home is.",
            shown(&request.person)
        );
    }
    print!(
        "{} ({transport} login: {}, node: {}) wants to pair. Accept? [y/N] ",
        shown(&request.name),
        shown(&request.person),
        shown(&request.node)
    );
    use std::io::Write as _;
    let _ = std::io::stdout().flush();
    let mut answer = String::new();
    std::io::stdin()
        .read_line(&mut answer)
        .map_err(|e| failed(e.to_string()))?;
    let accept = matches!(answer.trim(), "y" | "Y" | "yes");
    let left =
        || failed("the device left before it was paired: run `enclos app pair` again".to_owned());
    if !accept {
        if !store
            .decide_pairing(&code, "decline")
            .map_err(|e| failed(e.to_string()))?
        {
            return Err(left());
        }
        println!("Declined: the device is not paired.");
        return Ok(exit::OK);
    }
    // The bridge stores the device only once it reads `accept`, which is
    // written inside the audit entry
    let target = format!(
        "{} ({}, node {})",
        request.name, request.person, request.node
    );
    let device = engine.app_access(
        by,
        "app pair",
        target,
        |device: &String| format!("paired as device {device}"),
        || {
            if !store
                .decide_pairing(&code, "accept")
                .map_err(|e| failed(e.to_string()))?
            {
                // The bridge had its word first: the device left.
                return Err(left());
            }
            // Paired once the device has its answer, which the bridge says.
            for _ in 0..20 {
                match store
                    .pairing_decision(&code)
                    .map_err(|e| failed(e.to_string()))?
                    .as_deref()
                {
                    Some("paired") => {
                        // The bridge records the device it made
                        return store
                            .paired_device(&code)
                            .map_err(|e| failed(e.to_string()))?
                            .ok_or_else(|| {
                                failed(
                                    "the bridge paired a device but did not say which".to_owned(),
                                )
                            });
                    }
                    Some("gone") => return Err(left()),
                    _ => std::thread::sleep(std::time::Duration::from_millis(500)),
                }
            }
            Err(failed(
                "accepted, but the bridge did not answer the device: is `enclos app serve` running?"
                    .to_owned(),
            ))
        },
    )?;
    println!("Paired: device {device}.");
    // The bridge names the first device's person before it says `paired`.
    if host_before.is_none()
        && let Ok(Some(host)) = store.host_person()
    {
        println!(
            "{} is the host's person: each agent's Home is theirs (`enclos app host` changes it).",
            shown(&host)
        );
    }
    Ok(exit::OK)
}

fn host(engine: &Engine, by: &Actor, person: Option<String>) -> Result<u8> {
    let store = open_store(engine)?;
    let Some(person) = person else {
        let host = store.host_person().map_err(|e| failed(e.to_string()))?;
        match (output::json(), host) {
            (true, host) => output::emit(&json!({"host_person": host})),
            (false, Some(host)) => {
                println!("{}: each agent's Home is theirs.", shown(&host));
            }
            (false, None) => println!(
                "Nobody yet: the first device paired with `enclos app pair` names the host's person."
            ),
        }
        return Ok(exit::OK);
    };
    let devices = store.devices().map_err(|e| failed(e.to_string()))?;
    if !devices.iter().any(|d| d.person == person) {
        return Err(failed(format!(
            "{} has no paired device: `enclos app devices` lists who has",
            shown(&person)
        )));
    }
    engine.app_access(
        by,
        "app host",
        person.clone(),
        |_| "the host's person: each agent's Home is theirs".to_owned(),
        || store.set_host(&person).map_err(|e| failed(e.to_string())),
    )?;
    match output::json() {
        true => output::emit(&json!({"host_person": person})),
        false => println!(
            "{} is the host's person: each agent's Home is theirs, with what it holds.",
            shown(&person)
        ),
    }
    Ok(exit::OK)
}

/// Text a device or a caller chose, as the terminal shows it: controls
/// escaped, so it cannot move the cursor or redraw a line, then what
/// `output::for_terminal` escapes (invisible and bidirectional marks). The
/// bridge keeps names plain already; this covers rows stored before it did.
fn shown(text: &str) -> String {
    let escaped: String = text
        .chars()
        .map(|c| match c {
            '\u{0}'..='\u{1f}' => format!("\\u{:04x}", c as u32),
            c => c.to_string(),
        })
        .collect();
    output::for_terminal(&escaped)
}

fn when(seconds: Option<i64>) -> String {
    match seconds {
        None => "never".to_owned(),
        Some(at) => {
            let ago = (now() - at).max(0);
            match ago {
                0..60 => "just now".to_owned(),
                60..3600 => format!("{} min ago", ago / 60),
                3600..86400 => format!("{} h ago", ago / 3600),
                _ => format!("{} d ago", ago / 86400),
            }
        }
    }
}

/// A time of the bridge's database, seconds since the Unix epoch, as the
/// other documents give one.
fn instant(seconds: i64) -> Value {
    match Timestamp::from_second(seconds) {
        Ok(at) => json!(at.to_string()),
        Err(_) => json!(seconds),
    }
}

fn devices(engine: &Engine) -> Result<u8> {
    let store = open_store(engine)?;
    let devices = store.devices().map_err(|e| failed(e.to_string()))?;
    if output::json() {
        output::emit(&json!({
            "devices": devices.iter().map(|d| json!({
                "device": d.id,
                "name": d.name,
                "person": d.person,
                "paired_at": instant(d.paired),
                "seen_at": d.seen.map(instant),
            })).collect::<Vec<_>>(),
        }));
        return Ok(exit::OK);
    }
    if devices.is_empty() {
        println!("No paired device: pair one with `enclos app pair`.");
    }
    for d in devices {
        println!(
            "{}  {}  {}  paired {}, seen {}",
            d.id,
            shown(&d.name),
            shown(&d.person),
            when(Some(d.paired)),
            when(d.seen)
        );
    }
    Ok(exit::OK)
}

fn unpair(engine: &Engine, by: &Actor, device: &str) -> Result<u8> {
    let store = open_store(engine)?;
    let person = store.device(device).ok().flatten().map(|d| d.person);
    // A connected device's session ends once its row is gone: the bridge
    // looks for it before each message
    engine.app_access(
        by,
        "app unpair",
        device.to_owned(),
        |_| "removed: it can no longer connect".to_owned(),
        || match store.remove_device(device) {
            Ok(true) => Ok(()),
            Ok(false) => Err(failed(format!(
                "no paired device {device}: `enclos app devices` lists them"
            ))),
            Err(e) => Err(failed(e.to_string())),
        },
    )?;
    let _ = store.log(Some(device), None, "unpaired", None);
    match output::json() {
        true => output::emit(&json!({"device": device, "removed": true})),
        false => println!("Device {device} removed: it can no longer connect."),
    }
    // The host's person stays so with no device left (ADR 0044): their
    // Homes keep what comes, for when they pair again.
    if let Some(person) = person
        && store.host_person().ok().flatten().as_deref() == Some(person.as_str())
        && !store
            .devices()
            .unwrap_or_default()
            .iter()
            .any(|d| d.person == person)
    {
        eprintln!(
            "{} stays the host's person, with no paired device: each agent's Home keeps what comes until they pair again, or `enclos app host <person>` gives it to another.",
            shown(&person)
        );
    }
    Ok(exit::OK)
}

fn log(engine: &Engine, lines: i64) -> Result<u8> {
    let store = open_store(engine)?;
    let lines = store.log_lines(lines).map_err(|e| failed(e.to_string()))?;
    if output::json() {
        output::emit(&json!({
            "log": lines.iter().map(|l| json!({
                "at": instant(l.at),
                "event": l.event,
                "device": l.device,
                "person": l.person,
                "reason": l.reason,
            })).collect::<Vec<_>>(),
        }));
        return Ok(exit::OK);
    }
    for line in lines {
        println!("{}", log_line(&line));
    }
    Ok(exit::OK)
}

/// One line of the bridge's log for the terminal. Its fields can come from
/// a device or an agent's runtime, such as a routine's id, so each is
/// escaped: none can start another line or send the terminal an escape
/// sequence.
fn log_line(line: &LogLine) -> String {
    format!(
        "{}  {}  {}  {}{}",
        when(Some(line.at)),
        printable_line(&line.event),
        printable_line(line.device.as_deref().unwrap_or("-")),
        printable_line(line.person.as_deref().unwrap_or("-")),
        line.reason
            .as_deref()
            .map(|r| format!("  ({})", printable_line(r)))
            .unwrap_or_default()
    )
}

fn chat(
    engine: &Engine,
    by: &Actor,
    target: ChannelTarget,
    conversation: Option<String>,
) -> Result<u8> {
    let ChannelTarget { sandbox, agent } = target;
    // Hermes's built-in agent; a runtime with another would name it here.
    let agent = agent.map_or_else(|| "default".to_owned(), |a| a.to_string());
    let endpoint = engine.app_endpoint(&sandbox, &agent)?;
    let store = Store::open(&engine.app_store_path())
        .map_err(|e| failed(format!("cannot open the bridge's database: {e}")))?;
    let person = Person::new(format!("{}@{}", by.user, by.host))
        .map_err(|e| failed(format!("cannot name you as a person: {e}")))?;
    let conversation = match conversation {
        Some(c) => c,
        None => new_id().map_err(|e| failed(format!("cannot make a conversation id: {e}")))?,
    };
    let conversation = ConversationId::new(conversation)
        .map_err(|e| failed(format!("not a conversation id: {e}")))?;
    let (with_sandbox, with_agent, owner) = store
        .conversation(
            conversation.as_str(),
            sandbox.as_str(),
            &agent,
            person.as_str(),
        )
        .map_err(|e| failed(format!("cannot record the conversation: {e}")))?;
    resumable(
        conversation.as_str(),
        (&with_sandbox, &with_agent, &owner),
        (sandbox.as_str(), &agent, person.as_str()),
    )
    .map_err(failed)?;
    let plugin_error = |e: PluginError| failed(e.to_string());
    let (hello, mut reader, mut writer) = connect(
        &endpoint.socket,
        endpoint.token.expose(),
        &enclos::bridge::store::home_id(&format!("{sandbox}/{agent}")),
    )
    .map_err(plugin_error)?;
    eprintln!(
        "Talking to {sandbox}/{agent} ({}) in conversation {conversation}; Ctrl-D to stop.",
        printable_line(&hello.runtime)
    );

    // What the agent sends, printed as it comes and stored, then
    // acknowledged so its plugin drops it from its outbox.
    let store_path = engine.app_store_path();
    let mut acks = writer_ack(&mut writer)?;
    let (with, at) = (sandbox.to_string(), agent.clone());
    let printer = std::thread::spawn(move || -> std::result::Result<(), String> {
        let store = Store::open(&store_path).map_err(|e| e.to_string())?;
        let stdout = std::io::stdout();
        read_agent(
            &mut reader,
            &store,
            &mut acks,
            &mut stdout.lock(),
            &with,
            &at,
        )
    });

    for line in std::io::stdin().lock().lines() {
        let line = line.map_err(|e| failed(format!("cannot read what you type: {e}")))?;
        let text = line.trim();
        if text.is_empty() {
            continue;
        }
        // Stored first, so what the agent has is in the history.
        let id = new_id()
            .ok()
            .and_then(|id| MessageId::new(id).ok())
            .ok_or_else(|| failed("cannot make a message id".to_owned()))?;
        let whole = ConversationMessage {
            question: None,
            conversation: conversation.clone(),
            agent: format!("{sandbox}/{agent}"),
            from: person.to_string(),
            text: text.to_owned(),
            kind: "message".to_owned(),
            time: now(),
            seq: 0,
            attachments: Vec::new(),
        };
        store
            .add_pieces(
                &server::pieces(&id, &whole).map_err(failed)?,
                conversation.as_str(),
                &From::Person(person.to_string()),
                "message",
            )
            .map_err(|e| failed(format!("cannot store your message: {e}")))?;
        writer
            .send_with_id(id, typed_message(&conversation, &person, text))
            .map_err(plugin_error)?;
    }
    // End of input: close the connection itself, so the reading thread
    // sees its end and the plugin is free for the bridge.
    writer.shutdown();
    drop(writer);
    match printer.join() {
        Ok(Ok(())) => Ok(exit::OK),
        Ok(Err(e)) => Err(failed(e)),
        Err(_) => Err(failed("the reading thread stopped".to_owned())),
    }
}

/// What `person` typed in `app chat`, as the plugin gets it. Not from the
/// host's person (`host: false`): this terminal speaks on the plugin's
/// socket as any program holding the agent's token can, and the runtime's
/// approval commands typed here are answered by the plugin and never run,
/// like everyone's: a runtime approval is decided with a paired device's
/// buttons alone (ADR 0060).
fn typed_message(conversation: &ConversationId, person: &Person, text: &str) -> FromBridge {
    FromBridge::MessageIn {
        conversation: conversation.clone(),
        person: person.clone(),
        text: text.to_owned(),
        host: Some(false),
    }
}

/// Whether a conversation, as stored (`sandbox`, `agent`, owner), may go
/// on with this agent for this person. A conversation is one exchange with
/// one agent: another agent's replies would land in its history.
fn resumable(
    conversation: &str,
    stored: (&str, &str, &str),
    wanted: (&str, &str, &str),
) -> std::result::Result<(), String> {
    let (sandbox, agent, owner) = stored;
    if owner != wanted.2 {
        return Err(format!(
            "conversation {conversation} is {owner}'s, not yours"
        ));
    }
    if (sandbox, agent) != (wanted.0, wanted.1) {
        return Err(format!(
            "conversation {conversation} is with {sandbox}/{agent}: carry it on with `enclos app chat {sandbox}/{agent} --conversation {conversation}`"
        ));
    }
    Ok(())
}

/// What the agent sends, until its plugin closes the connection: each
/// message stored, printed to `out` and acknowledged, so the plugin drops
/// it from its outbox. Only messages in a conversation of this agent's
/// (`sandbox`/`agent`) are kept: one naming another agent's conversation
/// is acknowledged and dropped, with a note, since its history is not this
/// agent's to write. The text is the sandbox's, so it is printed escaped,
/// line by line; the stored text stays as sent.
fn read_agent(
    reader: &mut PluginReader,
    store: &Store,
    acks: &mut PluginWriter,
    out: &mut impl std::io::Write,
    sandbox: &str,
    agent: &str,
) -> std::result::Result<(), String> {
    while let Some(message) = reader.receive().map_err(|e| e.to_string())? {
        let FromPlugin::MessageOut {
            conversation,
            text,
            kind,
            ..
        } = &message.body
        else {
            continue;
        };
        let kind = match kind {
            OutKind::Reply => "reply",
            OutKind::Notify => "notify",
            OutKind::Status => "status",
        };
        let ours = store
            .conversation_of(conversation.as_str())
            .map_err(|e| e.to_string())?
            .is_some_and(|(s, a, _)| s == sandbox && a == agent);
        let shown = |text: &str| {
            text.split('\n')
                .map(printable_line)
                .collect::<Vec<_>>()
                .join("\n")
        };
        if !ours {
            let _ = writeln!(
                out,
                "\n[dropped: {sandbox}/{agent} sent a message to conversation {}, which is not one of its own]",
                printable_line(conversation.as_str())
            );
        } else if store
            .add_pieces(
                // In pieces a device can sync
                &server::pieces(
                    &message.id,
                    &ConversationMessage {
                        question: None,
                        conversation: conversation.clone(),
                        agent: format!("{sandbox}/{agent}"),
                        from: "agent".to_owned(),
                        text: text.clone(),
                        kind: kind.to_owned(),
                        time: now(),
                        seq: 0,
                        attachments: Vec::new(),
                    },
                )?,
                conversation.as_str(),
                &From::Agent,
                kind,
            )
            .map_err(|e| e.to_string())?
            .is_some()
        {
            let _ = match kind {
                "notify" => writeln!(
                    out,
                    "\n[{}, on its own] {}",
                    printable_line(conversation.as_str()),
                    shown(text)
                ),
                "status" => writeln!(
                    out,
                    "\n[{}, runtime] {}",
                    printable_line(conversation.as_str()),
                    shown(text)
                ),
                _ => writeln!(out, "\n{}", shown(text)),
            };
        }
        acks.ack(&message.id).map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// A second writer on the same connection, for the acknowledgements the
/// reading thread sends.
fn writer_ack(
    writer: &mut enclos::bridge::plugin::PluginWriter,
) -> Result<enclos::bridge::plugin::PluginWriter> {
    writer.try_clone().map_err(|e| Error::Session {
        what: format!("cannot share the connection to the agent: {e}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A stand-in plugin: answers the hello, sends `messages`, and closes
    /// once each is acknowledged; the acknowledged ids come back.
    fn plugin_sending(
        socket: &std::path::Path,
        messages: Vec<(&'static str, &'static str, &'static str, OutKind)>,
    ) -> std::thread::JoinHandle<Vec<String>> {
        use enclos_protocol::plugin::{FromBridge, decode_from_bridge};
        use enclos_protocol::{Envelope, MessageId, encode_line};
        use std::io::Write;
        let listener = std::os::unix::net::UnixListener::bind(socket).unwrap();
        std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut out = stream.try_clone().unwrap();
            let mut lines = std::io::BufReader::new(stream);
            let mut line = Vec::new();
            lines.read_until(b'\n', &mut line).unwrap();
            let mut send = |id: &str, body: FromPlugin| {
                out.write_all(&encode_line(&Envelope::new(
                    MessageId::new(id).unwrap(),
                    body,
                )))
                .unwrap();
            };
            send(
                "h-1",
                FromPlugin::Hello {
                    runtime: "hermes".into(),
                    agent: "main".into(),
                    capabilities: vec![],
                },
            );
            for (id, conversation, text, kind) in &messages {
                send(
                    id,
                    FromPlugin::MessageOut {
                        conversation: ConversationId::new(*conversation).unwrap(),
                        text: (*text).into(),
                        kind: *kind,
                        reply_to: None,
                        attachments: vec![],
                    },
                );
            }
            let mut acked = Vec::new();
            while acked.len() < messages.len() {
                line.clear();
                if lines.read_until(b'\n', &mut line).unwrap() == 0 {
                    break;
                }
                if let FromBridge::Ack { of } = decode_from_bridge(&line).unwrap().body {
                    acked.push(of.as_str().to_owned());
                }
            }
            acked
        })
    }

    #[test]
    fn the_chat_keeps_its_agents_messages_only_and_prints_them_escaped() {
        let folder = tempfile::tempdir().unwrap();
        let socket = folder.path().join("main.sock");
        let store = Store::open(&folder.path().join("app.db")).unwrap();
        store
            .conversation("c-1", "lab", "main", "victor@mac")
            .unwrap();
        store
            .conversation("home.work.default", "work", "default", "victor@mac")
            .unwrap();
        let plugin = plugin_sending(
            &socket,
            vec![
                (
                    "m-1",
                    "c-1",
                    "line one\nline two \x1b]52;c;cGFzdGU=\x07\u{202e}",
                    OutKind::Reply,
                ),
                (
                    "m-2",
                    "home.work.default",
                    "I am work/default",
                    OutKind::Notify,
                ),
                ("m-3", "c-1", "the weather", OutKind::Notify),
            ],
        );
        let (_, mut reader, writer) = connect(&socket, "t0ken", "home.lab.main").unwrap();
        let mut acks = writer.try_clone().unwrap();
        let mut printed = Vec::new();
        let done = std::thread::spawn(move || {
            let r = read_agent(&mut reader, &store, &mut acks, &mut printed, "lab", "main");
            (r, printed, store)
        });
        // Every message is acknowledged, the dropped one included
        assert_eq!(plugin.join().unwrap(), ["m-1", "m-2", "m-3"]);
        writer.shutdown();
        let (ended, printed, store) = done.join().unwrap();
        ended.unwrap();
        let printed = String::from_utf8(printed).unwrap();
        // Line breaks kept, the escape and the override shown, not run
        assert!(printed.contains("line one\nline two "), "{printed}");
        assert!(
            !printed.contains('\x1b') && !printed.contains('\u{202e}'),
            "{printed}"
        );
        assert!(printed.contains("\\u{1b}]52"), "{printed}");
        assert!(
            printed.contains("[c-1, on its own] the weather"),
            "{printed}"
        );
        assert!(
            printed.contains("[dropped: lab/main sent a message to conversation home.work.default"),
            "{printed}"
        );
        assert!(!printed.contains("I am work/default"), "{printed}");
        // Stored: this agent's two, as sent; nothing in work/default's
        let mine = store.since("victor@mac", 0).unwrap();
        assert_eq!(
            mine.iter()
                .map(|m| m.conversation.as_str())
                .collect::<Vec<_>>(),
            ["c-1", "c-1"]
        );
        assert!(mine[0].text.contains('\x1b'));
    }

    #[test]
    fn text_from_a_device_cannot_redraw_the_terminal() {
        assert_eq!(shown("Pixel 9"), "Pixel 9");
        assert_eq!(
            shown("Pixel\r\x1b[2Kok\u{202e}"),
            "Pixel\\u000d\\u001b[2Kok\\u202e"
        );
    }

    #[test]
    fn what_is_typed_in_the_chat_is_not_the_hosts_persons() {
        let conversation = ConversationId::new("c-1").unwrap();
        let person = Person::new("alice@mac").unwrap();
        for text in ["/approve always", "hello"] {
            assert_eq!(
                typed_message(&conversation, &person, text),
                FromBridge::MessageIn {
                    conversation: conversation.clone(),
                    person: person.clone(),
                    text: text.into(),
                    host: Some(false),
                }
            );
        }
    }

    #[test]
    fn a_conversation_goes_on_only_with_its_own_agent_and_person() {
        let stored = ("lab", "main", "victor@mac");
        assert!(resumable("c-1", stored, ("lab", "main", "victor@mac")).is_ok());
        let other_agent = resumable("c-1", stored, ("lab", "scout", "victor@mac")).unwrap_err();
        assert!(other_agent.contains("is with lab/main"), "{other_agent}");
        assert!(resumable("c-1", stored, ("work", "main", "victor@mac")).is_err());
        let other_person = resumable("c-1", stored, ("lab", "main", "alice@mac")).unwrap_err();
        assert!(other_person.contains("victor@mac's"), "{other_person}");
    }

    #[test]
    fn a_log_line_cannot_forge_another_or_reach_the_terminal_raw() {
        let line = LogLine {
            at: 0,
            device: Some("phone\u{1b}[2J".into()),
            person: None,
            event: "routine.create".into(),
            reason: Some(
                "lab/coder new confirmed as x\n1970-01-01  unpaired  phone  -\u{1b}]52;c;eA==\u{7}"
                    .into(),
            ),
        };
        let shown = log_line(&line);
        assert!(!shown.chars().any(char::is_control), "{shown}");
        assert!(shown.contains("phone\\u{1b}[2J"), "{shown}");
        assert!(shown.contains("confirmed as x\\n1970-01-01"), "{shown}");
    }
}
