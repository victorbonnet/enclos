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
use enclos::bridge::keys::bridge_keypair;
use enclos::bridge::plugin::{PluginError, connect};
use enclos::bridge::server::{self, AgentEndpoint};
use enclos::bridge::store::now;
use enclos::bridge::store::{From, Store};
use enclos::bridge::transport::Transport;
use enclos::engine::Engine;
use enclos::error::{Error, Result, exit};
use enclos::model::audit::Actor;
use enclos_protocol::pairing::PairLink;
use enclos_protocol::plugin::{FromPlugin, OutKind};
use enclos_protocol::{ConversationId, Person};
use qrcode::QrCode;
use qrcode::render::unicode::Dense1x2;

#[derive(Args)]
pub struct AppArgs {
    #[command(subcommand)]
    verb: AppVerb,
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
        AppVerb::Pair { url, transport } => pair(engine, url, transport),
        AppVerb::Devices | AppVerb::Status => devices(engine),
        AppVerb::Unpair { device } => unpair(engine, &device),
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
    server::serve(
        transport,
        port,
        engine.app_store_path(),
        engine.app_layout(),
        key.private,
        agents,
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

fn pair(engine: &Engine, url: Option<String>, transport: Transport) -> Result<u8> {
    let url = url.or_else(|| transport.address()).ok_or_else(|| {
        failed(format!(
            "cannot read the bridge's address from {transport}: give it with --url {}",
            transport.address_form()
        ))
    })?;
    let key = bridge_keypair(&engine.app_key_path())
        .map_err(|e| failed(format!("cannot read or make the bridge's key: {e}")))?;
    let store = open_store(engine)?;
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
    print!(
        "{} ({transport} login: {}) wants to pair. Accept? [y/N] ",
        request.name, request.person
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
    if !store
        .decide_pairing(&code, if accept { "accept" } else { "decline" })
        .map_err(|e| failed(e.to_string()))?
    {
        // The bridge had its word first: the device left.
        return Err(left());
    }
    if !accept {
        println!("Declined: the device is not paired.");
        return Ok(exit::OK);
    }
    // Paired once the device has its answer, which the bridge says.
    for _ in 0..20 {
        match store
            .pairing_decision(&code)
            .map_err(|e| failed(e.to_string()))?
            .as_deref()
        {
            Some("paired") => {
                println!("Paired.");
                return Ok(exit::OK);
            }
            Some("gone") => return Err(left()),
            _ => std::thread::sleep(std::time::Duration::from_millis(500)),
        }
    }
    Err(failed(
        "accepted, but the bridge did not answer the device: is `enclos app serve` running?"
            .to_owned(),
    ))
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
            d.name,
            d.person,
            when(Some(d.paired)),
            when(d.seen)
        );
    }
    Ok(exit::OK)
}

fn unpair(engine: &Engine, device: &str) -> Result<u8> {
    let store = open_store(engine)?;
    match store
        .remove_device(device)
        .map_err(|e| failed(e.to_string()))?
    {
        true => {
            let _ = store.log(Some(device), None, "unpaired", None);
            match output::json() {
                true => output::emit(&json!({"device": device, "removed": true})),
                false => println!("Device {device} removed: it can no longer connect."),
            }
            Ok(exit::OK)
        }
        false => Err(failed(format!(
            "no paired device {device}: `enclos app devices` lists them"
        ))),
    }
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
        println!(
            "{}  {}  {}  {}{}",
            when(Some(line.at)),
            line.event,
            line.device.as_deref().unwrap_or("-"),
            line.person.as_deref().unwrap_or("-"),
            line.reason.map(|r| format!("  ({r})")).unwrap_or_default()
        );
    }
    Ok(exit::OK)
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
    let (_, _, owner) = store
        .conversation(
            conversation.as_str(),
            sandbox.as_str(),
            &agent,
            person.as_str(),
        )
        .map_err(|e| failed(format!("cannot record the conversation: {e}")))?;
    if owner != person.as_str() {
        return Err(failed(format!(
            "conversation {conversation} is {owner}'s, not yours"
        )));
    }
    let plugin_error = |e: PluginError| failed(e.to_string());
    let (hello, mut reader, mut writer) = connect(
        &endpoint.socket,
        endpoint.token.expose(),
        &enclos::bridge::store::home_id(&format!("{sandbox}/{agent}")),
    )
    .map_err(plugin_error)?;
    eprintln!(
        "Talking to {sandbox}/{agent} ({}) in conversation {conversation}; Ctrl-D to stop.",
        hello.runtime
    );

    // What the agent sends, printed as it comes and stored, then
    // acknowledged so its plugin drops it from its outbox.
    let store_path = engine.app_store_path();
    let mut acks = writer_ack(&mut writer)?;
    let printer = std::thread::spawn(move || -> std::result::Result<(), String> {
        let store = Store::open(&store_path).map_err(|e| e.to_string())?;
        while let Some(message) = reader.receive().map_err(|e| e.to_string())? {
            if let FromPlugin::MessageOut {
                conversation,
                text,
                kind,
                ..
            } = &message.body
            {
                let kind = match kind {
                    OutKind::Reply => "reply",
                    OutKind::Notify => "notify",
                    OutKind::Status => "status",
                };
                let new = store
                    .add(
                        message.id.as_str(),
                        conversation.as_str(),
                        &From::Agent,
                        text,
                        kind,
                    )
                    .map_err(|e| e.to_string())?;
                if new.is_some() {
                    match kind {
                        "notify" => println!("\n[{conversation}, on its own] {text}"),
                        "status" => println!("\n[{conversation}, runtime] {text}"),
                        _ => println!("\n{text}"),
                    }
                }
                acks.ack(&message.id).map_err(|e| e.to_string())?;
            }
        }
        Ok(())
    });

    for line in std::io::stdin().lock().lines() {
        let line = line.map_err(|e| failed(format!("cannot read what you type: {e}")))?;
        let text = line.trim();
        if text.is_empty() {
            continue;
        }
        // Whoever types here is at the host itself, and could change the
        // runtime's approvals there anyway: their approval commands pass.
        let id = writer
            .message(&conversation, &person, text, true)
            .map_err(plugin_error)?;
        store
            .add(
                id.as_str(),
                conversation.as_str(),
                &From::Person(person.to_string()),
                text,
                "message",
            )
            .map_err(|e| failed(format!("cannot store your message: {e}")))?;
    }
    drop(writer);
    match printer.join() {
        Ok(Ok(())) => Ok(exit::OK),
        Ok(Err(e)) => Err(failed(e)),
        Err(_) => Err(failed("the reading thread stopped".to_owned())),
    }
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
