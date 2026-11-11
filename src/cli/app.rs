//! `enclos app`: the mobile app's side of enclos (ADR 0042, proposed). For
//! now `app chat`, which talks to an agent through its app channel from the
//! terminal, the way the bridge will for a phone.

use std::io::BufRead;

use clap::{Args, Subcommand};

use super::runtime::ChannelTarget;
use enclos::bridge::ids::new_id;
use enclos::bridge::plugin::{PluginError, PluginReader, PluginWriter, connect};
use enclos::bridge::store::{From, Store};
use enclos::engine::{Engine, printable_line};
use enclos::error::{Error, Result, exit};
use enclos::model::audit::Actor;
use enclos_protocol::plugin::{FromPlugin, OutKind};
use enclos_protocol::{ConversationId, Person};

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
}

pub fn run(engine: &Engine, by: &Actor, args: AppArgs) -> Result<u8> {
    match args.verb {
        AppVerb::Chat {
            target,
            conversation,
        } => chat(engine, by, target, conversation),
    }
}

fn chat(
    engine: &Engine,
    by: &Actor,
    target: ChannelTarget,
    conversation: Option<String>,
) -> Result<u8> {
    let failed = |what: String| Error::Session { what };
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
    let (hello, mut reader, mut writer) =
        connect(&endpoint.socket, endpoint.token.expose()).map_err(plugin_error)?;
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
        let id = writer
            .message(&conversation, &person, text)
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
            .add(
                message.id.as_str(),
                conversation.as_str(),
                &From::Agent,
                text,
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
        let (_, mut reader, writer) = connect(&socket, "t0ken").unwrap();
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
    fn a_conversation_goes_on_only_with_its_own_agent_and_person() {
        let stored = ("lab", "main", "victor@mac");
        assert!(resumable("c-1", stored, ("lab", "main", "victor@mac")).is_ok());
        let other_agent = resumable("c-1", stored, ("lab", "scout", "victor@mac")).unwrap_err();
        assert!(other_agent.contains("is with lab/main"), "{other_agent}");
        assert!(resumable("c-1", stored, ("work", "main", "victor@mac")).is_err());
        let other_person = resumable("c-1", stored, ("lab", "main", "alice@mac")).unwrap_err();
        assert!(other_person.contains("victor@mac's"), "{other_person}");
    }
}
