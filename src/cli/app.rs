//! `enclos app`: the mobile app's side of enclos (ADR 0042, proposed). For
//! now `app chat`, which talks to an agent through its app channel from the
//! terminal, the way the bridge will for a phone.

use std::io::BufRead;

use clap::{Args, Subcommand};

use super::runtime::ChannelTarget;
use enclos::bridge::ids::new_id;
use enclos::bridge::plugin::{PluginError, connect};
use enclos::bridge::store::{From, Store};
use enclos::engine::Engine;
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
    let (hello, mut reader, mut writer) =
        connect(&endpoint.socket, endpoint.token.expose()).map_err(plugin_error)?;
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
