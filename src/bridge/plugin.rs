//! The bridge's side of the plugin leg (`docs/protocol.md`): a connection
//! to one agent's channel plugin over its Unix socket in the sandbox home,
//! opened with the agent's token.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use enclos_protocol::plugin::{Capability, FromBridge, FromPlugin, decode_from_plugin};
use enclos_protocol::{ConversationId, DecodeError, Envelope, MessageId, Person, encode_line};

use super::ids::new_id;

/// How long the plugin has to answer the bridge's `hello`.
const HELLO_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a write to the plugin may wait for it to read: the socket is
/// in the sandbox home, and an agent that never reads must not hold the
/// bridge.
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, thiserror::Error)]
pub enum PluginError {
    #[error(
        "cannot reach the agent's app channel at {path}: {source} (is the sandbox started, and the channel set up?)"
    )]
    Connect {
        path: String,
        source: std::io::Error,
    },
    #[error(
        "the agent's app channel closed the connection without answering: the token it was given is not the one it holds, or another bridge is connected"
    )]
    Refused,
    #[error("the connection to the agent's app channel failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("the agent's app channel sent a message the bridge cannot read: {0}")]
    Decode(#[from] DecodeError),
    #[error("the agent's app channel did not follow the protocol: {0}")]
    Protocol(String),
}

/// What the plugin said of itself in its `hello`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginHello {
    pub runtime: String,
    pub agent: String,
    pub capabilities: Vec<Capability>,
}

/// Sends to the plugin.
pub struct PluginWriter {
    stream: UnixStream,
}

/// Reads what the plugin sends.
pub struct PluginReader {
    lines: BufReader<UnixStream>,
}

/// Connects to the plugin at `socket` and opens the connection with
/// `token`; the plugin answers with its own `hello`.
pub fn connect(
    socket: &Path,
    token: &str,
) -> Result<(PluginHello, PluginReader, PluginWriter), PluginError> {
    let stream = UnixStream::connect(socket).map_err(|source| PluginError::Connect {
        path: socket.display().to_string(),
        source,
    })?;
    stream.set_write_timeout(Some(WRITE_TIMEOUT))?;
    let mut writer = PluginWriter {
        stream: stream.try_clone()?,
    };
    writer.send(FromBridge::Hello {
        token: token.to_owned(),
    })?;
    stream.set_read_timeout(Some(HELLO_TIMEOUT))?;
    let mut reader = PluginReader {
        lines: BufReader::new(stream),
    };
    let hello = match reader.receive() {
        Ok(Some(message)) => message,
        Ok(None) => return Err(PluginError::Refused),
        Err(PluginError::Io(e)) if e.kind() == std::io::ErrorKind::ConnectionReset => {
            return Err(PluginError::Refused);
        }
        Err(e) => return Err(e),
    };
    let FromPlugin::Hello {
        runtime,
        agent,
        capabilities,
    } = hello.body
    else {
        return Err(PluginError::Protocol(format!(
            "its first message is not a hello: {:?}",
            hello.body
        )));
    };
    reader.lines.get_ref().set_read_timeout(None)?;
    Ok((
        PluginHello {
            runtime,
            agent,
            capabilities,
        },
        reader,
        writer,
    ))
}

impl PluginWriter {
    /// Another writer on the same connection, for another thread.
    pub fn try_clone(&self) -> std::io::Result<PluginWriter> {
        Ok(PluginWriter {
            stream: self.stream.try_clone()?,
        })
    }

    /// Sends `body` with a new id, which it returns.
    pub fn send(&mut self, body: FromBridge) -> Result<MessageId, PluginError> {
        let id = MessageId::new(new_id()?).map_err(|e| PluginError::Protocol(e.to_string()))?;
        self.send_as(id.clone(), body)?;
        Ok(id)
    }

    /// Sends `body` with `id`: the same on every try of one message, so the
    /// plugin knows a message it has had already.
    pub fn send_as(&mut self, id: MessageId, body: FromBridge) -> Result<(), PluginError> {
        self.stream
            .write_all(&encode_line(&Envelope::new(id, body)))?;
        Ok(())
    }

    /// A person's message to the agent, in `conversation`.
    pub fn message(
        &mut self,
        conversation: &ConversationId,
        person: &Person,
        text: &str,
    ) -> Result<MessageId, PluginError> {
        self.send(FromBridge::MessageIn {
            conversation: conversation.clone(),
            person: person.clone(),
            text: text.to_owned(),
        })
    }

    /// Says the bridge stored the plugin's message `of`, which it may then
    /// drop from its outbox.
    pub fn ack(&mut self, of: &MessageId) -> Result<MessageId, PluginError> {
        self.send(FromBridge::Ack { of: of.clone() })
    }

    /// Ends the connection both ways, for every reader and writer cloned
    /// from it: dropping one writer closes only its own descriptor, while
    /// the others keep the connection, and the plugin, waiting.
    pub fn shutdown(&self) {
        // Already closed by the plugin is as good as closed here.
        let _ = self.stream.shutdown(std::net::Shutdown::Both);
    }
}

impl PluginReader {
    /// The next message; `None` once the plugin closed the connection. A
    /// type this bridge does not know is skipped, as the protocol says.
    pub fn receive(&mut self) -> Result<Option<Envelope<FromPlugin>>, PluginError> {
        loop {
            let mut line = Vec::new();
            if self.lines.read_until(b'\n', &mut line)? == 0 {
                return Ok(None);
            }
            match decode_from_plugin(&line) {
                Ok(message) => return Ok(Some(message)),
                Err(DecodeError::UnknownType { .. }) => continue,
                Err(e) => return Err(e.into()),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use enclos_protocol::plugin::{OutKind, decode_from_bridge};
    use std::os::unix::net::UnixListener;

    /// A stand-in plugin: checks the token, answers hello, then answers
    /// each message with an ack and a reply that echoes it.
    fn echo_plugin(listener: UnixListener, token: &'static str) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut out = stream.try_clone().unwrap();
            let mut lines = BufReader::new(stream);
            let mut line = Vec::new();
            lines.read_until(b'\n', &mut line).unwrap();
            let FromBridge::Hello { token: given } = decode_from_bridge(&line).unwrap().body else {
                panic!("not a hello first");
            };
            if given != token {
                return; // closes, saying nothing
            }
            let send = |out: &mut UnixStream, body: FromPlugin| {
                let id = MessageId::new(new_id().unwrap()).unwrap();
                out.write_all(&encode_line(&Envelope::new(id, body)))
                    .unwrap();
            };
            send(
                &mut out,
                FromPlugin::Hello {
                    runtime: "hermes".into(),
                    agent: "main".into(),
                    capabilities: vec![Capability::Notify],
                },
            );
            loop {
                line.clear();
                if lines.read_until(b'\n', &mut line).unwrap() == 0 {
                    return;
                }
                let message = decode_from_bridge(&line).unwrap();
                if let FromBridge::MessageIn {
                    conversation, text, ..
                } = message.body
                {
                    send(
                        &mut out,
                        FromPlugin::Ack {
                            of: message.id.clone(),
                        },
                    );
                    send(
                        &mut out,
                        FromPlugin::MessageOut {
                            conversation,
                            text: format!("echo: {text}"),
                            kind: OutKind::Reply,
                            reply_to: Some(message.id),
                        },
                    );
                }
            }
        })
    }

    #[test]
    fn the_bridge_opens_with_the_token_and_gets_the_agents_answer() {
        let folder = tempfile::tempdir().unwrap();
        let socket = folder.path().join("main.sock");
        let plugin = echo_plugin(UnixListener::bind(&socket).unwrap(), "t0ken");
        let (hello, mut reader, mut writer) = connect(&socket, "t0ken").unwrap();
        assert_eq!(hello.agent, "main");
        assert_eq!(hello.capabilities, [Capability::Notify]);
        let conversation = ConversationId::new("c-1").unwrap();
        let sent = writer
            .message(
                &conversation,
                &Person::new("victor@example.com").unwrap(),
                "hi",
            )
            .unwrap();
        let ack = reader.receive().unwrap().unwrap();
        assert_eq!(ack.body, FromPlugin::Ack { of: sent.clone() });
        let reply = reader.receive().unwrap().unwrap();
        let FromPlugin::MessageOut {
            conversation: c,
            text,
            kind,
            reply_to,
        } = reply.body
        else {
            panic!("not a reply: {:?}", reply.body);
        };
        assert_eq!(
            (c, text.as_str(), kind, reply_to),
            (conversation, "echo: hi", OutKind::Reply, Some(sent))
        );
        writer.ack(&reply.id).unwrap();
        drop(writer);
        drop(reader);
        plugin.join().unwrap();
    }

    #[test]
    fn shutdown_ends_the_connection_for_every_clone_of_it() {
        let folder = tempfile::tempdir().unwrap();
        let socket = folder.path().join("main.sock");
        let plugin = echo_plugin(UnixListener::bind(&socket).unwrap(), "t0ken");
        let (_, mut reader, writer) = connect(&socket, "t0ken").unwrap();
        // A clone keeps the descriptor open, as the reading thread's
        // acknowledgements do in `enclos app chat`
        let clone = writer.try_clone().unwrap();
        let (done, waited) = std::sync::mpsc::channel();
        let reading = std::thread::spawn(move || {
            let end = reader.receive().unwrap();
            done.send(end.is_none()).unwrap();
        });
        writer.shutdown();
        drop(writer);
        let ended = waited
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("the reader still waits for the plugin");
        assert!(ended);
        reading.join().unwrap();
        // The plugin saw the end too, and stopped
        plugin.join().unwrap();
        drop(clone);
    }

    #[test]
    fn a_wrong_token_is_refused() {
        let folder = tempfile::tempdir().unwrap();
        let socket = folder.path().join("main.sock");
        let plugin = echo_plugin(UnixListener::bind(&socket).unwrap(), "t0ken");
        assert!(matches!(
            connect(&socket, "other"),
            Err(PluginError::Refused)
        ));
        plugin.join().unwrap();
    }

    #[test]
    fn no_plugin_says_where_it_looked() {
        let folder = tempfile::tempdir().unwrap();
        let socket = folder.path().join("main.sock");
        let Err(PluginError::Connect { path, .. }) = connect(&socket, "t0ken") else {
            panic!("connected to nothing");
        };
        assert!(path.ends_with("main.sock"));
    }
}
