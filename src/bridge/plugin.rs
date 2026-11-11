//! The bridge's side of the plugin leg (`docs/protocol.md`): a connection
//! to one agent's channel plugin over its Unix socket in the sandbox home,
//! opened with the agent's token.

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use enclos_protocol::plugin::{
    Capability, ErrorBody, ErrorCode, FromBridge, FromPlugin, decode_from_plugin,
};
use enclos_protocol::{
    ConversationId, DecodeError, Envelope, MAX_MESSAGE_BYTES, MessageId, Person, encode_line,
};

use super::ids::new_id;

/// How long the plugin has, in all, to answer the bridge's `hello`.
const HELLO_TIMEOUT: Duration = Duration::from_secs(10);
/// The longest `hello` the bridge reads: a few names and capabilities.
const MAX_HELLO_BYTES: usize = 64 * 1024;
/// How long one write to the plugin may wait for it to read: a plugin that
/// stops reading must not hold the bridge, which writes to it with its
/// connections locked.
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
    #[error("the agent's app channel sent a line over 1 MiB; the connection was ended")]
    TooLong,
    #[error("the agent's app channel speaks protocol version {0}, which this bridge does not")]
    Version(u64),
}

/// What the plugin said of itself in its `hello`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginHello {
    pub runtime: String,
    pub agent: String,
    pub capabilities: Vec<Capability>,
}

/// Sends to the plugin. Clones share one lock, so two threads never
/// interleave their lines on the connection.
pub struct PluginWriter {
    stream: UnixStream,
    lock: Arc<Mutex<()>>,
}

/// Reads what the plugin sends, and answers what it cannot read.
pub struct PluginReader {
    lines: BufReader<UnixStream>,
    answers: PluginWriter,
}

/// Connects to the plugin at `socket` and opens the connection with
/// `token` and the agent's `home` conversation; the plugin answers with its
/// own `hello`.
pub fn connect(
    socket: &Path,
    token: &str,
    home: &str,
) -> Result<(PluginHello, PluginReader, PluginWriter), PluginError> {
    connect_within(socket, token, home, HELLO_TIMEOUT)
}

/// [`connect`], with `wait` for the whole of the plugin's `hello`: a plugin
/// that sends it a byte at a time, or never ends its line, is given up on
/// once `wait` is over.
fn connect_within(
    socket: &Path,
    token: &str,
    home: &str,
    wait: Duration,
) -> Result<(PluginHello, PluginReader, PluginWriter), PluginError> {
    let deadline = Instant::now() + wait;
    // The folder is in the sandbox home, which the sandbox writes: a link
    // there would send the agent's token to another socket of the host
    refuse_linked_folder(socket)?;
    let stream = UnixStream::connect(socket).map_err(|source| PluginError::Connect {
        path: socket.display().to_string(),
        source,
    })?;
    stream.set_write_timeout(Some(WRITE_TIMEOUT))?;
    let mut writer = PluginWriter {
        stream: stream.try_clone()?,
        lock: Arc::new(Mutex::new(())),
    };
    writer.send(FromBridge::Hello {
        token: token.to_owned(),
        home: ConversationId::new(home).ok(),
    })?;
    let mut reader = PluginReader {
        lines: BufReader::new(stream),
        answers: writer.try_clone()?,
    };
    let hello = match reader.receive_hello(deadline, wait) {
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
            lock: Arc::clone(&self.lock),
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
        let line = encode_line(&Envelope::new(id, body));
        let _held = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        self.stream.write_all(&line)?;
        Ok(())
    }

    /// Answers the plugin's message `of` (when its id could be read) with
    /// an `error`.
    fn error(
        &mut self,
        of: Option<String>,
        code: ErrorCode,
        message: &str,
    ) -> Result<(), PluginError> {
        self.send(FromBridge::Error(ErrorBody {
            of: of.and_then(|id| MessageId::new(id).ok()),
            code,
            message: message.to_owned(),
        }))?;
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

/// Refuses a socket whose folder is a link (`docs/protocol.md`, the plugin
/// leg: the bridge sends the agent's token to whatever listens there).
fn refuse_linked_folder(socket: &Path) -> Result<(), PluginError> {
    let Some(folder) = socket.parent() else {
        return Ok(());
    };
    match std::fs::symlink_metadata(folder) {
        Ok(meta) if meta.file_type().is_symlink() => Err(PluginError::Connect {
            path: socket.display().to_string(),
            source: std::io::Error::other(format!(
                "{} is a link, not the sandbox home's own folder",
                folder.display()
            )),
        }),
        _ => Ok(()),
    }
}

impl PluginReader {
    /// The plugin's first message, by `deadline` whatever it sends until
    /// then (`wait` is how long it was given), at most [`MAX_HELLO_BYTES`].
    fn receive_hello(
        &mut self,
        deadline: Instant,
        wait: Duration,
    ) -> Result<Option<Envelope<FromPlugin>>, PluginError> {
        use std::io::ErrorKind::{Interrupted, TimedOut, WouldBlock};
        loop {
            let mut line = Vec::new();
            loop {
                let left = deadline.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    return Err(PluginError::Protocol(format!(
                        "it did not answer the hello within {} ms",
                        wait.as_millis()
                    )));
                }
                self.lines.get_ref().set_read_timeout(Some(left))?;
                let read = match self.lines.fill_buf() {
                    Ok(read) => read,
                    Err(e) if matches!(e.kind(), WouldBlock | TimedOut | Interrupted) => continue,
                    Err(e) => return Err(e.into()),
                };
                if read.is_empty() {
                    return Ok(None);
                }
                let (taken, ended) = match read.iter().position(|&b| b == b'\n') {
                    Some(end) => (end + 1, true),
                    None => (read.len(), false),
                };
                line.extend_from_slice(&read[..taken]);
                self.lines.consume(taken);
                if line.len() > MAX_HELLO_BYTES {
                    return Err(PluginError::Protocol(format!(
                        "its hello is longer than {MAX_HELLO_BYTES} bytes"
                    )));
                }
                if ended {
                    break;
                }
            }
            match decode_from_plugin(&line) {
                Ok(message) => return Ok(Some(message)),
                Err(DecodeError::UnknownType { .. }) => continue,
                Err(e) => return Err(e.into()),
            }
        }
    }

    /// The next message; `None` once the plugin closed the connection.
    ///
    /// As `docs/protocol.md` says: a line is read up to 1 MiB, and one
    /// longer is answered `bad_message` and ends the connection
    /// ([`PluginError::TooLong`]); a message this bridge cannot use is
    /// answered (`unknown_type`, `bad_message`, naming it when its id could
    /// be read) and reading goes on; a `v` it does not speak is answered
    /// `version` and ends the connection.
    pub fn receive(&mut self) -> Result<Option<Envelope<FromPlugin>>, PluginError> {
        loop {
            let mut line = Vec::new();
            let limit = MAX_MESSAGE_BYTES as u64 + 1;
            let read = (&mut self.lines).take(limit).read_until(b'\n', &mut line)?;
            if read == 0 {
                return Ok(None);
            }
            if !line.ends_with(b"\n") && line.len() as u64 >= limit {
                let _ = self
                    .answers
                    .error(None, ErrorCode::BadMessage, "a line over 1 MiB");
                return Err(PluginError::TooLong);
            }
            match decode_from_plugin(&line) {
                Ok(message) => return Ok(Some(message)),
                Err(DecodeError::UnknownType { id, kind }) => {
                    let why = format!("unknown type {kind}");
                    self.answers
                        .error(id, ErrorCode::UnknownType, &plain(&why))?;
                }
                Err(DecodeError::Bad { id, reason }) => {
                    self.answers
                        .error(id, ErrorCode::BadMessage, &plain(&reason))?;
                }
                Err(e @ (DecodeError::NotJson(_) | DecodeError::TooBig)) => {
                    self.answers
                        .error(None, ErrorCode::BadMessage, &plain(&e.to_string()))?;
                }
                Err(DecodeError::Version { id, v }) => {
                    let _ =
                        self.answers
                            .error(id, ErrorCode::Version, "this bridge speaks version 1");
                    return Err(PluginError::Version(v));
                }
            }
        }
    }
}

/// An error's text holds no control character (`docs/protocol.md`, Names).
fn plain(text: &str) -> String {
    text.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(200)
        .collect()
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
            let FromBridge::Hello { token: given, .. } = decode_from_bridge(&line).unwrap().body
            else {
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
                            attachments: Vec::new(),
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
        let (hello, mut reader, mut writer) = connect(&socket, "t0ken", "home.lab.main").unwrap();
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
            ..
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
        let (_, mut reader, writer) = connect(&socket, "t0ken", "home.lab.main").unwrap();
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

    /// A stand-in plugin that answers the hello, then writes `raw` as it
    /// is; the lines the bridge sends back come out of the receiver.
    fn raw_plugin(listener: UnixListener, raw: Vec<u8>) -> std::sync::mpsc::Receiver<Vec<u8>> {
        let (got, lines_back) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
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
            // The bridge may close before all of it is read
            let _ = out.write_all(&raw);
            loop {
                line.clear();
                match lines.read_until(b'\n', &mut line) {
                    Ok(0) | Err(_) => return,
                    Ok(_) => {
                        if got.send(line.clone()).is_err() {
                            return;
                        }
                    }
                }
            }
        });
        lines_back
    }

    fn answer(lines_back: &std::sync::mpsc::Receiver<Vec<u8>>) -> ErrorBody {
        let line = lines_back
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("no answer");
        match decode_from_bridge(&line).unwrap().body {
            FromBridge::Error(error) => error,
            other => panic!("not an error: {other:?}"),
        }
    }

    fn out_line(id: &str, text: &str) -> Vec<u8> {
        let body = FromPlugin::MessageOut {
            conversation: ConversationId::new("c-1").unwrap(),
            text: text.into(),
            kind: OutKind::Reply,
            reply_to: None,
            attachments: vec![],
        };
        encode_line(&Envelope::new(MessageId::new(id).unwrap(), body))
    }

    #[test]
    fn a_message_the_bridge_cannot_use_is_answered_and_reading_goes_on() {
        let folder = tempfile::tempdir().unwrap();
        let socket = folder.path().join("main.sock");
        let mut raw = Vec::new();
        raw.extend(br#"{"v":1,"type":"poke","id":"p-1"}"#);
        raw.push(b'\n');
        raw.extend(br#"{"v":1,"type":"message.out","id":"p-2"}"#);
        raw.push(b'\n');
        raw.extend(b"not json\n");
        raw.extend(out_line("p-3", "still here"));
        let lines_back = raw_plugin(UnixListener::bind(&socket).unwrap(), raw);
        let (_, mut reader, _writer) = connect(&socket, "t0ken", "home.lab.main").unwrap();
        let message = reader.receive().unwrap().unwrap();
        assert_eq!(message.id.as_str(), "p-3");
        let (unknown, bad, not_json) = (
            answer(&lines_back),
            answer(&lines_back),
            answer(&lines_back),
        );
        assert_eq!(
            (unknown.code, unknown.of.unwrap().as_str().to_owned()),
            (ErrorCode::UnknownType, "p-1".to_owned())
        );
        assert_eq!(
            (bad.code, bad.of.unwrap().as_str().to_owned()),
            (ErrorCode::BadMessage, "p-2".to_owned())
        );
        assert_eq!((not_json.code, not_json.of), (ErrorCode::BadMessage, None));
    }

    #[test]
    fn a_line_over_the_limit_is_answered_and_ends_the_connection() {
        let folder = tempfile::tempdir().unwrap();
        let socket = folder.path().join("main.sock");
        // No line break: a reader without a bound would keep growing
        let raw = vec![b'x'; MAX_MESSAGE_BYTES + 100];
        let lines_back = raw_plugin(UnixListener::bind(&socket).unwrap(), raw);
        let (_, mut reader, _writer) = connect(&socket, "t0ken", "home.lab.main").unwrap();
        assert!(matches!(reader.receive(), Err(PluginError::TooLong)));
        let error = answer(&lines_back);
        assert_eq!((error.code, error.of), (ErrorCode::BadMessage, None));
    }

    #[test]
    fn another_version_is_answered_and_ends_the_connection() {
        let folder = tempfile::tempdir().unwrap();
        let socket = folder.path().join("main.sock");
        let mut raw = br#"{"v":2,"type":"message.out","id":"p-1"}"#.to_vec();
        raw.push(b'\n');
        let lines_back = raw_plugin(UnixListener::bind(&socket).unwrap(), raw);
        let (_, mut reader, _writer) = connect(&socket, "t0ken", "home.lab.main").unwrap();
        assert!(matches!(reader.receive(), Err(PluginError::Version(2))));
        let error = answer(&lines_back);
        assert_eq!(
            (error.code, error.of.unwrap().as_str().to_owned()),
            (ErrorCode::Version, "p-1".to_owned())
        );
    }

    #[test]
    fn a_socket_in_a_linked_folder_is_not_connected_to() {
        let folder = tempfile::tempdir().unwrap();
        let real = folder.path().join("elsewhere");
        std::fs::create_dir(&real).unwrap();
        let plugin = echo_plugin(UnixListener::bind(real.join("main.sock")).unwrap(), "t0ken");
        let linked = folder.path().join(".enclos-app");
        std::os::unix::fs::symlink(&real, &linked).unwrap();
        let Err(PluginError::Connect { source, .. }) =
            connect(&linked.join("main.sock"), "t0ken", "home.lab.main")
        else {
            panic!("connected through a link");
        };
        assert!(source.to_string().contains("is a link"), "{source}");
        // The stand-in never got a connection
        drop(plugin);
    }

    #[test]
    fn a_wrong_token_is_refused() {
        let folder = tempfile::tempdir().unwrap();
        let socket = folder.path().join("main.sock");
        let plugin = echo_plugin(UnixListener::bind(&socket).unwrap(), "t0ken");
        assert!(matches!(
            connect(&socket, "other", "home.lab.main"),
            Err(PluginError::Refused)
        ));
        plugin.join().unwrap();
    }

    #[test]
    fn a_plugin_that_trickles_its_hello_is_given_up_on_in_time() {
        let folder = tempfile::tempdir().unwrap();
        let socket = folder.path().join("main.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let plugin = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            // A byte at a time, never a line: each read gets something
            // before a per-read timeout would end it.
            for _ in 0..40 {
                if stream.write_all(b" ").is_err() {
                    return;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        });
        let started = Instant::now();
        let refused = connect_within(
            &socket,
            "t0ken",
            "home.lab.main",
            Duration::from_millis(400),
        );
        assert!(
            matches!(refused, Err(PluginError::Protocol(_))),
            "{:?}",
            refused.map(|(hello, ..)| hello)
        );
        assert!(started.elapsed() < Duration::from_millis(1_500));
        plugin.join().unwrap();
    }

    #[test]
    fn a_hello_longer_than_its_bound_is_refused() {
        let folder = tempfile::tempdir().unwrap();
        let socket = folder.path().join("main.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let plugin = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            // The bridge's hello read first, and the connection kept until
            // the bridge leaves: closing on unread bytes would reset it.
            let mut lines = BufReader::new(stream.try_clone().unwrap());
            let mut line = Vec::new();
            lines.read_until(b'\n', &mut line).unwrap();
            let _ = stream.write_all(&vec![b'x'; MAX_HELLO_BYTES + 2]);
            while lines.read_until(b'\n', &mut line).unwrap_or(0) > 0 {}
        });
        assert!(matches!(
            connect(&socket, "t0ken", "home.lab.main"),
            Err(PluginError::Protocol(_))
        ));
        plugin.join().unwrap();
    }

    #[test]
    fn no_plugin_says_where_it_looked() {
        let folder = tempfile::tempdir().unwrap();
        let socket = folder.path().join("main.sock");
        let Err(PluginError::Connect { path, .. }) = connect(&socket, "t0ken", "home.lab.main")
        else {
            panic!("connected to nothing");
        };
        assert!(path.ends_with("main.sock"));
    }
}
