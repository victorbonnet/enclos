//! The bridge's side of the plugin leg (`docs/protocol.md`): a connection
//! to one agent's channel plugin over its Unix socket in the sandbox home,
//! opened with the agent's token.

use std::io::{BufRead, BufReader, Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::fs::FileTypeExt;
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
pub(super) const HELLO_TIMEOUT: Duration = Duration::from_secs(10);
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
    /// The path is not the channel's own socket: the socket, or the folder it
    /// is in, is a link (`refuse_linked_folder`), or it is a file that is not
    /// a socket, a folder, or a path this bridge cannot read
    /// (`connect_within`, `not_a_channel`). A link is nothing a restart
    /// explains, and neither is a path that is not a socket, so this failure
    /// is never called one (#376). It says what `Connect` says: the person's
    /// diagnostic does not change.
    #[error(
        "cannot reach the agent's app channel at {path}: {source} (is the sandbox started, and the channel set up?)"
    )]
    Linked {
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

impl PluginError {
    /// Whether this failure is one that a runtime restart explains: the
    /// connection could not be made, or the peer went away on it
    /// (`BrokenPipe`, `ConnectionReset`, `ConnectionAborted`, `NotConnected`,
    /// `UnexpectedEof`). A connect, hello, read or write timeout is not one of
    /// these and falls back through the existing diagnostic text (a connect
    /// timeout is routed to `Protocol` rather than `Connect`). A send only
    /// reaches the restart notice for a channel that answered in this bridge
    /// run and whose sandbox is running (`Hub::hold_for_restart` asks both), so
    /// the notice is said of an agent that answered and then went away, never
    /// of one that refused. A plugin that answered and refused the token, that
    /// does not speak this protocol, or that sent something unreadable says
    /// something else about the agent, and is never called a restart.
    /// `PermissionDenied` on connect is routed to `Linked` by `not_a_channel`
    /// before it can become `Connect`, so it never reaches the `Connect` arm
    /// here.
    ///
    /// Known remainder: the attachment-file read error in
    /// `incoming.rs::send_with_files` (`opened.read_exact`, a bridge-side file)
    /// also arrives as `Io`; only these kinds are restart-eligible, any other
    /// kind of it falls back, and a bridge-side `UnexpectedEof`/similar there
    /// still reads as a restart. That is documented behaviour, not fixed here.
    pub(super) fn may_be_restarting(&self) -> bool {
        use std::io::ErrorKind::{
            BrokenPipe, ConnectionAborted, ConnectionReset, NotConnected, UnexpectedEof,
        };
        match self {
            PluginError::Connect { .. } => true,
            PluginError::Io(e) => matches!(
                e.kind(),
                BrokenPipe | ConnectionReset | ConnectionAborted | NotConnected | UnexpectedEof
            ),
            _ => false,
        }
    }

    /// A `hello` write that failed because the plugin had already closed the
    /// connection: the plugin refused this bridge without reading it — the
    /// Hermes plugin closes the connection before the `hello` when its one
    /// bridge slot is taken. The read side says the same of a reset before a
    /// line (`connect_within`); this is the write side of that race, and a
    /// restart is not its explanation (#376).
    fn closed_before_hello(self) -> PluginError {
        match self {
            PluginError::Io(ref e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset
                ) =>
            {
                PluginError::Refused
            }
            other => other,
        }
    }
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

/// How long to pause between non-blocking connect attempts when the
/// listener's accept queue is full.
const CONNECT_RETRY: Duration = Duration::from_millis(10);

/// [`connect`], with `wait` for the connect and the whole of the plugin's
/// `hello`: a listener with a full accept queue, or a plugin that sends its
/// `hello` a byte at a time or never ends its line, is given up on once
/// `wait` is over.
pub(super) fn connect_within(
    socket: &Path,
    token: &str,
    home: &str,
    wait: Duration,
) -> Result<(PluginHello, PluginReader, PluginWriter), PluginError> {
    let deadline = Instant::now() + wait;
    let stream = connect_until(socket, deadline, wait)?;
    open_on(stream, token, home, wait, deadline)
}

#[cfg(not(target_vendor = "apple"))]
fn nonblocking_unix_socket() -> std::io::Result<OwnedFd> {
    Ok(rustix::net::socket_with(
        rustix::net::AddressFamily::UNIX,
        rustix::net::SocketType::STREAM,
        rustix::net::SocketFlags::CLOEXEC | rustix::net::SocketFlags::NONBLOCK,
        None,
    )?)
}

#[cfg(target_vendor = "apple")]
fn nonblocking_unix_socket() -> std::io::Result<OwnedFd> {
    let fd = rustix::net::socket(
        rustix::net::AddressFamily::UNIX,
        rustix::net::SocketType::STREAM,
        None,
    )?;
    rustix::io::fcntl_setfd(&fd, rustix::io::FdFlags::CLOEXEC)?;
    let flags = rustix::fs::fcntl_getfl(&fd)?;
    rustix::fs::fcntl_setfl(&fd, flags | rustix::fs::OFlags::NONBLOCK)?;
    Ok(fd)
}

/// Connects to the Unix stream socket at `socket`, giving up at `deadline`
/// if the listener's accept queue stays full instead of blocking without
/// limit (`wait` is how long it was given).
///
/// On Linux a non-blocking Unix connect reports a full accept queue as
/// `EAGAIN`; macOS reports a full queue differently (not tested here), so
/// this bound matters most where it is `EAGAIN`.
fn connect_until(
    socket: &Path,
    deadline: Instant,
    wait: Duration,
) -> Result<UnixStream, PluginError> {
    let map_connect_err = |source: std::io::Error| {
        // A failure of the path itself — a file that is not a socket, a
        // folder, a folder this bridge cannot read — is nothing a restart
        // explains: it is refused as `Linked` is, and says what `Connect`
        // says (#376).
        if not_a_channel(socket, &source) {
            PluginError::Linked {
                path: socket.display().to_string(),
                source,
            }
        } else {
            PluginError::Connect {
                path: socket.display().to_string(),
                source,
            }
        }
    };
    let address =
        rustix::net::SocketAddrUnix::new(socket).map_err(|e| map_connect_err(e.into()))?;
    let fd = nonblocking_unix_socket().map_err(map_connect_err)?;
    loop {
        // The folder is in the sandbox home, which the sandbox writes: a link
        // there would send the agent's token to another socket of the host.
        // Re-check before every attempt so a swap during EAGAIN retries is
        // refused on the next iteration.
        refuse_linked_folder(socket)?;
        match rustix::net::connect(&fd, &address) {
            Ok(()) => break,
            Err(rustix::io::Errno::INTR) => continue,
            Err(e) if std::io::Error::from(e).kind() == std::io::ErrorKind::WouldBlock => {
                let left = deadline.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    return Err(PluginError::Io(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        format!(
                            "it did not accept a connection within {} ms",
                            wait.as_millis()
                        ),
                    )));
                }
                std::thread::sleep(left.min(CONNECT_RETRY));
            }
            Err(e) => return Err(map_connect_err(e.into())),
        }
    }
    let flags = rustix::fs::fcntl_getfl(&fd).map_err(|e| map_connect_err(e.into()))?;
    rustix::fs::fcntl_setfl(&fd, flags.difference(rustix::fs::OFlags::NONBLOCK))
        .map_err(|e| map_connect_err(e.into()))?;
    Ok(UnixStream::from(fd))
}

/// Runs the plugin `hello` exchange on an already-connected `stream`.
fn open_on(
    stream: UnixStream,
    token: &str,
    home: &str,
    wait: Duration,
    deadline: Instant,
) -> Result<(PluginHello, PluginReader, PluginWriter), PluginError> {
    write_wait(&stream, Some(WRITE_TIMEOUT))?;
    let mut writer = PluginWriter {
        stream: stream.try_clone()?,
        lock: Arc::new(Mutex::new(())),
    };
    writer
        .send(FromBridge::Hello {
            token: token.to_owned(),
            capabilities: vec![
                Capability::Questions,
                Capability::RuntimeApprovals,
                Capability::RuntimeApprovalScopes,
                Capability::Abort,
                Capability::Activity,
                Capability::Tasks,
                Capability::HeldTaskDetails,
                Capability::TaskDetails,
                Capability::Usage,
                Capability::HeldTasks,
                Capability::AgentUsage,
                Capability::TaskEvents,
            ],
            home: ConversationId::new(home).ok(),
        })
        .map_err(PluginError::closed_before_hello)?;
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
    read_wait(reader.lines.get_ref(), None)?;
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
    #[cfg(test)]
    pub(super) fn for_test(stream: UnixStream) -> Self {
        Self {
            stream,
            lock: Arc::new(Mutex::new(())),
        }
    }

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
        self.send_as(&id, body)?;
        Ok(id)
    }

    /// Sends `body` as message `id`, which the caller made ([`new_id`]) so
    /// as to know it before an answer to it can come, or which it stored
    /// the message with: the same on every try, so the plugin knows a
    /// message it has had already.
    pub fn send_as(&mut self, id: &MessageId, body: FromBridge) -> Result<(), PluginError> {
        let line = encode_line(&Envelope::new(id.clone(), body));
        let _held = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        // A write that fails, a timeout included, may have sent part of
        // the line: the connection is shut down then, so the plugin never
        // reads the next line glued to that part, and the reader thread
        // ends it as a closed connection.
        if let Err(e) = (&self.stream).write_all(&line) {
            let _ = self.stream.shutdown(std::net::Shutdown::Both);
            return Err(e.into());
        }
        Ok(())
    }

    /// Sends `body` with `id`, one the bridge made, and stored, first: a
    /// correlated control request keeps its stable id across a reconnect.
    pub fn send_with_id(&mut self, id: MessageId, body: FromBridge) -> Result<(), PluginError> {
        self.send_as(&id, body)
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

    /// A person's message to the agent, in `conversation`; `host` when
    /// the person is the host's person. Unsigned: it grants nothing.
    pub fn message(
        &mut self,
        conversation: &ConversationId,
        person: &Person,
        text: &str,
        host: bool,
    ) -> Result<MessageId, PluginError> {
        self.send(FromBridge::MessageIn {
            conversation: conversation.clone(),
            person: person.clone(),
            text: text.to_owned(),
            host: Some(host),
            files: Vec::new(),
            signed: None,
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

    /// What ends this connection and sends nothing on it: held apart from
    /// the writer, it ends the connection while a write holds the writer.
    pub fn closer(&self) -> std::io::Result<PluginCloser> {
        Ok(PluginCloser(self.stream.try_clone()?))
    }
}

/// Ends a plugin connection ([`PluginWriter::closer`]), and can do
/// nothing else: no line goes past the writer's lock through it.
pub struct PluginCloser(UnixStream);

impl PluginCloser {
    /// As [`PluginWriter::shutdown`]: for every clone of the connection,
    /// at once.
    pub fn shutdown(&self) {
        let _ = self.0.shutdown(std::net::Shutdown::Both);
    }
}

/// Refuses a socket whose folder, or which itself, is a link
/// (`docs/protocol.md`, the plugin leg: the bridge sends the agent's token
/// to whatever listens there).
///
/// The check runs before each `connect` attempt inside [`connect_until`]
/// (including across retries when the accept queue is full), so the race
/// window is the gap between check and connect on each attempt, and this
/// holds across retries. A sandbox that rewrites its own folder or socket
/// link between them can still win on one attempt. A security review of
/// commit `a59cb1c9` won about one attempt in three on Linux with a
/// full-rate swap loop in a native program that repeats the same
/// check-then-connect sequence; it did not measure this Rust code or macOS.
/// The number of attempts is not what bounds the exposure.
///
/// The race is accepted, not closed. If a sandbox wins it, the exposure is
/// one fixed `hello` (the agent's own token, which the sandbox already holds,
/// plus the bridge's capabilities) written to a socket the sandbox could not
/// reach itself; the person's messages follow only if that listener answers
/// with a well-formed plugin `hello`, and the bridge checks no token or
/// agent name in it (the peer check is its own card). A directory descriptor
/// alone would not close the race: the leaf `main.sock` stays followable, so
/// closing it needs the peer checked after connect (its own card), not only
/// a descriptor.
fn refuse_linked_folder(socket: &Path) -> Result<(), PluginError> {
    let Some(folder) = socket.parent() else {
        return Ok(());
    };
    for (path, what) in [
        (folder, "the sandbox home's own folder"),
        (socket, "the channel's own socket"),
    ] {
        if let Ok(meta) = std::fs::symlink_metadata(path)
            && meta.file_type().is_symlink()
        {
            return Err(PluginError::Linked {
                path: socket.display().to_string(),
                source: std::io::Error::other(format!("{} is a link, not {what}", path.display())),
            });
        }
    }
    Ok(())
}

/// Whether a failed connection to `socket` failed because the path is not the
/// channel's own socket — a file that is not one, a folder, or something this
/// bridge cannot look at — rather than because no channel is listening there.
/// A restart explains the second, never the first (`refuse_linked_folder`
/// refuses the link, [`not_a_channel`] the rest), so the first says what
/// `Connect` says and is never called one (#376).
fn not_a_channel(socket: &Path, source: &std::io::Error) -> bool {
    if source.kind() == std::io::ErrorKind::PermissionDenied {
        return true;
    }
    match std::fs::symlink_metadata(socket) {
        Ok(meta) => !meta.file_type().is_socket(),
        // A socket taken away as the bridge asks for it is a channel going
        // away, which a restart explains; anything else is a path this bridge
        // cannot look at.
        Err(e) => e.kind() != std::io::ErrorKind::NotFound,
    }
}

/// Tolerates macOS's `EINVAL` from `set_{read,write}_timeout` once the peer
/// has closed the connection; Rust's own zero-duration refusal is
/// `InvalidInput` too, but carries no OS error and stays an error.
fn tolerate_closed_timeout(result: std::io::Result<()>) -> std::io::Result<()> {
    match result {
        Err(e) if e.kind() == std::io::ErrorKind::InvalidInput && e.raw_os_error().is_some() => {
            Ok(())
        }
        other => other,
    }
}

/// Sets how long a read on `stream` may wait. macOS refuses to change it
/// (`EINVAL`) once the connection is shut both ways, which it is as soon
/// as the plugin has closed its end: a plugin may send its `hello` and
/// close before the bridge has read it. A read there never waits, it gets
/// what is left and then the end, so that refusal is no failure.
fn read_wait(stream: &UnixStream, wait: Option<Duration>) -> std::io::Result<()> {
    tolerate_closed_timeout(stream.set_read_timeout(wait))
}

/// Sets how long a write on `stream` may wait. macOS refuses to change it
/// (`EINVAL`) once the peer has closed its end (for instance, a plugin that
/// accepts and drops the connection because its one bridge slot is taken).
/// The write that follows then fails with `BrokenPipe`/`ConnectionReset` and
/// `closed_before_hello` turns it into `Refused`.
fn write_wait(stream: &UnixStream, wait: Option<Duration>) -> std::io::Result<()> {
    tolerate_closed_timeout(stream.set_write_timeout(wait))
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
                read_wait(self.lines.get_ref(), Some(left))?;
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
                // Ended now, for every clone of the connection, not when
                // the last one is dropped.
                self.answers.shutdown();
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
                    self.answers.shutdown();
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
                    capabilities: vec![Capability::Typing],
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
                            suggested_replies: Vec::new(),
                            conversation,
                            text: format!("echo: {text}"),
                            kind: OutKind::Reply,
                            reply_to: Some(message.id),
                            attachments: Vec::new(),
                            task_event: None,
                        },
                    );
                }
            }
        })
    }

    #[test]
    fn a_write_that_fails_part_way_closes_the_connection_rather_than_leave_half_a_line() {
        let (ours, theirs) = UnixStream::pair().unwrap();
        ours.set_write_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        let mut writer = PluginWriter::for_test(ours);
        // The plugin reads nothing: a line far larger than the socket's
        // buffer times out after part of it was written.
        let conversation = ConversationId::new("c-1").unwrap();
        let person = Person::new("owner@example.com").unwrap();
        assert!(
            writer
                .message(&conversation, &person, &"x".repeat(4 << 20), false)
                .is_err()
        );
        theirs
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut partial = Vec::new();
        let read = std::io::Read::read_to_end(&mut &theirs, &mut partial);
        assert!(
            read.is_ok(),
            "the plugin sees the connection end, not a stalled half line: {read:?}"
        );
        assert!(!partial.is_empty() && !partial.ends_with(b"\n"));
    }

    #[test]
    fn the_bridge_opens_with_the_token_and_gets_the_agents_answer() {
        let folder = tempfile::tempdir().unwrap();
        let socket = folder.path().join("main.sock");
        let plugin = echo_plugin(UnixListener::bind(&socket).unwrap(), "t0ken");
        let (hello, mut reader, mut writer) = connect(&socket, "t0ken", "home.lab.main").unwrap();
        assert_eq!(hello.agent, "main");
        assert_eq!(hello.capabilities, [Capability::Typing]);
        let conversation = ConversationId::new("c-1").unwrap();
        let sent = writer
            .message(
                &conversation,
                &Person::new("victor@example.com").unwrap(),
                "hi",
                true,
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
            suggested_replies: Vec::new(),
            conversation: ConversationId::new("c-1").unwrap(),
            text: text.into(),
            kind: OutKind::Reply,
            reply_to: None,
            attachments: vec![],
            task_event: None,
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
        // Ended for the plugin too, though a writer of it is still held.
        assert_ended(&lines_back);
    }

    /// The stand-in plugin saw the connection end, and stopped.
    fn assert_ended(lines_back: &std::sync::mpsc::Receiver<Vec<u8>>) {
        assert_eq!(
            lines_back.recv_timeout(std::time::Duration::from_secs(5)),
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected)
        );
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
        assert_ended(&lines_back);
    }

    #[test]
    fn a_socket_in_a_linked_folder_is_not_connected_to() {
        let folder = tempfile::tempdir().unwrap();
        let real = folder.path().join("elsewhere");
        std::fs::create_dir(&real).unwrap();
        let plugin = echo_plugin(UnixListener::bind(real.join("main.sock")).unwrap(), "t0ken");
        let linked = folder.path().join(".enclos-app");
        std::os::unix::fs::symlink(&real, &linked).unwrap();
        let Err(PluginError::Linked { source, .. }) =
            connect(&linked.join("main.sock"), "t0ken", "home.lab.main")
        else {
            panic!("connected through a link");
        };
        assert!(source.to_string().contains("is a link"), "{source}");
        // The stand-in never got a connection
        drop(plugin);
    }

    #[test]
    fn a_socket_that_is_a_link_is_not_connected_to() {
        let folder = tempfile::tempdir().unwrap();
        let elsewhere = folder.path().join("elsewhere.sock");
        let plugin = echo_plugin(UnixListener::bind(&elsewhere).unwrap(), "t0ken");
        let own = folder.path().join(".enclos-app");
        std::fs::create_dir(&own).unwrap();
        std::os::unix::fs::symlink(&elsewhere, own.join("main.sock")).unwrap();
        let Err(PluginError::Linked { source, .. }) =
            connect(&own.join("main.sock"), "t0ken", "home.lab.main")
        else {
            panic!("connected through a link");
        };
        assert!(
            source.to_string().contains("not the channel's own socket"),
            "{source}"
        );
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
    fn a_hello_write_that_found_the_connection_closed_is_a_refusal() {
        use std::io::{Error, ErrorKind};
        // The plugin closed the connection before reading the hello: the read
        // side says `Refused` of the same close, so does the write side.
        for kind in [ErrorKind::BrokenPipe, ErrorKind::ConnectionReset] {
            let err = PluginError::Io(Error::from(kind)).closed_before_hello();
            assert!(matches!(err, PluginError::Refused), "{err:?}");
            assert!(!err.may_be_restarting(), "{err}");
            let said = err.to_string();
            assert!(
                said.contains("closed the connection without answering"),
                "{said}"
            );
            assert!(!said.contains("restart"), "{said}");
        }
        // Anything else is left as it was: a timeout is not a restart either.
        let timed_out = PluginError::Io(Error::from(ErrorKind::TimedOut)).closed_before_hello();
        assert!(matches!(timed_out, PluginError::Io(_)));
        assert!(!timed_out.may_be_restarting());
    }

    /// Deterministic companion to the racy end-to-end
    /// `restart_tests::an_accept_and_drop_channel_is_never_called_a_restart`:
    /// dropping the peer before `open_on` guarantees the `hello` write hits a
    /// closed socket (`BrokenPipe`) and exercises `write_wait` +
    /// `closed_before_hello` -> `Refused` on every run.
    #[test]
    fn a_hello_write_to_an_already_closed_stream_is_refused() {
        let (ours, theirs) = UnixStream::pair().unwrap();
        drop(theirs);
        let wait = Duration::from_secs(1);
        let Err(err) = open_on(ours, "t0ken", "home.lab.main", wait, Instant::now() + wait) else {
            panic!("opened on a closed stream");
        };
        assert!(matches!(err, PluginError::Refused), "{err:?}");
        assert!(!err.may_be_restarting(), "{err}");
        let said = err.to_string();
        assert!(
            said.contains("closed the connection without answering"),
            "{said}"
        );
        assert!(!said.contains("restart"), "{said}");
    }

    #[test]
    fn only_a_connection_that_failed_before_the_hello_may_be_a_restart() {
        use std::io::{Error, ErrorKind};
        let at = |kind| PluginError::Connect {
            path: "/home/alice/.enclos-app/main.sock".into(),
            source: Error::from(kind),
        };
        // The channel is not there, or is going away: a restart explains both.
        assert!(at(ErrorKind::ConnectionRefused).may_be_restarting());
        assert!(at(ErrorKind::NotFound).may_be_restarting());
        // Only the I/O kinds a peer going away produces may be a restart;
        // timeouts and other I/O failures fall back.
        for (kind, expected) in [
            (ErrorKind::BrokenPipe, true),
            (ErrorKind::ConnectionReset, true),
            (ErrorKind::ConnectionAborted, true),
            (ErrorKind::NotConnected, true),
            (ErrorKind::UnexpectedEof, true),
            (ErrorKind::TimedOut, false),
            (ErrorKind::InvalidInput, false),
            (ErrorKind::PermissionDenied, false),
            (ErrorKind::Other, false),
        ] {
            assert_eq!(
                PluginError::Io(Error::from(kind)).may_be_restarting(),
                expected,
                "Io({kind:?})"
            );
        }
        // What the plugin answered, or failed to say, is its own answer.
        assert!(
            !PluginError::Linked {
                path: "p".into(),
                source: Error::other("a link"),
            }
            .may_be_restarting()
        );
        assert!(!PluginError::Refused.may_be_restarting());
        assert!(!PluginError::Protocol("spoke oddly".into()).may_be_restarting());
        assert!(!PluginError::TooLong.may_be_restarting());
        assert!(!PluginError::Version(2).may_be_restarting());
    }

    #[test]
    fn a_file_where_the_socket_belongs_is_refused_not_called_a_restart() {
        let folder = tempfile::tempdir().unwrap();
        let socket = folder.path().join("main.sock");
        std::fs::write(&socket, b"not a socket").unwrap();
        let Err(failed) = connect(&socket, "t0ken", "home.lab.main") else {
            panic!("connected to a file");
        };
        assert!(matches!(failed, PluginError::Linked { .. }), "{failed:?}");
        assert!(!failed.may_be_restarting(), "{failed}");
        // The person's diagnostic is the one `Connect` gives: unchanged.
        let said = failed.to_string();
        assert!(
            said.contains("cannot reach the agent's app channel at"),
            "{said}"
        );
        assert!(
            said.contains("(is the sandbox started, and the channel set up?)"),
            "{said}"
        );
    }

    #[test]
    fn a_folder_this_bridge_cannot_read_is_refused_not_called_a_restart() {
        use std::os::unix::fs::PermissionsExt;
        let folder = tempfile::tempdir().unwrap();
        let own = folder.path().join(".enclos-app");
        std::fs::create_dir(&own).unwrap();
        let _plugin = UnixListener::bind(own.join("main.sock")).unwrap();
        std::fs::set_permissions(&own, std::fs::Permissions::from_mode(0o000)).unwrap();
        if std::fs::read_dir(&own).is_ok() {
            // Run as root, which reads everything.
            std::fs::set_permissions(&own, std::fs::Permissions::from_mode(0o700)).unwrap();
            return;
        }
        let failed = connect(&own.join("main.sock"), "t0ken", "home.lab.main");
        std::fs::set_permissions(&own, std::fs::Permissions::from_mode(0o700)).unwrap();
        let Err(failed) = failed else {
            panic!("connected into a folder this bridge cannot read");
        };
        assert!(matches!(failed, PluginError::Linked { .. }), "{failed:?}");
        assert!(!failed.may_be_restarting(), "{failed}");
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
    fn a_plugin_that_says_hello_and_closes_at_once_is_still_read() {
        let folder = tempfile::tempdir().unwrap();
        let socket = folder.path().join("main.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let plugin = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut out = stream.try_clone().unwrap();
            let mut line = Vec::new();
            BufReader::new(stream).read_until(b'\n', &mut line).unwrap();
            let hello = FromPlugin::Hello {
                runtime: "hermes".into(),
                agent: "main".into(),
                capabilities: vec![],
            };
            let id = MessageId::new(new_id().unwrap()).unwrap();
            out.write_all(&encode_line(&Envelope::new(id, hello)))
                .unwrap();
            out.write_all(&out_line("p-1", "last words")).unwrap();
            // Closed here, as a rule before the bridge is done with the
            // hello (on macOS, the timeout it then clears is refused).
        });
        let (hello, mut reader, _writer) = connect(&socket, "t0ken", "home.lab.main").unwrap();
        assert_eq!(hello.agent, "main");
        assert_eq!(reader.receive().unwrap().unwrap().id.as_str(), "p-1");
        assert!(reader.receive().unwrap().is_none());
        plugin.join().unwrap();
    }

    #[test]
    fn a_read_wait_on_a_closed_connection_is_no_failure() {
        let (stream, other) = UnixStream::pair().unwrap();
        drop(other);
        read_wait(&stream, Some(Duration::from_secs(5))).unwrap();
        read_wait(&stream, None).unwrap();
        assert_eq!((&stream).read(&mut [0; 8]).unwrap(), 0);
        // A zero wait is still refused, as Rust refuses it.
        assert!(read_wait(&stream, Some(Duration::ZERO)).is_err());
    }

    #[test]
    fn a_write_wait_on_a_closed_connection_is_no_failure() {
        let (stream, other) = UnixStream::pair().unwrap();
        drop(other);
        write_wait(&stream, Some(Duration::from_secs(5))).unwrap();
        write_wait(&stream, None).unwrap();
        // A zero wait is still refused, as Rust refuses it (no OS error).
        let zero = write_wait(&stream, Some(Duration::ZERO)).unwrap_err();
        assert_eq!(zero.kind(), std::io::ErrorKind::InvalidInput);
        assert!(zero.raw_os_error().is_none());
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

    #[test]
    fn connect_until_returns_a_blocking_stream() {
        let folder = tempfile::tempdir().unwrap();
        let socket = folder.path().join("main.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let wait = Duration::from_secs(1);
        let stream = connect_until(&socket, Instant::now() + wait, wait).unwrap();
        let flags = rustix::fs::fcntl_getfl(&stream).unwrap();
        assert!(
            !flags.contains(rustix::fs::OFlags::NONBLOCK),
            "expected blocking stream, got flags: {flags:?}"
        );
        let (_peer, _) = listener.accept().unwrap();
    }

    #[cfg(target_os = "linux")]
    fn full_queue_listener(socket: &Path) -> (OwnedFd, Vec<OwnedFd>) {
        let addr = rustix::net::SocketAddrUnix::new(socket).unwrap();
        let listener = rustix::net::socket_with(
            rustix::net::AddressFamily::UNIX,
            rustix::net::SocketType::STREAM,
            rustix::net::SocketFlags::CLOEXEC,
            None,
        )
        .unwrap();
        rustix::net::bind(&listener, &addr).unwrap();
        rustix::net::listen(&listener, 0).unwrap();

        let mut held = Vec::new();
        loop {
            let client = nonblocking_unix_socket().unwrap();
            match rustix::net::connect(&client, &addr) {
                Ok(()) => {
                    held.push(client);
                    assert!(held.len() < 1024, "accept queue never filled");
                }
                Err(e) if std::io::Error::from(e).kind() == std::io::ErrorKind::WouldBlock => {
                    break;
                }
                Err(e) => panic!("unexpected connect error while filling queue: {e}"),
            }
        }
        (listener, held)
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_listener_with_a_full_accept_queue_is_given_up_on_in_time() {
        let folder = tempfile::tempdir().unwrap();
        let socket = folder.path().join("main.sock");
        let (listener, held) = full_queue_listener(&socket);

        let started = Instant::now();
        let failed = connect_within(
            &socket,
            "t0ken",
            "home.lab.main",
            Duration::from_millis(400),
        );
        let elapsed = started.elapsed();
        let Err(err) = failed else {
            panic!("expected Protocol error on full queue, got Ok");
        };
        assert!(!err.may_be_restarting(), "{err}");
        let PluginError::Io(source) = &err else {
            panic!("expected a timed-out Io error on full queue, got {err:?}");
        };
        assert_eq!(source.kind(), std::io::ErrorKind::TimedOut, "{source}");
        assert!(
            source.to_string().contains("did not accept a connection"),
            "{source}"
        );
        assert!(
            elapsed >= Duration::from_millis(300) && elapsed < Duration::from_millis(1_500),
            "elapsed: {elapsed:?}"
        );
        drop(held);
        drop(listener);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_socket_replaced_with_a_link_during_queue_retry_is_refused() {
        let folder = tempfile::tempdir().unwrap();
        let own = folder.path().join(".enclos-app");
        std::fs::create_dir(&own).unwrap();
        // Nothing listens behind the link: if a connect ever follows it, the
        // attempt fails at once instead of waiting out the hello.
        let elsewhere = folder.path().join("elsewhere.sock");
        let socket = own.join("main.sock");
        let (listener, held) = full_queue_listener(&socket);

        let (entered, ready) = std::sync::mpsc::channel();
        let socket_for_thread = socket.clone();
        let started = Instant::now();
        let connecting = std::thread::spawn(move || {
            entered.send(()).unwrap();
            connect_within(
                &socket_for_thread,
                "t0ken",
                "home.lab.main",
                Duration::from_secs(1),
            )
        });

        ready.recv().unwrap();
        std::thread::sleep(Duration::from_millis(80));
        let staged = own.join("main.sock.link");
        std::os::unix::fs::symlink(&elsewhere, &staged).unwrap();
        std::fs::rename(&staged, &socket).unwrap();

        let result = connecting.join().unwrap();
        let elapsed = started.elapsed();
        let Err(PluginError::Linked { source, .. }) = result else {
            panic!(
                "expected Linked error after swap during retry, got {:?}",
                result.map(|(hello, ..)| hello)
            );
        };
        assert!(source.to_string().contains("is a link"), "{source}");
        assert!(
            elapsed < Duration::from_millis(800),
            "expected refusal before wait ended, elapsed: {elapsed:?}"
        );
        drop(held);
        drop(listener);
    }
}
