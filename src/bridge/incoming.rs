//! A person's message with files (ADR 0076, proposed; `docs/protocol.md`,
//! Sending files). On the device leg, `message.begin` and then its files'
//! bytes in `message.part`s on the same connection; on the plugin leg,
//! `message.in` with `files` and then the same parts. Nothing of it
//! outlives the device's connection but a stored message: a message whose
//! bytes did not all come is dropped, and the device sends it again.

use std::io::{Read, Write};

use enclos_protocol::incoming::{Begin, IncomingFile, MAX_PART_BYTES, Part, PartData};

use super::*;
use crate::bridge::plugin::PluginError;
use crate::bridge::store::NotStored;

/// A message with files coming from a device, held by its connection
/// alone. Its files are written in the bridge's `.incoming` folder, and
/// removed when it is dropped unless the message was stored with them.
pub(super) struct Upload {
    id: MessageId,
    conversation: ConversationId,
    /// Its agent, as `sandbox/agent`, and the two apart: the destination
    /// it was let in for, checked again as it is stored.
    agent: String,
    to: (String, String),
    text: String,
    files: Vec<IncomingFile>,
    /// The bridge's id of each file, and its copy in `.incoming`.
    copies: Vec<(String, PathBuf)>,
    /// The file being written, and how many of its bytes came.
    at: usize,
    offset: u64,
    open: Option<std::fs::File>,
    kept: bool,
}

impl Drop for Upload {
    fn drop(&mut self) {
        if !self.kept {
            for (_, copy) in &self.copies {
                let _ = std::fs::remove_file(copy);
            }
        }
    }
}

fn refuse(of: &MessageId, code: ErrorCode, message: &str) -> Result<Option<ToDevice>, String> {
    Ok(Some(ToDevice::Error(ErrorBody {
        of: Some(of.clone()),
        code,
        message: message.to_owned(),
    })))
}

/// `message.begin`: checks who may send what where, and that the agent's
/// plugin takes files now, then makes the files' copies. What to answer
/// the device when it is refused; nothing while its bytes are awaited.
pub(super) fn begin(
    hub: &Arc<Hub>,
    store: &Store,
    device: &Device,
    upload: &mut Option<Upload>,
    id: MessageId,
    Begin {
        conversation,
        text,
        files,
    }: Begin,
) -> Result<Option<ToDevice>, String> {
    use ErrorCode::*;
    if upload.is_some() {
        return refuse(
            &id,
            Conflict,
            "Another message with files is still being sent.",
        );
    }
    let person = device.person.as_str();
    let owned = store
        .conversation_of(conversation.as_str())
        .map_err(|e| e.to_string())?
        .filter(|(_, _, owner)| owner == person);
    let Some((sandbox, agent, _)) = owned else {
        return refuse(&id, NotAllowed, "No such conversation.");
    };
    if store
        .deletion_started(conversation.as_str())
        .map_err(|e| e.to_string())?
    {
        return refuse(&id, Conflict, "This conversation is being deleted.");
    }
    let group = group_of(store, conversation.as_str()).map_err(|e| e.to_string())?;
    if group.is_some() {
        return refuse(&id, NotAllowed, "Files go to one agent, not to a group.");
    }
    if questions::typed_approval(&text) {
        let why = "Runtime approvals are decided with the app's buttons, not typed commands.";
        return refuse(&id, NotAllowed, why);
    }
    if home_command(&text) {
        // Answered by the plugin, not given to the runtime: its files would be lost
        let why = "/sethome is answered, not run: send the files with another message.";
        return refuse(&id, NotAllowed, why);
    }
    let name = format!("{sandbox}/{agent}");
    // Its echo, its files' ids as long as the bridge's, fits one message
    let echo = echo(&conversation, &name, person, &text, &files, "f".repeat(36));
    if split_text(&echo).len() > 1 {
        return refuse(
            &id,
            BadMessage,
            "longer than one message on the device leg holds",
        );
    }
    if let Err(e) = hub.plugin(&name) {
        let why = format!("{e}: nothing was sent; send it again once the agent can be reached");
        return refuse(&id, AgentUnavailable, &why);
    }
    if !takes_files(
        hub,
        &name,
        files.iter().any(|f| f.mime.starts_with("image/")),
    ) {
        let why = if takes_files(hub, &name, false) {
            "This agent's app channel does not take images; documents remain available: nothing was sent."
        } else {
            "This agent's app channel does not take files: nothing was sent."
        };
        return refuse(&id, Unsupported, why);
    }
    let incoming = hub.media().join(INCOMING);
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&incoming)
            .map_err(|e| format!("{}: {e}", incoming.display()))?;
    }
    let mut made = Upload {
        id,
        conversation,
        agent: name,
        to: (sandbox, agent),
        text,
        files,
        copies: Vec::new(),
        at: 0,
        offset: 0,
        open: None,
        kept: false,
    };
    for _ in 0..made.files.len() {
        let file = new_id().map_err(|e| e.to_string())?;
        let copy = incoming.join(&file);
        made.copies.push((file, copy));
    }
    *upload = Some(made);
    Ok(None)
}

/// `message.part`: the next bytes of the message being sent, written to
/// its file's copy. A part that is not the next one, or that goes past its
/// file's declared size, drops the whole message. Once every declared byte
/// came, the message is stored with its files ([`finish`]). What to answer
/// the device, after what its outbox holds.
pub(super) fn part(
    hub: &Arc<Hub>,
    store: &Store,
    device: &Device,
    upload: &mut Option<Upload>,
    of: MessageId,
    part: Part,
) -> Result<Option<ToDevice>, String> {
    let Some(u) = upload.as_mut().filter(|u| u.id == part.message) else {
        let why = "No message with files is being sent under that id.";
        return refuse(&of, ErrorCode::BadMessage, why);
    };
    let bytes = part.data.bytes();
    let size = u.files[u.at].size;
    let (at, offset) = (u.at, u.offset);
    if usize::from(part.file) != at || part.offset != offset {
        let why = format!("expected file {at} from byte {offset}: the message was not sent");
        let id = upload.take().expect("held").id.clone();
        return refuse(&id, ErrorCode::BadMessage, &why);
    }
    if offset + bytes.len() as u64 > size {
        let why = format!("file {at} is longer than its {size} bytes: the message was not sent");
        let id = upload.take().expect("held").id.clone();
        return refuse(&id, ErrorCode::BadMessage, &why);
    }
    let written = match u.open.take() {
        Some(file) => Ok(file),
        None => {
            use std::os::unix::fs::OpenOptionsExt;
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&u.copies[u.at].1)
        }
    }
    .and_then(|mut file| file.write_all(bytes).map(|()| file));
    match written {
        Ok(file) => u.open = Some(file),
        Err(e) => {
            eprintln!("enclos app: a file of {} cannot be written: {e}", u.agent);
            let id = upload.take().expect("held").id.clone();
            let why = "The bridge could not keep the file: the message was not sent.";
            return refuse(&id, ErrorCode::Internal, why);
        }
    }
    u.offset += bytes.len() as u64;
    if u.offset == size {
        u.open = None;
        u.at += 1;
        u.offset = 0;
    }
    if u.at < u.files.len() {
        return Ok(None);
    }
    finish(hub, store, device, upload.take().expect("held"))
}

/// Stores the message with its files, as one, and gives it to the agent's
/// plugin; the device is answered `ack`, after the echo.
fn finish(
    hub: &Arc<Hub>,
    store: &Store,
    device: &Device,
    mut u: Upload,
) -> Result<Option<ToDevice>, String> {
    let person = device.person.as_str();
    // Its plugin may have connected again since, as one that takes no files
    if !takes_files(
        hub,
        &u.agent,
        u.files.iter().any(|f| f.mime.starts_with("image/")),
    ) {
        let why = if takes_files(hub, &u.agent, false) {
            "This agent's app channel does not take images; documents remain available: nothing was sent."
        } else {
            "This agent's app channel does not take files: nothing was sent."
        };
        return refuse(&u.id, ErrorCode::Unsupported, why);
    }
    let stored: Vec<StoredAttachment> = u
        .files
        .iter()
        .zip(&u.copies)
        .map(|(f, (id, _))| StoredAttachment {
            id: id.clone(),
            conversation: u.conversation.as_str().to_owned(),
            mime: f.mime.clone(),
            name: f.name.clone(),
            size: f.size as i64,
        })
        .collect();
    // Sent again (the device did not hear back): stored the first time
    let origin = format!("{}/{}", device.id, u.id.as_str());
    let stored_as = new_id().map_err(|e| e.to_string())?;
    // Still the person's, to the same agent alone: else its copies go with `u`
    let to = (u.conversation.as_str(), u.to.0.as_str(), u.to.1.as_str());
    let added = match store
        .add_from_device_with_files(&origin, &stored_as, to, person, &u.text, &stored)
        .map_err(|e| e.to_string())?
    {
        Ok(added) => added,
        Err(NotStored::NotAllowed) => {
            return refuse(&u.id, ErrorCode::NotAllowed, "No such conversation.");
        }
        Err(NotStored::Deleting) => {
            let why = "This conversation is being deleted.";
            return refuse(&u.id, ErrorCode::Conflict, why);
        }
    };
    let new = matches!(added, Added::New(_));
    if let Added::New(seq) = added {
        // Recorded: one not moved now is moved when the bridge starts again
        u.kept = true;
        let media = hub.media();
        for (id, copy) in &u.copies {
            if let Err(e) = std::fs::rename(copy, media.join(id)) {
                eprintln!("enclos app: a file stays in .incoming: {e}");
            }
        }
        let mut message = echo(
            &u.conversation,
            &u.agent,
            person,
            &u.text,
            &[],
            String::new(),
        );
        message.seq = seq;
        message.attachments = stored.into_iter().map(attachment_info).collect();
        hub.deliver(person, ToDevice::Message(message));
    }
    // Acknowledged once its plugin was sent it: `forward` passes over a
    // message whose files it cannot send now
    let why = match hub.forward(store, &u.agent) {
        Ok(()) if !new || handed_over(hub, store, &u.agent, &stored_as)? => {
            return Ok(Some(ToDevice::Ack { of: u.id.clone() }));
        }
        Ok(()) => "its files could not be given to the agent's app channel".to_owned(),
        Err(e) => e,
    };
    let why = format!("{why}: the message is kept, and goes to the agent once it can be reached");
    refuse(&u.id, ErrorCode::AgentUnavailable, &why)
}

/// What the device is told when a line it sent could not be read while a
/// message with files was being sent: that message is dropped, whole.
pub(super) fn dropped(upload: &mut Option<Upload>) -> Option<ToDevice> {
    let u = upload.take()?;
    let why = "A line could not be read while the files were sent: the message was not sent.";
    refuse(&u.id, ErrorCode::BadMessage, why).ok().flatten()
}

/// Whether `agent`'s plugin, connected now, names `incoming_files`.
fn takes_files(hub: &Hub, agent: &str, images: bool) -> bool {
    let plugins = hub.plugins.lock().expect("not poisoned");
    plugins.get(agent).is_some_and(|p| {
        p.capabilities.contains(&Capability::IncomingFiles)
            && (!images || p.capabilities.contains(&Capability::IncomingImages))
    })
}

/// Whether stored message `id` was sent to `agent`'s plugin, or taken by it.
fn handed_over(hub: &Hub, store: &Store, agent: &str, id: &str) -> Result<bool, String> {
    let (sandbox, name) = agent.split_once('/').unwrap_or((agent, ""));
    let pending = store.pending(sandbox, name).map_err(|e| e.to_string())?;
    if !pending.iter().any(|m| m.id == id) {
        return Ok(true);
    }
    let plugins = hub.plugins.lock().expect("not poisoned");
    let out = plugins.get(agent).map(|p| Arc::clone(&p.out));
    drop(plugins);
    Ok(out.is_some_and(|out| out.lock().expect("not poisoned").sent.contains(id)))
}

/// Whether `text` is `/sethome` (or `/set-home`), which the plugin answers
/// without giving it to the runtime (ADR 0044).
fn home_command(text: &str) -> bool {
    let first = text.split_whitespace().next().unwrap_or_default();
    ["/sethome", "/set-home"]
        .iter()
        .any(|c| first.eq_ignore_ascii_case(c))
}

/// The echo of a person's message with `files`, each named `id` until it is
/// stored.
fn echo(
    conversation: &ConversationId,
    agent: &str,
    person: &str,
    text: &str,
    files: &[IncomingFile],
    id: String,
) -> ConversationMessage {
    ConversationMessage {
        suggested_replies: Vec::new(),
        question: None,
        held_task: None,
        // A person's message is never a runtime's task event.
        task_event: None,
        conversation: conversation.clone(),
        agent: agent.to_owned(),
        from: person.to_owned(),
        text: text.to_owned(),
        kind: "message".to_owned(),
        time: now(),
        seq: 0,
        attachments: files
            .iter()
            .map(|f| Attachment {
                id: id.clone(),
                mime: f.mime.clone(),
                name: f.name.clone(),
                size: f.size,
            })
            .collect(),
    }
}

/// The files of stored message `id`, each opened in the bridge's media
/// folder and found at its recorded size, as its plugin is sent them.
pub(super) fn stored_files(
    hub: &Hub,
    store: &Store,
    id: &str,
) -> Result<Vec<(IncomingFile, std::fs::File)>, String> {
    let mut files = Vec::new();
    for a in store.attachments_of(id).map_err(|e| e.to_string())? {
        let size = u64::try_from(a.size).map_err(|e| e.to_string())?;
        let file = IncomingFile::new(a.name, a.mime, size).map_err(|e| e.to_string())?;
        // The id is the bridge's own (a UUID), never a path from a device
        let opened = std::fs::File::open(hub.media().join(&a.id)).map_err(|e| e.to_string())?;
        if opened.metadata().map_err(|e| e.to_string())?.len() != size {
            return Err(format!("file {} is not its recorded size", a.id));
        }
        files.push((file, opened));
    }
    Ok(files)
}

/// Sends `message.in` `body` as `id`, then every byte of `files` in parts.
pub(super) fn send_with_files(
    writer: &mut PluginWriter,
    id: &MessageId,
    body: FromBridge,
    files: Vec<(IncomingFile, std::fs::File)>,
) -> Result<(), PluginError> {
    writer.send_as(id, body)?;
    let mut buffer = vec![0; MAX_PART_BYTES];
    for (n, (file, mut opened)) in files.into_iter().enumerate() {
        let mut offset = 0;
        while offset < file.size {
            let len = MAX_PART_BYTES.min((file.size - offset) as usize);
            opened.read_exact(&mut buffer[..len])?;
            let data = PartData::new(buffer[..len].to_vec())
                .map_err(|e| PluginError::Protocol(e.to_string()))?;
            writer.send(FromBridge::MessagePart(Part {
                message: id.clone(),
                file: n as u8,
                offset,
                data,
            }))?;
            offset += len as u64;
        }
    }
    Ok(())
}
