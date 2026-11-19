//! A person's message with files, from a device through the bridge to the
//! agent's plugin (ADR 0076, proposed). The bounds of one file or part are
//! the protocol crate's and the plugin's own tests.

use super::*;
use enclos_protocol::incoming::{
    Begin, IncomingFile, MAX_FILE_BYTES, MAX_PART_BYTES, Part, PartData,
};
use std::process::{Child, ChildStdout, Command, Stdio};

fn file(name: &str, mime: &str, size: usize) -> IncomingFile {
    IncomingFile::new(name.into(), mime.into(), size as u64).unwrap()
}

fn bytes(size: usize, seed: u8) -> Vec<u8> {
    (0..size)
        .map(|i| (i as u8).wrapping_mul(31) ^ seed)
        .collect()
}

fn begin(device: &mut PhoneLink, id: &str, conversation: &str, text: &str, files: &[IncomingFile]) {
    let begin = Begin {
        conversation: ConversationId::new(conversation).unwrap(),
        text: text.into(),
        files: files.to_vec(),
    };
    device.send(id, FromDevice::MessageBegin(begin));
}

fn part(device: &mut PhoneLink, id: &str, message: &str, file: u8, offset: u64, data: &[u8]) {
    let part = Part {
        message: MessageId::new(message).unwrap(),
        file,
        offset,
        data: PartData::new(data.to_vec()).unwrap(),
    };
    device.send(id, FromDevice::MessagePart(part));
}

/// Every byte of `contents`, file after file, in parts.
fn send_all(device: &mut PhoneLink, message: &str, contents: &[Vec<u8>]) {
    let mut n = 0;
    for (i, content) in contents.iter().enumerate() {
        for (k, chunk) in content.chunks(MAX_PART_BYTES).enumerate() {
            n += 1;
            let (id, offset) = (format!("{message}-p{n}"), (k * MAX_PART_BYTES) as u64);
            part(device, &id, message, i as u8, offset, chunk);
        }
    }
}

/// A stand-in plugin at `socket` that names `incoming_files` when
/// `takes_files`, and keeps every `message.in` and `message.part` it gets.
/// It acknowledges none: in these tests, nothing is to reach it.
fn files_plugin(socket: &Path, takes_files: bool) -> Arc<Mutex<Vec<FromBridge>>> {
    let listener = UnixListener::bind(socket).unwrap();
    let got = Arc::new(Mutex::new(Vec::new()));
    let kept = Arc::clone(&got);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let stream = stream.unwrap();
            let mut out = stream.try_clone().unwrap();
            let mut lines = BufReader::new(stream);
            let mut line = Vec::new();
            while lines.read_until(b'\n', &mut line).unwrap_or(0) > 0 {
                let message = decode_from_bridge(&line).unwrap();
                line.clear();
                match message.body {
                    FromBridge::Hello { .. } => {
                        let capabilities =
                            Vec::from_iter(takes_files.then_some(Capability::IncomingFiles));
                        let hello = FromPlugin::Hello {
                            runtime: "hermes".into(),
                            agent: "main".into(),
                            capabilities,
                        };
                        let id = MessageId::new(new_id().unwrap()).unwrap();
                        let _ = out.write_all(&encode_line(&Envelope::new(id, hello)));
                    }
                    body @ (FromBridge::MessageIn { .. } | FromBridge::MessagePart(_)) => {
                        kept.lock().unwrap().push(body)
                    }
                    _ => {}
                }
            }
        }
    });
    got
}

/// What the bridge answered `of`: an `error`'s code, or `None` for `ack`.
fn answer_to(device: &mut PhoneLink, of: &str) -> Option<ErrorCode> {
    loop {
        match device.receive().expect("closed") {
            ToDevice::Ack { of: acked } if acked.as_str() == of => return None,
            ToDevice::Error(e) if e.of.as_ref().map(MessageId::as_str) == Some(of) => {
                return Some(e.code);
            }
            _ => {}
        }
    }
}

/// The files left in the bridge's `.incoming` folder.
fn incoming_left(bridge: &Bridge) -> usize {
    let media = bridge.store.with_file_name(crate::layout::APP_MEDIA_DIR);
    std::fs::read_dir(media.join(INCOMING)).map_or(0, |entries| entries.count())
}

/// A bridge serving `lab/main` at `socket`, a paired device of its host's
/// person connected and synced, with conversation `c-1` started.
fn ready(folder: &Path, socket: PathBuf) -> (Bridge, PhoneLink) {
    let main = vec![AgentEndpoint {
        name: "lab/main".to_owned(),
        runtime: "hermes".to_owned(),
        socket,
        token: TOKEN.to_owned(),
    }];
    let host = Host::new(
        crate::layout::Layout::at(folder.join("enclos")),
        "/unused/enclos".into(),
    );
    let bridge = bridge_built(folder, SILENCE, host, main, None);
    let phone = paired(&bridge, "n-pixel");
    let (mut device, first) = connect(&bridge, &phone);
    assert!(
        matches!(first, Some(ToDevice::Authenticated { capabilities, .. }) if capabilities.iter().any(|c| c == enclos_protocol::device::MESSAGE_BEGIN))
    );
    start_conversation(&mut device);
    synced(&mut device, 0);
    (bridge, device)
}

#[test]
fn a_plugin_that_takes_no_files_or_a_group_refuses_the_whole_message() {
    let folder = tempfile::tempdir().unwrap();
    let socket = folder.path().join("main.sock");
    let got = files_plugin(&socket, false);
    let (bridge, mut device) = ready(folder.path(), socket);
    let one = [file("a.txt", "text/plain", 2)];
    begin(&mut device, "m-1", "c-1", "look", &one);
    assert_eq!(answer_to(&mut device, "m-1"), Some(ErrorCode::Unsupported));
    // Its parts name no message being sent
    part(&mut device, "p-1", "m-1", 0, 0, b"hi");
    assert_eq!(answer_to(&mut device, "p-1"), Some(ErrorCode::BadMessage));
    let store = Store::open(&bridge.store).unwrap();
    store
        .group("g-1", "lab", &["main".into(), "coder".into()], PERSON)
        .unwrap();
    begin(&mut device, "m-2", "g-1", "look", &one);
    assert_eq!(answer_to(&mut device, "m-2"), Some(ErrorCode::NotAllowed));
    // /sethome is answered, not run: its files would go nowhere
    begin(&mut device, "m-3", "c-1", " /SetHome", &one);
    assert_eq!(answer_to(&mut device, "m-3"), Some(ErrorCode::NotAllowed));
    // Nothing stored, nothing given to the agent, not even the text
    assert!(synced(&mut device, 0).0.is_empty());
    assert!(got.lock().unwrap().is_empty());
    assert_eq!(incoming_left(&bridge), 0);
}

#[test]
fn a_part_that_is_not_the_next_or_goes_past_its_size_drops_the_message() {
    let folder = tempfile::tempdir().unwrap();
    let socket = folder.path().join("main.sock");
    let got = files_plugin(&socket, true);
    let (bridge, mut device) = ready(folder.path(), socket);
    let files = [
        file("a.txt", "text/plain", 4),
        file("b.txt", "text/plain", 2),
    ];
    // A gap
    begin(&mut device, "m-1", "c-1", "", &files);
    part(&mut device, "p-1", "m-1", 0, 1, b"bc");
    assert_eq!(answer_to(&mut device, "m-1"), Some(ErrorCode::BadMessage));
    // The second file before the first is whole
    begin(&mut device, "m-2", "c-1", "", &files);
    part(&mut device, "p-2", "m-2", 0, 0, b"ab");
    part(&mut device, "p-3", "m-2", 1, 0, b"xy");
    assert_eq!(answer_to(&mut device, "m-2"), Some(ErrorCode::BadMessage));
    // More bytes than declared
    begin(&mut device, "m-3", "c-1", "", &files);
    part(&mut device, "p-4", "m-3", 0, 0, b"abcde");
    assert_eq!(answer_to(&mut device, "m-3"), Some(ErrorCode::BadMessage));
    // A part that cannot be read: the message is dropped, its next part too
    begin(&mut device, "m-6", "c-1", "", &files);
    part(&mut device, "p-7", "m-6", 0, 0, b"ab");
    device.send_raw(br#"{"v":1,"type":"message.part","id":"p-8","message":"m-6","file":0,"offset":2,"data":"a+b/"}
"#);
    assert_eq!(answer_to(&mut device, "m-6"), Some(ErrorCode::BadMessage));
    part(&mut device, "p-9", "m-6", 0, 2, b"cd");
    assert_eq!(answer_to(&mut device, "p-9"), Some(ErrorCode::BadMessage));
    assert_eq!(incoming_left(&bridge), 0);
    // A second message while one is being sent
    begin(&mut device, "m-4", "c-1", "", &files);
    begin(&mut device, "m-5", "c-1", "", &files);
    assert_eq!(answer_to(&mut device, "m-5"), Some(ErrorCode::Conflict));
    part(&mut device, "p-5", "m-4", 0, 0, b"abcd");
    part(&mut device, "p-6", "m-4", 1, 0, b"x");
    assert!(eventually(|| incoming_left(&bridge) == 2));
    // The connection ends with m-4 one byte short: it is dropped
    drop(device);
    assert!(eventually(|| incoming_left(&bridge) == 0));
    let store = Store::open(&bridge.store).unwrap();
    assert_eq!(store.newest_seq().unwrap(), 0);
    assert!(got.lock().unwrap().is_empty());
}

/// Home changes owner while its files are sent: the message is refused at
/// its last byte, its copies go, nothing is stored or given to the agent.
/// One sent whole before the change is stored and given, as ever.
#[test]
fn a_conversation_that_changes_owner_while_files_are_sent_refuses_them() {
    let folder = tempfile::tempdir().unwrap();
    let socket = folder.path().join("main.sock");
    let got = files_plugin(&socket, true);
    let (bridge, mut device) = ready(folder.path(), socket);
    let store = Store::open(&bridge.store).unwrap();
    store.ensure_home("lab/main", PERSON, true).unwrap();
    let two = [file("a.txt", "text/plain", 2)];
    begin(&mut device, "m-1", "home.lab.main", "", &two);
    part(&mut device, "p-1", "m-1", 0, 0, b"ok");
    assert_eq!(answer_to(&mut device, "m-1"), None);
    assert!(eventually(|| got.lock().unwrap().len() == 2));
    let seq = store.newest_seq().unwrap();
    begin(&mut device, "m-2", "home.lab.main", "", &two);
    part(&mut device, "p-2", "m-2", 0, 0, b"a");
    // Its first byte is kept: the message was let in
    assert!(eventually(|| incoming_left(&bridge) == 1));
    store.set_host("someone@example.com").unwrap();
    part(&mut device, "p-3", "m-2", 0, 1, b"b");
    assert_eq!(answer_to(&mut device, "m-2"), Some(ErrorCode::NotAllowed));
    assert_eq!(incoming_left(&bridge), 0);
    assert_eq!(store.newest_seq().unwrap(), seq);
    assert_eq!(got.lock().unwrap().len(), 2);
}

/// The Hermes plugin's own adapter, in Python, on a socket in a synthetic
/// sandbox home (a temporary folder laid out as one; no sandbox runs),
/// stopped if the test fails first.
struct Peer(Child, BufReader<ChildStdout>);

impl Drop for Peer {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

impl Peer {
    fn start(socket: &Path) -> Self {
        let script =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("channels/hermes/tests/bridge_peer.py");
        let mut child = Command::new("python3")
            .arg("-I")
            .arg(&script)
            .args([socket.as_os_str(), TOKEN.as_ref()])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let out = BufReader::new(child.stdout.take().unwrap());
        Peer(child, out)
    }

    fn line(&mut self) -> String {
        let mut line = String::new();
        self.1.read_line(&mut line).unwrap();
        line
    }
}

/// As many files as a message carries, one as large as a file may be: the
/// bridge stores and echoes the message, then streams every byte to the
/// plugin, which writes the files in the sandbox home and gives Hermes
/// them as media with the message.
#[test]
fn a_message_with_files_reaches_the_hermes_plugin_whole_in_the_sandbox_home() {
    let folder = tempfile::tempdir().unwrap();
    let home = folder.path().join("home");
    let socket = home.join(".enclos-app").join("main.sock");
    let mut peer = Peer::start(&socket);
    assert_eq!(peer.line(), "listening\n");
    let (bridge, mut device) = ready(folder.path(), socket);
    let contents = vec![
        bytes(MAX_FILE_BYTES as usize, 1),
        bytes(MAX_PART_BYTES + 1, 2),
        b"line one\n".to_vec(),
        bytes(1, 4),
    ];
    let files = [
        file("scan.pdf", "application/pdf", contents[0].len()),
        file("Beach photo.JPG", "image/jpeg", contents[1].len()),
        file("notes.txt", "text/plain", contents[2].len()),
        file("dot.png", "image/png", 1),
    ];
    begin(&mut device, "m-1", "c-1", "have a look", &files);
    send_all(&mut device, "m-1", &contents);
    let echo = loop {
        match device.receive().expect("closed") {
            ToDevice::Message(m) => break m,
            ToDevice::Error(e) => panic!("{e:?}"),
            _ => {}
        }
    };
    assert_eq!(echo.text, "have a look");
    let shown: Vec<_> = echo.attachments.iter().map(|a| (&a.name, a.size)).collect();
    let declared: Vec<_> = files.iter().map(|f| (&f.name, f.size)).collect();
    assert_eq!(shown, declared);
    assert_eq!(answer_to(&mut device, "m-1"), None);
    // Kept with the message, as an agent's files are, for its devices
    let media = bridge.store.with_file_name(crate::layout::APP_MEDIA_DIR);
    let kept = std::fs::read(media.join(&echo.attachments[1].id)).unwrap();
    assert_eq!(kept, contents[1]);
    // What Hermes got: printed once its message is whole
    let event: serde_json::Value = serde_json::from_str(&peer.line()).unwrap();
    assert_eq!(event["text"], "have a look");
    assert_eq!(event["message_type"], "photo");
    let types: Vec<_> = files.iter().map(|f| f.mime.as_str()).collect();
    assert_eq!(event["media_types"], serde_json::json!(types));
    let urls = event["media_urls"].as_array().unwrap();
    assert_eq!(urls.len(), 4);
    let inbox = home.join(".enclos-app").join("incoming").join("main");
    for (url, content) in urls.iter().zip(&contents) {
        let path = Path::new(url.as_str().unwrap());
        assert_eq!(path.parent().unwrap().parent().unwrap(), inbox);
        assert_eq!(&std::fs::read(path).unwrap(), content);
    }
    assert!(urls[1].as_str().unwrap().ends_with("/2-Beach photo.JPG"));
    // The plugin's ack is stored before the folder, and the database in it,
    // goes; the peer stops when its input closes
    let store = Store::open(&bridge.store).unwrap();
    assert!(eventually(|| store
        .pending("lab", "main")
        .unwrap()
        .is_empty()));
    assert_eq!(incoming_left(&bridge), 0);
    drop(peer.0.stdin.take());
    assert!(peer.0.wait().unwrap().success());
}
