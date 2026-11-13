use super::*;

fn out(file: &str) -> OutAttachment {
    OutAttachment {
        file: file.to_owned(),
        mime: "image/png".to_owned(),
        name: "folder/unicorn.png".to_owned(),
        size: 4,
    }
}

/// A sandbox home with the plugin's `.enclos-app/media` folder, and the
/// bridge's `app-media` beside it: `(dir, home, inbox, media)`.
fn folders() -> (tempfile::TempDir, PathBuf, PathBuf, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    let inbox = home.join(".enclos-app").join("media");
    std::fs::create_dir_all(&inbox).unwrap();
    let media = dir.path().join("app-media");
    (dir, home, inbox, media)
}

#[test]
fn the_sandbox_home_is_two_folders_above_the_app_socket() {
    let layout = crate::layout::Layout::at("/srv/enclos");
    assert_eq!(
        sandbox_home(&layout.agent_app_socket("lab", "main")),
        layout.sandbox_home("lab")
    );
}

#[test]
fn a_file_of_the_media_folder_is_moved_into_the_bridges() {
    let (_dir, home, inbox, media) = folders();
    std::fs::write(inbox.join("a1.png"), b"\x89PNG").unwrap();
    let taken = take_attachment(&home, &media, "c-1", &out("a1.png")).unwrap();
    assert_eq!(
        (taken.size, taken.name.as_str(), taken.mime.as_str()),
        (4, "unicorn.png", "image/png")
    );
    assert_eq!(std::fs::read(media.join(&taken.id)).unwrap(), b"\x89PNG");
    assert!(!inbox.join("a1.png").exists(), "moved, not copied");
}

#[test]
fn a_link_a_path_or_a_folder_is_refused() {
    let (dir, home, inbox, media) = folders();
    std::fs::write(dir.path().join("secret"), b"host file").unwrap();
    std::os::unix::fs::symlink(dir.path().join("secret"), inbox.join("link.png")).unwrap();
    std::fs::create_dir(inbox.join("folder")).unwrap();
    for file in [
        "link.png",
        "../secret",
        "/etc/hosts",
        ".hidden",
        "folder",
        "",
    ] {
        assert!(
            take_attachment(&home, &media, "c-1", &out(file)).is_err(),
            "{file:?}"
        );
    }
    assert_eq!(
        std::fs::read(dir.path().join("secret")).unwrap(),
        b"host file"
    );
}

#[test]
fn a_link_in_place_of_the_media_folder_or_its_parent_is_refused() {
    // A host folder holding a file the sandbox must not reach.
    let dir = tempfile::tempdir().unwrap();
    let host = dir.path().join("host-ssh");
    std::fs::create_dir_all(host.join("media")).unwrap();
    std::fs::write(host.join("id_ed25519"), b"host key").unwrap();
    std::fs::write(host.join("media").join("id_ed25519"), b"host key").unwrap();
    let media = dir.path().join("app-media");
    // `media` is a link to the host folder.
    let home = dir.path().join("home");
    std::fs::create_dir_all(home.join(".enclos-app")).unwrap();
    std::os::unix::fs::symlink(&host, home.join(".enclos-app").join("media")).unwrap();
    // `.enclos-app` is a link to the host folder, which has a `media`.
    let other = dir.path().join("other");
    std::fs::create_dir_all(&other).unwrap();
    std::os::unix::fs::symlink(&host, other.join(".enclos-app")).unwrap();
    for home in [&home, &other] {
        let refused = take_attachment(home, &media, "c-1", &out("id_ed25519"));
        assert!(refused.is_err(), "{}", home.display());
    }
    assert_eq!(std::fs::read(host.join("id_ed25519")).unwrap(), b"host key");
    assert_eq!(
        std::fs::read(host.join("media").join("id_ed25519")).unwrap(),
        b"host key"
    );
    assert!(!media.exists(), "nothing copied");
}

#[test]
fn a_file_with_another_link_to_it_is_refused() {
    let (dir, home, inbox, media) = folders();
    std::fs::write(dir.path().join("secret"), b"host file").unwrap();
    std::fs::hard_link(dir.path().join("secret"), inbox.join("a3.png")).unwrap();
    assert!(take_attachment(&home, &media, "c-1", &out("a3.png")).is_err());
    assert_eq!(
        std::fs::read(dir.path().join("secret")).unwrap(),
        b"host file"
    );
}

#[test]
fn a_named_pipe_is_refused_at_once() {
    let (_dir, home, inbox, media) = folders();
    let made = std::process::Command::new("mkfifo")
        .arg(inbox.join("a4.png"))
        .status()
        .unwrap();
    assert!(made.success());
    let (done, result) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = done.send(take_attachment(&home, &media, "c-1", &out("a4.png")).is_err());
    });
    assert_eq!(
        result.recv_timeout(Duration::from_secs(5)),
        Ok(true),
        "refused, not waiting for a writer"
    );
}

#[test]
fn a_copy_stops_at_the_limit_and_leaves_no_file() {
    let dir = tempfile::tempdir().unwrap();
    let to = dir.path().join("grown");
    // A source that never ends, as a file the sandbox keeps writing to.
    assert!(copy_at_most(std::io::repeat(7), &to, 1000).is_err());
    assert!(!to.exists());
    assert_eq!(copy_at_most(&b"12345"[..], &to, 5), Ok(5));
    assert_eq!(std::fs::read(&to).unwrap(), b"12345");
}

#[test]
fn a_file_name_loses_its_hidden_characters() {
    let (_dir, home, inbox, media) = folders();
    std::fs::write(inbox.join("a5.pdf"), b"%PDF").unwrap();
    let mut a = out("a5.pdf");
    a.name = "report\u{202E}fdp.exe\u{200B}".to_owned();
    assert_eq!(
        take_attachment(&home, &media, "c-1", &a).unwrap().name,
        "reportfdp.exe"
    );
}

#[test]
fn a_strange_media_type_is_a_plain_file() {
    let (_dir, home, inbox, media) = folders();
    std::fs::write(inbox.join("a2.bin"), b"x").unwrap();
    let mut a = out("a2.bin");
    a.mime = "text/html; <script>".to_owned();
    assert_eq!(
        take_attachment(&home, &media, "c-1", &a).unwrap().mime,
        "application/octet-stream"
    );
}

/// A hub with no agent, its database in `dir`, and one connected device
/// for each of `people`: what each of them receives.
fn hub_with(
    dir: &std::path::Path,
    people: &[&str],
) -> (Hub, Vec<std::sync::mpsc::Receiver<ToDevice>>) {
    let mut devices = HashMap::new();
    let mut received = Vec::new();
    for (i, person) in people.iter().enumerate() {
        let (sender, receiver) = channel();
        devices.insert(format!("d-{i}"), ((*person).to_owned(), sender, i as u64));
        received.push(receiver);
    }
    let hub = Hub {
        transport: Transport::Tailscale,
        whois: Arc::new(|_: &str| Err("no transport in this test".to_owned())),
        store_path: dir.join("app.db"),
        bridge_private: vec![0; 32],
        agents: Vec::new(),
        plugins: Mutex::new(HashMap::new()),
        generations: AtomicU64::new(0),
        devices: Mutex::new(devices),
        waiting: AtomicUsize::new(0),
        refusals: Mutex::new(HashMap::new()),
        silence: SILENCE,
    };
    (hub, received)
}

#[test]
fn only_the_owner_moves_how_far_a_conversation_was_read() {
    let dir = tempfile::tempdir().unwrap();
    let (hub, received) = hub_with(dir.path(), &["alice@example.com", "bob@example.com"]);
    let store = hub.store().unwrap();
    store
        .conversation("c-1", "lab", "main", "alice@example.com")
        .unwrap();
    for id in ["m-1", "m-2", "m-3"] {
        store.add(id, "c-1", &From::Agent, "hi", "reply").unwrap();
    }
    let c1 = ConversationId::new("c-1").unwrap();
    let read_of = |store: &Store| store.conversation_info("c-1").unwrap().unwrap().read;
    // Another person's device: nothing moves, and nobody is told.
    read(&hub, &store, "bob@example.com", &c1, 2).unwrap();
    assert_eq!(read_of(&store), None);
    assert!(received.iter().all(|r| r.try_recv().is_err()));
    // The owner's: kept, and sent to the owner's devices only.
    read(&hub, &store, "alice@example.com", &c1, 2).unwrap();
    assert_eq!(read_of(&store), Some(2));
    match received[0].try_recv() {
        Ok(ToDevice::Conversation(info)) => assert_eq!(info.read, Some(2)),
        other => panic!("expected the conversation, got {other:?}"),
    }
    assert!(received[1].try_recv().is_err());
}

#[test]
fn an_agents_message_goes_to_its_own_conversation_else_to_its_home() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("app.db")).unwrap();
    let host = Some("victor@example.com");
    store
        .conversation("c-a", "lab", "a", "alice@example.com")
        .unwrap();
    store
        .conversation("c-b", "lab", "b", "bob@example.com")
        .unwrap();
    let id = |s: &str| ConversationId::new(s).unwrap();
    assert_eq!(
        destination(&store, host, "lab/a", id("c-a")),
        Some(id("c-a"))
    );
    // Another agent's conversation, or one the bridge does not know: Home,
    // the host's person's.
    for other in ["c-b", "c-unknown"] {
        assert_eq!(
            destination(&store, host, "lab/a", id(other)),
            Some(id("home.lab.a"))
        );
    }
    assert_eq!(
        store.owner("home.lab.a").unwrap().as_deref(),
        Some("victor@example.com")
    );
    // An agent whose Home's id the protocol refuses (longer than an id may
    // be): nothing, which the caller acknowledges.
    let long = format!("lab/{}", "a".repeat(130));
    assert_eq!(destination(&store, host, &long, id("c-unknown")), None);
    assert_eq!(store.conversation_info(&home_id(&long)).unwrap(), None);
}

#[test]
fn a_forgotten_device_is_unpaired_and_logged() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("app.db")).unwrap();
    let phone = Device {
        id: "d-1".to_owned(),
        name: "Pixel".to_owned(),
        person: "alice@example.com".to_owned(),
        noise_key: vec![1; 32],
        device_key: vec![2; 32],
        push_key: vec![3; 32],
        push_token: None,
        paired: 1,
        seen: None,
        node: Some("n-pixel".to_owned()),
    };
    store.add_device(&phone).unwrap();
    forget(&store, &phone, "alice@example.com").unwrap();
    // Its keys find no device: `connection` refuses the next `auth` with
    // them as "an unknown device".
    assert_eq!(store.device_by_noise_key(&phone.noise_key).unwrap(), None);
    assert!(store.devices().unwrap().is_empty());
    let last = store.log_lines(1).unwrap().pop().unwrap();
    assert_eq!(
        (
            last.device.as_deref(),
            last.person.as_deref(),
            last.event.as_str(),
            last.reason.as_deref()
        ),
        (
            Some("d-1"),
            Some("alice@example.com"),
            "unpaired",
            Some("forgotten on the device")
        )
    );
}

#[test]
fn a_message_takes_at_most_ten_files() {
    let (dir, home, inbox, media) = folders();
    let store = Store::open(&dir.path().join("app.db")).unwrap();
    store
        .conversation("c-1", "lab", "main", "alice@example.com")
        .unwrap();
    store
        .add("m-1", "c-1", &From::Agent, "files", "reply")
        .unwrap();
    let files: Vec<OutAttachment> = (0..12)
        .map(|i| {
            let file = format!("f{i}.png");
            std::fs::write(inbox.join(&file), b"x").unwrap();
            out(&file)
        })
        .collect();
    let taken = take_attachments(&store, &home, &media, "lab/main", "c-1", "m-1", &files);
    assert_eq!(taken.len(), MAX_ATTACHMENTS);
    assert_eq!(store.attachments_of("m-1").unwrap().len(), MAX_ATTACHMENTS);
    assert!(inbox.join("f11.png").exists(), "not taken");
}

#[test]
fn a_file_that_cannot_be_recorded_leaves_none_behind() {
    let (dir, home, inbox, media) = folders();
    let path = dir.path().join("app.db");
    let store = Store::open(&path).unwrap();
    store
        .conversation("c-1", "lab", "main", "alice@example.com")
        .unwrap();
    rusqlite::Connection::open(&path)
        .unwrap()
        .execute_batch("DROP TABLE attachments")
        .unwrap();
    std::fs::write(inbox.join("a6.png"), b"x").unwrap();
    let taken = take_attachments(
        &store,
        &home,
        &media,
        "lab/main",
        "c-1",
        "m-1",
        &[out("a6.png")],
    );
    assert!(taken.is_empty());
    assert_eq!(std::fs::read_dir(&media).unwrap().count(), 0, "no orphan");
}

#[test]
fn home_keeps_its_name() {
    let dir = tempfile::tempdir().unwrap();
    let (hub, _received) = hub_with(dir.path(), &["alice@example.com"]);
    let hub = Arc::new(hub);
    let store = hub.store().unwrap();
    store
        .ensure_home("lab/main", "alice@example.com", true)
        .unwrap();
    let home = ConversationId::new("home.lab.main").unwrap();
    // Neither renamed nor cleared, which would let the runtime's names in
    for title in ["Mine", ""] {
        rename(&hub, &store, "alice@example.com", &home, title).unwrap();
    }
    let titled = store
        .conversations("alice@example.com")
        .unwrap()
        .into_iter()
        .find(|c| c.id == "home.lab.main")
        .unwrap();
    assert_eq!(titled.title.as_deref(), Some("Home"));
}
