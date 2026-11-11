use super::*;

fn out(file: &str) -> OutAttachment {
    OutAttachment {
        file: file.to_owned(),
        mime: "image/png".to_owned(),
        name: "folder/unicorn.png".to_owned(),
        size: 4,
    }
}

#[test]
fn a_file_of_the_media_folder_is_moved_into_the_bridges() {
    let dir = tempfile::tempdir().unwrap();
    let (inbox, media) = (dir.path().join("media"), dir.path().join("app-media"));
    std::fs::create_dir(&inbox).unwrap();
    std::fs::write(inbox.join("a1.png"), b"\x89PNG").unwrap();
    let taken = take_attachment(&inbox, &media, "c-1", &out("a1.png")).unwrap();
    assert_eq!(
        (taken.size, taken.name.as_str(), taken.mime.as_str()),
        (4, "unicorn.png", "image/png")
    );
    assert_eq!(std::fs::read(media.join(&taken.id)).unwrap(), b"\x89PNG");
    assert!(!inbox.join("a1.png").exists(), "moved, not copied");
}

#[test]
fn a_link_a_path_or_a_folder_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let (inbox, media) = (dir.path().join("media"), dir.path().join("app-media"));
    std::fs::create_dir(&inbox).unwrap();
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
            take_attachment(&inbox, &media, "c-1", &out(file)).is_err(),
            "{file:?}"
        );
    }
    assert_eq!(
        std::fs::read(dir.path().join("secret")).unwrap(),
        b"host file"
    );
}

#[test]
fn a_strange_media_type_is_a_plain_file() {
    let dir = tempfile::tempdir().unwrap();
    let (inbox, media) = (dir.path().join("media"), dir.path().join("app-media"));
    std::fs::create_dir(&inbox).unwrap();
    std::fs::write(inbox.join("a2.bin"), b"x").unwrap();
    let mut a = out("a2.bin");
    a.mime = "text/html; <script>".to_owned();
    assert_eq!(
        take_attachment(&inbox, &media, "c-1", &a).unwrap().mime,
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
        host: Mutex::new(None),
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
