use super::*;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;

/// A hub whose host's person is alice, with a state database, so the
/// removal check can tell: a sandbox it has no record of, and no folder
/// of, is gone with its agents.
fn fixture() -> (tempfile::TempDir, Arc<Hub>, Store) {
    fixture_serving(&[])
}

/// [`fixture`], serving agents `names` of sandbox `lab`, whose plugins
/// listen at `<dir>/<name>.sock`.
fn fixture_serving(names: &[&str]) -> (tempfile::TempDir, Arc<Hub>, Store) {
    let dir = tempfile::tempdir().unwrap();
    let agents = names
        .iter()
        .map(|name| AgentEndpoint {
            name: format!("lab/{name}"),
            runtime: "hermes".into(),
            socket: dir.path().join(format!("{name}.sock")),
            token: "token".into(),
        })
        .collect();
    let hub = Arc::new(Hub::new(
        Transport::Tailscale,
        Arc::new(|_| Err("test".into())),
        dir.path().join("app.db"),
        crate::layout::Layout::at(dir.path().join("enclos")),
        vec![7; 32],
        agents,
        Some("alice".into()),
        SILENCE,
    ));
    let store = hub.store().unwrap();
    std::fs::create_dir_all(hub.layout.data()).unwrap();
    let state = crate::state::sqlite::SqliteStateStore::new(
        hub.layout.state_db(),
        hub.layout.state_lock(),
        crate::state::Wait::Command,
    );
    {
        use crate::state::StateStore;
        let lock = state.lock().unwrap();
        state.migrate(&lock).unwrap();
    }
    store.claim_host("alice").unwrap();
    (dir, hub, store)
}

fn phone(hub: &Hub, store: &Store, id: &str, person: &str) -> (Device, Receiver<ToDevice>) {
    let device = Device {
        id: id.into(),
        name: id.into(),
        person: person.into(),
        noise_key: id.as_bytes().to_vec(),
        device_key: vec![],
        push_key: vec![],
        push_token: None,
        paired: now(),
        seen: None,
        node: None,
    };
    store.add_device(&device).unwrap();
    let (tx, rx) = channel();
    hub.devices
        .lock()
        .unwrap()
        .insert(id.into(), (person.into(), tx, 0));
    (device, rx)
}

fn deleted(rx: &Receiver<ToDevice>) -> Vec<String> {
    rx.try_iter()
        .filter_map(|m| match m {
            ToDevice::ConversationDeleted { conversation } => Some(conversation.to_string()),
            _ => None,
        })
        .collect()
}

#[test]
fn the_host_forgets_a_removed_agent_and_every_device_of_theirs_drops_it() {
    let (dir, hub, store) = fixture();
    let (device, rx) = phone(&hub, &store, "phone", "alice");
    let (_tablet, tablet) = phone(&hub, &store, "tablet", "alice");
    let (_bob, bob) = phone(&hub, &store, "bob-phone", "bob");
    store.ensure_home("gone/coder", "alice", true).unwrap();
    store.conversation("c-1", "gone", "coder", "alice").unwrap();
    rusqlite::Connection::open(dir.path().join("app.db"))
        .unwrap()
        .execute_batch(
            "INSERT INTO attachments (id, message, conversation, mime, name, size)
             VALUES ('a-1', 'm-1', 'c-1', 'text/plain', 'notes.txt', 5)",
        )
        .unwrap();
    let media = dir.path().join(crate::layout::APP_MEDIA_DIR);
    std::fs::create_dir_all(&media).unwrap();
    std::fs::write(media.join("a-1"), "notes").unwrap();
    store.conversation("c-bob", "gone", "coder", "bob").unwrap();
    assert_eq!(hub.removed_agents(&store, "alice").unwrap(), ["gone/coder"]);
    // Only the host's person forgets.
    assert!(hub.removed_agents(&store, "bob").unwrap().is_empty());
    hub.forget_agent(&store, &device, "alice", "gone/coder")
        .unwrap();
    for rx in [&rx, &tablet] {
        assert_eq!(deleted(rx), ["c-1", "home.gone.coder"]);
    }
    assert!(deleted(&bob).is_empty());
    assert!(store.conversation_info("c-bob").unwrap().is_some());
    assert!(hub.removed_agents(&store, "alice").unwrap().is_empty());
    assert_eq!(
        store.deletions("alice").unwrap(),
        ["c-1", "home.gone.coder"]
    );
    assert!(!media.join("a-1").exists());
}

#[test]
fn an_agent_whose_data_was_kept_is_not_forgotten() {
    let (_dir, hub, store) = fixture();
    let (device, _rx) = phone(&hub, &store, "phone", "alice");
    // Removed with `--keep-data`: its profile is still in the sandbox's home
    let profile = hub
        .layout
        .sandbox_home("kept")
        .join(".hermes/profiles/coder");
    std::fs::create_dir_all(&profile).unwrap();
    std::fs::write(profile.join("config.yaml"), "model: auto\n").unwrap();
    store.ensure_home("kept/coder", "alice", true).unwrap();
    assert!(hub.removed_agents(&store, "alice").unwrap().is_empty());
    let error = hub
        .forget_agent(&store, &device, "alice", "kept/coder")
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::NotAllowed);
    assert!(
        store
            .conversation_info("home.kept.coder")
            .unwrap()
            .is_some()
    );
    assert_eq!(
        store.home_of("kept/coder").unwrap().as_deref(),
        Some("home.kept.coder")
    );
}

#[test]
fn only_the_hosts_person_on_a_paired_device_forgets() {
    let (_dir, hub, store) = fixture();
    let (bob, _rx) = phone(&hub, &store, "bob-phone", "bob");
    store.conversation("c-bob", "gone", "coder", "bob").unwrap();
    let error = hub
        .forget_agent(&store, &bob, "bob", "gone/coder")
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::NotAllowed);
    assert!(store.conversation_info("c-bob").unwrap().is_some());
    // An unpaired device of the host's person is refused too.
    let (device, _rx) = phone(&hub, &store, "phone", "alice");
    store.remove_device(&device.id).unwrap();
    store.ensure_home("gone/coder", "alice", true).unwrap();
    assert_eq!(
        hub.forget_agent(&store, &device, "alice", "gone/coder")
            .unwrap_err()
            .code,
        ErrorCode::NotAllowed
    );
    assert!(
        store
            .conversation_info("home.gone.coder")
            .unwrap()
            .is_some()
    );
}

#[test]
fn a_name_that_is_no_agent_is_refused_before_any_check() {
    let (_dir, hub, store) = fixture();
    let (device, _rx) = phone(&hub, &store, "phone", "alice");
    for name in ["coder", "../x/coder", "gone/../coder", "Gone/coder"] {
        assert_eq!(
            hub.forget_agent(&store, &device, "alice", name)
                .unwrap_err()
                .code,
            ErrorCode::BadMessage,
            "{name}"
        );
    }
}

#[test]
fn without_a_state_database_enclos_cannot_tell_so_nothing_is_forgotten() {
    let (_dir, hub, store) = fixture();
    let (device, _rx) = phone(&hub, &store, "phone", "alice");
    std::fs::remove_file(hub.layout.state_db()).unwrap();
    store.ensure_home("gone/coder", "alice", true).unwrap();
    assert!(hub.removed_agents(&store, "alice").unwrap().is_empty());
    assert_eq!(
        hub.forget_agent(&store, &device, "alice", "gone/coder")
            .unwrap_err()
            .code,
        ErrorCode::NotAllowed
    );
}

#[test]
fn a_file_that_cannot_be_removed_leaves_a_forget_to_retry() {
    let (dir, hub, store) = fixture();
    let (device, _rx) = phone(&hub, &store, "phone", "alice");
    store.conversation("c-1", "gone", "coder", "alice").unwrap();
    rusqlite::Connection::open(dir.path().join("app.db"))
        .unwrap()
        .execute_batch(
            "INSERT INTO attachments (id, message, conversation, mime, name, size)
             VALUES ('a-1', 'm-1', 'c-1', 'text/plain', 'notes.txt', 5)",
        )
        .unwrap();
    // A folder where the file goes: it cannot be removed as a file.
    let media = dir.path().join(crate::layout::APP_MEDIA_DIR);
    std::fs::create_dir_all(media.join("a-1")).unwrap();
    std::fs::write(media.join("a-1/inside"), "x").unwrap();
    let error = hub
        .forget_agent(&store, &device, "alice", "gone/coder")
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::Internal);
    assert!(store.conversation_info("c-1").unwrap().is_some());
    assert!(store.deletions("alice").unwrap().is_empty());
    assert_eq!(
        store.home_of("gone/coder").unwrap().as_deref(),
        Some("home.gone.coder")
    );
    std::fs::remove_dir_all(media.join("a-1")).unwrap();
    hub.forget_agent(&store, &device, "alice", "gone/coder")
        .unwrap();
    assert!(store.conversation_info("c-1").unwrap().is_none());
}

#[test]
fn the_plugin_hears_the_claimed_home_and_a_forgotten_agent_is_not_connected() {
    let (dir, hub, store) = fixture_serving(&["main"]);
    store.forget_agent("lab/main", "alice", "phone").unwrap();
    let refused = hub.plugin("lab/main").unwrap_err();
    assert!(refused.contains("was forgotten"), "{refused}");
    assert_eq!(store.claim_home("lab/main").unwrap(), "home.lab.main.2");
    let listener = UnixListener::bind(dir.path().join("main.sock")).unwrap();
    let (heard, hello) = channel();
    std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let mut writer = stream.try_clone().unwrap();
        let mut lines = BufReader::new(stream);
        let mut line = String::new();
        lines.read_line(&mut line).unwrap();
        heard.send(line.clone()).unwrap();
        writer
            .write_all(&encode_line(&Envelope::new(
                MessageId::new("hello").unwrap(),
                FromPlugin::Hello {
                    runtime: "hermes".into(),
                    agent: "main".into(),
                    capabilities: vec![],
                },
            )))
            .unwrap();
        // Kept open while the test runs.
        while lines.read_line(&mut line).unwrap_or(0) > 0 {}
    });
    hub.plugin("lab/main").unwrap();
    let line = hello.recv_timeout(Duration::from_secs(5)).unwrap();
    let hello: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(hello["home"], "home.lab.main.2");
}
