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
fn an_html_artefact_keeps_its_bytes_and_type_as_an_attachment() {
    let dir = tempfile::tempdir().unwrap();
    let (inbox, media) = (dir.path().join("media"), dir.path().join("app-media"));
    std::fs::create_dir(&inbox).unwrap();
    let html = b"<!doctype html><meta charset=utf-8><style>h1{color:green}</style><h1>Report</h1>";
    std::fs::write(inbox.join("report.html"), html).unwrap();
    let a = OutAttachment {
        file: "report.html".into(),
        mime: "text/html".into(),
        name: "report.html".into(),
        size: html.len() as u64,
    };
    let taken = take_attachment(&inbox, &media, "c-1", &a).unwrap();
    assert_eq!(std::fs::read(media.join(&taken.id)).unwrap(), html);
    assert_eq!(taken.conversation, "c-1");
    let info = attachment_info(taken);
    assert_eq!(
        (info.mime.as_str(), info.name.as_str()),
        ("text/html", "report.html")
    );
    assert_eq!(info.size, html.len() as u64);
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

fn approval_sample() -> enclos_protocol::approval::Approval {
    use enclos_protocol::approval::*;
    Approval {
        request: "r1".into(),
        sandbox: "lab".into(),
        agent: "lab/main".into(),
        conversation: Some("c1".into()),
        access: Access {
            kind: AccessKind::Network,
            target: "example.com".into(),
            private: false,
        },
        action: "Connect to example.com".into(),
        time: 1,
        state: "pending".into(),
        change: "Allow example.com".into(),
        restart: false,
        revision: "rev1".into(),
        available: true,
        reason: None,
    }
}
#[test]
fn approval_two_devices_cannot_decide_or_refresh_the_same_request() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("app.db");
    let first = Store::open(&path).unwrap();
    let second = Store::open(&path).unwrap();
    let a = approval_sample();
    assert!(first.create_approval(&a).unwrap());
    assert!(!second.create_approval(&a).unwrap());
    assert!(first.claim_approval(&a.request).unwrap());
    assert!(!second.claim_approval(&a.request).unwrap());
    assert!(!second.refresh_approval(&a).unwrap());
    assert_eq!(
        second.approval(&a.request).unwrap().unwrap().state,
        "applying"
    );
    let mut denied = a.clone();
    denied.state = "denied".into();
    first.put_approval(&denied).unwrap();
    assert!(!second.create_approval(&a).unwrap());
    assert_eq!(
        second.approval(&a.request).unwrap().unwrap().state,
        "denied"
    );
}
#[test]
fn approval_restart_marks_interrupted_decisions_for_review_without_replaying() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("app.db");
    {
        let store = Store::open(&path).unwrap();
        store.create_approval(&approval_sample()).unwrap();
        store.claim_approval("r1").unwrap();
    }
    let store = Store::open(&path).unwrap();
    store.recover_approvals().unwrap();
    assert_eq!(store.approval("r1").unwrap().unwrap().state, "failed");
    assert!(!store.claim_approval("r1").unwrap());
}

#[test]
fn approval_close_persists_without_rewriting_the_request_or_deciding_access() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("app.db");
    let store = Store::open(&path).unwrap();
    let mut a = approval_sample();
    a.available = false;
    a.reason = Some("This scope cannot be approved from the phone.".into());
    store.create_approval(&a).unwrap();
    let db = rusqlite::Connection::open(&path).unwrap();
    let body = || {
        db.query_row("SELECT body FROM approvals WHERE id='r1'", [], |row| {
            row.get::<_, String>(0)
        })
        .unwrap()
    };
    let original_body = body();
    assert!(
        store
            .close_approval("r1", "pending", "phone", "owner@example.com")
            .unwrap()
    );
    assert!(
        !store
            .close_approval("r1", "pending", "tablet", "owner@example.com")
            .unwrap()
    );
    assert!(!store.claim_approval("r1").unwrap());
    assert!(!store.refresh_approval(&a).unwrap());
    assert!(!store.create_approval(&a).unwrap());
    assert_eq!(body(), original_body);
    assert!(store.accepted_access().unwrap().is_empty());
    drop(store);
    let reopened = Store::open(&path).unwrap();
    reopened.recover_approvals().unwrap();
    a.state = "closed".into();
    assert_eq!(reopened.approval("r1").unwrap(), Some(a.clone()));
    assert_eq!(reopened.approvals().unwrap(), vec![a]);
    let log = reopened.log_lines(20).unwrap();
    assert_eq!(log.len(), 1);
    assert_eq!(log[0].event, "approval.closed");
    assert_eq!(log[0].device.as_deref(), Some("phone"));
    assert_eq!(log[0].person.as_deref(), Some("owner@example.com"));
    assert_eq!(log[0].reason.as_deref(), Some("r1"));
}

#[test]
fn approval_close_allows_failed_requests_but_preserves_inflight_and_terminal_decisions() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("app.db")).unwrap();
    for state in [
        "failed",
        "applying",
        "approved",
        "denied",
        "diagnostic",
        "closed",
    ] {
        let mut a = approval_sample();
        a.request = state.into();
        a.state = state.into();
        store.create_approval(&a).unwrap();
        assert_eq!(
            store
                .close_approval(state, state, "phone", "owner@example.com")
                .unwrap(),
            state == "failed"
        );
        assert_eq!(
            store.approval(state).unwrap().unwrap().state,
            if state == "failed" { "closed" } else { state }
        );
    }
    assert!(
        !store
            .close_approval("unknown", "pending", "phone", "owner@example.com")
            .unwrap()
    );
    assert_eq!(store.log_lines(20).unwrap().len(), 1);
}

#[test]
fn approval_close_closes_only_from_the_state_that_was_checked() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("app.db")).unwrap();
    let mut a = approval_sample();
    a.state = "failed".into();
    store.create_approval(&a).unwrap();
    // Read as applying, failed since: not closed without the failure's check.
    assert!(
        !store
            .close_approval("r1", "applying", "phone", "owner@example.com")
            .unwrap()
    );
    // Read as pending, failed since: the same.
    assert!(
        !store
            .close_approval("r1", "pending", "phone", "owner@example.com")
            .unwrap()
    );
    assert_eq!(store.approval("r1").unwrap().unwrap().state, "failed");
    assert!(store.log_lines(20).unwrap().is_empty());
    assert!(
        store
            .close_approval("r1", "failed", "phone", "owner@example.com")
            .unwrap()
    );
}

#[test]
fn approval_close_and_audit_are_atomic() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("app.db");
    let store = Store::open(&path).unwrap();
    store.create_approval(&approval_sample()).unwrap();
    let db = rusqlite::Connection::open(&path).unwrap();
    db.execute_batch(
        "CREATE TRIGGER reject_close_log BEFORE INSERT ON log WHEN NEW.event='approval.closed' BEGIN SELECT RAISE(ABORT, 'test audit failure'); END;",
    )
    .unwrap();
    assert!(
        store
            .close_approval("r1", "pending", "phone", "owner@example.com")
            .is_err()
    );
    assert_eq!(store.approval("r1").unwrap().unwrap().state, "pending");
    assert!(store.log_lines(20).unwrap().is_empty());
}

#[test]
fn approval_close_races_with_claim_and_exactly_one_wins() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("app.db");
    let store = Store::open(&path).unwrap();
    store.create_approval(&approval_sample()).unwrap();
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let close = {
        let path = path.clone();
        let barrier = barrier.clone();
        std::thread::spawn(move || {
            let store = Store::open(&path).unwrap();
            barrier.wait();
            store
                .close_approval("r1", "pending", "phone", "owner@example.com")
                .unwrap()
        })
    };
    let claim = std::thread::spawn(move || {
        let store = Store::open(&path).unwrap();
        barrier.wait();
        store.claim_approval("r1").unwrap()
    });
    let closed = close.join().unwrap();
    let claimed = claim.join().unwrap();
    assert_ne!(closed, claimed);
    assert_eq!(
        store.approval("r1").unwrap().unwrap().state,
        if closed { "closed" } else { "applying" }
    );
    assert_eq!(store.log_lines(20).unwrap().len(), usize::from(closed));
}

#[test]
fn approval_authority_requires_the_host_person_and_a_still_paired_device() {
    let dir = tempfile::tempdir().unwrap();
    let mut hub = Arc::new(Hub {
        transport: Transport::Tailscale,
        store_path: dir.path().join("app.db"),
        layout: crate::layout::Layout::at(dir.path().join("enclos")),
        bridge_private: vec![],
        agents: vec![],
        host: Some("owner@example.com".into()),
        plugins: Mutex::new(HashMap::new()),
        routines: Mutex::new(Default::default()),
        questions: Mutex::new(Default::default()),
        commands: Mutex::new(HashMap::new()),
        groups: Mutex::new(HashMap::new()),
        stops: Mutex::new(Default::default()),
        devices: Mutex::new(HashMap::new()),
    });
    let store = hub.store().unwrap();
    let device = Device {
        id: "d1".into(),
        name: "phone".into(),
        person: "owner@example.com".into(),
        noise_key: vec![],
        device_key: vec![],
        push_key: vec![],
        push_token: None,
        paired: now(),
        seen: None,
    };
    assert!(
        hub.decide_access(&store, &device, "guest@example.com", "r1", "rev1", true)
            .unwrap_err()
            .contains("Only the host")
    );
    assert!(
        hub.decide_access(&store, &device, "owner@example.com", "r1", "rev1", true)
            .unwrap_err()
            .contains("no longer paired")
    );
    assert!(
        hub.policy_authority(&store, &device, "guest@example.com", "lab")
            .unwrap_err()
            .contains("Only the host")
    );
    assert!(
        hub.policy_authority(&store, &device, "owner@example.com", "lab")
            .unwrap_err()
            .contains("no longer paired")
    );
    store.add_device(&device).unwrap();
    Arc::get_mut(&mut hub).unwrap().agents.push(AgentEndpoint {
        name: "lab/coder".into(),
        runtime: "hermes".into(),
        socket: dir.path().join("unused.sock"),
        token: "fixture".into(),
    });
    assert!(
        hub.policy_authority(&store, &device, "owner@example.com", "lab")
            .is_ok()
    );
    assert!(
        hub.policy_authority(&store, &device, "owner@example.com", "other")
            .is_err()
    );
    store.remove_device(&device.id).unwrap();
    assert!(
        hub.policy_authority(&store, &device, "owner@example.com", "lab")
            .is_err()
    );
    assert!(store.approvals().unwrap().is_empty());
}

#[test]
fn accepted_access_is_not_limited_to_the_inbox_history_window() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("app.db")).unwrap();
    for i in 0..210 {
        let mut a = approval_sample();
        a.request = format!("r{i}");
        store.create_approval(&a).unwrap();
        store.claim_approval(&a.request).unwrap();
        a.state = "approved".into();
        store.put_approval(&a).unwrap();
    }
    assert_eq!(store.accepted_access().unwrap().len(), 210);
}

fn diagnostic_approval_hub() -> (tempfile::TempDir, Arc<Hub>, Store) {
    let dir = tempfile::tempdir().unwrap();
    let hub = Arc::new(Hub {
        transport: Transport::Tailscale,
        store_path: dir.path().join("app.db"),
        layout: crate::layout::Layout::at(dir.path().join("enclos")),
        bridge_private: vec![],
        agents: vec![],
        host: Some("owner@example.com".into()),
        plugins: Mutex::new(HashMap::new()),
        routines: Mutex::new(Default::default()),
        questions: Mutex::new(Default::default()),
        commands: Mutex::new(HashMap::new()),
        groups: Mutex::new(HashMap::new()),
        stops: Mutex::new(Default::default()),
        devices: Mutex::new(HashMap::new()),
    });
    let store = hub.store().unwrap();
    (dir, hub, store)
}

#[test]
fn approval_close_requires_the_host_person_and_a_still_paired_device() {
    let (_dir, mut hub, store) = diagnostic_approval_hub();
    let owner = "owner@example.com";
    let device = avatar_device("phone", owner);
    store.create_approval(&approval_sample()).unwrap();
    assert!(
        hub.close_access(&store, &device, "guest@example.com", "r1")
            .unwrap_err()
            .contains("Only the host")
    );
    assert!(
        hub.close_access(&store, &device, owner, "r1")
            .unwrap_err()
            .contains("no longer paired")
    );
    let mut other_person = device.clone();
    other_person.person = "guest@example.com".into();
    store.add_device(&other_person).unwrap();
    assert!(hub.close_access(&store, &device, owner, "r1").is_err());
    store.remove_device(&device.id).unwrap();
    store.add_device(&device).unwrap();
    assert_eq!(
        hub.close_access(&store, &device, owner, "unknown")
            .unwrap_err(),
        "Unknown policy request"
    );
    Arc::get_mut(&mut hub).unwrap().host = None;
    assert!(
        hub.close_access(&store, &device, owner, "r1")
            .unwrap_err()
            .contains("Only the host")
    );
    assert_eq!(store.approval("r1").unwrap().unwrap().state, "pending");
    assert!(store.log_lines(20).unwrap().is_empty());
}

#[test]
fn approval_close_reaches_all_owner_devices_without_policy_or_runtime_work() {
    let (dir, hub, store) = diagnostic_approval_hub();
    let owner = "owner@example.com";
    let device = avatar_device("phone", owner);
    store.add_device(&device).unwrap();
    let mut a = approval_sample();
    a.available = false;
    a.reason = Some("This scope cannot be approved from the phone.".into());
    store.create_approval(&a).unwrap();
    let (first_tx, first_rx) = channel();
    let (second_tx, second_rx) = channel();
    let (guest_tx, guest_rx) = channel();
    {
        let mut devices = hub.devices.lock().unwrap();
        devices.insert("phone".into(), (owner.into(), first_tx));
        devices.insert("tablet".into(), (owner.into(), second_tx));
        devices.insert("guest".into(), ("guest@example.com".into(), guest_tx));
    }
    // There is deliberately no initialized policy engine or runtime in this fixture.
    assert!(!dir.path().join("enclos").exists());
    for _ in 0..2 {
        hub.close_access(&store, &device, owner, "r1").unwrap();
        for rx in [&first_rx, &second_rx] {
            let ToDevice::Approval(closed) = rx.try_recv().unwrap() else {
                panic!("expected the canonical policy request");
            };
            let mut expected = a.clone();
            expected.state = "closed".into();
            assert_eq!(closed, expected);
            assert!(rx.try_recv().is_err());
        }
        assert!(guest_rx.try_recv().is_err());
    }
    for approve in [true, false] {
        hub.decide_access(&store, &device, owner, "r1", "rev1", approve)
            .unwrap();
        for rx in [&first_rx, &second_rx] {
            assert!(matches!(rx.try_recv().unwrap(), ToDevice::Approval(a) if a.state == "closed"));
        }
    }
    assert_eq!(store.log_lines(20).unwrap().len(), 1);
    assert!(store.accepted_access().unwrap().is_empty());
    assert!(!dir.path().join("enclos").exists());
}

#[test]
fn approval_close_keeps_a_failure_while_its_policy_change_waits_on_the_host() {
    let mut a = approval_sample();
    a.state = "failed".into();
    let why = approvals::close_blocked(&a, |_| true).unwrap();
    assert!(why.contains("enclos policy apply lab"), "{why}");
    assert!(approvals::close_blocked(&a, |_| false).is_none());
    // A pending request has no policy work left behind: it closes.
    a.state = "pending".into();
    assert!(approvals::close_blocked(&a, |_| true).is_none());
}

#[test]
fn approval_close_waits_for_an_inflight_decision_then_can_close_its_failure() {
    let (_dir, hub, store) = diagnostic_approval_hub();
    let owner = "owner@example.com";
    let device = avatar_device("phone", owner);
    store.add_device(&device).unwrap();
    let mut a = approval_sample();
    store.create_approval(&a).unwrap();
    store.claim_approval("r1").unwrap();
    assert!(
        hub.close_access(&store, &device, owner, "r1")
            .unwrap_err()
            .contains("already being decided")
    );
    assert_eq!(store.approval("r1").unwrap().unwrap().state, "applying");
    assert!(store.log_lines(20).unwrap().is_empty());
    a.state = "failed".into();
    a.reason = Some("Decision failed; review active policy.".into());
    store.put_approval(&a).unwrap();
    hub.close_access(&store, &device, owner, "r1").unwrap();
    a.state = "closed".into();
    assert_eq!(store.approval("r1").unwrap(), Some(a));
}

#[test]
fn approval_closed_requests_are_not_recreated_by_collection_or_agent_retries() {
    let (_dir, hub, store) = diagnostic_approval_hub();
    let owner = "owner@example.com";
    let device = avatar_device("phone", owner);
    store.add_device(&device).unwrap();
    let access = approval_sample().access;
    hub.request_access(&store, "lab", None, access.clone(), "proxy refusal")
        .unwrap();
    let request = store.approvals().unwrap().remove(0).request;
    hub.close_access(&store, &device, owner, &request).unwrap();
    hub.request_access(&store, "lab", None, access.clone(), "same refusal")
        .unwrap();
    // The agent is told, not left waiting for a request nobody sees.
    let told = hub
        .request_access(
            &store,
            "lab/main",
            Some("c1"),
            access.clone(),
            "same refusal",
        )
        .unwrap_err();
    assert!(told.contains("already closed"), "{told}");
    let reopened = hub.store().unwrap();
    reopened.recover_approvals().unwrap();
    hub.request_access(&reopened, "lab", None, access, "same refusal after restart")
        .unwrap();
    let requests = reopened.approvals().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].request, request);
    assert_eq!(requests[0].state, "closed");
    assert_eq!(reopened.log_lines(20).unwrap().len(), 1);
}

#[test]
fn archive_changes_are_owner_only_and_reach_all_of_their_devices() {
    let (_dir, hub, store) = diagnostic_approval_hub();
    let owner = "owner@example.com";
    store
        .conversation("c-archive", "lab", "main", owner)
        .unwrap();
    let (first_tx, first_rx) = channel();
    let (second_tx, second_rx) = channel();
    let (guest_tx, guest_rx) = channel();
    {
        let mut devices = hub.devices.lock().unwrap();
        devices.insert("phone".into(), (owner.into(), first_tx));
        devices.insert("tablet".into(), (owner.into(), second_tx));
        devices.insert("guest".into(), ("guest@example.com".into(), guest_tx));
    }
    let missing = archive_conversation(&hub, &store, owner, "missing", true).unwrap_err();
    assert_eq!(
        archive_conversation(&hub, &store, "guest@example.com", "c-archive", true).unwrap_err(),
        missing
    );
    assert!(first_rx.try_recv().is_err());
    assert!(
        !store
            .conversation_info("c-archive")
            .unwrap()
            .unwrap()
            .archived
    );
    for archived in [true, false] {
        let direct = archive_conversation(&hub, &store, owner, "c-archive", archived).unwrap();
        assert_eq!(direct.archived, archived);
        for rx in [&first_rx, &second_rx] {
            let ToDevice::Conversation(info) = rx.try_recv().unwrap() else {
                panic!("expected conversation metadata");
            };
            assert_eq!(info.conversation.as_str(), "c-archive");
            assert_eq!(info.archived, archived);
            assert_eq!(info, direct);
        }
        assert!(guest_rx.try_recv().is_err());
        let retried = archive_conversation(&hub, &store, owner, "c-archive", archived).unwrap();
        assert_eq!(retried, direct, "a retry returns canonical metadata too");
        assert!(first_rx.try_recv().is_err());
        assert!(second_rx.try_recv().is_err());
    }
    assert!(
        hub.plugins.lock().unwrap().is_empty(),
        "archive never reaches a runtime"
    );
    assert!(
        hub.groups.lock().unwrap().is_empty(),
        "archive starts or stops no discussion"
    );
}

#[test]
fn home_archive_is_rejected_without_a_broadcast_and_unarchive_still_recovers_it() {
    let (_dir, hub, store) = diagnostic_approval_hub();
    let owner = "owner@example.com";
    let home = home_id("lab/main");
    store.ensure_home("lab/main", owner).unwrap();
    let (tx, rx) = channel();
    hub.devices
        .lock()
        .unwrap()
        .insert("phone".into(), (owner.into(), tx));
    let before = store.conversation_info(&home).unwrap().unwrap();
    assert_eq!(
        archive_conversation(&hub, &store, owner, &home, true).unwrap_err(),
        "Home cannot be archived"
    );
    assert_eq!(store.conversation_info(&home).unwrap().unwrap(), before);
    assert!(rx.try_recv().is_err());
    let missing = archive_conversation(&hub, &store, owner, "home.missing.main", true).unwrap_err();
    assert_eq!(
        archive_conversation(&hub, &store, "guest@example.com", &home, true).unwrap_err(),
        missing
    );
    let current = archive_conversation(&hub, &store, owner, &home, false).unwrap();
    assert!(current.home);
    assert!(!current.archived);
    assert_eq!(current.revision, before.revision);
    assert!(rx.try_recv().is_err());

    rusqlite::Connection::open(&hub.store_path)
        .unwrap()
        .execute(
            "UPDATE conversations SET archived = 1 WHERE id = ?1",
            [&home],
        )
        .unwrap();
    let restored = archive_conversation(&hub, &store, owner, &home, false).unwrap();
    assert!(restored.home);
    assert!(!restored.archived);
    assert_eq!(restored.revision, before.revision + 1);
    let ToDevice::Conversation(broadcast) = rx.try_recv().unwrap() else {
        panic!("expected restored Home metadata");
    };
    assert_eq!(broadcast, restored);
}

#[test]
fn delayed_archive_read_and_rename_snapshots_keep_their_revision() {
    let (_dir, hub, first) = diagnostic_approval_hub();
    let second = hub.store().unwrap();
    let owner = "owner@example.com";
    first
        .conversation("c-ordered", "lab", "main", owner)
        .unwrap();
    first.name("c-ordered", "Before", BY_PERSON).unwrap();
    let seq = first
        .add("ordered-message", "c-ordered", &From::Agent, "hi", "reply")
        .unwrap()
        .unwrap();
    let archive = archive_conversation(&hub, &first, owner, "c-ordered", true).unwrap();
    let restore = archive_conversation(&hub, &second, owner, "c-ordered", false).unwrap();
    second.name("c-ordered", "After", BY_PERSON).unwrap();
    let renamed = conversation_info(
        &second,
        second.conversation_info("c-ordered").unwrap().unwrap(),
    )
    .unwrap();
    first.mark_read("c-ordered", seq).unwrap();
    // A direct sync sends metadata even when no message is newer than its cursor.
    assert!(first.since(owner, i64::MAX).unwrap().is_empty());
    let synced = conversation_info(&first, first.conversations(owner).unwrap().remove(0)).unwrap();
    assert_eq!(
        [
            archive.revision,
            restore.revision,
            renamed.revision,
            synced.revision
        ],
        [2, 3, 4, 5]
    );
    assert!(archive.archived);
    assert_eq!(archive.title.as_deref(), Some("Before"));
    assert!(!restore.archived);
    assert_eq!(renamed.title.as_deref(), Some("After"));
    assert_eq!(renamed.read, None);
    assert_eq!(synced.read, Some(seq));
    let (tx, rx) = channel();
    hub.devices
        .lock()
        .unwrap()
        .insert("phone".into(), (owner.into(), tx));
    // Queued broadcasts can arrive after a direct sync, in another writer's order.
    for snapshot in [&synced, &archive, &renamed, &restore] {
        hub.deliver(owner, ToDevice::Conversation(snapshot.clone()));
    }
    for expected in [&synced, &archive, &renamed, &restore] {
        assert_eq!(
            rx.try_recv().unwrap(),
            ToDevice::Conversation(expected.clone())
        );
    }
    let retried = archive_conversation(&hub, &second, owner, "c-ordered", false).unwrap();
    assert_eq!(
        retried, synced,
        "retry echo is canonical, not the delayed archive snapshot"
    );
    assert!(
        rx.try_recv().is_err(),
        "idempotent retry does not produce another broadcast"
    );
}

#[test]
fn diagnostic_probe_destination_never_becomes_an_approval_request() {
    use enclos_protocol::approval::{Access, AccessKind};
    let (_dir, hub, store) = diagnostic_approval_hub();
    hub.request_access(
        &store,
        "lab",
        None,
        Access {
            kind: AccessKind::Network,
            target: "probe.enclos.invalid:8443".into(),
            private: false,
        },
        "Connect to the network probe",
    )
    .unwrap();
    assert!(
        store.approvals().unwrap().is_empty(),
        "an enclos diagnostic probe must not enter the approval inbox"
    );
}

#[test]
fn diagnostic_probe_matching_is_exact_and_real_destinations_still_request_access() {
    use enclos_protocol::approval::{Access, AccessKind};
    let (_dir, hub, store) = diagnostic_approval_hub();
    for target in ["PROBE.ENCLOS.INVALID.:443", "probe.enclos.invalid:8080"] {
        hub.request_access(
            &store,
            "lab",
            None,
            Access {
                kind: AccessKind::Network,
                target: target.into(),
                private: false,
            },
            "probe",
        )
        .unwrap();
    }
    assert!(store.approvals().unwrap().is_empty());
    for target in [
        "10.0.0.1:443",
        "api.example.com:8443",
        "other.enclos.invalid:8443",
        "probe.enclos.invalid.example.com:443",
    ] {
        hub.request_access(
            &store,
            "lab",
            None,
            Access {
                kind: AccessKind::Network,
                target: target.into(),
                private: true,
            },
            "agent work",
        )
        .unwrap();
    }
    assert_eq!(store.approvals().unwrap().len(), 4);
}
#[test]
fn diagnostic_probe_existing_pending_notification_is_dismissed_and_broadcast() {
    let (_dir, hub, store) = diagnostic_approval_hub();
    let (tx, rx) = channel();
    hub.devices
        .lock()
        .unwrap()
        .insert("d1".into(), ("owner@example.com".into(), tx));
    let mut a = approval_sample();
    a.access.target = "probe.enclos.invalid:8443".into();
    a.agent.clear();
    store.create_approval(&a).unwrap();
    hub.dismiss_probe_requests(&store).unwrap();
    let closed = store.approval(&a.request).unwrap().unwrap();
    assert_eq!(closed.state, "diagnostic");
    assert!(!closed.available);
    assert!(!store.claim_approval(&a.request).unwrap());
    assert!(matches!(rx.try_recv().unwrap(),ToDevice::Approval(v) if v.state=="diagnostic"));
    hub.dismiss_probe_requests(&store).unwrap();
    assert!(rx.try_recv().is_err());
}
#[test]
fn diagnostic_probe_dismissal_preserves_existing_decisions_and_rejects_explicit_agent_requests() {
    use enclos_protocol::approval::{Access, AccessKind};
    let (_dir, hub, store) = diagnostic_approval_hub();
    let mut a = approval_sample();
    a.access.target = "probe.enclos.invalid:8443".into();
    store.create_approval(&a).unwrap();
    store.claim_approval(&a.request).unwrap();
    assert!(store.dismiss_probe(&a).unwrap().is_none());
    a.state = "approved".into();
    store.put_approval(&a).unwrap();
    hub.dismiss_probe_requests(&store).unwrap();
    assert_eq!(
        store.approval(&a.request).unwrap().unwrap().state,
        "approved"
    );
    assert!(
        hub.request_access(
            &store,
            "lab/coder",
            Some("c1"),
            Access {
                kind: AccessKind::Network,
                target: "probe.enclos.invalid:8443".into(),
                private: false
            },
            "probe"
        )
        .is_err()
    );
}

#[test]
fn diagnostic_probe_stale_phone_decision_cannot_approve_the_notification() {
    let (_dir, hub, store) = diagnostic_approval_hub();
    let device = Device {
        id: "d1".into(),
        name: "phone".into(),
        person: "owner@example.com".into(),
        noise_key: vec![],
        device_key: vec![],
        push_key: vec![],
        push_token: None,
        paired: now(),
        seen: None,
    };
    store.add_device(&device).unwrap();
    let mut a = approval_sample();
    a.access.target = "probe.enclos.invalid:8443".into();
    store.create_approval(&a).unwrap();
    let error = hub
        .decide_access(
            &store,
            &device,
            "owner@example.com",
            &a.request,
            &a.revision,
            true,
        )
        .unwrap_err();
    assert!(error.contains("diagnostic"));
    assert_eq!(
        store.approval(&a.request).unwrap().unwrap().state,
        "diagnostic"
    );
}

#[test]
fn diagnostic_provenance_preserves_explicit_agent_identity_and_later_real_requests() {
    use enclos_protocol::approval::{Access, AccessKind};
    let (_dir, hub, store) = diagnostic_approval_hub();
    let a = Access {
        kind: AccessKind::Network,
        target: "10.0.0.1:443".into(),
        private: true,
    };
    hub.request_access(&store, "lab", None, a.clone(), "proxy refusal")
        .unwrap();
    let old = store.approvals().unwrap()[0].clone();
    hub.request_access(
        &store,
        "lab/coder",
        Some("c1"),
        a.clone(),
        "explicit request",
    )
    .unwrap();
    assert_eq!(
        store.approval(&old.request).unwrap().unwrap().agent,
        "lab/coder"
    );
    assert!(
        store.dismiss_probe(&old).unwrap().is_none(),
        "stale cleanup cannot discard the agent identity update"
    );
    assert_eq!(
        store.approval(&old.request).unwrap().unwrap().state,
        "pending"
    );
}

#[test]
fn diagnostic_provenance_later_real_requests_get_fresh_ids_and_keep_denial_deduplication() {
    use enclos_protocol::approval::{Access, AccessKind};
    let (_dir, hub, store) = diagnostic_approval_hub();
    let a = Access {
        kind: AccessKind::Network,
        target: "10.0.0.1:443".into(),
        private: true,
    };
    hub.request_access(&store, "lab", None, a.clone(), "proxy refusal")
        .unwrap();
    let old = store.approvals().unwrap()[0].clone();
    assert!(store.dismiss_probe(&old).unwrap().is_some());
    hub.request_access(
        &store,
        "lab/coder",
        Some("c1"),
        a.clone(),
        "genuine later attempt",
    )
    .unwrap();
    let next = store
        .approvals()
        .unwrap()
        .into_iter()
        .find(|v| v.state == "pending")
        .unwrap();
    assert_ne!(next.request, old.request);
    store.claim_approval(&next.request).unwrap();
    let mut denied = next.clone();
    denied.state = "denied".into();
    store.put_approval(&denied).unwrap();
    hub.request_access(&store, "lab", None, a, "same refusal")
        .unwrap();
    assert!(
        !store
            .approvals()
            .unwrap()
            .iter()
            .any(|v| v.state == "pending")
    );
}

fn avatar_fixture(width: u32, height: u32) -> Vec<u8> {
    let image = image::RgbImage::from_fn(width, height, |x, y| {
        image::Rgb([(x % 255) as u8, (y % 255) as u8, 80])
    });
    let mut out = std::io::Cursor::new(Vec::new());
    image::DynamicImage::ImageRgb8(image)
        .write_to(&mut out, image::ImageFormat::Png)
        .unwrap();
    out.into_inner()
}
fn avatar_device(id: &str, person: &str) -> Device {
    Device {
        id: id.into(),
        name: id.into(),
        person: person.into(),
        noise_key: id.as_bytes().to_vec(),
        device_key: id.as_bytes().to_vec(),
        push_key: vec![],
        push_token: None,
        paired: now(),
        seen: None,
    }
}

#[test]
fn shared_agent_names_survive_restart_clear_and_stale_writers_without_renaming_identity() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("app.db");
    let original = Store::open(&path).unwrap();
    original
        .conversation("conversation", "lab", "comptoir-dev", "owner")
        .unwrap();
    original.ensure_home("lab/comptoir-dev", "owner").unwrap();
    original
        .add(
            "message",
            "conversation",
            &super::super::store::From::Agent,
            "Existing history",
            "reply",
        )
        .unwrap();
    original
        .set_avatar("lab/comptoir-dev", 0, Some(b"photo"), ("phone", "owner"))
        .unwrap();
    let conversations = original.conversations("owner").unwrap();
    let messages = original.messages_after("conversation", 0).unwrap();
    let photo = original.avatar("lab/comptoir-dev").unwrap();
    drop(original);
    // The preceding bridge has no name table: opening it must add only that table.
    rusqlite::Connection::open(&path)
        .unwrap()
        .execute_batch("DROP TABLE agent_names")
        .unwrap();
    let first = Store::open(&path).unwrap();
    let second = Store::open(&path).unwrap();
    assert_eq!(first.agent_name("lab/comptoir-dev").unwrap().revision, 0);
    let saved = first
        .set_agent_name(
            "lab/comptoir-dev",
            0,
            Some("Gégé Commit"),
            ("phone", "owner"),
        )
        .unwrap()
        .unwrap();
    assert_eq!(saved.revision, 1);
    assert_eq!(second.agent_name("lab/comptoir-dev").unwrap(), saved);
    assert!(
        second
            .set_agent_name(
                "lab/comptoir-dev",
                0,
                Some("Stale name"),
                ("tablet", "owner")
            )
            .unwrap()
            .is_none()
    );
    let no_change = second
        .set_agent_name(
            "lab/comptoir-dev",
            1,
            Some("Gégé Commit"),
            ("tablet", "owner"),
        )
        .unwrap()
        .unwrap();
    assert_eq!(no_change, saved);
    assert_eq!(
        first
            .log_lines(20)
            .unwrap()
            .iter()
            .filter(|l| l.event == "agent.name.set")
            .count(),
        1
    );
    let cleared = second
        .set_agent_name("lab/comptoir-dev", 1, None, ("tablet", "owner"))
        .unwrap()
        .unwrap();
    assert_eq!(cleared.revision, 2);
    assert_eq!(cleared.display_name, None);
    drop(first);
    drop(second);
    let reopened = Store::open(&path).unwrap();
    assert_eq!(reopened.agent_name("lab/comptoir-dev").unwrap(), cleared);
    assert_eq!(
        reopened.agent_name_metadata().unwrap()["lab/comptoir-dev"],
        cleared
    );
    assert!(
        reopened
            .set_agent_name("lab/comptoir-dev", 1, Some("Old name"), ("phone", "owner"))
            .unwrap()
            .is_none()
    );
    assert_eq!(reopened.conversations("owner").unwrap(), conversations);
    assert_eq!(
        reopened.messages_after("conversation", 0).unwrap(),
        messages
    );
    assert_eq!(reopened.avatar("lab/comptoir-dev").unwrap(), photo);
    assert_eq!(
        reopened.conversation_of("conversation").unwrap().unwrap().1,
        "comptoir-dev"
    );
}

#[test]
fn shared_name_revisions_never_overflow_or_accept_noninteger_values() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("app.db");
    let store = Store::open(&path).unwrap();
    store
        .set_agent_name("lab/main", 0, Some("Original"), ("phone", "owner"))
        .unwrap();
    let db = rusqlite::Connection::open(&path).unwrap();
    for revision in ["-1", "1.5", "9223372036854775808"] {
        assert!(
            db.execute_batch(&format!(
                "UPDATE agent_names SET revision={revision} WHERE agent='lab/main'"
            ))
            .is_err()
        );
    }
    db.execute(
        "UPDATE agent_names SET revision=?1 WHERE agent='lab/main'",
        [i64::MAX],
    )
    .unwrap();
    assert!(
        store
            .set_agent_name("lab/main", i64::MAX, Some("Overflow"), ("phone", "owner"))
            .is_err()
    );
    let kept = store.agent_name("lab/main").unwrap();
    assert_eq!(kept.revision, i64::MAX);
    assert_eq!(kept.display_name.as_deref(), Some("Original"));
    assert_eq!(
        store
            .log_lines(20)
            .unwrap()
            .iter()
            .filter(|l| l.event == "agent.name.set")
            .count(),
        1
    );
}

#[test]
fn simultaneous_name_edits_have_one_winner_at_the_same_revision() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("app.db");
    let first = Store::open(&path).unwrap();
    let second = Store::open(&path).unwrap();
    let ready = Arc::new(std::sync::Barrier::new(3));
    let edits: Vec<_> = [(first, "Gégé Commit"), (second, "Another name")]
        .into_iter()
        .map(|(store, name)| {
            let ready = Arc::clone(&ready);
            std::thread::spawn(move || {
                ready.wait();
                store
                    .set_agent_name("lab/comptoir-dev", 0, Some(name), ("phone", "owner"))
                    .unwrap()
            })
        })
        .collect();
    ready.wait();
    let outcomes: Vec<_> = edits.into_iter().map(|edit| edit.join().unwrap()).collect();
    assert_eq!(
        outcomes.iter().filter(|outcome| outcome.is_some()).count(),
        1
    );
    let saved = Store::open(&path).unwrap();
    assert_eq!(saved.agent_name("lab/comptoir-dev").unwrap().revision, 1);
    assert_eq!(saved.log_lines(10).unwrap().len(), 1);
}

#[test]
fn large_agent_names_use_bounded_noise_frames_without_losing_inventory_or_tombstones() {
    use enclos_protocol::agent_name::NameMetadata;
    use enclos_protocol::noise::{Initiator, MAX_NOISE_MESSAGE, Responder, generate_keypair};
    let original: Vec<_> = (0..100)
        .map(|i| AgentInfo {
            agent: format!("lab/comptoir-dev-{i:03}"),
            runtime: "hermes".into(),
            capabilities: vec![
                Capability::Typing,
                Capability::Titles,
                Capability::Tools,
                Capability::Commands,
                Capability::Approval,
            ],
            abilities: vec!["read".into(), "chat".into()],
            avatar: enclos_protocol::avatar::AvatarMetadata {
                revision: 1,
                version: Some("f".repeat(64)),
            },
            can_edit_avatar: true,
            can_edit_name: true,
            display_name: (i > 1).then(|| "🦀".repeat(100)),
            name_revision: i64::from(i),
        })
        .collect();
    let raw = serde_json::to_vec(&enclos_protocol::Envelope::new(
        MessageId::new("m".repeat(128)).unwrap(),
        ToDevice::AgentsList {
            agents: original.clone(),
        },
    ))
    .unwrap();
    assert!(
        raw.len() + 16 > MAX_NOISE_MESSAGE,
        "the original valid named inventory reproduces an oversized Noise frame: {}",
        raw.len()
    );
    let messages = agent_names::agent_inventory_messages(original.clone()).unwrap();
    assert_eq!(
        messages.len(),
        100,
        "one inventory, 98 labels and one cleared tombstone"
    );
    let ToDevice::AgentsList { agents: inventory } = &messages[0] else {
        panic!("inventory must precede names");
    };
    assert_eq!(inventory.len(), original.len());
    for (snapshot, canonical) in inventory.iter().zip(&original) {
        assert_eq!(snapshot.agent, canonical.agent);
        assert_eq!(snapshot.capabilities, canonical.capabilities);
        assert_eq!(snapshot.abilities, canonical.abilities);
        assert_eq!(snapshot.avatar, canonical.avatar);
        assert_eq!(snapshot.can_edit_name, canonical.can_edit_name);
        assert_eq!(snapshot.can_edit_avatar, canonical.can_edit_avatar);
        assert_eq!(snapshot.name_revision, 0);
        assert_eq!(snapshot.display_name, None);
    }
    let bridge_key = generate_keypair().unwrap();
    let device_key = generate_keypair().unwrap();
    let mut initiator = Initiator::new(&device_key.private, &bridge_key.public).unwrap();
    let mut responder = Responder::new(&bridge_key.private).unwrap();
    responder.read_hello(&initiator.hello().unwrap()).unwrap();
    let (answer, mut bridge_session) = responder.answer().unwrap();
    let mut device_session = initiator.finish(&answer).unwrap();
    let mut restored: HashMap<_, _> = inventory
        .iter()
        .map(|agent| (agent.agent.clone(), NameMetadata::default()))
        .collect();
    for message in messages {
        let encoded = serde_json::to_vec(&enclos_protocol::Envelope::new(
            MessageId::new("m".repeat(128)).unwrap(),
            message,
        ))
        .unwrap();
        assert!(encoded.len() <= agent_names::AGENT_MESSAGE_BUDGET);
        let encrypted = bridge_session.encrypt(&encoded).unwrap();
        assert!(encrypted.len() <= MAX_NOISE_MESSAGE);
        let decoded =
            enclos_protocol::device::decode_to_device(&device_session.decrypt(&encrypted).unwrap())
                .unwrap();
        if let ToDevice::AgentName(name) = decoded.body {
            assert!(name.of.is_empty());
            *restored
                .get_mut(&name.agent)
                .expect("canonical inventory address") = NameMetadata {
                revision: name.revision,
                display_name: name.display_name,
            };
        }
    }
    for agent in &original {
        assert_eq!(
            restored[&agent.agent],
            NameMetadata {
                revision: agent.name_revision,
                display_name: agent.display_name.clone()
            }
        );
    }
    assert_eq!(restored["lab/comptoir-dev-001"].display_name, None);
    assert_eq!(
        restored["lab/comptoir-dev-001"].revision, 1,
        "cleared state keeps its revision"
    );
    let normal = agent_names::agent_inventory_messages(original[2..3].to_vec()).unwrap();
    assert_eq!(
        normal,
        vec![ToDevice::AgentsList {
            agents: original[2..3].to_vec()
        }],
        "ordinary inventories keep names inline"
    );
    let too_many: Vec<_> = (0..500)
        .map(|i| {
            let mut agent = original[0].clone();
            agent.agent = format!("lab/agent-{i:03}");
            agent
        })
        .collect();
    assert!(
        agent_names::agent_inventory_messages(too_many).is_err(),
        "an oversized base inventory reports a size error rather than truncating agents"
    );
}

#[test]
fn name_changes_are_owner_only_validated_and_published_to_still_paired_devices() {
    use enclos_protocol::agent_name::NameSet;
    use enclos_protocol::plugin::ErrorCode;
    let (dir, mut hub, store) = diagnostic_approval_hub();
    Arc::get_mut(&mut hub).unwrap().agents.extend(
        ["lab/comptoir-dev", "other/comptoir-dev", "lab/Geg"].map(|name| AgentEndpoint {
            name: name.into(),
            runtime: "hermes".into(),
            socket: dir.path().join("not-connected.sock"),
            token: "fixture".into(),
        }),
    );
    let owner = avatar_device("phone", "owner@example.com");
    let guest = avatar_device("tablet", "guest@example.com");
    let revoked = avatar_device("revoked", "owner@example.com");
    store.add_device(&owner).unwrap();
    store.add_device(&guest).unwrap();
    let (s1, r1) = channel();
    let (s2, r2) = channel();
    let (s3, r3) = channel();
    hub.devices.lock().unwrap().extend([
        (owner.id.clone(), (owner.person.clone(), s1)),
        (guest.id.clone(), (guest.person.clone(), s2)),
        (revoked.id.clone(), (revoked.person.clone(), s3)),
    ]);
    let edit = NameSet {
        agent: "lab/comptoir-dev".into(),
        revision: 0,
        display_name: Some("  Gégé Commit  ".into()),
    };
    assert_eq!(
        hub.set_agent_name(&store, &guest, &guest.person, &edit, "denied".into())
            .unwrap_err()
            .code,
        ErrorCode::NotAllowed
    );
    assert_eq!(
        hub.set_agent_name(&store, &revoked, &revoked.person, &edit, "denied".into())
            .unwrap_err()
            .code,
        ErrorCode::NotAllowed
    );
    assert_eq!(
        hub.get_agent_name(
            &store,
            &owner,
            &owner.person,
            "missing/agent",
            "read".into()
        )
        .unwrap_err()
        .code,
        ErrorCode::NotAllowed
    );
    let reply = hub
        .set_agent_name(&store, &owner, &owner.person, &edit, "saved".into())
        .unwrap();
    let ToDevice::AgentName(name) = reply else {
        panic!("not a name reply");
    };
    assert_eq!(name.of, "saved");
    assert_eq!(name.agent, "lab/comptoir-dev");
    assert_eq!(name.display_name.as_deref(), Some("Gégé Commit"));
    assert_eq!(name.revision, 1);
    let published = r1.try_recv().unwrap();
    assert_eq!(published, r2.try_recv().unwrap());
    assert!(r3.try_recv().is_err());
    assert!(
        matches!(published, ToDevice::AgentName(ref n) if n.of.is_empty() && n.display_name == name.display_name && n.agent == "lab/comptoir-dev")
    );
    assert!(
        hub.get_agent_name(&store, &guest, &guest.person, &edit.agent, "read".into())
            .is_ok()
    );
    assert_eq!(
        hub.set_agent_name(&store, &owner, &owner.person, &edit, "stale".into())
            .unwrap_err()
            .code,
        ErrorCode::Conflict
    );
    assert!(r1.try_recv().is_err());
    for bad in [Some(""), Some("\n"), Some("bad\u{2028}name")] {
        let invalid = NameSet {
            revision: 1,
            display_name: bad.map(str::to_owned),
            ..edit.clone()
        };
        assert_eq!(
            hub.set_agent_name(&store, &owner, &owner.person, &invalid, "bad".into())
                .unwrap_err()
                .code,
            ErrorCode::BadMessage
        );
    }
    let negative = NameSet {
        revision: -1,
        ..edit.clone()
    };
    assert_eq!(
        hub.set_agent_name(&store, &owner, &owner.person, &negative, "bad".into())
            .unwrap_err()
            .code,
        ErrorCode::BadMessage
    );
    assert_eq!(store.agent_name("lab/comptoir-dev").unwrap().revision, 1);
    assert_eq!(
        store.agent_name("other/comptoir-dev").unwrap().display_name,
        None,
        "equal handles on other sandboxes retain their names"
    );
    let same_handle = NameSet {
        revision: 1,
        display_name: Some("Geg".into()),
        ..edit.clone()
    };
    hub.set_agent_name(
        &store,
        &owner,
        &owner.person,
        &same_handle,
        "collision".into(),
    )
    .unwrap();
    assert_eq!(
        store.agent_name("lab/Geg").unwrap().display_name,
        None,
        "a display name never addresses another agent"
    );
    assert_eq!(hub.agents[0].name, "lab/comptoir-dev");
    assert!(hub.plugins.lock().unwrap().is_empty());
    r1.try_recv().unwrap();
    r2.try_recv().unwrap();
    let no_change = NameSet {
        revision: 2,
        ..same_handle.clone()
    };
    hub.set_agent_name(&store, &owner, &owner.person, &no_change, "noop".into())
        .unwrap();
    assert!(r1.try_recv().is_err());
    assert!(r2.try_recv().is_err());
    store.remove_device(&guest.id).unwrap();
    assert_eq!(
        hub.get_agent_name(&store, &guest, &guest.person, &edit.agent, "read".into())
            .unwrap_err()
            .code,
        ErrorCode::NotAllowed
    );
    let clear = NameSet {
        revision: 2,
        display_name: None,
        ..edit
    };
    hub.set_agent_name(&store, &owner, &owner.person, &clear, "clear".into())
        .unwrap();
    assert!(
        matches!(r1.try_recv().unwrap(), ToDevice::AgentName(n) if n.revision == 3 && n.display_name.is_none())
    );
    assert!(r2.try_recv().is_err());
    assert!(r3.try_recv().is_err());
}
#[test]
fn avatar_normalizes_to_a_bounded_square_and_refuses_untrusted_input() {
    use enclos_protocol::avatar::MAX_AVATAR_BYTES;
    let input = avatar_fixture(100, 60);
    let out = avatars::normalize(&input).unwrap();
    let decoded = image::load_from_memory(&out).unwrap();
    assert_eq!((decoded.width(), decoded.height()), (256, 256));
    assert!(out.starts_with(&[0xff, 0xd8]) && out.len() <= MAX_AVATAR_BYTES);
    for invalid in [
        vec![],
        vec![0; MAX_AVATAR_BYTES + 1],
        b"<svg onload='alert(1)'/>".to_vec(),
        input[..input.len() / 2].to_vec(),
        avatar_fixture(513, 1),
    ] {
        assert!(avatars::normalize(&invalid).is_err());
    }
}
#[test]
fn avatar_persistence_conflicts_and_removal_survive_other_connections_and_restart() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("app.db");
    let first = Store::open(&path).unwrap();
    let second = Store::open(&path).unwrap();
    let original = first
        .set_avatar("lab/coder", 0, Some(b"image"), ("d1", "owner"))
        .unwrap()
        .unwrap();
    assert_eq!(second.avatar("lab/coder").unwrap(), original);
    assert_eq!(original.version, Some(crate::policy::sha256_hex(b"image")));
    assert!(
        second
            .set_avatar("lab/coder", 0, None, ("d2", "owner"))
            .unwrap()
            .is_none()
    );
    assert_eq!(first.log_lines(10).unwrap().len(), 1);
    let removed = second
        .set_avatar("lab/coder", 1, None, ("d2", "owner"))
        .unwrap()
        .unwrap();
    assert_eq!(removed.revision, 2);
    assert_eq!(removed.image, None);
    assert_eq!(removed.version, None);
    drop(first);
    drop(second);
    let reopened = Store::open(&path).unwrap();
    assert_eq!(reopened.avatar("lab/coder").unwrap(), removed);
    assert_eq!(reopened.avatar_metadata().unwrap()["lab/coder"].revision, 2);
    assert!(
        reopened
            .set_avatar("lab/coder", 1, Some(b"stale"), ("d1", "owner"))
            .unwrap()
            .is_none()
    );
    assert_eq!(reopened.avatar("other/coder").unwrap().revision, 0);
}
#[test]
fn avatar_owner_changes_broadcast_to_paired_devices_but_guests_and_revoked_devices_cannot_write() {
    use enclos_protocol::avatar::AvatarSet;
    let (dir, mut hub, store) = diagnostic_approval_hub();
    Arc::get_mut(&mut hub).unwrap().agents.push(AgentEndpoint {
        name: "lab/coder".into(),
        runtime: "hermes".into(),
        socket: dir.path().join("unused.sock"),
        token: "fixture".into(),
    });
    let owner = avatar_device("phone", "owner@example.com");
    let guest = avatar_device("tablet", "guest@example.com");
    let revoked = avatar_device("revoked", "owner@example.com");
    store.add_device(&owner).unwrap();
    store.add_device(&guest).unwrap();
    let (s1, r1) = channel();
    let (s2, r2) = channel();
    let (s3, r3) = channel();
    hub.devices.lock().unwrap().extend([
        (owner.id.clone(), (owner.person.clone(), s1)),
        (guest.id.clone(), (guest.person.clone(), s2)),
        (revoked.id.clone(), (revoked.person.clone(), s3)),
    ]);
    let edit = AvatarSet {
        agent: "lab/coder".into(),
        revision: 0,
        image: Some(encode(&avatar_fixture(40, 40))),
    };
    assert!(
        hub.set_agent_avatar(&store, &guest, &guest.person, &edit, "denied".into())
            .unwrap_err()
            .contains("Only the host")
    );
    assert!(
        hub.set_agent_avatar(&store, &revoked, &revoked.person, &edit, "denied".into())
            .is_err()
    );
    assert!(
        hub.get_avatar(&store, &owner, &owner.person, "lab/missing", "read".into())
            .is_err()
    );
    assert_eq!(store.avatar("lab/coder").unwrap().revision, 0);
    let reply = hub
        .set_agent_avatar(&store, &owner, &owner.person, &edit, "saved".into())
        .unwrap();
    let broadcast = r1.try_recv().unwrap();
    assert_eq!(broadcast, r2.try_recv().unwrap());
    assert!(r3.try_recv().is_err());
    let ToDevice::AgentAvatar(photo) = reply else {
        panic!("photo reply")
    };
    assert_eq!(photo.of, "saved");
    assert_eq!(photo.revision, 1);
    assert!(
        matches!(broadcast,ToDevice::AgentAvatar(ref p) if p.of.is_empty() && p.version==photo.version)
    );
    assert!(
        hub.get_avatar(&store, &guest, &guest.person, "lab/coder", "read".into())
            .is_ok()
    );
    assert!(
        hub.set_agent_avatar(&store, &owner, &owner.person, &edit, "stale".into())
            .is_err()
    );
    assert!(r1.try_recv().is_err());
    for image in ["%%%".to_owned(), "A".repeat(50_000)] {
        assert!(
            hub.set_agent_avatar(
                &store,
                &owner,
                &owner.person,
                &AvatarSet {
                    image: Some(image),
                    revision: 1,
                    ..edit.clone()
                },
                "bad".into()
            )
            .is_err()
        );
    }
    assert_eq!(store.avatar("lab/coder").unwrap().revision, 1);
    let removal = AvatarSet {
        revision: 1,
        image: None,
        ..edit
    };
    hub.set_agent_avatar(&store, &owner, &owner.person, &removal, "removed".into())
        .unwrap();
    assert!(
        matches!(r2.try_recv().unwrap(),ToDevice::AgentAvatar(p) if p.image.is_none() && p.revision==2)
    );
    store.remove_device(&guest.id).unwrap();
    assert!(
        hub.get_avatar(&store, &guest, &guest.person, "lab/coder", "read".into())
            .is_err()
    );
}
