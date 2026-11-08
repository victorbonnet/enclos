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
fn approval_authority_requires_the_host_person_and_a_still_paired_device() {
    let dir = tempfile::tempdir().unwrap();
    let hub = Arc::new(Hub {
        transport: Transport::Tailscale,
        store_path: dir.path().join("app.db"),
        layout: crate::layout::Layout::at(dir.path().join("enclos")),
        bridge_private: vec![],
        agents: vec![],
        host: Some("owner@example.com".into()),
        plugins: Mutex::new(HashMap::new()),
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
    assert!(store.approvals().unwrap().is_empty());
}
