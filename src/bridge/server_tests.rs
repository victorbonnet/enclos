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
        commands: Mutex::new(HashMap::new()),
        groups: Mutex::new(HashMap::new()),
        stops: Mutex::new(Default::default()),
        devices: Mutex::new(HashMap::new()),
    });
    let store = hub.store().unwrap();
    (dir, hub, store)
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
