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
fn an_html_artefact_keeps_its_bytes_and_type_as_an_attachment() {
    let (_dir, home, inbox, media) = folders();
    let html = b"<!doctype html><meta charset=utf-8><style>h1{color:green}</style><h1>Report</h1>";
    std::fs::write(inbox.join("report.html"), html).unwrap();
    let a = OutAttachment {
        file: "report.html".into(),
        mime: "text/html".into(),
        name: "report.html".into(),
        size: html.len() as u64,
    };
    let taken = take_attachment(&home, &media, "c-1", &a).unwrap();
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

#[test]
fn an_attachment_name_loses_its_hidden_characters() {
    let (_dir, home, inbox, media) = folders();
    std::fs::write(inbox.join("a3.bin"), b"x").unwrap();
    let mut a = out("a3.bin");
    a.mime = "text/html".to_owned();
    a.name = "report\u{202E}lmth.txt\nsecond line".to_owned();
    assert_eq!(
        take_attachment(&home, &media, "c-1", &a).unwrap().name,
        "reportlmth.txtsecond line"
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
        scope: "example.com".into(),
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
    let mut hub = Arc::new(Hub::new(
        Transport::Tailscale,
        no_whois(),
        dir.path().join("app.db"),
        crate::layout::Layout::at(dir.path().join("enclos")),
        vec![],
        vec![],
        Some("owner@example.com".into()),
        SILENCE,
    ));
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
        node: None,
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
fn accepted_access_labels_the_entry_the_engine_wrote() {
    use enclos_protocol::approval::{Access, AccessKind};
    let net = |target: &str, private| Access {
        kind: AccessKind::Network,
        target: target.into(),
        private,
    };
    assert!(policy::accepted_entry(
        "allow",
        "api.example.com",
        &net("API.Example.com:443", false)
    ));
    assert!(policy::accepted_entry(
        "allow",
        "api.example.com:8443",
        &net("api.example.com:8443", false)
    ));
    assert!(!policy::accepted_entry(
        "allow",
        "api.example.com",
        &net("api.example.com:8443", false)
    ));
    assert!(policy::accepted_entry(
        "private",
        "nas.local",
        &net("NAS.local:8443", true)
    ));
    assert!(!policy::accepted_entry(
        "private",
        "nas.local",
        &net("nas.local:8443", false)
    ));
    let dir = tempfile::tempdir().unwrap();
    let real = dir.path().join("real");
    std::fs::create_dir(&real).unwrap();
    std::os::unix::fs::symlink(&real, dir.path().join("alias")).unwrap();
    let write = Access {
        kind: AccessKind::Write,
        target: dir.path().join("alias").display().to_string(),
        private: false,
    };
    let stored = crate::policy::paths::real_path(&real).display().to_string();
    assert!(policy::accepted_entry("write", &stored, &write));
    assert!(!policy::accepted_entry("allow", &stored, &write));
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
    let hub = Arc::new(Hub::new(
        Transport::Tailscale,
        no_whois(),
        dir.path().join("app.db"),
        crate::layout::Layout::at(dir.path().join("enclos")),
        vec![],
        vec![],
        Some("owner@example.com".into()),
        SILENCE,
    ));
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
fn diagnostic_probe_requests_are_matched_against_one_read_of_the_log() {
    use crate::model::net::{DeniedDestination, Reason};
    let denied = |host: &str, reason| DeniedDestination {
        host: host.into(),
        port: 443,
        reason,
        count: 1,
        first: jiff::Timestamp::UNIX_EPOCH,
        last: jiff::Timestamp::UNIX_EPOCH,
    };
    let mut a = approval_sample();
    a.agent.clear();
    a.access.target = "10.0.0.1:443".into();
    let probe_only = (vec![denied("10.0.0.1", Reason::PrivateAddress)], vec![]);
    assert!(approvals::only_probe_events(&a, &probe_only));
    // Refused outside a diagnostic run too: a real request.
    let both = (
        vec![denied("10.0.0.1", Reason::PrivateAddress)],
        vec![denied("10.0.0.1", Reason::PrivateAddress)],
    );
    assert!(!approvals::only_probe_events(&a, &both));
    // Another destination, or an agent's explicit request, is not the probe's.
    assert!(!approvals::only_probe_events(
        &a,
        &(vec![denied("10.0.0.2", Reason::PrivateAddress)], vec![])
    ));
    a.agent = "lab/main".into();
    assert!(!approvals::only_probe_events(&a, &probe_only));
}

#[test]
fn diagnostic_probe_existing_pending_notification_is_dismissed_and_broadcast() {
    let (_dir, hub, store) = diagnostic_approval_hub();
    let (tx, rx) = channel();
    hub.devices
        .lock()
        .unwrap()
        .insert("d1".into(), ("owner@example.com".into(), tx, 1));
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
        node: None,
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

/// A hub of the host's person, with no enclos set up beside it.
fn approval_hub() -> (tempfile::TempDir, Arc<Hub>, Store) {
    let dir = tempfile::tempdir().unwrap();
    let hub = Arc::new(Hub::new(
        Transport::Tailscale,
        no_whois(),
        dir.path().join("app.db"),
        crate::layout::Layout::at(dir.path().join("enclos")),
        vec![],
        vec![],
        Some("owner@example.com".into()),
        SILENCE,
    ));
    let store = hub.store().unwrap();
    (dir, hub, store)
}

fn network(target: &str) -> enclos_protocol::approval::Access {
    enclos_protocol::approval::Access {
        kind: enclos_protocol::approval::AccessKind::Network,
        target: target.into(),
        private: false,
    }
}

#[test]
fn approval_requests_are_capped_per_sandbox_for_agents_and_proxies_alike() {
    let (_dir, hub, store) = approval_hub();
    for i in 0..approvals::MAX_PENDING {
        hub.request_access(
            &store,
            "lab/main",
            None,
            network(&format!("a{i}.example.com")),
            "",
        )
        .unwrap();
    }
    let refused = hub
        .request_access(&store, "lab/main", None, network("more.example.com"), "")
        .unwrap_err();
    assert!(refused.contains("pending policy requests"), "{refused}");
    // A proxy refusal is left for a later collection, without an error.
    hub.request_access(&store, "lab", None, network("proxy.example.com"), "")
        .unwrap();
    // Another sandbox has its own room.
    hub.request_access(&store, "other/main", None, network("more.example.com"), "")
        .unwrap();
    let pending = store.approvals().unwrap();
    assert_eq!(
        pending.iter().filter(|a| a.sandbox == "lab").count(),
        approvals::MAX_PENDING
    );
    assert_eq!(pending.len(), approvals::MAX_PENDING + 1);
}

#[test]
fn an_agents_request_for_a_scope_already_open_upgrades_it_even_at_the_cap() {
    let (_dir, hub, store) = approval_hub();
    // A proxy refusal opened it, then the sandbox filled up
    hub.request_access(&store, "lab", None, network("api.example.com"), "")
        .unwrap();
    for i in 1..approvals::MAX_PENDING {
        hub.request_access(
            &store,
            "lab",
            None,
            network(&format!("a{i}.example.com")),
            "",
        )
        .unwrap();
    }
    // The agent's explicit request for the same scope adds nothing: it is
    // not refused by the cap, and the open request becomes the agent's
    hub.request_access(
        &store,
        "lab/main",
        None,
        network("api.example.com"),
        "Fetch the forecast",
    )
    .unwrap();
    let open = store.approvals().unwrap();
    assert_eq!(open.len(), approvals::MAX_PENDING);
    let upgraded = open
        .iter()
        .find(|a| a.access.target == "api.example.com")
        .unwrap();
    assert_eq!(
        (upgraded.agent.as_str(), upgraded.action.as_str()),
        ("lab/main", "Fetch the forecast")
    );
    // A new scope is still refused
    assert!(
        hub.request_access(&store, "lab/main", None, network("new.example.com"), "")
            .is_err()
    );
}

#[test]
fn approval_requests_refuse_hidden_characters_and_strip_them_from_labels() {
    let (_dir, hub, store) = approval_hub();
    assert!(
        hub.request_access(
            &store,
            "lab/main",
            None,
            network("a.example.com\u{202E}"),
            ""
        )
        .is_err()
    );
    hub.request_access(
        &store,
        "lab/main",
        None,
        network("b.example.com"),
        "Read \u{202E}txt.emdaer\u{200B}",
    )
    .unwrap();
    let saved = store.approvals().unwrap();
    assert_eq!(saved.len(), 1);
    assert_eq!(saved[0].action, "Read txt.emdaer");
}

#[test]
fn approval_a_refusal_counts_once_and_a_denial_is_not_asked_again() {
    let mut denied = approval_sample();
    denied.state = "denied".into();
    denied.time = 100;
    let known = [denied.clone()];
    let access = &denied.access;
    // Older than the bridge's first collection: never asked.
    assert!(approvals::refusal_counted(&[], "lab", access, 40, 50));
    // Seen before the request was made: that request had it, whatever the
    // policy became since.
    assert!(approvals::refusal_counted(&known, "lab", access, 90, 50));
    assert!(approvals::refusal_counted(&known, "lab", access, 100, 50));
    // Tried again after it: a new refusal.
    assert!(!approvals::refusal_counted(&known, "lab", access, 101, 50));
    // Another sandbox, scope or opt-in is another request.
    assert!(!approvals::refusal_counted(&known, "other", access, 90, 50));
    let mut private = access.clone();
    private.private = true;
    assert!(!approvals::refusal_counted(&known, "lab", &private, 90, 50));
    assert!(!approvals::refusal_counted(
        &known,
        "lab",
        &network("other.example.com"),
        90,
        50
    ));
}

#[test]
fn approval_refusals_are_collected_from_the_first_collection_on() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("app.db");
    let first = Store::open(&path).unwrap().refusals_since().unwrap();
    assert!(first > 0);
    // Kept, not moved forward, by later collections and restarts.
    assert_eq!(Store::open(&path).unwrap().refusals_since().unwrap(), first);
}

#[test]
fn approval_requests_name_only_the_agents_own_conversations_or_groups() {
    let (_dir, _hub, store) = approval_hub();
    store
        .ensure_home("lab/main", "owner@example.com", true)
        .unwrap();
    let home = crate::bridge::store::home_id("lab/main");
    assert!(approvals::speaks_in(&store, "lab/main", &home));
    assert!(!approvals::speaks_in(&store, "lab/coder", &home));
    assert!(!approvals::speaks_in(&store, "other/main", &home));
    assert!(!approvals::speaks_in(&store, "lab/main", "unknown"));
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
    let hub = Hub::new(
        Transport::Tailscale,
        no_whois(),
        dir.join("app.db"),
        crate::layout::Layout::at(dir.join("enclos")),
        vec![0; 32],
        Vec::new(),
        None,
        SILENCE,
    );
    *hub.devices.lock().unwrap() = devices;
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

/// A hub serving `lab/<name>` for each of `names`, each with its plugin's
/// socket in `dir`, and no device yet.
fn hub(dir: &std::path::Path, names: &[&str]) -> Arc<Hub> {
    let agents = names
        .iter()
        .map(|name| AgentEndpoint {
            name: format!("lab/{name}"),
            runtime: "hermes".to_owned(),
            socket: dir.join(format!("{name}.sock")),
            token: "t0ken".to_owned(),
        })
        .collect();
    Arc::new(Hub::new(
        Transport::Tailscale,
        no_whois(),
        dir.join("bridge.db"),
        crate::layout::Layout::at(dir.join("enclos")),
        vec![7; 32],
        agents,
        Some("alice@example.com".to_owned()),
        SILENCE,
    ))
}

/// A transport that knows no caller: these tests open no device connection.
fn no_whois() -> Whois {
    Arc::new(|_: &str| Err("no transport in this test".to_owned()))
}

/// One connection of a stand-in plugin: its `hello`'s capabilities, the
/// `commands` it sends then, and whether it closes after.
struct Answer {
    capabilities: Vec<Capability>,
    commands: Option<Vec<Command>>,
    closes: bool,
}

/// A stand-in plugin at `socket`: answers each connection in turn as
/// `answers` say, the last one kept open until the bridge closes it.
fn stand_in_plugin(socket: &std::path::Path, answers: Vec<Answer>) {
    use std::io::{BufRead, BufReader, Write};
    let listener = std::os::unix::net::UnixListener::bind(socket).unwrap();
    std::thread::spawn(move || {
        for answer in answers {
            let (stream, _) = listener.accept().unwrap();
            let mut out = stream.try_clone().unwrap();
            let mut lines = BufReader::new(stream);
            let mut line = Vec::new();
            lines.read_until(b'\n', &mut line).unwrap();
            let mut send = |body: FromPlugin| {
                let id = MessageId::new(new_id().unwrap()).unwrap();
                out.write_all(&encode_line(&Envelope::new(id, body)))
                    .unwrap();
            };
            send(FromPlugin::Hello {
                runtime: "hermes".into(),
                agent: "main".into(),
                capabilities: answer.capabilities,
            });
            if let Some(commands) = answer.commands {
                send(FromPlugin::Commands { commands });
            }
            if !answer.closes {
                while lines.read_until(b'\n', &mut line).unwrap_or(0) > 0 {}
            }
        }
    });
}

fn command(name: &str, description: &str) -> Command {
    Command {
        name: name.to_owned(),
        description: description.to_owned(),
        args: None,
    }
}

/// Waits up to 5 seconds for `done`.
fn until(done: impl Fn() -> bool) {
    let started = std::time::Instant::now();
    while !done() {
        assert!(started.elapsed() < Duration::from_secs(5), "never came");
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn an_agents_commands_are_cleaned_kept_and_sent_to_every_device() {
    let dir = tempfile::tempdir().unwrap();
    let hub = hub(dir.path(), &["main"]);
    stand_in_plugin(
        &dir.path().join("main.sock"),
        vec![
            Answer {
                capabilities: vec![Capability::Commands],
                commands: Some(vec![
                    command("new", "Start\u{202E} a new\n session"),
                    command("Bad Name", "left out"),
                ]),
                closes: true,
            },
            Answer {
                capabilities: Vec::new(),
                commands: None,
                closes: false,
            },
        ],
    );
    let (alice, from_alice) = channel();
    let (bob, from_bob) = channel();
    {
        let mut devices = hub.devices.lock().unwrap();
        devices.insert("d-1".to_owned(), ("alice@example.com".to_owned(), alice, 1));
        devices.insert("d-2".to_owned(), ("bob@example.com".to_owned(), bob, 2));
    }
    let listed = |commands: Vec<Command>| ToDevice::Commands {
        agent: "lab/main".to_owned(),
        commands,
    };
    let cleaned = vec![command("new", "Start a new session")];

    hub.plugin("lab/main").unwrap();
    for device in [&from_alice, &from_bob] {
        let got = device.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(got, listed(cleaned.clone()));
    }
    // Kept once the plugin is gone, and sent after the agents' list.
    until(|| !hub.plugins.lock().unwrap().contains_key("lab/main"));
    let answer = hub.agents_answer();
    assert!(matches!(&answer[0], ToDevice::AgentsList { agents } if agents.len() == 1));
    assert_eq!(answer[1..], [listed(cleaned)]);

    // Connected again without the capability: its old list is dropped.
    hub.plugin("lab/main").unwrap();
    for device in [&from_alice, &from_bob] {
        let got = device.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(got, listed(Vec::new()));
    }
    assert_eq!(hub.agents_answer().len(), 1);
}

#[test]
fn a_plugin_that_stalls_its_hello_holds_up_no_other_agent() {
    let dir = tempfile::tempdir().unwrap();
    let hub = hub(dir.path(), &["slow", "main"]);
    // `slow` takes the connection and says nothing until released.
    let slow = std::os::unix::net::UnixListener::bind(dir.path().join("slow.sock")).unwrap();
    let (accepted, was_accepted) = channel();
    let (release, released) = channel::<()>();
    std::thread::spawn(move || {
        let (stream, _) = slow.accept().unwrap();
        accepted.send(()).unwrap();
        let _ = released.recv();
        drop(stream);
    });
    stand_in_plugin(
        &dir.path().join("main.sock"),
        vec![Answer {
            capabilities: vec![Capability::Commands],
            commands: None,
            closes: false,
        }],
    );

    hub.open_plugins();
    was_accepted.recv_timeout(Duration::from_secs(5)).unwrap();
    assert!(hub.opening_all.load(Ordering::SeqCst), "one pass, running");
    hub.open_plugins(); // another request while it runs: no second pass

    let started = std::time::Instant::now();
    assert!(matches!(
        &hub.agents_answer()[0],
        ToDevice::AgentsList { .. }
    ));
    hub.plugin("lab/main").unwrap();
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "waited {:?} on another agent's hello",
        started.elapsed()
    );

    drop(release);
    until(|| !hub.opening_all.load(Ordering::SeqCst));
    assert!(!hub.plugins.lock().unwrap().contains_key("lab/slow"));
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
