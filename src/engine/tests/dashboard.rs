//! `enclos dashboard` where it has nothing to serve. CI's `bubblewrap` job
//! runs it for real (`tests/dashboard.rs`).

use std::sync::atomic::AtomicBool;

use super::policy::with_sandbox;
use super::*;
use crate::model::runtime::RuntimeKind;

/// A dashboard of a sandbox not yet running starts no session or service.
#[test]
fn a_sandbox_not_running_is_refused_before_anything_starts() {
    let (_dir, engine, name) = with_sandbox();
    engine
        .write(
            &alice(),
            "test",
            None,
            |_| String::new(),
            |lock| {
                let mut record = engine.state.get(&name)?.unwrap();
                record.runtime = Some(RuntimeKind::Hermes);
                Ok(engine.state.put(lock, &record)?)
            },
        )
        .unwrap();
    let audited = engine.audit(None).unwrap().len();
    let mut opened = |_: &crate::engine::DashboardOpen| panic!("it served");
    let refused = engine
        .dashboard_until(&alice(), &name, &AtomicBool::new(false), &mut opened)
        .unwrap_err();
    let Error::Dashboard { what } = refused else {
        panic!("{refused}");
    };
    assert!(what.contains("not running"), "{what}");
    assert!(what.contains("enclos sandbox start home"), "{what}");
    assert!(engine.state.sessions(&name, true).unwrap().is_empty());
    assert_eq!(engine.audit(None).unwrap().len(), audited);
    assert!(!engine.layout.dashboard_lock("home").exists());
}

#[test]
fn missing_runtime_files_offer_no_dashboard_and_start_nothing() {
    use crate::model::sandbox::SandboxState;
    for state in [
        SandboxState::Stopped,
        SandboxState::Failed {
            reason: "test".into(),
        },
        SandboxState::Running,
    ] {
        let (_dir, engine, name) = with_sandbox();
        engine
            .write(
                &alice(),
                "test",
                None,
                |_| String::new(),
                |lock| {
                    let mut record = engine.record(&name)?;
                    record.runtime = Some(RuntimeKind::Hermes);
                    record.state = state.clone();
                    Ok(engine.state.put(lock, &record)?)
                },
            )
            .unwrap();
        let audited = engine.audit(None).unwrap().len();
        let refused = engine
            .dashboard_until(&alice(), &name, &AtomicBool::new(false), &mut |_| {
                panic!("it served")
            })
            .unwrap_err();
        let Error::Dashboard { what } = refused else {
            panic!("{refused}");
        };
        assert!(
            what.contains("not running") || what.contains("files are missing"),
            "{what}"
        );
        assert!(engine.state.sessions(&name, true).unwrap().is_empty());
        assert_eq!(engine.audit(None).unwrap().len(), audited);
        assert!(!engine.layout.dashboard_lock("home").exists());
        assert_eq!(
            engine.status(Some(&name)).unwrap().sandboxes[0].dashboard_command,
            None
        );
    }
}

#[test]
fn the_private_dashboard_uses_the_host_url_one_lock_and_an_audited_session() {
    let _turn = crate::host_ports::HostPorts
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    use crate::model::sandbox::SandboxState;
    use crate::model::session::{SessionId, SessionKind, SessionRecord};
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::Ordering;
    let root = super::Root {
        parent: std::path::PathBuf::from("/tmp"),
        leaf: "e".into(),
    };
    let (_dir, engine, name) =
        super::policy::with_sandbox_under(FakeBackend::available(BackendKind::Seatbelt), &root);
    let home = engine.sandbox_home(&name);
    std::fs::create_dir_all(home.join(".hermes/hermes-agent")).unwrap();
    std::fs::create_dir_all(home.join("bin")).unwrap();
    let hermes = home.join("bin/hermes");
    std::fs::write(
        &hermes,
        r##"#!/usr/bin/python3
import os, socket
print('http://untrusted.invalid/dashboard', flush=True)
s = socket.socket(fileno=int(os.environ['ENCLOS_DASHBOARD_FD']))
while True:
    client, _ = s.accept()
    try:
        client.recv(4096)
        client.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nsecret')
    except OSError:
        pass
    finally:
        client.close()
"##,
    )
    .unwrap();
    std::fs::set_permissions(&hermes, std::fs::Permissions::from_mode(0o700)).unwrap();
    let (mut proxy, _) = super::listener::gateway(&engine, &name, 1);
    let reference = crate::lifecycle::process::reference_of_child(&proxy).unwrap();
    engine
        .write(
            &alice(),
            "test",
            None,
            |_| String::new(),
            |lock| {
                let mut record = engine.record(&name)?;
                record.runtime = Some(RuntimeKind::Hermes);
                record.state = SandboxState::Running;
                engine.state.put(lock, &record)?;
                let session = SessionRecord {
                    id: SessionId(0),
                    sandbox: name.clone(),
                    kind: SessionKind::Proxy,
                    service: None,
                    version: 1,
                    snapshot: engine.policy(&name)?.snapshot.id,
                    compiled: None,
                    root: reference.clone(),
                    pgid: None,
                    cgroup: None,
                    tracked: vec![],
                    started_at: crate::model::now(),
                    ended_at: None,
                };
                engine.state.start_session(lock, &session, &record)?;
                Ok(())
            },
        )
        .unwrap();
    let ended = AtomicBool::new(false);
    let mut shown = None;
    let result = engine.dashboard_until(&alice(), &name, &ended, &mut |open| {
        assert!(
            !(crate::model::sandbox::PORT_FIRST..=crate::model::sandbox::PORT_LAST)
                .contains(&open.port)
        );
        assert!(
            open.url
                .starts_with(&format!("http://127.0.0.1:{}/", open.port))
        );
        assert_ne!(open.port, engine.record(&name).unwrap().proxy_port);
        let second = engine
            .dashboard_until(&alice(), &name, &AtomicBool::new(false), &mut |_| {
                panic!("second served")
            })
            .unwrap_err();
        assert!(
            second.to_string().contains("already has a dashboard"),
            "{second}"
        );
        let capability = open.url.split('/').nth(3).unwrap();
        assert!(!second.to_string().contains(capability));
        let lock = std::fs::read_to_string(engine.layout.dashboard_lock(name.as_str())).unwrap();
        assert!(!lock.contains(capability));
        let mut client = TcpStream::connect(("127.0.0.1", open.port)).unwrap();
        client
            .set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .unwrap();
        let path = open
            .url
            .strip_prefix(&format!("http://127.0.0.1:{}", open.port))
            .unwrap();
        client
            .write_all(format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n").as_bytes())
            .unwrap();
        let mut answer = String::new();
        client.read_to_string(&mut answer).unwrap();
        assert!(answer.ends_with("secret"), "{answer}");
        shown = Some(open.clone());
        ended.store(true, Ordering::Relaxed);
    });
    let _ = proxy.kill();
    let _ = proxy.wait();
    let result = result.unwrap();
    assert!(
        result.failed.is_none(),
        "{:?}: {}",
        result.failed,
        std::fs::read_to_string(engine.dashboard_log(&name)).unwrap_or_default()
    );
    let shown = shown.expect("opened");
    assert!(TcpStream::connect(("127.0.0.1", shown.port)).is_err());
    assert!(!engine.layout.dashboard_socket(name.as_str()).exists());
    assert!(
        !home
            .join(".hermes/hermes-agent/_enclos_dashboard.py")
            .exists()
    );
    assert!(
        engine
            .state
            .sessions(&name, true)
            .unwrap()
            .iter()
            .all(|s| s.id != shown.session)
    );
    let audited = engine.audit(None).unwrap();
    for command in ["dashboard", "dashboard end"] {
        assert!(
            audited.iter().any(|entry| entry.intent.command == command),
            "{command}"
        );
    }
}
