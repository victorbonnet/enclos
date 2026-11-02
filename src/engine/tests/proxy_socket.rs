//! The sandbox's proxy on its Unix socket (design §5, Linux networking).

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;

use super::policy::with_sandbox;
use super::*;
use crate::model::net::{Reason, Verdict};

#[test]
fn a_running_proxy_decides_and_logs_on_its_socket() {
    let (_dir, engine, name) = with_sandbox();
    let layout = engine.layout.clone();
    let proxied = name.clone();
    std::thread::spawn(move || {
        let state = SqliteStateStore::new(layout.state_db(), layout.state_lock());
        let audit = JsonlAuditLog::new(layout.audit_log());
        let engine = Engine::new(layout, Box::new(state), Box::new(audit), Vec::new());
        engine.run_proxy(&proxied, 0, None)
    });
    let path = engine.layout.proxy_socket(name.as_str());
    let started = std::time::Instant::now();
    let mut conn = loop {
        match UnixStream::connect(&path) {
            Ok(conn) => break conn,
            Err(e) if started.elapsed().as_secs() > 30 => panic!("{e}"),
            Err(_) => std::thread::sleep(std::time::Duration::from_millis(10)),
        }
    };
    // Not a web port, so public mode does not allow it either.
    conn.write_all(b"CONNECT evil.example.com:9 HTTP/1.1\r\n\r\n")
        .unwrap();
    let mut reply = String::new();
    conn.read_to_string(&mut reply).unwrap();
    assert!(reply.starts_with("HTTP/1.1 403"), "{reply}");
    let log = engine.net_log(&name, None).unwrap();
    assert_eq!(log.len(), 1);
    assert_eq!(
        (log[0].host.as_str(), log[0].verdict, log[0].reason),
        (
            "evil.example.com",
            Verdict::Denied,
            Some(Reason::NotAllowed)
        )
    );
}

/// An engine whose folders make the proxy's socket path too long.
fn engine_with_a_long_path() -> (tempfile::TempDir, Engine) {
    let dir = tempfile::tempdir().unwrap();
    let layout = Layout::at(dir.path().join("e".repeat(120)));
    let state = SqliteStateStore::new(layout.state_db(), layout.state_lock());
    let audit = JsonlAuditLog::new(layout.audit_log());
    let engine = Engine::new(layout, Box::new(state), Box::new(audit), Vec::new());
    (dir, engine)
}

#[test]
fn a_path_too_long_for_a_socket_leaves_a_seatbelt_proxy_its_port() {
    let (_dir, engine) = engine_with_a_long_path();
    let socket = engine
        .proxy_socket(&"home".parse().unwrap(), BackendKind::Seatbelt)
        .unwrap();
    assert!(socket.is_none());
}

#[test]
fn a_path_too_long_for_a_socket_stops_a_proxy_that_needs_it() {
    let (_dir, engine) = engine_with_a_long_path();
    let err = engine
        .proxy_socket(&"home".parse().unwrap(), BackendKind::Bubblewrap)
        .unwrap_err();
    assert!(matches!(err, Error::ProxySocket { .. }), "{err}");
}

/// A file where the sandbox's proxy's socket goes.
fn block_the_socket(engine: &Engine, name: &SandboxName) {
    let path = engine.layout.proxy_socket(name.as_str());
    engine
        .layout
        .create_proxy_socket_dir(name.as_str())
        .unwrap();
    std::fs::write(&path, "not a socket").unwrap();
}

#[test]
fn a_socket_that_cannot_be_opened_is_said_and_leaves_a_seatbelt_proxy_its_port() {
    let (_dir, engine, name) = with_sandbox();
    block_the_socket(&engine, &name);
    let socket = engine.proxy_socket(&name, BackendKind::Seatbelt).unwrap();
    assert!(socket.is_none());
}

#[test]
fn a_socket_that_cannot_be_opened_is_named() {
    let (_dir, engine, name) = with_sandbox();
    block_the_socket(&engine, &name);
    let err = engine
        .proxy_socket(&name, BackendKind::Bubblewrap)
        .unwrap_err();
    assert!(matches!(err, Error::ProxySocket { .. }), "{err}");
    assert!(err.to_string().contains("proxy.sock"), "{err}");
}

/// A sandbox on `backend`.
fn on_backend(backend: BackendKind) -> (TempDir, Engine, SandboxName) {
    let (dir, engine) = engine_with(vec![Box::new(FakeBackend::available(backend))]);
    done(engine.init(&alice(), Confirm::Yes).unwrap());
    let name: SandboxName = "home".parse().unwrap();
    let spec = crate::engine::SandboxSpec {
        name: name.clone(),
        backend,
        template: "assistant".parse().unwrap(),
    };
    done(engine.create_sandbox(&alice(), spec, Confirm::Yes).unwrap());
    (dir, engine, name)
}

/// Runs a proxy that records itself, on a thread, in another engine on the
/// same folders.
fn run_proxy_of(
    engine: &Engine,
    name: &SandboxName,
) -> std::thread::JoinHandle<crate::error::Result<()>> {
    let layout = engine.layout.clone();
    let name = name.clone();
    std::thread::spawn(move || {
        let state = SqliteStateStore::new(layout.state_db(), layout.state_lock());
        let audit = JsonlAuditLog::new(layout.audit_log());
        let engine = Engine::new(layout, Box::new(state), Box::new(audit), Vec::new());
        engine.run_proxy(&name, 0, Some(&alice()))
    })
}

#[test]
fn a_proxy_goes_by_its_sandboxs_backend_when_its_socket_cannot_be_opened() {
    let (_dir, engine, name) = on_backend(BackendKind::Bubblewrap);
    block_the_socket(&engine, &name);
    let err = run_proxy_of(&engine, &name).join().unwrap().unwrap_err();
    assert!(matches!(err, Error::ProxySocket { .. }), "{err}");
    assert!(!engine.proxy_runs(&name).unwrap());

    let (_dir, engine, name) = on_backend(BackendKind::Seatbelt);
    block_the_socket(&engine, &name);
    let running = run_proxy_of(&engine, &name);
    let started = std::time::Instant::now();
    while !engine.proxy_runs(&name).unwrap() {
        assert!(!running.is_finished(), "the proxy stopped");
        assert!(started.elapsed().as_secs() < 30, "the proxy never recorded");
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

#[test]
fn removing_a_sandbox_removes_its_run_folder_even_keeping_its_data() {
    for keep_data in [false, true] {
        let (_dir, engine, name) = with_sandbox();
        engine.proxy_socket(&name, BackendKind::Seatbelt).unwrap();
        let run = engine.layout.sandbox_run_dir(name.as_str());
        assert!(run.is_dir());
        engine
            .remove_sandbox(&alice(), &name, keep_data, Confirm::Yes)
            .unwrap();
        assert!(!run.exists(), "keep_data: {keep_data}");
    }
}
