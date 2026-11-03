//! The sandbox's proxy on its Unix socket (design §5, Linux networking).

use std::io::{ErrorKind, Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, TcpStream};
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};

use super::policy::with_sandbox;
use super::*;
use crate::model::net::{Reason, Verdict};

/// These tests start real proxies on their sandboxes' reserved ports: one
/// at a time, with every other test run of this user too.
static HOST_PORTS: crate::host_ports::HostPorts = crate::host_ports::HostPorts;

/// The variables that have [`runs_a_proxy_when_asked`] run a proxy: the
/// engine's folder, the sandbox, its port, and, when set, that it records
/// itself.
const PROXY_FOLDER: &str = "ENCLOS_TEST_PROXY_FOLDER";
const PROXY_SANDBOX: &str = "ENCLOS_TEST_PROXY_SANDBOX";
const PROXY_PORT: &str = "ENCLOS_TEST_PROXY_PORT";
const PROXY_RECORDS: &str = "ENCLOS_TEST_PROXY_RECORDS";

/// What [`ProxyChild`] runs: the sandbox's proxy when asked to, until
/// killed; passes at once otherwise.
#[test]
fn runs_a_proxy_when_asked() {
    let Some(folder) = std::env::var_os(PROXY_FOLDER) else {
        return;
    };
    let name: SandboxName = std::env::var(PROXY_SANDBOX).unwrap().parse().unwrap();
    let port = std::env::var(PROXY_PORT).unwrap().parse().unwrap();
    let records = std::env::var_os(PROXY_RECORDS).is_some();
    let layout = Layout::at(std::path::PathBuf::from(folder));
    let state = SqliteStateStore::new(layout.state_db(), layout.state_lock());
    let audit = JsonlAuditLog::new(layout.audit_log());
    let engine = Engine::new(layout, Box::new(state), Box::new(audit), Vec::new());
    let err = engine
        .run_proxy(&name, port, records.then_some(&alice()))
        .unwrap_err();
    panic!("the proxy stopped: {err}");
}

/// The sandbox's proxy on its reserved port, in a child running this test
/// program's [`runs_a_proxy_when_asked`], as `enclos proxy run` runs it. A
/// proxy has no way to stop but its process ending: on a thread of this
/// program, it would keep its port, which the next sandbox of another test
/// is given, for every test after. Killed when dropped; [`ProxyChild::end`]
/// also checks the port is free again. Take the [`HOST_PORTS`] turn first
/// and keep it until then.
struct ProxyChild {
    child: Child,
    port: u16,
}

impl ProxyChild {
    fn start(engine: &Engine, name: &SandboxName, records: bool) -> ProxyChild {
        let port = engine.state.get(name).unwrap().unwrap().proxy_port;
        // `Layout::at` keeps everything in one folder, the state's.
        let folder = engine.layout.state_db().parent().unwrap().to_owned();
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "engine::tests::proxy_socket::runs_a_proxy_when_asked",
                "--test-threads=1",
            ])
            .env(PROXY_FOLDER, folder)
            .env(PROXY_SANDBOX, name.as_str())
            .env(PROXY_PORT, port.to_string())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if records {
            command.env(PROXY_RECORDS, "1");
        }
        ProxyChild {
            child: command.spawn().unwrap(),
            port,
        }
    }

    fn exited(&mut self) -> bool {
        self.child.try_wait().unwrap().is_some()
    }

    /// Kills the proxy and checks that nothing answers on its port any
    /// more, on either loopback.
    fn end(mut self) {
        self.child.kill().unwrap();
        self.child.wait().unwrap();
        let refused = TcpStream::connect((Ipv4Addr::LOCALHOST, self.port)).unwrap_err();
        assert_eq!(refused.kind(), ErrorKind::ConnectionRefused, "{refused}");
        // `[::1]` may not be configured: any error says nothing answers.
        assert!(TcpStream::connect((Ipv6Addr::LOCALHOST, self.port)).is_err());
    }
}

impl Drop for ProxyChild {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn a_running_proxy_decides_and_logs_on_its_socket() {
    let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
    let (_dir, engine, name) = with_sandbox();
    let mut proxy = ProxyChild::start(&engine, &name, false);
    let path = engine.layout.proxy_socket(name.as_str());
    let started = std::time::Instant::now();
    let mut conn = loop {
        match UnixStream::connect(&path) {
            Ok(conn) => break conn,
            Err(e) if started.elapsed().as_secs() > 30 || proxy.exited() => panic!("{e}"),
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
    proxy.end();
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
    assert!(err.to_string().contains("ENCLOS_HOME"), "{err}");
    assert!(err.to_string().contains("shorter sandbox name"), "{err}");
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
    assert!(err.to_string().contains("move it aside"), "{err}");
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

/// Runs a proxy that records itself on the sandbox's reserved port, on a
/// thread, in another engine on the same folders. Only for a proxy that
/// stops on its own: one that serves never ends, see [`ProxyChild`].
fn run_proxy_of(
    engine: &Engine,
    name: &SandboxName,
) -> std::thread::JoinHandle<crate::error::Result<()>> {
    let layout = engine.layout.clone();
    let name = name.clone();
    let port = engine.state.get(&name).unwrap().unwrap().proxy_port;
    std::thread::spawn(move || {
        let state = SqliteStateStore::new(layout.state_db(), layout.state_lock());
        let audit = JsonlAuditLog::new(layout.audit_log());
        let engine = Engine::new(layout, Box::new(state), Box::new(audit), Vec::new());
        engine.run_proxy(&name, port, Some(&alice()))
    })
}

/// A file where the sandbox's run folder goes.
fn block_the_run_folder(engine: &Engine, name: &SandboxName) {
    let run = engine.layout.sandbox_run_dir(name.as_str());
    std::fs::create_dir_all(run.parent().unwrap()).unwrap();
    std::fs::write(&run, "not a folder").unwrap();
}

#[test]
fn a_folder_that_cannot_be_made_leaves_a_seatbelt_proxy_its_port() {
    let (_dir, engine, name) = with_sandbox();
    block_the_run_folder(&engine, &name);
    let socket = engine.proxy_socket(&name, BackendKind::Seatbelt).unwrap();
    assert!(socket.is_none());
}

#[test]
fn a_folder_that_cannot_be_made_stops_a_proxy_that_needs_it() {
    let (_dir, engine, name) = with_sandbox();
    block_the_run_folder(&engine, &name);
    let err = engine
        .proxy_socket(&name, BackendKind::Bubblewrap)
        .unwrap_err();
    assert!(matches!(err, Error::ProxySocket { .. }), "{err}");
    assert!(err.to_string().contains("visible"), "{err}");
    assert!(err.to_string().contains("move it aside"), "{err}");
}

#[test]
fn a_proxy_goes_by_its_sandboxs_backend_when_its_socket_cannot_be_opened() {
    let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
    let (_dir, engine, name) = on_backend(BackendKind::Bubblewrap);
    block_the_socket(&engine, &name);
    let port = engine.state.get(&name).unwrap().unwrap().proxy_port;
    let err = run_proxy_of(&engine, &name).join().unwrap().unwrap_err();
    assert!(matches!(err, Error::ProxySocket { .. }), "{err}");
    assert!(!engine.proxy_runs(&name).unwrap());
    // It let its port go as it stopped.
    let refused = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap_err();
    assert_eq!(refused.kind(), ErrorKind::ConnectionRefused, "{refused}");

    let (_dir, engine, name) = on_backend(BackendKind::Seatbelt);
    block_the_socket(&engine, &name);
    let mut running = ProxyChild::start(&engine, &name, true);
    let started = std::time::Instant::now();
    while !engine.proxy_runs(&name).unwrap() {
        assert!(!running.exited(), "the proxy stopped");
        assert!(started.elapsed().as_secs() < 30, "the proxy never recorded");
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    running.end();
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
