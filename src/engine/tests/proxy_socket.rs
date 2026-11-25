//! The sandbox's proxy on its Unix socket (design §5, Linux networking).

use std::io::{ErrorKind, Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, TcpStream};
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};

use super::policy::with_sandbox;
use super::*;
use crate::engine::loopback::reached_another;
use crate::lifecycle::marker::spawn_unmarked;
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
const HOLD_PORT: &str = "ENCLOS_TEST_HOLD_PORT";
const HOLD_READY: &str = "ENCLOS_TEST_HOLD_READY";
const HOLD_STOP: &str = "ENCLOS_TEST_HOLD_STOP";

/// Holds [`HOLD_PORT`] bound without listening until [`HOLD_STOP`] appears
/// (or 60 s pass); passes at once otherwise.
#[test]
fn holds_a_port_when_asked() {
    let Some(port) = std::env::var_os(HOLD_PORT) else {
        return;
    };
    let port: u16 = port.to_string_lossy().parse().unwrap();
    let ready = std::path::PathBuf::from(std::env::var_os(HOLD_READY).unwrap());
    let stop = std::path::PathBuf::from(std::env::var_os(HOLD_STOP).unwrap());
    let _held = bind_never_listening(port);
    std::fs::write(&ready, "ready").unwrap();
    let started = std::time::Instant::now();
    while !stop.exists() && started.elapsed() < std::time::Duration::from_secs(60) {
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}

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
    let state = SqliteStateStore::new(
        layout.state_db(),
        layout.state_lock(),
        crate::state::Wait::Command,
    );
    let audit = JsonlAuditLog::new(layout.audit_log());
    let engine = Engine::new(layout, Box::new(state), Box::new(audit), Vec::new());
    let err = engine
        .run_proxy(&name, port, records.then_some(&alice()))
        .unwrap_err();
    panic!("the proxy stopped: {err}");
}

/// The sandbox's proxy, in a child running this test program's
/// [`runs_a_proxy_when_asked`], as `enclos proxy run` runs it. A proxy has
/// no way to stop but its process ending: on a thread of this program, it
/// would keep its port, which the next sandbox of another test is given,
/// for every test after. Killed when dropped; [`ProxyChild::end`]
/// also checks the port is free again. Take the [`HOST_PORTS`] turn first
/// and keep it until then. What the child writes is kept, for a test to
/// say why the proxy stopped ([`ProxyChild::said`]).
struct ProxyChild {
    child: Child,
    port: u16,
    output: std::path::PathBuf,
}

impl ProxyChild {
    fn start(engine: &Engine, name: &SandboxName, records: bool) -> ProxyChild {
        let port = engine.state.get(name).unwrap().unwrap().proxy_port;
        // `Layout::at` keeps everything in one folder, the state's.
        let folder = engine.layout.state_db().parent().unwrap().to_owned();
        ProxyChild::start_at(&folder, name, port, records)
    }

    /// [`ProxyChild::start`], for the engine whose folder is `folder`.
    fn start_at(
        folder: &std::path::Path,
        name: &SandboxName,
        port: u16,
        records: bool,
    ) -> ProxyChild {
        let output = folder.join(format!("proxy-child-{port}.out"));
        let file = std::fs::File::create(&output).unwrap();
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
            .stdout(Stdio::from(file.try_clone().unwrap()))
            .stderr(Stdio::from(file));
        if records {
            command.env(PROXY_RECORDS, "1");
        }
        ProxyChild {
            child: spawn_unmarked(&mut command).unwrap(),
            port,
            output,
        }
    }

    /// What the child wrote: libtest's report, with the proxy's error once
    /// it stopped.
    fn said(&self) -> String {
        std::fs::read_to_string(&self.output).unwrap_or_else(|e| format!("nothing to read: {e}"))
    }

    fn exited(&mut self) -> bool {
        self.child.try_wait().unwrap().is_some()
    }

    /// A connection to the proxy's socket at `path`, once it answers there.
    fn connect(&mut self, path: &std::path::Path) -> UnixStream {
        let started = std::time::Instant::now();
        loop {
            match UnixStream::connect(path) {
                Ok(conn) => return conn,
                Err(e) if started.elapsed().as_secs() > 30 || self.exited() => {
                    panic!("{e}; the proxy wrote:\n{}", self.said())
                }
                Err(_) => std::thread::sleep(std::time::Duration::from_millis(10)),
            }
        }
    }

    /// Kills the proxy and checks that nothing answers on its port any
    /// more, on either loopback.
    fn end(mut self) {
        self.child.kill().unwrap();
        self.child.wait().unwrap();
        assert_nothing_listens(self.port);
    }
}

/// Asserts that nothing listens on `port`, on either loopback: a connection
/// to 127.0.0.1 is refused or reaches itself, and one to `[::1]`, which may
/// not be configured, fails or reaches itself. Linux can give a connection the port
/// it connects to as its own, since its ephemeral range holds the proxy
/// range; with nothing listening, the connection then reaches itself. It is
/// reset as it closes, so that it leaves the port free for the next proxy
/// (see `loopback`).
fn assert_nothing_listens(port: u16) {
    match TcpStream::connect((Ipv4Addr::LOCALHOST, port)) {
        Err(refused) => assert_eq!(refused.kind(), ErrorKind::ConnectionRefused, "{refused}"),
        Ok(conn) => assert!(
            !reached_another(conn),
            "something listens on 127.0.0.1:{port}"
        ),
    }
    // `[::1]` may not be configured: any error says nothing answers.
    if let Ok(conn) = TcpStream::connect((Ipv6Addr::LOCALHOST, port)) {
        assert!(!reached_another(conn), "something listens on [::1]:{port}");
    }
}

/// The control for [`assert_nothing_listens`]: a listener on the port fails
/// it. The listener's port is outside the proxy range, so no proxy test
/// shares it.
#[test]
#[should_panic(expected = "something listens on 127.0.0.1:")]
fn a_listener_on_the_port_fails_the_check_that_nothing_listens() {
    let listener = crate::test_ports::tcp_listener(Ipv4Addr::LOCALHOST);
    assert_nothing_listens(listener.local_addr().unwrap().port());
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
    let mut conn = proxy.connect(&engine.layout.proxy_socket(name.as_str()));
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
    let state = SqliteStateStore::new(
        layout.state_db(),
        layout.state_lock(),
        crate::state::Wait::Command,
    );
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

#[test]
fn a_socket_failure_stops_the_proxy_of_every_backend_whose_sessions_need_it() {
    let (_dir, engine) = engine_with_a_long_path();
    for backend in BackendKind::ALL {
        let socket = engine.proxy_socket(&"home".parse().unwrap(), backend);
        match backend.reaches_proxy_over_socket() {
            true => assert!(
                matches!(socket, Err(Error::ProxySocket { .. })),
                "{backend}"
            ),
            false => assert!(matches!(socket, Ok(None)), "{backend}"),
        }
    }
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
        let state = SqliteStateStore::new(
            layout.state_db(),
            layout.state_lock(),
            crate::state::Wait::Command,
        );
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
    // Nothing holds its port.
    assert_nothing_listens(port);

    let (_dir, engine, name) = on_backend(BackendKind::Seatbelt);
    block_the_socket(&engine, &name);
    let mut running = ProxyChild::start(&engine, &name, true);
    let started = std::time::Instant::now();
    while !engine.proxy_runs(&name).unwrap() {
        assert!(!running.exited(), "the proxy stopped:\n{}", running.said());
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

#[test]
fn a_proxy_whose_sessions_reach_it_over_its_socket_leaves_its_port_free() {
    let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
    for backend in [BackendKind::Bubblewrap, BackendKind::Seatbelt] {
        let (_dir, engine, name) = on_backend(backend);
        let mut proxy = ProxyChild::start(&engine, &name, false);
        // The socket opens last, so every listener is up once it answers.
        proxy.connect(&engine.layout.proxy_socket(name.as_str()));
        match backend.reaches_proxy_over_socket() {
            true => assert_nothing_listens(proxy.port),
            false => {
                let tcp = TcpStream::connect((Ipv4Addr::LOCALHOST, proxy.port)).unwrap();
                assert!(reached_another(tcp), "the proxy does not listen");
            }
        }
        proxy.end();
    }
}

#[test]
fn a_second_proxy_leaves_the_running_one_its_socket_when_neither_holds_a_port() {
    let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
    let (_dir, engine, name) = on_backend(BackendKind::Bubblewrap);
    let mut running = ProxyChild::start(&engine, &name, false);
    let path = engine.layout.proxy_socket(name.as_str());
    running.connect(&path);
    let err = run_proxy_of(&engine, &name).join().unwrap().unwrap_err();
    assert!(
        matches!(&err, Error::ProxyRuns { on, .. } if on == "its socket"),
        "{err}"
    );
    UnixStream::connect(&path).unwrap();
    assert!(!running.exited(), "the proxy stopped:\n{}", running.said());
    running.end();
}

#[test]
fn a_proxy_whose_sessions_reach_it_over_its_socket_starts_whatever_holds_its_port() {
    let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
    for backend in [BackendKind::Bubblewrap, BackendKind::Seatbelt] {
        let (dir, engine, name) = on_backend(backend);
        // No program there: what goes as far as starting the proxy fails then.
        let engine = engine.with_exe(dir.path().join("no-such-program"));
        let record = engine.state.get(&name).unwrap().unwrap();
        // Another program on the port, which accepts connections.
        let _taken = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, record.proxy_port)).unwrap();
        let lock = engine.state.lock().unwrap();
        let err = engine.ensure_proxy(&lock, &record).unwrap_err();
        match backend.reaches_proxy_over_socket() {
            true => assert!(
                err.to_string().contains("could not start the proxy"),
                "{err}"
            ),
            false => assert!(matches!(err, Error::ProxyPortTaken { .. }), "{err}"),
        }
    }
}

/// A socket bound to `127.0.0.1:port` without `SO_REUSEADDR` that never
/// listens: connection probes are refused, yet another bind on `port` fails.
fn bind_never_listening(port: u16) -> std::os::fd::OwnedFd {
    use rustix::net::{AddressFamily, SocketType};

    let socket = rustix::net::socket(AddressFamily::INET, SocketType::STREAM, None).unwrap();
    rustix::net::bind(
        &socket,
        &std::net::SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
    )
    .unwrap();
    socket
}

/// Writes an executable shell script in `dir` that `ensure_proxy` can spawn
/// (`<script> proxy run <name> --port <port>`) to run this test binary's
/// [`runs_a_proxy_when_asked`].
fn write_proxy_exe(
    dir: &std::path::Path,
    engine: &Engine,
    name: &SandboxName,
) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;

    let quote = |s: &str| format!("'{}'", s.replace('\'', "'\\''"));
    let folder = engine.layout.state_db().parent().unwrap().to_owned();
    let exe = std::env::current_exe().unwrap();
    let script = dir.join("fake-enclos-proxy.sh");
    let body = format!(
        "#!/bin/sh\nexport {PROXY_FOLDER}={}\nexport {PROXY_SANDBOX}={}\nexport {PROXY_PORT}=\"$5\"\nexec {} --exact engine::tests::proxy_socket::runs_a_proxy_when_asked --test-threads=1\n",
        quote(&folder.display().to_string()),
        quote(name.as_str()),
        quote(&exe.display().to_string()),
    );
    std::fs::write(&script, body).unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
    script
}

/// Ends a proxy that `ensure_proxy` started and recorded, even if an
/// assertion panics, so no proxy leaks to other tests.
struct RecordedProxyGuard<'a> {
    engine: &'a Engine,
    name: SandboxName,
    port: u16,
    stopped: bool,
}

impl RecordedProxyGuard<'_> {
    fn kill_group(&self) {
        if let Ok(sessions) = self.engine.state.sessions(&self.name, true) {
            for session in sessions
                .into_iter()
                .filter(|s| s.kind == crate::model::session::SessionKind::Proxy)
            {
                if let Some(pgid) = session.pgid
                    && let Some(pid) = rustix::process::Pid::from_raw(pgid as i32)
                {
                    let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
                    let _ =
                        rustix::process::waitpid(Some(pid), rustix::process::WaitOptions::empty());
                }
            }
        }
    }

    fn end(mut self) {
        self.kill_group();
        self.stopped = true;
        let started = std::time::Instant::now();
        while self.engine.proxy_runs(&self.name).unwrap() {
            assert!(
                started.elapsed().as_secs() < 5,
                "proxy of {} did not stop",
                self.name
            );
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert_nothing_listens(self.port);
    }
}

impl Drop for RecordedProxyGuard<'_> {
    fn drop(&mut self) {
        if !self.stopped {
            self.kill_group();
        }
    }
}

#[test]
fn a_proxy_that_loses_its_port_at_start_takes_the_next_one() {
    use crate::model::sandbox::{PORT_FIRST, PORT_LAST};

    let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
    let (dir, engine, name) = on_backend(BackendKind::Seatbelt);
    let script = write_proxy_exe(dir.path(), &engine, &name);
    let engine = engine.with_exe(script);
    let record = engine.state.get(&name).unwrap().unwrap();
    let old_port = record.proxy_port;
    let held = bind_never_listening(old_port);

    let lock = engine.state.lock().unwrap();
    let updated = engine.ensure_proxy(&lock, &record).unwrap();
    drop(lock);
    let guard = RecordedProxyGuard {
        engine: &engine,
        name: name.clone(),
        port: updated.proxy_port,
        stopped: false,
    };

    assert_ne!(updated.proxy_port, old_port);
    assert!((PORT_FIRST..=PORT_LAST).contains(&updated.proxy_port));
    assert_eq!(
        engine.state.get(&name).unwrap().unwrap().proxy_port,
        updated.proxy_port
    );
    assert!(engine.proxy_runs(&name).unwrap());
    let conn = TcpStream::connect((Ipv4Addr::LOCALHOST, updated.proxy_port)).unwrap();
    assert!(reached_another(conn));
    assert!(!crate::engine::loopback::free(
        std::net::SocketAddr::from((Ipv4Addr::LOCALHOST, old_port)),
        std::time::Duration::from_millis(200),
    ));

    guard.end();
    drop(held);
}

#[test]
fn the_profile_of_a_start_that_took_another_port_allows_that_port_alone() {
    use crate::backend::{
        Backend, Capabilities, CompileError, Compiled, Launch, Probe, SandboxContext, WrapError,
    };
    use crate::engine::start::{CommandKind, Group, Starting};
    use crate::model::policy::Policy;
    use crate::probes::OwnProbes;

    /// Compiles real Seatbelt profiles on Linux while delegating launch and
    /// availability to [`FakeBackend`] so `start_session` can run end to end.
    struct SeatbeltCompileBackend {
        fake: FakeBackend,
        seatbelt: crate::backend::seatbelt::Seatbelt,
    }

    impl Backend for SeatbeltCompileBackend {
        fn kind(&self) -> BackendKind {
            self.fake.kind()
        }
        fn probe(&self) -> Probe {
            self.fake.probe()
        }
        fn try_run(&self) -> Probe {
            self.fake.try_run()
        }
        fn capabilities(&self) -> Capabilities {
            self.fake.capabilities()
        }
        fn compile(
            &self,
            policy: &Policy,
            ctx: &SandboxContext,
        ) -> std::result::Result<Compiled, CompileError> {
            self.seatbelt.compile(policy, ctx)
        }
        fn wrap(
            &self,
            compiled: &std::path::Path,
            ctx: &SandboxContext,
            launch: &Launch,
        ) -> std::result::Result<Command, WrapError> {
            self.fake.wrap(compiled, ctx, launch)
        }
        fn own_probes(
            &self,
            compiled: Option<&str>,
        ) -> std::result::Result<Box<dyn OwnProbes>, String> {
            self.fake.own_probes(compiled)
        }
    }

    let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
    let backend = SeatbeltCompileBackend {
        fake: FakeBackend::available(BackendKind::Seatbelt),
        seatbelt: crate::backend::seatbelt::Seatbelt::default(),
    };
    let (dir, engine) = engine_with(vec![Box::new(backend)]);
    done(engine.init(&alice(), Confirm::Yes).unwrap());
    let name: SandboxName = "home".parse().unwrap();
    let spec = crate::engine::SandboxSpec {
        name: name.clone(),
        backend: BackendKind::Seatbelt,
        template: "assistant".parse().unwrap(),
    };
    done(engine.create_sandbox(&alice(), spec, Confirm::Yes).unwrap());
    let script = write_proxy_exe(dir.path(), &engine, &name);
    let engine = engine.with_exe(script);
    let old_port = engine.state.get(&name).unwrap().unwrap().proxy_port;
    let held = bind_never_listening(old_port);

    // Ends any proxy the start recorded, even if it then fails.
    let mut guard = RecordedProxyGuard {
        engine: &engine,
        name: name.clone(),
        port: old_port,
        stopped: false,
    };
    let lock = engine.state.lock().unwrap();
    let mut started = engine
        .start_session(
            &lock,
            &name,
            &[std::ffi::OsString::from("/usr/bin/true")],
            Starting::Command {
                kind: CommandKind::Exec,
                group: Group::Own,
                reads: &[],
            },
            || Ok(()),
        )
        .unwrap();
    drop(lock);

    let new_port = engine.state.get(&name).unwrap().unwrap().proxy_port;
    guard.port = new_port;
    assert!(started.child.wait().unwrap().success());
    assert_ne!(new_port, old_port);

    let compiled_path = std::path::PathBuf::from(started.session.compiled.as_deref().unwrap());
    assert_eq!(
        compiled_path,
        engine.compile_policy(&name, new_port).unwrap()
    );
    let text = std::fs::read_to_string(&compiled_path).unwrap();
    assert!(
        text.contains(&format!(
            "(allow network-outbound (remote tcp \"localhost:{new_port}\"))"
        )),
        "{text}"
    );
    assert!(!text.contains(&format!("localhost:{old_port}")), "{text}");

    guard.end();
    drop(held);
}

#[test]
fn a_proxy_that_loses_its_port_while_a_session_runs_keeps_the_port_and_fails() {
    use super::sandbox::{Sleeping, put, session_of};

    let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
    let (dir, engine, name) = on_backend(BackendKind::Seatbelt);
    let script = write_proxy_exe(dir.path(), &engine, &name);
    let engine = engine.with_exe(script);
    let record = engine.state.get(&name).unwrap().unwrap();
    let old_port = record.proxy_port;
    // A session that started with the old port allowed and in its proxy
    // variables would go on sending to whatever holds it.
    let running = Sleeping::new();
    put(&engine, &session_of(&engine, &name, running.process()));
    let held = bind_never_listening(old_port);

    let lock = engine.state.lock().unwrap();
    let err = engine.ensure_proxy(&lock, &record).unwrap_err();
    drop(lock);

    let text = err.to_string();
    assert!(
        text.contains("still runs") && text.contains("enclos sandbox stop"),
        "{text}"
    );
    assert_eq!(
        engine.state.get(&name).unwrap().unwrap().proxy_port,
        old_port
    );
    assert!(!engine.proxy_runs(&name).unwrap());
    drop(held);
}

#[test]
fn a_proxy_that_exits_while_its_port_is_free_keeps_its_port_and_fails() {
    use std::os::unix::fs::PermissionsExt;

    let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
    let (dir, engine, name) = on_backend(BackendKind::Seatbelt);
    let runs = dir.path().join("runs");
    let script = dir.path().join("fails.sh");
    let quoted_runs = format!("'{}'", runs.display().to_string().replace('\'', "'\\''"));
    std::fs::write(
        &script,
        format!("#!/bin/sh\necho run >> {quoted_runs}\nexit 1\n"),
    )
    .unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
    let engine = engine.with_exe(script);
    let record = engine.state.get(&name).unwrap().unwrap();
    let old_port = record.proxy_port;

    let lock = engine.state.lock().unwrap();
    let err = engine.ensure_proxy(&lock, &record).unwrap_err();
    drop(lock);

    assert!(err.to_string().contains("exited"), "{err}");
    assert_eq!(
        engine.state.get(&name).unwrap().unwrap().proxy_port,
        old_port
    );
    assert_eq!(std::fs::read_to_string(&runs).unwrap().lines().count(), 1);
}

#[test]
fn a_proxy_that_loses_all_five_tries_leaves_the_record_on_the_last_port_and_reports_the_exit() {
    use std::collections::HashSet;
    use std::os::unix::fs::PermissionsExt;

    use crate::engine::proxy::PROXY_PORT_TRIES;
    use crate::model::sandbox::{PORT_FIRST, PORT_LAST};
    use crate::model::session::SessionKind;

    struct HolderGuard {
        stop: std::path::PathBuf,
        pids: std::path::PathBuf,
    }

    impl Drop for HolderGuard {
        fn drop(&mut self) {
            let _ = std::fs::write(&self.stop, "stop");
            let pids: Vec<rustix::process::Pid> = std::fs::read_to_string(&self.pids)
                .unwrap_or_default()
                .lines()
                .filter_map(|line| line.trim().parse::<i32>().ok())
                .filter_map(rustix::process::Pid::from_raw)
                .collect();
            let started = std::time::Instant::now();
            while started.elapsed() < std::time::Duration::from_secs(5)
                && pids
                    .iter()
                    .any(|&pid| rustix::process::test_kill_process(pid).is_ok())
            {
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            for pid in pids {
                let _ = rustix::process::kill_process(pid, rustix::process::Signal::KILL);
            }
        }
    }

    let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
    let (dir, engine, name) = on_backend(BackendKind::Seatbelt);
    let quote = |s: &str| format!("'{}'", s.replace('\'', "'\\''"));
    let exe = std::env::current_exe().unwrap();
    let runs = dir.path().join("runs");
    let pids = dir.path().join("pids");
    let stop = dir.path().join("stop");
    let script = dir.path().join("lose-every-bind.sh");
    let body = format!(
        concat!(
            "#!/bin/sh\n",
            "port=\"$5\"\n",
            "ready={ready_prefix}\"$port\"\n",
            "{HOLD_PORT}=\"$port\" {HOLD_READY}=\"$ready\" {HOLD_STOP}={stop} ",
            "{exe} --exact engine::tests::proxy_socket::holds_a_port_when_asked --test-threads=1 ",
            "</dev/null >/dev/null 2>&1 &\n",
            "echo \"$!\" >> {pids}\n",
            "i=0\n",
            "while [ ! -f \"$ready\" ] && [ \"$i\" -lt 200 ]; do\n",
            "    sleep 0.05\n",
            "    i=$((i + 1))\n",
            "done\n",
            "echo \"$port\" >> {runs}\n",
            "echo \"bind failed on $port\" >&2\n",
            "exit 1\n",
        ),
        ready_prefix = quote(&dir.path().join("ready-").display().to_string()),
        HOLD_PORT = HOLD_PORT,
        HOLD_READY = HOLD_READY,
        HOLD_STOP = HOLD_STOP,
        stop = quote(&stop.display().to_string()),
        exe = quote(&exe.display().to_string()),
        pids = quote(&pids.display().to_string()),
        runs = quote(&runs.display().to_string()),
    );
    std::fs::write(&script, body).unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
    let engine = engine.with_exe(script);
    let record = engine.state.get(&name).unwrap().unwrap();
    let old_port = record.proxy_port;

    let holders = HolderGuard { stop, pids };
    let lock = engine.state.lock().unwrap();
    let err = engine.ensure_proxy(&lock, &record).unwrap_err();
    drop(lock);

    assert!(err.to_string().contains("exited"), "{err}");
    let ports: Vec<u16> = std::fs::read_to_string(&runs)
        .unwrap()
        .lines()
        .map(|line| line.trim().parse().unwrap())
        .collect();
    assert_eq!(ports.len(), 5, "{ports:?}");
    assert_eq!(ports.len(), PROXY_PORT_TRIES);
    assert_eq!(ports[0], old_port);
    let unique: HashSet<u16> = ports.iter().copied().collect();
    assert_eq!(unique.len(), ports.len(), "{ports:?}");
    assert!(ports.iter().all(|p| (PORT_FIRST..=PORT_LAST).contains(p)));
    let saved_port = engine.state.get(&name).unwrap().unwrap().proxy_port;
    assert_eq!(saved_port, *ports.last().unwrap());
    assert_ne!(saved_port, old_port);
    assert!(!engine.proxy_runs(&name).unwrap());
    assert!(
        engine
            .state
            .sessions(&name, true)
            .unwrap()
            .iter()
            .all(|s| s.kind != SessionKind::Proxy)
    );
    drop(holders);
}

#[test]
fn a_start_that_cannot_take_another_port_shows_why() {
    use crate::model::sandbox::{PORT_FIRST, PORT_LAST};

    let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
    let (dir, engine, name) = on_backend(BackendKind::Seatbelt);
    let script = write_proxy_exe(dir.path(), &engine, &name);
    let engine = engine.with_exe(script);
    let record = engine.state.get(&name).unwrap().unwrap();
    let old_port = record.proxy_port;

    let lock = engine.state.lock().unwrap();
    for port in PORT_FIRST..=PORT_LAST {
        if port == old_port {
            continue;
        }
        let mut other = record.clone();
        other.name = format!("p{port}").parse().unwrap();
        other.proxy_port = port;
        engine.state.put(&lock, &other).unwrap();
    }
    let held = bind_never_listening(old_port);

    let err = engine.ensure_proxy(&lock, &record).unwrap_err();
    drop(lock);

    let text = err.to_string();
    assert!(text.contains("exited"), "{text}");
    assert!(text.contains("no other port could be taken"), "{text}");
    assert_eq!(
        engine.state.get(&name).unwrap().unwrap().proxy_port,
        old_port
    );
    assert!(!engine.proxy_runs(&name).unwrap());
    drop(held);
}

#[test]
fn a_policy_test_that_loses_its_port_compiles_the_profile_again_with_the_new_one() {
    use std::sync::{Arc, Mutex};

    use crate::backend::{
        Backend, Capabilities, CompileError, Compiled, Launch, Probe, SandboxContext, WrapError,
    };
    use crate::model::policy::Policy;
    use crate::probes::OwnProbes;

    struct RecordingSeatbeltBackend {
        fake: FakeBackend,
        seatbelt: crate::backend::seatbelt::Seatbelt,
        seen: Arc<Mutex<Vec<String>>>,
    }

    impl Backend for RecordingSeatbeltBackend {
        fn kind(&self) -> BackendKind {
            self.fake.kind()
        }
        fn probe(&self) -> Probe {
            self.fake.probe()
        }
        fn try_run(&self) -> Probe {
            self.fake.try_run()
        }
        fn capabilities(&self) -> Capabilities {
            self.fake.capabilities()
        }
        fn compile(
            &self,
            policy: &Policy,
            ctx: &SandboxContext,
        ) -> std::result::Result<Compiled, CompileError> {
            self.seatbelt.compile(policy, ctx)
        }
        fn wrap(
            &self,
            compiled: &std::path::Path,
            ctx: &SandboxContext,
            launch: &Launch,
        ) -> std::result::Result<Command, WrapError> {
            self.fake.wrap(compiled, ctx, launch)
        }
        fn own_probes(
            &self,
            compiled: Option<&str>,
        ) -> std::result::Result<Box<dyn OwnProbes>, String> {
            let mut seen = self.seen.lock().unwrap();
            seen.push(compiled.unwrap().to_owned());
            if seen.len() == 2 {
                return Err("stop here".into());
            }
            self.fake.own_probes(compiled)
        }
    }

    let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
    let seen = Arc::new(Mutex::new(Vec::new()));
    let backend = RecordingSeatbeltBackend {
        fake: FakeBackend::available(BackendKind::Seatbelt),
        seatbelt: crate::backend::seatbelt::Seatbelt::default(),
        seen: Arc::clone(&seen),
    };
    let (dir, engine) = engine_with(vec![Box::new(backend)]);
    done(engine.init(&alice(), Confirm::Yes).unwrap());
    let name: SandboxName = "home".parse().unwrap();
    let spec = crate::engine::SandboxSpec {
        name: name.clone(),
        backend: BackendKind::Seatbelt,
        template: "assistant".parse().unwrap(),
    };
    done(engine.create_sandbox(&alice(), spec, Confirm::Yes).unwrap());
    let script = write_proxy_exe(dir.path(), &engine, &name);
    let engine = engine.with_exe(script);
    let old_port = engine.state.get(&name).unwrap().unwrap().proxy_port;
    let held = bind_never_listening(old_port);

    let mut guard = RecordedProxyGuard {
        engine: &engine,
        name: name.clone(),
        port: old_port,
        stopped: false,
    };
    let err = engine
        .policy_test(&alice(), &name, false, Confirm::Yes)
        .unwrap_err();
    let new_port = engine.state.get(&name).unwrap().unwrap().proxy_port;
    guard.port = new_port;

    assert!(err.to_string().contains("stop here"), "{err}");
    assert_ne!(new_port, old_port);
    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 2);
    assert!(
        seen[0].contains(&format!("localhost:{old_port}")),
        "{}",
        seen[0]
    );
    assert!(
        seen[1].contains(&format!("localhost:{new_port}")),
        "{}",
        seen[1]
    );
    assert!(
        !seen[1].contains(&format!("localhost:{old_port}")),
        "{}",
        seen[1]
    );

    guard.end();
    drop(held);
}

#[test]
fn a_started_proxy_is_waited_for_where_its_sessions_reach_it() {
    let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
    for backend in [BackendKind::Bubblewrap, BackendKind::Seatbelt] {
        let (dir, engine, name) = on_backend(backend);
        let record = engine.state.get(&name).unwrap().unwrap();
        let mut proxy = ProxyChild::start(&engine, &name, false);
        let reached = engine.proxy_reached_at(&record);
        let lock = engine.state.lock().unwrap();
        engine
            .record_started_proxy(
                &lock,
                &record,
                &mut proxy.child,
                &reached,
                &dir.path().join("proxy.log"),
            )
            .unwrap();
        drop(lock);
        assert!(engine.proxy_runs(&name).unwrap(), "{backend}");
        proxy.end();
    }
}

/// `sandbox start` holds the state lock while it installs the sandbox's
/// services, the proxy first, and the service manager runs the proxy at
/// once, which records itself under that lock. On a Raspberry Pi under load
/// (2026-11-11), installing the services after it took longer than the 10
/// seconds a command waits for the lock: the proxy gave up, and `sandbox
/// start` said it had not started. It waits as long as a write no person
/// waits on (design §11), then records itself.
#[test]
fn a_proxy_service_records_itself_after_a_long_sandbox_start() {
    use crate::engine::service::{PROXY_WAIT, Unit};
    use crate::model::runtime::RuntimeKind;
    use crate::service::ServiceLabel;

    let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
    let (_dir, engine, fake, name) =
        super::services::sandbox_with_services(Some(RuntimeKind::Hermes));
    let port = engine.state.get(&name).unwrap().unwrap().proxy_port;
    let folder = engine.layout.state_db().parent().unwrap().to_owned();
    let proxy = engine.label(&name, Unit::Proxy).unwrap();
    let running = std::rc::Rc::new(std::cell::RefCell::new(None));
    let started = std::rc::Rc::clone(&running);
    let sandbox = name.clone();
    *fake.on_start.borrow_mut() = Some(Box::new(move |label: &ServiceLabel| {
        if *label == proxy {
            *started.borrow_mut() = Some(ProxyChild::start_at(&folder, &sandbox, port, true));
        } else {
            // The gateway's install takes longer than a command waits for
            // the lock, as systemd's did on the Pi.
            std::thread::sleep(std::time::Duration::from_secs(11));
        }
    }));
    engine.start_sandbox(&alice(), &name).unwrap();
    let mut proxy = running.borrow_mut().take().unwrap();
    // As `sandbox start` waits for it once the services are installed.
    let recorded = engine.proxy_started(&name, PROXY_WAIT).unwrap();
    assert!(!proxy.exited(), "the proxy exited:\n{}", proxy.said());
    assert!(recorded, "the proxy did not record itself");
    proxy.end();
}
