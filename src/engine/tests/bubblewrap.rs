//! A bubblewrap sandbox's session, started as every recorded session is,
//! with stand-ins for bubblewrap, `systemd-run`, enclos and the proxy: what
//! the backend hands `start_session`, never a real sandbox. CI's
//! `bubblewrap` job runs the real one (`tests/bubblewrap.rs`).

use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use super::*;
use crate::backend::bubblewrap::Bubblewrap;
use crate::engine::start::{CommandKind, Group, Starting};

/// These tests start stand-in proxies on their sandboxes' reserved ports:
/// one at a time, with every other test run of this user too.
static HOST_PORTS: crate::host_ports::HostPorts = crate::host_ports::HostPorts;

fn script(path: &Path, body: &str) {
    crate::test_scripts::write_script(path, body);
}

/// A bubblewrap sandbox whose programs are stand-ins in `dir`: `bwrap`
/// passes the probe, and for a session writes its arguments and variables
/// there, then runs what follows `--`.
struct Stood {
    dir: TempDir,
    engine: Engine,
    name: SandboxName,
    /// What the stand-in proxy listens through, already running.
    holder: std::process::Child,
}

impl Drop for Stood {
    fn drop(&mut self) {
        let _ = self.holder.kill();
        let _ = self.holder.wait();
    }
}

impl Stood {
    fn new() -> Stood {
        Stood::with_proxy_socket(true)
    }

    /// With a proxy that opens its socket, or holds its port alone.
    fn with_proxy_socket(opens: bool) -> Stood {
        let dir = tempfile::tempdir().unwrap();
        let at = |name: &str| dir.path().join(name);
        script(
            &at("bwrap"),
            &format!(
                "[ \"$*\" = '--ro-bind / / true' ] && exit 0\nprintf '%s\\n' \"$@\" > '{args}'\nenv > '{env}'\nwhile [ $# -gt 0 ]; do a=$1; shift; [ \"$a\" = -- ] && exec \"$@\"; done\nexit 99",
                args = at("args").display(),
                env = at("env").display()
            ),
        );
        script(&at("systemd-run"), "echo 'systemd 257 (257.1-1)'");
        script(&at("enclos"), "exit 99");
        let backend = Bubblewrap::at(&at("bwrap"), &at("systemd-run"), Some(at("enclos")));
        let layout = Layout::at(at("enclos-home"));
        let state = SqliteStateStore::new(layout.state_db(), layout.state_lock());
        let audit = JsonlAuditLog::new(layout.audit_log());
        let socket = layout.proxy_socket("lab");
        // The proxy only tells `holder` to listen: an interpreter starting
        // under load could take longer than the engine waits. What it did
        // is in its log, for a test that fails.
        script(
            &at("proxy"),
            &format!(
                "echo \"proxy started: $*\" >&2\nprintf go > '{go}' && echo 'proxy wrote go' >&2\nexec sleep 60",
                go = at("go").display()
            ),
        );
        let engine = Engine::new(
            layout,
            Box::new(state),
            Box::new(audit),
            vec![Box::new(backend)],
        )
        .with_exe(at("proxy"));
        done(engine.init(&alice(), Confirm::Yes).unwrap());
        let name: SandboxName = "lab".parse().unwrap();
        let spec = crate::engine::SandboxSpec {
            name: name.clone(),
            backend: BackendKind::Bubblewrap,
            template: "minimal".parse().unwrap(),
        };
        done(engine.create_sandbox(&alice(), spec, Confirm::Yes).unwrap());
        let port = engine.state.get(&name).unwrap().unwrap().proxy_port;
        let holder = hold_port(port, &socket, &at("go"), &at("holder.log"), opens);
        Stood {
            dir,
            engine,
            name,
            holder,
        }
    }

    /// What the stand-in proxy and `holder` did, for a test that fails.
    fn said(&mut self) -> String {
        let log = |path: &Path| match std::fs::read_to_string(path) {
            Ok(text) if text.is_empty() => "(empty)".to_owned(),
            Ok(text) => text,
            Err(e) => format!("({e})"),
        };
        let go = self.dir.path().join("go");
        format!(
            "proxy.log:\n{}\nholder (pid {}, {:?}):\n{}\ngo: {}",
            log(&self.engine.proxy_log(&self.name)),
            self.holder.id(),
            self.holder.try_wait(),
            log(&self.dir.path().join("holder.log")),
            match std::fs::symlink_metadata(&go) {
                Ok(m) => format!("{:?}", m.file_type()),
                Err(e) => e.to_string(),
            },
        )
    }

    fn read(&self, name: &str) -> String {
        std::fs::read_to_string(self.dir.path().join(name)).unwrap()
    }

    /// Ends the stand-in proxy this sandbox's session started.
    fn end_proxy(&self) {
        let lock = self.engine.state.lock().unwrap();
        for session in self.engine.state.sessions(&self.name, true).unwrap() {
            if session.kind == crate::model::session::SessionKind::Proxy {
                let _ = rustix::process::kill_process(
                    rustix::process::Pid::from_raw(session.root.pid as i32).unwrap(),
                    rustix::process::Signal::KILL,
                );
                self.engine.state.end_session(&lock, session.id).unwrap();
            }
        }
    }
}

/// A process that holds `port` without listening on it, so that the engine
/// finds it free, and, once the stand-in proxy writes to the pipe at `go`,
/// listens on it and then, if `opens`, on `socket`, as `proxy run` does.
/// What it does, and any error, it writes to `log`. It holds no session's
/// marker, so another test ending its session never ends it. Returns once
/// it holds the port, waiting at most 30 seconds.
fn hold_port(port: u16, socket: &Path, go: &Path, log: &Path, opens: bool) -> std::process::Child {
    use std::io::BufRead;
    let mut command = std::process::Command::new("/usr/bin/python3");
    command
        .args([
            "-c",
            "import os, socket, sys
port, path, go, opens = int(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4] == 'opens'
t = socket.socket(); t.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); t.bind(('127.0.0.1', port))
os.mkfifo(go)
print('holding', flush=True)
heard = open(go).read()
print('heard', repr(heard), file=sys.stderr, flush=True)
t.listen()
print('listening on', port, file=sys.stderr, flush=True)
if opens:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    u = socket.socket(socket.AF_UNIX); u.bind(path); u.listen()
    print('listening on', path, file=sys.stderr, flush=True)
sys.stdin.read()",
        ])
        .arg(port.to_string())
        .arg(socket)
        .arg(go)
        .arg(if opens { "opens" } else { "port" })
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::fs::File::create(log).unwrap());
    let mut holder = crate::lifecycle::marker::spawn_unmarked(&mut command).unwrap();
    let stdout = holder.stdout.take().unwrap();
    let (said, heard) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut line = String::new();
        let _ = std::io::BufReader::new(stdout).read_line(&mut line);
        let _ = said.send(line);
    });
    match heard.recv_timeout(std::time::Duration::from_secs(30)) {
        Ok(line) if line == "holding\n" => holder,
        other => {
            let _ = holder.kill();
            panic!("the stand-in proxy did not hold port {port}: {other:?}");
        }
    }
}

/// `start_session` runs bubblewrap on the compiled file, with the marker
/// the session's processes hold, and records the session as any other.
#[test]
fn a_bubblewrap_session_starts_through_start_session_holding_its_marker() {
    let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
    let stood = Stood::new();
    let fds = stood.dir.path().join("fds");
    let command = vec![
        "/bin/sh".into(),
        "-c".into(),
        "ls -l /proc/$$/fd > \"$0\"".into(),
        fds.clone().into(),
    ];
    let starting = Starting::Command {
        kind: CommandKind::Exec,
        group: Group::Own,
    };
    let lock = stood.engine.state.lock().unwrap();
    let started = stood
        .engine
        .start_session(&lock, &stood.name, &command, starting, || Ok(()));
    drop(lock);
    let mut started = started.unwrap();
    assert!(started.child.wait().unwrap().success());
    stood.end_proxy();

    let args = stood.read("args");
    let args: Vec<&str> = args.lines().collect();
    let compiled = started.session.compiled.clone().unwrap();
    assert!(compiled.ends_with(".json"), "{compiled}");
    let at = args.iter().rposition(|a| *a == "inside").unwrap() - 1;
    assert!(args[at].ends_with("/enclos"), "{args:?}");
    assert_eq!(
        &args[at + 1..],
        [
            "inside",
            "--compiled",
            compiled.as_str(),
            // A command's session: its Ctrl-C is the command's (`wrap`).
            "--restore-interrupts",
            "--",
            "/bin/sh",
            "-c",
            "ls -l /proc/$$/fd > \"$0\"",
            fds.to_str().unwrap()
        ]
    );
    assert_eq!(&args[..3], ["--ro-bind", "/", "/"]);
    // The marker, open in the program bubblewrap ran.
    let members = stood.engine.layout.sandbox_dir("lab").join("members");
    let held = std::fs::read_to_string(&fds).unwrap();
    assert!(held.contains(members.to_str().unwrap()), "{held}");
    // The sandbox's own variables, never this process's.
    let env = stood.read("env");
    let home = stood.engine.layout.sandbox_home("lab");
    assert!(env.contains(&format!("HOME={}", home.display())), "{env}");
    assert!(!env.contains("CARGO_PKG_NAME"), "{env}");
    assert_eq!(started.session.sandbox, stood.name);
}

/// A folder of the user's home that holds a deny entry and cannot be
/// listed stops the start before anything runs, and says which.
#[test]
fn a_session_the_host_refuses_at_launch_starts_nothing() {
    // Root lists it all the same.
    if rustix::process::geteuid().is_root() {
        return;
    }
    let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
    let stood = Stood::new();
    // `~/.config/gh` is on the default deny list; `~` is this test's folder.
    let config = stood.dir.path().join(".config");
    std::fs::create_dir_all(config.join("gh")).unwrap();
    std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o000)).unwrap();
    let starting = Starting::Command {
        kind: CommandKind::Exec,
        group: Group::Own,
    };
    let lock = stood.engine.state.lock().unwrap();
    let started =
        stood
            .engine
            .start_session(&lock, &stood.name, &["/bin/true".into()], starting, || {
                Ok(())
            });
    drop(lock);
    stood.end_proxy();
    std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o755)).unwrap();
    let Err(e) = started else {
        panic!("started");
    };
    let why = e.to_string();
    assert!(why.contains("cannot look at"), "{why}");
    assert!(why.contains(".config"), "{why}");
    assert!(!stood.dir.path().join("args").exists());
    let open: Vec<_> = stood
        .engine
        .state
        .sessions(&stood.name, true)
        .unwrap()
        .into_iter()
        .filter(|s| s.kind != crate::model::session::SessionKind::Proxy)
        .collect();
    assert!(open.is_empty(), "{open:?}");
}

/// The #119 review: the proxy's port answering says nothing of its socket,
/// which `run_proxy` opens after it, and a bubblewrap session has no other
/// way out. A proxy that never opens it fails the start, which says so.
#[test]
fn a_session_waits_for_its_proxys_socket_and_fails_without_it() {
    let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
    let mut stood = Stood::with_proxy_socket(false);
    let starting = Starting::Command {
        kind: CommandKind::Exec,
        group: Group::Own,
    };
    let lock = stood.engine.state.lock().unwrap();
    let started =
        stood
            .engine
            .start_session(&lock, &stood.name, &["/bin/true".into()], starting, || {
                Ok(())
            });
    drop(lock);
    let Err(e) = started else {
        panic!("started without the proxy's socket");
    };
    let why = e.to_string();
    let socket = stood.engine.layout.proxy_socket("lab");
    assert!(
        why.contains(&format!("did not start listening on {}", socket.display())),
        "{why}\n{}",
        stood.said()
    );
    assert!(!stood.dir.path().join("args").exists());
    // Ended, not left running where no `stop` finds it.
    assert!(
        stood
            .engine
            .state
            .sessions(&stood.name, true)
            .unwrap()
            .is_empty()
    );
}
