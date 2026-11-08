//! A bubblewrap sandbox's session, started as every recorded session is,
//! with stand-ins for bubblewrap, `systemd-run`, enclos and the proxy: what
//! the backend hands `start_session`, never a real sandbox. CI's
//! `bubblewrap` job runs the real one (`tests/bubblewrap.rs`).

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use super::*;
use crate::backend::bubblewrap::Bubblewrap;
use crate::engine::start::{CommandKind, Group, Starting};
use crate::model::agent::AgentName;
use crate::service::fake::FakeServices;

/// These tests start stand-in proxies on their sandboxes' reserved ports:
/// one at a time, with every other test run of this user too.
static HOST_PORTS: crate::host_ports::HostPorts = crate::host_ports::HostPorts;

fn script(path: &Path, body: &str) {
    crate::test_scripts::write_script(path, body);
}

/// A bubblewrap sandbox whose programs are stand-ins in `dir`: `bwrap`
/// passes the probe, and for a session writes its arguments and variables
/// there, then runs what follows `--`; `enclos holder join` runs what
/// follows its `--`, and a namespace holder in this process answers on the
/// sandbox's socket.
struct Stood {
    dir: TempDir,
    engine: Engine,
    name: SandboxName,
    /// What the stand-in proxy listens through, already running.
    proxy_listener: std::process::Child,
}

impl Drop for Stood {
    fn drop(&mut self) {
        let _ = self.proxy_listener.kill();
        let _ = self.proxy_listener.wait();
    }
}

impl Stood {
    fn new() -> Stood {
        Stood::with_proxy_socket(true)
    }

    /// With a stand-in proxy that serves its socket alone, as a bubblewrap
    /// sandbox's proxy does, or, without `opens`, with something listening
    /// on the sandbox's port and no socket.
    fn with_proxy_socket(opens: bool) -> Stood {
        let stood = Stood::with(opens, None);
        let socket = stood.engine.layout.holder_socket("lab");
        crate::backend::bubblewrap::holder::stand_in(&socket, (32768, 60999));
        stood
    }

    /// With no namespace holder answering, and `services` as the service
    /// manager when given, else none.
    fn with(opens: bool, services: Option<std::rc::Rc<FakeServices>>) -> Stood {
        let dir = tempfile::tempdir().unwrap();
        let at = |name: &str| dir.path().join(name);
        script(
            &at("bwrap"),
            &format!(
                r#"[ "$*" = --version ] && echo 'bubblewrap 0.12.0' && exit 0
[ "$*" = '--ro-bind / / true' ] && exit 0
printf '%s\n' "$@" > '{args}'
{{ printf '%s\n' "$@"; echo ===; }} >> '{calls}'
env > '{env}'
while [ $# -gt 0 ]; do a=$1; shift; [ "$a" = -- ] && exec "$@"; done
exit 99"#,
                args = at("args").display(),
                calls = at("calls").display(),
                env = at("env").display()
            ),
        );
        script(&at("systemd-run"), "echo 'systemd 257 (257.1-1)'");
        // `holder join`, which here becomes what follows its `--`, as the
        // `holder enter` it runs does.
        script(
            &at("enclos"),
            &format!(
                r#"printf '%s\n' "$@" > '{join}'
[ "$1 $2" = 'holder join' ] || exit 99
while [ $# -gt 0 ]; do a=$1; shift; [ "$a" = -- ] && exec "$@"; done
exit 99"#,
                join = at("join").display()
            ),
        );
        let backend = Bubblewrap::at(&at("bwrap"), &at("systemd-run"), Some(at("enclos")));
        let layout = Layout::at(at("enclos-home"));
        let state = SqliteStateStore::new(layout.state_db(), layout.state_lock());
        let audit = JsonlAuditLog::new(layout.audit_log());
        let socket = layout.proxy_socket("lab");
        // The proxy only tells its listener to listen: an interpreter starting
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
        .with_exe(at("proxy"))
        .with_downloader(Box::new(LocalFiles));
        let engine = match services {
            Some(services) => engine.with_services(Box::new(services)),
            None => engine,
        };
        done(engine.init(&alice(), Confirm::Yes).unwrap());
        let name: SandboxName = "lab".parse().unwrap();
        let spec = crate::engine::SandboxSpec {
            name: name.clone(),
            backend: BackendKind::Bubblewrap,
            template: "minimal".parse().unwrap(),
        };
        done(engine.create_sandbox(&alice(), spec, Confirm::Yes).unwrap());
        let port = engine.state.get(&name).unwrap().unwrap().proxy_port;
        let proxy_listener = hold_port(port, &socket, &at("go"), &at("holder.log"), opens);
        Stood {
            dir,
            engine,
            name,
            proxy_listener,
        }
    }

    /// What the stand-in proxy and its listener did, for a test that fails.
    fn said(&mut self) -> String {
        let log = |path: &Path| match std::fs::read_to_string(path) {
            Ok(text) if text.is_empty() => "(empty)".to_owned(),
            Ok(text) => text,
            Err(e) => format!("({e})"),
        };
        let go = self.dir.path().join("go");
        format!(
            "proxy.log:\n{}\nits listener (pid {}, {:?}):\n{}\ngo: {}",
            log(&self.engine.proxy_log(&self.name)),
            self.proxy_listener.id(),
            self.proxy_listener.try_wait(),
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

/// What the stand-in proxy listens through: once the proxy writes to the
/// pipe at `go`, it listens on `socket` alone if `opens`, as `proxy run`
/// does for a bubblewrap sandbox, else on `port` alone, which it holds from
/// the start. What it does, and any error, it writes to `log`. It holds no session's
/// marker, so another test ending its session never ends it. Returns once
/// it holds the port, waiting at most 30 seconds.
fn hold_port(port: u16, socket: &Path, go: &Path, log: &Path, opens: bool) -> std::process::Child {
    use std::io::BufRead;
    let mut command = std::process::Command::new("/usr/bin/python3");
    command
        .args([
            "-c",
            "import os, socket, sys, threading


def drain(listener):
    # A real proxy accepts: a listener that never does stops answering once
    # its queue holds 129 connections, which the engine's polling reaches.
    while True:
        try:
            listener.accept()[0].close()
        except OSError:
            return


port, path, go, opens = int(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4] == 'opens'
if not opens:
    t = socket.socket(); t.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); t.bind(('127.0.0.1', port))
os.mkfifo(go)
print('holding', flush=True)
heard = open(go).read()
print('heard', repr(heard), file=sys.stderr, flush=True)
if opens:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    u = socket.socket(socket.AF_UNIX); u.bind(path); u.listen()
    threading.Thread(target=drain, args=(u,), daemon=True).start()
    print('listening on', path, file=sys.stderr, flush=True)
else:
    t.listen()
    threading.Thread(target=drain, args=(t,), daemon=True).start()
    print('listening on', port, file=sys.stderr, flush=True)
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
            panic!("the stand-in proxy's listener did not start: {other:?}");
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
        reads: &[],
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
    // The session joined the namespace holder first, which became
    // bubblewrap.
    let join = stood.read("join");
    let join: Vec<&str> = join.lines().collect();
    let socket = stood.engine.layout.holder_socket("lab");
    assert_eq!(
        &join[..5],
        ["holder", "join", "--socket", socket.to_str().unwrap(), "--"]
    );
    assert!(join[5].ends_with("/bwrap"), "{join:?}");
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

/// The first session of a sandbox that was never started installs its
/// namespace holder alone, as a service, and joins it once it answers
/// (ADR 0039). Here the service manager is a stand-in, so the namespace
/// holder that answers is one this test starts as the unit is started:
/// before, the engine finds none.
#[test]
fn a_first_session_installs_the_namespace_holder_and_waits_for_it() {
    let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
    let services = std::rc::Rc::new(FakeServices::default());
    let stood = Stood::with(true, Some(services.clone()));
    let socket = stood.engine.layout.holder_socket("lab");
    let holder = stood.engine.label(&stood.name, Unit::Holder).unwrap();
    *services.on_start.borrow_mut() = Some(Box::new(move |label| {
        if *label == holder {
            crate::backend::bubblewrap::holder::stand_in(&socket, (32768, 60999));
        }
    }));
    let starting = Starting::Command {
        kind: CommandKind::Exec,
        group: Group::Own,
        reads: &[],
    };
    let lock = stood.engine.state.lock().unwrap();
    let (started, said) = crate::notes::heard(|| {
        stood
            .engine
            .start_session(&lock, &stood.name, &["/bin/true".into()], starting, || {
                Ok(())
            })
    });
    drop(lock);
    let mut started = started.unwrap();
    assert!(started.child.wait().unwrap().success());
    stood.end_proxy();
    let label = stood.engine.label(&stood.name, Unit::Holder).unwrap();
    let installed = services.started.borrow();
    let units: Vec<_> = installed.iter().filter(|u| u.label == label).collect();
    let [unit] = units.as_slice() else {
        panic!("{installed:?}");
    };
    assert_eq!(unit.args, ["holder", "run", "lab"]);
    assert_eq!(
        unit.log,
        stood
            .engine
            .layout
            .sandbox_dir("lab")
            .join("logs/holder.log")
    );
    // It reads no secret, so it gets no way to a secret store.
    assert_eq!(unit.env, stood.engine.layout.env());
    // Nothing else of the sandbox's: it was never started.
    assert_eq!(installed.len(), 1, "{installed:?}");
    assert!(
        said.iter()
            .any(|s| s.contains("starting the namespace holder of sandbox lab")),
        "{said:?}"
    );
}

/// `sandbox start` replaces the sandbox's services but a namespace holder
/// that answers: its namespace holds the sessions still open, and a new one
/// would split them (ADR 0039). One that does not answer is replaced.
#[test]
fn sandbox_start_keeps_a_namespace_holder_that_answers() {
    let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
    let services = std::rc::Rc::new(FakeServices::default());
    let stood = Stood::with(true, Some(services.clone()));
    let label = stood.engine.label(&stood.name, Unit::Holder).unwrap();
    let holders = || {
        let started = services.started.borrow();
        started.iter().filter(|u| u.label == label).count()
    };
    services.seed(label.as_str());
    // None answers: it is removed and installed again with the others.
    stood.engine.start_sandbox(&alice(), &stood.name).unwrap();
    assert!(services.stopped.borrow().contains(&label));
    assert_eq!(holders(), 1);
    let proxy = stood.engine.label(&stood.name, Unit::Proxy).unwrap();
    assert!(services.started.borrow().iter().any(|u| u.label == proxy));

    services.stopped.borrow_mut().clear();
    let socket = stood.engine.layout.holder_socket("lab");
    crate::backend::bubblewrap::holder::stand_in(&socket, (32768, 60999));
    stood.engine.start_sandbox(&alice(), &stood.name).unwrap();
    assert!(!services.stopped.borrow().contains(&label));
    assert!(services.stopped.borrow().contains(&proxy));
    assert_eq!(holders(), 1);
}

/// `listen = false`, which every template leaves, is not held on
/// bubblewrap (design §15): each start says so, once.
#[test]
fn a_session_whose_policy_does_not_listen_says_at_start_that_it_is_not_held() {
    let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
    let stood = Stood::new();
    let starting = Starting::Command {
        kind: CommandKind::Exec,
        group: Group::Own,
        reads: &[],
    };
    let lock = stood.engine.state.lock().unwrap();
    let (started, said) = crate::notes::heard(|| {
        stood
            .engine
            .start_session(&lock, &stood.name, &["/bin/true".into()], starting, || {
                Ok(())
            })
    });
    drop(lock);
    let mut started = started.unwrap();
    assert!(started.child.wait().unwrap().success());
    stood.end_proxy();
    assert_eq!(
        said,
        [
            "sandbox lab: `listen = false` is not held on bubblewrap: nothing refuses bind or listen in the sandbox's network namespace, which its sessions share (enclos doctor)"
        ]
    );
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
        reads: &[],
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

/// A bubblewrap session reaches its proxy through the socket alone, so
/// something answering on the sandbox's port says nothing of the proxy: a
/// proxy that never opens its socket fails the start, which names it.
#[test]
fn a_session_waits_for_its_proxys_socket_and_fails_without_it() {
    let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
    let mut stood = Stood::with_proxy_socket(false);
    let starting = Starting::Command {
        kind: CommandKind::Exec,
        group: Group::Own,
        reads: &[],
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

/// The bubblewrap sandbox does not see enclos's data folder, where an
/// install stages its installer, beside the home: `wrap` binds back what the
/// install reads, each file alone and read-only, so the installer that runs
/// is the file whose SHA-256 was recorded. An ordinary session is shown none
/// of it. A Linux sandbox's `mktemp` follows `TMPDIR`, so no shim for it is
/// staged or put on its PATH.
#[test]
fn an_install_session_is_shown_its_staged_files_read_only_and_no_other_session_is() {
    let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
    let stood = Stood::new();
    let runtime = super::runtime::TestRuntime::new(
        stood.dir.path(),
        "#!/bin/sh\necho \"installed $*\" > \"$HOME/installed\"\n",
    );
    let installed =
        stood
            .engine
            .install_runtime_with(&alice(), &stood.name, &runtime, Confirm::Yes);
    let args = stood.read("args");
    let Planned::Done(end) = installed.unwrap() else {
        panic!("a dry run");
    };
    assert!(end.installed, "{end:?}\n{args}");
    let installers = stood.engine.layout.sandbox_installers("lab");
    let installer = installers.join(format!("hermes-install-{}.sh", runtime.sha256));
    let staged = [installer];
    assert!(!installers.join("home-0").exists());
    let home = stood.engine.sandbox_home(&stood.name);
    assert!(!home.join("bin/mktemp").exists());
    assert_eq!(
        std::fs::read_to_string(home.join("installed")).unwrap(),
        "installed --non-interactive\n"
    );
    assert_eq!(bound_in(&args, &installers), staged, "{args}");

    // The proxy the install started still runs, and serves this session.
    let starting = Starting::Command {
        kind: CommandKind::Exec,
        group: Group::Own,
        reads: &[],
    };
    let lock = stood.engine.state.lock().unwrap();
    let started =
        stood
            .engine
            .start_session(&lock, &stood.name, &["/bin/true".into()], starting, || {
                Ok(())
            });
    drop(lock);
    let waited = started.map(|mut s| s.child.wait());
    stood.end_proxy();
    assert!(waited.unwrap().unwrap().success());
    let args = stood.read("args");
    assert!(!args.contains(installers.to_str().unwrap()), "{args}");
}

/// What bubblewrap's arguments mount from `folder`, each a file mounted
/// read-only at its own path: a mount of anything else of it, or of the
/// folder itself, is named instead, so the comparison fails.
fn bound_in(args: &str, folder: &Path) -> Vec<PathBuf> {
    let args: Vec<&str> = args.lines().collect();
    let mut bound = Vec::new();
    for (at, arg) in args.iter().enumerate() {
        let Some(path) = args.get(at + 1).map(Path::new) else {
            continue;
        };
        if !arg.starts_with("--") || !path.starts_with(folder) {
            continue;
        }
        match (*arg, args.get(at + 2)) {
            ("--ro-bind", Some(to)) if Path::new(to) == path && path != folder => {
                bound.push(path.to_owned())
            }
            _ => bound.push(PathBuf::from(format!("{arg} {}", path.display()))),
        }
    }
    bound
}

/// The plan names the host the installer is downloaded on.
#[test]
fn a_dry_run_of_an_install_names_this_linux_machine() {
    let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
    let stood = Stood::new();
    let runtime = super::runtime::TestRuntime::new(stood.dir.path(), "#!/bin/sh\n");
    let Planned::DryRun(plan) = stood
        .engine
        .install_runtime_with(&alice(), &stood.name, &runtime, Confirm::DryRun)
        .unwrap()
    else {
        panic!("installed");
    };
    let plan = plan.changes.join("\n");
    assert!(
        plan.contains(" on this Linux machine, as it is served now (ADR 0029)"),
        "{plan}"
    );
    assert!(!plan.contains("this Mac"), "{plan}");
}

/// An import's copy of its archive is in the same hidden folder: its
/// session is shown that one file, read-only, and not the folder.
#[test]
fn an_import_session_is_shown_its_copy_of_the_archive_read_only() {
    let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
    let stood = Stood::new();
    let runtime = super::runtime::TestRuntime::new(stood.dir.path(), super::runtime::INSTALLS);
    let installed =
        stood
            .engine
            .install_runtime_with(&alice(), &stood.name, &runtime, Confirm::Yes);
    let Planned::Done(end) = installed.unwrap() else {
        panic!("a dry run");
    };
    assert!(end.installed, "{end:?}");
    let archive = stood.dir.path().join("main.tar.gz");
    std::fs::write(&archive, b"an export").unwrap();
    let main: AgentName = "main".parse().unwrap();
    let imported = stood
        .engine
        .import_agent(&alice(), &stood.name, main, &archive, Confirm::Yes);
    let calls = stood.read("calls");
    stood.end_proxy();
    imported.unwrap();
    let installers = stood.engine.layout.sandbox_installers("lab");
    let copy = installers.join(format!("agent-main.{}.tar.gz", std::process::id()));
    // Every call bubblewrap got, the install's and the import's sessions,
    // then Hermes's own commands that set the agent up.
    let calls: Vec<&str> = calls.split("===\n").filter(|c| !c.is_empty()).collect();
    let import = calls
        .iter()
        .position(|c| c.contains("\nhermes\nprofile\nimport\n"))
        .unwrap_or_else(|| panic!("no import: {calls:?}"));
    assert_eq!(
        bound_in(calls[import], &installers),
        [copy],
        "{}",
        calls[import]
    );
    for after in &calls[import + 1..] {
        assert_eq!(
            bound_in(after, &installers),
            Vec::<PathBuf>::new(),
            "{after}"
        );
    }
}

/// The namespace holder installed alone, before anything of the sandbox
/// ran, as `enclos dashboard` does: its log's folder is made first, since
/// systemd starts no unit whose log it cannot open.
#[test]
fn a_namespace_holder_installed_alone_gets_its_logs_folder() {
    let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
    let services = std::rc::Rc::new(FakeServices::default());
    let stood = Stood::with(true, Some(services.clone()));
    let logs = stood.engine.layout.sandbox_dir("lab").join("logs");
    assert!(!logs.exists());
    let socket = stood.engine.layout.holder_socket("lab");
    let late = std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(300));
        crate::backend::bubblewrap::holder::stand_in(&socket, (32768, 60999));
    });
    let record = stood.engine.record(&stood.name).unwrap();
    let ((), _) = crate::notes::heard(|| stood.engine.ensure_holder(&record).unwrap());
    late.join().unwrap();
    assert!(logs.is_dir());
    assert_eq!(services.started.borrow().len(), 1);
}
