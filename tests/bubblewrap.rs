//! A bubblewrap sandbox for real: only in CI's `bubblewrap` job, on
//! GitHub's Ubuntu runners, since it runs bubblewrap, makes namespaces,
//! starts scopes in the runner's user manager and plants files in its home.
//! Each test makes a sandbox in a throwaway `ENCLOS_HOME` under the
//! runner's home, as a person trying it would, and runs `connect` there:
//! what the session cannot do, each with a control on the host, and what
//! it can.
#![cfg(target_os = "linux")]

use std::io::Read;
use std::net::{Ipv4Addr, TcpListener};
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use tempfile::TempDir;

#[path = "bubblewrap/limits.rs"]
mod limits;

#[path = "bubblewrap/own_places.rs"]
mod own_places;

#[path = "bubblewrap/mount_race.rs"]
mod mount_race;

#[path = "support/inherited.rs"]
mod inherited;
use inherited::{HOLDS_NINE, holding_open};

/// One sandbox at a time: each `ENCLOS_HOME` would give its first sandbox
/// the same proxy port.
static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

/// Whether to run these tests: they refuse anywhere but a GitHub-hosted
/// runner, in CI's `bubblewrap` job, which sets `ENCLOS_BUBBLEWRAP_TESTS`.
fn on_a_runner() -> bool {
    if std::env::var("ENCLOS_BUBBLEWRAP_TESTS").as_deref() != Ok("1") {
        eprintln!("bubblewrap tests not run: CI's bubblewrap job runs them");
        return false;
    }
    let var = |name: &str| std::env::var(name).unwrap_or_default();
    assert!(
        var("GITHUB_ACTIONS") == "true" && var("RUNNER_ENVIRONMENT") == "github-hosted",
        "these tests run bubblewrap sandboxes and plant files in the home: they run only on a GitHub-hosted runner"
    );
    true
}

fn home() -> PathBuf {
    PathBuf::from(std::env::var_os("HOME").expect("HOME"))
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).trim().to_owned()
}

/// A sandbox `lab` on the bubblewrap backend, `assistant` template, in an
/// `ENCLOS_HOME` of its own under the runner's home; stopped when dropped.
struct Lab {
    root: TempDir,
    _turn: std::sync::MutexGuard<'static, ()>,
}

impl Lab {
    fn new() -> Lab {
        let turn = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
        let lab = Lab {
            root: tempfile::Builder::new()
                .prefix("enclos-ci-")
                .tempdir_in(home())
                .unwrap(),
            _turn: turn,
        };
        lab.ok(&["init"]);
        lab.ok(&[
            "sandbox",
            "create",
            "lab",
            "--backend",
            "bubblewrap",
            "--template",
            "assistant",
        ]);
        lab
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_enclos"));
        cmd.arg("--text")
            .args(args)
            .env("ENCLOS_HOME", self.root.path())
            .stdin(Stdio::null());
        cmd
    }

    fn ok(&self, args: &[&str]) -> Output {
        let out = self.command(args).output().unwrap();
        assert!(out.status.success(), "{args:?}: {out:?}");
        out
    }

    /// `connect lab -- sh -c script`, as a script runs it.
    fn connect(&self, script: &str) -> Output {
        self.command(&["connect", "lab", "--", "/bin/sh", "-c", script])
            .output()
            .unwrap()
    }

    fn sandbox_home(&self) -> PathBuf {
        self.home_of("lab")
    }

    fn home_of(&self, sandbox: &str) -> PathBuf {
        self.root
            .path()
            .join("sandboxes")
            .join(sandbox)
            .join("home")
    }

    fn layout(&self) -> enclos::layout::Layout {
        enclos::layout::Layout::at(self.root.path())
    }

    /// The record of `sandbox`, read as enclos keeps it.
    fn record(&self, sandbox: &str) -> enclos::model::sandbox::SandboxRecord {
        use enclos::state::StateStore;
        let layout = self.layout();
        let state =
            enclos::state::sqlite::SqliteStateStore::new(layout.state_db(), layout.state_lock());
        state.get(&sandbox.parse().unwrap()).unwrap().unwrap()
    }

    fn proxy_port(&self, sandbox: &str) -> u16 {
        self.record(sandbox).proxy_port
    }

    /// Records Hermes as `lab`'s runtime, as `runtime install` would, and
    /// puts a stand-in for it in the sandbox's home: its gateway listens on
    /// 127.0.0.1:0, as Hermes's does, and writes its port and a token of
    /// its own to `~/gateway.port`; it answers each connection with that
    /// token, and exits 1, for the service manager to start it again, when
    /// a connection says `exit`.
    fn with_stand_in_hermes(&self) {
        use enclos::state::StateStore;
        let layout = self.layout();
        let state =
            enclos::state::sqlite::SqliteStateStore::new(layout.state_db(), layout.state_lock());
        let lock = state.lock().unwrap();
        let mut record = self.record("lab");
        record.runtime = Some(enclos::model::runtime::RuntimeKind::Hermes);
        state.put(&lock, &record).unwrap();
        drop(lock);
        let home = self.sandbox_home();
        std::fs::create_dir_all(home.join(".hermes/hermes-agent")).unwrap();
        let bin = home.join(".local/bin");
        std::fs::create_dir_all(&bin).unwrap();
        let hermes = bin.join("hermes");
        std::fs::write(
            &hermes,
            format!("#!/bin/sh\nexec /usr/bin/python3 -c '{STAND_IN_GATEWAY}'\n"),
        )
        .unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&hermes, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    /// What the stand-in gateway wrote, once it has: its port and token.
    fn gateway(&self, other_than: Option<&str>, within: Duration) -> (u16, String) {
        let file = self.sandbox_home().join("gateway.port");
        let deadline = Instant::now() + within;
        loop {
            if let Ok(text) = std::fs::read_to_string(&file)
                && let Some((port, token)) = text.trim().split_once(' ')
                && Some(token) != other_than
            {
                return (port.parse().unwrap(), token.to_owned());
            }
            assert!(Instant::now() < deadline, "the gateway never listened");
            std::thread::sleep(Duration::from_millis(200));
        }
    }
}

/// The stand-in gateway, in Python, between single quotes.
const STAND_IN_GATEWAY: &str = r#"
import os, socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
s.listen()
token = os.urandom(4).hex()
port = os.path.join(os.environ["HOME"], "gateway.port")
with open(port + ".tmp", "w") as f:
    f.write("%d %s" % (s.getsockname()[1], token))
os.rename(port + ".tmp", port)
while True:
    c, _ = s.accept()
    said = c.recv(16)
    c.sendall(("gateway " + token).encode())
    c.close()
    if said.startswith(b"exit"):
        raise SystemExit(1)
"#;

/// A client, in Python: connects to 127.0.0.1 at each port given, says
/// `hi`, and prints what it was answered, or why it could not connect.
const CLIENT: &str = r#"
import socket, sys
for port in sys.argv[1:]:
    try:
        c = socket.create_connection(("127.0.0.1", int(port)), timeout=5)
        c.sendall(b"hi")
        print(port, "reached", c.recv(64).decode())
    except OSError as e:
        print(port, "refused", e)
"#;

/// A listener, in Python: on 127.0.0.1:0, writes its port to the file
/// named first, in the home, and answers the next connections it is told
/// to wait for with the word given second, then exits.
const LISTENER: &str = r#"
import os, socket, sys
s = socket.socket()
s.bind(("127.0.0.1", 0))
s.listen()
path = os.path.join(os.environ["HOME"], sys.argv[1])
with open(path + ".tmp", "w") as f:
    f.write(str(s.getsockname()[1]))
os.rename(path + ".tmp", path)
for _ in range(int(sys.argv[3])):
    c, _ = s.accept()
    c.sendall(sys.argv[2].encode())
    c.close()
"#;

/// The file `name` once it is there, waiting at most 30 seconds.
fn once_there(path: &std::path::Path) -> String {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Ok(text) = std::fs::read_to_string(path) {
            return text;
        }
        assert!(Instant::now() < deadline, "{} never came", path.display());
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// The namespace descriptors among `pid`'s open descriptors, read from the
/// host.
fn namespace_descriptors(pid: u32) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(format!("/proc/{pid}/fd")) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|e| std::fs::read_link(e.path()).ok())
        .map(|target| target.display().to_string())
        .filter(|target| is_namespace(target))
        .collect()
}

/// Whether a descriptor's target, as `/proc` writes it, is a namespace.
fn is_namespace(target: &str) -> bool {
    [
        "user:[", "net:[", "mnt:[", "pid:[", "ipc:[", "uts:[", "cgroup:[", "time:[",
    ]
    .iter()
    .any(|kind| target.starts_with(kind))
}

/// The parent of `pid`, from its `status`.
fn parent_of(pid: u32) -> Option<u32> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    status
        .lines()
        .find_map(|l| l.strip_prefix("PPid:"))?
        .trim()
        .parse()
        .ok()
}

impl Drop for Lab {
    /// Each sandbox a test made, whose services, its namespace holder's
    /// included, would otherwise run on in the runner's user manager.
    fn drop(&mut self) {
        for sandbox in ["lab", "other"] {
            let _ = self.command(&["sandbox", "stop", sandbox]).output();
        }
    }
}

#[test]
fn on_a_runner_a_bubblewrap_sandbox_is_created_and_runs_a_session() {
    if !on_a_runner() {
        return;
    }
    let lab = Lab::new();
    let out = lab.connect("echo ran; echo $ENCLOS_SANDBOX; pwd");
    assert!(out.status.success(), "{out:?}");
    let said = text(&out.stdout);
    let home = lab.sandbox_home();
    assert_eq!(said, format!("ran\nlab\n{}", home.display()), "{out:?}");
    // Recorded, and ended with its program.
    let list = text(&lab.ok(&["sandbox", "show", "lab"]).stdout);
    assert!(list.contains("bubblewrap"), "{list}");
}

#[test]
fn on_a_runner_ssh_is_hidden_and_a_write_in_the_home_works() {
    if !on_a_runner() {
        return;
    }
    let lab = Lab::new();
    let ssh = home().join(".ssh");
    std::fs::create_dir_all(&ssh).unwrap();
    let planted = ssh.join("enclos-ci-planted");
    std::fs::write(&planted, "secret\n").unwrap();
    // The control: the host reads it.
    assert_eq!(std::fs::read_to_string(&planted).unwrap(), "secret\n");
    let out = lab.connect(&format!(
        "cat '{}' && echo READ; echo written > \"$HOME/enclos-ci-written\" && echo WROTE",
        planted.display()
    ));
    let _ = std::fs::remove_file(&planted);
    let said = text(&out.stdout);
    assert!(!said.contains("READ"), "{out:?}");
    assert!(!said.contains("secret"), "{out:?}");
    assert!(said.contains("WROTE"), "{out:?}");
    let written = lab.sandbox_home().join("enclos-ci-written");
    assert_eq!(std::fs::read_to_string(written).unwrap(), "written\n");
}

#[test]
fn on_a_runner_a_write_outside_the_home_fails() {
    if !on_a_runner() {
        return;
    }
    let lab = Lab::new();
    let outside = home().join("enclos-ci-outside");
    let _ = std::fs::remove_file(&outside);
    // The control: the host writes there.
    std::fs::write(&outside, "").unwrap();
    std::fs::remove_file(&outside).unwrap();
    let out = lab.connect(&format!("echo x > '{}' && echo WROTE", outside.display()));
    assert!(!text(&out.stdout).contains("WROTE"), "{out:?}");
    assert!(!outside.exists(), "{out:?}");
}

/// A listener on the host's loopback, which the session's own network
/// namespace does not reach.
#[test]
fn on_a_runner_the_hosts_loopback_is_out_of_reach() {
    if !on_a_runner() {
        return;
    }
    let lab = Lab::new();
    // Clear of the proxies' range, 41000 to 41999, which a bind of port 0
    // can land in.
    let (_listener, port) = (0..64)
        .map(|_| {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            let port = listener.local_addr().unwrap().port();
            (listener, port)
        })
        .find(|(_, port)| !(41000..=41999).contains(port))
        .unwrap();
    // The control: the host reaches it.
    let control = std::net::TcpStream::connect((Ipv4Addr::LOCALHOST, port));
    assert!(control.is_ok(), "{control:?}");
    let out = lab.connect(&format!(
        "python3 -c \"import socket; socket.create_connection(('127.0.0.1', {port}), timeout=5); print('REACHED')\""
    ));
    assert!(!text(&out.stdout).contains("REACHED"), "{out:?}");
    assert!(
        text(&out.stderr).contains("Connection refused")
            || text(&out.stderr).contains("unreachable"),
        "{out:?}"
    );
}

/// The proxy is the way out: a page the `assistant` template allows
/// answers, through the relay and the proxy's socket. Needs the network.
#[test]
fn on_a_runner_a_request_through_the_proxy_works() {
    if !on_a_runner() {
        return;
    }
    let lab = Lab::new();
    let out = lab.connect("curl -sS -o /dev/null -w '%{http_code}\\n' https://example.com/");
    assert!(out.status.success(), "{out:?}");
    assert_eq!(text(&out.stdout), "200", "{out:?}");
    let log = text(&lab.ok(&["net", "log", "lab"]).stdout);
    assert!(log.contains("example.com"), "{log}");
}

/// The host pid of a process whose command line is `words`, among this
/// user's.
fn host_pid_of(words: &[&str]) -> Option<u32> {
    std::fs::read_dir("/proc")
        .ok()?
        .flatten()
        .find_map(|entry| {
            let pid: u32 = entry.file_name().to_str()?.parse().ok()?;
            let cmdline = std::fs::read(entry.path().join("cmdline")).ok()?;
            let args: Vec<&[u8]> = cmdline
                .split(|b| *b == 0)
                .filter(|a| !a.is_empty())
                .collect();
            let matches = args.len() == words.len()
                && args
                    .iter()
                    .zip(words)
                    .all(|(a, w)| a.ends_with(w.as_bytes()));
            matches.then_some(pid)
        })
}

/// Each session has its own PID namespace: another session's process is
/// not there to read, though the host reads its start-up environment.
#[test]
fn on_a_runner_another_sessions_environment_is_not_read() {
    if !on_a_runner() {
        return;
    }
    let lab = Lab::new();
    let mut first = lab
        .command(&["connect", "lab", "--", "/bin/sleep", "4321"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    let pid = loop {
        if let Some(pid) = host_pid_of(&["sleep", "4321"]) {
            break pid;
        }
        assert!(Instant::now() < deadline, "the first session never ran");
        std::thread::sleep(Duration::from_millis(200));
    };
    // The control: the host reads it, and finds the sandbox's variables.
    let environ = std::fs::read(format!("/proc/{pid}/environ")).unwrap();
    assert!(text(&environ).contains("ENCLOS_SANDBOX=lab"));
    let out = lab.connect(&format!(
        "cat /proc/{pid}/environ | tr '\\0' '\\n' | grep ENCLOS_SANDBOX && echo READ"
    ));
    // Ours alone: the test started it.
    let _ = Command::new("kill").arg(pid.to_string()).status();
    let _ = first.kill();
    let _ = first.wait();
    assert!(!text(&out.stdout).contains("READ"), "{out:?}");
}

/// What a script on a terminal gets: Python's `pty.fork`, so the session's
/// command has the terminal as its controlling one, and `enclos connect`
/// leads its group as a shell's job does. Writes `send` once `wait_for`
/// shows, then reads to the end: what was said, and the exit code.
const ON_A_TERMINAL: &str = r#"
import os, pty, sys, time
wait_for, send, argv = sys.argv[1].encode(), sys.argv[2].encode(), sys.argv[3:]
pid, master = pty.fork()
if pid == 0:
    os.execv(argv[0], argv)
said, sent, deadline = b"", False, time.time() + 60
while time.time() < deadline:
    try:
        chunk = os.read(master, 1024)
    except OSError:
        break
    if not chunk:
        break
    said += chunk
    if not sent and wait_for in said:
        time.sleep(0.5)
        os.write(master, send)
        sent = True
_, status = os.waitpid(pid, 0)
sys.stdout.write(said.decode(errors="replace"))
print(f"\nEXIT {os.waitstatus_to_exitcode(status)}")
"#;

fn on_a_terminal(lab: &Lab, wait_for: &str, send: &str, args: &[&str]) -> String {
    let mut cmd = Command::new("/usr/bin/python3");
    cmd.arg("-c")
        .arg(ON_A_TERMINAL)
        .arg(wait_for)
        .arg(send)
        .arg(env!("CARGO_BIN_EXE_enclos"))
        .arg("--text")
        .args(args)
        .env("ENCLOS_HOME", lab.root.path())
        .stdin(Stdio::null())
        .stdout(Stdio::piped());
    let mut child = cmd.spawn().unwrap();
    let mut said = String::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut said)
        .unwrap();
    child.wait().unwrap();
    said
}

/// design §8: `connect` waits for its program through Ctrl-C. bubblewrap's
/// outer process is in the terminal's group too: were it ended by Ctrl-C,
/// it would end the session, a program that catches SIGINT included.
#[test]
fn on_a_runner_ctrl_c_reaches_the_program_and_not_bubblewrap() {
    if !on_a_runner() {
        return;
    }
    let lab = Lab::new();
    let said = on_a_terminal(
        &lab,
        "ready",
        "\x03",
        &[
            "connect",
            "lab",
            "--",
            "/bin/sh",
            "-c",
            "trap 'echo caught' INT; echo ready; sleep 5; echo after",
        ],
    );
    assert!(said.contains("caught"), "{said}");
    assert!(said.contains("after"), "{said}");
    assert!(said.trim_end().ends_with("EXIT 0"), "{said}");
}

/// A program that leaves SIGINT alone ends on Ctrl-C: it is not the
/// namespace's first process, whom the kernel spares such a signal.
#[test]
fn on_a_runner_ctrl_c_ends_a_program_that_does_not_catch_it() {
    if !on_a_runner() {
        return;
    }
    let lab = Lab::new();
    let started = Instant::now();
    let said = on_a_terminal(
        &lab,
        "ready",
        "\x03",
        &[
            "connect",
            "lab",
            "--",
            "/bin/sh",
            "-c",
            "echo ready; exec /bin/sleep 30",
        ],
    );
    assert!(started.elapsed() < Duration::from_secs(25), "{said}");
    assert!(said.trim_end().ends_with("EXIT 130"), "{said}");
}

/// What the runner's host gives the sessions, for reading the results: the
/// backend runs, and the Host section names what it found, as the job's
/// "The host under test" step prints it, and the job's own lingering.
#[test]
fn on_a_runner_doctor_reports_the_backend() {
    if !on_a_runner() {
        return;
    }
    let lab = Lab::new();
    let out = lab.command(&["doctor"]).output().unwrap();
    let said = text(&out.stdout);
    println!("{said}");
    assert!(out.status.success(), "{out:?}");
    assert!(said.contains("bubblewrap: runs here"), "{out:?}");
    for line in [
        "\nHost\n  systemd ",
        "\n  bubblewrap: /usr/bin/bwrap is bubblewrap 0.",
        "\n  user namespaces: allowed",
        "\n  bubblewrap starts a program: it does",
        "\n  Landlock: ABI ",
        "\n  memory controller: delegated to your systemd manager",
        "\n  cpu controller: delegated to your systemd manager",
        "\n  lingering: on",
        "\n  Secret Service: ",
    ] {
        assert!(said.contains(line), "{line:?} in {said}");
    }
    assert!(!said.contains("(degraded)"), "{said}");
}

/// The session of an install or an import reads what enclos staged in the
/// sandbox's `installers/` folder, which the sandbox does not otherwise see
/// (design §5, "Staged files"). Staged here as the engine stages it, a file
/// the host writes in that folder, and launched through the backend's
/// `wrap` with the file named, as the engine launches an install: the
/// session reads it, cannot write, replace or remove it, and does not see
/// the file beside it. The control: an ordinary session is shown neither.
#[test]
fn on_a_runner_a_staged_file_is_read_only_and_alone_in_its_session() {
    use enclos::backend::bubblewrap::{BWRAP, Bubblewrap, CompiledSandbox};
    use enclos::backend::{Backend, Launch, SandboxContext};
    if !on_a_runner() {
        return;
    }
    let lab = Lab::new();
    // Starts the sandbox's proxy, which the session's relay reaches, and
    // writes the compiled file.
    let out = lab.connect("true");
    assert!(out.status.success(), "{out:?}");
    let sandbox = lab.root.path().join("sandboxes/lab");
    let installers = sandbox.join("installers");
    std::fs::create_dir_all(&installers).unwrap();
    let staged = installers.join("home-0");
    let beside = installers.join("agent-other.1.tar.gz");
    std::fs::write(&staged, "staged by the host\n").unwrap();
    std::fs::write(&beside, "another import\n").unwrap();
    let compiled: Vec<PathBuf> = std::fs::read_dir(sandbox.join("compiled"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        .collect();
    let [compiled] = compiled.as_slice() else {
        panic!("one compiled file: {compiled:?}");
    };
    let parsed: Result<CompiledSandbox, _> =
        serde_json::from_str(&std::fs::read_to_string(compiled).unwrap());
    assert!(parsed.is_ok(), "{parsed:?}");
    let layout = enclos::layout::Layout::at(lab.root.path());
    let ctx = SandboxContext::new(&layout, &"lab".parse().unwrap(), lab.proxy_port("lab"));
    let backend = Bubblewrap::at(
        std::path::Path::new(BWRAP),
        std::path::Path::new(enclos::lifecycle::cgroup::SYSTEMD_RUN),
        Some(PathBuf::from(env!("CARGO_BIN_EXE_enclos"))),
    );
    let script = "cat \"$1\" && echo READ
echo changed >> \"$1\" 2>/dev/null && echo WROTE
echo new > \"$1.new\" 2>/dev/null && echo MADE
mv \"$1\" \"$1.moved\" 2>/dev/null && echo MOVED
rm -f \"$1\" 2>/dev/null; [ -e \"$1\" ] || echo REMOVED
cat \"$2\" 2>/dev/null && echo BESIDE
ls \"$(dirname \"$1\")\" 2>/dev/null";
    let session = |reads: Vec<PathBuf>| {
        let launch = Launch {
            program: "/bin/sh".into(),
            args: vec![
                "-c".into(),
                script.into(),
                "sh".into(),
                staged.clone().into(),
                beside.clone().into(),
            ],
            env: Vec::new(),
            in_terminal: false,
            service_port: None,
            limits: Default::default(),
            reads,
        };
        let out = backend
            .wrap(compiled, &ctx, &launch)
            .unwrap()
            .stdin(Stdio::null())
            .output()
            .unwrap();
        (text(&out.stdout), out)
    };

    let (said, out) = session(vec![staged.clone()]);
    for line in ["staged by the host", "READ"] {
        assert!(said.contains(line), "{line}: {out:?}");
    }
    // `agent-other`: the folder's listing names the staged file alone.
    for line in [
        "WROTE",
        "MADE",
        "MOVED",
        "REMOVED",
        "BESIDE",
        "another import",
        "agent-other",
    ] {
        assert!(!said.contains(line), "{line}: {out:?}");
    }
    assert_eq!(
        std::fs::read_to_string(&staged).unwrap(),
        "staged by the host\n"
    );
    assert!(!installers.join("home-0.new").exists());

    // The control: the host's own files, which an ordinary session does
    // not see at all.
    let (said, out) = session(Vec::new());
    for line in ["staged by the host", "READ", "BESIDE", "another import"] {
        assert!(!said.contains(line), "{line}: {out:?}");
    }
    std::fs::write(&staged, "the host writes it\n").unwrap();
}

/// A sandbox's sessions share one network namespace (ADR 0039): what one
/// session listens on at 127.0.0.1 another `connect` session of the same
/// sandbox reaches, and a session of another sandbox does not, though it
/// reaches a listener of its own the same way: the control.
#[test]
fn on_a_runner_a_listener_is_reached_from_its_sandbox_and_not_from_another() {
    if !on_a_runner() {
        return;
    }
    let lab = Lab::new();
    lab.ok(&[
        "sandbox",
        "create",
        "other",
        "--backend",
        "bubblewrap",
        "--template",
        "assistant",
    ]);
    let python = |args: &[&str]| -> Vec<String> {
        ["/usr/bin/python3", "-c"]
            .iter()
            .chain(args)
            .map(|a| (*a).to_owned())
            .collect()
    };
    let session = |sandbox: &str, command: &[String]| {
        let mut args = vec!["connect", sandbox, "--"];
        args.extend(command.iter().map(String::as_str));
        lab.command(&args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap()
    };
    // Two connections: lab's other session, and the host's look below.
    let listening = session(
        "lab",
        &python(&[LISTENER, "listening.port", "lab-answers", "1"]),
    );
    let port = once_there(&lab.sandbox_home().join("listening.port"));
    let out = session("lab", &python(&[CLIENT, &port]))
        .wait_with_output()
        .unwrap();
    let reached = text(&out.stdout);
    assert!(
        reached.contains(&format!("{port} reached lab-answers")),
        "{out:?}"
    );
    let first = listening.wait_with_output().unwrap();
    assert!(first.status.success(), "{first:?}");

    // Lab listens again; `other` tries it, and a listener of its own.
    let listening = session(
        "lab",
        &python(&[LISTENER, "again.port", "lab-answers", "1"]),
    );
    let port = once_there(&lab.sandbox_home().join("again.port"));
    let script = format!(
        "/usr/bin/python3 -c '{LISTENER}' own.port other-answers 1 &
while [ ! -e \"$HOME/own.port\" ]; do sleep 0.1; done
/usr/bin/python3 -c '{CLIENT}' \"$(cat \"$HOME/own.port\")\" {port}
wait"
    );
    let out = lab
        .command(&["connect", "other", "--", "/bin/sh", "-c", &script])
        .output()
        .unwrap();
    let said = text(&out.stdout);
    let own = std::fs::read_to_string(lab.home_of("other").join("own.port")).unwrap();
    assert!(
        said.contains(&format!("{own} reached other-answers")),
        "{out:?}"
    );
    assert!(said.contains(&format!("{port} refused")), "{out:?}");
    assert!(!said.contains("lab-answers"), "{out:?}");
    // Lab's listener still waits for its one connection: from lab itself.
    let out = session("lab", &python(&[CLIENT, &port]))
        .wait_with_output()
        .unwrap();
    assert!(text(&out.stdout).contains("reached lab-answers"), "{out:?}");
    assert!(listening.wait_with_output().unwrap().status.success());
}

/// A session joins the namespace holder's namespaces through descriptors
/// that close on `exec`: no process of the session holds one, inside its
/// PID namespace or, read from the host, the bubblewrap that runs it. The
/// control: the namespace holder itself, read from the host, holds its own.
#[test]
fn on_a_runner_a_session_holds_no_namespace_descriptor() {
    if !on_a_runner() {
        return;
    }
    let lab = Lab::new();
    let script = r#"
import os
seen, held = 0, []
for pid in filter(str.isdigit, os.listdir("/proc")):
    try:
        fds = os.listdir("/proc/%s/fd" % pid)
    except OSError:
        continue
    for fd in fds:
        try:
            target = os.readlink("/proc/%s/fd/%s" % (pid, fd))
        except OSError:
            continue
        seen += 1
        if target.split(":[")[0] in ("user", "net", "mnt", "pid", "ipc", "uts", "cgroup", "time"):
            held.append("%s %s" % (pid, target))
print("seen", seen)
print("held", held)
"#;
    let out = lab.connect(&format!("/usr/bin/python3 -c '{script}'"));
    let said = text(&out.stdout);
    assert!(said.contains("held []"), "{out:?}");
    let seen: usize = said
        .lines()
        .find_map(|l| l.strip_prefix("seen "))
        .and_then(|n| n.parse().ok())
        .unwrap_or(0);
    assert!(seen > 3, "{out:?}");

    // From the host: the bubblewrap of a session that runs, and what it
    // runs, hold none.
    let mut running = lab
        .command(&["connect", "lab", "--", "/bin/sleep", "4322"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    let sleep = loop {
        if let Some(pid) = host_pid_of(&["sleep", "4322"]) {
            break pid;
        }
        assert!(Instant::now() < deadline, "the session never ran");
        std::thread::sleep(Duration::from_millis(200));
    };
    let inside = parent_of(sleep).unwrap();
    let bwrap = parent_of(inside).unwrap();
    let cmdline = std::fs::read(format!("/proc/{bwrap}/cmdline")).unwrap();
    assert!(
        text(&cmdline).starts_with("/usr/bin/bwrap"),
        "{}",
        text(&cmdline)
    );
    let held: Vec<String> = [sleep, inside, bwrap]
        .into_iter()
        .flat_map(namespace_descriptors)
        .collect();
    // Ours alone: the test started it.
    let _ = Command::new("kill").arg(sleep.to_string()).status();
    let _ = running.wait();
    assert!(held.is_empty(), "{held:?}");
    // The control: the namespace holder holds its user and network
    // namespaces, as the host reads them.
    let socket = lab.layout().proxy_socket("lab");
    let holder = host_pid_of(&[
        "enclos",
        "holder",
        "serve",
        "--port",
        &lab.proxy_port("lab").to_string(),
        "--proxy",
        socket.to_str().unwrap(),
    ])
    .expect("the namespace holder runs");
    let own = namespace_descriptors(holder);
    assert!(own.iter().any(|t| t.starts_with("user:[")), "{own:?}");
    assert!(own.iter().any(|t| t.starts_with("net:[")), "{own:?}");
}

/// What `pid` holds open, as the host reads it.
fn open_files(pid: u32) -> Vec<PathBuf> {
    std::fs::read_dir(format!("/proc/{pid}/fd"))
        .unwrap()
        .flatten()
        .filter_map(|e| std::fs::read_link(e.path()).ok())
        .collect()
}

/// A descriptor `connect`'s caller passed on reaches neither the session's
/// program nor the proxy `connect` started, which runs on after it. The
/// controls: a program the same shell starts on the host holds it, and
/// `/proc` shows it held.
#[test]
fn on_a_runner_what_connect_starts_holds_none_of_its_callers_descriptors() {
    if !on_a_runner() {
        return;
    }
    let lab = Lab::new();
    let lock = lab.root.path().join("caller.lock");
    std::fs::write(&lock, "").unwrap();
    let lock = lock.canonicalize().unwrap();

    let out = holding_open(&lock, Command::new("/bin/sh").args(["-c", HOLDS_NINE]))
        .output()
        .unwrap();
    assert_eq!(text(&out.stdout), "held", "{out:?}");
    let mut sleeping = holding_open(&lock, Command::new("/bin/sleep").arg("4323"))
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while !open_files(sleeping.id()).contains(&lock) {
        assert!(
            Instant::now() < deadline,
            "/proc never showed the lock held"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    let _ = sleeping.kill();
    let _ = sleeping.wait();

    let connect = lab.command(&["connect", "lab", "--", "/bin/sh", "-c", HOLDS_NINE]);
    let out = holding_open(&lock, &connect).output().unwrap();
    assert!(out.status.success(), "{out:?}");
    assert_eq!(text(&out.stdout), "none", "{out:?}");
    let port = lab.proxy_port("lab").to_string();
    let proxy = host_pid_of(&["enclos", "proxy", "run", "lab", "--port", &port])
        .expect("the proxy connect started runs on");
    let held = open_files(proxy);
    assert!(!held.contains(&lock), "{held:?}");
}

/// With the runtime's service listening, `connect` starts its session at
/// once: enclos reads the service's port in the sandbox's namespace, not on
/// the host, and the session reaches it on 127.0.0.1. The control: the
/// host's own loopback does not have it.
#[test]
fn on_a_runner_connect_does_not_wait_when_the_service_listens() {
    if !on_a_runner() {
        return;
    }
    let lab = Lab::new();
    lab.with_stand_in_hermes();
    lab.ok(&["sandbox", "start", "lab"]);
    let (port, token) = lab.gateway(None, Duration::from_secs(60));
    // Recorded as its session once it runs: give `launch` that long.
    std::thread::sleep(Duration::from_secs(1));
    let started = Instant::now();
    let out = lab.connect(&format!("/usr/bin/python3 -c '{CLIENT}' {port}"));
    let took = started.elapsed();
    let said = text(&out.stdout);
    assert!(
        said.contains(&format!("{port} reached gateway {token}")),
        "{out:?}"
    );
    let stderr = text(&out.stderr);
    assert!(!stderr.contains("waiting for the gateway"), "{stderr}");
    assert!(!stderr.contains("not listening"), "{stderr}");
    assert!(took < Duration::from_secs(20), "{took:?}: {stderr}");
    // The control: not on the host's loopback.
    assert!(std::net::TcpStream::connect((Ipv4Addr::LOCALHOST, port)).is_err());
}

/// A session open while the service restarts reaches it on its new port
/// with no help (ADR 0039): its namespace is the same. Here the stand-in
/// gateway exits when told, and the service manager starts it again. The
/// control: the port and the token did change.
#[test]
fn on_a_runner_a_session_open_across_a_gateway_restart_reaches_the_new_port() {
    if !on_a_runner() {
        return;
    }
    let lab = Lab::new();
    lab.with_stand_in_hermes();
    lab.ok(&["sandbox", "start", "lab"]);
    lab.gateway(None, Duration::from_secs(60));
    std::thread::sleep(Duration::from_secs(1));
    let script = r#"
import socket, time
def port():
    with open(__import__("os").environ["HOME"] + "/gateway.port") as f:
        p, t = f.read().split()
    return int(p), t
def say(p, word):
    c = socket.create_connection(("127.0.0.1", p), timeout=5)
    c.sendall(word)
    answer = c.recv(64).decode()
    c.close()
    return answer
first, token = port()
print("first", first, say(first, b"hi"), flush=True)
say(first, b"exit")
deadline = time.time() + 90
while time.time() < deadline:
    try:
        second, new = port()
        if new != token:
            print("second", second, say(second, b"hi"), flush=True)
            break
    except (OSError, ValueError):
        pass
    time.sleep(0.5)
"#;
    let out = lab.connect(&format!("/usr/bin/python3 -c '{script}'"));
    let said = text(&out.stdout);
    let line = |name: &str| -> Vec<String> {
        said.lines()
            .find(|l| l.starts_with(name))
            .unwrap_or_else(|| panic!("no {name} line: {out:?}"))
            .split(' ')
            .map(str::to_owned)
            .collect()
    };
    let (first, second) = (line("first"), line("second"));
    // `first <port> gateway <token>`, as the gateway wrote them.
    assert_eq!(first[2], "gateway");
    assert_eq!(second[2], "gateway");
    assert_ne!(first[3], second[3], "{said}");
    let (port, token) = lab.gateway(Some(&first[3]), Duration::from_secs(5));
    assert_eq!(second[1], port.to_string(), "{said}");
    assert_eq!(second[3], token, "{said}");
}

/// A session of another sandbox, in Python: listens on the abstract socket
/// named first, says so with a file in its home, and waits.
const ABSTRACT_LISTENER: &str = r#"
import os, socket, sys, time
s = socket.socket(socket.AF_UNIX)
s.bind("\0" + sys.argv[1])
s.listen()
open(os.path.join(os.environ["HOME"], "abstract.ready"), "w").close()
time.sleep(600)
"#;

/// The text of a `policy test --json` report, a line per probe, for the
/// job's log.
fn report_lines(report: &serde_json::Value) -> String {
    let mut lines = vec![
        report["verdict"]
            .as_str()
            .unwrap_or("no verdict")
            .to_owned(),
    ];
    for probe in report["probes"].as_array().into_iter().flatten() {
        lines.push(format!(
            "{:<12}  {:<16}  {}{}",
            probe["outcome"].as_str().unwrap_or("?"),
            probe["route"].as_str().unwrap_or("?"),
            probe["name"].as_str().unwrap_or("?"),
            probe["why"]
                .as_str()
                .map(|why| format!("  ({why})"))
                .unwrap_or_default()
        ));
    }
    for (what, key) in [
        ("Not here", "not_here"),
        ("Not probed", "not_probed"),
        ("Said", "notices"),
    ] {
        for item in report[key].as_array().into_iter().flatten() {
            lines.push(format!("{what}: {}", item.as_str().unwrap_or("?")));
        }
    }
    lines.join("\n") + "\n"
}

/// `policy test` runs bubblewrap's own escape probes and is READY, with no
/// probe open and every route of milestone 3's step 5 shown closed (design
/// §13): with a denied folder in the user's home, a workspace holding a
/// denied folder and a denied file, and another sandbox running a session
/// that listens on an abstract socket, its `secrets/` folder there, and a
/// socket listening in the user's home that no deny entry names, which
/// `wrap` masks at each launch. Each probe's control runs on the host. The
/// report goes to the test's target folder, which the job prints.
#[test]
fn on_a_runner_policy_test_is_ready_and_no_probe_gets_out() {
    if !on_a_runner() {
        return;
    }
    let lab = Lab::new();
    let ssh = home().join(".ssh");
    std::fs::create_dir_all(&ssh).unwrap();
    let planted = ssh.join("enclos-ci-probe");
    std::fs::write(&planted, "secret\n").unwrap();
    let work = home().join("enclos-ci-work");
    std::fs::create_dir_all(work.join(".secrets")).unwrap();
    std::fs::create_dir_all(work.join("config")).unwrap();
    std::fs::write(work.join(".secrets/token"), "secret\n").unwrap();
    std::fs::write(work.join("config/.env"), "TOKEN=secret\n").unwrap();
    let policy_file = lab.root.path().join("sandboxes/lab/policy.toml");
    let original = std::fs::read_to_string(&policy_file).unwrap();
    let policy = original.replace(
        "write_add = []\nread_deny_add = []",
        "write_add = [\"~/enclos-ci-work\"]\nread_deny_add = [\"~/enclos-ci-work/.secrets\", \"~/enclos-ci-work/config/.env\"]",
    );
    assert_ne!(policy, original, "the grant was not added:\n{original}");
    std::fs::write(&policy_file, policy).unwrap();
    // `policy allow` applies the file's other changes with `--yes`.
    lab.ok(&["policy", "allow", "lab", "example.com", "--yes"]);

    lab.ok(&[
        "sandbox",
        "create",
        "other",
        "--backend",
        "bubblewrap",
        "--template",
        "assistant",
    ]);
    let mut other = lab
        .command(&[
            "connect",
            "other",
            "--",
            "/usr/bin/python3",
            "-c",
            ABSTRACT_LISTENER,
            "enclos-ci-other",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    once_there(&lab.home_of("other").join("abstract.ready"));
    // As `launch` writes it for a service (ADR 0034).
    let secrets = lab.root.path().join("sandboxes/other/secrets");
    std::fs::create_dir_all(&secrets).unwrap();
    std::fs::write(secrets.join(".env"), "TOKEN=other\n").unwrap();
    // This test's own, listening until it ends.
    let listening = home().join("enclos-ci-listening.sock");
    let _ = std::fs::remove_file(&listening);
    let listener = std::os::unix::net::UnixListener::bind(&listening).unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_enclos"))
        .args(["--json", "policy", "test", "lab"])
        .env("ENCLOS_HOME", lab.root.path())
        .stdin(Stdio::null())
        .output()
        .unwrap();
    drop(listener);
    let _ = std::fs::remove_file(&listening);
    let _ = std::fs::remove_file(&planted);
    let _ = std::fs::remove_dir_all(&work);
    let _ = lab.command(&["sandbox", "stop", "other"]).output();
    let _ = other.kill();
    let _ = other.wait();

    let report: serde_json::Value =
        serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("{e}: {out:?}"));
    let lines = report_lines(&report);
    let file = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("policy-test-lab.txt");
    std::fs::write(&file, &lines).unwrap();
    let probes = report["probes"].as_array().cloned().unwrap_or_default();
    let with = |outcome: &str| -> Vec<String> {
        probes
            .iter()
            .filter(|p| p["outcome"] == outcome)
            .map(|p| format!("{}: {}", p["route"], p["name"]))
            .collect()
    };
    assert!(with("open").is_empty(), "open: {:?}\n{lines}", with("open"));
    assert!(
        with("not_run").is_empty(),
        "not run: {:?}\n{lines}",
        with("not_run")
    );
    assert_eq!(report["ready"], true, "{lines}");
    assert_eq!(out.status.code(), Some(0), "{lines}");
    let closed = |route: &str, name: &str| {
        probes.iter().any(|p| {
            p["outcome"] == "closed"
                && p["route"] == route
                && p["name"].as_str().is_some_and(|n| n.contains(name))
        })
    };
    let other_secrets = format!("read {}", secrets.display());
    for (route, name) in [
        ("sensitive files", "read "),
        ("sensitive files", "under a write grant"),
        ("enclos files", "read "),
        ("other sandboxes", other_secrets.as_str()),
        ("writes", "write outside the home"),
        ("writable folders", "remove the sandbox home"),
        ("writable folders", "rename "),
        ("renames", "/enclos-ci-work/config"),
        ("network", "where a program listens on the host"),
        ("vsock", "AF_VSOCK"),
        ("dns", "resolver"),
        ("host sockets", "connect to /"),
        ("host sockets", "/enclos-ci-listening.sock"),
        ("abstract sockets", "where enclos listens on the host"),
        ("abstract sockets", "@enclos-ci-other, of sandbox other"),
        ("session bus", "session bus"),
        ("system bus", "system bus"),
        ("systemd --user", "manager"),
        ("signals", "signal a process outside"),
        ("ptrace", "attach"),
        ("environment", "a process outside the sandbox"),
        ("environment", "of sandbox other"),
        ("terminals", "TIOCSTI"),
        ("setuid", "chage"),
        ("user namespace", "user namespace"),
        ("mounts", "mount"),
        ("cgroup", "cgroup"),
    ] {
        assert!(
            closed(route, name),
            "no closed {route} probe `{name}`:\n{lines}"
        );
    }
}
