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
        self.root.path().join("sandboxes/lab/home")
    }
}

impl Drop for Lab {
    fn drop(&mut self) {
        let _ = self.command(&["sandbox", "stop", "lab"]).output();
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

/// What the runner's host gives the sessions, for reading the results.
#[test]
fn on_a_runner_doctor_reports_the_backend() {
    if !on_a_runner() {
        return;
    }
    let lab = Lab::new();
    let out = lab.command(&["doctor"]).output().unwrap();
    let said = text(&out.stdout);
    println!("{said}");
    assert!(said.contains("bubblewrap: runs here"), "{out:?}");
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
    let parsed: CompiledSandbox =
        serde_json::from_str(&std::fs::read_to_string(compiled).unwrap()).unwrap();
    let layout = enclos::layout::Layout::at(lab.root.path());
    let ctx = SandboxContext::new(&layout, &"lab".parse().unwrap(), parsed.relay.port);
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
