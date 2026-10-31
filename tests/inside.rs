//! `enclos inside` applied for real: only in CI's `confinement` job, each
//! test in a child process of its own, since what it applies cannot be
//! undone and a rule that did not hold would act on the host. The refusals
//! here are Landlock's and seccomp's alone, with no bubblewrap around them.
//! The rest of `enclos inside` is `src/backend/bubblewrap/inside/`'s tests.
#![cfg(target_os = "linux")]

use std::io::{Read, Write};
use std::net::TcpListener;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;
use tempfile::TempDir;

const PYTHON: &str = "/usr/bin/python3";

/// Reports what `unshare(CLONE_NEWUSER)` answers.
const UNSHARE: &str = r#"
import ctypes, errno, os
libc = ctypes.CDLL(None, use_errno=True)
print("ok" if libc.unshare(0x10000000) == 0 else errno.errorcode[ctypes.get_errno()])
"#;

/// Reports what TIOCSTI answers on its own controlling terminal, which is
/// what the kernel checks first.
const TIOCSTI: &str = r#"
import errno, fcntl, os, pty, sys
pid, master = pty.fork()
if pid == 0:
    try:
        fcntl.ioctl(0, 0x5412, b"x")
        print("ok")
    except OSError as e:
        print(errno.errorcode[e.errno])
    sys.stdout.flush()
    os._exit(0)
said = b""
try:
    while chunk := os.read(master, 100):
        said += chunk
except OSError:
    pass
os.waitpid(pid, 0)
print(said.decode().split()[-1])
"#;

/// Whether to run these tests: they refuse anywhere but a GitHub-hosted
/// runner, in CI's `confinement` job, which sets `ENCLOS_CONFINEMENT_TESTS`.
fn on_a_runner() -> bool {
    if std::env::var("ENCLOS_CONFINEMENT_TESTS").as_deref() != Ok("1") {
        eprintln!("confinement tests not run: CI's confinement job runs them");
        return false;
    }
    let var = |name: &str| std::env::var(name).unwrap_or_default();
    assert!(
        var("GITHUB_ACTIONS") == "true" && var("RUNNER_ENVIRONMENT") == "github-hosted",
        "these tests apply Landlock and seccomp and try what they refuse: they run only on a GitHub-hosted runner"
    );
    true
}

/// A folder holding a compiled file: the `minimal` template's rules, with
/// `allowed/` the only place to write, and a relay of its own. The program
/// under test stays out of the execute rules, in `target/`, as an enclos in
/// the user's home is.
struct Confined {
    dir: TempDir,
    compiled: PathBuf,
    port: u16,
}

impl Confined {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let allowed = dir.path().join("allowed");
        std::fs::create_dir(&allowed).unwrap();
        let snapshot =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("src/backend/bubblewrap/minimal.snapshot");
        let mut compiled: Value =
            serde_json::from_str(&std::fs::read_to_string(snapshot).unwrap()).unwrap();
        let port = free_port();
        compiled["landlock"]["write"] = serde_json::json!([allowed]);
        compiled["relay"] = serde_json::json!({
            "port": port,
            "socket": dir.path().join("proxy.sock"),
            "log": dir.path().join("allowed/relay.log"),
        });
        let file = dir.path().join("compiled.json");
        std::fs::write(&file, compiled.to_string()).unwrap();
        Self {
            dir,
            compiled: file,
            port,
        }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn run(&self, command: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_enclos"))
            .arg("inside")
            .arg("--compiled")
            .arg(&self.compiled)
            .arg("--")
            .args(command)
            .output()
            .unwrap()
    }
}

fn free_port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).trim().to_owned()
}

/// What a probe printed, once it ran to its end.
fn said(output: &Output) -> String {
    assert!(output.status.success(), "{output:?}");
    text(&output.stdout)
}

fn python(script: &str) -> Output {
    Command::new(PYTHON).args(["-c", script]).output().unwrap()
}

/// Stops at the file, before anything is started or applied, so this one
/// runs anywhere.
#[test]
fn a_compiled_file_that_is_not_there_stops_a_session_before_its_command() {
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("ran");
    let output = Command::new(env!("CARGO_BIN_EXE_enclos"))
        .args(["inside", "--compiled"])
        .arg(dir.path().join("none.json"))
        .args(["--", "/usr/bin/touch"])
        .arg(&marker)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(125), "{output:?}");
    assert!(
        text(&output.stderr).contains("cannot read the compiled file"),
        "{output:?}"
    );
    assert!(!marker.exists());
}

/// The same write with no rules works: the rules, not the folder, refuse it.
#[test]
fn on_a_runner_a_write_outside_the_rules_is_refused_and_an_allowed_one_works() {
    if !on_a_runner() {
        return;
    }
    let confined = Confined::new();
    let script = "echo written > \"$1\"";
    let write = |path: &Path| {
        let path = path.to_str().unwrap().to_owned();
        confined.run(&["/bin/sh", "-c", script, "sh", &path])
    };

    let allowed = confined.path("allowed/file");
    let written = write(&allowed);
    assert!(written.status.success(), "{written:?}");
    assert!(written.stderr.is_empty(), "{written:?}");
    assert_eq!(std::fs::read_to_string(&allowed).unwrap(), "written\n");

    let outside = confined.path("outside");
    let host = Command::new("/bin/sh")
        .args(["-c", script, "sh"])
        .arg(&outside)
        .status()
        .unwrap();
    assert!(host.success(), "the control could not write");
    std::fs::remove_file(&outside).unwrap();

    let refused = write(&outside);
    assert!(!refused.status.success(), "{refused:?}");
    assert!(
        text(&refused.stderr).contains("Permission denied"),
        "{refused:?}"
    );
    assert!(!outside.exists());
}

#[test]
fn on_a_runner_a_program_outside_the_execute_rules_is_refused() {
    if !on_a_runner() {
        return;
    }
    let confined = Confined::new();
    let copy = confined.path("allowed/true");
    std::fs::copy("/usr/bin/true", &copy).unwrap();
    let copy = copy.to_str().unwrap();
    let ran = Command::new(copy).status().unwrap();
    assert!(ran.success(), "the control could not run");

    let refused = confined.run(&[copy]);
    assert_eq!(refused.status.code(), Some(125), "{refused:?}");
    assert!(
        text(&refused.stderr).contains("Permission denied"),
        "{refused:?}"
    );
}

#[test]
fn on_a_runner_tiocsti_is_refused() {
    if !on_a_runner() {
        return;
    }
    let host = said(&python(TIOCSTI));
    assert_ne!(
        host, "EPERM",
        "the control is refused as the filter refuses"
    );
    let inside = Confined::new().run(&[PYTHON, "-c", TIOCSTI]);
    assert_eq!(said(&inside), "EPERM");
}

#[test]
fn on_a_runner_a_user_namespace_is_refused() {
    if !on_a_runner() {
        return;
    }
    assert_eq!(said(&python(UNSHARE)), "ok", "the control");
    let inside = Confined::new().run(&[PYTHON, "-c", UNSHARE]);
    assert_eq!(said(&inside), "EPERM");
}

/// Answers one connection from the relay, as a proxy would.
fn answer_once(socket: PathBuf) -> std::thread::JoinHandle<()> {
    let proxy = UnixListener::bind(socket).unwrap();
    std::thread::spawn(move || {
        let (mut client, _) = proxy.accept().unwrap();
        let mut asked = [0; 4];
        client.read_exact(&mut asked).unwrap();
        assert_eq!(&asked, b"ping");
        client.write_all(b"pong").unwrap();
    })
}

/// The relay is confined too, serves from a program no execute rule covers,
/// and is there by the time the command runs.
#[test]
fn on_a_runner_the_command_reaches_the_proxy_through_the_confined_relay() {
    if !on_a_runner() {
        return;
    }
    let confined = Confined::new();
    let proxy = answer_once(confined.path("proxy.sock"));
    let script = format!(
        "import socket\nc = socket.create_connection(('127.0.0.1', {}))\nc.sendall(b'ping')\nprint(c.recv(4).decode())",
        confined.port
    );
    let output = confined.run(&[PYTHON, "-c", &script]);
    assert_eq!(said(&output), "pong");
    proxy.join().unwrap();
}

/// A relay's notice goes to its log, not to the session's terminal.
#[test]
fn on_a_runner_the_relays_notices_stay_out_of_the_sessions_stderr() {
    if !on_a_runner() {
        return;
    }
    let confined = Confined::new();
    let script = format!(
        "import socket\nc = socket.create_connection(('127.0.0.1', {}))\nprint(c.recv(1))",
        confined.port
    );
    let output = confined.run(&[PYTHON, "-c", &script]);
    assert_eq!(said(&output), "b''");
    assert!(output.stderr.is_empty(), "{output:?}");
    let log = std::fs::read_to_string(confined.path("allowed/relay.log")).unwrap();
    assert!(log.contains("cannot reach"), "{log}");
}
