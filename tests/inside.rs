//! `enclos inside` applied for real: only in CI's `confinement` job, each
//! test in a child process of its own, since what it applies cannot be
//! undone and a rule that did not hold would act on the host. The refusals
//! here are Landlock's and seccomp's alone, with no bubblewrap around them.
//! The rest of `enclos inside` is `src/backend/bubblewrap/inside/`'s tests.
#![cfg(target_os = "linux")]

use std::fs::Permissions;
use std::io::{ErrorKind, Read, Write};
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::{Duration, Instant};

use serde_json::Value;
use tempfile::TempDir;

const PYTHON: &str = "/usr/bin/python3";
const TRUE: &str = "/usr/bin/true";
const TOUCH: &str = "/usr/bin/touch";

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

/// Finds the relay as [`RELAY_STATUS`] does, starts a child of this program,
/// and reports what signalling each answers. A signal 0 is checked as any
/// other and sends nothing.
const SIGNALS: &str = r#"
import errno, os, subprocess
def signalled(pid):
    try:
        os.kill(pid, 0)
        return "ok"
    except OSError as e:
        return errno.errorcode[e.errno]
me = str(os.getpid())
parent = str(os.getppid())
relay = None
for pid in filter(str.isdigit, os.listdir("/proc")):
    try:
        status = open(f"/proc/{pid}/status").read()
    except OSError:
        continue
    if f"PPid:\t{parent}\n" in status and pid != me:
        relay = int(pid)
child = subprocess.Popen(["/usr/bin/sleep", "30"])
print(signalled(relay), signalled(child.pid))
child.kill()
child.wait()
"#;

/// Reports what `socket` answers for vsock, then for two families a session
/// keeps.
const SOCKETS: &str = r#"
import errno, socket
def opened(family):
    try:
        socket.socket(family, socket.SOCK_STREAM).close()
        return "ok"
    except OSError as e:
        return errno.errorcode[e.errno]
print(opened(40), opened(socket.AF_UNIX), opened(socket.AF_INET))
"#;

/// Prints each sibling's seccomp mode, no_new_privs and process group, as
/// the kernel shows them, then the command's own group: `enclos inside`
/// starts the relay and the command, and nothing else.
const RELAY_STATUS: &str = r#"
import os
me = str(os.getpid())
parent = str(os.getppid())
for pid in filter(str.isdigit, os.listdir("/proc")):
    try:
        status = open(f"/proc/{pid}/status").read()
    except OSError:
        continue
    fields = dict(line.split(":\t", 1) for line in status.splitlines() if ":\t" in line)
    if fields.get("PPid") == parent and pid != me:
        print(fields["Seccomp"], fields["NoNewPrivs"], fields["NSpgid"], os.getpgid(0))
"#;

/// Ports for relays, one each. They lie below the kernel's ephemeral ports,
/// so no bind of port 0 gets one, and outside the proxies' range. A port a
/// bind of 0 found and let go could be another test's by the time a relay
/// binds it.
static NEXT_PORT: AtomicU16 = AtomicU16::new(20000);

fn next_port() -> u16 {
    NEXT_PORT.fetch_add(1, Ordering::Relaxed)
}

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
        let port = next_port();
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

    /// What a session's command left.
    fn session(&self, command: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_enclos"))
            .arg("inside")
            .arg("--compiled")
            .arg(&self.compiled)
            .arg("--")
            .args(command)
            .output()
            .unwrap()
    }

    /// What the session's command left, and its folder.
    fn run(self, command: &[&str]) -> (Output, TempDir) {
        let output = self.session(command);
        (output, self.dir)
    }
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).trim().to_owned()
}

/// What a probe printed, once it ran to its end.
fn said(output: &Output) -> String {
    assert!(output.status.success(), "{output:?}");
    text(&output.stdout)
}

/// Whether a session's command ran to its end with no word from either.
fn said_nothing(output: &Output) -> bool {
    output.status.success() && output.stderr.is_empty()
}

fn python(script: &str) -> Output {
    Command::new(PYTHON).args(["-c", script]).output().unwrap()
}

/// The kernel's own range is read, so a host that widened it fails here
/// rather than as a port taken under a session.
#[test]
fn a_relay_port_is_one_no_bind_of_port_0_gets_and_no_proxy_uses() {
    let range = std::fs::read_to_string("/proc/sys/net/ipv4/ip_local_port_range").unwrap();
    let first: u16 = range.split_whitespace().next().unwrap().parse().unwrap();
    let (one, other) = (next_port(), next_port());
    assert_ne!(one, other);
    for port in [one, other] {
        assert!(port < first, "{port} is an ephemeral port, from {first}");
        assert!(port < 41000, "{port} may be a proxy's");
    }
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

/// A rule on a path nobody may look at stops the relay at that rule, before
/// it restricts anything and before the session does, so this one runs
/// anywhere: it is the real start of a relay that never says it is ready. The
/// control is what keeps it so, as a root that can look would apply the rules.
#[test]
fn a_relay_that_cannot_confine_itself_stops_the_session_and_says_why() {
    let confined = Confined::new();
    let locked = confined.path("locked");
    std::fs::create_dir(&locked).unwrap();
    let file = std::fs::read_to_string(&confined.compiled).unwrap();
    let mut compiled: Value = serde_json::from_str(&file).unwrap();
    let rule = compiled["landlock"]["write"].as_array_mut().unwrap();
    rule.push(serde_json::json!(locked.join("inside")));
    std::fs::write(&confined.compiled, compiled.to_string()).unwrap();
    std::fs::set_permissions(&locked, Permissions::from_mode(0o000)).unwrap();
    let looked = std::fs::metadata(locked.join("inside")).unwrap_err();
    assert_eq!(looked.kind(), ErrorKind::PermissionDenied, "the control");

    let marker = confined.path("allowed/ran");
    let output = confined.session(&[TOUCH, marker.to_str().unwrap()]);
    std::fs::set_permissions(&locked, Permissions::from_mode(0o700)).unwrap();
    assert_eq!(output.status.code(), Some(125), "{output:?}");
    let stderr = text(&output.stderr);
    assert!(stderr.contains("the relay did not start: "), "{stderr}");
    assert!(stderr.contains("Permission denied"), "{stderr}");
    assert!(stderr.contains("locked/inside"), "{stderr}");
    assert!(!marker.exists());
}

const WRITE: &str = "echo written > \"$1\"";

fn write_in(confined: Confined, path: &Path) -> (Output, TempDir) {
    let path = path.to_str().unwrap().to_owned();
    confined.run(&["/bin/sh", "-c", WRITE, "sh", &path])
}

/// With nothing on stderr, so every rule held: no line says Landlock is
/// older or missing.
#[test]
fn on_a_runner_an_allowed_write_works() {
    if !on_a_runner() {
        return;
    }
    let confined = Confined::new();
    let allowed = confined.path("allowed/file");
    let (written, _dir) = write_in(confined, &allowed);
    assert!(written.status.success(), "{written:?}");
    assert!(written.stderr.is_empty(), "{written:?}");
    assert_eq!(std::fs::read_to_string(&allowed).unwrap(), "written\n");
}

/// The same write with no rules works: the rules, not the folder, refuse it.
#[test]
fn on_a_runner_a_write_outside_the_rules_is_refused() {
    if !on_a_runner() {
        return;
    }
    let confined = Confined::new();
    let outside = confined.path("outside");
    let host = Command::new("/bin/sh")
        .args(["-c", WRITE, "sh"])
        .arg(&outside)
        .status()
        .unwrap();
    assert!(host.success(), "the control could not write");
    std::fs::remove_file(&outside).unwrap();

    let (refused, _dir) = write_in(confined, &outside);
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
    // Copied by a program of its own: a descriptor this process held open
    // for writing could reach a child a parallel test is starting, and the
    // copy then could not run (ETXTBSY).
    let copied = Command::new("/bin/cp")
        .arg(TRUE)
        .arg(&copy)
        .status()
        .unwrap();
    assert!(copied.success(), "the copy failed");
    let copy = copy.to_str().unwrap();
    let ran = Command::new(copy).status().unwrap();
    assert!(ran.success(), "the control could not run");

    let (refused, _dir) = confined.run(&[copy]);
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
    let (inside, _dir) = Confined::new().run(&[PYTHON, "-c", TIOCSTI]);
    assert_eq!(said(&inside), "EPERM");
}

#[test]
fn on_a_runner_a_user_namespace_is_refused() {
    if !on_a_runner() {
        return;
    }
    assert_eq!(said(&python(UNSHARE)), "ok", "the control");
    let (inside, _dir) = Confined::new().run(&[PYTHON, "-c", UNSHARE]);
    assert_eq!(said(&inside), "EPERM");
}

/// The control is that the host does not answer as the filter does: a host
/// with no vsock says so with another errno.
#[test]
fn on_a_runner_a_socket_family_outside_the_compiled_ones_is_refused() {
    if !on_a_runner() {
        return;
    }
    let host = said(&python(SOCKETS));
    assert!(host.ends_with(" ok ok"), "the control: {host}");
    assert!(!host.starts_with("EPERM"), "the control: {host}");
    let (inside, _dir) = Confined::new().run(&[PYTHON, "-c", SOCKETS]);
    assert_eq!(said(&inside), "EPERM ok ok");
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
    let (output, _dir) = confined.run(&[PYTHON, "-c", &script]);
    assert_eq!(said(&output), "pong");
    proxy.join().unwrap();
}

/// It starts before the session applies anything, so a filter on it is the
/// one it applied to itself.
#[test]
fn on_a_runner_the_relay_applied_the_filter_to_itself() {
    if !on_a_runner() {
        return;
    }
    let (output, _dir) = Confined::new().run(&[PYTHON, "-c", RELAY_STATUS]);
    let status = said(&output);
    let fields: Vec<&str> = status.split_whitespace().collect();
    assert_eq!(fields[..2], ["2", "1"], "{output:?}");
}

/// `enclos inside` runs the command to its end and gives its exit code.
#[test]
fn on_a_runner_the_commands_exit_code_is_the_sessions() {
    if !on_a_runner() {
        return;
    }
    let (output, _dir) = Confined::new().run(&["/bin/sh", "-c", "echo ran; exit 3"]);
    assert_eq!(output.status.code(), Some(3), "{output:?}");
    assert_eq!(text(&output.stdout), "ran");
}

/// Not dumpable, so the kernel gives its `/proc` entries to root, and no
/// process of the session attaches to it or writes its memory; the command
/// it started is dumpable, as the control.
#[test]
fn on_a_runner_enclos_inside_is_not_dumpable() {
    if !on_a_runner() {
        return;
    }
    let script = "import os; print(os.stat(f'/proc/{os.getppid()}/mem').st_uid, os.stat(f'/proc/{os.getpid()}/mem').st_uid == os.getuid())";
    let (output, _dir) = Confined::new().run(&[PYTHON, "-c", script]);
    assert_eq!(said(&output), "0 True", "{output:?}");
}

/// A terminal signals the foreground group, which is the command's.
#[test]
fn on_a_runner_the_relay_keeps_out_of_the_commands_process_group() {
    if !on_a_runner() {
        return;
    }
    let (output, _dir) = Confined::new().run(&[PYTHON, "-c", RELAY_STATUS]);
    let status = said(&output);
    let fields: Vec<&str> = status.split_whitespace().collect();
    assert_eq!(fields.len(), 4, "{status}");
    assert_ne!(fields[2], fields[3], "{status}");
}

/// The relay is in a Landlock domain of its own, a sibling of the command's;
/// a child of the command shares the command's, and is the control.
#[test]
fn on_a_runner_a_sessions_command_cannot_signal_its_relay() {
    if !on_a_runner() {
        return;
    }
    let (output, _dir) = Confined::new().run(&[PYTHON, "-c", SIGNALS]);
    assert_eq!(said(&output), "EPERM ok", "{output:?}");
}

/// A relay leaves within a look at its parent of its session's end: one left
/// behind holds the port for as long as it runs.
#[test]
fn on_a_runner_a_second_session_gets_the_port_of_the_first() {
    if !on_a_runner() {
        return;
    }
    let confined = Confined::new();
    assert!(said_nothing(&confined.session(&[TRUE])));
    let until = Instant::now() + Duration::from_secs(5);
    while TcpListener::bind(("127.0.0.1", confined.port)).is_err() {
        assert!(Instant::now() < until, "the first session's relay stayed");
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(said_nothing(&confined.session(&[TRUE])));
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
    let log = confined.path("allowed/relay.log");
    let (output, _dir) = confined.run(&[PYTHON, "-c", &script]);
    assert_eq!(said(&output), "b''");
    assert!(output.stderr.is_empty(), "{output:?}");
    let log = std::fs::read_to_string(log).unwrap();
    assert!(log.contains("cannot reach"), "{log}");
}
