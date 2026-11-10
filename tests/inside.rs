//! `enclos inside` applied for real: only in CI's `confinement` job, each
//! test in a child process of its own, since what it applies cannot be
//! undone and a rule that did not hold would act on the host. The refusals
//! here are Landlock's and seccomp's alone, with no bubblewrap around them.
//! The rest of `enclos inside` is `src/backend/bubblewrap/inside/`'s tests.
#![cfg(target_os = "linux")]

use std::fs::Permissions;
use std::io::ErrorKind;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

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

/// Prints how many other children the command's parent, `enclos inside`,
/// has: it starts the command and nothing else, so the command is PID 2 of
/// a session's PID namespace, as the host finds a service's program
/// (`lifecycle::proc::program_in_pid_namespace`).
const SIBLINGS: &str = r#"
import os
me = str(os.getpid())
parent = str(os.getppid())
others = 0
for pid in filter(str.isdigit, os.listdir("/proc")):
    try:
        status = open(f"/proc/{pid}/status").read()
    except OSError:
        continue
    if f"PPid:\t{parent}\n" in status and pid != me:
        others += 1
print(others)
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
/// `allowed/` the only place to write. The program under test stays out of
/// the execute rules, in `target/`, as an enclos in the user's home is.
struct Confined {
    dir: TempDir,
    compiled: PathBuf,
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
        compiled["landlock"]["write"] = serde_json::json!([allowed]);
        let file = dir.path().join("compiled.json");
        std::fs::write(&file, compiled.to_string()).unwrap();
        Self {
            dir,
            compiled: file,
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

/// A rule on a path nobody may look at stops the session at that rule,
/// before it restricts anything, so this one runs anywhere. The control is
/// what keeps it so, as a root that can look would apply the rules.
#[test]
fn a_rule_that_cannot_be_made_stops_the_session_before_its_command() {
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
    assert!(stderr.contains("Landlock: "), "{stderr}");
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

/// The signals `/proc/self/status` says the command ignores, when the
/// session was started with SIGINT and SIGQUIT ignored, as `wrap` starts
/// bubblewrap in a terminal, with and without the flag that hands them back.
fn ignored_by_the_command(restore: bool) -> u64 {
    let confined = Confined::new();
    let mut inside = vec!["inside", "--compiled", confined.compiled.to_str().unwrap()];
    if restore {
        inside.push("--restore-interrupts");
    }
    let out = Command::new("/bin/sh")
        .arg("-c")
        .arg("trap '' INT QUIT; exec \"$0\" \"$@\"")
        .arg(env!("CARGO_BIN_EXE_enclos"))
        .args(&inside)
        .args([
            "--",
            "/bin/sh",
            "-c",
            "grep '^SigIgn:' /proc/self/status | cut -f2",
        ])
        .output()
        .unwrap();
    u64::from_str_radix(&said(&out), 16).unwrap()
}

/// Ctrl-C and Ctrl-\ reach the command again, which bubblewrap's outer
/// process ignores; without the flag they stay ignored, the control.
#[test]
fn on_a_runner_the_command_gets_back_the_interrupts_bubblewrap_ignores() {
    if !on_a_runner() {
        return;
    }
    const INT_AND_QUIT: u64 = 0b110;
    assert_eq!(ignored_by_the_command(false) & INT_AND_QUIT, INT_AND_QUIT);
    assert_eq!(ignored_by_the_command(true) & INT_AND_QUIT, 0);
}

/// `enclos inside` starts the command and nothing else: no relay, which
/// the sandbox's namespace holder serves (ADR 0039).
#[test]
fn on_a_runner_the_command_is_the_only_process_enclos_inside_starts() {
    if !on_a_runner() {
        return;
    }
    let (output, _dir) = Confined::new().run(&[PYTHON, "-c", SIBLINGS]);
    assert_eq!(said(&output), "0", "{output:?}");
}

/// Says how many of the command's descriptors open the file named first,
/// and the variable that named bubblewrap's stderr to `enclos inside`.
const STDERR_COPIES: &str = r#"
import os, sys
copies = 0
for fd in os.listdir("/proc/self/fd"):
    try:
        copies += os.readlink(f"/proc/self/fd/{fd}") == sys.argv[1]
    except OSError:
        pass
print("copies", copies, "variable", os.environ.get("ENCLOS_BUBBLEWRAP_STDERR", "none"), file=sys.stderr)
"#;

/// Started as a session's bubblewrap is (`setup`), with its stderr a pipe
/// and the stderr it was given named apart: `enclos inside` says it runs
/// and takes that stderr back, so the command writes to it at 2, holds no
/// other copy, and never sees the variable; what enclos read on the pipe
/// before is not passed on.
#[test]
fn on_a_runner_the_command_writes_to_the_stderr_given_and_holds_no_other_copy() {
    if !on_a_runner() {
        return;
    }
    let confined = Confined::new();
    let given = confined.path("stderr");
    let stderr = std::fs::File::create(&given).unwrap();
    let given = given.canonicalize().unwrap();
    let status = enclos::backend::bubblewrap::setup::run(
        || {
            let mut inside = Command::new(env!("CARGO_BIN_EXE_enclos"));
            inside
                .args(["inside", "--compiled"])
                .arg(&confined.compiled)
                .args(["--", PYTHON, "-c", STDERR_COPIES])
                .arg(&given);
            Ok(inside)
        },
        &stderr,
        &enclos::backend::bubblewrap::setup::PAUSES,
    )
    .unwrap();
    let said = std::fs::read_to_string(&given).unwrap();
    assert!(status.success(), "{status} {said}");
    assert_eq!(said, "copies 1 variable none\n");
}
