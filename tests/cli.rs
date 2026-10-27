//! Runs the `enclos` binary against a temporary `ENCLOS_HOME` and `HOME`, so
//! tests never touch the real home folder, its `~/Library/LaunchAgents`
//! included. No test runs `sandbox start`: it would install real services.

use std::fs::File;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::Duration;

use tempfile::TempDir;

struct Home {
    _dir: TempDir,
    root: PathBuf,
}

impl Home {
    fn new() -> Home {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("enclos");
        Home { _dir: dir, root }
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_enclos"));
        // Text, though the output is piped: the tests below read what a
        // person reads, and get JSON by piping without it (`run_piped`).
        cmd.arg("--text")
            .args(args)
            .env("ENCLOS_HOME", &self.root)
            .env("HOME", self._dir.path())
            // The baseline enclos ships, whatever the shell running the
            // tests exported; a test that compares sets it itself.
            .env_remove("ENCLOS_SEATBELT_BASELINE");
        cmd
    }

    fn run(&self, args: &[&str]) -> Run {
        Run(self.command(args).output().unwrap())
    }

    /// As a script runs it: output piped, and no --text.
    fn piped(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_enclos"));
        cmd.args(args)
            .env("ENCLOS_HOME", &self.root)
            .env("HOME", self._dir.path())
            .env_remove("ENCLOS_SEATBELT_BASELINE");
        cmd
    }

    fn run_piped(&self, args: &[&str]) -> Run {
        Run(self.piped(args).output().unwrap())
    }

    /// The JSON document a piped run printed.
    /// The JSON document a piped run printed, whose `error` agrees with
    /// its exit code: there exactly when it fails, with that code.
    fn json(&self, args: &[&str]) -> (i32, serde_json::Value) {
        let out = self.run_piped(args);
        let doc: serde_json::Value = serde_json::from_str(&out.stdout()).unwrap_or_else(|e| {
            panic!(
                "{args:?}: {e}\nstdout: {}\nstderr: {}",
                out.stdout(),
                out.stderr()
            )
        });
        let code = out.code();
        assert_eq!(
            code == 0,
            doc.get("error").is_none(),
            "{args:?}: exit {code}, {doc}"
        );
        if let Some(error) = doc.get("error") {
            assert_eq!(error["exit_code"], code, "{args:?}: {doc}");
        }
        (code, doc)
    }

    fn init(&self, times: usize) {
        for _ in 0..times {
            self.run(&["init"]).ok();
        }
    }

    fn audit_lines(&self) -> Vec<String> {
        std::fs::read_to_string(self.root.join("audit.jsonl"))
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect()
    }

    fn write_audit_lines(&self, lines: &[String]) {
        std::fs::write(self.root.join("audit.jsonl"), lines.join("\n") + "\n").unwrap();
    }
}

struct Run(Output);

impl Run {
    fn code(&self) -> i32 {
        self.0.status.code().unwrap()
    }

    fn stdout(&self) -> String {
        String::from_utf8_lossy(&self.0.stdout).into_owned()
    }

    fn stderr(&self) -> String {
        String::from_utf8_lossy(&self.0.stderr).into_owned()
    }

    fn ok(&self) -> &Self {
        assert_eq!(
            self.code(),
            0,
            "stdout: {}\nstderr: {}",
            self.stdout(),
            self.stderr()
        );
        self
    }
}

fn mode(path: &Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

#[test]
fn version_prints_name_and_version() {
    let home = Home::new();
    let expected = format!("enclos {}\n", env!("CARGO_PKG_VERSION"));
    for flag in ["--version", "-V"] {
        assert_eq!(home.run(&[flag]).ok().stdout(), expected);
    }
}

#[test]
fn usage_errors_exit_1() {
    let home = Home::new();
    assert_eq!(home.run(&["frobnicate"]).code(), 1);
    assert_eq!(home.run(&[]).code(), 1);
    let bad_since = home.run(&["audit", "--since", "soon"]);
    assert_eq!(bad_since.code(), 1);
    assert!(bad_since.stderr().contains("such as `30m` or `7d`"));
}

#[test]
fn init_creates_the_layout_and_is_idempotent() {
    let home = Home::new();
    let out = home.run(&["init"]);
    out.ok();
    assert!(out.stdout().contains("created"));
    for dir in ["", "runtimes", "templates", "run", "sandboxes"] {
        let path = home.root.join(dir);
        assert!(path.is_dir(), "{}", path.display());
        assert_eq!(mode(&path), 0o700, "{}", path.display());
    }
    for file in ["config.toml", "state.db", "audit.jsonl"] {
        let path = home.root.join(file);
        assert!(path.is_file(), "{}", path.display());
        assert_eq!(mode(&path), 0o600, "{}", path.display());
    }
    let config = std::fs::read_to_string(home.root.join("config.toml")).unwrap();
    assert!(config.contains("schema_version = 1"));

    let again = home.run(&["init"]);
    again.ok();
    assert!(
        again.stdout().contains("Already initialized"),
        "{}",
        again.stdout()
    );
    let after = std::fs::read_to_string(home.root.join("config.toml")).unwrap();
    assert_eq!(config, after);
}

#[test]
fn dry_run_changes_nothing() {
    let home = Home::new();
    let out = home.run(&["init", "--dry-run"]);
    out.ok();
    assert!(out.stdout().contains("Would create"));
    assert!(!home.root.exists());
}

#[test]
fn init_leaves_a_finished_audit_entry() {
    let home = Home::new();
    home.init(1);
    let lines = home.audit_lines();
    assert_eq!(lines.len(), 2);
    assert!(lines[0].contains("\"kind\":\"begin\"") && lines[0].contains("\"command\":\"init\""));
    assert!(lines[1].contains("\"kind\":\"finish\"") && lines[1].contains("\"result\":\"ok\""));
    assert!(lines.iter().all(|l| l.contains("\"schema_version\":1")));

    let listed = home.run(&["audit"]);
    listed.ok();
    assert!(listed.stdout().contains("init"));
    assert!(listed.stdout().contains("ok: created 8 paths"));
    assert!(
        home.run(&["audit", "--since", "1h"])
            .ok()
            .stdout()
            .contains("init")
    );
}

#[test]
fn a_state_changing_command_waits_for_the_state_lock() {
    let home = Home::new();
    home.init(1);
    let lock = File::options()
        .write(true)
        .open(home.root.join("state.lock"))
        .unwrap();
    lock.lock().unwrap();

    let mut child = home
        .command(&["init"])
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    std::thread::sleep(Duration::from_millis(500));
    assert!(
        child.try_wait().unwrap().is_none(),
        "init ran without the lock"
    );
    assert_eq!(home.audit_lines().len(), 2);

    drop(lock);
    assert!(child.wait().unwrap().success());
    assert_eq!(home.audit_lines().len(), 4);
}

#[test]
fn verify_passes_on_a_clean_log() {
    let home = Home::new();
    home.init(3);
    let out = home.run(&["audit", "verify"]);
    out.ok();
    assert!(
        out.stdout()
            .contains("Audit log intact: 6 lines, 3 entries")
    );
}

fn assert_verify_fails(home: &Home, line: u64, problem: &str) {
    let out = home.run(&["audit", "verify"]);
    assert_eq!(out.code(), 1, "stdout: {}", out.stdout());
    let expected = format!("line {line} {problem}");
    assert!(out.stderr().contains(&expected), "{}", out.stderr());
}

#[test]
fn verify_fails_on_an_edited_line() {
    let home = Home::new();
    home.init(3);
    let mut lines = home.audit_lines();
    lines[2] = lines[2].replace("\"command\":\"init\"", "\"command\":\"oops\"");
    home.write_audit_lines(&lines);
    assert_verify_fails(&home, 3, "was changed after it was written");
}

#[test]
fn a_damaged_log_refuses_writes_until_it_is_set_aside() {
    let home = Home::new();
    home.init(3);
    let mut lines = home.audit_lines();
    lines[2] = lines[2].replace("\"command\":\"init\"", "\"command\":\"oops\"");
    home.write_audit_lines(&lines);

    let out = home.run(&["init"]);
    assert_eq!(out.code(), 1, "stdout: {}", out.stdout());
    assert!(
        out.stderr()
            .contains("line 3 was changed after it was written"),
        "{}",
        out.stderr()
    );
    assert!(
        out.stderr().contains("audit.jsonl.damaged"),
        "{}",
        out.stderr()
    );
    assert_eq!(home.audit_lines(), lines);

    let verify = home.run(&["audit", "verify"]);
    assert_eq!(verify.code(), 1);
    assert!(
        verify.stderr().contains("audit.jsonl.damaged"),
        "{}",
        verify.stderr()
    );

    // The repair the messages give: keep the file under another name, and
    // the next command starts a new chain.
    let log = home.root.join("audit.jsonl");
    std::fs::rename(&log, home.root.join("audit.jsonl.damaged")).unwrap();
    home.init(1);
    assert_eq!(home.audit_lines().len(), 2);
    home.run(&["audit", "verify"]).ok();
}

#[test]
fn verify_fails_on_a_deleted_middle_line() {
    let home = Home::new();
    home.init(3);
    let mut lines = home.audit_lines();
    lines.remove(2);
    home.write_audit_lines(&lines);
    assert_verify_fails(&home, 3, "does not follow the line before it");
}

#[test]
fn verify_fails_on_reordered_lines() {
    let home = Home::new();
    home.init(3);
    let mut lines = home.audit_lines();
    lines.swap(1, 2);
    home.write_audit_lines(&lines);
    assert_verify_fails(&home, 2, "does not follow the line before it");
}

#[test]
fn verify_reports_an_unfinished_entry() {
    let home = Home::new();
    home.init(2);
    // Dropping the last line leaves the second init open, as a crash would.
    let mut lines = home.audit_lines();
    lines.pop();
    home.write_audit_lines(&lines);
    let out = home.run(&["audit", "verify"]);
    out.ok();
    assert!(
        out.stdout().contains("1 entry never finished"),
        "{}",
        out.stdout()
    );
    assert!(out.stdout().contains("line 3"));
    assert!(home.run(&["audit"]).ok().stdout().contains("unfinished"));
}

#[test]
fn a_crash_mid_write_is_recovered_by_the_next_command() {
    let home = Home::new();
    home.init(1);
    // A line cut short, as when enclos stops while writing it.
    let audit = home.root.join("audit.jsonl");
    let mut content = std::fs::read(&audit).unwrap();
    content.extend_from_slice(b"{\"schema_version\":1,\"seq\":3");
    std::fs::write(&audit, content).unwrap();

    let out = home.run(&["audit", "verify"]);
    out.ok();
    assert!(
        out.stdout().contains("the last line is incomplete"),
        "{}",
        out.stdout()
    );

    home.run(&["init"]).ok();
    let out = home.run(&["audit", "verify"]);
    out.ok();
    assert!(
        out.stdout().contains("was moved to audit.jsonl.torn-3"),
        "{}",
        out.stdout()
    );
    assert!(home.root.join("audit.jsonl.torn-3").exists());
}

#[test]
fn commands_before_init_say_to_run_init() {
    let home = Home::new();
    for args in [&["audit"][..], &["audit", "verify"]] {
        let out = home.run(args);
        assert_eq!(out.code(), 1);
        assert!(
            out.stderr().contains("Run `enclos init` first"),
            "{}",
            out.stderr()
        );
    }
    assert!(!home.root.exists());
}

#[test]
fn a_relative_enclos_home_is_refused() {
    let out = Command::new(env!("CARGO_BIN_EXE_enclos"))
        .args(["--text", "init"])
        .env("ENCLOS_HOME", "relative/enclos")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("must be an absolute path"));
}

#[test]
fn policy_commands_name_an_unknown_sandbox() {
    let home = Home::new();
    home.init(1);
    for args in [
        &["policy", "show", "home"][..],
        &["policy", "allow", "home", "api.example.com"],
    ] {
        let out = home.run(args);
        assert_eq!(out.code(), 1);
        assert!(
            out.stderr().contains("no sandbox named `home`"),
            "{}",
            out.stderr()
        );
    }
}

#[test]
fn policy_allow_refuses_an_unsafe_destination_before_anything_else() {
    let home = Home::new();
    home.init(1);
    // Refused by policy (design §10): exit 2, naming why.
    for (destination, says) in [
        ("*", "every destination"),
        ("*.com", "public suffix"),
        ("127.0.0.1", "never reachable"),
        ("localhost", "never reachable"),
    ] {
        let out = home.run(&["policy", "allow", "lab", destination]);
        assert_eq!(out.code(), 2, "{destination}: {}", out.stderr());
        assert!(
            out.stderr().contains(says),
            "{destination}: {}",
            out.stderr()
        );
    }
}

#[test]
fn policy_allow_of_a_destination_that_does_not_parse_is_an_error() {
    let home = Home::new();
    home.init(1);
    for destination in ["exa mple.com", "example.com:0", "a*.example.com", "*.-bad"] {
        let out = home.run(&["policy", "allow", "lab", destination]);
        assert_eq!(out.code(), 1, "{destination}: {}", out.stderr());
        assert!(
            out.stderr().contains(destination),
            "{destination}: {}",
            out.stderr()
        );
    }
}

/// An `EDITOR` that runs `script` on the file it is given, as `$1`.
#[cfg(target_os = "macos")]
fn editor(home: &Home, script: &str) -> String {
    let path = home._dir.path().join("editor.sh");
    std::fs::write(&path, format!("#!/bin/sh\nset -e\n{script}\n")).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    path.display().to_string()
}

/// A keychain file of the test's own, unlocked. `create-keychain` adds it
/// to the user's search list; `delete-keychain`, when dropped, takes it out
/// again.
#[cfg(target_os = "macos")]
struct TestKeychain(PathBuf);

#[cfg(target_os = "macos")]
impl TestKeychain {
    fn new(home: &Home) -> TestKeychain {
        let file = home._dir.path().join("test.keychain-db");
        let path = file.to_str().unwrap();
        for args in [
            &["create-keychain", "-p", "test", path][..],
            &["unlock-keychain", "-p", "test", path],
        ] {
            assert!(
                Command::new("/usr/bin/security")
                    .args(args)
                    .status()
                    .unwrap()
                    .success()
            );
        }
        TestKeychain(file)
    }
}

#[cfg(target_os = "macos")]
impl Drop for TestKeychain {
    fn drop(&mut self) {
        let _ = Command::new("/usr/bin/security")
            .arg("delete-keychain")
            .arg(&self.0)
            .status();
    }
}

#[cfg(target_os = "macos")]
#[test]
fn a_secret_set_from_the_input_reaches_the_sessions_its_policy_grants_it_to() {
    use std::io::Write;
    let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
    let home = Home::new();
    let keychain = TestKeychain::new(&home);
    let run = |args: &[&str], input: Option<&[u8]>| {
        let mut cmd = home.command(args);
        cmd.env("ENCLOS_KEYCHAIN", &keychain.0)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = cmd.spawn().unwrap();
        let mut stdin = child.stdin.take().unwrap();
        if let Some(input) = input {
            stdin.write_all(input).unwrap();
        }
        drop(stdin);
        Run(child.wait_with_output().unwrap())
    };
    home.init(1);
    home.run(&["sandbox", "create", "home"]).ok();
    let _stop = StopOnDrop(&home, "home");

    let out = run(&["secret", "set", "home/telegram"], Some(b"tok-123:abc\n"));
    assert!(
        out.ok().stdout().contains("Stored secret home/telegram"),
        "{}",
        out.stdout()
    );
    let out = run(&["secret", "list", "home"], None);
    assert!(out.ok().stdout().contains("telegram"), "{}", out.stdout());
    assert!(!out.stdout().contains("tok-123"), "{}", out.stdout());

    let mut edit = home.command(&["policy", "edit", "home"]);
    edit.env("ENCLOS_KEYCHAIN", &keychain.0)
        .env_remove("VISUAL")
        .env(
            "EDITOR",
            editor(
                &home,
                r#"printf '\n[secrets]\nenv = { TOKEN = "secret:home/telegram" }\n' >> "$1""#,
            ),
        );
    Run(edit.output().unwrap()).ok();
    let out = run(
        &["exec", "home", "--", "/bin/sh", "-c", "echo \"$TOKEN\""],
        None,
    );
    assert_eq!(out.ok().stdout(), "tok-123:abc\n");

    // Granted, it cannot go; neither the audit log nor the files hold it.
    let out = run(&["--yes", "secret", "rm", "home/telegram"], None);
    assert_eq!(out.code(), 1, "{}", out.stderr());
    assert!(
        out.stderr().contains("granted as $TOKEN"),
        "{}",
        out.stderr()
    );
    for file in ["audit.jsonl", "sandboxes/home/policy.toml"] {
        let text = std::fs::read_to_string(home.root.join(file)).unwrap();
        assert!(!text.contains("tok-123"), "{file}");
    }

    // Taken out of the policy, it goes, after asking.
    let mut edit = home.command(&["policy", "edit", "home"]);
    edit.env("ENCLOS_KEYCHAIN", &keychain.0)
        .env_remove("VISUAL")
        .env(
            "EDITOR",
            editor(&home, r#"sed -i '' '/secrets/d; /TOKEN/d' "$1""#),
        );
    Run(edit.output().unwrap()).ok();
    let out = run(&["secret", "rm", "home/telegram"], None);
    assert_eq!(out.code(), 3, "{}", out.stderr());
    let out = run(&["--yes", "secret", "rm", "home/telegram"], None);
    assert!(
        out.ok().stdout().contains("Removed secret home/telegram"),
        "{}",
        out.stdout()
    );
    let out = run(&["secret", "list", "home"], None);
    assert!(
        out.ok().stdout().contains("has no secrets"),
        "{}",
        out.stdout()
    );

    // A value of several lines, piped in, comes whole; nothing is not one.
    let pem = "-----BEGIN KEY-----\nabc\n-----END KEY-----\n";
    run(&["secret", "set", "home/pem"], Some(pem.as_bytes())).ok();
    let mut edit = home.command(&["policy", "edit", "home"]);
    edit.env("ENCLOS_KEYCHAIN", &keychain.0)
        .env_remove("VISUAL")
        .env(
            "EDITOR",
            editor(
                &home,
                r#"printf '\n[secrets]\nenv = { PEM = "secret:home/pem" }\n' >> "$1""#,
            ),
        );
    Run(edit.output().unwrap()).ok();
    let out = run(
        &[
            "exec",
            "home",
            "--",
            "/bin/sh",
            "-c",
            "printf '%s' \"$PEM\"",
        ],
        None,
    );
    assert_eq!(out.ok().stdout(), pem.trim_end_matches('\n'));
    let out = run(&["secret", "set", "home/empty"], Some(b""));
    assert_eq!(out.code(), 1, "{}", out.stderr());
    assert!(
        out.stderr().contains("the value is empty"),
        "{}",
        out.stderr()
    );
    let out = run(&["secret", "list", "home"], None);
    assert!(!out.ok().stdout().contains("empty"), "{}", out.stdout());
}

/// With no keychain to write to, a secret is refused before anything is
/// written, rather than waiting on a dialog nobody sees.
#[cfg(target_os = "macos")]
#[test]
fn a_secret_with_no_keychain_to_hold_it_is_refused() {
    use std::io::Write;
    let home = Home::new();
    home.init(1);
    home.run(&["sandbox", "create", "home"]).ok();
    let missing = home._dir.path().join("none.keychain-db");
    let mut cmd = home.command(&["secret", "set", "home/telegram"]);
    cmd.env("ENCLOS_KEYCHAIN", &missing)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().unwrap();
    child.stdin.take().unwrap().write_all(b"tok\n").unwrap();
    let out = Run(child.wait_with_output().unwrap());
    assert_eq!(out.code(), 1, "{}", out.stderr());
    assert!(out.stderr().contains("does not exist"), "{}", out.stderr());
    let out = home.run(&["secret", "list", "home"]);
    assert!(
        out.ok().stdout().contains("has no secrets"),
        "{}",
        out.stdout()
    );
}

#[cfg(target_os = "macos")]
#[test]
fn exec_runs_one_command_with_its_input_and_exits_with_its_code() {
    use std::io::Write;
    let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
    let home = Home::new();
    home.init(1);
    home.run(&["sandbox", "create", "home"]).ok();
    let _stop = StopOnDrop(&home, "home");

    let out = home.run(&["exec", "home", "--", "/bin/sh", "-c", "echo out; exit 7"]);
    assert_eq!(out.code(), 7, "stderr: {}", out.stderr());
    assert_eq!(out.stdout(), "out\n");
    // Its input is the caller's: a script can pipe into it.
    let mut child = home
        .command(&["exec", "home", "--", "/bin/cat"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"piped in\n")
        .unwrap();
    let out = Run(child.wait_with_output().unwrap());
    assert_eq!(out.ok().stdout(), "piped in\n");

    // A command a signal ended exits as a shell says it: 128 plus the signal.
    let out = home.run(&[
        "exec",
        "home",
        "--",
        "/bin/sh",
        "-c",
        "echo a; kill -TERM $$",
    ]);
    assert_eq!(out.code(), 143, "{}", out.stderr());
    assert_eq!(out.stdout(), "a\n");
    assert!(
        out.stderr().contains("ended by signal 15"),
        "{}",
        out.stderr()
    );

    // A TERM sent to enclos reaches the command, in a group of its own
    // without a terminal, and enclos records its end.
    let child = home
        .command(&["exec", "home", "--", "/bin/sleep", "30"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let pid = child.id().to_string();
    assert!(eventually(|| {
        home.run(&["sandbox", "show", "home"])
            .stdout()
            .contains("/bin/sleep")
    }));
    let show = home.run(&["sandbox", "show", "home"]).ok().stdout();
    assert!(show.contains(" exec: "), "{show}");
    Command::new("/bin/kill")
        .args(["-TERM", &pid])
        .status()
        .unwrap();
    let out = Run(child.wait_with_output().unwrap());
    assert_eq!(out.code(), 143, "{}", out.stderr());
    assert!(
        !home
            .run(&["sandbox", "show", "home"])
            .ok()
            .stdout()
            .contains("/bin/sleep")
    );

    // Each is a session of its own, audited as `exec`; a dry run and a
    // usage error record nothing.
    let lines = home.audit_lines().len();
    let out = home.run(&["exec", "home"]);
    assert_eq!(out.code(), 125, "{}", out.stderr());
    let out = home.run(&["exec", "Bad_Name", "--", "/bin/ls"]);
    assert_eq!(out.code(), 125, "{}", out.stderr());
    assert_eq!(home.run(&["exec", "--help"]).code(), 0);
    let out = home.run(&["--dry-run", "exec", "home", "--", "/bin/ls"]);
    assert!(
        out.ok().stdout().contains("Would run `/bin/ls`"),
        "{}",
        out.stdout()
    );
    assert_eq!(home.audit_lines().len(), lines);
    let audit = home.run(&["audit"]).ok().stdout();
    assert_eq!(audit.matches("exec home").count(), 4, "{audit}");

    // When enclos itself fails, it exits 125, which tells its failure apart
    // from the command's own 1, 2 or 3.
    let out = home.run(&["exec", "nope", "--", "/bin/ls"]);
    assert_eq!(out.code(), 125, "{}", out.stderr());
    assert!(
        out.stderr().contains("no sandbox named `nope`"),
        "{}",
        out.stderr()
    );
}

#[cfg(target_os = "macos")]
#[test]
fn policy_history_diff_rollback_and_refresh() {
    let home = Home::new();
    home.init(1);
    home.run(&["sandbox", "create", "home"]).ok();
    home.run(&["policy", "allow", "home", "a.example.com"]).ok();
    home.run(&["policy", "allow", "home", "b.example.com"]).ok();

    let history = home.run(&["policy", "history", "home"]).ok().stdout();
    let row = |v: &str| {
        history
            .lines()
            .find(|l| l.trim_start().starts_with(v))
            .unwrap_or_default()
            .to_owned()
    };
    assert!(
        !row("v1").is_empty() && !row("v2").contains("in force"),
        "{history}"
    );
    assert!(row("v3").ends_with("in force"), "{history}");
    let diff = home.run(&["policy", "diff", "home"]).ok().stdout();
    assert!(diff.contains("what v3 changes from v2"), "{diff}");
    assert!(diff.contains("allow b.example.com"), "{diff}");
    let diff = home
        .run(&["policy", "diff", "home", "--from", "1", "--to", "1"])
        .ok()
        .stdout();
    assert!(diff.contains("grants the same"), "{diff}");
    let (_, history) = home.json(&["policy", "history", "home"]);
    assert_eq!(history["active"], 3, "{history}");
    let versions: Vec<_> = history["versions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v["version"].clone())
        .collect();
    assert_eq!(versions, [1, 2, 3], "{history}");
    assert!(
        history["versions"][0]["by"]["user"].is_string(),
        "{history}"
    );
    let (_, diff) = home.json(&["policy", "diff", "home"]);
    assert!(
        diff["changes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c.as_str().is_some_and(|c| c.contains("b.example.com"))),
        "{diff}"
    );
    let (code, allowed) = home.json(&["policy", "allow", "home", "c.example.com", "--dry-run"]);
    assert_eq!(code, 0, "{allowed}");
    assert_eq!(allowed["dry_run"], true, "{allowed}");

    let out = home
        .run(&["policy", "rollback", "home", "--to", "1"])
        .ok()
        .stdout();
    assert!(out.contains("policy v4, from v1"), "{out}");
    assert!(out.contains("stop allowing a.example.com"), "{out}");
    let history = home.run(&["policy", "history", "home"]).ok().stdout();
    assert!(history.contains("in force; restores v1"), "{history}");
    let (_, history) = home.json(&["policy", "history", "home"]);
    assert_eq!(history["active"], 4, "{history}");
    assert_eq!(history["versions"][3]["restores"], 1, "{history}");
    let shown = home.run(&["policy", "show", "home"]).ok().stdout();
    assert!(shown.contains("allowed: nothing listed"), "{shown}");

    let out = home.run(&["policy", "refresh", "home"]).ok().stdout();
    assert!(out.contains("nothing changed"), "{out}");
    let out = home.run(&["policy", "rollback", "home", "--to", "9"]);
    assert_eq!(out.code(), 1);
    assert!(out.stderr().contains("no policy v9"), "{}", out.stderr());

    // An edit of policy.toml by hand stops a rollback, and `policy edit`
    // closed as it is applies it, as the refusal says.
    let file = home.root.join("sandboxes/home/policy.toml");
    let text = std::fs::read_to_string(&file).unwrap();
    std::fs::write(
        &file,
        text.replace("allow_add = []", "allow_add = [\"d.example.com\"]"),
    )
    .unwrap();
    let out = home.run(&["policy", "rollback", "home", "--to", "2"]);
    assert_eq!(out.code(), 1);
    assert!(
        out.stderr().contains("holds an edit not applied"),
        "{}",
        out.stderr()
    );
    let mut edit = home.command(&["policy", "edit", "home"]);
    edit.env_remove("VISUAL")
        .env("EDITOR", editor(&home, "true"));
    let out = Run(edit.output().unwrap());
    assert!(out.ok().stdout().contains("policy v5"), "{}", out.stdout());
    home.run(&["policy", "rollback", "home", "--to", "2"]).ok();
}

#[cfg(target_os = "macos")]
#[test]
fn policy_edit_applies_the_file_and_keeps_an_edit_it_refuses() {
    let home = Home::new();
    home.init(1);
    home.run(&["sandbox", "create", "home"]).ok();
    let edit = |script: &str| {
        let mut cmd = home.command(&["policy", "edit", "home"]);
        cmd.env_remove("VISUAL")
            .env("EDITOR", editor(&home, script));
        Run(cmd.output().unwrap())
    };

    let out = edit(r#"sed -i '' 's/allow_add = \[\]/allow_add = ["api.example.com"]/' "$1""#);
    out.ok();
    assert!(out.stdout().contains("policy v2"), "{}", out.stdout());
    assert!(
        out.stdout().contains("allow api.example.com"),
        "{}",
        out.stdout()
    );
    let shown = home.run(&["policy", "show", "home"]).ok().stdout();
    assert!(shown.contains("allowed: api.example.com"), "{shown}");
    assert!(shown.contains("enclos policy edit home"), "{shown}");

    // Refused by policy: nothing applies, and the edit is kept for the next
    // `policy edit`, which opens it again.
    let out = edit(r#"sed -i '' 's/write_add = \[\]/write_add = ["~"]/' "$1""#);
    assert_eq!(out.code(), 2, "{}", out.stderr());
    let kept = home.root.join("sandboxes/home/policy.toml.edit");
    assert!(
        out.stderr().contains(&kept.display().to_string()),
        "{}",
        out.stderr()
    );
    let out = edit("true");
    assert_eq!(out.code(), 2, "{}", out.stderr());
    assert!(
        out.stdout().contains("Continuing the edit kept"),
        "{}",
        out.stdout()
    );
    std::fs::remove_file(&kept).unwrap();
    assert!(edit("true").ok().stdout().contains("No change"));

    // A kept edit is never applied over a change made since it began: it
    // would undo that change.
    let out = edit(r#"sed -i '' 's/write_add = \[\]/write_add = ["~"]/' "$1""#);
    assert_eq!(out.code(), 2, "{}", out.stderr());
    home.run(&["policy", "allow", "home", "b.example.com"]).ok();
    let out = edit("true");
    assert_eq!(out.code(), 1, "{}", out.stderr());
    assert!(
        out.stderr().contains("changed since your edit"),
        "{}",
        out.stderr()
    );
    let file = home.root.join("sandboxes/home/policy.toml");
    assert!(
        std::fs::read_to_string(&file)
            .unwrap()
            .contains("b.example.com")
    );
    home.run(&["policy", "discard", "home"]).ok();
    assert!(!kept.exists());

    // An editor that fails applies nothing and keeps the edit.
    let out = edit(r#"sed -i '' 's/allow_add = \[/allow_add = ["c.example.com", /' "$1"; exit 1"#);
    assert_eq!(out.code(), 1, "{}", out.stderr());
    assert!(
        out.stderr().contains("did not exit cleanly"),
        "{}",
        out.stderr()
    );
    assert!(
        !std::fs::read_to_string(&file)
            .unwrap()
            .contains("c.example.com")
    );
    assert!(kept.exists());

    // Kept, then refused once the file changed; copied over its base, as
    // the error says, it opens again and applies.
    home.run(&["policy", "allow", "home", "d.example.com"]).ok();
    let out = edit("true");
    assert_eq!(out.code(), 1, "{}", out.stderr());
    assert!(
        out.stderr().contains("copy policy.toml over"),
        "{}",
        out.stderr()
    );
    std::fs::copy(
        &file,
        home.root.join("sandboxes/home/policy.toml.edit.base"),
    )
    .unwrap();
    let out = edit("true");
    assert!(
        out.ok().stdout().contains("Continuing the edit kept"),
        "{}",
        out.stdout()
    );
    assert!(
        std::fs::read_to_string(&file)
            .unwrap()
            .contains("c.example.com")
    );
    assert!(!kept.exists());

    let out = home.run(&["policy", "discard", "home"]);
    assert!(
        out.ok().stdout().contains("nothing pending"),
        "{}",
        out.stdout()
    );
    let out = home.run(&["policy", "apply", "home"]);
    assert_eq!(out.code(), 1);
    assert!(
        out.stderr().contains("no pending policy"),
        "{}",
        out.stderr()
    );
    let out = home.run(&["policy", "show", "home", "--pending"]);
    assert_eq!(out.code(), 1);
}

#[cfg(not(target_os = "macos"))]
#[test]
fn a_seatbelt_sandbox_is_refused_off_macos() {
    let home = Home::new();
    home.init(1);
    let out = home.run(&["sandbox", "create", "home"]);
    assert_eq!(out.code(), 2, "{}", out.stderr());
    assert!(out.stderr().contains("cannot run"), "{}", out.stderr());
    assert!(
        home.run(&["sandbox", "list"])
            .ok()
            .stdout()
            .contains("No sandboxes yet")
    );
}

/// Where each column of a table line starts: after two spaces or more.
#[cfg(target_os = "macos")]
fn column_starts(line: &str) -> Vec<usize> {
    let bytes = line.as_bytes();
    (0..bytes.len())
        .filter(|&i| bytes[i] != b' ' && (i == 0 || bytes[..i].ends_with(b"  ")))
        .collect()
}

#[cfg(target_os = "macos")]
#[test]
fn sandbox_list_lines_up_its_columns_for_names_of_any_length() {
    let home = Home::new();
    home.init(1);
    home.run(&["sandbox", "create", "ab"]).ok();
    let long = "a-name-longer-than-twenty-letters";
    home.run(&["sandbox", "create", long]).ok();
    let out = home.run(&["sandbox", "list"]);
    let text = out.ok().stdout();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 3, "{text}");
    let header = column_starts(lines[0]);
    assert_eq!(header.len(), 5, "{text}");
    for line in &lines[1..] {
        assert_eq!(column_starts(line), header, "{text}");
    }
}

#[cfg(target_os = "macos")]
#[path = "../src/host_ports.rs"]
mod host_ports;

/// Tests that start proxies take turns: proxy ports are the host's, shared
/// by every test's enclos folder and every other test run of this user.
#[cfg(target_os = "macos")]
static HOST_PORTS: host_ports::HostPorts = host_ports::HostPorts;

/// Stops the sandbox when the test ends, passed or not, so the proxy it
/// started never outlives the test.
#[cfg(target_os = "macos")]
struct StopOnDrop<'a>(&'a Home, &'a str);

#[cfg(target_os = "macos")]
impl Drop for StopOnDrop<'_> {
    fn drop(&mut self) {
        let _ = self.0.run(&["sandbox", "stop", self.1]);
    }
}

#[cfg(target_os = "macos")]
#[test]
fn a_sandbox_runs_a_command_under_seatbelt_and_its_proxy_and_stops() {
    let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
    let home = Home::new();
    home.init(1);
    let out = home.run(&["sandbox", "create", "home"]);
    out.ok();
    assert!(
        out.stdout().contains("Created sandbox home"),
        "{}",
        out.stdout()
    );
    let _stop = StopOnDrop(&home, "home");

    // The assistant template reaches the public web, and says so (ADR 0025).
    let show = home.run(&["policy", "show", "home"]);
    assert!(
        show.ok().stdout().contains("Network: public web"),
        "{}",
        show.stdout()
    );

    // The command's exit code comes back; it wrote only in its home.
    let script = "echo hi > \"$HOME/hello\"; echo no > \"$HOME/../escaped\" 2>/dev/null; exit 3";
    let out = home.run(&["connect", "home", "--", "/bin/sh", "-c", script]);
    assert_eq!(out.code(), 3, "stderr: {}", out.stderr());
    let sandbox = home.root.join("sandboxes/home");
    assert!(sandbox.join("home/hello").exists());
    assert!(!sandbox.join("escaped").exists());

    // Through the proxy, a destination the policy does not open is refused
    // and logged: the public web is ports 80 and 443 only.
    let curl = "/usr/bin/curl -s -o /dev/null -w '%{http_code}' https://example.com:8443/ || true";
    home.run(&["connect", "home", "--", "/bin/sh", "-c", curl])
        .ok();
    let denied = home.run(&["net", "denied", "home"]);
    assert!(
        denied
            .ok()
            .stdout()
            .contains("example.com:8443  not-allowed"),
        "{}",
        denied.stdout()
    );
    let (code, denied) = home.json(&["net", "denied", "home"]);
    assert_eq!(code, 0, "{denied}");
    let one = denied["denied"]
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["host"] == "example.com" && d["port"] == 8443)
        .unwrap_or_else(|| panic!("{denied}"))
        .clone();
    assert_eq!(one["reason"], "not-allowed", "{one}");
    assert!(one["count"].as_u64().is_some_and(|c| c >= 1), "{one}");
    for at in ["first", "last"] {
        assert!(one[at].as_str().is_some_and(|s| s.contains('T')), "{one}");
    }
    let (code, logged) = home.json(&["net", "log", "home"]);
    assert_eq!(code, 0, "{logged}");
    assert!(
        logged["connections"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["host"] == "example.com" && c["verdict"] == "denied"),
        "{logged}"
    );

    // The proxy runs as its own session until the sandbox stops.
    let show = home.run(&["sandbox", "show", "home"]);
    assert!(show.ok().stdout().contains("proxy"), "{}", show.stdout());
    let stop = home.run(&["sandbox", "stop", "home"]);
    assert!(
        stop.ok().stdout().contains("Stopped sandbox home"),
        "{}",
        stop.stdout()
    );
    assert!(
        home.run(&["sandbox", "show", "home"])
            .ok()
            .stdout()
            .contains("no sessions running")
    );

    // Removing deletes the home, after confirmation.
    assert_eq!(home.run(&["sandbox", "rm", "home"]).code(), 3);
    home.run(&["sandbox", "rm", "home", "--yes"]).ok();
    assert!(!sandbox.exists());
}

#[cfg(target_os = "macos")]
#[test]
fn every_escape_probe_fails_in_a_new_sandbox() {
    let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
    let home = Home::new();
    home.init(1);
    home.run(&["sandbox", "create", "home"]).ok();
    home.run(&["sandbox", "create", "lab"]).ok();
    let _stop = StopOnDrop(&home, "home");
    // Fake sensitive files at default deny-list paths in this test's own
    // HOME, so that the default deny list is probed wherever this runs, and
    // a workspace grant holding deny-list entries of its own.
    let user = home._dir.path();
    for (path, contents) in [
        (".ssh/id_ed25519", "not a key"),
        (".aws/credentials", "not a credential"),
        (".netrc", "machine example.com"),
        (".zsh_history", "echo hi"),
        ("Library/LaunchAgents/org.example.fake.plist", "not a plist"),
        ("work/.secrets/token", "not a token"),
        ("work/.env", "TOKEN=x"),
        (".cargo/credentials.toml", "secret"),
        (".zhistory", "secret"),
        (
            "Library/Application Support/Google/Chrome Beta/Default/Cookies",
            "secret",
        ),
        (".password-store/bank.gpg", "secret"),
        (".gemini/oauth_creds.json", "secret"),
        (
            "Library/Group Containers/group.com.apple.notes/NoteStore.sqlite",
            "secret",
        ),
    ] {
        let file = user.join(path);
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(file, contents).unwrap();
    }
    let policy_file = home.root.join("sandboxes/home/policy.toml");
    let original = std::fs::read_to_string(&policy_file).unwrap();
    let policy = original.replace(
        "write_add = []\nread_deny_add = []",
        "write_add = [\"~/work\"]\nread_deny_add = [\"~/work/.secrets\", \"~/work/.env\"]",
    );
    assert_ne!(policy, original, "the grant was not added:\n{original}");
    std::fs::write(&policy_file, policy).unwrap();
    // `policy allow` applies the file's other changes with `--yes`.
    home.run(&["policy", "allow", "home", "example.com", "--yes"])
        .ok();
    let policy = std::fs::read_to_string(&policy_file).unwrap();
    // The host-service probes act on the host if a rule fails: only where
    // CI asks for them by name, never because some tool set `CI`.
    let host_services = host_service_probes_asked();
    // CI runs them: a workflow that lost the variable must not pass quietly.
    if std::env::var("GITHUB_ACTIONS").as_deref() == Ok("true") {
        assert!(
            host_services,
            "CI runs the host-service probes: ENCLOS_HOST_SERVICE_PROBES=1 is missing"
        );
    }
    let mut args = vec!["policy", "test", "home"];
    if host_services {
        args.push("--host-services");
    }
    // A keychain of the test's own, holding a secret of the sandbox, so the
    // keychain item probe runs, and is seen not to touch that secret.
    let keychain = TestKeychain::new(&home);
    let mut set = home.command(&["secret", "set", "home/keep"]);
    set.env("ENCLOS_KEYCHAIN", &keychain.0)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = set.spawn().unwrap();
    {
        use std::io::Write;
        child.stdin.take().unwrap().write_all(b"kept\n").unwrap();
    }
    Run(child.wait_with_output().unwrap()).ok();
    let out = Run(home
        .command(&args)
        .env("ENCLOS_KEYCHAIN", &keychain.0)
        .env_remove("ENCLOS_SEATBELT_BASELINE")
        .output()
        .unwrap());
    // Under the baseline enclos ships (ADR 0006).
    assert!(
        std::fs::read_dir(home.root.join("sandboxes/home/compiled"))
            .unwrap()
            .any(|e| std::fs::read_to_string(e.unwrap().path())
                .unwrap()
                .contains("\n(deny default (with message \"enclos:home\"))\n")),
        "no deny-by-default policy was compiled"
    );
    assert_eq!(
        out.code(),
        0,
        "stdout: {}\nstderr: {}",
        out.stdout(),
        out.stderr()
    );
    let report = out.stdout();
    assert!(!report.contains("OPEN"), "{report}");
    assert!(!report.contains("NOT RUN"), "{report}");
    // Nothing says it ran on the comparison baseline.
    assert!(
        !out.stderr().contains("(allow default)"),
        "{}",
        out.stderr()
    );
    assert!(!report.contains("comparison baseline"), "{report}");
    let mut routes = vec![
        "sensitive files",
        "enclos files",
        "other sandboxes",
        "writes",
        "renames",
        "clones",
        "network",
        "dns",
        "signals",
        "terminals",
        "pasteboard",
        "at",
    ];
    if host_services {
        routes.extend([
            "launchservices",
            "apple events",
            "launchd",
            "preferences",
            "launch agents",
        ]);
    }
    let closed = |text: &str| {
        report
            .lines()
            .any(|l| l.trim_start().starts_with("closed ") && l.contains(text))
    };
    for route in routes {
        assert!(
            closed(&format!(" {route} ")),
            "no closed {route} probe:\n{report}"
        );
    }
    for path in [
        "/.ssh",
        "/.aws",
        "/.netrc",
        "/.zsh_history",
        "/Library/LaunchAgents",
        "/work/.secrets",
        "/work/.env",
    ] {
        let read = report.lines().any(|l| {
            l.trim_start().starts_with("closed ")
                && l.contains(" read ")
                && l.trim_end().ends_with(path)
        });
        assert!(read, "reading {path} is not shown closed:\n{report}");
    }
    for probe in [
        "/work/.secrets, under a write grant",
        "/work/.env, under a write grant",
        "write the sandbox's own policy.toml",
        "the sandbox's own compiled folder",
        "lab/home",
        "/state.lock",
    ] {
        assert!(closed(probe), "{probe} is not shown closed:\n{report}");
    }
    assert!(
        report
            .lines()
            .any(|l| l.trim_start().starts_with("closed ") && l.trim_end().ends_with("/run")),
        "reading run/ is not shown closed:\n{report}"
    );
    if host_services {
        let agents = "write in ~/Library/LaunchAgents";
        assert!(closed(agents), "{agents} is not shown closed:\n{report}");
    }
    assert!(closed("read a keychain item"), "{report}");
    assert!(!report.contains("keychain items ("), "{report}");
    let items = Command::new("/usr/bin/security")
        .arg("dump-keychain")
        .arg(&keychain.0)
        .output()
        .unwrap();
    let items = String::from_utf8_lossy(&items.stdout);
    assert!(
        !items.contains("home/probe"),
        "the probe's item stays:\n{items}"
    );
    assert!(
        items.contains("home/keep"),
        "the sandbox's secret went:\n{items}"
    );
    assert!(!report.contains("denied paths exists here"), "{report}");
    assert!(
        !report.contains("no ~/Library/LaunchAgents here"),
        "{report}"
    );
    // Seatbelt itself refuses setuid programs: the report says so.
    let at = report
        .lines()
        .find(|l| l.contains("list the `at` queue"))
        .unwrap();
    assert!(at.contains("Seatbelt itself refuses"), "{at}");
    // Said by who; with the host services, the baseline's two as well.
    let apart = match host_services {
        true => "(1 by Seatbelt itself, 2 by the (deny default) baseline)",
        false => "(1 by Seatbelt itself)",
    };
    assert!(report.contains(apart), "{report}");
    // Each fake file's deny entry: the folder, or the file itself.
    for entry in [
        "/.ssh",
        "/.cargo/credentials.toml",
        "/.zhistory",
        "/Library/Application Support/Google/Chrome Beta",
        "/.password-store",
        "/.gemini",
        "/Library/Group Containers/group.com.apple.notes",
    ] {
        let closed = report.lines().any(|l| {
            l.trim_start().starts_with("closed ")
                && l.contains(" sensitive files ")
                && l.ends_with(entry)
        });
        assert!(closed, "no closed probe reads {entry}:\n{report}");
    }
    assert!(
        report
            .trim_end()
            .lines()
            .last()
            .is_some_and(|l| l.starts_with("READY: no probe got out of sandbox ")),
        "{report}"
    );
    // `.env`, LaunchAgents and the sandbox's policy keep what the test put
    // there; any other file a probe left would show as OPEN above.
    assert_eq!(
        std::fs::read_to_string(user.join("work/.env")).unwrap(),
        "TOKEN=x"
    );
    assert_eq!(
        std::fs::read_dir(user.join("Library/LaunchAgents"))
            .unwrap()
            .count(),
        1
    );
    assert_eq!(std::fs::read_to_string(&policy_file).unwrap(), policy);
    let audit = home.run(&["audit"]).ok().stdout();
    assert!(
        audit.contains("policy test") && audit.contains(" 0 open,") && audit.contains(" 0 not run"),
        "{audit}"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn a_route_that_gets_through_fails_the_policy_test() {
    let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
    let home = Home::new();
    home.init(1);
    home.run(&["sandbox", "create", "home"]).ok();
    let _stop = StopOnDrop(&home, "home");
    // Allowing the destination and port a proxy probe asks for opens that
    // route: the proxy lets the request through and answers 502, as the name
    // does not resolve. Nothing leaves this host.
    home.run(&[
        "policy",
        "allow",
        "home",
        "probe.enclos.invalid:8443",
        "--yes",
    ])
    .ok();
    let out = home.run(&["policy", "test", "home"]);
    assert_eq!(out.code(), 1, "{}", out.stdout());
    let open = out
        .stdout()
        .lines()
        .any(|l| l.trim_start().starts_with("OPEN") && l.contains(" network "));
    assert!(open, "{}", out.stdout());
    assert!(
        out.stderr().starts_with("NOT READY: sandbox home: ")
            && out.stderr().contains("probes got out")
            && out.stderr().contains("Do not use it until this is fixed."),
        "{}",
        out.stderr()
    );
    assert!(!out.stdout().contains("shown closed"), "{}", out.stdout());
    // A script reading the JSON sees it too.
    let (code, tested) = home.json(&["policy", "test", "home"]);
    assert_eq!(code, 1, "{tested}");
    assert_eq!(tested["ready"], false, "{tested}");
    assert_eq!(tested["error"]["exit_code"], 1, "{tested}");
    assert_eq!(tested["error"]["kind"], "error", "{tested}");
    assert!(
        tested["verdict"]
            .as_str()
            .is_some_and(|v| v.starts_with("NOT READY")),
        "{tested}"
    );
    assert!(
        tested["probes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["outcome"] == "open"),
        "{tested}"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn policy_test_fails_when_the_sandbox_home_is_unusable() {
    let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
    let home = Home::new();
    home.init(1);
    home.run(&["sandbox", "create", "home"]).ok();
    let _stop = StopOnDrop(&home, "home");
    // A home no probe can run in.
    let sandbox_home = home.root.join("sandboxes/home/home");
    std::fs::remove_dir_all(&sandbox_home).unwrap();
    std::fs::write(&sandbox_home, "not a folder").unwrap();
    let out = home.run(&["policy", "test", "home"]);
    assert_ne!(out.code(), 0, "{}", out.stdout());
    // Refused before anything is compiled.
    assert!(
        out.stderr().contains("is not a real folder"),
        "{}",
        out.stderr()
    );
    assert!(!out.stdout().contains("shown closed"), "{}", out.stdout());
}

#[cfg(target_os = "macos")]
#[test]
fn a_policy_test_dry_run_starts_and_records_nothing() {
    let home = Home::new();
    home.init(1);
    home.run(&["sandbox", "create", "home"]).ok();
    let before = home.audit_lines().len();
    let out = home.run(&["policy", "test", "home", "--host-services", "--dry-run"]);
    let plan = out.ok().stdout();
    assert!(
        plan.contains("Would start the proxy of sandbox home"),
        "{plan}"
    );
    assert!(plan.contains("escape probes in sandbox home"), "{plan}");
    assert!(plan.contains("host-service routes included"), "{plan}");
    let plain = home
        .run(&["policy", "test", "home", "--dry-run"])
        .ok()
        .stdout();
    assert!(plain.contains("escape probes in sandbox home"), "{plain}");
    assert!(!plain.contains("host-service"), "{plain}");
    assert!(!plan.contains("closed"), "{plan}");
    assert_eq!(home.audit_lines().len(), before);
    assert!(!home.root.join("sandboxes/home/compiled").exists());
    let show = home.run(&["sandbox", "show", "home"]).ok().stdout();
    assert!(show.contains("no sessions running"), "{show}");
}

#[cfg(target_os = "macos")]
#[test]
fn a_session_stays_open_while_its_command_left_processes_running() {
    let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
    let home = Home::new();
    home.init(1);
    home.run(&["sandbox", "create", "home"]).ok();
    let _stop = StopOnDrop(&home, "home");

    // The command exits at once and leaves a short sleep in its group, with
    // its output closed so this test does not wait for it.
    let script = "/bin/sleep 3 >/dev/null 2>&1 & exit 0";
    let out = home.run(&["connect", "home", "--", "/bin/sh", "-c", script]);
    assert_eq!(out.code(), 0, "{}", out.stderr());
    assert!(
        out.stderr().contains("left 1 processes running"),
        "{}",
        out.stderr()
    );
    let show = home.run(&["sandbox", "show", "home"]).ok().stdout();
    assert!(show.contains("session 2 interactive"), "{show}");
    assert!(show.contains("sleep"), "{show}");
    // Its home cannot be removed while the process runs.
    let rm = home.run(&["sandbox", "rm", "home", "--yes"]);
    assert_ne!(rm.code(), 0, "{}", rm.stdout());

    // Once the sleep ends, stop finds the group empty and ends the session.
    assert!(eventually(|| {
        !home
            .run(&["sandbox", "show", "home"])
            .ok()
            .stdout()
            .contains("sleep")
    }));
    home.run(&["sandbox", "stop", "home"]).ok();
    let show = home.run(&["sandbox", "show", "home"]).ok().stdout();
    assert!(show.contains("no sessions running"), "{show}");
}

#[cfg(target_os = "macos")]
#[test]
fn a_session_opens_the_terminal_it_runs_in_by_name() {
    let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
    let home = Home::new();
    home.init(1);
    home.run(&["sandbox", "create", "home"]).ok();
    let _stop = StopOnDrop(&home, "home");
    // `script` runs enclos in a terminal of its own, never this test's.
    let script = r#"t=$(/usr/bin/tty) && : < "$t" && : >> "$t" && echo own-by-name"#;
    let out = Command::new("/usr/bin/script")
        .args(["-q", "/dev/null", env!("CARGO_BIN_EXE_enclos")])
        .args(["connect", "home", "--", "/bin/sh", "-c", script])
        .env("ENCLOS_HOME", &home.root)
        .env("HOME", home._dir.path())
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let out = String::from_utf8_lossy(&out.stdout);
    assert!(out.contains("own-by-name"), "{out}");
}

#[cfg(target_os = "macos")]
#[test]
fn connect_refuses_a_port_another_program_listens_on() {
    let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
    let home = Home::new();
    home.init(1);
    home.run(&["sandbox", "create", "home"]).ok();
    let _stop = StopOnDrop(&home, "home");
    let port = proxy_port(&home);
    // Another program takes the sandbox's proxy port first, on either
    // loopback: the sandbox can reach both.
    for (loopback, named) in [("127.0.0.1", "127.0.0.1"), ("::1", "[::1]")] {
        let _squatter = std::net::TcpListener::bind((loopback, port)).unwrap();
        let out = home.run(&["connect", "home", "--", "/usr/bin/true"]);
        assert_eq!(out.code(), 1, "{loopback}");
        assert!(
            out.stderr()
                .contains(&format!("in use on {named} by another program; stop it")),
            "{loopback}: {}",
            out.stderr()
        );
    }
    // Design §8 step 7: the failure is saved on the sandbox.
    let show = home.run(&["sandbox", "show", "home"]).ok().stdout();
    assert!(
        show.contains("Sandbox home: failed: connect failed: port")
            && show.contains("by another program"),
        "{show}"
    );
}

/// The proxy port `sandbox show` lists for the sandbox.
#[cfg(target_os = "macos")]
fn proxy_port(home: &Home) -> u16 {
    let show = home.run(&["sandbox", "show", "home"]).ok().stdout();
    show.split("proxy port ")
        .nth(1)
        .and_then(|rest| rest.lines().next())
        .and_then(|p| p.trim().parse().ok())
        .unwrap()
}

/// Kills the `enclos` this test started when the test ends, passed or not.
#[cfg(target_os = "macos")]
struct KillOnDrop(std::process::Child);

#[cfg(target_os = "macos")]
impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Polls `check` for up to ten seconds.
#[cfg(target_os = "macos")]
fn eventually(mut check: impl FnMut() -> bool) -> bool {
    let start = std::time::Instant::now();
    while start.elapsed() < Duration::from_secs(10) {
        if check() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

/// The pid `sandbox show` lists under the sandbox's running proxy.
#[cfg(target_os = "macos")]
fn proxy_pid(home: &Home) -> Option<u32> {
    let show = home.run(&["sandbox", "show", "home"]).ok().stdout();
    let mut lines = show.lines().skip_while(|l| !l.contains("  proxy, session"));
    lines.next()?;
    let line = lines.next()?.trim();
    line.strip_prefix("pid ")?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

#[cfg(target_os = "macos")]
#[test]
fn a_proxy_that_died_is_replaced_and_stop_works_from_another_time_zone() {
    let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
    let home = Home::new();
    home.init(1);
    home.run(&["sandbox", "create", "home"]).ok();
    let _stop = StopOnDrop(&home, "home");

    // A long command: its connect, the parent of the proxy it started,
    // stays, so a proxy that dies stays an unreaped zombie.
    let mut long = KillOnDrop(
        home.command(&["connect", "home", "--", "/bin/sleep", "30"])
            .env("TZ", "UTC0")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let mut first = None;
    assert!(eventually(|| {
        first = proxy_pid(&home);
        first.is_some()
    }));
    let first = first.unwrap();
    // The proxy this test's enclos started, as `sandbox show` names it.
    Command::new("/bin/kill")
        .args(["-TERM", &first.to_string()])
        .status()
        .unwrap();
    assert!(eventually(|| proxy_pid(&home).is_none()));

    // The next connect starts a new proxy.
    home.run(&["connect", "home", "--", "/usr/bin/true"]).ok();
    let second = proxy_pid(&home);
    assert!(second.is_some_and(|p| p != first), "{second:?}");

    // Stop, from another time zone, still recognizes what connect recorded.
    let stop = Run(home
        .command(&["sandbox", "stop", "home"])
        .env("TZ", "America/Bogota")
        .output()
        .unwrap());
    assert!(
        stop.ok().stdout().contains("Stopped sandbox home"),
        "{}",
        stop.stdout()
    );
    assert!(eventually(|| long.0.try_wait().unwrap().is_some()));
}

#[cfg(target_os = "macos")]
#[test]
fn stop_ends_an_interactive_shell_and_its_jobs() {
    use std::io::Write;

    let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
    let home = Home::new();
    home.init(1);
    home.run(&["sandbox", "create", "home"]).ok();
    let _stop = StopOnDrop(&home, "home");
    // An empty .zshrc, so zsh does not ask a new user to set it up.
    std::fs::write(home.root.join("sandboxes/home/home/.zshrc"), "").unwrap();

    // `script` gives connect a terminal: the default shell is interactive
    // and puts itself, and each job, in a group of its own.
    let mut terminal = KillOnDrop(
        Command::new("/usr/bin/script")
            .args([
                "-q",
                "/dev/null",
                env!("CARGO_BIN_EXE_enclos"),
                "connect",
                "home",
            ])
            .env("ENCLOS_HOME", &home.root)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let mut input = terminal.0.stdin.take().unwrap();
    input.write_all(b"/bin/sleep 45\n").unwrap();
    input.flush().unwrap();

    let mut show = String::new();
    assert!(
        eventually(|| {
            show = home.run(&["sandbox", "show", "home"]).ok().stdout();
            show.contains("sleep")
        }),
        "{show}"
    );
    let interactive: String = show
        .lines()
        .skip_while(|l| !l.contains(" interactive:"))
        .skip(1)
        .take_while(|l| l.trim_start().starts_with("pid "))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(interactive.contains("zsh"), "{show}");
    assert!(!interactive.contains("enclos"), "{show}");
    let sleep: u32 = interactive
        .lines()
        .find(|l| l.contains("sleep"))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|pid| pid.parse().ok())
        .unwrap();

    let stop = home.run(&["sandbox", "stop", "home"]);
    assert!(
        stop.ok().stdout().contains("Stopped sandbox home"),
        "{}",
        stop.stdout()
    );
    let gone = |pid: u32| {
        !Command::new("/bin/ps")
            .args(["-p", &pid.to_string()])
            .stdout(Stdio::null())
            .status()
            .unwrap()
            .success()
    };
    assert!(eventually(|| gone(sleep)));
    assert!(eventually(|| terminal.0.try_wait().unwrap().is_some()));
    drop(input);
}

#[cfg(target_os = "macos")]
#[test]
fn connect_outlives_ctrl_c_and_records_the_programs_end() {
    let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
    let home = Home::new();
    home.init(1);
    home.run(&["sandbox", "create", "home"]).ok();
    let _stop = StopOnDrop(&home, "home");

    // Without a terminal the program runs in a group of its own: the INT
    // sent below reaches this enclos alone, which outlives it and passes it
    // on to the program, which handles it and exits 3.
    // It says when its trap is set: an INT passed on before would end it
    // as INT does, 130, not 3.
    let script = "trap 'exit 3' INT; : > \"$HOME/trapped\"; /bin/sleep 10 & wait";
    let trapped = home.root.join("sandboxes/home/home/trapped");
    let mut connect = KillOnDrop(
        home.command(&["connect", "home", "--", "/bin/sh", "-c", script])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let audit = || home.run(&["audit"]).ok().stdout();
    // The connect entry closes once the session is recorded.
    assert!(
        eventually(|| audit().contains("ok: session 2")),
        "{}",
        audit()
    );
    assert!(eventually(|| trapped.exists()), "the program set no trap");
    // The enclos this test started.
    Command::new("/bin/kill")
        .args(["-INT", &connect.0.id().to_string()])
        .status()
        .unwrap();
    let mut status = None;
    assert!(eventually(|| {
        status = connect.0.try_wait().unwrap();
        status.is_some()
    }));
    assert_eq!(status.unwrap().code(), Some(3));
    assert!(audit().contains("ok: exit 3"), "{}", audit());
}

#[cfg(target_os = "macos")]
#[test]
fn a_runtime_install_dry_run_starts_nothing() {
    let home = Home::new();
    home.init(1);
    home.run(&["sandbox", "create", "home"]).ok();
    let before = home.audit_lines().len();
    let out = home.run(&[
        "runtime",
        "install",
        "hermes",
        "--sandbox",
        "home",
        "--dry-run",
    ]);
    let plan = out.ok().stdout();
    assert!(
        plan.contains("Would allow the 13 destinations hermes needs"),
        "{plan}"
    );
    assert!(
        plan.contains("Would download the hermes installer from https://"),
        "{plan}"
    );
    assert!(plan.contains("Would start the proxy"), "{plan}");
    assert!(
        plan.contains("record hermes as its runtime if the installer exits 0"),
        "{plan}"
    );
    assert_eq!(home.audit_lines().len(), before);
    assert!(!home.root.join("sandboxes/home/installers").exists());
    let show = home.run(&["sandbox", "show", "home"]).ok().stdout();
    assert!(show.contains("no sessions running"), "{show}");
    assert!(show.contains("active policy v1"), "{show}");
}

#[cfg(target_os = "macos")]
#[test]
fn agent_commands_need_a_runtime_and_their_dry_runs_change_nothing() {
    let home = Home::new();
    home.init(1);
    home.run(&["sandbox", "create", "home"]).ok();
    let before = home.audit_lines().len();
    // Without a runtime, nothing to add to: said before anything runs.
    let out = home.run(&["agent", "add", "home/main", "--dry-run"]);
    assert_eq!(out.code(), 1);
    assert!(out.stderr().contains("no runtime yet"), "{}", out.stderr());
    let out = home.run(&["agent", "rm", "home/main", "--dry-run"]);
    assert_eq!(out.code(), 1);
    let archive = home.root.join("main.tar.gz");
    std::fs::write(&archive, b"an export").unwrap();
    let out = home.run(&[
        "agent",
        "add",
        "home/main",
        "--from",
        archive.to_str().unwrap(),
        "--dry-run",
    ]);
    assert_eq!(out.code(), 1);
    assert!(out.stderr().contains("no runtime yet"), "{}", out.stderr());
    assert!(!home.root.join("sandboxes/home/installers").exists());
    assert_eq!(home.audit_lines().len(), before);
    // Names are checked before anything else.
    for bad in [
        "main",
        "home/",
        "home/../x",
        "home/a;b",
        "home/$(x)",
        "home/-x",
    ] {
        let out = home.run(&["agent", "add", bad]);
        assert_ne!(out.code(), 0, "{bad}");
        assert!(
            out.stderr().contains("<sandbox>/<agent>") || out.stderr().contains("not a valid"),
            "{bad}: {}",
            out.stderr()
        );
    }
    assert_eq!(home.audit_lines().len(), before);
}

#[cfg(target_os = "macos")]
#[test]
fn a_recording_proxy_records_itself_once_it_holds_the_port_and_stop_ends_it() {
    let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
    let home = Home::new();
    home.init(1);
    home.run(&["sandbox", "create", "home"]).ok();
    let _stop = StopOnDrop(&home, "home");
    let port = proxy_port(&home);
    let port_arg = port.to_string();
    let args = ["proxy", "run", "home", "--record", "--port", &port_arg];
    // With the port taken on either loopback, it records nothing: a
    // recorded proxy owns its port, which a service's `launch` relies on.
    for (loopback, named) in [("127.0.0.1", "127.0.0.1"), ("::1", "[::1]")] {
        let _squatter = std::net::TcpListener::bind((loopback, port)).unwrap();
        let out = home.run(&args);
        assert_eq!(out.code(), 1, "{loopback}: {}", out.stderr());
        assert!(
            out.stderr()
                .contains(&format!("in use on {named} by another program; stop it")),
            "{loopback}: {}",
            out.stderr()
        );
        assert!(
            out.stderr()
                .contains("recreate the sandbox to get another port"),
            "{}",
            out.stderr()
        );
        assert!(proxy_pid(&home).is_none());
        assert!(!home.audit_lines().iter().any(|l| l.contains("proxy start")));
        // A port other than the sandbox's own is not the sandbox's to give
        // up: no advice to recreate it.
        let other = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let elsewhere = other.local_addr().unwrap().port().to_string();
        let out = home.run(&["proxy", "run", "home", "--port", &elsewhere]);
        assert_eq!(out.code(), 1, "{}", out.stderr());
        assert!(
            out.stderr().contains("cannot listen on"),
            "{}",
            out.stderr()
        );
        assert!(!out.stderr().contains("recreate"), "{}", out.stderr());
    }
    // As the service manager runs it.
    let mut proxy = KillOnDrop(
        home.command(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    assert!(eventually(|| proxy_pid(&home) == Some(proxy.0.id())));
    // Once recorded, it holds the port on both loopbacks.
    for loopback in ["127.0.0.1", "::1"] {
        assert!(
            std::net::TcpListener::bind((loopback, port)).is_err(),
            "{loopback}"
        );
    }
    // A second proxy finds the port held by the sandbox's own: nothing to
    // stop or recreate.
    let out = home.run(&["proxy", "run", "home", "--port", &port_arg]);
    assert_eq!(out.code(), 1, "{}", out.stderr());
    assert!(
        out.stderr().contains("already runs") && !out.stderr().contains("recreate"),
        "{}",
        out.stderr()
    );
    // `connect` uses it rather than starting another.
    home.run(&["connect", "home", "--", "/usr/bin/true"]).ok();
    assert_eq!(proxy_pid(&home), Some(proxy.0.id()));
    home.run(&["sandbox", "stop", "home"]).ok();
    assert!(eventually(|| proxy.0.try_wait().unwrap().is_some()));
    assert!(proxy_pid(&home).is_none());
}

#[cfg(target_os = "macos")]
#[test]
fn logs_of_a_sandbox_without_services_say_how_to_start_it() {
    let home = Home::new();
    home.init(1);
    home.run(&["sandbox", "create", "home"]).ok();
    let out = home.run(&["logs", "home"]);
    out.ok();
    assert!(
        out.stdout().contains("no service logs yet")
            && out.stdout().contains("enclos sandbox start home"),
        "{}",
        out.stdout()
    );
    let out = home.run(&["logs", "nope"]);
    assert_eq!(out.code(), 1);
}

/// What the services print comes from the sandbox, so `enclos logs` shows
/// it escaped: this one would set the clipboard and clear the screen.
#[cfg(target_os = "macos")]
#[test]
fn logs_show_what_the_services_printed_escaped() {
    let home = Home::new();
    home.init(1);
    home.run(&["sandbox", "create", "home"]).ok();
    let logs = home.root.join("sandboxes/home/logs");
    std::fs::create_dir_all(&logs).unwrap();
    std::fs::write(
        logs.join("gateway.log"),
        "ok\n\x1b]52;c;cHduZWQ=\x07\x1b[2Jcleared\n",
    )
    .unwrap();
    let out = home.run(&["logs", "home"]);
    out.ok();
    assert!(
        out.stdout()
            .contains("\\u{1b}]52;c;cHduZWQ=\\u{7}\\u{1b}[2Jcleared"),
        "{}",
        out.stdout()
    );
    assert!(!out.stdout().contains('\x1b'), "{}", out.stdout());
}

/// §10's flow starts and stops two sandboxes in one command; a name that is
/// not a sandbox changes nothing, even after a good one.
#[cfg(target_os = "macos")]
#[test]
fn start_and_stop_take_several_sandboxes() {
    let home = Home::new();
    home.init(1);
    home.run(&["sandbox", "create", "home"]).ok();
    home.run(&["sandbox", "create", "lab"]).ok();

    let out = home.run(&["sandbox", "start", "home", "lab", "--dry-run"]);
    out.ok();
    for name in ["home", "lab"] {
        assert!(
            out.stdout()
                .contains(&format!(".{name}.proxy of sandbox {name}")),
            "{}",
            out.stdout()
        );
    }

    let before = home.audit_lines().len();
    let out = home.run(&["sandbox", "stop", "home", "nope"]);
    assert_eq!(out.code(), 1);
    assert!(out.stdout().is_empty(), "{}", out.stdout());
    assert!(
        out.stderr().contains("no sandbox named `nope`"),
        "{}",
        out.stderr()
    );
    assert_eq!(home.audit_lines().len(), before);

    let out = home.run(&["sandbox", "stop", "home", "lab", "home"]);
    out.ok();
    assert_eq!(
        out.stdout().matches("Stopped sandbox").count(),
        2,
        "{}",
        out.stdout()
    );
    assert!(
        out.stdout().contains("Stopped sandbox home")
            && out.stdout().contains("Stopped sandbox lab"),
        "{}",
        out.stdout()
    );
}

/// A reader that leaves before `enclos` prints, as `| head -0` does, ends
/// it by SIGPIPE, as any Unix tool, not by a panic.
#[cfg(target_os = "macos")]
#[test]
fn a_reader_that_left_ends_a_listing_quietly() {
    use std::os::unix::process::ExitStatusExt;

    let home = Home::new();
    home.init(1);
    for name in ["home", "lab"] {
        home.run(&["sandbox", "create", name]).ok();
    }
    let mut child = home
        .command(&["sandbox", "list"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    drop(child.stdout.take());
    let out = child.wait_with_output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!stderr.contains("panicked"), "{stderr}");
    assert_eq!(out.status.signal(), Some(13), "{:?} {stderr}", out.status);
    // In JSON, whose document has a descriptor of its own, the write fails
    // and the command says what it did. The reader is gone before enclos
    // starts, so no write can come first.
    let (reader, writer) = std::io::pipe().unwrap();
    drop(reader);
    let out = Run(home
        .piped(&["sandbox", "list"])
        .stdout(writer)
        .output()
        .unwrap());
    assert_eq!(out.code(), 1, "{}", out.stderr());
    let said: serde_json::Value = serde_json::from_str(out.stderr().trim()).unwrap();
    let message = said["error"]["message"].as_str().unwrap();
    assert!(
        message.contains("cannot write the JSON document (Broken pipe")
            && message.contains("the command itself succeeded"),
        "{said}"
    );
}

/// Records Hermes as the runtime of sandbox `name` without installing it,
/// and gives back a way to make a Hermes profile in the sandbox home as
/// `hermes profile create` would, so the agent commands have something to
/// report without a Hermes install.
#[cfg(target_os = "macos")]
fn record_hermes(home: &Home, name: &str) -> impl Fn(&str) {
    use enclos::state::StateStore;
    let layout = enclos::layout::Layout::at(&home.root);
    let state =
        enclos::state::sqlite::SqliteStateStore::new(layout.state_db(), layout.state_lock());
    let lock = state.lock().unwrap();
    let mut record = state.get(&name.parse().unwrap()).unwrap().unwrap();
    record.runtime = Some(enclos::model::runtime::RuntimeKind::Hermes);
    state.put(&lock, &record).unwrap();
    let profiles = layout.sandbox_home(name).join(".hermes/profiles");
    move |agent: &str| {
        std::fs::create_dir_all(profiles.join(agent)).unwrap();
        std::fs::write(profiles.join(agent).join("config.yaml"), "").unwrap();
    }
}

#[cfg(target_os = "macos")]
#[test]
fn agent_list_and_sandbox_show_report_an_agent_made_inside_the_sandbox() {
    let home = Home::new();
    home.init(1);
    home.run(&["sandbox", "create", "home"]).ok();
    let make = record_hermes(&home, "home");
    make("scout");
    make("my_bot");

    let untracked = "home/scout: Hermes has this agent; enclos does not track it. Track it with `enclos agent add home/scout`.";
    let untrackable = "Hermes has an agent enclos cannot track: `my_bot` is not a valid agent name";
    let list = home.run(&["agent", "list", "home"]);
    let out = list.ok().stdout();
    assert!(!out.contains("no agents yet"), "{out}");
    assert_eq!(
        out.lines().take(2).collect::<Vec<_>>(),
        ["home/default  built in", untracked],
        "{out}"
    );
    assert!(out.contains(untrackable), "{out}");
    let (code, listed) = home.json(&["agent", "list", "home"]);
    assert_eq!(code, 0, "{listed}");
    assert_eq!(listed["builtin"], "default", "{listed}");
    assert_eq!(listed["agents"], serde_json::json!([]), "{listed}");
    assert!(
        listed["notes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|n| n == untracked),
        "{listed}"
    );
    let (_, shown) = home.json(&["sandbox", "show", "home"]);
    assert_eq!(shown["agents"], serde_json::json!([]), "{shown}");
    assert!(shown["services"].is_array(), "{shown}");
    assert!(shown.get("error").is_none(), "{shown}");
    let show = home.run(&["sandbox", "show", "home"]);
    let out = show.ok().stdout();
    assert!(out.contains("\n  agents: none\n"), "{out}");
    assert!(out.contains(&format!("\n  {untracked}\n")), "{out}");

    // Adopting records it without running Hermes (there is none to run),
    // and says so instead of the next steps after a creation.
    let before = home.audit_lines().len();
    let (code, added) = home.json(&["--dry-run", "agent", "add", "home/scout"]);
    assert_eq!(code, 0, "{added}");
    assert_eq!(added["dry_run"], true, "{added}");
    assert_eq!(home.audit_lines().len(), before);
    let add = home.run(&["agent", "add", "home/scout"]);
    let out = add.ok().stdout();
    assert_eq!(
        out.trim(),
        "Tracked agent home/scout, which Hermes already had. Talk to it with `enclos connect home -- hermes -p scout`."
    );
    // One entry, opened and closed: no session ran.
    assert_eq!(home.audit_lines().len(), before + 2);
    let list = home.run(&["agent", "list", "home"]);
    let out = list.ok().stdout();
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines.len(), 4, "{out}");
    assert_eq!(
        lines[..3],
        ["home/default  built in", "home/scout", ""],
        "{out}"
    );
    assert!(lines[3].starts_with(untrackable), "{out}");
    let show = home.run(&["sandbox", "show", "home"]);
    assert!(
        show.ok().stdout().contains("\n  agents: scout\n"),
        "{}",
        show.stdout()
    );

    let (_, shown) = home.json(&["sandbox", "show", "home"]);
    assert_eq!(shown["agents"], serde_json::json!(["scout"]), "{shown}");

    // Removing the record alone keeps the files, so Hermes still has the agent.
    let (code, removed) = home.json(&["agent", "rm", "home/scout", "--keep-data"]);
    assert_eq!(code, 0, "{removed}");
    assert_eq!(removed["agent"], "home/scout", "{removed}");
    assert_eq!(removed["files_removed"], false, "{removed}");
    assert!(removed["files_kept_because"].is_string(), "{removed}");
    let list = home.run(&["agent", "list", "home"]);
    assert_eq!(list.ok().stdout().lines().nth(1), Some(untracked));

    // A home enclos cannot read safely is said, not shown as clean.
    let hermes = home.root.join("sandboxes/home/home/.hermes");
    let kept = home.root.join("sandboxes/home/home/hermes-kept");
    std::fs::rename(&hermes, &kept).unwrap();
    std::os::unix::fs::symlink(&kept, &hermes).unwrap();
    let list = home.run(&["agent", "list", "home"]);
    let out = list.ok().stdout();
    assert_eq!(
        out.lines().nth(1),
        Some(
            "enclos cannot read Hermes's agents in sandbox home: ~/.hermes is a link. Agents made inside the sandbox are not reported."
        ),
        "{out}"
    );
    let add = home.run(&["agent", "add", "home/scout"]);
    assert_eq!(add.code(), 1);
    assert!(
        add.stderr().contains("~/.hermes is a link"),
        "{}",
        add.stderr()
    );
}

#[cfg(target_os = "macos")]
#[test]
fn agent_add_from_an_archive_imports_it_and_its_dry_run_copies_nothing() {
    let home = Home::new();
    home.init(1);
    home.run(&["sandbox", "create", "home"]).ok();
    let _make = record_hermes(&home, "home");
    let archive = home.root.join("main.tar.gz");
    std::fs::write(&archive, b"an export").unwrap();
    let before = home.audit_lines().len();
    let out = home.run(&[
        "agent",
        "add",
        "home/main",
        "--from",
        archive.to_str().unwrap(),
        "--dry-run",
    ]);
    let stdout = out.ok().stdout();
    assert!(
        stdout.starts_with(&format!("Would copy {} (sha256 ", archive.display())),
        "{stdout}"
    );
    assert!(
        stdout.contains("Would run `hermes profile import ") && stdout.contains("--name main`"),
        "{stdout}"
    );
    assert!(!home.root.join("sandboxes/home/installers").exists());
    assert_eq!(home.audit_lines().len(), before);
    let missing = home.root.join("missing.tar.gz");
    let out = home.run(&[
        "agent",
        "add",
        "home/main",
        "--from",
        missing.to_str().unwrap(),
        "--dry-run",
    ]);
    assert_eq!(out.code(), 1);
    assert!(
        out.stderr().contains("cannot read the archive at"),
        "{}",
        out.stderr()
    );
}

#[cfg(target_os = "macos")]
#[test]
fn connect_reports_untracked_agents_on_stderr_without_the_untrackable_names() {
    let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
    let home = Home::new();
    home.init(1);
    home.run(&["sandbox", "create", "home"]).ok();
    let _stop = StopOnDrop(&home, "home");
    let _make = record_hermes(&home, "home");

    // Made in the session, as Hermes's own commands would.
    let script = "mkdir -p ~/.hermes/profiles/scout ~/.hermes/profiles/my_bot && touch ~/.hermes/profiles/scout/config.yaml ~/.hermes/profiles/my_bot/SOUL.md && echo made; exit 4";
    let out = home.run(&["connect", "home", "--", "/bin/sh", "-c", script]);
    assert_eq!(out.code(), 4, "stderr: {}", out.stderr());
    assert_eq!(out.stdout(), "made\n");
    assert!(
        out.stderr().contains(
            "enclos: home/scout: Hermes has this agent; enclos does not track it. Track it with `enclos agent add home/scout`."
        ),
        "{}",
        out.stderr()
    );
    assert!(!out.stderr().contains("my_bot"), "{}", out.stderr());
}

#[test]
fn status_without_sandboxes_says_how_to_make_one_and_names_an_unknown_sandbox() {
    let home = Home::new();
    home.init(1);
    let out = home.run(&["status"]);
    assert_eq!(
        out.ok().stdout(),
        "No sandboxes yet. Create one with `enclos sandbox create lab`.\n"
    );
    let out = home.run(&["status", "--json"]);
    let json: serde_json::Value = serde_json::from_str(&out.ok().stdout()).unwrap();
    assert_eq!(json["sandboxes"], serde_json::json!([]));
    assert_eq!(json["unlisted"], serde_json::json!([]));
    assert_eq!(json["suggestions"], serde_json::json!([]));
    assert_eq!(
        (&json["bytes"], &json["complete"], &json["idle_days"]),
        (
            &serde_json::json!(0),
            &serde_json::json!(true),
            &serde_json::json!(30)
        )
    );
    assert_eq!(json["data"], home.root.display().to_string());
    let out = home.run(&["status", "nope"]);
    assert_eq!(out.code(), 1);
    assert!(
        out.stderr().contains("no sandbox named `nope`"),
        "{}",
        out.stderr()
    );
}

#[cfg(target_os = "macos")]
#[test]
fn status_shows_each_sandbox_its_agents_and_what_to_do() {
    let home = Home::new();
    home.init(1);
    home.run(&["sandbox", "create", "home"]).ok();
    home.run(&["sandbox", "create", "spare"]).ok();
    let make = record_hermes(&home, "home");
    make("scout");
    make("gone");
    home.run(&["agent", "add", "home/gone"]).ok();
    let profiles = home.root.join("sandboxes/home/home/.hermes/profiles");
    std::fs::remove_dir_all(profiles.join("gone")).unwrap();
    // Without Hermes's own files, status says to install it again.
    let text = home.run(&["status", "home"]).ok().stdout();
    assert!(text.contains("Hermes, files missing"), "{text}");
    assert!(
        text.contains("enclos runtime install hermes --sandbox home"),
        "{text}"
    );
    std::fs::create_dir_all(home.root.join("sandboxes/home/home/.hermes/hermes-agent")).unwrap();

    let out = home.run(&["status"]);
    let text = out.ok().stdout();
    // The built-in agent and the tracked one, and the untracked one apart.
    assert!(
        text.starts_with("2 sandboxes, 2 agents (1 more not tracked), "),
        "{text}"
    );
    // With nothing untracked, the header gives the count alone.
    let spare = home.run(&["status", "spare"]).ok().stdout();
    assert!(spare.starts_with("1 sandbox, 0 agents, "), "{spare}");
    for line in [
        "home   created   Hermes, not logged in",
        "spare  created   no runtime",
        "  AGENT    LAST ACTIVE        SIZE  MODEL",
        "  default  never",
        "built in",
        "scout",
        "made inside the sandbox, not tracked",
        "the runtime no longer has it",
        "What you could do",
        "enclos agent add home/scout",
        "enclos agent rm home/gone",
        "enclos connect home -- hermes -p default setup",
        "enclos runtime install <runtime> --sandbox spare",
    ] {
        assert!(text.contains(line), "{line:?} in\n{text}");
    }
    let out = home.run(&["status", "home", "--json"]);
    let json: serde_json::Value = serde_json::from_str(&out.ok().stdout()).unwrap();
    let agents = &json["sandboxes"][0]["agents"]["agents"];
    assert_eq!(agents[0]["kind"], "builtin");
    assert_eq!(agents[1]["name"], "gone");
    assert_eq!(agents[1]["in_runtime"], "gone");
    assert_eq!(agents[2]["kind"], "untracked");

    // A model name the sandbox wrote shows with the characters that do not
    // show as themselves escaped, and the rest as it is, in `--json` and in
    // the text.
    std::fs::write(
        profiles.join("scout/config.yaml"),
        "model:\n  default: a\u{115F}\u{FE0F}\u{1D173}\u{600}\u{2028}b café 👨\u{200D}👩\u{200D}👧\n",
    )
    .unwrap();
    let out = home.run(&["status", "home", "--json"]);
    let json: serde_json::Value = serde_json::from_str(&out.ok().stdout()).unwrap();
    let agents = json["sandboxes"][0]["agents"]["agents"].as_array().unwrap();
    let scout = agents.iter().find(|a| a["name"] == "scout").unwrap();
    assert_eq!(
        scout["model"]["known"],
        "a\\u{115f}\\u{fe0f}\\u{1d173}\\u{600}\\u{2028}b café 👨\u{200D}👩\u{200D}👧"
    );
    let text = home.run(&["status", "home"]).ok().stdout();
    assert!(
        text.contains(
            "a\\u{115f}\\u{fe0f}\\u{1d173}\\u{600}\\u{2028}b café 👨\u{200D}👩\u{200D}👧"
        ),
        "{text}"
    );
    assert!(!text.contains(['\u{115F}', '\u{2028}']), "{text}");

    // `agent rm` of the agent Hermes no longer has says so.
    let rm = home.run(&["agent", "rm", "home/gone"]);
    assert_eq!(
        rm.ok().stdout(),
        "Removed the record of agent home/gone, which Hermes no longer had.\n"
    );
}

/// `secret set` at a terminal: a line longer than the terminal's own limit
/// comes whole, a pasted second line is refused, Ctrl-C cancels at once,
/// and echo is back on after each.
#[cfg(target_os = "macos")]
#[test]
fn a_secret_typed_at_a_terminal_is_one_line_read_whole() {
    use rustix::pty::{OpenptFlags, grantpt, openpt, ptsname, unlockpt};
    use rustix::termios::{LocalModes, tcgetattr};
    let home = Home::new();
    let keychain = TestKeychain::new(&home);
    home.init(1);
    home.run(&["sandbox", "create", "home"]).ok();
    let at_terminal = |name: &str, keys: &[u8]| {
        let master = openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY).unwrap();
        grantpt(&master).unwrap();
        unlockpt(&master).unwrap();
        let path = ptsname(&master, Vec::new()).unwrap();
        let slave = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path.to_str().unwrap())
            .unwrap();
        let mut cmd = home.command(&["secret", "set", &format!("home/{name}")]);
        cmd.env("ENCLOS_KEYCHAIN", &keychain.0)
            .stdin(slave.try_clone().unwrap())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let child = cmd.spawn().unwrap();
        std::thread::sleep(Duration::from_millis(300));
        // From a thread: a paste longer than the terminal's queue waits for
        // enclos to read it. A 0xff byte, never typed, stands for a pause
        // longer than enclos waits for a quiet input.
        let keys = keys.to_vec();
        let writer = master.try_clone().unwrap();
        let typing = std::thread::spawn(move || {
            for part in keys.split(|b| *b == 0xff) {
                let mut part = part;
                while !part.is_empty() {
                    match rustix::io::write(&writer, part) {
                        Ok(n) => part = &part[n..],
                        Err(_) => return,
                    }
                }
                std::thread::sleep(Duration::from_millis(800));
            }
        });
        let out = Run(child.wait_with_output().unwrap());
        // Not joined: a writer still blocked means enclos stopped reading,
        // which the bytes left below show, rather than a test that hangs.
        std::thread::sleep(Duration::from_millis(100));
        drop(typing);
        let echo = tcgetattr(&slave)
            .unwrap()
            .local_modes
            .contains(LocalModes::ECHO);
        // What the shell would read next: nothing of the value.
        let left = rustix::io::ioctl_fionread(&slave).unwrap();
        assert_eq!(left, 0, "{left} bytes left for the shell");
        // enclos turned bracketed paste on, then off, on this terminal.
        rustix::fs::fcntl_setfl(&master, rustix::fs::OFlags::NONBLOCK).unwrap();
        let mut shown = Vec::new();
        let mut buf = [0u8; 4096];
        while let Ok(n @ 1..) = rustix::io::read(&master, &mut buf[..]) {
            shown.extend_from_slice(&buf[..n]);
        }
        let shown = String::from_utf8_lossy(&shown);
        assert!(
            shown.contains("\x1b[?2004h") && shown.ends_with("\x1b[?2004l"),
            "{shown:?}"
        );
        (out, echo)
    };
    let (out, echo) = at_terminal("long", &[b"k".repeat(1500), b"\r".to_vec()].concat());
    assert!(
        out.ok().stdout().contains("Stored secret home/long"),
        "{}",
        out.stdout()
    );
    assert!(echo);
    let (out, echo) = at_terminal("pasted", b"first-line\rsecond-part");
    assert_eq!(out.code(), 1, "{}", out.stderr());
    assert!(
        out.stderr().contains("more came after the line"),
        "{}",
        out.stderr()
    );
    assert!(echo);
    // A paste far past the limit and the terminal's queue: refused, and
    // none of it left for the shell.
    let (out, echo) = at_terminal("huge", &b"k".repeat(6000));
    assert_eq!(out.code(), 1, "{}", out.stderr());
    assert!(
        out.stderr().contains("at most 4096 bytes"),
        "{}",
        out.stderr()
    );
    assert!(echo);
    let pem = [
        b"-----BEGIN KEY-----\r".to_vec(),
        b"k".repeat(3000),
        b"\r-----END KEY-----\r".to_vec(),
    ]
    .concat();
    let (out, echo) = at_terminal("pem", &pem);
    assert_eq!(out.code(), 1, "{}", out.stderr());
    assert!(
        out.stderr().contains("more came after the line"),
        "{}",
        out.stderr()
    );
    assert!(echo);
    // A paste whose second half comes after a pause, as over a slow link:
    // its end is known from the marks a terminal puts around a paste.
    let (out, echo) = at_terminal(
        "slow",
        b"\x1b[200~first-line\rsecond\xff\rthird-line\x1b[201~",
    );
    assert_eq!(out.code(), 1, "{}", out.stderr());
    assert!(
        out.stderr().contains("more came after the line"),
        "{}",
        out.stderr()
    );
    assert!(echo);
    // A pasted value with its line ending, then Return: one line.
    let (out, _) = at_terminal("whole", b"\x1b[200~tok-123\r\x1b[201~");
    assert!(
        out.ok().stdout().contains("Stored secret home/whole"),
        "{}",
        out.stdout()
    );
    let (out, echo) = at_terminal("cancel", b"abc\x03");
    assert_eq!(out.code(), 1, "{}", out.stderr());
    assert!(out.stderr().contains("cancelled"), "{}", out.stderr());
    assert!(echo);
    let listed = home.run(&["secret", "list", "home"]);
    let listed = listed.ok().stdout();
    assert!(
        listed.contains("long") && !listed.contains("pasted"),
        "{listed}"
    );
}

/// `policy edit` of sandbox `home`, adding a `[resources]` section with
/// `lines`.
#[cfg(target_os = "macos")]
fn edit_limits(home: &Home, lines: &str) -> Run {
    let mut edit = home.command(&["policy", "edit", "home"]);
    edit.env_remove("VISUAL").env(
        "EDITOR",
        editor(
            home,
            &format!("printf '\n[resources]\n{lines}\n' >> \"$1\""),
        ),
    );
    Run(edit.output().unwrap())
}

/// How many versions of sandbox `home`'s policy are stored.
#[cfg(target_os = "macos")]
fn policy_versions(home: &Home) -> usize {
    let history = home.run(&["policy", "history", "home"]).ok().stdout();
    history
        .lines()
        .filter(|l| l.trim_start().starts_with('v'))
        .count()
}

/// A limit Seatbelt cannot enforce as written is refused with why, by any
/// command that stores the policy, and nothing is stored.
#[cfg(target_os = "macos")]
#[test]
fn a_limit_seatbelt_cannot_hold_is_refused_and_nothing_is_stored() {
    let home = Home::new();
    home.init(1);
    home.run(&["sandbox", "create", "home"]).ok();
    let policy = home.root.join("sandboxes/home/policy.toml");
    let clean = std::fs::read_to_string(&policy).unwrap();
    // `policy edit` keeps the refused file, so the file as created is put
    // back each time.
    let before = policy_versions(&home);
    for (line, why) in [
        ("memory = \"2G\"", "cannot enforce a memory limit"),
        ("file_size = \"1M\"", "append"),
        ("cpu_seconds = 600", "SIGXCPU"),
    ] {
        let out = edit_limits(&home, line);
        assert_eq!(out.code(), 2, "{line}: {}", out.stderr());
        assert!(out.stderr().contains(why), "{line}: {}", out.stderr());
        home.run(&["policy", "discard", "home"]);
        std::fs::write(&policy, &clean).unwrap();
        assert_eq!(policy_versions(&home), before, "{line}");
    }
    // Refused by any command that stores the policy, not only `edit`.
    std::fs::write(&policy, format!("{clean}\n[resources]\nmemory = \"2G\"\n")).unwrap();
    let out = home.run(&["policy", "allow", "home", "x.example.com", "--yes"]);
    assert_eq!(out.code(), 2, "{}", out.stderr());
    assert_eq!(policy_versions(&home), before);
}

/// A `[resources]` section holds a sandbox's sessions to its open-file
/// limit: the least starts, in a session `ulimit` shows it, a process
/// cannot open more or raise it, and `policy test` shows it closed.
#[cfg(target_os = "macos")]
#[test]
fn a_sandbox_runs_under_its_open_file_limit() {
    let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
    let home = Home::new();
    home.init(1);
    home.run(&["sandbox", "create", "home"]).ok();
    let _stop = StopOnDrop(&home, "home");
    let policy = home.root.join("sandboxes/home/policy.toml");
    let clean = std::fs::read_to_string(&policy).unwrap();

    // The least a session starts with.
    edit_limits(&home, "open_files = 16").ok();
    home.run(&["exec", "home", "--", "/usr/bin/true"]).ok();
    std::fs::write(&policy, &clean).unwrap();
    let mut back = home.command(&["policy", "edit", "home"]);
    back.env_remove("VISUAL")
        .env("EDITOR", editor(&home, "true"));
    Run(back.output().unwrap()).ok();

    let out = edit_limits(&home, "open_files = 64");
    assert!(
        out.ok()
            .stdout()
            .contains("limit the files a process holds open to 64"),
        "{}",
        out.stdout()
    );
    let shown = home.run(&["policy", "show", "home"]).ok().stdout();
    assert!(shown.contains("  open files: 64"), "{shown}");
    let out = home.run(&["exec", "home", "--", "/bin/sh", "-c", "ulimit -Hn"]);
    assert_eq!(out.ok().stdout(), "64\n");
    // No process opens more, or raises the limit.
    let opens = "my @f; for my $n (1..100) { open(my $f, '<', '/dev/null') or die \"refused at $n: $!\\n\"; push @f, $f }";
    let out = home.run(&["exec", "home", "--", "/usr/bin/perl", "-e", opens]);
    assert_ne!(out.code(), 0, "{}", out.stderr());
    assert!(
        out.stderr().contains("Too many open files"),
        "{}",
        out.stderr()
    );
    let out = home.run(&[
        "exec",
        "home",
        "--",
        "/bin/sh",
        "-c",
        "ulimit -n 65 && echo raised",
    ]);
    let said = format!("{}{}", out.stdout(), out.stderr());
    assert!(!said.contains("raised"), "{said}");
    assert!(said.contains("cannot modify limit"), "{said}");

    let out = home.run(&["policy", "test", "home"]);
    let report = out.stdout();
    assert!(
        report.lines().any(|l| l.trim_start().starts_with("closed ")
            && l.contains("have a hard limit above 64 open files")),
        "not shown closed:\n{report}"
    );
}

/// A limit above the hard one enclos runs under stops the session, with
/// the field named, and runs nothing.
#[cfg(target_os = "macos")]
#[test]
fn a_limit_above_enclos_own_hard_limit_stops_the_session() {
    let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
    let home = Home::new();
    home.init(1);
    home.run(&["sandbox", "create", "home"]).ok();
    let _stop = StopOnDrop(&home, "home");
    edit_limits(&home, "open_files = 64").ok();
    let out = Run(Command::new("/bin/bash")
        .arg("-c")
        .arg("ulimit -n 32 && exec \"$0\" \"$@\"")
        .arg(env!("CARGO_BIN_EXE_enclos"))
        .args(["exec", "home", "--", "/bin/echo", "ran"])
        .env("ENCLOS_HOME", &home.root)
        .env("HOME", home._dir.path())
        .output()
        .unwrap());
    assert_eq!(out.code(), 125, "{}", out.stderr());
    assert!(!out.stdout().contains("ran"));
    assert!(
        out.stderr()
            .contains("resources.open_files = 64 is above the hard limit enclos runs under (32)"),
        "{}",
        out.stderr()
    );
}

/// A sandbox made from `minimal` or `mcp-only` reaches only what is listed:
/// a public site the `assistant` template would reach is refused by its
/// proxy as not allowed, `policy show` says so, and `policy test` (run
/// once, for `minimal`, since both compile to the same rules) finds nothing
/// open.
#[cfg(target_os = "macos")]
#[test]
fn a_sandbox_from_minimal_or_mcp_only_reaches_only_what_is_listed() {
    let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
    for template in ["minimal", "mcp-only"] {
        let home = Home::new();
        home.init(1);
        home.run(&["sandbox", "create", "lab", "--template", template])
            .ok();
        let _stop = StopOnDrop(&home, "lab");
        let policy = std::fs::read_to_string(home.root.join("sandboxes/lab/policy.toml")).unwrap();
        assert!(
            policy.contains(&format!("extends = \"{template}\"")),
            "{policy}"
        );
        let shown = home.run(&["policy", "show", "lab"]).ok().stdout();
        assert!(shown.contains("\nNetwork: allowlist"), "{shown}");
        let listed = home.run(&["sandbox", "list"]).ok().stdout();
        assert!(
            listed
                .lines()
                .any(|l| l.starts_with("lab ") && l.contains(template)),
            "{listed}"
        );
        let (code, list) = home.json(&["sandbox", "list"]);
        assert_eq!(code, 0, "{list}");
        assert_eq!(list["sandboxes"][0]["template"], template, "{list}");
        // Refused at the proxy: no connection leaves the host.
        let out = home.run(&[
            "exec",
            "lab",
            "--",
            "/usr/bin/curl",
            "-s",
            "-o",
            "/dev/null",
            "-w",
            "%{http_connect}",
            "https://example.com/",
        ]);
        assert_eq!(out.stdout(), "403", "{template}: {}", out.stderr());
        let out = home.run(&["net", "denied", "lab"]);
        let denied = out.ok().stdout();
        assert!(
            denied
                .lines()
                .any(|l| l.contains("example.com:443") && l.contains("not-allowed")),
            "{denied}"
        );
        if template == "minimal" {
            let out = home.run(&["policy", "test", "lab"]);
            assert_eq!(
                out.code(),
                0,
                "{template}:\n{}\n{}",
                out.stdout(),
                out.stderr()
            );
            assert!(!out.stdout().contains("OPEN"), "{}", out.stdout());
        }
    }
}

/// Once `policy.toml` names another template, `sandbox list` and `show` name
/// the one the active policy is built on, not the one the sandbox was
/// created from.
#[cfg(target_os = "macos")]
#[test]
fn a_sandbox_is_listed_and_shown_with_its_active_template() {
    let home = Home::new();
    home.init(1);
    home.run(&["sandbox", "create", "lab"]).ok();
    let mut edit = home.command(&["policy", "edit", "lab"]);
    edit.env_remove("VISUAL").env(
        "EDITOR",
        editor(
            &home,
            "sed -i \x27\x27 \x27s/^extends = \"assistant\"$/extends = \"minimal\"/\x27 \"$1\"",
        ),
    );
    Run(edit.output().unwrap()).ok();
    let listed = home.run(&["sandbox", "list"]).ok().stdout();
    assert!(
        listed
            .lines()
            .any(|l| l.starts_with("lab ") && l.contains(" minimal ")),
        "{listed}"
    );
    let shown = home.run(&["sandbox", "show", "lab"]).ok().stdout();
    assert!(shown.contains(", template minimal, "), "{shown}");
    let (_, list) = home.json(&["sandbox", "list"]);
    assert_eq!(list["sandboxes"][0]["template"], "minimal", "{list}");
    let (_, show) = home.json(&["sandbox", "show", "lab"]);
    assert_eq!(show["template"], "minimal", "{show}");
}

/// `--help` names every template; on macOS, where the backend runs and so
/// the template is the first thing refused, one this enclos does not ship
/// is refused with the ones it has, and leaves no folder.
#[test]
fn an_unknown_template_is_refused_with_the_ones_there_are() {
    let home = Home::new();
    home.init(1);
    let help = home.run(&["sandbox", "create", "--help"]).ok().stdout();
    for name in enclos::policy::template_names() {
        assert!(help.contains(name), "{name}: {help}");
    }
    if !cfg!(target_os = "macos") {
        return;
    }
    let out = home.run(&["sandbox", "create", "lab", "--template", "coding"]);
    assert_eq!(out.code(), 1, "{}", out.stderr());
    assert!(
        out.stderr()
            .contains("unknown template `coding`: this enclos has minimal, mcp-only, assistant"),
        "{}",
        out.stderr()
    );
    assert!(!home.root.join("sandboxes/lab").exists());
}

/// `state check` finds nothing in a new sandbox, names what differs once a
/// file is gone, and `state repair` puts it back.
#[cfg(target_os = "macos")]
#[test]
fn state_check_and_repair_compare_the_records_with_the_host() {
    let home = Home::new();
    home.init(1);
    home.run(&["sandbox", "create", "home"]).ok();
    let out = home.run(&["state", "check"]);
    assert!(
        out.ok().stdout().contains("match the host"),
        "{}",
        out.stdout()
    );
    let policy = home.root.join("sandboxes/home/policy.toml");
    let text = std::fs::read_to_string(&policy).unwrap();
    std::fs::remove_file(&policy).unwrap();
    let out = home.run(&["state", "check", "home"]);
    assert_eq!(out.code(), 1, "{}", out.stdout());
    assert!(
        out.stdout().contains("repair: write policy.toml again"),
        "{}",
        out.stdout()
    );
    // The repair said is that sandbox's alone.
    assert!(
        out.stdout().contains("`enclos state repair home` fixes"),
        "{}",
        out.stdout()
    );
    let out = home.run(&["state", "repair", "--dry-run"]);
    assert!(
        out.ok()
            .stdout()
            .contains("would repair: write policy.toml again"),
        "{}",
        out.stdout()
    );
    assert!(!policy.exists());
    let out = home.run(&["state", "repair"]);
    assert!(
        out.ok().stdout().contains("home: its ")
            && out
                .stdout()
                .contains("  repaired: write policy.toml again from the text its active policy"),
        "{}",
        out.stdout()
    );
    assert_eq!(std::fs::read_to_string(&policy).unwrap(), text);
    home.run(&["state", "check"]).ok();

    // What is left for a person is named, by a dry run too, and exits 1.
    std::fs::remove_dir_all(home.root.join("sandboxes/home/home")).unwrap();
    for args in [&["state", "repair", "--dry-run"][..], &["state", "repair"]] {
        let out = home.run(args);
        assert_eq!(out.code(), 1, "{args:?}: {}", out.stdout());
        assert!(
            out.stdout().contains("  for you: `mkdir "),
            "{}",
            out.stdout()
        );
    }
    let out = home.run(&["state", "check", "nosuch"]);
    assert_eq!(out.code(), 1);
    assert!(!out.stdout().contains("match the host"), "{}", out.stdout());

    // A repair that fails is said so, and exits 1.
    std::fs::create_dir(home.root.join("sandboxes/home/home")).unwrap();
    std::fs::remove_file(&policy).unwrap();
    let dir = home.root.join("sandboxes/home");
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o500)).unwrap();
    let out = home.run(&["state", "repair"]);
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(out.code(), 1, "{}", out.stdout());
    assert!(
        out.stdout()
            .contains("  repair failed: write policy.toml again"),
        "{}",
        out.stdout()
    );
    assert!(!out.stdout().contains("repaired:"), "{}", out.stdout());

    // The same in JSON, and one left for a person.
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o500)).unwrap();
    let (code, doc) = home.json(&["state", "repair"]);
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(code, 1, "{doc}");
    let remedy = &doc["findings"][0]["remedy"];
    assert_eq!(remedy["kind"], "repair_failed", "{doc}");
    assert!(
        remedy["error"].as_str().is_some_and(|e| !e.is_empty()),
        "{doc}"
    );
    std::fs::remove_dir_all(home.root.join("sandboxes/home/home")).unwrap();
    let (code, doc) = home.json(&["state", "repair"]);
    assert_eq!(code, 1, "{doc}");
    let kinds: Vec<_> = doc["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["remedy"]["kind"].clone())
        .collect();
    assert!(kinds.contains(&"manual".into()), "{doc}");
    assert!(kinds.contains(&"repaired".into()), "{doc}");
    assert!(
        doc["error"]["message"]
            .as_str()
            .unwrap()
            .contains("1 findings need you"),
        "{doc}"
    );
}

/// `doctor` runs a program in Seatbelt, checks each sandbox's next session,
/// and names a compiled file that no longer holds what its policy compiled
/// to; it exits 1 when a next session cannot start.
#[cfg(target_os = "macos")]
#[test]
fn doctor_checks_the_backend_and_each_sandboxs_next_session() {
    let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
    let home = Home::new();
    let out = home.run(&["doctor"]);
    assert!(
        out.ok().stdout().contains("seatbelt: runs here"),
        "{}",
        out.stdout()
    );
    assert!(out.stdout().contains("not initialized"), "{}", out.stdout());
    home.init(1);
    home.run(&["sandbox", "create", "home"]).ok();
    let out = home.run(&["doctor"]);
    assert!(
        out.ok()
            .stdout()
            .contains("home: its next session compiles policy v1"),
        "{}",
        out.stdout()
    );
    assert!(
        out.stdout().contains("no session has run"),
        "{}",
        out.stdout()
    );
    // `exec` starts the proxy: stopped when the test ends.
    let _stop = StopOnDrop(&home, "home");
    home.run(&["exec", "home", "--", "/usr/bin/true"]).ok();
    let out = home.run(&["doctor"]);
    assert!(
        out.ok().stdout().contains("policy v1 compiles as it did"),
        "{}",
        out.stdout()
    );
    // The file the session ran under, changed after it was written.
    let compiled = home.root.join("sandboxes/home/compiled");
    let file = std::fs::read_dir(&compiled)
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.extension().is_some_and(|e| e == "sb"))
        .unwrap();
    let text = std::fs::read_to_string(&file).unwrap();
    std::fs::write(
        &file,
        format!("{text}(deny file-read* (literal \"/earlier\"))\n"),
    )
    .unwrap();
    let out = home.run(&["doctor"]);
    assert!(
        out.ok()
            .stdout()
            .contains("it was changed after it was written"),
        "{}",
        out.stdout()
    );
    assert!(
        out.stdout()
            .contains("      - (deny file-read* (literal \"/earlier\"))"),
        "{}",
        out.stdout()
    );
    let (code, doctor) = home.json(&["doctor"]);
    assert_eq!(code, 0, "{doctor}");
    let drift = &doctor["records"]["sandboxes"][0]["drift"][0];
    assert_eq!(drift["kind"], "edited", "{doctor}");
    assert!(
        drift["lines"]
            .as_array()
            .unwrap()
            .iter()
            .any(|l| l["removed"] == "(deny file-read* (literal \"/earlier\"))"),
        "{doctor}"
    );
    assert_eq!(drift["running_unsure"], false, "{doctor}");
    // With its home gone, its next session cannot start.
    std::fs::remove_dir_all(home.root.join("sandboxes/home/home")).unwrap();
    let out = home.run(&["doctor"]);
    assert_eq!(out.code(), 1, "{}", out.stdout());
    assert!(
        out.stdout()
            .contains("its active policy cannot be compiled"),
        "{}",
        out.stdout()
    );
}

/// In a sandbox whose policy has a deny rule, as every enclos sandbox's
/// has, macOS refuses Seatbelt to the programs it runs (exit 71), and doctor
/// says so.
/// A baseline value that is neither makes Seatbelt unusable, which doctor
/// says with why, in text and JSON; on the comparison baseline it says what
/// it compares against.
#[cfg(target_os = "macos")]
#[test]
fn doctor_says_what_a_baseline_value_does() {
    let home = Home::new();
    home.init(1);
    let out = Run(home
        .command(&["doctor"])
        .env("ENCLOS_SEATBELT_BASELINE", "1")
        .output()
        .unwrap());
    assert_eq!(out.code(), 1, "{}", out.stdout());
    assert!(
        out.stdout()
            .contains("not usable here: ENCLOS_SEATBELT_BASELINE is \"1\""),
        "{}",
        out.stdout()
    );
    let out = home
        .piped(&["doctor"])
        .env("ENCLOS_SEATBELT_BASELINE", "1")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let doc: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(doc["backends"][0]["state"], "unavailable", "{doc}");
    assert!(
        doc["backends"][0]["reason"]
            .as_str()
            .unwrap()
            .contains("ENCLOS_SEATBELT_BASELINE is \"1\""),
        "{doc}"
    );
    let out = Run(home
        .command(&["doctor"])
        .env("ENCLOS_SEATBELT_BASELINE", "allow-default")
        .output()
        .unwrap());
    assert!(
        out.stderr().contains("(allow default) comparison baseline"),
        "{}",
        out.stderr()
    );
}

#[cfg(target_os = "macos")]
#[test]
fn doctor_in_a_sandbox_says_seatbelt_refused_to_run() {
    let home = Home::new();
    let inner = home.command(&["doctor"]);
    let mut outer = std::process::Command::new("/usr/bin/sandbox-exec");
    outer
        .args([
            "-p",
            "(version 1)(allow default)(deny file-write* (literal \"/enclos-doctor-test\"))",
        ])
        .arg(inner.get_program())
        .args(inner.get_args())
        .envs(inner.get_envs().filter_map(|(k, v)| v.map(|v| (k, v))));
    let out = outer.output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(1), "{stdout}");
    assert!(
        stdout.contains("seatbelt: on this host, and it refused to run a program"),
        "{stdout}"
    );
    assert!(stdout.contains("Operation not permitted"), "{stdout}");
    assert!(stdout.contains("exit status: 71"), "{stdout}");
}

/// Piped, each command prints one JSON document: its result, or its error
/// with what kind of failure it is and the exit code, also for a refusal, a
/// change that needs confirmation and a usage error (design §10).
#[cfg(target_os = "macos")]
#[test]
fn piped_output_is_json_errors_and_refusals_included() {
    let home = Home::new();
    let (code, init) = home.json(&["init"]);
    assert_eq!(code, 0);
    assert!(
        init["created"].as_array().is_some_and(|c| !c.is_empty()),
        "{init}"
    );
    let (code, created) = home.json(&["sandbox", "create", "home"]);
    assert_eq!(code, 0, "{created}");
    assert_eq!(created["sandbox"], "home");
    assert_eq!(created["policy_version"], 1);
    let (_, list) = home.json(&["sandbox", "list"]);
    assert_eq!(list["sandboxes"][0]["name"], "home", "{list}");
    assert_eq!(list["sandboxes"][0]["state"]["state"], "created", "{list}");
    let (_, policy) = home.json(&["policy", "show", "home"]);
    assert_eq!(policy["version"]["version"], 1, "{policy}");
    assert!(policy["policy"]["fs"]["write"].is_array(), "{policy}");
    let (code, planned) = home.json(&["--dry-run", "sandbox", "create", "lab"]);
    assert_eq!(code, 0);
    assert_eq!(planned["dry_run"], true, "{planned}");

    let failure = |args: &[&str], code: i32, kind: &str| {
        let out = home.run_piped(args);
        assert_eq!(out.code(), code, "{args:?}: {}", out.stdout());
        let doc: serde_json::Value = serde_json::from_str(&out.stdout()).unwrap();
        assert_eq!(doc["error"]["kind"], kind, "{args:?}: {doc}");
        assert_eq!(doc["error"]["exit_code"], code, "{doc}");
        assert!(
            doc["error"]["message"]
                .as_str()
                .is_some_and(|m| !m.is_empty())
        );
        assert_eq!(out.stderr(), "", "{args:?}");
    };
    failure(&["sandbox", "show", "nosuch"], 1, "error");
    failure(&["policy", "allow", "home", "localhost"], 2, "refused");
    failure(&["sandbox", "rm", "home"], 3, "needs_confirmation");
    failure(&["sandbox", "frobnicate"], 1, "error");

    // --text reads as a person reads, though piped; --json wins over it.
    let out = home.run_piped(&["--text", "sandbox", "list"]);
    assert!(out.ok().stdout().starts_with("NAME"), "{}", out.stdout());
    let (_, list) = home.json(&["--text", "--json", "sandbox", "list"]);
    assert_eq!(list["sandboxes"][0]["name"], "home");
}

/// `exec`'s output is its command's, piped or not; with --json, a failure
/// of enclos's own is JSON on stderr.
#[cfg(target_os = "macos")]
#[test]
fn exec_output_stays_its_commands_when_piped() {
    let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
    let home = Home::new();
    home.init(1);
    home.run(&["sandbox", "create", "home"]).ok();
    let _stop = StopOnDrop(&home, "home");
    let out = home.run_piped(&["exec", "home", "--", "/bin/echo", "hi"]);
    assert_eq!(out.stdout(), "hi\n");
    assert_eq!(out.code(), 0, "{}", out.stderr());
    // Its command's code, and no JSON on stderr, without --json.
    let out = home.run_piped(&["exec", "home", "--", "/bin/sh", "-c", "exit 7"]);
    assert_eq!(out.code(), 7, "{}", out.stderr());
    assert!(
        !out.stderr().lines().any(|l| l.starts_with('{')),
        "{}",
        out.stderr()
    );
    let out = home.run_piped(&["--json", "exec", "nosuch", "--", "/bin/echo", "hi"]);
    assert_eq!(out.code(), 125);
    assert_eq!(out.stdout(), "");
    let doc: serde_json::Value = serde_json::from_str(out.stderr().trim()).unwrap();
    assert_eq!(doc["error"]["exit_code"], 125, "{doc}");
    assert_eq!(doc["error"]["kind"], "error", "{doc}");
    // A usage error of its own, too, is JSON on stderr, not on its stdout.
    let out = home.run_piped(&["--json", "exec", "home"]);
    assert_eq!(out.code(), 125);
    assert_eq!(out.stdout(), "");
    let doc: serde_json::Value = serde_json::from_str(out.stderr().trim()).unwrap();
    assert_eq!(doc["error"]["exit_code"], 125, "{doc}");
    // Without --json, piped, it stays text.
    let out = home.run_piped(&["exec", "home"]);
    assert_eq!(out.code(), 125);
    assert!(out.stderr().contains("Usage"), "{}", out.stderr());
    // With --json, a command that runs keeps its stdout and its code, and
    // how its session ended is one line on stderr.
    let out = home.run_piped(&[
        "--json",
        "exec",
        "home",
        "--",
        "/bin/sh",
        "-c",
        "echo hi; exit 7",
    ]);
    assert_eq!(out.code(), 7, "{}", out.stderr());
    assert_eq!(out.stdout(), "hi\n");
    // Every word of enclos's own there is a JSON line.
    assert!(
        out.stderr()
            .lines()
            .all(|l| serde_json::from_str::<serde_json::Value>(l).is_ok()),
        "{}",
        out.stderr()
    );
    let ended = out
        .stderr()
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .find(|l| l.get("session").is_some())
        .unwrap_or_else(|| panic!("{}", out.stderr()));
    assert_eq!(ended["session"]["exit"], 7, "{ended}");
    // A dry run's plan is JSON on stdout, and nothing runs.
    for args in [
        &[
            "--json",
            "--dry-run",
            "exec",
            "home",
            "--",
            "/bin/echo",
            "ran",
        ][..],
        &["--json", "--dry-run", "connect", "home"][..],
    ] {
        let out = home.run_piped(args);
        assert_eq!(out.code(), 0, "{args:?}: {}", out.stderr());
        let doc: serde_json::Value = serde_json::from_str(&out.stdout()).unwrap();
        assert_eq!(doc["dry_run"], true, "{doc}");
        assert!(!out.stdout().contains("ran\n"), "{}", out.stdout());
    }
}

/// In a terminal, text; JSON only when asked, as a person reads.
#[cfg(target_os = "macos")]
#[test]
fn a_terminal_gets_text_and_json_only_when_asked() {
    let home = Home::new();
    home.init(1);
    // `script` runs enclos in a terminal of its own.
    let in_terminal = |args: &[&str]| {
        let out = Command::new("/usr/bin/script")
            .args(["-q", "/dev/null", env!("CARGO_BIN_EXE_enclos")])
            .args(args)
            .env("ENCLOS_HOME", &home.root)
            .env("HOME", home._dir.path())
            .stdin(Stdio::null())
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout).replace("\r\n", "\n")
    };
    let text = in_terminal(&["sandbox", "list"]);
    assert!(text.contains("No sandboxes yet"), "{text:?}");
    assert!(!text.contains('{'), "{text:?}");
    let json = in_terminal(&["--json", "sandbox", "list"]);
    let start = json.find('{').unwrap_or_else(|| panic!("{json:?}"));
    let end = json.rfind('}').unwrap_or_else(|| panic!("{json:?}"));
    let doc: serde_json::Value = serde_json::from_str(&json[start..=end]).unwrap();
    assert_eq!(doc["sandboxes"], serde_json::json!([]), "{doc}");
}

/// What the editor of `policy edit` prints goes to stderr: the document on
/// stdout stays whole.
#[cfg(target_os = "macos")]
#[test]
fn what_a_program_enclos_starts_prints_stays_out_of_the_document() {
    let home = Home::new();
    home.init(1);
    home.run(&["sandbox", "create", "home"]).ok();
    let script = r#"echo editor-noise; sed -i '' 's/allow_add = \[\]/allow_add = ["api.example.com"]/' "$1""#;
    let mut cmd = home.piped(&["policy", "edit", "home"]);
    cmd.env_remove("VISUAL")
        .env("EDITOR", editor(&home, script));
    let out = Run(cmd.output().unwrap());
    let doc: serde_json::Value = serde_json::from_str(&out.ok().stdout())
        .unwrap_or_else(|e| panic!("{e}: {}", out.stdout()));
    assert_eq!(doc["version"], 2, "{doc}");
    assert_eq!(doc["changed"], true, "{doc}");
    assert_eq!(doc["outcome"]["in_force"], true, "{doc}");
    assert!(!out.stdout().contains("editor-noise"), "{}", out.stdout());
    assert!(out.stderr().contains("editor-noise"), "{}", out.stderr());
}

/// A document nobody reads fails the command, and says what the command
/// itself did, so that it is not run again blindly.
#[cfg(target_os = "macos")]
#[test]
fn a_document_that_cannot_be_written_fails_the_command() {
    let home = Home::new();
    home.init(1);
    home.run(&["sandbox", "create", "home"]).ok();
    // A pipe whose reader is gone before enclos starts: its write fails.
    let (reader, writer) = std::io::pipe().unwrap();
    drop(reader);
    let out = Run(home
        .piped(&["--json", "--dry-run", "connect", "home"])
        .stdout(writer)
        .output()
        .unwrap());
    assert_eq!(out.code(), 1, "{}", out.stderr());
    // enclos's own words are JSON on stderr there.
    let said: serde_json::Value = serde_json::from_str(out.stderr().trim()).unwrap();
    let message = said["error"]["message"].as_str().unwrap();
    assert!(
        message.contains("cannot write the JSON document")
            && message.contains("the command itself succeeded"),
        "{said}"
    );
    // `exec`'s own failure is 125, whatever it was.
    let (reader, writer) = std::io::pipe().unwrap();
    drop(reader);
    let out = Run(home
        .piped(&[
            "--json",
            "--dry-run",
            "exec",
            "home",
            "--",
            "/bin/echo",
            "x",
        ])
        .stdout(writer)
        .output()
        .unwrap());
    assert_eq!(out.code(), 125, "{}", out.stderr());
    let said: serde_json::Value = serde_json::from_str(out.stderr().trim()).unwrap();
    assert_eq!(said["error"]["exit_code"], 125, "{said}");
    assert!(
        said["error"]["message"]
            .as_str()
            .unwrap()
            .contains("enclos itself succeeded"),
        "{said}"
    );
    // A command whose result is the document, and that failed: its own
    // code is said, and the error the document held.
    let (reader, writer) = std::io::pipe().unwrap();
    drop(reader);
    let out = Run(home
        .piped(&["sandbox", "show", "nosuch"])
        .stdout(writer)
        .output()
        .unwrap());
    assert_eq!(out.code(), 1, "{}", out.stderr());
    let said: serde_json::Value = serde_json::from_str(out.stderr().trim()).unwrap();
    let message = said["error"]["message"].as_str().unwrap();
    assert!(
        message.contains("the command itself failed, with exit code 1")
            && message.contains("nosuch"),
        "{said}"
    );
}

/// `sandbox show` keeps its view when what it reads after fails: in text,
/// the view first and then the error; in JSON, the view with an `error`
/// beside it, what could not be read null.
#[cfg(target_os = "macos")]
#[test]
fn sandbox_show_keeps_its_view_beside_an_error() {
    let home = Home::new();
    home.init(1);
    home.run(&["sandbox", "create", "home"]).ok();
    let _make = record_hermes(&home, "home");
    // An agent record that does not read as an agent's name: the sandbox's
    // view reads, its agents do not.
    let broke = Command::new("/usr/bin/sqlite3")
        .arg(home.root.join("state.db"))
        .arg("INSERT INTO agents (sandbox, name, created_at) VALUES ('home', 'Not A Name!', 'x');")
        .status()
        .unwrap();
    assert!(broke.success());
    let out = home.run(&["sandbox", "show", "home"]);
    assert_eq!(out.code(), 1, "{}", out.stdout());
    assert!(out.stdout().starts_with("Sandbox home"), "{}", out.stdout());
    let (code, shown) = home.json(&["sandbox", "show", "home"]);
    assert_eq!(code, 1, "{shown}");
    assert_eq!(shown["name"], "home", "{shown}");
    assert!(shown["state"].is_object(), "{shown}");
    assert!(shown["services"].is_array(), "{shown}");
    assert!(shown["agents"].is_null(), "{shown}");
    assert_eq!(shown["error"]["exit_code"], 1, "{shown}");
}

/// Help and the version are text, piped or not, and succeed.
#[test]
fn help_and_version_are_text_when_piped() {
    let home = Home::new();
    let out = home.run_piped(&["--version"]);
    assert_eq!(out.code(), 0);
    assert_eq!(
        out.stdout(),
        format!("enclos {}\n", env!("CARGO_PKG_VERSION"))
    );
    let out = home.run_piped(&["--help"]);
    assert_eq!(out.code(), 0);
    assert!(out.stdout().contains("Usage"), "{}", out.stdout());
    assert!(serde_json::from_str::<serde_json::Value>(&out.stdout()).is_err());
}

/// `logs` fails when `tail` does, and says so as enclos's own error: what it
/// could read is still shown.
#[cfg(target_os = "macos")]
#[test]
fn logs_fail_when_a_log_cannot_be_read() {
    let home = Home::new();
    home.init(1);
    home.run(&["sandbox", "create", "home"]).ok();
    let logs = home.root.join("sandboxes/home/logs");
    std::fs::create_dir_all(&logs).unwrap();
    std::fs::write(logs.join("gateway.log"), "fine\n").unwrap();
    let hidden = logs.join("proxy.log");
    std::fs::write(&hidden, "hidden\n").unwrap();
    std::fs::set_permissions(&hidden, std::fs::Permissions::from_mode(0o000)).unwrap();
    let out = home.run_piped(&["--json", "logs", "home"]);
    std::fs::set_permissions(&hidden, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(out.code(), 1, "{}", out.stderr());
    assert!(out.stdout().contains("\"fine\""), "{}", out.stdout());
    let last = out.stderr().lines().last().unwrap_or_default().to_owned();
    let said: serde_json::Value =
        serde_json::from_str(&last).unwrap_or_else(|e| panic!("{e}: {}", out.stderr()));
    assert_eq!(said["error"]["exit_code"], 1, "{said}");
    assert!(
        said["error"]["message"].as_str().unwrap().contains("tail"),
        "{said}"
    );
}

/// A policy change while a session runs waits as the pending policy; `policy
/// apply` restarts the sandbox into it. Both in JSON, with no service started:
/// the only session is one this test starts.
#[cfg(target_os = "macos")]
#[test]
fn a_change_while_a_session_runs_waits_and_apply_restarts_into_it() {
    let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
    let home = Home::new();
    home.init(1);
    home.run(&["sandbox", "create", "home"]).ok();
    let _stop = StopOnDrop(&home, "home");
    let mut session = home
        .command(&["exec", "home", "--", "/bin/sleep", "30"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    assert!(eventually(|| {
        home.run(&["sandbox", "show", "home"])
            .stdout()
            .contains("/bin/sleep")
    }));
    let file = home.root.join("sandboxes/home/policy.toml");
    let text = std::fs::read_to_string(&file).unwrap();
    let work = home._dir.path().join("work");
    std::fs::create_dir_all(&work).unwrap();
    std::fs::write(
        &file,
        text.replace(
            "write_add = []",
            &format!("write_add = [\"{}\"]", work.display()),
        ),
    )
    .unwrap();
    let mut edit = home.piped(&["policy", "edit", "home"]);
    edit.env_remove("VISUAL")
        .env("EDITOR", editor(&home, "true"));
    let out = Run(edit.output().unwrap());
    let doc: serde_json::Value = serde_json::from_str(&out.ok().stdout()).unwrap();
    assert_eq!(doc["outcome"]["in_force"], false, "{doc}");
    assert!(doc["outcome"]["pending"]["snapshot"].is_string(), "{doc}");
    let (code, applied) = home.json(&["--yes", "policy", "apply", "home"]);
    let _ = session.wait();
    assert_eq!(code, 0, "{applied}");
    assert_eq!(applied["restarted"]["version"], 2, "{applied}");
    assert!(
        applied["restarted"]["stopped"]["sessions_ended"]
            .as_array()
            .is_some_and(|s| !s.is_empty()),
        "{applied}"
    );
    assert!(applied["restarted"]["started"].is_null(), "{applied}");
    assert!(applied.get("error").is_none(), "{applied}");
}

/// Several sandboxes give one document, one element each, in order; a dry
/// run's elements say what would start; a name that is no sandbox is one
/// error document.
#[cfg(target_os = "macos")]
#[test]
fn several_sandboxes_give_one_document_with_an_element_each() {
    let home = Home::new();
    home.init(1);
    home.run(&["sandbox", "create", "home"]).ok();
    home.run(&["sandbox", "create", "lab"]).ok();
    let (code, stopped) = home.json(&["sandbox", "stop", "home", "lab", "home"]);
    assert_eq!(code, 0, "{stopped}");
    let elements = stopped["sandboxes"].as_array().unwrap();
    assert_eq!(elements.len(), 2, "{stopped}");
    assert_eq!(elements[0]["sandbox"], "home");
    assert_eq!(elements[1]["sandbox"], "lab");
    assert!(elements.iter().all(|e| e["stopped"] == true), "{stopped}");
    for verb in ["start", "restart"] {
        let (code, planned) = home.json(&["--dry-run", "sandbox", verb, "home", "lab"]);
        assert_eq!(code, 0, "{planned}");
        assert_eq!(
            planned["sandboxes"].as_array().unwrap().len(),
            2,
            "{planned}"
        );
        for (element, name) in planned["sandboxes"]
            .as_array()
            .unwrap()
            .iter()
            .zip(["home", "lab"])
        {
            assert_eq!(element["dry_run"], true, "{planned}");
            // The plan says what it would start, as the text does.
            assert!(
                element["changes"].as_array().unwrap().iter().any(|c| c
                    .as_str()
                    .unwrap()
                    .starts_with("install and start the service")),
                "{planned}"
            );
            assert!(
                element["would_start"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|l| l.as_str().unwrap().ends_with(&format!(".{name}.proxy"))),
                "{planned}"
            );
        }
    }
    let out = home.run_piped(&["sandbox", "stop", "home", "nope"]);
    assert_eq!(out.code(), 1);
    let doc: serde_json::Value = serde_json::from_str(&out.stdout()).unwrap();
    assert_eq!(doc["error"]["kind"], "error", "{doc}");
}

/// A broken audit log, in JSON: the result, and an error beside it, exit 1.
#[test]
fn audit_and_verify_in_json() {
    let home = Home::new();
    home.init(3);
    let (_, audit) = home.json(&["audit"]);
    assert_eq!(audit["entries"].as_array().unwrap().len(), 3, "{audit}");
    assert_eq!(audit["entries"][0]["command"], "init");
    assert_eq!(audit["entries"][0]["finished"]["result"], "ok");
    let (code, verified) = home.json(&["audit", "verify"]);
    assert_eq!(code, 0);
    assert_eq!(verified["intact"], true);
    let mut lines = home.audit_lines();
    lines[2] = lines[2].replace("\"command\":\"init\"", "\"command\":\"oops\"");
    home.write_audit_lines(&lines);
    let (code, verified) = home.json(&["audit", "verify"]);
    assert_eq!(code, 1);
    assert_eq!(verified["intact"], false, "{verified}");
    assert_eq!(verified["broken"]["line"], 3, "{verified}");
    assert!(
        verified["error"]["message"]
            .as_str()
            .unwrap()
            .contains("audit.jsonl.damaged"),
        "{verified}"
    );
}

/// `doctor` and `state check` in JSON: a result, with an error beside it
/// when the command fails.
#[cfg(target_os = "macos")]
#[test]
fn doctor_and_state_check_in_json() {
    let home = Home::new();
    let (code, doctor) = home.json(&["doctor"]);
    assert_eq!(code, 0, "{doctor}");
    assert_eq!(doctor["records"]["initialized"], false, "{doctor}");
    let seatbelt = doctor["backends"]
        .as_array()
        .unwrap()
        .iter()
        .find(|b| b["kind"] == "seatbelt")
        .unwrap_or_else(|| panic!("{doctor}"))
        .clone();
    assert_eq!(seatbelt["state"], "runs", "{doctor}");
    assert!(seatbelt["reason"].is_null(), "{doctor}");
    assert!(doctor.get("error").is_none(), "{doctor}");
    home.init(1);
    home.run(&["sandbox", "create", "home"]).ok();
    let (code, check) = home.json(&["state", "check"]);
    assert_eq!(code, 0);
    assert_eq!(check["match"], true, "{check}");
    std::fs::remove_file(home.root.join("sandboxes/home/policy.toml")).unwrap();
    let (code, check) = home.json(&["state", "check"]);
    assert_eq!(code, 1);
    assert_eq!(check["findings"][0]["remedy"]["kind"], "repair", "{check}");
    assert_eq!(check["error"]["exit_code"], 1, "{check}");
    let (code, planned) = home.json(&["--dry-run", "state", "repair"]);
    assert_eq!(code, 0, "{planned}");
    assert_eq!(planned["dry_run"], true, "{planned}");
    assert_eq!(
        planned["findings"][0]["remedy"]["kind"], "repair",
        "{planned}"
    );
    // A repair made says so, apart from one a check would make.
    let (code, repaired) = home.json(&["state", "repair"]);
    assert_eq!(code, 0, "{repaired}");
    assert_eq!(repaired["dry_run"], false, "{repaired}");
    assert_eq!(
        repaired["findings"][0]["remedy"]["kind"], "repaired",
        "{repaired}"
    );
    assert!(repaired.get("error").is_none(), "{repaired}");
    assert_eq!(home.json(&["state", "check"]).1["match"], true);
    std::fs::remove_dir_all(home.root.join("sandboxes/home/home")).unwrap();
    let (code, doctor) = home.json(&["doctor"]);
    assert_eq!(code, 1, "{doctor}");
    assert_eq!(
        doctor["records"]["sandboxes"][0]["next_session"]["state"], "fails",
        "{doctor}"
    );
    assert_eq!(doctor["error"]["exit_code"], 1, "{doctor}");
}

/// `logs --json` writes JSON Lines, every line of every log and no tail
/// header; piped without it, the logs stay text; with none, nothing is on
/// stdout and the hint is on stderr.
#[cfg(target_os = "macos")]
#[test]
fn logs_in_json_are_json_lines() {
    let home = Home::new();
    home.init(1);
    home.run(&["sandbox", "create", "home"]).ok();
    let out = home.run_piped(&["--json", "logs", "home"]);
    assert_eq!(out.code(), 0);
    assert_eq!(out.stdout(), "");
    assert!(
        out.stderr().contains("no service logs yet"),
        "{}",
        out.stderr()
    );
    let logs = home.root.join("sandboxes/home/logs");
    std::fs::create_dir_all(&logs).unwrap();
    // A C1 control and a bidirectional one, which JSON leaves alone: the
    // document escapes them itself.
    std::fs::write(logs.join("gateway.log"), "o\u{9b}ne\u{202e}\n\x1b[2Jtwo\n").unwrap();
    std::fs::write(logs.join("proxy.log"), "three\n").unwrap();
    let out = home.run_piped(&["--json", "logs", "home"]);
    assert_eq!(out.code(), 0, "{}", out.stderr());
    let lines: Vec<String> = out
        .stdout()
        .lines()
        .map(|l| {
            let doc: serde_json::Value = serde_json::from_str(l).unwrap();
            doc["line"].as_str().unwrap().to_owned()
        })
        .collect();
    assert_eq!(lines.len(), 3, "{lines:?}");
    assert!(!lines.iter().any(|l| l.contains("==>")), "{lines:?}");
    for want in ["o\u{9b}ne\u{202e}", "\x1b[2Jtwo", "three"] {
        assert!(lines.iter().any(|l| l == want), "{want:?} in {lines:?}");
    }
    for raw in ['\x1b', '\u{9b}', '\u{202e}'] {
        assert!(!out.stdout().contains(raw), "{raw:?} in {}", out.stdout());
    }
    let out = home.run_piped(&["logs", "home"]);
    assert!(
        out.ok().stdout().contains("\\u{1b}[2Jtwo"),
        "{}",
        out.stdout()
    );
}

/// A JSON command that starts the proxy ends, and its reader sees the end
/// of the document: no program it starts holds the stdout it was given.
#[cfg(target_os = "macos")]
#[test]
fn a_piped_command_that_starts_the_proxy_ends_its_document() {
    let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
    let home = Home::new();
    home.init(1);
    home.run(&["sandbox", "create", "home"]).ok();
    let _stop = StopOnDrop(&home, "home");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_enclos"));
    cmd.args(["policy", "test", "home"])
        .env("ENCLOS_HOME", &home.root)
        .env("HOME", home._dir.path())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let child = cmd.spawn().unwrap();
    let pid = child.id();
    let (done, wait) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = done.send(child.wait_with_output());
    });
    let Ok(out) = wait.recv_timeout(std::time::Duration::from_secs(300)) else {
        // Only the enclos this test started.
        let _ = Command::new("/bin/kill")
            .args(["-KILL", &pid.to_string()])
            .status();
        panic!(
            "the document's reader still waits: a program enclos started holds its stdout or stderr"
        );
    };
    let out = out.unwrap();
    let doc: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(out.status.code(), Some(0), "{doc}");
    assert_eq!(doc["ready"], true, "{doc}");
    assert!(doc.get("error").is_none(), "{doc}");
    assert_eq!(doc["sandbox"], "home", "{doc}");
    assert!(
        doc["probes"].as_array().is_some_and(|p| !p.is_empty()),
        "{doc}"
    );
}

/// A secret's value is never in a document.
#[cfg(target_os = "macos")]
#[test]
fn a_secret_set_in_json_shows_no_value() {
    use std::io::Write;
    let home = Home::new();
    let keychain = TestKeychain::new(&home);
    home.init(1);
    home.run(&["sandbox", "create", "home"]).ok();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_enclos"));
    cmd.args(["secret", "set", "home/telegram"])
        .env("ENCLOS_HOME", &home.root)
        .env("HOME", home._dir.path())
        .env("ENCLOS_KEYCHAIN", &keychain.0)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"tok-123:abc\n")
        .unwrap();
    let out = Run(child.wait_with_output().unwrap());
    let doc: serde_json::Value = serde_json::from_str(&out.ok().stdout()).unwrap();
    assert_eq!(doc["secret"], "home/telegram", "{doc}");
    assert_eq!(doc["new"], true);
    assert!(!out.stdout().contains("tok-123"), "{}", out.stdout());
    assert!(!out.stderr().contains("tok-123"), "{}", out.stderr());
    let mut list = Command::new(env!("CARGO_BIN_EXE_enclos"));
    list.args(["secret", "list", "home"])
        .env("ENCLOS_HOME", &home.root)
        .env("HOME", home._dir.path())
        .env("ENCLOS_KEYCHAIN", &keychain.0);
    let out = Run(list.output().unwrap());
    let doc: serde_json::Value = serde_json::from_str(&out.ok().stdout()).unwrap();
    assert_eq!(doc["secrets"][0]["name"], "telegram", "{doc}");
    assert!(!out.stdout().contains("tok-123"));
    assert!(!out.stderr().contains("tok-123"));
}

/// ADR 0006's comparison: under the allow-by-default baseline enclos used
/// before, the probes a new sandbox has are closed as under deny by default
/// (`every_escape_probe_fails_in_a_new_sandbox`), the host-service ones where
/// CI asks for them, and a session runs a shell, Python, git and curl
/// through the proxy under either.
#[cfg(target_os = "macos")]
#[test]
fn every_escape_probe_fails_under_allow_by_default_too() {
    let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
    let home = Home::new();
    home.init(1);
    home.run(&["sandbox", "create", "home"]).ok();
    let _stop = StopOnDrop(&home, "home");
    // The folder the launch agents probe writes in, as a Mac has it.
    std::fs::create_dir_all(home._dir.path().join("Library/LaunchAgents")).unwrap();
    let host_services = host_service_probes_asked();
    // CI runs them: a workflow that lost the variable must not pass quietly.
    if std::env::var("GITHUB_ACTIONS").as_deref() == Ok("true") {
        assert!(
            host_services,
            "CI runs the host-service probes: ENCLOS_HOST_SERVICE_PROBES=1 is missing"
        );
    }
    let mut args = vec!["policy", "test", "home"];
    if host_services {
        args.push("--host-services");
    }
    let out = Run(home
        .command(&args)
        .env("ENCLOS_SEATBELT_BASELINE", "allow-default")
        .output()
        .unwrap());
    let report = out.stdout();
    assert_eq!(out.code(), 0, "stdout: {report}\nstderr: {}", out.stderr());
    // Said, on stderr and in the verdict: no sandbox runs on it.
    assert!(
        out.stderr().contains("compiled from (allow default)"),
        "{}",
        out.stderr()
    );
    assert!(
        report.contains("On the (allow default) comparison baseline"),
        "{report}"
    );
    let compiled = std::fs::read_dir(home.root.join("sandboxes/home/compiled"))
        .unwrap()
        .map(|e| std::fs::read_to_string(e.unwrap().path()).unwrap())
        .collect::<Vec<_>>();
    assert!(
        compiled.iter().any(|c| c.contains("\n(allow default)\n")),
        "no allow-by-default policy was compiled"
    );
    assert!(!report.contains("OPEN"), "{report}");
    assert!(!report.contains("NOT RUN"), "{report}");
    // The routes a new sandbox has; those that need files on the deny list
    // or a second sandbox are in `every_escape_probe_fails_in_a_new_sandbox`.
    // On this baseline LaunchServices and Apple Events close only on the
    // rules' own refusals (-54, -600): the rules are what is shown.
    let mut routes = vec![
        "enclos files",
        "writes",
        "renames",
        "clones",
        "network",
        "dns",
        "signals",
        "terminals",
        "pasteboard",
    ];
    if host_services {
        routes.extend([
            "launchservices",
            "apple events",
            "launchd",
            "preferences",
            "launch agents",
        ]);
    }
    for route in routes {
        assert!(
            report
                .lines()
                .any(|l| l.trim_start().starts_with("closed ") && l.contains(&format!(" {route} "))),
            "no closed {route} probe:\n{report}"
        );
    }

    // ADR 0006's comparison: every probe closed on the earlier baseline is
    // closed on the one enclos ships.
    let closed = |baseline: &str| {
        let mut args = vec!["--json"];
        args.extend(&args_for_json(host_services));
        let out = Run(home
            .piped(&args)
            .env("ENCLOS_SEATBELT_BASELINE", baseline)
            .output()
            .unwrap());
        let doc: serde_json::Value = serde_json::from_str(&out.stdout())
            .unwrap_or_else(|e| panic!("{baseline}: {e}: {}", out.stderr()));
        assert_eq!(doc["baseline"], baseline.replace('-', "_"), "{doc}");
        // What closes LaunchServices and Apple Events: the baseline on
        // (deny default), the rules on (allow default).
        for p in doc["probes"].as_array().unwrap() {
            if host_services && (p["route"] == "launchservices" || p["route"] == "apple events") {
                let by = match baseline {
                    "deny-default" => serde_json::json!("baseline"),
                    _ => serde_json::Value::Null,
                };
                assert_eq!(p["closed_by"], by, "{baseline}: {p}");
            }
        }
        doc["probes"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|p| p["outcome"] == "closed")
            .map(|p| format!("{}: {}", p["route"], p["name"]))
            .collect::<std::collections::BTreeSet<_>>()
    };
    let before = closed("allow-default");
    let now = closed("deny-default");
    let lost: Vec<_> = before.difference(&now).collect();
    assert!(lost.is_empty(), "closed only on (allow default): {lost:?}");

    // Any other value is neither baseline: refused, before anything runs.
    for value in ["1", "", "Allow-Default"] {
        let out = Run(home
            .command(&["exec", "home", "--", "/bin/echo", "ran"])
            .env("ENCLOS_SEATBELT_BASELINE", value)
            .output()
            .unwrap());
        assert_eq!(out.code(), 125, "{value:?}: {}", out.stdout());
        assert!(!out.stdout().contains("ran"), "{value:?}");
        assert!(
            out.stderr().contains("ENCLOS_SEATBELT_BASELINE is"),
            "{value:?}: {}",
            out.stderr()
        );
    }
}

/// `init` with a baseline value that names neither says why Seatbelt is
/// not available, rather than only that no backend is.
#[cfg(target_os = "macos")]
#[test]
fn init_says_why_a_bad_baseline_value_leaves_no_backend() {
    let home = Home::new();
    let out = Run(home
        .command(&["init"])
        .env("ENCLOS_SEATBELT_BASELINE", "1")
        .output()
        .unwrap());
    let said = out.ok().stdout();
    assert!(
        said.contains("No backend is available on this host yet:\n  seatbelt: ENCLOS_SEATBELT_BASELINE is \"1\""),
        "{said}"
    );
    // Said again at a later run, while the value stays.
    let out = Run(home
        .command(&["init"])
        .env("ENCLOS_SEATBELT_BASELINE", "1")
        .output()
        .unwrap());
    assert!(
        out.ok()
            .stdout()
            .contains("No backend is available on this host yet:\n  seatbelt: ENCLOS_SEATBELT_BASELINE is \"1\""),
        "{}",
        out.stdout()
    );
    let out = home
        .piped(&["init"])
        .env("ENCLOS_SEATBELT_BASELINE", "1")
        .output()
        .unwrap();
    let doc: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(doc["default_backend"], serde_json::Value::Null, "{doc}");
    assert_eq!(doc["unavailable"][0]["backend"], "seatbelt", "{doc}");
    assert!(
        doc["unavailable"][0]["reason"]
            .as_str()
            .unwrap()
            .contains("it takes `deny-default` or `allow-default`"),
        "{doc}"
    );
    // Once the value is gone, Seatbelt is available: init writes it in the
    // config written meanwhile, and says so.
    let said = home.run(&["init"]).ok().stdout();
    assert!(!said.contains("No backend is available"), "{said}");
    assert!(
        said.contains("Default backend: seatbelt, now written to"),
        "{said}"
    );
    let config = std::fs::read_to_string(home.root.join("config.toml")).unwrap();
    assert!(
        config.contains("default_backend = \"seatbelt\""),
        "{config}"
    );
}

/// Programs run, and TLS goes through, on either baseline: a page the
/// policy allows answers 200 over HTTP and HTTPS through the proxy. Needs
/// the network, as CI has.
#[cfg(target_os = "macos")]
#[test]
fn programs_and_tls_run_through_the_proxy_on_either_baseline() {
    let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
    let home = Home::new();
    home.init(1);
    home.run(&["sandbox", "create", "home"]).ok();
    let _stop = StopOnDrop(&home, "home");
    home.run(&["policy", "allow", "home", "example.com", "--yes"])
        .ok();
    let script = "echo hi && /usr/bin/python3 -c 'import ssl; print(2)' && /usr/bin/git --version >/dev/null && /usr/bin/curl -sS -o /dev/null -w '%{http_code} ' http://example.com/ && /usr/bin/curl -sS -o /dev/null -w '%{http_code}' https://example.com/";
    for baseline in ["allow-default", "deny-default"] {
        let out = Run(home
            .command(&["exec", "home", "--", "/bin/sh", "-c", script])
            .env("ENCLOS_SEATBELT_BASELINE", baseline)
            .output()
            .unwrap());
        assert_eq!(
            out.stdout(),
            "hi\n2\n200 200",
            "{baseline}: stderr: {}",
            out.stderr()
        );
        assert_eq!(
            out.stderr().contains("compiled from (allow default)"),
            baseline == "allow-default",
            "{baseline}: {}",
            out.stderr()
        );
    }
}

/// A service never runs on the comparison baseline, nor on a value that is
/// neither: `enclos launch`, which a service is, refuses before it starts
/// anything.
#[cfg(target_os = "macos")]
#[test]
fn a_service_refuses_any_baseline_but_deny_default() {
    let home = Home::new();
    home.init(1);
    home.run(&["sandbox", "create", "home"]).ok();
    for (value, why) in [
        ("allow-default", "asks for allow-default"),
        ("x", "it takes `deny-default` or `allow-default`"),
    ] {
        let out = Run(home
            .command(&["launch", "home", "gateway"])
            .env("ENCLOS_SEATBELT_BASELINE", value)
            .output()
            .unwrap());
        assert_ne!(out.code(), 0, "{value}");
        assert!(
            out.stderr().contains(why)
                && out
                    .stderr()
                    .contains("a service runs only on (deny default)"),
            "{value}: {}",
            out.stderr()
        );
    }
    let show = home.run(&["sandbox", "show", "home"]).ok().stdout();
    assert!(show.contains("no sessions running"), "{show}");
}

/// `policy test home`, with the host-service probes where CI asks for them.
#[cfg(target_os = "macos")]
fn args_for_json(host_services: bool) -> Vec<&'static str> {
    let mut args = vec!["policy", "test", "home"];
    if host_services {
        args.push("--host-services");
    }
    args
}

/// Whether the host-service probes run here: only where CI asks for them
/// by name. Said on stderr when they do not, so a run elsewhere is not
/// read as having shown them.
#[cfg(target_os = "macos")]
fn host_service_probes_asked() -> bool {
    let asked = std::env::var("ENCLOS_HOST_SERVICE_PROBES").as_deref() == Ok("1");
    if !asked {
        eprintln!("host-service probes not run: set ENCLOS_HOST_SERVICE_PROBES=1 (CI does)");
    }
    asked
}

/// The JSON of the commands that change a policy: an allow made, a
/// rollback, a refresh and a discard, and the pending policy shown, or an
/// error when there is none.
#[cfg(target_os = "macos")]
#[test]
fn the_commands_that_change_a_policy_print_their_documents() {
    let home = Home::new();
    home.init(1);
    home.run(&["sandbox", "create", "home"]).ok();
    let (code, allowed) = home.json(&["policy", "allow", "home", "a.example.com"]);
    assert_eq!(code, 0, "{allowed}");
    assert_eq!(allowed["version"], 2, "{allowed}");
    assert_eq!(allowed["changed"], true, "{allowed}");
    assert_eq!(allowed["destination"], "a.example.com", "{allowed}");
    let (code, rolled) = home.json(&["policy", "rollback", "home", "--to", "1"]);
    assert_eq!(code, 0, "{rolled}");
    assert_eq!(rolled["version"], 3, "{rolled}");
    assert_eq!(rolled["changed"], true, "{rolled}");
    let (code, refreshed) = home.json(&["policy", "refresh", "home"]);
    assert_eq!(code, 0, "{refreshed}");
    assert_eq!(refreshed["changed"], false, "{refreshed}");
    let (code, pending) = home.json(&["policy", "show", "home", "--pending"]);
    assert_eq!(code, 1, "{pending}");
    assert_eq!(pending["error"]["kind"], "error", "{pending}");
    let (code, discarded) = home.json(&["policy", "discard", "home"]);
    assert_eq!(code, 0, "{discarded}");
    assert_eq!(discarded["version"], 3, "{discarded}");
    assert_eq!(
        discarded["dropped_pending"],
        serde_json::Value::Null,
        "{discarded}"
    );
}

/// `logs` to a reader that has left stops with exit 0 and no error, in
/// text and in JSON: whoever read, such as `head`, has what it wanted.
#[cfg(target_os = "macos")]
#[test]
fn logs_to_a_reader_that_left_stop_quietly() {
    let home = Home::new();
    home.init(1);
    home.run(&["sandbox", "create", "home"]).ok();
    let logs = home.root.join("sandboxes/home/logs");
    std::fs::create_dir_all(&logs).unwrap();
    std::fs::write(logs.join("gateway.log"), "one\ntwo\nthree\n".repeat(20)).unwrap();
    for json in [false, true] {
        let (reader, writer) = std::io::pipe().unwrap();
        drop(reader);
        let mut logs = home.piped(&["logs", "home"]);
        if json {
            logs.arg("--json");
        }
        let out = Run(logs.stdout(writer).stderr(Stdio::piped()).output().unwrap());
        assert_eq!(out.code(), 0, "{json}: {}", out.stderr());
        assert!(!out.stderr().contains("error"), "{json}: {}", out.stderr());
    }
}

/// A sandbox whose proxy cannot hold its port is said to have failed to
/// start, in JSON, for that sandbox and for the command.
#[cfg(target_os = "macos")]
#[test]
fn a_start_whose_proxy_cannot_listen_fails_in_json() {
    let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
    let home = Home::new();
    home.init(1);
    let (_, created) = home.json(&["sandbox", "create", "home"]);
    let _stop = StopOnDrop(&home, "home");
    let port = created["proxy_port"].as_u64().unwrap() as u16;
    let _held = std::net::TcpListener::bind(("127.0.0.1", port)).unwrap();
    let (code, started) = home.json(&["sandbox", "start", "home"]);
    assert_eq!(code, 1, "{started}");
    let one = &started["sandboxes"][0];
    assert_eq!(one["proxy_started"], false, "{started}");
    assert_eq!(one["error"]["exit_code"], 1, "{started}");
}
