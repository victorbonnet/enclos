//! Runs the `enclos` binary against a temporary `ENCLOS_HOME`, so tests never
//! touch the real home folder.

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
        cmd.args(args).env("ENCLOS_HOME", &self.root);
        cmd
    }

    fn run(&self, args: &[&str]) -> Run {
        Run(self.command(args).output().unwrap())
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
        .args(["init"])
        .env("ENCLOS_HOME", "relative/enclos")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("must be an absolute path"));
}
