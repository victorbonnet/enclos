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
        cmd.args(args)
            .env("ENCLOS_HOME", &self.root)
            .env("HOME", self._dir.path());
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
        .args(["init"])
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

/// Tests that start proxies take turns: proxy ports are the host's, shared
/// by every test's enclos folder.
#[cfg(target_os = "macos")]
static HOST_PORTS: std::sync::Mutex<()> = std::sync::Mutex::new(());

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
    ] {
        let file = user.join(path);
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(file, contents).unwrap();
    }
    let policy_file = home.root.join("sandboxes/home/policy.toml");
    let policy = std::fs::read_to_string(&policy_file).unwrap().replace(
        "write_add = []\nread_deny_add = []",
        "write_add = [\"~/work\"]\nread_deny_add = [\"~/work/.secrets\", \"~/work/.env\"]",
    );
    std::fs::write(&policy_file, policy).unwrap();
    // `policy allow` applies the file's other changes with `--yes`.
    home.run(&["policy", "allow", "home", "example.com", "--yes"])
        .ok();
    // The host-service probes act on the host if a rule fails: only where
    // CI asks for them by name, never because some tool set `CI`.
    let host_services = std::env::var("ENCLOS_HOST_SERVICE_PROBES").as_deref() == Ok("1");
    let mut args = vec!["policy", "test", "home"];
    if host_services {
        args.push("--host-services");
    }
    let out = home.run(&args);
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
    let mut routes = vec![
        "sensitive files",
        "enclos files",
        "other sandboxes",
        "writes",
        "launch agents",
        "network",
        "dns",
        "signals",
        "pasteboard",
        "at",
    ];
    if host_services {
        routes.extend(["launchservices", "apple events", "launchd", "preferences"]);
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
        "the sandbox's own policy.toml",
        "the sandbox's own compiled folder",
        "write in ~/Library/LaunchAgents",
        "lab/home",
    ] {
        assert!(closed(probe), "{probe} is not shown closed:\n{report}");
    }
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
    assert!(
        report.contains("by Seatbelt itself rather than"),
        "{report}"
    );
    assert!(report.contains("probes were shown closed"), "{report}");
    // Nothing a probe wrote stayed: the files under the grant and the
    // sandbox's policy are as the test left them.
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
    assert!(
        std::fs::read_to_string(&policy_file)
            .unwrap()
            .contains("~/work/.env")
    );
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
        out.stderr().contains("probes got through"),
        "{}",
        out.stderr()
    );
    assert!(!out.stdout().contains("shown closed"), "{}", out.stdout());
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
    assert!(out.stderr().contains("home/tmp"), "{}", out.stderr());
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
fn connect_refuses_a_port_another_program_listens_on() {
    let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
    let home = Home::new();
    home.init(1);
    home.run(&["sandbox", "create", "home"]).ok();
    let _stop = StopOnDrop(&home, "home");
    let port = proxy_port(&home);
    // Another program takes the sandbox's proxy port first.
    let _squatter = std::net::TcpListener::bind(("127.0.0.1", port)).unwrap();
    let out = home.run(&["connect", "home", "--", "/usr/bin/true"]);
    assert_eq!(out.code(), 1);
    assert!(
        out.stderr().contains("in use by another program"),
        "{}",
        out.stderr()
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
    // sent below reaches this enclos alone, as a terminal's Ctrl-C reaches
    // it beside a program that handles it and goes on.
    let script = "/bin/sleep 2; exit 3";
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
    let listen = format!("127.0.0.1:{port}");
    let args = ["proxy", "run", "home", "--record", "--listen", &listen];
    // With the port taken, it records nothing: a recorded proxy owns its
    // port, which a service's `launch` relies on.
    {
        let _squatter = std::net::TcpListener::bind(("127.0.0.1", port)).unwrap();
        let out = home.run(&args);
        assert_eq!(out.code(), 1, "{}", out.stderr());
        assert!(proxy_pid(&home).is_none());
        assert!(!home.audit_lines().iter().any(|l| l.contains("proxy start")));
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
    let show = home.run(&["sandbox", "show", "home"]);
    let out = show.ok().stdout();
    assert!(out.contains("\n  agents: none\n"), "{out}");
    assert!(out.contains(&format!("\n  {untracked}\n")), "{out}");

    // Adopting records it without running Hermes (there is none to run),
    // and says so instead of the next steps after a creation.
    let before = home.audit_lines().len();
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

    // Removing the record alone keeps the files, so Hermes still has the agent.
    let rm = home.run(&["agent", "rm", "home/scout", "--keep-data"]);
    assert!(
        rm.ok()
            .stdout()
            .contains("enclos reports it as one it does not track"),
        "{}",
        rm.stdout()
    );
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
