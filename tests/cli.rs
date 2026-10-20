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
    let out = home.run(&["policy", "allow", "home", "*.com"]);
    assert_eq!(out.code(), 1);
    assert!(out.stderr().contains("public suffix"), "{}", out.stderr());
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

    // The command's exit code comes back; it wrote only in its home.
    let script = "echo hi > \"$HOME/hello\"; echo no > \"$HOME/../escaped\" 2>/dev/null; exit 3";
    let out = home.run(&["connect", "home", "--", "/bin/sh", "-c", script]);
    assert_eq!(out.code(), 3, "stderr: {}", out.stderr());
    let sandbox = home.root.join("sandboxes/home");
    assert!(sandbox.join("home/hello").exists());
    assert!(!sandbox.join("escaped").exists());

    // Through the proxy, a destination not on the allowlist is refused and logged.
    let curl = "/usr/bin/curl -s -o /dev/null -w '%{http_code}' https://example.com/ || true";
    home.run(&["connect", "home", "--", "/bin/sh", "-c", curl])
        .ok();
    let denied = home.run(&["net", "denied", "home"]);
    assert!(
        denied
            .ok()
            .stdout()
            .contains("example.com:443  not-allowed"),
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
        "enclos files",
        "other sandboxes",
        "writes",
        "network",
        "dns",
        "signals",
        "pasteboard",
    ];
    if host_services {
        routes.extend(["launchservices", "apple events", "launchd", "preferences"]);
    }
    for route in routes {
        let closed = report
            .lines()
            .any(|l| l.trim_start().starts_with("closed ") && l.contains(&format!(" {route} ")));
        assert!(closed, "no closed {route} probe:\n{report}");
    }
    assert!(report.contains("probes were shown closed"), "{report}");
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
    // Allowing the destination the proxy probe asks for opens that route:
    // the proxy lets the request through and answers 502, as the name does
    // not resolve. Nothing leaves this host.
    home.run(&["policy", "allow", "home", "probe.enclos.invalid", "--yes"])
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
    let show = home.run(&["sandbox", "show", "home"]).ok().stdout();
    let port: u16 = show
        .split("proxy port ")
        .nth(1)
        .and_then(|rest| rest.lines().next())
        .and_then(|p| p.trim().parse().ok())
        .unwrap();
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
