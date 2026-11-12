//! `enclos dashboard` for real (ADR 0040): only in CI's `bubblewrap` job,
//! on GitHub's Ubuntu runners, since it runs a bubblewrap sandbox, starts
//! scopes and services in the runner's user manager, and adds a second user
//! to the runner. Hermes is not installed there: a stand-in for `hermes
//! dashboard --port 0` serves a page holding a token of its own on
//! 127.0.0.1, at a port the kernel picks, in the sandbox's network
//! namespace.
#![cfg(target_os = "linux")]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Output, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tempfile::TempDir;

/// Whether to run these tests: they refuse anywhere but a GitHub-hosted
/// runner, in CI's `bubblewrap` job, which sets `ENCLOS_BUBBLEWRAP_TESTS`.
fn on_a_runner() -> bool {
    if std::env::var("ENCLOS_BUBBLEWRAP_TESTS").as_deref() != Ok("1") {
        eprintln!("dashboard tests not run: CI's bubblewrap job runs them");
        return false;
    }
    let var = |name: &str| std::env::var(name).unwrap_or_default();
    assert!(
        var("GITHUB_ACTIONS") == "true" && var("RUNNER_ENVIRONMENT") == "github-hosted",
        "these tests run bubblewrap sandboxes and add a user to the host: they run only on a GitHub-hosted runner"
    );
    true
}

/// The user the tests add, whose connections the dashboard must close.
const OTHER: &str = "enclos-ci-other";

/// The stand-in for Hermes's dashboard, in Python, between single quotes:
/// a page with a token of its own, on 127.0.0.1:0.
const STAND_IN_DASHBOARD: &str = r#"
import http.server, os
token = os.urandom(8).hex()
class Page(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = ("stand-in dashboard, token " + token + "\n").encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
server = http.server.HTTPServer(("127.0.0.1", 0), Page)
print("listening on", server.server_address[1], flush=True)
server.serve_forever()
"#;

/// A client, in Python, run as the second user: connects to 127.0.0.1 at
/// the port given, asks for the page, and prints how many bytes came back.
const CLIENT: &str = r#"
import socket, sys
c = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=10)
got = b""
try:
    c.sendall(b"GET / HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n")
    while True:
        chunk = c.recv(4096)
        if not chunk:
            break
        got += chunk
except OSError as e:
    print("ended by", type(e).__name__)
print("bytes", len(got))
print("got", got[:120])
"#;

/// A sandbox `lab` on the bubblewrap backend, `assistant` template, in an
/// `ENCLOS_HOME` of its own under the runner's home, with Hermes recorded
/// as its runtime and the stand-in on its `PATH`; stopped when dropped.
struct Lab {
    root: TempDir,
}

impl Lab {
    fn new() -> Lab {
        let home = PathBuf::from(std::env::var_os("HOME").expect("HOME"));
        let lab = Lab {
            root: tempfile::Builder::new()
                .prefix("enclos-ci-")
                .tempdir_in(home)
                .unwrap(),
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
        lab.with_stand_in_hermes();
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

    fn state(&self) -> enclos::state::sqlite::SqliteStateStore {
        let layout = enclos::layout::Layout::at(self.root.path());
        enclos::state::sqlite::SqliteStateStore::new(
            layout.state_db(),
            layout.state_lock(),
            enclos::state::Wait::Command,
        )
    }

    /// Records Hermes as `lab`'s runtime, as `runtime install` would, and
    /// puts the stand-in where its installer puts `hermes`.
    fn with_stand_in_hermes(&self) {
        use enclos::state::StateStore;
        let state = self.state();
        let lock = state.lock().unwrap();
        let mut record = state.get(&"lab".parse().unwrap()).unwrap().unwrap();
        record.runtime = Some(enclos::model::runtime::RuntimeKind::Hermes);
        state.put(&lock, &record).unwrap();
        drop(lock);
        let bin = self.root.path().join("sandboxes/lab/home/.local/bin");
        std::fs::create_dir_all(&bin).unwrap();
        let hermes = bin.join("hermes");
        std::fs::write(
            &hermes,
            format!(
                "#!/bin/sh\n[ \"$1\" = dashboard ] || exit 64\nexec /usr/bin/python3 -I -c '{STAND_IN_DASHBOARD}'\n"
            ),
        )
        .unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&hermes, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    fn proxy_port(&self) -> u16 {
        use enclos::state::StateStore;
        let record = self.state().get(&"lab".parse().unwrap()).unwrap().unwrap();
        record.proxy_port
    }

    /// `lab`'s open sessions of `kind`.
    fn open_sessions(&self, kind: enclos::model::session::SessionKind) -> usize {
        use enclos::state::StateStore;
        let sessions = self.state().sessions(&"lab".parse().unwrap(), true);
        sessions.unwrap().iter().filter(|s| s.kind == kind).count()
    }

    /// Starts `enclos dashboard lab` and waits for the address it prints.
    fn dashboard(&self) -> Dashboard {
        let mut child = self
            .command(&["dashboard", "lab"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let said = Arc::new(Mutex::new(String::new()));
        let stderr = child.stderr.take().unwrap();
        let heard = Arc::clone(&said);
        std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                let mut heard = heard.lock().unwrap();
                heard.push_str(&line);
                heard.push('\n');
            }
        });
        let stdout = child.stdout.take().unwrap();
        let (sent, url) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut line = String::new();
            let _ = BufReader::new(stdout).read_line(&mut line);
            let _ = sent.send(line);
        });
        let url = match url.recv_timeout(Duration::from_secs(180)) {
            Ok(line) if !line.is_empty() => line.trim().to_owned(),
            other => {
                let _ = child.kill();
                let logs = self.command(&["logs", "lab"]).output().unwrap();
                panic!(
                    "no address: {other:?}; {}\nenclos logs lab:\n{}",
                    said.lock().unwrap(),
                    String::from_utf8_lossy(&logs.stdout)
                );
            }
        };
        Dashboard { child, url, said }
    }
}

impl Drop for Lab {
    /// Its services, the namespace holder's included, would otherwise run
    /// on in the runner's user manager.
    fn drop(&mut self) {
        let _ = self.command(&["sandbox", "stop", "lab"]).output();
    }
}

/// A running `enclos dashboard lab`.
struct Dashboard {
    child: Child,
    url: String,
    /// What it said on stderr so far.
    said: Arc<Mutex<String>>,
}

impl Dashboard {
    /// Sends it SIGINT, as Ctrl-C does, and waits for it to end.
    fn interrupt(&mut self) -> std::process::ExitStatus {
        let pid = self.child.id().to_string();
        let sent = Command::new("kill").args(["-INT", &pid]).status().unwrap();
        assert!(sent.success());
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                return status;
            }
            assert!(Instant::now() < deadline, "it did not end on SIGINT");
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    fn said(&self) -> String {
        self.said.lock().unwrap().clone()
    }
}

impl Drop for Dashboard {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

/// What `GET /` at 127.0.0.1:`port` answers this user, whole.
fn page(port: u16) -> String {
    let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    write!(stream, "GET / HTTP/1.0\r\nHost: 127.0.0.1:{port}\r\n\r\n").unwrap();
    let mut answer = String::new();
    stream.read_to_string(&mut answer).unwrap();
    answer
}

/// The second user, added once to this runner.
fn other_user() {
    let known = Command::new("id").arg(OTHER).output().unwrap();
    if !known.status.success() {
        let added = Command::new("sudo")
            .args(["-n", "useradd", "--no-create-home", "--shell"])
            .args(["/usr/sbin/nologin", OTHER])
            .status()
            .unwrap();
        assert!(added.success(), "sudo useradd {OTHER}");
    }
}

/// What [`CLIENT`], run as the second user, says of 127.0.0.1:`port`.
fn as_other_user(port: u16) -> String {
    let out = Command::new("sudo")
        .args(["-n", "-u", OTHER, "/usr/bin/python3", "-I", "-c", CLIENT])
        .arg(port.to_string())
        .current_dir("/")
        .output()
        .unwrap();
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// The audit entries of `command`, as `enclos audit --json` gives them.
fn audited(lab: &Lab, command: &str) -> Vec<serde_json::Value> {
    let out = lab.ok(&["--json", "audit"]);
    let all: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    all["entries"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["command"] == command)
        .cloned()
        .collect()
}

/// The page goes to the user running the command, and a second user's
/// connection is closed with not a byte, while that user's connection to
/// another local server is served; `status` names the command and no
/// address; a second run is refused, naming the first, which serves on;
/// SIGINT ends the session and the listener, and both are audited.
#[test]
fn on_a_runner_the_dashboard_serves_its_user_alone_until_ctrl_c() {
    if !on_a_runner() {
        return;
    }
    other_user();
    let lab = Lab::new();
    let port = lab.proxy_port();
    let mut first = lab.dashboard();
    assert_eq!(first.url, format!("http://127.0.0.1:{port}/"));

    let answer = page(port);
    assert!(answer.starts_with("HTTP/1.0 200"), "{answer}");
    assert!(answer.contains("stand-in dashboard, token "), "{answer}");

    let refused = as_other_user(port);
    assert!(refused.contains("bytes 0"), "{refused}");
    assert!(!refused.contains("token"), "{refused}");
    // The control: the second user reaches this user's other servers.
    let control = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let control_port = control.local_addr().unwrap().port();
    std::thread::spawn(move || {
        if let Ok((mut stream, _)) = control.accept() {
            let _ = stream.write_all(b"control\n");
        }
    });
    let served = as_other_user(control_port);
    assert!(served.contains("bytes 8"), "{served}");
    let uid = String::from_utf8(
        Command::new("id")
            .args(["-u", OTHER])
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();
    let said = first.said();
    assert!(
        said.contains(&format!(
            "closed a connection from the user with uid {}",
            uid.trim()
        )),
        "{said}"
    );

    let status = String::from_utf8(lab.ok(&["status", "lab"]).stdout).unwrap();
    assert!(status.contains("`enclos dashboard lab`"), "{status}");
    assert!(!status.contains("http://"), "{status}");

    let second = lab.command(&["dashboard", "lab"]).output().unwrap();
    let why = String::from_utf8_lossy(&second.stderr);
    assert_eq!(second.status.code(), Some(1), "{second:?}");
    assert!(why.contains("already has a dashboard"), "{why}");
    assert!(why.contains(&format!("pid {}", first.child.id())), "{why}");
    assert!(page(port).contains("stand-in dashboard"));

    let exit = first.interrupt();
    let said = first.said();
    assert!(exit.success(), "{exit:?}: {said}");
    assert!(said.contains("is closed"), "{said}");
    assert!(TcpStream::connect((Ipv4Addr::LOCALHOST, port)).is_err());
    assert_eq!(
        lab.open_sessions(enclos::model::session::SessionKind::Exec),
        0
    );

    let started = audited(&lab, "dashboard");
    let ended = audited(&lab, "dashboard end");
    assert_eq!(started.len(), 1, "{started:?}");
    assert_eq!(ended.len(), 1, "{ended:?}");
    assert_eq!(started[0]["finished"]["result"], "ok", "{started:?}");
    assert_eq!(ended[0]["finished"]["result"], "ok", "{ended:?}");
    let message = ended[0]["finished"]["message"].as_str().unwrap();
    assert!(message.contains("told to end"), "{message}");
}
