//! A mount of the host that comes and goes while sessions start (design §5,
//! What `wrap` does at each launch). bubblewrap before 0.13, as the runners
//! have, reads the mount table and then remounts each mount read-only: one
//! taken away in between fails its setup. The control, bubblewrap alone,
//! fails so at times; every session starts all the same, its command run
//! once.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use super::{Lab, on_a_runner, text};

/// Where the churn mounts its tmpfs: under the runner's `/run`, as systemd
/// mounts a service's credentials there.
const CHURNED: &str = "/run/enclos-ci-churn";

/// What bubblewrap says when a mount it read is gone as it remounts it.
const MOUNT_CHANGED: &str = "Unable to apply mount flags: remount";

/// As root: mounts a tmpfs at the folder named first, holds it `on`
/// seconds, takes it away, waits `off` seconds, and again, as long as the
/// file named second is there; then removes the folder.
const CHURN: &str = r#"
import ctypes, os, sys, time
libc = ctypes.CDLL(None, use_errno=True)
path, flag, on, off = sys.argv[1], sys.argv[2], float(sys.argv[3]), float(sys.argv[4])
os.makedirs(path, exist_ok=True)
while os.path.exists(flag):
    if libc.mount(b"enclos-churn", path.encode(), b"tmpfs", 0, None) != 0:
        sys.exit("mount: " + os.strerror(ctypes.get_errno()))
    time.sleep(on)
    if libc.umount2(path.encode(), 0) != 0:
        sys.exit("umount: " + os.strerror(ctypes.get_errno()))
    time.sleep(off)
os.rmdir(path)
"#;

/// A tmpfs mounted and taken away at `CHURNED` until dropped. The test
/// stops it through a file the loop looks for, and signals nothing.
struct Churn {
    flag: PathBuf,
    child: Child,
}

impl Churn {
    fn start(flag: &Path, on: Duration, off: Duration) -> Churn {
        std::fs::write(flag, "").unwrap();
        let child = Command::new("sudo")
            .args(["-n", "/usr/bin/python3", "-c", CHURN, CHURNED])
            .arg(flag)
            .arg(on.as_secs_f64().to_string())
            .arg(off.as_secs_f64().to_string())
            .stdin(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let churn = Churn {
            flag: flag.to_owned(),
            child,
        };
        let deadline = Instant::now() + Duration::from_secs(10);
        while !mounted() {
            assert!(Instant::now() < deadline, "the churn never mounted");
            std::thread::sleep(Duration::from_millis(1));
        }
        churn
    }

    /// Stops the loop, and says why it stopped early if it did.
    fn stop(mut self) {
        let early = self.child.try_wait().unwrap();
        let _ = std::fs::remove_file(&self.flag);
        let out = std::mem::replace(&mut self.child, Command::new("true").spawn().unwrap())
            .wait_with_output()
            .unwrap();
        assert!(
            early.is_none() && out.status.success(),
            "the churn stopped early: {out:?}"
        );
    }
}

impl Drop for Churn {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.flag);
        let _ = self.child.wait();
    }
}

fn mounted() -> bool {
    std::fs::read_to_string("/proc/self/mountinfo")
        .unwrap()
        .lines()
        .any(|line| line.split(' ').nth(4) == Some(CHURNED))
}

/// bubblewrap alone, with the host's root read-only, as the backend's probe
/// runs it.
fn bubblewrap_alone() -> Output {
    Command::new("/usr/bin/bwrap")
        .args(["--ro-bind", "/", "/", "true"])
        .output()
        .unwrap()
}

/// TEMPORARY: how often bubblewrap alone fails under churns of each
/// period, to choose the one the test runs under.
#[test]
fn on_a_runner_measure_the_churn() {
    if !on_a_runner() {
        return;
    }
    let lab = Lab::new();
    let mut report = String::new();
    for ms in [1u64, 3, 10, 30, 100] {
        let period = Duration::from_millis(ms);
        let churn = Churn::start(&lab.root.path().join("churning"), period, period);
        let (mut runs, mut failed) = (0, 0);
        let started = Instant::now();
        while runs < 300 && started.elapsed() < Duration::from_secs(20) {
            let out = bubblewrap_alone();
            runs += 1;
            if !out.status.success() {
                failed += 1;
                let said = text(&out.stderr);
                assert!(said.contains(MOUNT_CHANGED), "{said}");
            }
        }
        let per_run = started.elapsed() / runs;
        churn.stop();
        report.push_str(&format!(
            "on/off {ms} ms: {failed} of {runs} failed, {per_run:?} each\n"
        ));
    }
    let churn = Churn::start(
        &lab.root.path().join("churning"),
        Duration::from_millis(3),
        Duration::from_millis(3),
    );
    let started = Instant::now();
    let (mut sessions, mut again) = (0, 0);
    while sessions < 20 {
        let out = lab
            .command(&[
                "exec",
                "lab",
                "--",
                "/bin/sh",
                "-c",
                "echo ran >>\"$HOME/runs\"; echo ran",
            ])
            .output()
            .unwrap();
        sessions += 1;
        assert!(out.status.success(), "session {sessions}: {out:?}");
        again += text(&out.stderr).matches("bubblewrap was started").count();
    }
    churn.stop();
    report.push_str(&format!(
        "sessions under 3 ms: {sessions} in {:?}, {again} started again\n",
        started.elapsed()
    ));
    panic!("{report}");
}
