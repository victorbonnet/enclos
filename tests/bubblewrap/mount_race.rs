//! A mount of the host that comes and goes while sessions start (design §5,
//! What `wrap` does at each launch). bubblewrap before 0.13, as the runners
//! have, reads the mount table and then remounts each mount read-only: one
//! taken away in between fails its setup. The control, bubblewrap alone,
//! fails so at times; every session starts all the same, its command run
//! once. Mounting needs root: the runner's `sudo`, which asks no password.

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
/// file named second is there; then removes the folder. Taking it away
/// fails with `EBUSY` while something briefly holds the mount, as it did in
/// about one run in twenty with sessions starting: that is tried again for
/// up to five seconds. On the way out it writes how many unmounts were busy
/// and the longest wait, so that a drift from rare and brief shows in the
/// job's log.
const CHURN: &str = r#"
import ctypes, errno, os, sys, time
libc = ctypes.CDLL(None, use_errno=True)
path, flag, on, off = sys.argv[1], sys.argv[2], float(sys.argv[3]), float(sys.argv[4])
os.makedirs(path, exist_ok=True)
cycles, busy, longest = 0, 0, 0.0
while os.path.exists(flag):
    if libc.mount(b"enclos-churn", path.encode(), b"tmpfs", 0, None) != 0:
        sys.exit("mount: " + os.strerror(ctypes.get_errno()))
    time.sleep(on)
    cycles += 1
    start = time.monotonic()
    waited = False
    while libc.umount2(path.encode(), 0) != 0:
        error = ctypes.get_errno()
        if error != errno.EBUSY or time.monotonic() > start + 5:
            sys.exit("umount: " + os.strerror(error))
        waited = True
        time.sleep(0.001)
    if waited:
        busy += 1
        longest = max(longest, time.monotonic() - start)
    time.sleep(off)
os.rmdir(path)
sys.stderr.write(f"{busy} of {cycles} unmounts busy, the longest for {longest * 1000:.0f} ms")
"#;

/// A tmpfs mounted and taken away at `CHURNED` until stopped or dropped.
/// The test stops it through a file the loop looks for, and signals
/// nothing.
struct Churn {
    flag: PathBuf,
    child: Option<Child>,
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
            child: Some(child),
        };
        let deadline = Instant::now() + Duration::from_secs(10);
        while !mounted() {
            assert!(Instant::now() < deadline, "the churn never mounted");
            std::thread::sleep(Duration::from_millis(1));
        }
        churn
    }

    /// Stops the loop, and says why if it had stopped before. Returns what
    /// it wrote on the way out: how many unmounts were busy.
    fn stop(mut self) -> String {
        let mut child = self.child.take().unwrap();
        let early = child.try_wait().unwrap();
        let _ = std::fs::remove_file(&self.flag);
        let out = child.wait_with_output().unwrap();
        assert!(
            early.is_none() && out.status.success(),
            "the churn stopped early: {out:?}"
        );
        assert!(!mounted(), "the churn left its mount");
        text(&out.stderr)
    }
}

impl Drop for Churn {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.flag);
        if let Some(mut child) = self.child.take() {
            let _ = child.wait();
        }
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

/// What a session started again says (`setup`).
const AGAIN: &str = "a mount of the host changed while bubblewrap set up, so it starts again";

/// How long the churn holds its mount, and how long it leaves it away: at
/// this pace bubblewrap alone failed about one start in twenty on the
/// runners (5 to 11%), often enough to show and rarely enough that five
/// starts in a row all fail almost never.
const PACE: Duration = Duration::from_millis(1);

/// Under a tmpfs mounted and taken away every millisecond under the
/// runner's `/run`, as the runner's own sessions start: bubblewrap alone,
/// the control, fails to set up at times; every session starts, the first
/// installing the namespace holder, some are started again, and each runs
/// its command once.
#[test]
fn on_a_runner_sessions_start_while_a_mount_of_the_host_comes_and_goes() {
    if !on_a_runner() {
        return;
    }
    let lab = Lab::new();
    let churn = Churn::start(&lab.root.path().join("churning"), PACE, PACE);
    let (mut alone, mut failed, mut said) = (0, 0, String::new());
    while failed < 3 && alone < 3000 {
        let out = bubblewrap_alone();
        alone += 1;
        if !out.status.success() {
            failed += 1;
            said = text(&out.stderr);
            assert!(said.contains(MOUNT_CHANGED), "{out:?}");
        }
    }
    let (mut sessions, mut again) = (0, 0);
    while (again < 3 || sessions < 30) && sessions < 150 {
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
        assert_eq!(text(&out.stdout), "ran", "session {sessions}: {out:?}");
        again += usize::from(text(&out.stderr).contains(AGAIN));
    }
    let busy = churn.stop();
    let runs = std::fs::read_to_string(lab.sandbox_home().join("runs")).unwrap();
    // Straight to the job's log, which keeps no output of a test that passes.
    use std::io::Write;
    let _ = writeln!(
        std::io::stderr(),
        "mount race: bubblewrap alone failed {failed} of {alone} starts, last with `{said}`; {sessions} sessions all started, {again} of them started again; churn: {busy}"
    );
    assert!(
        failed > 0,
        "bubblewrap alone never failed in {alone} starts: the churn did not reach its setup"
    );
    assert!(again > 0, "no session of {sessions} met the churn");
    assert_eq!(runs.lines().count(), sessions, "{runs}");
}
