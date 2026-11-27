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
/// this pace bubblewrap alone failed from under 1% of starts (arm) to over
/// 20% on one hosted x86 job, often enough to show and rarely enough that
/// five starts in a row all fail almost never.
const PACE: Duration = Duration::from_millis(1);

/// Hard cap on the number of sessions started in one test run.
const MAX_SESSIONS: usize = 3000;

/// Cap on wall-clock time spent looking for the first session that starts
/// again (as on main, it is not checked once one has).
const MAX_DURATION: Duration = Duration::from_secs(240);

/// Minimum number of sessions to start when the control rate is high, so
/// both the first session (which installs the namespace holder) and
/// subsequent sessions are exercised.
const MIN_SESSIONS: usize = 30;

/// Number of restarted sessions that is enough to stop early once at least
/// `MIN_SESSIONS` have run.
const ENOUGH_AGAIN: usize = 3;

/// Maximum number of sessions to run once at least one session has started
/// again.
const MOST_ONCE_MET: usize = 150;

/// Minimum number of control starts to sample: stopping at the third
/// failure alone over-reads the rate, so take at least this many starts.
const MIN_CONTROL: usize = 100;

/// Floor on the session budget, because a session meets the race less often
/// than bubblewrap alone and the control rate is only an estimate.
const MIN_BUDGET: usize = 100;

/// A session meets the race less often than bubblewrap alone (measured about
/// half as often on x86 runners, less on arm), so size the budget for a
/// quarter of the control's rate.
const SESSION_RATE_DIVISOR: f64 = 4.0;

/// Target upper bound on the probability that no session meets the churn
/// under the conservative per-start session rate `control_rate /
/// SESSION_RATE_DIVISOR` (1 in 10,000).
const MISS_PROB: f64 = 1e-4;

/// Derives the session budget from the control's measured failure rate
/// (`failed` of `alone` `bubblewrap_alone` starts), capped at `MAX_SESSIONS`
/// and floored at `MIN_BUDGET`.
///
/// Uses the conservative per-start session rate
/// `p = (failed / alone) / SESSION_RATE_DIVISOR`. Under that rate, the
/// chance that `N` independent sessions all miss the race is `(1 - p)^N`;
/// solving `(1 - p)^N <= MISS_PROB` gives
/// `N = ceil(ln(MISS_PROB) / ln(1 - p))`, keeping the miss probability at or
/// below `1e-4`.
///
/// Comparison with arm CI run 44533972837, where the control failed 3 of
/// 397 starts (`~0.76%`) and 0 of 150 sessions started again: with
/// `p = (3/397) / 4 ≈ 0.19%`, 150 sessions had a `(1 - p)^150 ≈ 75%` chance
/// of seeing zero retries. Reaching `MISS_PROB` at that rate needs 4871
/// sessions, which exceeds `MAX_SESSIONS` and is therefore capped at
/// `MAX_SESSIONS` (3000); `MAX_SESSIONS` and the 240 s `MAX_DURATION` limit
/// bound the search while no session has started again. At the 5–15%
/// control rates seen on x86 runners, this derives 733–241 sessions (ceil
/// values below `MIN_BUDGET` are raised to 100).
fn session_budget(failed: usize, alone: usize) -> usize {
    if failed == 0 || alone == 0 {
        return MAX_SESSIONS;
    }
    if failed >= alone {
        return MIN_BUDGET;
    }
    let p = (failed as f64 / alone as f64) / SESSION_RATE_DIVISOR;
    let needed = (MISS_PROB.ln() / (-p).ln_1p()).ceil();
    if !needed.is_finite() || needed >= MAX_SESSIONS as f64 {
        MAX_SESSIONS
    } else {
        (needed as usize).clamp(MIN_BUDGET, MAX_SESSIONS)
    }
}

/// Whether to start another session, after `sessions` of them with `again`
/// started again, `spent` into the loop, and a derived `budget` (capped at
/// `MAX_SESSIONS`).
///
/// Fewer than `MIN_SESSIONS` always continues. With `again == 0`, the loop
/// keeps going until `budget` sessions or `MAX_DURATION` is reached. Once the
/// churn is met (`again >= 1`), this keeps main's stop rule: 30 at least, 3
/// started again, 150 at most.
fn more_sessions(sessions: usize, again: usize, spent: Duration, budget: usize) -> bool {
    if sessions < MIN_SESSIONS {
        return true;
    }
    if again == 0 {
        return sessions < budget && spent < MAX_DURATION;
    }
    again < ENOUGH_AGAIN && sessions < MOST_ONCE_MET
}

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
    while (failed < 3 || alone < MIN_CONTROL) && alone < 3000 {
        let out = bubblewrap_alone();
        alone += 1;
        if !out.status.success() {
            failed += 1;
            said = text(&out.stderr);
            assert!(said.contains(MOUNT_CHANGED), "{out:?}");
        }
    }
    let budget = session_budget(failed, alone);
    // Check field 5 (mount point) of `/proc/self/mountinfo` in pure POSIX sh
    // without spawning a subprocess, so the session records whether `CHURNED`
    // reaches its mount namespace while keeping stdout and exit status
    // unchanged.
    let script = format!(
        "while read -r _ _ _ _ m _; do [ \"$m\" = {CHURNED} ] && {{ echo saw >>\"$HOME/saw\"; break; }}; done </proc/self/mountinfo; echo ran >>\"$HOME/runs\"; echo ran"
    );
    let (mut sessions, mut again) = (0, 0);
    let began = Instant::now();
    while more_sessions(sessions, again, began.elapsed(), budget) {
        let out = lab
            .command(&["exec", "lab", "--", "/bin/sh", "-c", &script])
            .output()
            .unwrap();
        sessions += 1;
        assert!(out.status.success(), "session {sessions}: {out:?}");
        assert_eq!(text(&out.stdout), "ran", "session {sessions}: {out:?}");
        again += usize::from(text(&out.stderr).contains(AGAIN));
    }
    let elapsed = began.elapsed();
    let busy = churn.stop();
    let runs = std::fs::read_to_string(lab.sandbox_home().join("runs")).unwrap();
    let saw = match std::fs::read_to_string(lab.sandbox_home().join("saw")) {
        Ok(text) => text.lines().count(),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => 0,
        Err(err) => panic!("reading saw count: {err}"),
    };
    let rate_pct = if alone > 0 {
        100.0 * failed as f64 / alone as f64
    } else {
        0.0
    };
    // Straight to the job's log, which keeps no output of a test that passes.
    use std::io::Write;
    let _ = writeln!(
        std::io::stderr(),
        "mount race: bubblewrap alone failed {failed} of {alone} starts ({rate_pct:.2}%, budget {budget}), last with `{said}`; {sessions} sessions all started, {again} of them started again, {saw} of {sessions} saw {CHURNED}; churn: {busy}"
    );
    assert!(
        failed > 0,
        "bubblewrap alone never failed in {alone} starts: the churn did not reach its setup"
    );
    let diagnosis = if saw == 0 {
        "none of the sessions saw the churned mount in /proc/self/mountinfo (the churned mount never reached the session's mount namespace)"
    } else {
        "the churned mount reaches the session's mount namespace, but none lost the race"
    };
    assert!(
        again > 0,
        "no session of {sessions} (budget {budget}, control {failed} of {alone}) met the churn in {elapsed:?}; {saw} of {sessions} saw {CHURNED}: {diagnosis}"
    );
    assert_eq!(runs.lines().count(), sessions, "{runs}");
}

#[test]
fn session_budget_scales_with_control_rate() {
    // Arm CI run 44533972837: 3 of 397 (~0.76%), conservative p = 0.0076/4
    // needs 4871 sessions, so it is capped at MAX_SESSIONS.
    let arm = session_budget(3, 397);
    assert_eq!(arm, MAX_SESSIONS);

    // Higher control rates need fewer sessions, down to the MIN_BUDGET floor.
    let mid = session_budget(3, 192);
    let five_pct = session_budget(3, 60);
    let ten_pct = session_budget(10, 100);
    let eleven_pct = session_budget(3, 27);
    assert_eq!(mid, 2354);
    assert_eq!(five_pct, 733);
    assert_eq!(ten_pct, 364);
    assert_eq!(eleven_pct, 327);
    assert!(
        arm >= mid
            && mid >= five_pct
            && five_pct >= ten_pct
            && ten_pct >= eleven_pct
            && eleven_pct >= MIN_BUDGET
    );

    // Every unclamped budget satisfies (1 - p')^N <= MISS_PROB and
    // (1 - p')^(N - 1) > MISS_PROB for p' = (failed / alone) / SESSION_RATE_DIVISOR.
    for (failed, alone) in [(3, 192), (3, 60), (10, 100), (3, 27)] {
        let p = (failed as f64 / alone as f64) / SESSION_RATE_DIVISOR;
        let n = session_budget(failed, alone);
        assert!(n > MIN_BUDGET && n < MAX_SESSIONS);
        assert!((1.0 - p).powi(n as i32) <= MISS_PROB);
        assert!((1.0 - p).powi((n - 1) as i32) > MISS_PROB);
    }

    // Boundary and degenerate inputs clamp cleanly.
    assert_eq!(session_budget(0, 3000), MAX_SESSIONS);
    assert_eq!(session_budget(0, 0), MAX_SESSIONS);
    assert_eq!(session_budget(1, 3000), MAX_SESSIONS);
    assert_eq!(session_budget(3, 3), MIN_BUDGET);
    assert_eq!(session_budget(5, 3), MIN_BUDGET);
}

#[test]
fn more_sessions_keeps_mains_stop_rule() {
    // Fewer than MIN_SESSIONS (30) always continues, regardless of retries,
    // elapsed time, or budget.
    assert!(more_sessions(0, 0, Duration::ZERO, 100));
    assert!(more_sessions(
        MIN_SESSIONS - 1,
        ENOUGH_AGAIN,
        MAX_DURATION,
        0
    ));

    // With again == 0, keep going until budget or MAX_DURATION is reached.
    assert!(more_sessions(MIN_SESSIONS, 0, Duration::ZERO, 100));
    assert!(more_sessions(
        99,
        0,
        MAX_DURATION - Duration::from_secs(1),
        100
    ));
    assert!(!more_sessions(100, 0, Duration::ZERO, 100));
    assert!(more_sessions(MOST_ONCE_MET, 0, Duration::ZERO, 300));
    assert!(!more_sessions(50, 0, MAX_DURATION, 300));
    assert!(!more_sessions(
        50,
        0,
        MAX_DURATION + Duration::from_secs(1),
        300
    ));

    // With 1 or 2 restarts, continue until MOST_ONCE_MET (150) sessions.
    assert!(more_sessions(MIN_SESSIONS, 1, Duration::ZERO, 100));
    assert!(more_sessions(MOST_ONCE_MET - 1, 1, Duration::ZERO, 100));
    assert!(more_sessions(MIN_SESSIONS, 2, Duration::ZERO, 100));
    assert!(more_sessions(MOST_ONCE_MET - 1, 2, Duration::ZERO, 100));

    // With ENOUGH_AGAIN (3) restarts, stop immediately at >= MIN_SESSIONS.
    assert!(!more_sessions(
        MIN_SESSIONS,
        ENOUGH_AGAIN,
        Duration::ZERO,
        300
    ));
    assert!(!more_sessions(50, ENOUGH_AGAIN, Duration::ZERO, 300));
    assert!(!more_sessions(50, ENOUGH_AGAIN + 1, Duration::ZERO, 300));

    // With at least one restart, stop at MOST_ONCE_MET (150) sessions.
    assert!(!more_sessions(MOST_ONCE_MET, 1, Duration::ZERO, 300));
    assert!(!more_sessions(MOST_ONCE_MET, 2, Duration::ZERO, 300));
    assert!(!more_sessions(200, 1, Duration::ZERO, 300));
}
