//! Looking at and signalling processes, with no `unsafe` code (ADR 0012):
//! the host lists them (`ps` on macOS, `/proc` on Linux) and `kill` or a
//! pidfd signals them.
//!
//! Signalling is narrow on purpose. enclos signals only a session's sure
//! members (see `members`): processes it recorded, and what they started.
//! A group is signalled only through its leader. Right before each signal,
//! it checks that the target is still the same process, same pid and same
//! start time, so a pid already reused by an unrelated process is not
//! signalled. On Linux a process alone is signalled through a pidfd taken
//! before the check, which reaches no process that reused the pid. A group
//! has no such handle, nor has a process on macOS: there the check narrows the
//! window to the moment between it and the signal, and cannot close it.
//!
//! A listing that fails is an error, never an empty answer: "no process"
//! from a listing that did not run would end sessions whose members still
//! run.

use std::process::{Child, Command, Stdio};

use crate::model::session::ProcessRef;

/// The host could not say which processes run.
#[derive(Debug, thiserror::Error)]
pub enum PsError {
    #[error("cannot look at processes with /bin/ps: {0}")]
    Ps(String),
    #[error("cannot look at processes in /proc: {0}")]
    Proc(String),
    /// A process this one started and has not waited for is not listed.
    #[error("cannot look at processes: pid {0}, just started, is not listed")]
    NotListed(u32),
    /// A session's cgroup could not be found or read (`lifecycle::cgroup`).
    #[error("cannot look at a session's cgroup: {0}")]
    Cgroup(String),
}

#[cfg(test)]
impl PsError {
    /// A `ps` failure with this reason, for tests of what follows one.
    pub(crate) fn new(why: &str) -> PsError {
        PsError::Ps(why.to_owned())
    }
}

/// What one look at a process shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Seen {
    /// It exited and was not yet reaped by its parent: it runs nothing and
    /// holds nothing. One whose main thread exited while others run on is no
    /// zombie.
    pub zombie: bool,
    /// When it started, as `ps -o lstart` writes it in UTC with single
    /// spaces: compared as text, never parsed.
    pub started: String,
}

/// The start time of `pid`, or `None` when no such process runs. A zombie
/// runs nothing and holds nothing, so it does not count as running.
pub fn start_time(pid: u32) -> Result<Option<String>, PsError> {
    Ok(super::host::seen(pid)?.and_then(|seen| (!seen.zombie).then_some(seen.started)))
}

/// A reference to a process that is running now.
pub fn reference(pid: u32) -> Result<Option<ProcessRef>, PsError> {
    Ok(start_time(pid)?.map(|started| ProcessRef { pid, started }))
}

/// A reference to `child`, which this process started and has not waited
/// for. Until it is waited for, its pid cannot be reused, so it is read even
/// when the program already exited.
pub fn reference_of_child(child: &Child) -> Result<ProcessRef, PsError> {
    let pid = child.id();
    let seen = super::host::seen(pid)?.ok_or(PsError::NotListed(pid))?;
    Ok(ProcessRef {
        pid,
        started: seen.started,
    })
}

/// Whether `process` is still the very process that was recorded.
pub fn is_same(process: &ProcessRef) -> Result<bool, PsError> {
    Ok(start_time(process.pid)?.is_some_and(|now| now == process.started))
}

/// The process group of `pid`, or `None` when no such process exists.
pub fn group_of(pid: u32) -> Result<Option<u32>, PsError> {
    super::host::group_of(pid)
}

/// A process as one listing shows it. `command` is what `ps` calls `comm`, to
/// show to the user and never to compare: what the process is called, which
/// it may choose, and on Linux cut at 15 characters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proc {
    pub pid: u32,
    pub ppid: u32,
    pub pgid: u32,
    pub started: String,
    pub command: String,
}

/// Every running process. Read-only. Zombies run nothing and are left out;
/// a listing that does not show the caller is an error, as it cannot be the
/// whole listing.
pub fn processes() -> Result<Vec<Proc>, PsError> {
    super::host::processes()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signal {
    Term,
    Kill,
    Usr1,
    Int,
    Quit,
    Hup,
}

impl Signal {
    pub fn name(self) -> &'static str {
        match self {
            Signal::Term => "TERM",
            Signal::Kill => "KILL",
            Signal::Usr1 => "USR1",
            Signal::Int => "INT",
            Signal::Quit => "QUIT",
            Signal::Hup => "HUP",
        }
    }

    #[cfg(target_os = "linux")]
    fn number(self) -> rustix::process::Signal {
        use rustix::process::Signal as S;
        match self {
            Signal::Term => S::TERM,
            Signal::Kill => S::KILL,
            Signal::Usr1 => S::USR1,
            Signal::Int => S::INT,
            Signal::Quit => S::QUIT,
            Signal::Hup => S::HUP,
        }
    }
}

/// What became of a signal enclos meant to send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Signalled {
    Sent,
    /// The target is no longer the recorded process: it exited, or its pid
    /// was reused. Nothing was sent.
    Gone,
    /// The leader no longer leads the group. Nothing was sent.
    NotLeader,
    /// `kill` refused or failed, with why.
    Failed(String),
}

/// Sends `signal` to the process group whose leader is `leader`, only if
/// that leader is still the recorded process and leads its own group.
pub fn signal_group(leader: &ProcessRef, pgid: u32, signal: Signal) -> Result<Signalled, PsError> {
    if leader.pid != pgid {
        return Ok(Signalled::NotLeader);
    }
    if !is_same(leader)? {
        return Ok(Signalled::Gone);
    }
    if group_of(leader.pid)? != Some(pgid) {
        return Ok(Signalled::NotLeader);
    }
    Ok(kill(signal, -i64::from(pgid)))
}

/// Sends `signal` to `process` alone, only if it is still the recorded
/// process.
#[cfg(not(target_os = "linux"))]
pub fn signal_process(process: &ProcessRef, signal: Signal) -> Result<Signalled, PsError> {
    if !is_same(process)? {
        return Ok(Signalled::Gone);
    }
    Ok(kill(signal, i64::from(process.pid)))
}

/// As above, through a pidfd taken before the check, so a reused pid is
/// never signalled.
#[cfg(target_os = "linux")]
pub fn signal_process(process: &ProcessRef, signal: Signal) -> Result<Signalled, PsError> {
    through_pidfd(process, signal, || is_same(process))
}

/// Takes a pidfd on `process`, then asks `same`, so that the signal reaches
/// the process that was checked or none.
#[cfg(target_os = "linux")]
fn through_pidfd(
    process: &ProcessRef,
    signal: Signal,
    same: impl FnOnce() -> Result<bool, PsError>,
) -> Result<Signalled, PsError> {
    use rustix::io::Errno;
    use rustix::process::{Pid, PidfdFlags, pidfd_open, pidfd_send_signal};
    let target = i64::from(process.pid);
    let pid = i32::try_from(process.pid).ok().and_then(Pid::from_raw);
    let Some(pid) = pid.filter(|_| !never_signalled(target)) else {
        return Ok(Signalled::Failed(format!("enclos never signals {target}")));
    };
    let pidfd = match pidfd_open(pid, PidfdFlags::empty()) {
        Ok(pidfd) => pidfd,
        Err(Errno::SRCH) => return Ok(Signalled::Gone),
        Err(e) => return Ok(Signalled::Failed(format!("cannot open pid {target}: {e}"))),
    };
    if !same()? {
        return Ok(Signalled::Gone);
    }
    Ok(match pidfd_send_signal(&pidfd, signal.number()) {
        Ok(()) => Signalled::Sent,
        Err(Errno::SRCH) => Signalled::Gone,
        Err(e) => Signalled::Failed(e.to_string()),
    })
}

/// Targets `kill` reads as more than one process of a session: 0 is the
/// caller's own group and -1 every process the user owns; 1 is launchd or
/// init.
fn never_signalled(target: i64) -> bool {
    target.abs() <= 1
}

fn kill(signal: Signal, target: i64) -> Signalled {
    if never_signalled(target) {
        return Signalled::Failed(format!("enclos never signals {target}"));
    }
    match Command::new("/bin/kill")
        .args(["-s", signal.name(), "--", &target.to_string()])
        .stdin(Stdio::null())
        .output()
    {
        Ok(out) if out.status.success() => Signalled::Sent,
        Ok(out) => Signalled::Failed(match String::from_utf8_lossy(&out.stderr).trim() {
            "" => out.status.to_string(),
            why => why.to_owned(),
        }),
        Err(e) => Signalled::Failed(format!("cannot run /bin/kill: {e}")),
    }
}

/// `python3` set to run a test's own process whose main thread exits while
/// another runs on, listening at 127.0.0.1 and writing its port once the main
/// thread is gone. Python, as a test program cannot end only its main thread
/// with no `unsafe` code.
#[cfg(all(test, target_os = "linux"))]
pub(crate) fn headless(python: &mut Command) -> &mut Command {
    const PROGRAM: &str = r#"
import ctypes, os, threading, time
def serve():
    s = listener()
    stat = "/proc/%d/stat" % os.getpid()
    while open(stat).read().rsplit(") ", 1)[1][0] != "Z":
        time.sleep(0.01)
    print(s.getsockname()[1], flush=True)
    time.sleep(30)
threading.Thread(target=serve).start()
ctypes.CDLL(None).pthread_exit(None)
"#;
    python
        .args([
            "-I",
            "-c",
            &format!("{}{PROGRAM}", crate::test_ports::python_listener()),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
}

/// The port [`headless`] wrote, once its main thread is gone.
#[cfg(all(test, target_os = "linux"))]
pub(crate) fn headless_port(child: &mut Child) -> u16 {
    use std::io::BufRead;
    let mut line = String::new();
    let out = child.stdout.take().unwrap();
    std::io::BufReader::new(out).read_line(&mut line).unwrap();
    line.trim().parse().unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::CommandExt;
    use std::time::{Duration, Instant};

    /// A `sleep` this test starts in a group of its own: the only kind of
    /// process these tests signal.
    fn own_group() -> Child {
        Command::new("/bin/sleep")
            .arg("30")
            .process_group(0)
            .spawn()
            .unwrap()
    }

    fn wait_gone(child: &mut Child) -> bool {
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(5) {
            if child.try_wait().unwrap().is_some() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        false
    }

    fn now(pid: u32) -> ProcessRef {
        reference(pid).unwrap().unwrap()
    }

    /// The variable that has [`sleeps_when_asked`] sleep.
    #[cfg(target_os = "linux")]
    const SLEEP: &str = "ENCLOS_TEST_SLEEP";

    /// What the long-named program below runs: sleeps when asked to, passes
    /// at once otherwise.
    #[cfg(target_os = "linux")]
    #[test]
    fn sleeps_when_asked() {
        if std::env::var_os(SLEEP).is_some() {
            std::thread::sleep(Duration::from_secs(30));
        }
    }

    /// Linux cuts a program's name at 15 characters, so a command is for
    /// showing only. The program is this test program through a link, whose
    /// name the kernel takes: `/bin/sleep` may be a multi-call binary, which
    /// exits at once under a name it does not know, and a copy being written
    /// can be busy when run, if another test forks meanwhile.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_long_program_name_is_listed_cut_at_15_characters() {
        let dir = tempfile::tempdir().unwrap();
        let long = dir.path().join("a-program-with-a-long-name");
        std::os::unix::fs::symlink(std::env::current_exe().unwrap(), &long).unwrap();
        let mut child = Command::new(&long)
            .args([
                "--exact",
                "lifecycle::process::tests::sleeps_when_asked",
                "--test-threads=1",
            ])
            .env(SLEEP, "1")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let listed = processes().unwrap();
        let _ = child.kill();
        let _ = child.wait();
        let found = listed.iter().find(|p| p.pid == child.id()).unwrap();
        assert_eq!(found.command, "a-program-with-");
    }

    /// A real one, which runs on until it is stopped: not a zombie to any
    /// reader, and it can be signalled.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_process_whose_main_thread_exited_runs_on() {
        let mut child = headless(&mut Command::new("/usr/bin/python3"))
            .spawn()
            .unwrap();
        headless_port(&mut child);
        let pid = child.id();
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
        assert!(stat.rsplit_once(") ").unwrap().1.starts_with('Z'), "{stat}");
        assert!(!super::super::host::seen(pid).unwrap().unwrap().zombie);
        let recorded = reference(pid).unwrap().expect("reads as not running");
        assert!(processes().unwrap().iter().any(|p| p.pid == pid));
        assert_eq!(
            signal_process(&recorded, Signal::Term).unwrap(),
            Signalled::Sent
        );
        assert!(wait_gone(&mut child));
    }

    #[test]
    fn a_reaped_pid_has_no_start_time_and_no_group() {
        let mut child = Command::new("/usr/bin/true").spawn().unwrap();
        let pid = child.id();
        child.wait().unwrap();
        assert_eq!(super::super::host::seen(pid).unwrap(), None);
        assert_eq!(group_of(pid).unwrap(), None);
    }

    #[test]
    fn a_recorded_group_is_found_and_stopped() {
        let mut child = own_group();
        let leader = now(child.id());
        assert!(is_same(&leader).unwrap());
        assert_eq!(group_of(child.id()).unwrap(), Some(child.id()));
        assert!(
            processes().unwrap().iter().any(|p| p.pid == child.id()
                && p.pgid == child.id()
                && p.started == leader.started)
        );
        assert_eq!(
            signal_group(&leader, child.id(), Signal::Term).unwrap(),
            Signalled::Sent
        );
        assert!(wait_gone(&mut child));
        assert!(!is_same(&leader).unwrap());
    }

    #[test]
    fn a_process_that_exited_is_not_the_same_even_unreaped() {
        let mut child = own_group();
        let recorded = now(child.id());
        child.kill().unwrap();
        // Not waited for: the process stays a zombie, with its pid and
        // start time, until `wait` below.
        let start = Instant::now();
        while is_same(&recorded).unwrap() && start.elapsed() < Duration::from_secs(5) {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(!is_same(&recorded).unwrap());
        assert!(!processes().unwrap().iter().any(|p| p.pid == child.id()));
        let _ = child.wait();
    }

    #[test]
    fn a_child_that_exited_at_once_still_has_a_reference_until_waited_for() {
        let mut child = Command::new("/usr/bin/true").spawn().unwrap();
        let start = Instant::now();
        while start_time(child.id()).unwrap().is_some() {
            assert!(start.elapsed() < Duration::from_secs(5));
            std::thread::sleep(Duration::from_millis(20));
        }
        let recorded = reference_of_child(&child).unwrap();
        assert_eq!(recorded.pid, child.id());
        let _ = child.wait();
        assert_eq!(start_time(recorded.pid).unwrap(), None);
    }

    #[test]
    fn start_times_read_in_utc_whatever_the_callers_time_zone() {
        let mut child = own_group();
        let started = start_time(child.id()).unwrap().unwrap();
        let read = jiff::civil::DateTime::strptime("%a %b %e %H:%M:%S %Y", &started)
            .unwrap()
            .to_zoned(jiff::tz::TimeZone::UTC)
            .unwrap()
            .timestamp();
        let off = (jiff::Timestamp::now() - read).get_seconds().abs();
        assert!(off < 60, "{started} is {off}s away from now in UTC");
        let _ = child.kill();
        let _ = child.wait();
    }

    #[test]
    fn a_process_is_signalled_alone_only_while_it_is_the_recorded_one() {
        let mut child = own_group();
        let recorded = now(child.id());
        let stale = ProcessRef {
            pid: child.id(),
            started: "Thu Jan 1 00:00:00 1970".into(),
        };
        assert_eq!(
            signal_process(&stale, Signal::Term).unwrap(),
            Signalled::Gone
        );
        assert!(child.try_wait().unwrap().is_none());
        assert_eq!(
            signal_process(&recorded, Signal::Term).unwrap(),
            Signalled::Sent
        );
        assert!(wait_gone(&mut child));
    }

    /// What exits right after the check is gone, and its pid, free again,
    /// is not what the signal goes to.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_process_that_ended_after_the_check_is_not_signalled() {
        let mut child = own_group();
        let recorded = now(child.id());
        let result = through_pidfd(&recorded, Signal::Term, || {
            child.kill().unwrap();
            child.wait().unwrap();
            Ok(true)
        });
        assert_eq!(result.unwrap(), Signalled::Gone);
    }

    /// Nor is pid 1, which no process of a session can be.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_process_is_never_signalled_at_a_target_of_many() {
        let init = ProcessRef {
            pid: 1,
            started: String::new(),
        };
        let result = through_pidfd(&init, Signal::Term, || panic!("looked at pid 1"));
        assert!(matches!(result.unwrap(), Signalled::Failed(_)));
    }

    #[test]
    fn a_leader_with_another_start_time_is_never_signalled() {
        let mut child = own_group();
        // The same pid, recorded at another time: as after pid reuse.
        let stale = ProcessRef {
            pid: child.id(),
            started: "Thu Jan 1 00:00:00 1970".into(),
        };
        assert_eq!(
            signal_group(&stale, child.id(), Signal::Term).unwrap(),
            Signalled::Gone
        );
        assert!(child.try_wait().unwrap().is_none());
        let _ = child.kill();
        let _ = child.wait();
    }

    #[test]
    fn a_process_that_does_not_lead_the_group_is_never_used_to_signal_it() {
        let mut child = own_group();
        let leader = now(child.id());
        // Our own pid is not the group's leader.
        assert_eq!(
            signal_group(&leader, std::process::id(), Signal::Term).unwrap(),
            Signalled::NotLeader
        );
        let _ = child.kill();
        let _ = child.wait();
    }

    #[test]
    fn targets_meaning_more_than_one_process_are_never_signalled() {
        // Checked on the rule alone: a test that sent them would signal the
        // test runner's group, or every process of the user.
        for target in [0, -1, 1] {
            assert!(never_signalled(target), "{target}");
        }
        assert!(!never_signalled(-4242));
        assert!(!never_signalled(4242));
    }
}
