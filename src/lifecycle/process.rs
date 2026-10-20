//! Looking at and signalling processes, through `ps` and `kill`, with no
//! `unsafe` code (ADR 0012).
//!
//! Signalling is narrow on purpose. enclos signals only a session's sure
//! members (see `members`): processes it recorded, and what they started.
//! A group is signalled only through its leader. Right before each signal,
//! it checks that the target is still the same process: same pid and same
//! start time, so a pid reused by an unrelated process is never signalled.

use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};

use crate::model::session::ProcessRef;

/// `ps`, reading dates in UTC and the C locale, so that a start time is
/// the same text whoever asks: start times are compared as text.
fn ps() -> Command {
    let mut ps = Command::new("/bin/ps");
    ps.env("TZ", "UTC0")
        .env("LC_ALL", "C")
        .stderr(Stdio::null());
    ps
}

/// The start time of `pid`, or `None` when no such process runs. A process
/// that exited but was not yet reaped by its parent (a zombie) runs
/// nothing and holds nothing, so it does not count as running.
pub fn start_time(pid: u32) -> Option<String> {
    let out = ps()
        .args(["-o", "stat=,lstart=", "-p", &pid.to_string()])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let (stat, started) = text.trim().split_once(char::is_whitespace)?;
    (out.status.success() && !stat.starts_with('Z')).then(|| started.trim().to_owned())
}

/// A reference to a process that is running now.
pub fn reference(pid: u32) -> Option<ProcessRef> {
    start_time(pid).map(|started| ProcessRef { pid, started })
}

/// Whether `process` is still the very process that was recorded.
pub fn is_same(process: &ProcessRef) -> bool {
    start_time(process.pid).is_some_and(|now| now == process.started)
}

/// The process group of `pid`.
pub fn group_of(pid: u32) -> Option<u32> {
    let out = ps()
        .args(["-o", "pgid=", "-p", &pid.to_string()])
        .output()
        .ok()?;
    String::from_utf8_lossy(&out.stdout).trim().parse().ok()
}

/// A process as one listing shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proc {
    pub pid: u32,
    pub ppid: u32,
    pub pgid: u32,
    pub started: String,
    pub command: String,
}

/// Every running process. Read-only. Zombies run nothing and are left out.
pub fn processes() -> Vec<Proc> {
    // In a group of its own, so `ps` is never in the group of the process
    // asking.
    let Ok(out) = ps()
        .args(["-A", "-o", "pid=,ppid=,pgid=,stat=,lstart=,comm="])
        .process_group(0)
        .output()
    else {
        return Vec::new();
    };
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|line| {
            let mut words = line.split_whitespace();
            let pid: u32 = words.next()?.parse().ok()?;
            let ppid: u32 = words.next()?.parse().ok()?;
            let pgid: u32 = words.next()?.parse().ok()?;
            let zombie = words.next()?.starts_with('Z');
            // lstart is five words: "Sun Oct 18 15:03:21 2026".
            let started = words.by_ref().take(5).collect::<Vec<_>>().join(" ");
            let command = words.collect::<Vec<_>>().join(" ");
            (!zombie).then_some(Proc {
                pid,
                ppid,
                pgid,
                started,
                command,
            })
        })
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signal {
    Term,
    Kill,
}

/// Sends `signal` to the process group whose leader is `leader`, only if
/// that leader is still the recorded process and leads its own group.
/// Returns whether it was sent.
pub fn signal_group(leader: &ProcessRef, pgid: u32, signal: Signal) -> bool {
    if leader.pid != pgid || !is_same(leader) || group_of(leader.pid) != Some(pgid) {
        return false;
    }
    kill(signal, &format!("-{pgid}"))
}

/// Sends `signal` to `process` alone, only if it is still the recorded
/// process. Returns whether it was sent.
pub fn signal_process(process: &ProcessRef, signal: Signal) -> bool {
    is_same(process) && kill(signal, &process.pid.to_string())
}

fn kill(signal: Signal, target: &str) -> bool {
    let name = match signal {
        Signal::Term => "TERM",
        Signal::Kill => "KILL",
    };
    Command::new("/bin/kill")
        .args(["-s", name, "--", target])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::CommandExt;
    use std::time::{Duration, Instant};

    /// A `sleep` this test starts in a group of its own: the only kind of
    /// process these tests signal.
    fn own_group() -> std::process::Child {
        Command::new("/bin/sleep")
            .arg("30")
            .process_group(0)
            .spawn()
            .unwrap()
    }

    fn wait_gone(child: &mut std::process::Child) -> bool {
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(5) {
            if child.try_wait().unwrap().is_some() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        false
    }

    #[test]
    fn a_recorded_group_is_found_and_stopped() {
        let mut child = own_group();
        let leader = reference(child.id()).unwrap();
        assert!(is_same(&leader));
        assert_eq!(group_of(child.id()), Some(child.id()));
        assert!(
            processes().iter().any(|p| p.pid == child.id()
                && p.pgid == child.id()
                && p.started == leader.started)
        );
        assert!(signal_group(&leader, child.id(), Signal::Term));
        assert!(wait_gone(&mut child));
        assert!(!is_same(&leader));
    }

    #[test]
    fn a_process_that_exited_is_not_the_same_even_unreaped() {
        let mut child = own_group();
        let recorded = reference(child.id()).unwrap();
        child.kill().unwrap();
        // Not waited for: the process stays a zombie, with its pid and
        // start time, until `wait` below.
        let start = Instant::now();
        while is_same(&recorded) && start.elapsed() < Duration::from_secs(5) {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(!is_same(&recorded));
        let _ = child.wait();
    }

    #[test]
    fn start_times_read_in_utc_whatever_the_callers_time_zone() {
        let mut child = own_group();
        let started = start_time(child.id()).unwrap();
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
        let recorded = reference(child.id()).unwrap();
        let stale = ProcessRef {
            pid: child.id(),
            started: "Thu Jan  1 00:00:00 1970".into(),
        };
        assert!(!signal_process(&stale, Signal::Term));
        assert!(child.try_wait().unwrap().is_none());
        assert!(signal_process(&recorded, Signal::Term));
        assert!(wait_gone(&mut child));
    }

    #[test]
    fn a_leader_with_another_start_time_is_never_signalled() {
        let mut child = own_group();
        // The same pid, recorded at another time: as after pid reuse.
        let stale = ProcessRef {
            pid: child.id(),
            started: "Thu Jan  1 00:00:00 1970".into(),
        };
        assert!(!signal_group(&stale, child.id(), Signal::Term));
        assert!(child.try_wait().unwrap().is_none());
        let _ = child.kill();
        let _ = child.wait();
    }

    #[test]
    fn a_process_that_does_not_lead_the_group_is_never_used_to_signal_it() {
        let mut child = own_group();
        let leader = reference(child.id()).unwrap();
        // Our own pid is not the group's leader.
        assert!(!signal_group(&leader, std::process::id(), Signal::Term));
        let _ = child.kill();
        let _ = child.wait();
    }
}
