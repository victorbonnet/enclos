//! Looking at and signalling processes, through `ps` and `kill`, with no
//! `unsafe` code (ADR 0012).
//!
//! Signalling is narrow on purpose. enclos signals only process groups it
//! created and recorded, and only after checking that the group's recorded
//! leader is still the same process: same pid and same start time, so a pid
//! reused by an unrelated process is never signalled.

use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};

use crate::model::session::{Member, ProcessRef};

/// The start time `ps` reports for `pid`, or `None` when no such process
/// exists. Compared as text with what was recorded.
pub fn start_time(pid: u32) -> Option<String> {
    let out = Command::new("/bin/ps")
        .args(["-o", "lstart=", "-p", &pid.to_string()])
        .stderr(Stdio::null())
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    (out.status.success() && !text.is_empty()).then_some(text)
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
    let out = Command::new("/bin/ps")
        .args(["-o", "pgid=", "-p", &pid.to_string()])
        .stderr(Stdio::null())
        .output()
        .ok()?;
    String::from_utf8_lossy(&out.stdout).trim().parse().ok()
}

/// Every running process in process group `pgid`. Read-only. A process
/// that exited but was not yet reaped by its parent (a zombie) runs nothing
/// and is not counted.
pub fn group_members(pgid: u32) -> Vec<Member> {
    // In a group of its own, so `ps` never lists itself as a member of the
    // group of the process asking.
    let Ok(out) = Command::new("/bin/ps")
        .args(["-A", "-o", "pid=,pgid=,stat=,lstart=,comm="])
        .process_group(0)
        .stderr(Stdio::null())
        .output()
    else {
        return Vec::new();
    };
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|line| {
            let mut words = line.split_whitespace();
            let pid: u32 = words.next()?.parse().ok()?;
            let group: u32 = words.next()?.parse().ok()?;
            let zombie = words.next()?.starts_with('Z');
            // lstart is five words: "Sun Oct 18 15:03:21 2026".
            let started = words.by_ref().take(5).collect::<Vec<_>>().join(" ");
            let command = words.collect::<Vec<_>>().join(" ");
            (group == pgid && !zombie).then_some(Member {
                pid,
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
    let name = match signal {
        Signal::Term => "TERM",
        Signal::Kill => "KILL",
    };
    Command::new("/bin/kill")
        .args(["-s", name, "--", &format!("-{pgid}")])
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
            group_members(child.id())
                .iter()
                .any(|m| m.pid == child.id())
        );
        assert!(signal_group(&leader, child.id(), Signal::Term));
        assert!(wait_gone(&mut child));
        assert!(!is_same(&leader));
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
