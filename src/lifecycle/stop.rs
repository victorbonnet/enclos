//! Stopping a session: every member (design §8).
//!
//! TERM to the members, a grace period, KILL to what is left, then a check.
//! A group is signalled through its leader when the leader is a sure
//! member, any other sure member alone; members that are only counted are
//! never signalled, and are reported if they remain (see `members`).

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use super::members::{Found, find};
use super::process::{Signal, processes, signal_group, signal_process};
use crate::model::session::{Member, SessionRecord};

pub const GRACE: Duration = Duration::from_secs(5);
const POLL: Duration = Duration::from_millis(50);

/// What stopping one session did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stopped {
    /// Every member is gone.
    Clean,
    /// These members still run.
    Survivors(Vec<Member>),
}

pub fn stop(session: &SessionRecord, grace: Duration) -> Stopped {
    let first = find(&processes(), session, &session.tracked);
    if !first.iter().any(|f| f.sure) {
        // Nothing enclos may signal: what is only counted is reported.
        return match first.is_empty() {
            true => Stopped::Clean,
            false => Stopped::Survivors(first.into_iter().map(|f| f.member).collect()),
        };
    }
    // What was found stays known while the signals end parents: a member
    // whose parent exits first is still the session's.
    let mut known = session.tracked.clone();
    known.extend(first.iter().filter(|f| f.sure).map(Found::process));
    let now = || find(&processes(), session, &known);
    signal(&first, Signal::Term);
    if wait_empty(&now, grace) {
        return Stopped::Clean;
    }
    signal(&now(), Signal::Kill);
    if wait_empty(&now, grace) {
        Stopped::Clean
    } else {
        Stopped::Survivors(now().into_iter().map(|f| f.member).collect())
    }
}

fn signal(found: &[Found], signal: Signal) {
    let sure: Vec<&Found> = found.iter().filter(|f| f.sure).collect();
    let leaders: BTreeSet<u32> = sure
        .iter()
        .filter(|f| f.member.pid == f.pgid)
        .map(|f| f.pgid)
        .collect();
    for f in sure {
        let process = f.process();
        if leaders.contains(&f.member.pid) {
            signal_group(&process, f.pgid, signal);
        } else if !leaders.contains(&f.pgid) {
            signal_process(&process, signal);
        }
    }
}

fn wait_empty(now: &impl Fn() -> Vec<Found>, within: Duration) -> bool {
    let start = Instant::now();
    loop {
        if now().is_empty() {
            return true;
        }
        if start.elapsed() >= within {
            return false;
        }
        std::thread::sleep(POLL);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lifecycle::members::members;
    use crate::lifecycle::process::reference;
    use crate::model::now;
    use crate::model::session::{ProcessRef, SessionId, SessionKind};
    use std::os::unix::process::CommandExt;
    use std::process::Command;

    fn session_of(child: &std::process::Child) -> SessionRecord {
        SessionRecord {
            id: SessionId(1),
            sandbox: "home".parse().unwrap(),
            kind: SessionKind::Service,
            version: 1,
            snapshot: crate::model::policy::SnapshotId("x".into()),
            compiled: None,
            root: reference(child.id()).unwrap(),
            pgid: child.id(),
            tracked: Vec::new(),
            started_at: now(),
            ended_at: None,
        }
    }

    #[test]
    fn stop_ends_the_leader_and_the_members_it_started() {
        // A shell this test starts in its own group, with a child of its own.
        let mut child = Command::new("/bin/sh")
            .args(["-c", "/bin/sleep 30 & wait"])
            .process_group(0)
            .spawn()
            .unwrap();
        let session = session_of(&child);
        let start = Instant::now();
        while members(&session).len() < 2 && start.elapsed() < Duration::from_secs(5) {
            std::thread::sleep(POLL);
        }
        assert_eq!(members(&session).len(), 2);
        assert_eq!(stop(&session, Duration::from_secs(5)), Stopped::Clean);
        let _ = child.wait();
    }

    #[test]
    fn stop_ends_a_job_in_a_group_of_its_own() {
        // A child that moves to a group of its own, as an interactive
        // shell's jobs do.
        let mut child = Command::new("/bin/sh")
            .args(["-c", "/usr/bin/perl -e 'setpgrp; sleep 30' & wait"])
            .process_group(0)
            .spawn()
            .unwrap();
        let session = session_of(&child);
        let start = Instant::now();
        let job = loop {
            let found = members(&session);
            if let Some(job) = found.iter().find(|m| {
                crate::lifecycle::process::group_of(m.pid) == Some(m.pid) && m.pid != child.id()
            }) {
                break job.clone();
            }
            assert!(start.elapsed() < Duration::from_secs(5), "{found:?}");
            std::thread::sleep(POLL);
        };
        assert_eq!(stop(&session, Duration::from_secs(5)), Stopped::Clean);
        let _ = child.wait();
        assert!(!crate::lifecycle::process::is_same(&ProcessRef {
            pid: job.pid,
            started: job.started,
        }));
    }

    #[test]
    fn a_member_ignoring_term_is_killed() {
        let mut child = Command::new("/bin/sh")
            .args(["-c", "trap '' TERM; /bin/sleep 30"])
            .process_group(0)
            .spawn()
            .unwrap();
        std::thread::sleep(Duration::from_millis(200));
        let session = session_of(&child);
        assert_eq!(stop(&session, Duration::from_millis(500)), Stopped::Clean);
        let _ = child.wait();
    }
}
