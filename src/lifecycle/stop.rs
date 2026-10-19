//! Stopping a session: every member of its process group (design §8).
//!
//! TERM to the group, a grace period, KILL to what is left, then a check.
//! The group is signalled only while its recorded leader is still the same
//! process (see `process`). If the leader is already gone, nothing is
//! signalled and whatever still runs in its group is reported as surviving.
//!
//! Known gap (milestone 1): a member that leaves the group (`setsid`) is
//! not seen. It keeps its Seatbelt restrictions, so this is a lifecycle bug,
//! not a way out of the sandbox (ADR 0019).

use std::time::{Duration, Instant};

use super::process::{Signal, group_members, is_same, signal_group};
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
    if !is_same(&session.root) {
        // The leader is gone: its group may still hold members, but without
        // the leader there is no proof they are this session's.
        let left = group_members(session.pgid);
        return if left.is_empty() {
            Stopped::Clean
        } else {
            Stopped::Survivors(left)
        };
    }
    signal_group(&session.root, session.pgid, Signal::Term);
    if wait_empty(session.pgid, grace) {
        return Stopped::Clean;
    }
    // KILL needs the leader too; a leader that already exited leaves its
    // members to be reported.
    signal_group(&session.root, session.pgid, Signal::Kill);
    if wait_empty(session.pgid, grace) {
        Stopped::Clean
    } else {
        Stopped::Survivors(group_members(session.pgid))
    }
}

fn wait_empty(pgid: u32, within: Duration) -> bool {
    let start = Instant::now();
    loop {
        if group_members(pgid).is_empty() {
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
    use crate::lifecycle::process::reference;
    use crate::model::now;
    use crate::model::session::{SessionId, SessionKind};
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
        while group_members(session.pgid).len() < 2 && start.elapsed() < Duration::from_secs(5) {
            std::thread::sleep(POLL);
        }
        assert_eq!(group_members(session.pgid).len(), 2);
        assert_eq!(stop(&session, Duration::from_secs(5)), Stopped::Clean);
        let _ = child.wait();
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
