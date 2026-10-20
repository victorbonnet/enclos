//! Finding a session's members on macOS (design §8, ADR 0019).
//!
//! A session's members are its root process and what it recorded, every
//! child of a member, and every process in a group a member leads: an
//! interactive shell puts itself and each of its jobs in groups of their
//! own, so the session's first group alone would miss them. While a
//! session runs, enclos records the members it sees, so that one whose
//! parent exited is still found by itself.
//!
//! The group a session started in also counts when its leader is gone:
//! the members the program left there. Those are counted but never
//! signalled, since without the leader nothing proves the group is still
//! the session's.
//!
//! Known gaps (milestone 1): a process that leaves its group (`setsid`),
//! or that starts and loses its parent between two looks, is not seen. It
//! keeps its Seatbelt restrictions, so this is a lifecycle bug, not a way
//! out of the sandbox.

use std::collections::BTreeSet;

use super::process::{Proc, processes};
use crate::model::session::{Member, ProcessRef, SessionRecord};

/// A member found in one listing of the processes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Found {
    pub member: Member,
    pub pgid: u32,
    /// Reached from the root or a recorded member, which enclos may
    /// signal; otherwise only counted.
    pub sure: bool,
}

impl Found {
    pub fn process(&self) -> ProcessRef {
        ProcessRef {
            pid: self.member.pid,
            started: self.member.started.clone(),
        }
    }
}

/// The session's members running now.
pub fn members(session: &SessionRecord) -> Vec<Member> {
    find(&processes(), session, &session.tracked)
        .into_iter()
        .map(|f| f.member)
        .collect()
}

/// The members of `session` in `procs`, also looking for the `tracked`
/// processes, which replace what the session recorded.
pub fn find(procs: &[Proc], session: &SessionRecord, tracked: &[ProcessRef]) -> Vec<Found> {
    let is = |p: &Proc, r: &ProcessRef| p.pid == r.pid && p.started == r.started;
    let mut sure: BTreeSet<u32> = procs
        .iter()
        .filter(|p| is(p, &session.root) || tracked.iter().any(|r| is(p, r)))
        .map(|p| p.pid)
        .collect();
    grow(procs, &mut sure, &BTreeSet::new());

    // The group the session started in. A group made for it counts once
    // its leader, the root, is gone: whatever is left there. (While a
    // process has the leader's pid, it is the root, whose group is found
    // above, or the pid was reused and the group is no longer the
    // session's.) In the group of the `enclos` holding the terminal, which
    // is not a member, only what lost its parent counts: a pager piped
    // from `enclos` is the caller's.
    let pgid = session.pgid;
    let made_for_it = pgid == session.root.pid;
    let leader_runs = procs.iter().any(|p| p.pid == pgid);
    let mut counted: BTreeSet<u32> = if pgid == 0 || (made_for_it && leader_runs) {
        BTreeSet::new()
    } else {
        procs
            .iter()
            .filter(|p| p.pgid == pgid && p.pid != pgid && (made_for_it || p.ppid == 1))
            .map(|p| p.pid)
            .filter(|pid| !sure.contains(pid))
            .collect()
    };
    grow(procs, &mut counted, &sure);

    procs
        .iter()
        .filter(|p| sure.contains(&p.pid) || counted.contains(&p.pid))
        .map(|p| Found {
            member: Member {
                pid: p.pid,
                started: p.started.clone(),
                command: p.command.clone(),
            },
            pgid: p.pgid,
            sure: sure.contains(&p.pid),
        })
        .collect()
}

/// Adds to `set` every child of its processes and every process in a
/// group one of them leads, until nothing changes; `besides` are left out.
fn grow(procs: &[Proc], set: &mut BTreeSet<u32>, besides: &BTreeSet<u32>) {
    loop {
        let more: Vec<u32> = procs
            .iter()
            .filter(|p| !set.contains(&p.pid) && !besides.contains(&p.pid))
            .filter(|p| set.contains(&p.ppid) || set.contains(&p.pgid))
            .map(|p| p.pid)
            .collect();
        if more.is_empty() {
            return;
        }
        set.extend(more);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::now;
    use crate::model::session::{SessionId, SessionKind};

    fn proc(pid: u32, ppid: u32, pgid: u32) -> Proc {
        Proc {
            pid,
            ppid,
            pgid,
            started: format!("t{pid}"),
            command: format!("p{pid}"),
        }
    }

    fn at(pid: u32) -> ProcessRef {
        ProcessRef {
            pid,
            started: format!("t{pid}"),
        }
    }

    fn session(root: u32, pgid: u32) -> SessionRecord {
        SessionRecord {
            id: SessionId(1),
            sandbox: "home".parse().unwrap(),
            kind: SessionKind::Interactive,
            version: 1,
            snapshot: crate::model::policy::SnapshotId("x".into()),
            compiled: None,
            root: at(root),
            pgid,
            tracked: Vec::new(),
            started_at: now(),
            ended_at: None,
        }
    }

    fn pids(found: &[Found]) -> Vec<(u32, bool)> {
        found.iter().map(|f| (f.member.pid, f.sure)).collect()
    }

    /// An outer shell (10, its own group), an `enclos` leading its job
    /// (20), the sandboxed shell it started (21) in a group of its own,
    /// and the shell's foreground job (22) in another.
    fn terminal() -> Vec<Proc> {
        vec![
            proc(10, 1, 10),
            proc(20, 10, 20),
            proc(21, 20, 21),
            proc(22, 21, 22),
            proc(23, 22, 22),
        ]
    }

    #[test]
    fn a_shell_and_its_jobs_are_members_and_the_enclos_holding_the_terminal_is_not() {
        let found = find(&terminal(), &session(21, 20), &[]);
        assert_eq!(pids(&found), [(21, true), (22, true), (23, true)]);
    }

    #[test]
    fn a_job_whose_shell_exited_is_found_through_what_was_recorded() {
        // The shell exited; its background job (22, 23) lost its parent.
        let procs = vec![
            proc(10, 1, 10),
            proc(20, 10, 20),
            proc(22, 1, 22),
            proc(23, 22, 22),
        ];
        assert!(find(&procs, &session(21, 20), &[]).is_empty());
        let found = find(&procs, &session(21, 20), &[at(22)]);
        assert_eq!(pids(&found), [(22, true), (23, true)]);
    }

    #[test]
    fn a_recorded_pid_now_used_by_another_process_is_not_a_member() {
        let procs = vec![proc(22, 1, 22)];
        let reused = ProcessRef {
            pid: 22,
            started: "earlier".into(),
        };
        assert!(find(&procs, &session(21, 20), &[reused]).is_empty());
    }

    #[test]
    fn what_the_program_left_in_its_own_group_is_counted_but_not_sure() {
        // The program (30) led a group made for it and exited; a child it
        // started there runs on, and that child's own child too.
        let procs = vec![proc(31, 1, 30), proc(32, 31, 30)];
        let found = find(&procs, &session(30, 30), &[]);
        assert_eq!(pids(&found), [(31, false), (32, false)]);
    }

    #[test]
    fn a_group_whose_leader_pid_was_reused_is_not_the_sessions() {
        // pid 30 now leads another group: the session's group is gone.
        let procs = vec![proc(30, 1, 30), proc(31, 30, 30)];
        let mut s = session(30, 30);
        s.root.started = "earlier".into();
        assert!(find(&procs, &s, &[]).is_empty());
    }

    #[test]
    fn in_the_terminals_group_only_what_lost_its_parent_counts() {
        // enclos (20) leads the terminal's job; a pager (25) piped from it
        // belongs to the outer shell, and a sleep (26) the exited program
        // left behind lost its parent.
        let procs = vec![
            proc(10, 1, 10),
            proc(20, 10, 20),
            proc(25, 10, 20),
            proc(26, 1, 20),
        ];
        let found = find(&procs, &session(21, 20), &[]);
        assert_eq!(pids(&found), [(26, false)]);
    }

    #[test]
    fn a_session_without_a_group_of_its_own_counts_only_its_tree() {
        // Started from a terminal by another program (40), which leads the
        // job: the session has no group, and the caller is never counted.
        let procs = vec![proc(40, 1, 40), proc(41, 40, 40), proc(42, 41, 40)];
        let found = find(&procs, &session(41, 0), &[]);
        assert_eq!(pids(&found), [(41, true), (42, true)]);
    }
}
