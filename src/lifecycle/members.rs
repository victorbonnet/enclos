//! Finding a session's members on macOS (design §8, ADR 0019).
//!
//! A session's members are its root process and what it recorded, every
//! child of a member, and every process in a group a member leads: an
//! interactive shell puts itself and each of its shell jobs in groups of
//! their own, so the session's first group alone would miss them. While a
//! session runs, enclos records the sure members it sees, so that one
//! whose parent exited is still found by itself.
//!
//! The group a session started in also counts: a group made for the
//! program once its leader, the program, is gone, since nothing then
//! proves the group is still the session's; and, in the terminal's job,
//! which the `enclos` holding the terminal leads, only processes that lost
//! their parent, since the rest of that group is the caller's. Those are
//! counted but never signalled.
//!
//! A process holding the session's marker (ADR 0030) is a sure member too:
//! the engine adds it to `tracked`, so a double fork is found and stopped.
//!
//! Known gap: a process that closes its marker's descriptor and leaves its
//! group and parent is seen only by the rules above. It keeps its Seatbelt
//! restrictions, so this is a lifecycle bug, not a way out of the sandbox.

use std::collections::BTreeSet;

use super::process::{Proc, PsError, processes};
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
    /// The process, to record or signal, when it is a sure member; a member
    /// that is only counted gives none.
    pub fn sure_ref(&self) -> Option<ProcessRef> {
        self.sure.then(|| ProcessRef {
            pid: self.member.pid,
            started: self.member.started.clone(),
        })
    }
}

/// The session's members running now.
pub fn members(session: &SessionRecord) -> Result<Vec<Member>, PsError> {
    Ok(find(&processes()?, session, &session.tracked)
        .into_iter()
        .map(|f| f.member)
        .collect())
}

/// Whether nothing of `session` runs in `procs`: its root and every member
/// it recorded are gone (no longer listed, or listed with another start
/// time, as after a restart of the Mac), and nothing else counts as its
/// member. Only its end is then left to record.
pub fn is_gone(procs: &[Proc], session: &SessionRecord) -> bool {
    find(procs, session, &session.tracked).is_empty()
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
    let mut counted: BTreeSet<u32> = match session.pgid {
        None => BTreeSet::new(),
        Some(pgid) => {
            let made_for_it = pgid == session.root.pid;
            let leader_runs = procs.iter().any(|p| p.pid == pgid);
            if made_for_it && leader_runs {
                BTreeSet::new()
            } else {
                procs
                    .iter()
                    .filter(|p| p.pgid == pgid && p.pid != pgid && (made_for_it || p.ppid == 1))
                    .map(|p| p.pid)
                    .filter(|pid| !sure.contains(pid))
                    .collect()
            }
        }
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
        // A group whose pgid is a member's pid is not the member's unless
        // the member leads it: its leader may have exited and its pid gone
        // to the member.
        let leads: BTreeSet<u32> = procs
            .iter()
            .filter(|p| set.contains(&p.pid) && p.pgid == p.pid)
            .map(|p| p.pid)
            .collect();
        let more: Vec<u32> = procs
            .iter()
            .filter(|p| !set.contains(&p.pid) && !besides.contains(&p.pid))
            .filter(|p| set.contains(&p.ppid) || leads.contains(&p.pgid))
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

    fn session(root: u32, pgid: Option<u32>) -> SessionRecord {
        SessionRecord {
            id: SessionId(1),
            sandbox: "home".parse().unwrap(),
            kind: SessionKind::Interactive,
            service: None,
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
        let found = find(&terminal(), &session(21, Some(20)), &[]);
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
        assert!(find(&procs, &session(21, Some(20)), &[]).is_empty());
        let found = find(&procs, &session(21, Some(20)), &[at(22)]);
        assert_eq!(pids(&found), [(22, true), (23, true)]);
    }

    #[test]
    fn a_recorded_pid_now_used_by_another_process_is_not_a_member() {
        let procs = vec![proc(22, 1, 22)];
        let reused = ProcessRef {
            pid: 22,
            started: "earlier".into(),
        };
        assert!(find(&procs, &session(21, Some(20)), &[reused]).is_empty());
    }

    #[test]
    fn what_the_program_left_in_its_own_group_is_counted_but_not_sure() {
        // The program (30) led a group made for it and exited; a child it
        // started there runs on, and that child's own child too.
        let procs = vec![proc(31, 1, 30), proc(32, 31, 30)];
        let found = find(&procs, &session(30, Some(30)), &[]);
        assert_eq!(pids(&found), [(31, false), (32, false)]);
    }

    #[test]
    fn a_group_whose_leader_pid_was_reused_is_not_the_sessions() {
        // pid 30 now leads another group: the session's group is gone.
        let procs = vec![proc(30, 1, 30), proc(31, 30, 30)];
        let mut s = session(30, Some(30));
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
        let found = find(&procs, &session(21, Some(20)), &[]);
        assert_eq!(pids(&found), [(26, false)]);
    }

    #[test]
    fn a_group_is_a_members_only_when_the_member_leads_it() {
        // 22 is the shell's child in the shell's group. Group 22, left by a
        // leader that exited, holds 30: pid 22 was reused, and 30 is not
        // the session's.
        let procs = vec![proc(21, 20, 21), proc(22, 21, 21), proc(30, 1, 22)];
        let found = find(&procs, &session(21, Some(20)), &[]);
        assert_eq!(pids(&found), [(21, true), (22, true)]);
    }

    #[test]
    fn a_session_is_gone_only_when_nothing_of_it_runs() {
        let mut s = session(30, Some(30));
        s.tracked = vec![at(40)];
        // After a restart of the Mac: its pids are free, or used again by
        // processes started at other times.
        let restarted = vec![proc(10, 1, 10), proc(31, 1, 31)];
        let mut reused = proc(30, 1, 30);
        reused.started = "later".into();
        assert!(is_gone(&restarted, &s));
        assert!(is_gone(&[reused], &s));
        // Its root, a member it recorded, or what is left in its group
        // keeps it open.
        assert!(!is_gone(&[proc(30, 1, 30)], &s));
        assert!(!is_gone(&[proc(40, 1, 40)], &s));
        assert!(!is_gone(&[proc(31, 1, 30)], &s));
    }

    #[test]
    fn after_a_restart_a_recorded_member_or_the_terminals_job_whose_pids_were_reused_is_gone() {
        // A shell (21) run from a terminal, whose job the `enclos` holding
        // it (20) led, and a job of the shell (22) it recorded.
        let mut s = session(21, Some(20));
        s.tracked = vec![at(22)];
        // After the restart, every one of those pids runs another process,
        // started at another time, each in a group of its own, as launchd
        // starts its jobs; one of them has a child in its group.
        let mut restarted = vec![
            proc(20, 1, 20),
            proc(21, 1, 21),
            proc(22, 1, 22),
            proc(23, 20, 20),
        ];
        for p in &mut restarted[..3] {
            p.started = "after the restart".into();
        }
        assert!(is_gone(&restarted, &s));
        // A process that lost its parent in a group with the number of the
        // terminal's job still counts, never signalled: nothing tells it
        // apart from what the session left, so the session stays open rather
        // than ending while a member may run.
        assert!(!is_gone(&[proc(24, 1, 20)], &s));
    }

    #[test]
    fn only_sure_members_give_a_process_to_record_or_signal() {
        let procs = vec![proc(31, 1, 30), proc(32, 31, 30)];
        let counted = find(&procs, &session(30, Some(30)), &[]);
        assert!(counted.iter().all(|f| f.sure_ref().is_none()));
        let sure = find(&procs, &session(30, Some(30)), &[at(31)]);
        assert_eq!(sure[0].sure_ref(), Some(at(31)));
    }

    #[test]
    fn a_session_without_a_group_of_its_own_counts_only_its_tree() {
        // Started from a terminal by another program (40), which leads the
        // job: the session has no group, and the caller is never counted.
        let procs = vec![proc(40, 1, 40), proc(41, 40, 40), proc(42, 41, 40)];
        let found = find(&procs, &session(41, None), &[]);
        assert_eq!(pids(&found), [(41, true), (42, true)]);
    }
}
