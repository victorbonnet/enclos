//! Stopping a session: every member (design §8).
//!
//! TERM to the members, a grace period, KILL to what is left, then a check.
//! A group is signalled through its leader when the leader is a sure
//! member; any sure member outside those groups is signalled alone; members
//! that are only counted are never signalled, and are reported if they
//! remain (see `members`), each survivor with why it survived. A session in
//! a cgroup is looked at through it at every step: what the cgroup holds is
//! signalled, KILL goes to the whole cgroup, and the check reads it again, so
//! a process `ps` does not list is reported too.

use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

use super::cgroup::Hierarchy;
use super::members::{Found, find};
use super::process::{Proc, PsError, Signal, Signalled, processes, signal_group, signal_process};
use crate::model::session::{Member, ProcessRef, SessionRecord};

/// How long members have to exit after TERM, and again after KILL.
pub const GRACE: Duration = Duration::from_secs(5);
const POLL: Duration = Duration::from_millis(50);

/// What stopping one session did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stopped {
    /// Nothing of the session ran when `stop` first looked: nothing was
    /// signalled, and only its end is left to record.
    Gone,
    /// Every member is gone.
    Clean,
    /// These members still run.
    Survivors(Vec<Survivor>),
}

/// A member still running after `stop`, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Survivor {
    pub member: Member,
    pub why: Why,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Why {
    /// Only counted, so never signalled: nothing proves it is the session's.
    NotSignalled,
    /// Sent TERM and KILL, and still runs.
    Survived,
    /// enclos could not signal it, with why.
    NotSent(String),
    /// Its session's cgroup holds it, and `ps` does not list it.
    NotListed,
}

impl Why {
    pub fn describe(&self) -> String {
        match self {
            Why::NotSignalled => {
                "not signalled: enclos cannot prove it is the session's".to_owned()
            }
            Why::Survived => "still runs after TERM and KILL".to_owned(),
            Why::NotSent(why) => format!("could not be signalled: {why}"),
            Why::NotListed => "still in the session's cgroup, and not listed by ps".to_owned(),
        }
    }
}

/// Each survivor as `pid N command: why`, as `sandbox stop` lists them.
pub fn describe_survivors(left: &[Survivor]) -> String {
    left.iter()
        .map(|s| {
            format!(
                "pid {} {}: {}",
                s.member.pid,
                s.member.command,
                s.why.describe()
            )
        })
        .collect::<Vec<_>>()
        .join("; ")
}

pub fn stop(session: &SessionRecord, grace: Duration) -> Result<Stopped, PsError> {
    stop_in(&Hierarchy::host(), session, grace)
}

/// `stop`, reading a session's cgroup in `cgroups`.
fn stop_in(
    cgroups: &Hierarchy,
    session: &SessionRecord,
    grace: Duration,
) -> Result<Stopped, PsError> {
    let first = look(cgroups, session, &session.tracked)?;
    if first.is_empty() {
        return Ok(Stopped::Gone);
    }
    if !first.iter().any(|f| f.sure) {
        // Nothing enclos may signal: what is only counted is reported.
        return Ok(survivors(first, &Signals::default(), session));
    }
    // What was found stays known while the signals end parents: a member
    // whose parent exits first is still the session's.
    let mut known = session.tracked.clone();
    known.extend(first.iter().filter_map(Found::sure_ref));
    let now = || look(cgroups, session, &known);
    let mut signals = Signals::default();
    signals.send(&first, Signal::Term)?;
    if wait_empty(&now, grace)? {
        return Ok(Stopped::Clean);
    }
    if let Some(cgroup) = &session.cgroup {
        cgroups.kill(cgroup);
    }
    signals.send(&now()?, Signal::Kill)?;
    if wait_empty(&now, grace)? {
        return Ok(Stopped::Clean);
    }
    Ok(survivors(now()?, &signals, session))
}

/// The members of `session` now, with what its cgroup holds as sure members.
/// A process in the cgroup that a second listing does not show either is
/// neither signalled nor forgotten: it is found, and not sure.
fn look(
    cgroups: &Hierarchy,
    session: &SessionRecord,
    known: &[ProcessRef],
) -> Result<Vec<Found>, PsError> {
    let mut procs = processes()?;
    let Some(cgroup) = &session.cgroup else {
        return Ok(find(&procs, session, known));
    };
    let unlisted = |pids: &BTreeSet<u32>, procs: &[Proc]| -> BTreeSet<u32> {
        let listed: BTreeSet<u32> = procs.iter().map(|p| p.pid).collect();
        pids.difference(&listed).copied().collect()
    };
    let mut inside = cgroups.pids(cgroup)?;
    if !unlisted(&inside, &procs).is_empty() {
        procs = processes()?;
        inside = cgroups.pids(cgroup)?;
    }
    let mut known = known.to_vec();
    known.extend(
        procs
            .iter()
            .filter(|p| inside.contains(&p.pid))
            .map(|p| ProcessRef {
                pid: p.pid,
                started: p.started.clone(),
            }),
    );
    let mut found = find(&procs, session, &known);
    found.extend(unlisted(&inside, &procs).into_iter().map(|pid| Found {
        member: Member {
            pid,
            started: String::new(),
            command: "(not listed)".to_owned(),
        },
        pgid: 0,
        sure: false,
    }));
    Ok(found)
}

fn survivors(left: Vec<Found>, signals: &Signals, session: &SessionRecord) -> Stopped {
    if left.is_empty() {
        return Stopped::Clean;
    }
    let survivors = left
        .into_iter()
        .map(|f| {
            let pid = f.member.pid;
            let why = match (f.sure, signals.failed.get(&pid)) {
                (false, _) if session.cgroup.is_some() => Why::NotListed,
                (false, _) => Why::NotSignalled,
                (true, Some(why)) => Why::NotSent(why.clone()),
                (true, None) if signals.tried.contains(&pid) => Why::Survived,
                (true, None) => Why::NotSent("it started after the last signal".to_owned()),
            };
            Survivor {
                member: f.member,
                why,
            }
        })
        .collect();
    Stopped::Survivors(survivors)
}

/// The signals sent so far: to which members, and which could not be sent.
#[derive(Default)]
struct Signals {
    tried: BTreeSet<u32>,
    failed: BTreeMap<u32, String>,
}

impl Signals {
    fn send(&mut self, found: &[Found], signal: Signal) -> Result<(), PsError> {
        let sure: Vec<(&Found, ProcessRef)> = found
            .iter()
            .filter_map(|f| f.sure_ref().map(|r| (f, r)))
            .collect();
        // Groups whose leader is a sure member, signalled through it. A
        // leader that left its group, or exited, leaves its members to be
        // signalled alone.
        let mut groups: BTreeMap<u32, Option<String>> = BTreeMap::new();
        for (f, leader) in &sure {
            if f.member.pid != f.pgid {
                continue;
            }
            match signal_group(leader, f.pgid, signal)? {
                Signalled::Sent => {
                    groups.insert(f.pgid, None);
                }
                Signalled::Failed(why) => {
                    groups.insert(f.pgid, Some(why));
                }
                Signalled::Gone | Signalled::NotLeader => {}
            }
        }
        for (f, process) in &sure {
            let pid = f.member.pid;
            self.tried.insert(pid);
            match groups.get(&f.pgid) {
                Some(None) => {}
                Some(Some(why)) => {
                    self.failed.insert(pid, why.clone());
                }
                None => {
                    if let Signalled::Failed(why) = signal_process(process, signal)? {
                        self.failed.insert(pid, why);
                    }
                }
            }
        }
        Ok(())
    }
}

fn wait_empty(
    now: &impl Fn() -> Result<Vec<Found>, PsError>,
    within: Duration,
) -> Result<bool, PsError> {
    let start = Instant::now();
    loop {
        if now()?.is_empty() {
            return Ok(true);
        }
        if start.elapsed() >= within {
            return Ok(false);
        }
        std::thread::sleep(POLL);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lifecycle::members::members;
    use crate::lifecycle::process::{group_of, is_same, reference};
    use crate::model::now;
    use crate::model::session::{SessionId, SessionKind};
    use std::io::Write;
    use std::os::unix::process::CommandExt;
    use std::process::{Child, Command, Stdio};

    fn session_of(child: &Child) -> SessionRecord {
        SessionRecord {
            id: SessionId(1),
            sandbox: "home".parse().unwrap(),
            kind: SessionKind::Service,
            service: Some("gateway".into()),
            version: 1,
            snapshot: crate::model::policy::SnapshotId("x".into()),
            compiled: None,
            root: reference(child.id()).unwrap().unwrap(),
            pgid: Some(child.id()),
            cgroup: None,
            tracked: Vec::new(),
            started_at: now(),
            ended_at: None,
        }
    }

    /// A shell running `script` in a group of its own, which exits once its
    /// input closes.
    fn shell_until_input_closes(script: &str) -> Child {
        Command::new("/bin/sh")
            .args(["-c", &format!("{script} read line")])
            .stdin(Stdio::piped())
            .process_group(0)
            .spawn()
            .unwrap()
    }

    /// Waits until `session` has a member besides its root for which `pick`
    /// holds, and returns it.
    fn member_besides_root(session: &SessionRecord, pick: impl Fn(&Member) -> bool) -> Member {
        let start = Instant::now();
        loop {
            let found = members(session).unwrap();
            if let Some(m) = found.iter().find(|m| m.pid != session.root.pid && pick(m)) {
                return m.clone();
            }
            assert!(start.elapsed() < Duration::from_secs(5), "{found:?}");
            std::thread::sleep(POLL);
        }
    }

    fn reference_to(m: &Member) -> ProcessRef {
        ProcessRef {
            pid: m.pid,
            started: m.started.clone(),
        }
    }

    /// A stand-in for the cgroup hierarchy with one cgroup holding `pids`,
    /// and `session` in it.
    fn in_cgroup(session: &mut SessionRecord, pids: &[u32]) -> (tempfile::TempDir, Hierarchy) {
        let dir = tempfile::tempdir().unwrap();
        session.cgroup = Some("/s.scope".to_owned());
        write_cgroup(dir.path(), pids);
        let cgroups = Hierarchy::at(dir.path());
        (dir, cgroups)
    }

    fn write_cgroup(root: &std::path::Path, pids: &[u32]) {
        let folder = root.join("s.scope");
        std::fs::create_dir_all(&folder).unwrap();
        let text: String = pids.iter().map(|p| format!("{p}\n")).collect();
        std::fs::write(folder.join("cgroup.procs"), text).unwrap();
    }

    #[test]
    fn a_member_that_left_its_group_and_parent_is_ended_through_the_cgroup() {
        // Started apart: no group, parent or record ties it to the session.
        let mut root = shell_until_input_closes("");
        let mut other = shell_until_input_closes("");
        let mut session = session_of(&root);
        let (dir, cgroups) = in_cgroup(&mut session, &[root.id(), other.id()]);
        let other_ref = reference(other.id()).unwrap().unwrap();

        // The stand-in does not empty itself: this thread does, as each exits.
        let done = std::sync::atomic::AtomicBool::new(false);
        let stopped = std::thread::scope(|s| {
            s.spawn(|| {
                while !done.load(std::sync::atomic::Ordering::Relaxed) {
                    let left: Vec<u32> = [root.id(), other.id()]
                        .into_iter()
                        .filter(|pid| {
                            std::fs::read_to_string(format!("/proc/{pid}/stat"))
                                .is_ok_and(|s| !s.contains(") Z "))
                        })
                        .collect();
                    write_cgroup(dir.path(), &left);
                    std::thread::sleep(POLL);
                }
            });
            let stopped = stop_in(&cgroups, &session, GRACE).unwrap();
            done.store(true, std::sync::atomic::Ordering::Relaxed);
            stopped
        });
        assert_eq!(stopped, Stopped::Clean);
        let _ = root.wait();
        let _ = other.wait();
        assert!(!is_same(&other_ref).unwrap());
    }

    #[test]
    fn what_stays_in_the_cgroup_after_kill_is_reported_with_why() {
        // A pid `ps` cannot list: this test's stand-in holds it for ever.
        let unlisted = u32::MAX - 1;
        let mut root = shell_until_input_closes("");
        let mut session = session_of(&root);
        let (dir, cgroups) = in_cgroup(&mut session, &[root.id(), unlisted]);
        let stopped = stop_in(&cgroups, &session, Duration::from_millis(100)).unwrap();
        let _ = root.wait();
        let Stopped::Survivors(left) = stopped else {
            panic!("{stopped:?}");
        };
        let why: Vec<_> = left.iter().map(|s| (s.member.pid, &s.why)).collect();
        assert!(why.contains(&(unlisted, &Why::NotListed)), "{why:?}");
        let asked = dir.path().join("s.scope/cgroup.kill");
        assert_eq!(std::fs::read_to_string(asked).unwrap(), "1");
    }

    #[test]
    fn an_empty_cgroup_is_gone_and_a_cgroup_that_cannot_be_read_is_an_error() {
        let mut root = shell_until_input_closes("");
        let mut session = session_of(&root);
        // The root is a member by its record, so only once it exited.
        drop(root.stdin.take());
        root.wait().unwrap();
        let (dir, cgroups) = in_cgroup(&mut session, &[]);
        assert_eq!(stop_in(&cgroups, &session, GRACE).unwrap(), Stopped::Gone);
        std::fs::write(dir.path().join("s.scope/cgroup.procs"), "x\n").unwrap();
        assert!(stop_in(&cgroups, &session, GRACE).is_err());
    }

    #[test]
    fn a_session_of_which_nothing_runs_is_gone_and_nothing_is_signalled() {
        let mut child = shell_until_input_closes("");
        let session = session_of(&child);
        drop(child.stdin.take());
        child.wait().unwrap();
        assert_eq!(stop(&session, GRACE).unwrap(), Stopped::Gone);
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
        member_besides_root(&session, |_| true);
        assert_eq!(stop(&session, GRACE).unwrap(), Stopped::Clean);
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
        let job = member_besides_root(&session, |m| group_of(m.pid).unwrap() == Some(m.pid));
        assert_eq!(stop(&session, GRACE).unwrap(), Stopped::Clean);
        let _ = child.wait();
        assert!(!is_same(&reference_to(&job)).unwrap());
    }

    #[test]
    fn a_member_ignoring_term_is_killed() {
        let mut child = Command::new("/bin/sh")
            .args(["-c", "trap '' TERM; /bin/sleep 30"])
            .process_group(0)
            .spawn()
            .unwrap();
        let session = session_of(&child);
        member_besides_root(&session, |_| true);
        let started = Instant::now();
        assert_eq!(
            stop(&session, Duration::from_millis(500)).unwrap(),
            Stopped::Clean
        );
        // The shell ignored TERM: only KILL, after the grace, ended it.
        assert!(started.elapsed() >= Duration::from_millis(500));
        let _ = child.wait();
    }

    #[test]
    fn term_comes_first_and_a_member_that_obeys_it_ends_well_within_the_grace() {
        let mut child = Command::new("/bin/sh")
            .args(["-c", "trap 'exit 7' TERM; /bin/sleep 30 & wait"])
            .process_group(0)
            .spawn()
            .unwrap();
        let session = session_of(&child);
        member_besides_root(&session, |_| true);
        let started = Instant::now();
        assert_eq!(stop(&session, GRACE).unwrap(), Stopped::Clean);
        assert!(started.elapsed() < Duration::from_secs(2));
        assert_eq!(child.wait().unwrap().code(), Some(7));
    }

    #[test]
    fn a_job_found_only_through_what_was_recorded_is_stopped() {
        // The shell starts a job in a group of its own that ignores TERM,
        // and exits: the job lost its parent and its group is no member's.
        let mut child = shell_until_input_closes(
            "/usr/bin/perl -e '$SIG{TERM} = q(IGNORE); setpgrp; sleep 30' &",
        );
        let mut session = session_of(&child);
        let job = member_besides_root(&session, |m| group_of(m.pid).unwrap() == Some(m.pid));
        drop(child.stdin.take());
        child.wait().unwrap();
        assert!(members(&session).unwrap().is_empty());

        // What `connect` recorded while the shell ran finds it.
        session.tracked = vec![reference_to(&job)];
        assert_eq!(members(&session).unwrap(), std::slice::from_ref(&job));
        assert_eq!(
            stop(&session, Duration::from_millis(500)).unwrap(),
            Stopped::Clean
        );
        assert!(!is_same(&reference_to(&job)).unwrap());
    }

    #[test]
    fn a_member_only_counted_is_reported_and_never_signalled() {
        // The program leaves a sleep in the group made for it, and exits.
        let mut child = shell_until_input_closes("/bin/sleep 30 &");
        let session = session_of(&child);
        let sleep = member_besides_root(&session, |_| true);
        child.stdin.take().unwrap().write_all(b"\n").unwrap();
        child.wait().unwrap();

        let stopped = stop(&session, Duration::from_millis(200)).unwrap();
        assert_eq!(
            stopped,
            Stopped::Survivors(vec![Survivor {
                member: sleep.clone(),
                why: Why::NotSignalled,
            }])
        );
        let sleep = reference_to(&sleep);
        assert!(is_same(&sleep).unwrap(), "the sleep was signalled");
        assert_eq!(
            signal_process(&sleep, Signal::Kill).unwrap(),
            Signalled::Sent
        );
    }
}
