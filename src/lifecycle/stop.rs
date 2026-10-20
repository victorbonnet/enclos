//! Stopping a session: every member (design §8).
//!
//! TERM to the members, a grace period, KILL to what is left, then a check.
//! A group is signalled through its leader when the leader is a sure
//! member; any sure member outside those groups is signalled alone; members
//! that are only counted are never signalled, and are reported if they
//! remain (see `members`), each survivor with why it survived.

use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

use super::members::{Found, find};
use super::process::{PsError, Signal, Signalled, processes, signal_group, signal_process};
use crate::model::session::{Member, ProcessRef, SessionRecord};

/// How long members have to exit after TERM, and again after KILL.
pub const GRACE: Duration = Duration::from_secs(5);
const POLL: Duration = Duration::from_millis(50);

/// What stopping one session did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stopped {
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
}

impl Why {
    pub fn describe(&self) -> String {
        match self {
            Why::NotSignalled => {
                "not signalled: enclos cannot prove it is the session's".to_owned()
            }
            Why::Survived => "still runs after TERM and KILL".to_owned(),
            Why::NotSent(why) => format!("could not be signalled: {why}"),
        }
    }
}

pub fn stop(session: &SessionRecord, grace: Duration) -> Result<Stopped, PsError> {
    let first = find(&processes()?, session, &session.tracked);
    if !first.iter().any(|f| f.sure) {
        // Nothing enclos may signal: what is only counted is reported.
        return Ok(survivors(first, &Signals::default()));
    }
    // What was found stays known while the signals end parents: a member
    // whose parent exits first is still the session's.
    let mut known = session.tracked.clone();
    known.extend(first.iter().filter_map(Found::sure_ref));
    let now = || -> Result<Vec<Found>, PsError> { Ok(find(&processes()?, session, &known)) };
    let mut signals = Signals::default();
    signals.send(&first, Signal::Term)?;
    if wait_empty(&now, grace)? {
        return Ok(Stopped::Clean);
    }
    signals.send(&now()?, Signal::Kill)?;
    if wait_empty(&now, grace)? {
        return Ok(Stopped::Clean);
    }
    Ok(survivors(now()?, &signals))
}

fn survivors(left: Vec<Found>, signals: &Signals) -> Stopped {
    if left.is_empty() {
        return Stopped::Clean;
    }
    let survivors = left
        .into_iter()
        .map(|f| {
            let pid = f.member.pid;
            let why = match (f.sure, signals.failed.get(&pid)) {
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
            version: 1,
            snapshot: crate::model::policy::SnapshotId("x".into()),
            compiled: None,
            root: reference(child.id()).unwrap().unwrap(),
            pgid: Some(child.id()),
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
