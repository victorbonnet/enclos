//! One look at what runs of a sandbox's sessions (ADR 0019, ADR 0030).
//!
//! A session's members are found from a listing of the host's processes and
//! from the processes `lsof` shows holding its marker, always in that order:
//! a holder that exits in between, its pid reused, is then listed with its
//! own start time and fails the same-process check before a signal, where
//! the other order would name the process that reused the pid. A [`Look`]
//! can only be made that way, and it answers for every session of the
//! sandbox from the same listing.
//!
//! A look that fails says nothing about any session, so it is an error
//! rather than an answer: what it means is the caller's to decide. `sandbox
//! stop` treats every session as running, `sandbox rm` and `status` refuse,
//! `doctor` reports it is unsure, and a session whose program exited stays
//! open.
//!
//! Which listed processes are a session's is `members`'s to say; `stop`
//! sends the signals.

use std::borrow::Cow;
use std::path::Path;
use std::time::Duration;

use super::marker::{Held, MarkerError, holders, name_of};
use super::members::{Found, find, is_gone};
use super::process::{Proc, PsError, processes};
use super::stop::{Stopped, Survivor, Why};
use crate::model::session::{ProcessRef, SessionRecord};

/// Why a look could not be made.
#[derive(Debug, thiserror::Error)]
pub enum LookError {
    #[error(transparent)]
    Processes(#[from] PsError),
    #[error(transparent)]
    Markers(#[from] MarkerError),
}

/// The host's processes and who holds each marker of one sandbox.
#[derive(Debug)]
pub struct Look<'a> {
    procs: Cow<'a, [Proc]>,
    held: Held,
}

impl Look<'static> {
    /// Lists the processes, then looks at the markers in `markers`.
    pub fn now(markers: &Path) -> Result<Look<'static>, LookError> {
        let procs = processes()?;
        let held = holders(markers)?;
        Ok(Look {
            procs: Cow::Owned(procs),
            held,
        })
    }
}

impl<'a> Look<'a> {
    /// Looks at the markers in `markers`, after `procs`, for the commands
    /// that list the processes once for every sandbox.
    pub fn in_listing(procs: &'a [Proc], markers: &Path) -> Result<Look<'a>, MarkerError> {
        Ok(Look {
            procs: Cow::Borrowed(procs),
            held: holders(markers)?,
        })
    }

    /// `procs` with no marker held: when there are no markers to look for,
    /// or, with `&[]`, when no session is open and nothing was looked at.
    pub fn without_markers(procs: &'a [Proc]) -> Look<'a> {
        Look {
            procs: Cow::Borrowed(procs),
            held: Held::new(),
        }
    }

    /// The processes this look listed.
    pub fn listing(&self) -> &[Proc] {
        &self.procs
    }

    /// `session`, with the processes holding its marker added to those it
    /// tracked, each once.
    pub fn marked(&self, session: &SessionRecord) -> SessionRecord {
        let mut marked = session.clone();
        if let Some(pids) = self.held.get(&name_of(&session.root)) {
            for p in self.procs.iter().filter(|p| pids.contains(&p.pid)) {
                let holder = ProcessRef {
                    pid: p.pid,
                    started: p.started.clone(),
                };
                if !marked.tracked.contains(&holder) {
                    marked.tracked.push(holder);
                }
            }
        }
        marked
    }

    /// The members of `session` running now, what holds its marker included.
    pub fn members(&self, session: &SessionRecord) -> Vec<Found> {
        let marked = self.marked(session);
        find(&self.procs, &marked, &marked.tracked)
    }

    /// Whether nothing of `session` runs now, what holds its marker included.
    pub fn is_gone(&self, session: &SessionRecord) -> bool {
        is_gone(&self.procs, &self.marked(session))
    }
}

/// Stops `session`'s members, with what holds its marker, then, whatever
/// came of it, looks at the marker again: a process that gained it
/// meanwhile, such as one a member detached during the grace period or a
/// child its TERM handler forked, is stopped too, and one that survives that
/// is a survivor, so the session stays open.
///
/// `look` makes a fresh look, `stop` stops the members of a session, and
/// `runs` says whether a process still runs.
pub fn stop_marked(
    session: &SessionRecord,
    grace: Duration,
    look: impl Fn() -> Result<Look<'static>, LookError>,
    stop: impl Fn(&SessionRecord, Duration) -> Result<Stopped, PsError>,
    runs: impl Fn(&ProcessRef) -> Result<bool, PsError>,
) -> Result<Stopped, LookError> {
    let marked = look()?.marked(session);
    let first = stop(&marked, grace)?;
    // Looked at again whatever came of it, survivors included: a child a
    // member's TERM handler forked before it exited is an orphan only the
    // marker proves the session's, so it is reported as not signalled until
    // it is.
    let mut again = look()?.marked(session);
    if again.tracked.iter().all(|r| marked.tracked.contains(r)) {
        return Ok(first);
    }
    // What the first stop knew stays known: the first look's holders, and
    // the members it signalled that survived, which may since have closed
    // the marker or lost their parent.
    let earlier: Vec<Survivor> = match &first {
        Stopped::Survivors(left) => left.clone(),
        Stopped::Clean | Stopped::Gone => Vec::new(),
    };
    let signalled = earlier
        .iter()
        .filter(|s| !matches!(s.why, Why::NotSignalled))
        .map(|s| ProcessRef {
            pid: s.member.pid,
            started: s.member.started.clone(),
        });
    for known in marked.tracked.iter().cloned().chain(signalled) {
        if !again.tracked.contains(&known) {
            again.tracked.push(known);
        }
    }
    let second = stop(&again, grace)?;
    Ok(merged(first, second, runs)?)
}

/// What two stops of a session came to, the second after the marker gained
/// holders: the second's survivors, and each survivor of the first that
/// `runs` still and the second did not report, as one only counted, which
/// is never signalled for it but never dropped either. `Gone` only when
/// both found nothing.
fn merged(
    first: Stopped,
    second: Stopped,
    runs: impl Fn(&ProcessRef) -> Result<bool, PsError>,
) -> Result<Stopped, PsError> {
    let mut left = match &second {
        Stopped::Survivors(left) => left.clone(),
        Stopped::Clean | Stopped::Gone => Vec::new(),
    };
    if let Stopped::Survivors(earlier) = &first {
        for s in earlier {
            let process = ProcessRef {
                pid: s.member.pid,
                started: s.member.started.clone(),
            };
            if !left.iter().any(|l| l.member.pid == s.member.pid) && runs(&process)? {
                left.push(s.clone());
            }
        }
    }
    Ok(match (left.is_empty(), second, first) {
        (false, ..) => Stopped::Survivors(left),
        (true, Stopped::Gone, Stopped::Gone) => Stopped::Gone,
        (true, ..) => Stopped::Clean,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::now;
    use crate::model::session::{Member, SessionId, SessionKind};
    use std::cell::RefCell;
    use std::collections::BTreeSet;

    fn at(pid: u32) -> ProcessRef {
        ProcessRef {
            pid,
            started: format!("start {pid}"),
        }
    }

    fn session(id: i64, root: u32) -> SessionRecord {
        SessionRecord {
            id: SessionId(id),
            sandbox: "home".parse().unwrap(),
            kind: SessionKind::Interactive,
            service: None,
            version: 1,
            snapshot: crate::model::policy::SnapshotId("s".into()),
            compiled: None,
            pgid: None,
            root: at(root),
            tracked: Vec::new(),
            started_at: now(),
            ended_at: None,
        }
    }

    fn proc_(pid: u32) -> Proc {
        Proc {
            pid,
            ppid: 1,
            pgid: pid,
            started: format!("start {pid}"),
            command: "sleep".into(),
        }
    }

    /// A look at `procs`, with `held` holding the marker of `session`.
    fn look(procs: &[u32], session: &SessionRecord, held: &[u32]) -> Look<'static> {
        Look {
            procs: Cow::Owned(procs.iter().copied().map(proc_).collect()),
            held: match held {
                [] => Held::new(),
                pids => Held::from([(
                    name_of(&session.root),
                    pids.iter().copied().collect::<BTreeSet<u32>>(),
                )]),
            },
        }
    }

    fn pids(found: &[Found]) -> Vec<u32> {
        found.iter().map(|f| f.member.pid).collect()
    }

    fn survivor(pid: u32, why: Why) -> Survivor {
        Survivor {
            member: Member {
                pid,
                started: format!("start {pid}"),
                command: "sleep".into(),
            },
            why,
        }
    }

    /// A process holding one session's marker is that session's member,
    /// never another's (ADR 0030).
    #[test]
    fn a_marker_holder_is_its_own_sessions_member_only() {
        let (a, b) = (session(1, 10), session(2, 20));
        let seen = look(&[11, 12, 21], &a, &[11, 12]);
        assert_eq!(seen.marked(&a).tracked, [at(11), at(12)]);
        assert!(seen.marked(&b).tracked.is_empty());
        // A holder no longer listed is not added.
        assert_eq!(look(&[11], &a, &[11, 12]).marked(&a).tracked, [at(11)]);
    }

    #[test]
    fn a_process_both_tracked_and_holding_the_marker_counts_once() {
        let mut a = session(1, 10);
        a.tracked = vec![at(11)];
        let seen = look(&[11], &a, &[11]);
        assert_eq!(seen.marked(&a).tracked, [at(11)]);
        // Asking again of what is already marked adds nothing.
        assert_eq!(seen.marked(&seen.marked(&a)).tracked, [at(11)]);
    }

    /// A double fork leaves a process with no parent, group or record
    /// linking it to the session: the marker alone keeps the session open.
    #[test]
    fn a_session_is_not_gone_while_a_process_holds_its_marker() {
        let a = session(1, 10);
        assert!(look(&[50], &a, &[]).is_gone(&a));
        let seen = look(&[50], &a, &[50]);
        assert!(!seen.is_gone(&a));
        assert_eq!(pids(&seen.members(&a)), [50]);
    }

    /// A holder `lsof` named that the listing, made first, does not show
    /// started after it, or was a pid since reused: nothing proves it is
    /// the process the session holds, and it is not a member.
    #[test]
    fn a_holder_the_listing_does_not_show_is_no_member() {
        let a = session(1, 10);
        let seen = look(&[], &a, &[50]);
        assert!(seen.is_gone(&a));
        assert!(seen.members(&a).is_empty());
    }

    /// What holds a session's marker is sure, so it may be signalled.
    #[test]
    fn a_holder_is_a_sure_member() {
        let a = session(1, 10);
        let found = look(&[50], &a, &[50]).members(&a);
        assert_eq!(found[0].sure_ref(), Some(at(50)));
    }

    #[test]
    fn a_look_with_no_markers_counts_only_the_listing() {
        let a = session(1, 10);
        let procs = [proc_(10)];
        let seen = Look::without_markers(&procs);
        assert!(!seen.is_gone(&a));
        assert_eq!(seen.listing(), procs);
        assert!(Look::without_markers(&[]).is_gone(&a));
    }

    /// A markers' folder that cannot be read is a failed look, not a look
    /// that found no holder.
    #[test]
    fn a_markers_folder_that_cannot_be_read_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("members");
        std::fs::write(&file, "").unwrap();
        assert!(matches!(
            Look::in_listing(&[], &file),
            Err(MarkerError::Folder(_))
        ));
    }

    #[test]
    fn no_markers_folder_yet_is_no_marker_held() {
        let dir = tempfile::tempdir().unwrap();
        let seen = Look::in_listing(&[], &dir.path().join("members")).unwrap();
        assert!(seen.is_gone(&session(1, 10)));
    }

    /// Stops `a` with looks answering from `looks` in turn (the last one
    /// repeats) and stops answering from `stops`, and returns the result
    /// with what each stop was asked to end.
    fn stopped_with(
        a: &SessionRecord,
        looks: &[&[u32]],
        stops: Vec<Stopped>,
    ) -> (Stopped, Vec<Vec<ProcessRef>>) {
        let looked = RefCell::new(0);
        let asked = RefCell::new(Vec::new());
        let stops = RefCell::new(stops);
        let result = stop_marked(
            a,
            Duration::ZERO,
            || {
                let mut n = looked.borrow_mut();
                let held = looks[(*n).min(looks.len() - 1)];
                *n += 1;
                Ok(look(held, a, held))
            },
            |s, _| {
                asked.borrow_mut().push(s.tracked.clone());
                Ok(stops.borrow_mut().remove(0))
            },
            |p| Ok(p.pid == 1),
        )
        .unwrap();
        (result, asked.into_inner())
    }

    #[test]
    fn a_stop_that_gains_no_holder_stops_once() {
        let a = session(1, 10);
        let (result, asked) = stopped_with(&a, &[&[50]], vec![Stopped::Clean]);
        assert_eq!(result, Stopped::Clean);
        assert_eq!(asked, [vec![at(50)]]);
    }

    /// A holder gone since the first look is no new holder.
    #[test]
    fn a_holder_that_ended_with_the_stop_asks_for_no_second_stop() {
        let a = session(1, 10);
        let (result, asked) = stopped_with(&a, &[&[50], &[]], vec![Stopped::Clean]);
        assert_eq!(result, Stopped::Clean);
        assert_eq!(asked.len(), 1);
    }

    /// One a member detached during the grace period holds the marker only
    /// on the second look, and the second stop still knows the first's.
    #[test]
    fn a_holder_gained_during_the_stop_is_stopped_too_with_what_was_known() {
        let a = session(1, 10);
        let (result, asked) =
            stopped_with(&a, &[&[50], &[60]], vec![Stopped::Clean, Stopped::Clean]);
        assert_eq!(result, Stopped::Clean);
        assert_eq!(asked, [vec![at(50)], vec![at(60), at(50)]]);
    }

    /// A member signalled that survived stays known to the second stop;
    /// one only counted stays unsignalled.
    #[test]
    fn the_second_stop_knows_only_the_survivors_the_first_signalled() {
        let a = session(1, 10);
        let first = Stopped::Survivors(vec![
            survivor(70, Why::Survived),
            survivor(71, Why::NotSignalled),
        ]);
        let (_, asked) = stopped_with(&a, &[&[], &[60]], vec![first, Stopped::Clean]);
        assert_eq!(asked[1], [at(60), at(70)]);
    }

    /// With no new holder, the first stop's own report stands.
    #[test]
    fn survivors_with_no_new_holder_are_reported_as_they_are() {
        let a = session(1, 10);
        let first = Stopped::Survivors(vec![survivor(70, Why::Survived)]);
        let (result, asked) = stopped_with(&a, &[&[]], vec![first.clone()]);
        assert_eq!(result, first);
        assert_eq!(asked.len(), 1);
    }

    /// A look that fails, before or after signals, is no answer: it is the
    /// caller's to say the session stays open.
    #[test]
    fn a_look_that_fails_after_the_stop_is_an_error() {
        let a = session(1, 10);
        let looked = RefCell::new(0);
        let result = stop_marked(
            &a,
            Duration::ZERO,
            || {
                let mut n = looked.borrow_mut();
                *n += 1;
                match *n {
                    1 => Ok(look(&[], &a, &[])),
                    _ => Err(LookError::Markers(MarkerError::Lsof("no lsof".into()))),
                }
            },
            |_, _| Ok(Stopped::Clean),
            |_| Ok(false),
        );
        assert!(matches!(result, Err(LookError::Markers(_))));
    }

    /// Two stops of a session together: the first's survivors that still
    /// run and that the second did not report stay reported (ADR 0030).
    #[test]
    fn two_stops_keep_a_survivor_of_the_first_that_still_runs() {
        let runs = |p: &ProcessRef| Ok(p.pid == 1 || p.pid == 2);
        let merged = |first, second| merged(first, second, runs).unwrap();
        // One still running that the second stop could not see is kept.
        let first =
            Stopped::Survivors(vec![survivor(1, Why::Survived), survivor(3, Why::Survived)]);
        assert_eq!(
            merged(first, Stopped::Clean),
            Stopped::Survivors(vec![survivor(1, Why::Survived)])
        );
        // The second's own report wins for one both saw.
        let first = Stopped::Survivors(vec![survivor(2, Why::NotSignalled)]);
        let second = Stopped::Survivors(vec![survivor(2, Why::Survived)]);
        assert_eq!(
            merged(first, second),
            Stopped::Survivors(vec![survivor(2, Why::Survived)])
        );
        // Gone only when both found nothing; a survivor since gone is not kept.
        assert_eq!(merged(Stopped::Gone, Stopped::Gone), Stopped::Gone);
        assert_eq!(merged(Stopped::Clean, Stopped::Gone), Stopped::Clean);
        let first = Stopped::Survivors(vec![survivor(3, Why::NotSignalled)]);
        assert_eq!(merged(first, Stopped::Gone), Stopped::Clean);
        // One only counted that still runs stays reported, never signalled.
        let first = Stopped::Survivors(vec![survivor(1, Why::NotSignalled)]);
        assert_eq!(
            merged(first, Stopped::Gone),
            Stopped::Survivors(vec![survivor(1, Why::NotSignalled)])
        );
    }
}
