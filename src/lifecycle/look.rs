//! One look at what runs of a sandbox's sessions (ADR 0019, ADR 0030).
//!
//! A session's members are found from a listing of the host's processes,
//! then from the processes `lsof`, on macOS, or `/proc/<pid>/fd`, on Linux,
//! shows holding its marker, always in that order: each holder is known by the
//! start time the listing gave its pid, so one that exits and whose pid is
//! reused fails the same-process check before a signal. With the look at the
//! markers first, the listing would give it the start time of the process that
//! reused the pid, and that process would be signalled. A [`Look`] that holds
//! markers can only be made that way, and it answers for every session of the
//! sandbox from the same listing. On Linux that look cannot see a zombie or a
//! process it cannot read, so such a process can hold a marker unseen.
//!
//! A look that fails says nothing about any session, so it is an error
//! rather than an answer, and what it means is the caller's to decide:
//! `sandbox stop` counts every session as having run, and fails if its stop
//! cannot look either; `sandbox rm` refuses; `status` lists the sandbox as
//! "cannot tell"; `doctor` reports it is unsure; and a session whose program
//! exited stays open. A markers folder that is not there is not a failed
//! look: no marker is held, and `state check` alone, which tells a person
//! so, treats that as no answer.
//!
//! A session in a cgroup is looked at through it too ([`Look::in_cgroups`]),
//! after the listing as well: what its cgroup holds counts as holding its
//! marker, so one the listing does not show keeps the session open and is
//! not signalled. A cgroup that cannot be read fails the look; only one
//! removed is empty.
//!
//! Which listed processes are a session's is `members`'s to say; `stop`
//! sends the signals.

use std::borrow::Cow;
use std::path::Path;
use std::time::Duration;

use super::cgroup::Hierarchy;
use super::marker::{Held, MarkerError, holders, is_held, name_of};
use super::members::{Found, find, is_gone};
use super::process::{Proc, PsError, processes};
use super::stop::{Stopped, Survivor};
use crate::model::session::{ProcessRef, SessionRecord};

/// Why a look, or a stop that depends on one, failed.
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
        Look::made(processes, || holders(markers))
    }

    /// `list`, then `hold`, which runs only once `list` gave a listing.
    fn made(
        list: impl FnOnce() -> Result<Vec<Proc>, PsError>,
        hold: impl FnOnce() -> Result<Held, MarkerError>,
    ) -> Result<Look<'static>, LookError> {
        let procs = list()?;
        let held = hold()?;
        Ok(Look {
            procs: Cow::Owned(procs),
            held,
        })
    }

    /// The look of a sandbox with no open session, for which nothing is
    /// looked at. It calls every session gone, so it is asked only about
    /// the sessions that were open: none.
    pub fn nothing_open() -> Look<'static> {
        Look::markers_unseen(&[])
    }
}

impl<'a> Look<'a> {
    /// Looks at the markers in `markers`, after `procs`, for the commands
    /// that list the processes once for every sandbox. The listing may be
    /// older than this look, so a process started since is not counted: a
    /// session this calls gone is looked at again before its end is
    /// recorded, and no signal follows from this look.
    pub fn in_listing(procs: &'a [Proc], markers: &Path) -> Result<Look<'a>, MarkerError> {
        Ok(Look {
            procs: Cow::Borrowed(procs),
            held: holders(markers)?,
        })
    }

    /// `procs`, with no look at the markers: for a sandbox whose markers
    /// cannot be looked for, so whether one is held is not known. The
    /// caller says so where it matters.
    pub fn markers_unseen(procs: &'a [Proc]) -> Look<'a> {
        Look {
            procs: Cow::Borrowed(procs),
            held: Held::new(),
        }
    }

    /// This look, with the processes in the cgroup of each of `sessions`
    /// counted as holding its marker. Whatever that cgroup holds is the
    /// session's, with or without the marker, and it is read after the
    /// listing, as the markers are.
    pub fn in_cgroups<'s>(
        mut self,
        cgroups: &Hierarchy,
        sessions: impl IntoIterator<Item = &'s SessionRecord>,
    ) -> Result<Look<'a>, PsError> {
        for session in sessions {
            if let Some(cgroup) = &session.cgroup {
                self.held
                    .entry(name_of(&session.root))
                    .or_default()
                    .extend(cgroups.pids(cgroup)?);
            }
        }
        Ok(self)
    }

    /// `session`, with the listed processes holding its marker added to
    /// those it tracked, each once.
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

    /// The members of `session` in this look, the listed holders of its
    /// marker included.
    pub fn members(&self, session: &SessionRecord) -> Vec<Found> {
        let marked = self.marked(session);
        find(&self.procs, &marked, &marked.tracked)
    }

    /// Whether nothing of `session` runs in this look: it has no member,
    /// and nothing holds its marker. A holder the listing does not show
    /// started after it, so it has no start time to be known by, but it
    /// shows the session is not over.
    pub fn is_gone(&self, session: &SessionRecord) -> bool {
        is_gone(&self.procs, &self.marked(session)) && !is_held(&self.held, &session.root)
    }

    /// The members of `session` in this look, for ending it when there are
    /// none. Only a holder the listing does not show keeps those from
    /// being all that is left, and that is an error, so the session stays
    /// open.
    pub fn left(&self, session: &SessionRecord) -> Result<Vec<Found>, MarkerError> {
        let found = self.members(session);
        match found.is_empty() && is_held(&self.held, &session.root) {
            true => Err(MarkerError::Unlisted(session.root.pid)),
            false => Ok(found),
        }
    }
}

/// Stops `session`'s members, with what holds its marker, then, whatever
/// came of it, looks at the marker again: a process that gained it
/// meanwhile, such as one a member detached during the grace period or one
/// its TERM handler forked, is stopped too, and one that survives that is a
/// survivor, so the session stays open.
///
/// `look` makes a fresh look, `stop` stops the members of a session, and
/// `runs` says whether a process still runs. `look` gives a `Look<'static>`
/// so that a listing shared between sandboxes, which may be old, never
/// decides a signal.
pub fn stop_marked(
    session: &SessionRecord,
    grace: Duration,
    look: impl Fn() -> Result<Look<'static>, LookError>,
    stop: impl Fn(&SessionRecord, Duration) -> Result<Stopped, PsError>,
    runs: impl Fn(&ProcessRef) -> Result<bool, PsError>,
) -> Result<Stopped, LookError> {
    let marked = look()?.marked(session);
    let first = stop(&marked, grace)?;
    // Looked at again whatever came of it, survivors included: a process a
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
    let signalled = survivors(&first)
        .iter()
        .filter(|s| s.why.signalled())
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

/// What of the session a stop left running.
fn survivors(stopped: &Stopped) -> &[Survivor] {
    match stopped {
        Stopped::Survivors(left) => left,
        Stopped::Clean | Stopped::Gone => &[],
    }
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
    let mut left = survivors(&second).to_vec();
    for s in survivors(&first) {
        let process = ProcessRef {
            pid: s.member.pid,
            started: s.member.started.clone(),
        };
        if !left.iter().any(|l| l.member.pid == s.member.pid) && runs(&process)? {
            left.push(s.clone());
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
    use super::super::stop::Why;
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
            cgroup: None,
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
            held: Held::from([(name_of(&session.root), set(held))]),
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

    /// The listing comes first, whatever the look at the markers answers: that
    /// order is what keeps a pid reused from being signalled (ADR 0030).
    #[test]
    fn a_look_lists_the_processes_before_it_looks_at_the_markers() {
        let steps = RefCell::new(Vec::new());
        Look::made(
            || {
                steps.borrow_mut().push("list");
                Ok(Vec::new())
            },
            || {
                steps.borrow_mut().push("hold");
                Ok(Held::new())
            },
        )
        .unwrap();
        assert_eq!(*steps.borrow(), ["list", "hold"]);
    }

    #[test]
    fn a_listing_that_fails_looks_at_no_marker() {
        let looked = Look::made(
            || Err(PsError::new("ps failed")),
            || panic!("the markers were looked at"),
        );
        assert!(matches!(looked, Err(LookError::Processes(_))));
    }

    #[test]
    fn a_look_at_the_markers_that_fails_is_no_listing_alone() {
        let looked = Look::made(
            || Ok(vec![proc_(10)]),
            || Err(MarkerError::Lsof("no lsof".into())),
        );
        assert!(matches!(looked, Err(LookError::Markers(_))));
    }

    /// A process holding one session's marker is that session's member,
    /// never another's (ADR 0030).
    #[test]
    fn a_marker_holder_is_its_own_sessions_member_only() {
        let (a, b) = (session(1, 10), session(2, 20));
        let seen = look(&[11, 12, 21], &a, &[11, 12]);
        assert_eq!(seen.marked(&a).tracked, [at(11), at(12)]);
        assert!(seen.marked(&b).tracked.is_empty());
        // A holder the listing does not show is not added.
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
        assert_eq!(pids(&seen.left(&a).unwrap()), [50]);
    }

    /// A holder the look at the markers names that the listing, made first,
    /// does not show started after it: this look has no start time to know it
    /// by, so it is no member to signal, but the session is not over.
    #[test]
    fn a_holder_the_listing_does_not_show_keeps_the_session_open() {
        let a = session(1, 10);
        let seen = look(&[], &a, &[50]);
        assert!(seen.members(&a).is_empty());
        assert!(!seen.is_gone(&a));
        assert!(matches!(seen.left(&a), Err(MarkerError::Unlisted(10))));
    }

    #[test]
    fn a_session_of_which_nothing_runs_has_nothing_left() {
        let a = session(1, 10);
        assert!(look(&[50], &a, &[]).left(&a).unwrap().is_empty());
    }

    /// Only the session's own marker counts.
    #[test]
    fn a_holder_of_another_sessions_marker_keeps_this_one_from_nothing() {
        let (a, b) = (session(1, 10), session(2, 20));
        let seen = look(&[], &a, &[50]);
        assert!(seen.is_gone(&b));
        assert!(seen.left(&b).unwrap().is_empty());
    }

    /// What holds a session's marker is sure, so it may be signalled.
    #[test]
    fn a_holder_is_a_sure_member() {
        let a = session(1, 10);
        let found = look(&[50], &a, &[50]).members(&a);
        assert_eq!(found[0].sure_ref(), Some(at(50)));
    }

    #[test]
    fn a_look_at_no_markers_counts_only_the_listing() {
        let a = session(1, 10);
        let procs = [proc_(10)];
        assert!(!Look::markers_unseen(&procs).is_gone(&a));
        assert!(Look::markers_unseen(&[]).is_gone(&a));
    }

    #[test]
    fn with_nothing_open_nothing_was_looked_at() {
        let look = Look::nothing_open();
        assert!(look.procs.is_empty());
        assert!(look.held.is_empty());
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

    /// A stand-in for the hierarchy with `a` in a cgroup holding `text`.
    fn in_cgroup(a: &mut SessionRecord, text: &str) -> (tempfile::TempDir, Hierarchy) {
        let dir = tempfile::tempdir().unwrap();
        let folder = dir.path().join("s.scope");
        std::fs::create_dir(&folder).unwrap();
        std::fs::write(folder.join("cgroup.procs"), text).unwrap();
        a.cgroup = Some("/s.scope".parse().unwrap());
        let cgroups = Hierarchy::at(dir.path());
        (dir, cgroups)
    }

    #[test]
    fn what_a_cgroup_holds_is_its_sessions_member_only() {
        let (mut a, b) = (session(1, 10), session(2, 20));
        let (_dir, cgroups) = in_cgroup(&mut a, "50\n");
        let seen = look(&[50], &a, &[]).in_cgroups(&cgroups, [&a]).unwrap();
        assert_eq!(seen.members(&a)[0].sure_ref(), Some(at(50)));
        assert!(!seen.is_gone(&a));
        assert!(seen.is_gone(&b));
    }

    /// As with a marker's holder: it has no start time to be known by, so
    /// it is no member to signal, but the session is not over.
    #[test]
    fn what_a_cgroup_holds_that_the_listing_does_not_show_keeps_the_session_open() {
        let mut a = session(1, 10);
        let (_dir, cgroups) = in_cgroup(&mut a, "50\n");
        let seen = look(&[], &a, &[]).in_cgroups(&cgroups, [&a]).unwrap();
        assert!(seen.members(&a).is_empty());
        assert!(!seen.is_gone(&a));
        assert!(matches!(seen.left(&a), Err(MarkerError::Unlisted(10))));
    }

    #[test]
    fn a_cgroup_that_cannot_be_read_fails_the_look_and_is_no_empty_answer() {
        let mut a = session(1, 10);
        let (_dir, cgroups) = in_cgroup(&mut a, "not a pid\n");
        assert!(look(&[], &a, &[]).in_cgroups(&cgroups, [&a]).is_err());
    }

    #[test]
    fn a_cgroup_systemd_removed_is_empty() {
        let mut a = session(1, 10);
        let (dir, cgroups) = in_cgroup(&mut a, "50\n");
        std::fs::remove_dir_all(dir.path().join("s.scope")).unwrap();
        let seen = look(&[], &a, &[]).in_cgroups(&cgroups, [&a]).unwrap();
        assert!(seen.is_gone(&a));
    }

    /// Stops `a` with looks answering from `looks` in turn (the last one
    /// repeats) and stops answering from `stops`, and returns the result
    /// with the pids each stop was asked to end. Only pid 1 still runs.
    fn stopped_with(
        a: &SessionRecord,
        looks: &[&[u32]],
        stops: Vec<Stopped>,
    ) -> (Stopped, Vec<BTreeSet<u32>>) {
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
                asked
                    .borrow_mut()
                    .push(s.tracked.iter().map(|r| r.pid).collect());
                Ok(stops.borrow_mut().remove(0))
            },
            |p| Ok(p.pid == 1),
        )
        .unwrap();
        (result, asked.into_inner())
    }

    fn set(pids: &[u32]) -> BTreeSet<u32> {
        pids.iter().copied().collect()
    }

    #[test]
    fn a_stop_that_gains_no_holder_stops_once() {
        let a = session(1, 10);
        let (result, asked) = stopped_with(&a, &[&[50]], vec![Stopped::Clean]);
        assert_eq!(result, Stopped::Clean);
        assert_eq!(asked, [set(&[50])]);
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
        assert_eq!(asked, [set(&[50]), set(&[50, 60])]);
    }

    /// A member signalled that survived, or that could not be, stays known
    /// to the second stop; one only counted stays unsignalled.
    #[test]
    fn the_second_stop_knows_only_the_survivors_the_first_tried_to_signal() {
        let a = session(1, 10);
        let first = Stopped::Survivors(vec![
            survivor(70, Why::Survived),
            survivor(71, Why::NotSignalled),
            survivor(72, Why::NotSent("no permission".into())),
        ]);
        let (_, asked) = stopped_with(&a, &[&[], &[60]], vec![first, Stopped::Clean]);
        assert_eq!(asked[1], set(&[60, 70, 72]));
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

    /// One a cgroup holds and no listing shows has no start time, and no
    /// signal was sent to it: the second stop reads the cgroup again.
    #[test]
    fn the_second_stop_does_not_take_an_unlisted_survivor_for_a_signalled_one() {
        let a = session(1, 10);
        let first = Stopped::Survivors(vec![survivor(73, Why::NotListed)]);
        let (_, asked) = stopped_with(&a, &[&[], &[60]], vec![first, Stopped::Clean]);
        assert_eq!(asked[1], set(&[60]));
    }

    /// A survivor of the first stop that still runs is reported though the
    /// second stop, which never saw it, ended everything it was asked to.
    #[test]
    fn two_stops_report_a_survivor_of_the_first_that_still_runs() {
        let a = session(1, 10);
        let first = Stopped::Survivors(vec![survivor(1, Why::NotSignalled)]);
        let (result, _) = stopped_with(&a, &[&[], &[60]], vec![first, Stopped::Clean]);
        assert_eq!(
            result,
            Stopped::Survivors(vec![survivor(1, Why::NotSignalled)])
        );
    }

    /// A look that fails is no answer, and it comes before any signal.
    #[test]
    fn a_first_look_that_fails_stops_nothing() {
        let a = session(1, 10);
        let result = stop_marked(
            &a,
            Duration::ZERO,
            || Err(LookError::Markers(MarkerError::Lsof("no lsof".into()))),
            |_, _| panic!("stopped without a look"),
            |_| Ok(false),
        );
        assert!(matches!(result, Err(LookError::Markers(_))));
    }

    /// After signals too: it is the caller's to say the session stays open.
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

    #[test]
    fn a_second_stop_that_fails_is_an_error() {
        let a = session(1, 10);
        let looked = RefCell::new(0);
        let stops = RefCell::new(0);
        let result = stop_marked(
            &a,
            Duration::ZERO,
            || {
                let mut n = looked.borrow_mut();
                *n += 1;
                Ok(match *n {
                    1 => look(&[], &a, &[]),
                    _ => look(&[60], &a, &[60]),
                })
            },
            |_, _| {
                let mut n = stops.borrow_mut();
                *n += 1;
                match *n {
                    1 => Ok(Stopped::Clean),
                    _ => Err(PsError::new("ps failed")),
                }
            },
            |_| Ok(false),
        );
        assert!(matches!(result, Err(LookError::Processes(_))));
    }

    /// Whether a survivor still runs not being known, nothing shows it does
    /// not: the stops do not come to `Clean`.
    #[test]
    fn a_survivor_that_cannot_be_looked_at_is_an_error() {
        let first = Stopped::Survivors(vec![survivor(1, Why::Survived)]);
        let result = merged(first, Stopped::Clean, |_| Err(PsError::new("ps failed")));
        assert!(result.is_err());
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
