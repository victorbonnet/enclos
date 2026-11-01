//! The marker a session's processes inherit, by which enclos finds them
//! (ADR 0030).

use std::time::Duration;

use super::Engine;
use crate::error::Result;
use crate::layout::LayoutError;
use crate::lifecycle::marker::{self, Marker};
use crate::lifecycle::process::{Proc, is_same, processes};
use crate::lifecycle::stop::{Stopped, Survivor, Why};
use crate::model::sandbox::SandboxName;
use crate::model::session::{ProcessRef, SessionRecord};

/// What two stops of a session came to, the second after the marker gained
/// holders: the second's survivors, and each survivor of the first that
/// `runs` still and the second did not report, as one only counted, which
/// is never signalled for it but never dropped either. `Gone` only when
/// both found nothing.
pub(super) fn merged(
    first: Stopped,
    second: Stopped,
    runs: impl Fn(&ProcessRef) -> std::result::Result<bool, crate::lifecycle::process::PsError>,
) -> std::result::Result<Stopped, crate::lifecycle::process::PsError> {
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

/// The processes holding each marker of a sandbox, by marker file name.
pub(super) type Held = std::collections::BTreeMap<String, std::collections::BTreeSet<u32>>;

/// `tracked`, with the processes in `procs` that hold `session`'s marker
/// (ADR 0030).
pub(super) fn marked_in(
    session: &SessionRecord,
    tracked: &[ProcessRef],
    procs: &[Proc],
    held: &Held,
) -> Vec<ProcessRef> {
    let mut tracked = tracked.to_vec();
    if let Some(pids) = held.get(&marker::name_of(&session.root)) {
        for p in procs.iter().filter(|p| pids.contains(&p.pid)) {
            let holder = ProcessRef {
                pid: p.pid,
                started: p.started.clone(),
            };
            if !tracked.contains(&holder) {
                tracked.push(holder);
            }
        }
    }
    tracked
}

impl Engine {
    /// The folder of the sandbox's markers (ADR 0030).
    pub(super) fn markers(&self, name: &SandboxName) -> std::path::PathBuf {
        self.layout.sandbox_dir(name.as_str()).join("members")
    }

    /// A new marker for a program about to start in sandbox `name`.
    pub(super) fn new_marker(&self, name: &SandboxName) -> Result<Marker> {
        let dir = self.markers(name);
        Marker::new(&dir).map_err(|source| LayoutError::Io { path: dir, source }.into())
    }

    /// Names a started program's marker after its session's `root`, before
    /// the session is recorded.
    pub(super) fn name_marker(
        &self,
        name: &SandboxName,
        marked: marker::Started,
        root: &ProcessRef,
    ) -> Result<()> {
        marked.name(root).map_err(|source| {
            LayoutError::Io {
                path: self.markers(name),
                source,
            }
            .into()
        })
    }

    /// Removes an ended session's marker, once a fresh look shows nothing
    /// holds it. A session ends only once nothing of it runs, its marker's
    /// holders included; this second look keeps the file for one that
    /// gained the marker since. One left behind is an empty file, which a
    /// later session cannot take for its own (its name has the root's start
    /// time).
    pub(super) fn forget_marker(&self, session: &SessionRecord) {
        let dir = self.markers(&session.sandbox);
        if let Ok(held) = marker::holders(&dir)
            && !held.contains_key(&marker::name_of(&session.root))
        {
            let _ = marker::remove(&dir, &session.root);
        }
    }

    /// The processes holding each marker of sandbox `name`, by marker.
    pub(super) fn held(&self, name: &SandboxName) -> Result<Held> {
        Ok(marker::holders(&self.markers(name))?)
    }

    /// `session`, with the processes holding its marker added to those it
    /// tracked (ADR 0030). The processes are listed before `lsof` looks: a
    /// holder that exits in between, its pid reused, is then listed with
    /// its own start time and fails the same-process check before a signal,
    /// where the other order would name the process that reused the pid.
    pub(super) fn marked(&self, session: &SessionRecord) -> Result<SessionRecord> {
        Ok(self.marked_listed(session)?.1)
    }

    /// `marked`, with the listing it was made from, to look at it again.
    pub(super) fn marked_listed(
        &self,
        session: &SessionRecord,
    ) -> Result<(Vec<Proc>, SessionRecord)> {
        let procs = processes()?;
        let held = self.held(&session.sandbox)?;
        let mut marked = session.clone();
        marked.tracked = marked_in(session, &session.tracked, &procs, &held);
        Ok((procs, marked))
    }

    /// Stops `session`'s members, with what holds its marker (ADR 0030),
    /// then, whatever came of it, looks at the marker again: a process that
    /// gained it meanwhile, such as one a member detached during the grace
    /// period or a child its TERM handler forked, is stopped too, and one
    /// that survives that is a survivor, so the session stays open.
    pub(super) fn stop_marked(
        &self,
        session: &SessionRecord,
        grace: Duration,
        stop: super::StopMembers,
    ) -> Result<Stopped> {
        let marked = self.marked(session)?;
        let first = stop(&marked, grace)?;
        // Looked at again whatever came of it, survivors included: a child
        // a member's TERM handler forked before it exited is an orphan only
        // the marker proves the session's, so it is reported as not
        // signalled until it is.
        let mut again = self.marked(session)?;
        if again.tracked.iter().all(|r| marked.tracked.contains(r)) {
            return Ok(first);
        }
        // What the first stop knew stays known: the first look's holders,
        // and the members it signalled that survived, which may since have
        // closed the marker or lost their parent.
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
        Ok(merged(first, second, is_same)?)
    }
}
