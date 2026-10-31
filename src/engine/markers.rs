//! The engine's side of what runs of a sandbox: the marker a session's
//! processes inherit, and looking at them (ADR 0030). `lifecycle::look`
//! holds what a look answers.

use std::time::Duration;

use super::Engine;
use crate::error::Result;
use crate::layout::LayoutError;
use crate::lifecycle::look::{self, Look};
use crate::lifecycle::marker::{self, Marker};
use crate::lifecycle::process::is_same;
use crate::lifecycle::stop::Stopped;
use crate::model::sandbox::SandboxName;
use crate::model::session::{ProcessRef, SessionRecord};

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
            && !marker::is_held(&held, &session.root)
        {
            let _ = marker::remove(&dir, &session.root);
        }
    }

    /// A look at what runs of sandbox `name`, to ask about `open`, its open
    /// sessions or some of them. With none, as for most sandboxes, nothing
    /// is looked at, and the look is asked about no other session.
    pub(super) fn look_open(
        &self,
        name: &SandboxName,
        open: &[SessionRecord],
    ) -> Result<Look<'static>> {
        match open.is_empty() {
            true => Ok(Look::nothing_open()),
            false => Ok(Look::now(&self.markers(name))?.in_cgroups(&self.cgroups, open)?),
        }
    }

    /// A look at what runs of sandbox `name` now, its open sessions' cgroups
    /// included.
    pub(super) fn look_now(&self, name: &SandboxName) -> Result<Look<'static>> {
        let open = self.state.sessions(name, true)?;
        Ok(Look::now(&self.markers(name))?.in_cgroups(&self.cgroups, &open)?)
    }

    /// Stops `session`'s members, with what holds its marker or is in its
    /// cgroup now and what gains either meanwhile (`look::stop_marked`).
    pub(super) fn stop_marked(
        &self,
        session: &SessionRecord,
        grace: Duration,
        stop: super::StopMembers,
    ) -> Result<Stopped> {
        let dir = self.markers(&session.sandbox);
        Ok(look::stop_marked(
            session,
            grace,
            || Ok(Look::now(&dir)?.in_cgroups(&self.cgroups, [session])?),
            stop,
            is_same,
        )?)
    }
}
