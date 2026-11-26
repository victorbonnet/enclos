//! Host pause records stored in `state.db` (migration 14).

use crate::model::Timestamp;
use crate::model::audit::Actor;
use crate::model::sandbox::SandboxName;

/// The singleton `host_pause` row: at most one pause is in force on a host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostPauseRecord {
    /// Monotonic revision bumped on every change to the pause record.
    pub revision: u64,
    /// `true`: asked for the whole host (`--all`); `false`: a named subset.
    pub pause_all: bool,
    pub by: Actor,
    pub at: Timestamp,
}

/// One sandbox's `sandbox_pauses` row under the host pause in force.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxPauseRecord {
    pub sandbox: SandboxName,
    /// The runtime service labels this pause stopped; empty when it found none.
    pub labels: Vec<String>,
    /// The sandbox's other service labels that kept running.
    pub kept: Vec<String>,
    /// Timestamp set when a resume is asked, before its services are installed;
    /// `None` while the pause holds it.
    pub released: Option<Timestamp>,
    pub at: Timestamp,
    pub by: Actor,
}

/// Monotonic revision across record lifetimes: `max(previous + 1, unix_milliseconds_now)`.
///
/// Assumes wall-clock millisecond timestamps move forward between a deletion and
/// the next creation; within a single record's lifetime `previous + 1` guarantees
/// monotonicity even if the system clock steps backward or two writes happen in
/// the same millisecond.
pub fn next_revision(previous: u64, at: Timestamp) -> u64 {
    let ms = u64::try_from(at.as_millisecond()).unwrap_or(0);
    previous.saturating_add(1).max(ms)
}
