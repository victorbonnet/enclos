//! Backends: the isolation technologies sandboxes are built on (design §5).
//!
//! The trait holds only what the commands built so far need; it grows toward
//! the full shape in design §9 (compile, prepare, wrap, members, ...) as the
//! commands that use it arrive.

#[cfg(test)]
pub mod fake;

use crate::model::sandbox::BackendKind;

/// Whether a backend can run on this host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Probe {
    Available,
    Unavailable { reason: String },
}

/// One isolation technology. Prepares, wraps and finds members; never
/// supervises.
pub trait Backend {
    fn kind(&self) -> BackendKind;
    /// Checks, without side effects, whether this backend works on this host.
    fn probe(&self) -> Probe;
}

/// Every backend this build of enclos ships, in order of preference.
///
/// This is the one explicit list of implementations. Seatbelt is added here
/// by its own issue; until then no backend is available.
pub fn registered() -> Vec<Box<dyn Backend>> {
    Vec::new()
}
