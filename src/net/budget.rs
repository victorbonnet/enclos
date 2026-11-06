//! What a long-running enclos process may hold at once: the descriptors it
//! plans for, and a counted place among its connections.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

/// The most descriptors a process plans for, however many it was given: its
/// connections also hold threads, which nothing else bounds.
const MOST_DESCRIPTORS: u64 = 1024;

/// The descriptors this process may plan for after keeping `own`: its soft
/// `RLIMIT_NOFILE`, the one a descriptor hits, at most [`MOST_DESCRIPTORS`].
pub(crate) fn descriptors_to_share(own: u64) -> u64 {
    left_after(
        rustix::process::getrlimit(rustix::process::Resource::Nofile).current,
        own,
    )
}

/// What is left of a soft limit of `descriptors` (None: unlimited), at most
/// [`MOST_DESCRIPTORS`], after keeping `own`.
pub(crate) fn left_after(descriptors: Option<u64>, own: u64) -> u64 {
    descriptors
        .unwrap_or(MOST_DESCRIPTORS)
        .min(MOST_DESCRIPTORS)
        .saturating_sub(own)
}

/// A place among the connections, or the lookups, a process runs at once;
/// it frees when dropped, as the connection or lookup ends.
pub(crate) struct Slot(Arc<AtomicUsize>);

impl Slot {
    /// A place, if fewer than `max` of `open` are taken.
    pub(crate) fn take(open: &Arc<AtomicUsize>, max: usize) -> Option<Slot> {
        open.try_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
            (n < max).then_some(n + 1)
        })
        .ok()?;
        Some(Slot(Arc::clone(open)))
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn what_is_left_is_the_soft_limit_at_most_1024_less_what_is_kept() {
        assert_eq!(left_after(Some(256), 8), 248);
        assert_eq!(left_after(Some(1 << 20), 8), 1016);
        assert_eq!(left_after(None, 24), 1000);
        assert_eq!(left_after(Some(3), 8), 0);
    }

    #[test]
    fn the_limit_read_is_shared_the_same_way() {
        let soft = rustix::process::getrlimit(rustix::process::Resource::Nofile).current;
        assert_eq!(descriptors_to_share(8), left_after(soft, 8));
    }

    #[test]
    fn a_place_is_taken_up_to_the_most_and_frees_when_dropped() {
        let open = Arc::new(AtomicUsize::new(0));
        let first = Slot::take(&open, 2).unwrap();
        let second = Slot::take(&open, 2).unwrap();
        assert!(Slot::take(&open, 2).is_none());
        drop(first);
        assert_eq!(open.load(Ordering::SeqCst), 1);
        let _third = Slot::take(&open, 2).unwrap();
        drop(second);
        assert_eq!(open.load(Ordering::SeqCst), 1);
    }
}
