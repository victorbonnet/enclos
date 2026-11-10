//! Lifecycle: sessions, their members, and stopping them (design §8).

pub mod bounded;
pub mod cgroup;
pub mod descriptors;
pub mod inherited;
pub mod listeners;
pub mod look;
pub mod lsof;
pub mod marker;
pub mod members;
pub mod proc;
pub mod process;
pub mod programs;
pub mod ps;
pub mod slice;
pub mod stop;

/// How this host looks at processes: `ps`, `lsof` and `sysctl` on macOS,
/// `/proc` on Linux. Both are compiled on every system, so the tests of each
/// run on either; this is the one place that picks between them.
#[cfg(target_os = "macos")]
pub use lsof as host;
#[cfg(not(target_os = "macos"))]
pub use proc as host;
