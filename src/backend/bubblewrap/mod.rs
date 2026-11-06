//! The bubblewrap backend: Linux's sandbox (ADR 0004). So far what it
//! compiles, what it declares and what it runs first inside; it is not
//! registered, so nothing runs under it yet.

pub mod compile;
#[cfg(target_os = "linux")]
pub mod inside;
pub mod proposed;
pub mod seccomp;

pub use compile::{CompiledSandbox, compile};
pub use proposed::{Host, capabilities};
