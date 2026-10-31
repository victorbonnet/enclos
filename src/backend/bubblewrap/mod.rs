//! The bubblewrap backend: Linux's sandbox (ADR 0004). So far what it
//! compiles and what it declares; it is not registered, so nothing runs
//! under it yet (M3-15).

pub mod compile;
pub mod proposed;

pub use compile::{CompiledSandbox, compile};
pub use proposed::{Host, capabilities};
