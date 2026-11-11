//! The mobile app's bridge (ADR 0042, proposed; `docs/protocol.md`): what
//! stands between a person and an agent's app channel. This part keeps the
//! conversations and talks to an agent's channel plugin over its socket;
//! the device side, over the tailnet, comes after.

pub mod ids;
pub mod keys;
pub mod pace;
pub mod page;
pub mod plugin;
pub mod server;
pub mod store;
pub mod text;
pub mod transport;
