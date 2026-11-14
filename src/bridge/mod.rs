//! The mobile app's bridge (ADR 0042, proposed; `docs/protocol.md`): what
//! stands between a person and an agent's app channel. This part keeps the
//! conversations, talks to an agent's channel plugin over its socket, and
//! serves paired devices over the tailnet (`server`).

pub mod groups;
pub mod ids;
pub mod keys;
pub mod pace;
pub mod page;
pub mod plugin;
pub mod provisioning;
pub mod server;
pub mod store;
pub mod text;
pub mod transport;

pub mod portable;
