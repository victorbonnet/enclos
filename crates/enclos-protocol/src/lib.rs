//! The enclos mobile app's protocol, as `docs/protocol.md` describes it.
//!
//! Types and their encoding only: no I/O, no clock, no randomness, so the
//! bridge and the app (through `enclos-app`'s UniFFI glue) share it, and
//! tests feed it bytes and read bytes back.
//!
//! This first part covers the plugin leg: the messages between the bridge
//! and an agent's channel plugin. The device leg, Noise and pairing come
//! next.

mod envelope;
mod ids;
pub mod plugin;

pub use envelope::{DecodeError, Envelope, MAX_MESSAGE_BYTES, VERSION, decode, encode_line};
pub use ids::{ConversationId, IdError, MessageId, Person};
