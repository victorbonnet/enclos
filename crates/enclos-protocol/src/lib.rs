//! The enclos mobile app's protocol, as `docs/protocol.md` describes it.
//!
//! Types, their encoding and the device leg's crypto, with no I/O and no
//! clock, so the bridge and the app (through `enclos-app`'s UniFFI glue)
//! share it, and tests feed it bytes and read bytes back. Only new keys and
//! nonces come from the system's random source.
//!
//! - [`plugin`]: the bridge and an agent's channel plugin.
//! - [`device`], [`noise`], [`pairing`], [`preview`]: the bridge and a
//!   paired device.

pub mod approval;
pub mod device;
mod envelope;
mod ids;
pub mod noise;
pub mod pairing;
pub mod plugin;
pub mod preview;
pub mod visible;

pub use envelope::{DecodeError, Envelope, MAX_MESSAGE_BYTES, VERSION, decode, encode_line};
pub use ids::{ConversationId, IdError, MessageId, Person};
