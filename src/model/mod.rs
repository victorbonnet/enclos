//! Typed models that cross component boundaries (design principle 5).

pub mod agent;
pub mod audit;
pub mod net;
pub mod plan;
pub mod policy;
pub mod runtime;
pub mod sandbox;
pub mod secret;
pub mod session;

/// A point in time, stored and printed in RFC 3339 (UTC).
pub type Timestamp = jiff::Timestamp;

/// The current time, rounded to milliseconds so stored values stay short.
pub fn now() -> Timestamp {
    let now = Timestamp::now();
    now.round(jiff::Unit::Millisecond).unwrap_or(now)
}
