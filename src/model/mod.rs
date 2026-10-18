//! Typed models that cross component boundaries (design principle 5).

pub mod audit;
pub mod plan;
pub mod sandbox;

/// A point in time, stored and printed in RFC 3339 (UTC).
pub type Timestamp = jiff::Timestamp;

/// The current time, rounded to milliseconds so stored values stay short.
pub fn now() -> Timestamp {
    let now = Timestamp::now();
    now.round(jiff::Unit::Millisecond).unwrap_or(now)
}
