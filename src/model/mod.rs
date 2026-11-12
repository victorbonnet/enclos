//! Typed models that cross component boundaries (design principle 5).

pub mod agent;
pub mod audit;
pub mod channel;
pub mod limits;
pub mod net;
pub mod plan;
pub mod policy;
pub mod runtime;
pub mod sandbox;
pub mod secret;
pub mod session;
pub mod unenforced;

/// A point in time, stored and printed in RFC 3339 (UTC).
pub type Timestamp = jiff::Timestamp;

/// The current time, rounded to milliseconds so stored values stay short.
pub fn now() -> Timestamp {
    let now = Timestamp::now();
    now.round(jiff::Unit::Millisecond).unwrap_or(now)
}

/// `n` things in words, the noun agreeing with the number: `count(1,
/// "session", "sessions")` is "1 session", and 0 or 2 take `many`.
pub fn count(n: usize, one: &str, many: &str) -> String {
    match n {
        1 => format!("1 {one}"),
        n => format!("{n} {many}"),
    }
}

#[cfg(test)]
mod tests {
    use super::count;

    #[test]
    fn a_count_agrees_with_its_noun() {
        assert_eq!(count(0, "session", "sessions"), "0 sessions");
        assert_eq!(count(1, "session", "sessions"), "1 session");
        assert_eq!(count(2, "service", "services"), "2 services");
    }
}
