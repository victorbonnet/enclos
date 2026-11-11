//! How fast an agent's plugin may have the bridge store its messages.
//!
//! Every runtime may send on its own (`kind: notify`), and each message is
//! kept in the bridge's database and queued to its owner's devices. An
//! agent that sends in a loop would fill both. Past a burst, the bridge
//! reads the plugin's next message only when there is room again: the
//! plugin waits, as it would on a slow network, and nothing is lost, since
//! it keeps each message until the bridge's `ack`.

use std::time::{Duration, Instant};

/// The messages an agent may have stored at once, after a quiet time.
pub const BURST: f64 = 30.0;
/// How many more it may have stored each minute, past the burst.
pub const PER_MINUTE: f64 = 30.0;

/// One agent's room for messages: a token bucket of [`BURST`], filled at
/// [`PER_MINUTE`].
#[derive(Debug, Clone)]
pub struct Pace {
    room: f64,
    at: Instant,
}

impl Pace {
    pub fn new(now: Instant) -> Pace {
        Pace {
            room: BURST,
            at: now,
        }
    }

    /// Takes room for one message at `now`; else how long until there is.
    pub fn take(&mut self, now: Instant) -> Result<(), Duration> {
        let since = now.saturating_duration_since(self.at).as_secs_f64();
        self.room = (self.room + since * PER_MINUTE / 60.0).min(BURST);
        self.at = now;
        if self.room >= 1.0 {
            self.room -= 1.0;
            Ok(())
        } else {
            Err(Duration::from_secs_f64(
                (1.0 - self.room) * 60.0 / PER_MINUTE,
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_burst_is_stored_then_one_message_at_the_pace() {
        let start = Instant::now();
        let mut pace = Pace::new(start);
        for _ in 0..BURST as usize {
            assert_eq!(pace.take(start), Ok(()));
        }
        let wait = pace.take(start).unwrap_err();
        assert_eq!(wait, Duration::from_secs_f64(60.0 / PER_MINUTE));
        // Half the wait is not enough; all of it is.
        assert!(pace.take(start + wait / 2).is_err());
        assert_eq!(pace.take(start + wait), Ok(()));
        assert!(pace.take(start + wait).is_err());
    }

    #[test]
    fn a_quiet_time_gives_back_the_burst_and_no_more() {
        let start = Instant::now();
        let mut pace = Pace::new(start);
        for _ in 0..BURST as usize {
            pace.take(start).unwrap();
        }
        let later = start + Duration::from_secs(3_600);
        for _ in 0..BURST as usize {
            assert_eq!(pace.take(later), Ok(()));
        }
        assert!(pace.take(later).is_err());
    }
}
