//! Literal, optional replies to an ordinary message. They grant no authority.
use serde::{Deserialize, Deserializer};

pub const MAX_REPLIES: usize = 4;
pub const MAX_REPLY_BYTES: usize = 256;

pub fn validate(replies: &[String]) -> bool {
    replies.len() <= MAX_REPLIES
        && replies.iter().enumerate().all(|(i, reply)| {
            !reply.trim().is_empty()
                && reply.len() <= MAX_REPLY_BYTES
                && !crate::visible::has_hidden(reply, false)
                && !replies[..i]
                    .iter()
                    .any(|other| crate::visible::bare(other) == crate::visible::bare(reply))
        })
}

/// Bad optional metadata must never hide an otherwise readable message.
pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<String>, D::Error> {
    let value = serde_json::Value::deserialize(d)?;
    Ok(serde_json::from_value::<Vec<String>>(value)
        .ok()
        .filter(|replies| validate(replies))
        .unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_distinct_visible_bounded_literal_replies_are_offered() {
        assert!(validate(&[
            "Fix Inbox filters".into(),
            "Keep paused".into()
        ]));
        for replies in [
            vec![" ".into()],
            vec!["Allow\nall".into()],
            vec!["Allow\u{202e}all".into()],
            vec!["Same".into(), "Same".into()],
            vec!["x".repeat(257)],
            vec!["x".into(); 5],
        ] {
            assert!(!validate(&replies), "{replies:?}");
        }
    }
}
