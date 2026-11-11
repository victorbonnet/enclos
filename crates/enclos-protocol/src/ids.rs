//! The names the protocol carries, checked when a message is decoded.

use serde::{Deserialize, Serialize};

/// Longest id or name the protocol accepts, in bytes.
pub const MAX_ID_BYTES: usize = 128;

/// Why an id was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IdError {
    #[error("empty")]
    Empty,
    #[error("longer than 128 bytes")]
    TooLong,
    #[error("holds a control character")]
    Control,
}

/// The rule every id and name follows: not empty, at most
/// [`MAX_ID_BYTES`], no control character.
pub(crate) fn check(value: &str) -> Result<(), IdError> {
    if value.is_empty() {
        Err(IdError::Empty)
    } else if value.len() > MAX_ID_BYTES {
        Err(IdError::TooLong)
    } else if value.chars().any(char::is_control) {
        Err(IdError::Control)
    } else {
        Ok(())
    }
}

macro_rules! id {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, IdError> {
                let value = value.into();
                check(&value)?;
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<String> for $name {
            type Error = IdError;

            fn try_from(value: String) -> Result<Self, IdError> {
                Self::new(value)
            }
        }

        impl From<$name> for String {
            fn from(id: $name) -> String {
                id.0
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

id!(
    /// A message's id, unique per sender (a UUID); acknowledged by `ack`.
    MessageId
);
id!(
    /// A conversation's id, made by the app (a UUID); the runtime's chat id.
    ConversationId
);
id!(
    /// A person, by their tailnet login (`alice@example.com`).
    Person
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_id_is_neither_empty_nor_too_long_nor_controlled() {
        assert_eq!(MessageId::new(""), Err(IdError::Empty));
        assert_eq!(
            MessageId::new("a".repeat(MAX_ID_BYTES + 1)),
            Err(IdError::TooLong)
        );
        assert_eq!(MessageId::new("a\nb"), Err(IdError::Control));
        assert!(MessageId::new("a".repeat(MAX_ID_BYTES)).is_ok());
        assert_eq!(
            Person::new("alice@example.com").unwrap().as_str(),
            "alice@example.com"
        );
    }
}
