//! Signed decisions (ADR 0060, proposed; `docs/protocol.md`, Runtime
//! approvals): the bridge signs each person's runtime-approval decision it
//! passes to an agent's channel plugin, with a key no sandbox reads, and the
//! plugin acts on a decision only with that signature. The plugin token
//! proves nothing about the person, since the agent can read it; this
//! signature is what keeps an agent that speaks on its own plugin's socket
//! from approving its own command.
//!
//! The statement signed is every field below, in this order, each as its
//! UTF-8 bytes after their length as 4 bytes big-endian: [`LABEL`], the
//! agent (`sandbox/agent`), the conversation, the approval's id, the id of
//! the bridge's `question.answer` that carries it, the action, the command,
//! the reason, the number of patterns in decimal, each pattern, and the
//! signing time in decimal seconds since the Unix epoch. The signature is
//! ECDSA P-256 with SHA-256, `r` then `s`, 64 bytes, in base64url without
//! padding; the public key is SEC1 uncompressed, 65 bytes, encoded the same.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::ecdsa::signature::{Signer as _, Verifier as _};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

/// What every statement starts with: a signature by this key says this and
/// nothing else, whatever else the key might one day sign.
pub const LABEL: &str = "enclos/runtime-approval/1";

/// How old a signed decision may be when the plugin reads it, in seconds:
/// the bridge signs it as it sends it, and waits 25 seconds for its receipt.
pub const MAX_AGE_SECONDS: i64 = 60;

/// How far ahead of the plugin's clock its signing time may be, in seconds:
/// the bridge and the plugin read the same host's clock.
pub const MAX_AHEAD_SECONDS: i64 = 5;

/// The signature a `question.answer` for a runtime approval carries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedDecision {
    /// When the bridge signed it, in seconds since the Unix epoch.
    pub at: i64,
    /// ECDSA P-256 over the statement, `r` then `s`, base64url.
    pub sig: String,
}

/// A decision, field by field, as the statement holds it.
#[derive(Debug, Clone, Copy)]
pub struct Decision<'a> {
    /// The agent the approval is from, `sandbox/agent`.
    pub agent: &'a str,
    pub conversation: &'a str,
    /// The approval's id (its `question` id).
    pub question: &'a str,
    /// The id of the `question.answer` that carries the decision.
    pub request: &'a str,
    /// `once`, `session`, `always` or `deny`.
    pub action: &'a str,
    /// The approval's command, reason and patterns, exactly as defined.
    pub command: &'a str,
    pub reason: &'a str,
    pub patterns: &'a [String],
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DecisionError {
    #[error("not a P-256 key: {0}")]
    BadKey(String),
    #[error("the signature cannot be read")]
    Unreadable,
    #[error("the signature is not fresh: signed at {at}, read at {now}")]
    Stale { at: i64, now: i64 },
    #[error("the signature does not match this decision and key")]
    Mismatch,
}

impl Decision<'_> {
    /// The bytes signed, for a decision signed at `at`.
    pub fn statement(&self, at: i64) -> Vec<u8> {
        let count = self.patterns.len().to_string();
        let at = at.to_string();
        let mut fields: Vec<&str> = vec![
            LABEL,
            self.agent,
            self.conversation,
            self.question,
            self.request,
            self.action,
            self.command,
            self.reason,
            &count,
        ];
        fields.extend(self.patterns.iter().map(String::as_str));
        fields.push(&at);
        let mut bytes = Vec::new();
        for field in fields {
            let length = u32::try_from(field.len()).expect("a field fits a message");
            bytes.extend_from_slice(&length.to_be_bytes());
            bytes.extend_from_slice(field.as_bytes());
        }
        bytes
    }
}

/// The bridge's key for signed decisions.
pub struct DecisionKey(SigningKey);

impl DecisionKey {
    /// The key whose secret scalar is `bytes` (32 bytes, big-endian).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DecisionError> {
        SigningKey::from_slice(bytes)
            .map(Self)
            .map_err(|e| DecisionError::BadKey(e.to_string()))
    }

    /// The public key, SEC1 uncompressed.
    pub fn public(&self) -> Vec<u8> {
        self.0
            .verifying_key()
            .to_sec1_point(false)
            .as_ref()
            .to_vec()
    }

    /// The public key as the plugin is given it: base64url, no padding.
    pub fn public_text(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.public())
    }

    /// `decision`, signed at `at` (seconds since the Unix epoch).
    pub fn sign(&self, decision: &Decision, at: i64) -> SignedDecision {
        let signature: Signature = self.0.sign(&decision.statement(at));
        SignedDecision {
            at,
            sig: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        }
    }
}

/// Checks that `signed` is the signature, by the key `public` (SEC1), of
/// `decision`, made within [`MAX_AGE_SECONDS`] before `now` and at most
/// [`MAX_AHEAD_SECONDS`] after it. The plugin's own check, in Python, does
/// the same.
pub fn check(
    public: &[u8],
    decision: &Decision,
    signed: &SignedDecision,
    now: i64,
) -> Result<(), DecisionError> {
    let key =
        VerifyingKey::from_sec1_bytes(public).map_err(|e| DecisionError::BadKey(e.to_string()))?;
    if signed.at < now.saturating_sub(MAX_AGE_SECONDS)
        || signed.at > now.saturating_add(MAX_AHEAD_SECONDS)
    {
        return Err(DecisionError::Stale { at: signed.at, now });
    }
    let raw = URL_SAFE_NO_PAD
        .decode(&signed.sig)
        .map_err(|_| DecisionError::Unreadable)?;
    let signature = Signature::from_slice(&raw).map_err(|_| DecisionError::Unreadable)?;
    key.verify(&decision.statement(signed.at), &signature)
        .map_err(|_| DecisionError::Mismatch)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    /// The decision in `tests/fixtures/decision/approval.json`, which the
    /// Hermes plugin's tests read too.
    #[derive(Deserialize)]
    struct Fixture {
        bridge: String,
        agent: String,
        conversation: String,
        question: String,
        request: String,
        action: String,
        command: String,
        reason: String,
        patterns: Vec<String>,
        at: i64,
        statement: String,
        sig: String,
    }

    fn fixture() -> Fixture {
        serde_json::from_str(include_str!("../tests/fixtures/decision/approval.json")).unwrap()
    }

    fn decision(f: &Fixture) -> Decision<'_> {
        Decision {
            agent: &f.agent,
            conversation: &f.conversation,
            question: &f.question,
            request: &f.request,
            action: &f.action,
            command: &f.command,
            reason: &f.reason,
            patterns: &f.patterns,
        }
    }

    /// A key for tests alone: its scalar is no secret.
    fn key() -> DecisionKey {
        DecisionKey::from_bytes(&[7u8; 32]).unwrap()
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn the_statement_and_signature_are_the_fixtures() {
        let f = fixture();
        let decision = decision(&f);
        assert_eq!(hex(&decision.statement(f.at)), f.statement);
        assert_eq!(key().public_text(), f.bridge);
        // RFC 6979: the same key and statement give the same signature.
        assert_eq!(key().sign(&decision, f.at).sig, f.sig);
        let public = URL_SAFE_NO_PAD.decode(&f.bridge).unwrap();
        let signed = SignedDecision {
            at: f.at,
            sig: f.sig.clone(),
        };
        assert_eq!(check(&public, &decision, &signed, f.at + 10), Ok(()));
    }

    #[test]
    fn a_field_of_another_length_never_reads_as_the_same_statement() {
        let f = fixture();
        let one = Decision {
            command: "ab",
            reason: "c",
            ..decision(&f)
        };
        let other = Decision {
            command: "a",
            reason: "bc",
            ..decision(&f)
        };
        assert_ne!(one.statement(1), other.statement(1));
        let patterns = ["a".to_owned(), "b".to_owned()];
        let joined = ["a b".to_owned()];
        assert_ne!(
            Decision {
                patterns: &patterns,
                ..decision(&f)
            }
            .statement(1),
            Decision {
                patterns: &joined,
                ..decision(&f)
            }
            .statement(1)
        );
    }

    #[test]
    fn an_altered_forged_or_stale_decision_is_refused() {
        let f = fixture();
        let decision = decision(&f);
        let public = key().public();
        let signed = key().sign(&decision, 1_000);
        assert_eq!(check(&public, &decision, &signed, 1_000), Ok(()));
        // Altered: another action, command, approval, request or scope.
        let wider = ["*".to_owned()];
        for altered in [
            Decision {
                action: "always",
                ..decision
            },
            Decision {
                command: "rm -rf ~",
                ..decision
            },
            Decision {
                question: "another-approval",
                ..decision
            },
            Decision {
                request: "another-request",
                ..decision
            },
            Decision {
                agent: "lab/other",
                ..decision
            },
            Decision {
                conversation: "another",
                ..decision
            },
            Decision {
                patterns: &wider,
                ..decision
            },
        ] {
            assert_eq!(
                check(&public, &altered, &signed, 1_000),
                Err(DecisionError::Mismatch)
            );
        }
        // Its time changed, so as to look fresh.
        let moved = SignedDecision {
            at: 1_050,
            ..signed.clone()
        };
        assert_eq!(
            check(&public, &decision, &moved, 1_050),
            Err(DecisionError::Mismatch)
        );
        // Forged: signed by another key.
        let forged = DecisionKey::from_bytes(&[9u8; 32])
            .unwrap()
            .sign(&decision, 1_000);
        assert_eq!(
            check(&public, &decision, &forged, 1_000),
            Err(DecisionError::Mismatch)
        );
        // Replayed later, or dated ahead.
        assert!(matches!(
            check(&public, &decision, &signed, 1_000 + MAX_AGE_SECONDS + 1),
            Err(DecisionError::Stale { .. })
        ));
        assert!(matches!(
            check(&public, &decision, &signed, 1_000 - MAX_AHEAD_SECONDS - 1),
            Err(DecisionError::Stale { .. })
        ));
        // Not a signature, or not a key.
        let garbled = SignedDecision {
            sig: "not base64!".into(),
            ..signed.clone()
        };
        assert_eq!(
            check(&public, &decision, &garbled, 1_000),
            Err(DecisionError::Unreadable)
        );
        assert!(matches!(
            check(&[4u8; 65], &decision, &signed, 1_000),
            Err(DecisionError::BadKey(_))
        ));
    }
}
