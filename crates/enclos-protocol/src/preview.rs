//! Notification previews (`docs/protocol.md`, Notifications):
//! XChaCha20-Poly1305 under the device's `push_key`, so the push service
//! carries ciphertext only. `nonce ‖ ciphertext`.
//!
//! The push's `v`, `host` and `seq`, which travel beside the ciphertext,
//! are its associated data: a preview opens only with the ones it was
//! sealed with, so one kept by the push service, or by anyone who holds a
//! payload, cannot come back under another `seq`. The plaintext is padded
//! to one size, so the ciphertext's length does not tell the text's.

use chacha20poly1305::aead::{Aead, Generate, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};

const NONCE_BYTES: usize = 24;

/// The size every preview's plaintext is padded to, its padding marker
/// included: room for the JSON of 120 characters of text however they
/// are escaped, an agent and a conversation id, and, sealed and in
/// base64url, well within a push's 4 KB.
pub const PADDED_BYTES: usize = 2048;

/// Ends the plaintext, before the zeros that pad it.
const PAD_MARKER: u8 = 0x80;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PreviewError {
    #[error("a push key is 32 bytes")]
    BadKey,
    #[error("the preview cannot be opened with this key, for this host and seq")]
    Sealed,
    #[error("a preview holds at most {} bytes", PADDED_BYTES - 1)]
    TooLong,
}

/// What a push carries beside the preview, which the preview is bound to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushFields<'a> {
    pub host: &'a str,
    pub seq: i64,
}

impl PushFields<'_> {
    /// The associated data: the protocol's version (`v`), the host and
    /// `seq`, each one's length fixed or given, so no two sets of fields
    /// read the same.
    fn associated(&self) -> Vec<u8> {
        let mut out = b"enclos preview".to_vec();
        out.extend_from_slice(&crate::VERSION.to_be_bytes());
        out.extend_from_slice(&(self.host.len() as u64).to_be_bytes());
        out.extend_from_slice(self.host.as_bytes());
        out.extend_from_slice(&self.seq.to_be_bytes());
        out
    }
}

/// Seals `plaintext` for the device holding `push_key`, bound to `push`.
pub fn seal(
    push_key: &[u8],
    push: &PushFields<'_>,
    plaintext: &[u8],
) -> Result<Vec<u8>, PreviewError> {
    let cipher = XChaCha20Poly1305::new_from_slice(push_key).map_err(|_| PreviewError::BadKey)?;
    if plaintext.len() >= PADDED_BYTES {
        return Err(PreviewError::TooLong);
    }
    let mut padded = plaintext.to_vec();
    padded.push(PAD_MARKER);
    padded.resize(PADDED_BYTES, 0);
    let nonce = XNonce::generate();
    let aad = push.associated();
    let sealed = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: &padded,
                aad: &aad,
            },
        )
        .map_err(|_| PreviewError::Sealed)?;
    let mut out = nonce.to_vec();
    out.extend(sealed);
    Ok(out)
}

/// Opens what [`seal`] made for the same `push`.
pub fn open(
    push_key: &[u8],
    push: &PushFields<'_>,
    sealed: &[u8],
) -> Result<Vec<u8>, PreviewError> {
    let cipher = XChaCha20Poly1305::new_from_slice(push_key).map_err(|_| PreviewError::BadKey)?;
    if sealed.len() < NONCE_BYTES {
        return Err(PreviewError::Sealed);
    }
    let (nonce, ciphertext) = sealed.split_at(NONCE_BYTES);
    let nonce = XNonce::try_from(nonce).map_err(|_| PreviewError::Sealed)?;
    let aad = push.associated();
    let mut padded = cipher
        .decrypt(
            &nonce,
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| PreviewError::Sealed)?;
    // The zeros, then the marker: what is left is the text.
    let end = padded
        .iter()
        .rposition(|&b| b != 0)
        .filter(|&at| padded[at] == PAD_MARKER)
        .ok_or(PreviewError::Sealed)?;
    padded.truncate(end);
    Ok(padded)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PUSH: PushFields<'static> = PushFields {
        host: "mac",
        seq: 1234,
    };

    #[test]
    fn a_preview_opens_with_its_key_only() {
        let key = [4u8; 32];
        let sealed = seal(&key, &PUSH, b"scout: daily weather").unwrap();
        assert_ne!(
            seal(&key, &PUSH, b"scout: daily weather").unwrap(),
            sealed,
            "a new nonce each time"
        );
        assert_eq!(open(&key, &PUSH, &sealed).unwrap(), b"scout: daily weather");
        assert_eq!(open(&[5u8; 32], &PUSH, &sealed), Err(PreviewError::Sealed));
        assert_eq!(open(&key, &PUSH, &sealed[..10]), Err(PreviewError::Sealed));
        assert_eq!(seal(&[1u8; 31], &PUSH, b"x"), Err(PreviewError::BadKey));
    }

    #[test]
    fn a_preview_opens_only_with_the_host_and_seq_it_was_sealed_for() {
        let key = [4u8; 32];
        let sealed = seal(&key, &PUSH, b"old news").unwrap();
        for other in [
            PushFields {
                host: "mac",
                seq: 1235,
            },
            PushFields {
                host: "mini",
                seq: 1234,
            },
        ] {
            assert_eq!(open(&key, &other, &sealed), Err(PreviewError::Sealed));
        }
    }

    #[test]
    fn every_preview_is_one_size() {
        let key = [4u8; 32];
        let short = seal(&key, &PUSH, b"").unwrap();
        let long = seal(&key, &PUSH, &[b'a'; PADDED_BYTES - 1]).unwrap();
        assert_eq!(short.len(), long.len());
        assert_eq!(short.len(), NONCE_BYTES + PADDED_BYTES + 16);
        assert_eq!(open(&key, &PUSH, &short).unwrap(), b"");
        // Zeros at the end of the text are the text's.
        let zeros = seal(&key, &PUSH, b"a\0\0").unwrap();
        assert_eq!(open(&key, &PUSH, &zeros).unwrap(), b"a\0\0");
        assert_eq!(
            seal(&key, &PUSH, &[b'a'; PADDED_BYTES]),
            Err(PreviewError::TooLong)
        );
    }
}
