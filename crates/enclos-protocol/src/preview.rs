//! Notification previews (`docs/protocol.md`, Notifications):
//! XChaCha20-Poly1305 under the device's `push_key`, so the push service
//! carries ciphertext only. `nonce ‖ ciphertext`.

use chacha20poly1305::aead::{Aead, Generate};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};

const NONCE_BYTES: usize = 24;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PreviewError {
    #[error("a push key is 32 bytes")]
    BadKey,
    #[error("the preview cannot be opened with this key")]
    Sealed,
}

/// Seals `plaintext` for the device holding `push_key`.
pub fn seal(push_key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, PreviewError> {
    let cipher = XChaCha20Poly1305::new_from_slice(push_key).map_err(|_| PreviewError::BadKey)?;
    let nonce = XNonce::generate();
    let sealed = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|_| PreviewError::Sealed)?;
    let mut out = nonce.to_vec();
    out.extend(sealed);
    Ok(out)
}

/// Opens what [`seal`] made.
pub fn open(push_key: &[u8], sealed: &[u8]) -> Result<Vec<u8>, PreviewError> {
    let cipher = XChaCha20Poly1305::new_from_slice(push_key).map_err(|_| PreviewError::BadKey)?;
    if sealed.len() < NONCE_BYTES {
        return Err(PreviewError::Sealed);
    }
    let (nonce, ciphertext) = sealed.split_at(NONCE_BYTES);
    let nonce = XNonce::try_from(nonce).map_err(|_| PreviewError::Sealed)?;
    cipher
        .decrypt(&nonce, ciphertext)
        .map_err(|_| PreviewError::Sealed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_preview_opens_with_its_key_only() {
        let key = [4u8; 32];
        let sealed = seal(&key, b"scout: daily weather").unwrap();
        assert_ne!(
            seal(&key, b"scout: daily weather").unwrap(),
            sealed,
            "a new nonce each time"
        );
        assert_eq!(open(&key, &sealed).unwrap(), b"scout: daily weather");
        assert_eq!(open(&[5u8; 32], &sealed), Err(PreviewError::Sealed));
        assert_eq!(open(&key, &sealed[..10]), Err(PreviewError::Sealed));
        assert_eq!(seal(&[1u8; 31], b"x"), Err(PreviewError::BadKey));
    }
}
