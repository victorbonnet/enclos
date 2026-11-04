//! Pairing (`docs/protocol.md`, Pairing): the link the QR code holds, the
//! device's proof that it read the one-time code, and the check of its
//! hardware key's signature.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, KeyInit, Mac};
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use sha2::Sha256;

/// The pairing link: `enclos://pair?v=1&host=…&url=…&key=…&code=…&exp=…`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairLink {
    pub host: String,
    /// Where the bridge is reached, `https://<host>.<tailnet>.ts.net`.
    pub url: String,
    /// The bridge's static X25519 public key, which the device pins.
    pub key: Vec<u8>,
    /// The one-time code, 16 bytes.
    pub code: Vec<u8>,
    /// Until when the code works, in seconds since the Unix epoch.
    pub expires: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PairingError {
    #[error("not an enclos pairing link: {0}")]
    BadLink(String),
    #[error("the proof of the pairing code does not match")]
    BadProof,
    #[error("the device's key or signature cannot be read: {0}")]
    BadKey(String),
    #[error("the device's signature does not match its key")]
    BadSignature,
}

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn unb64(field: &str, text: &str) -> Result<Vec<u8>, PairingError> {
    URL_SAFE_NO_PAD
        .decode(text)
        .map_err(|e| PairingError::BadLink(format!("{field}: {e}")))
}

/// What a URL query value may hold unescaped: the link's values are
/// base64url, a host name, digits, and a URL, whose `:`, `/` and `.` are
/// written as they are; anything else is refused rather than escaped.
fn plain(value: &str) -> bool {
    value
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"-_.:/".contains(&b))
}

impl PairLink {
    pub fn to_link(&self) -> Result<String, PairingError> {
        if !plain(&self.host) || !plain(&self.url) {
            return Err(PairingError::BadLink(
                "the host or the URL holds a character a pairing link does not carry".to_owned(),
            ));
        }
        Ok(format!(
            "enclos://pair?v=1&host={}&url={}&key={}&code={}&exp={}",
            self.host,
            self.url,
            b64(&self.key),
            b64(&self.code),
            self.expires
        ))
    }

    pub fn parse(link: &str) -> Result<PairLink, PairingError> {
        let query = link.strip_prefix("enclos://pair?").ok_or_else(|| {
            PairingError::BadLink("it does not start with enclos://pair?".to_owned())
        })?;
        let mut v = None;
        let (mut host, mut url, mut key, mut code, mut expires) = (None, None, None, None, None);
        for pair in query.split('&') {
            let (name, value) = pair
                .split_once('=')
                .ok_or_else(|| PairingError::BadLink(format!("`{pair}` is not name=value")))?;
            if !plain(value) {
                return Err(PairingError::BadLink(format!(
                    "{name} holds an unexpected character"
                )));
            }
            match name {
                "v" => v = Some(value),
                "host" => host = Some(value.to_owned()),
                "url" => url = Some(value.to_owned()),
                "key" => key = Some(unb64("key", value)?),
                "code" => code = Some(unb64("code", value)?),
                "exp" => {
                    expires = Some(
                        value
                            .parse()
                            .map_err(|_| PairingError::BadLink("exp is not a number".to_owned()))?,
                    )
                }
                _ => {} // a newer link's field
            }
        }
        if v != Some("1") {
            return Err(PairingError::BadLink(
                "it is not version 1: update the app".to_owned(),
            ));
        }
        let missing = |f: &str| PairingError::BadLink(format!("{f} is missing"));
        let link = PairLink {
            host: host.ok_or_else(|| missing("host"))?,
            url: url.ok_or_else(|| missing("url"))?,
            key: key.ok_or_else(|| missing("key"))?,
            code: code.ok_or_else(|| missing("code"))?,
            expires: expires.ok_or_else(|| missing("exp"))?,
        };
        if link.key.len() != 32 || link.code.len() != 16 || !link.url.starts_with("https://") {
            return Err(PairingError::BadLink(
                "its key, code or URL is not of the expected kind".to_owned(),
            ));
        }
        Ok(link)
    }
}

/// HMAC-SHA256 of the handshake hash, keyed with the pairing code: proves
/// the device read the code, in this session.
pub fn proof(code: &[u8], handshake_hash: &[u8]) -> Vec<u8> {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(code).expect("HMAC takes any key");
    mac.update(handshake_hash);
    mac.finalize().into_bytes().to_vec()
}

/// Checks `proof` in constant time.
pub fn check_proof(code: &[u8], handshake_hash: &[u8], proof: &[u8]) -> Result<(), PairingError> {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(code).expect("HMAC takes any key");
    mac.update(handshake_hash);
    mac.verify_slice(proof).map_err(|_| PairingError::BadProof)
}

/// Checks the device's ECDSA P-256 signature (DER, as Android's Keystore
/// and Apple's Secure Enclave give it) of `message` with its key (SEC1).
pub fn check_signature(
    device_key: &[u8],
    message: &[u8],
    signature_der: &[u8],
) -> Result<(), PairingError> {
    let key = VerifyingKey::from_sec1_bytes(device_key)
        .map_err(|e| PairingError::BadKey(e.to_string()))?;
    let signature =
        Signature::from_der(signature_der).map_err(|e| PairingError::BadKey(e.to_string()))?;
    key.verify(message, &signature)
        .map_err(|_| PairingError::BadSignature)
}

/// Encodes bytes as the protocol carries them in JSON.
pub fn encode(bytes: &[u8]) -> String {
    b64(bytes)
}

/// Decodes what [`encode`] wrote.
pub fn decode(field: &str, text: &str) -> Result<Vec<u8>, PairingError> {
    unb64(field, text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::SigningKey;
    use p256::ecdsa::signature::Signer;

    fn link() -> PairLink {
        PairLink {
            host: "mac".into(),
            url: "https://mac.tail1234.ts.net".into(),
            key: vec![7; 32],
            code: vec![9; 16],
            expires: 1_800_000_000,
        }
    }

    #[test]
    fn a_link_reads_back_as_written() {
        let text = link().to_link().unwrap();
        assert!(
            text.starts_with("enclos://pair?v=1&host=mac&url=https://mac.tail1234.ts.net&key=")
        );
        assert_eq!(PairLink::parse(&text).unwrap(), link());
    }

    #[test]
    fn a_bad_link_is_refused() {
        let good = link().to_link().unwrap();
        for bad in [
            good.replace("v=1", "v=2"),
            good.replace("enclos://pair?", "https://pair?"),
            good.replace("https://mac", "http://mac"),
            good.replace("&exp=1800000000", ""),
            good.replace("host=mac", "host=m%20c"),
        ] {
            assert!(PairLink::parse(&bad).is_err(), "{bad}");
        }
        let mut long_code = link();
        long_code.code = vec![1; 17];
        assert!(PairLink::parse(&long_code.to_link().unwrap()).is_err());
    }

    #[test]
    fn the_proof_holds_for_the_code_and_this_session_only() {
        let code = [5u8; 16];
        let hash = [1u8; 32];
        let p = proof(&code, &hash);
        assert!(check_proof(&code, &hash, &p).is_ok());
        assert_eq!(
            check_proof(&[6u8; 16], &hash, &p),
            Err(PairingError::BadProof)
        );
        assert_eq!(
            check_proof(&code, &[2u8; 32], &p),
            Err(PairingError::BadProof)
        );
    }

    #[test]
    fn a_der_signature_of_the_device_key_is_checked() {
        let signing = SigningKey::from_slice(&[3u8; 32]).unwrap();
        let key = signing.verifying_key().to_sec1_point(false);
        let message = b"handshake hash";
        let signature: Signature = signing.sign(message);
        let der = signature.to_der();
        assert!(check_signature(key.as_ref(), message, der.as_bytes()).is_ok());
        assert_eq!(
            check_signature(key.as_ref(), b"another", der.as_bytes()),
            Err(PairingError::BadSignature)
        );
        assert!(check_signature(&[0u8; 65], message, der.as_bytes()).is_err());
    }
}
