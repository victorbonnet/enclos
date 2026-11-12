//! The device leg's encryption (`docs/protocol.md`, Handshake):
//! `Noise_IK_25519_ChaChaPoly_SHA256`, the device as initiator, the
//! bridge's static key known from pairing. The device then proves its
//! hardware key with `auth`, a P-256 signature of a fixed label and the
//! handshake hash ([`crate::pairing::Signed`]), in its first message after
//! the handshake.
//!
//! No I/O: each side turns bytes into bytes. Ephemeral keys come from the
//! system's random source.

use snow::{Builder, HandshakeState, TransportState};
use zeroize::Zeroizing;

const PATTERN: &str = "Noise_IK_25519_ChaChaPoly_SHA256";

/// What both sides mix into the handshake hash before the first message:
/// the protocol and its version, so a handshake of another version, or of
/// another protocol using the same keys, never yields this one's hash.
const PROLOGUE: &[u8] = b"enclos/device/1";

/// Largest Noise message.
pub const MAX_NOISE_MESSAGE: usize = 65535;

/// A static X25519 key pair: the bridge's, or a device's. The private key
/// is wiped from memory when the pair is dropped.
pub struct KeyPair {
    pub private: Zeroizing<Vec<u8>>,
    pub public: Vec<u8>,
}

#[derive(Debug, thiserror::Error)]
pub enum NoiseError {
    #[error("noise: {0}")]
    Noise(#[from] snow::Error),
    #[error("the peer's static key is missing from the handshake")]
    NoRemoteKey,
    #[error("a handshake message carries a payload, which the protocol does not have")]
    Payload,
}

fn builder<'a>() -> Builder<'a> {
    Builder::new(PATTERN.parse().expect("a valid Noise pattern"))
}

/// A builder for a handshake, the prologue set.
fn handshake<'a>() -> Result<Builder<'a>, NoiseError> {
    Ok(builder().prologue(PROLOGUE)?)
}

/// A new static key pair, from the system's random source.
pub fn generate_keypair() -> Result<KeyPair, NoiseError> {
    let keypair = builder().generate_keypair()?;
    Ok(KeyPair {
        private: Zeroizing::new(keypair.private),
        public: keypair.public,
    })
}

/// An encrypted session, once the handshake is done.
pub struct Session {
    transport: TransportState,
    handshake_hash: Vec<u8>,
    remote_static: Vec<u8>,
}

impl Session {
    fn from(state: HandshakeState) -> Result<Session, NoiseError> {
        let handshake_hash = state.get_handshake_hash().to_vec();
        let remote_static = state
            .get_remote_static()
            .ok_or(NoiseError::NoRemoteKey)?
            .to_vec();
        Ok(Session {
            transport: state.into_transport_mode()?,
            handshake_hash,
            remote_static,
        })
    }

    /// The hash of the whole handshake, which binds what is signed or
    /// proved to this session alone.
    pub fn handshake_hash(&self) -> &[u8] {
        &self.handshake_hash
    }

    /// The peer's static public key.
    pub fn remote_static(&self) -> &[u8] {
        &self.remote_static
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let mut out = vec![0u8; plaintext.len() + 16];
        let n = self.transport.write_message(plaintext, &mut out)?;
        out.truncate(n);
        Ok(out)
    }

    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let mut out = vec![0u8; ciphertext.len()];
        let n = self.transport.read_message(ciphertext, &mut out)?;
        out.truncate(n);
        Ok(out)
    }
}

/// The device's side of the handshake.
pub struct Initiator {
    state: HandshakeState,
}

impl Initiator {
    /// With the device's static private key and the bridge's public key,
    /// pinned from the pairing link.
    pub fn new(device_private: &[u8], bridge_public: &[u8]) -> Result<Initiator, NoiseError> {
        let state = handshake()?
            .local_private_key(device_private)?
            .remote_public_key(bridge_public)?
            .build_initiator()?;
        Ok(Initiator { state })
    }

    /// The first handshake message.
    pub fn hello(&mut self) -> Result<Vec<u8>, NoiseError> {
        let mut out = vec![0u8; MAX_NOISE_MESSAGE];
        let n = self.state.write_message(&[], &mut out)?;
        out.truncate(n);
        Ok(out)
    }

    /// Reads the bridge's answer, which ends the handshake.
    pub fn finish(mut self, answer: &[u8]) -> Result<Session, NoiseError> {
        let mut out = vec![0u8; MAX_NOISE_MESSAGE];
        if self.state.read_message(answer, &mut out)? != 0 {
            return Err(NoiseError::Payload);
        }
        Session::from(self.state)
    }
}

/// The bridge's side of the handshake.
pub struct Responder {
    state: HandshakeState,
}

impl Responder {
    pub fn new(bridge_private: &[u8]) -> Result<Responder, NoiseError> {
        let state = handshake()?
            .local_private_key(bridge_private)?
            .build_responder()?;
        Ok(Responder { state })
    }

    /// Reads the device's first message; returns the device's static
    /// public key, for the bridge to look up before answering. A payload,
    /// which the protocol does not have, is refused.
    pub fn read_hello(&mut self, hello: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let mut out = vec![0u8; MAX_NOISE_MESSAGE];
        if self.state.read_message(hello, &mut out)? != 0 {
            return Err(NoiseError::Payload);
        }
        Ok(self
            .state
            .get_remote_static()
            .ok_or(NoiseError::NoRemoteKey)?
            .to_vec())
    }

    /// Answers, which ends the handshake.
    pub fn answer(mut self) -> Result<(Vec<u8>, Session), NoiseError> {
        let mut out = vec![0u8; MAX_NOISE_MESSAGE];
        let n = self.state.write_message(&[], &mut out)?;
        out.truncate(n);
        Ok((out, Session::from(self.state)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_device_and_the_bridge_agree_and_talk() {
        let bridge = generate_keypair().unwrap();
        let device = generate_keypair().unwrap();
        let mut initiator = Initiator::new(&device.private, &bridge.public).unwrap();
        let mut responder = Responder::new(&bridge.private).unwrap();
        let hello = initiator.hello().unwrap();
        assert_eq!(responder.read_hello(&hello).unwrap(), device.public);
        let (answer, mut bridge_side) = responder.answer().unwrap();
        let mut device_side = initiator.finish(&answer).unwrap();
        assert_eq!(device_side.handshake_hash(), bridge_side.handshake_hash());
        assert_eq!(device_side.remote_static(), bridge.public);
        let sealed = device_side.encrypt(b"hello agent").unwrap();
        assert_eq!(bridge_side.decrypt(&sealed).unwrap(), b"hello agent");
        let sealed = bridge_side.encrypt(b"hello device").unwrap();
        assert_eq!(device_side.decrypt(&sealed).unwrap(), b"hello device");
    }

    #[test]
    fn a_device_that_pinned_another_bridge_fails() {
        let bridge = generate_keypair().unwrap();
        let impostor = generate_keypair().unwrap();
        let device = generate_keypair().unwrap();
        let mut initiator = Initiator::new(&device.private, &bridge.public).unwrap();
        let mut responder = Responder::new(&impostor.private).unwrap();
        let hello = initiator.hello().unwrap();
        assert!(responder.read_hello(&hello).is_err());
    }

    /// A device and the bridge after a handshake.
    fn sessions() -> (Session, Session) {
        let bridge = generate_keypair().unwrap();
        let device = generate_keypair().unwrap();
        let mut initiator = Initiator::new(&device.private, &bridge.public).unwrap();
        let mut responder = Responder::new(&bridge.private).unwrap();
        responder.read_hello(&initiator.hello().unwrap()).unwrap();
        let (answer, bridge_side) = responder.answer().unwrap();
        (initiator.finish(&answer).unwrap(), bridge_side)
    }

    #[test]
    fn a_changed_repeated_or_reordered_message_is_refused() {
        // Changed: one bit of the ciphertext, or of its tag.
        for in_tag in [false, true] {
            let (mut device, mut bridge) = sessions();
            let mut sealed = device.encrypt(b"first").unwrap();
            let at = if in_tag { sealed.len() - 1 } else { 0 };
            sealed[at] ^= 1;
            assert!(bridge.decrypt(&sealed).is_err(), "byte {at}");
        }
        // Repeated: the receiver's counter has moved on.
        let (mut device, mut bridge) = sessions();
        let sealed = device.encrypt(b"first").unwrap();
        assert_eq!(bridge.decrypt(&sealed).unwrap(), b"first");
        assert!(bridge.decrypt(&sealed).is_err());
        // Reordered: the second message first.
        let (mut device, mut bridge) = sessions();
        let _one = device.encrypt(b"one").unwrap();
        let two = device.encrypt(b"two").unwrap();
        assert!(bridge.decrypt(&two).is_err());
    }

    #[test]
    fn each_session_has_its_own_handshake_hash() {
        // The same keys on both sides, twice: the ephemeral keys differ, and
        // so does the hash that `auth` signs and `proof` covers.
        let bridge = generate_keypair().unwrap();
        let device = generate_keypair().unwrap();
        let hash = || {
            let mut initiator = Initiator::new(&device.private, &bridge.public).unwrap();
            let mut responder = Responder::new(&bridge.private).unwrap();
            responder.read_hello(&initiator.hello().unwrap()).unwrap();
            let (answer, bridge_side) = responder.answer().unwrap();
            let device_side = initiator.finish(&answer).unwrap();
            assert_eq!(device_side.handshake_hash(), bridge_side.handshake_hash());
            device_side.handshake_hash().to_vec()
        };
        assert_ne!(hash(), hash());
    }

    #[test]
    fn a_handshake_without_this_prologue_fails() {
        let bridge = generate_keypair().unwrap();
        let device = generate_keypair().unwrap();
        let mut other = builder()
            .prologue(b"enclos/device/2")
            .unwrap()
            .local_private_key(&device.private)
            .unwrap()
            .remote_public_key(&bridge.public)
            .unwrap()
            .build_initiator()
            .unwrap();
        let mut hello = vec![0u8; MAX_NOISE_MESSAGE];
        let n = other.write_message(&[], &mut hello).unwrap();
        let mut responder = Responder::new(&bridge.private).unwrap();
        assert!(responder.read_hello(&hello[..n]).is_err());
    }

    #[test]
    fn a_first_message_with_a_payload_is_refused() {
        let bridge = generate_keypair().unwrap();
        let device = generate_keypair().unwrap();
        let mut initiator = handshake()
            .unwrap()
            .local_private_key(&device.private)
            .unwrap()
            .remote_public_key(&bridge.public)
            .unwrap()
            .build_initiator()
            .unwrap();
        let mut hello = vec![0u8; MAX_NOISE_MESSAGE];
        let n = initiator
            .write_message(b"{\"device\":\"d-1\"}", &mut hello)
            .unwrap();
        let mut responder = Responder::new(&bridge.private).unwrap();
        assert!(matches!(
            responder.read_hello(&hello[..n]),
            Err(NoiseError::Payload)
        ));
    }
}
