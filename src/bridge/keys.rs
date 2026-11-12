//! The bridge's keys, each made once and kept beside enclos's state, the
//! user's alone (0600), in files no sandbox reads (`Layout::hidden_files`):
//! its static X25519 key pair, which every paired device pins, in
//! `app-bridge.key`, and the P-256 key it signs runtime-approval decisions
//! with (ADR 0060, proposed), in `app-approvals.key`.

use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use enclos_protocol::decision::DecisionKey;
use enclos_protocol::noise::{KeyPair, generate_keypair};
use zeroize::Zeroizing;

/// The key pair at `path`, made and written there the first time.
pub fn bridge_keypair(path: &Path) -> std::io::Result<KeyPair> {
    let bytes = kept(
        path,
        64,
        "a bridge key: remove it to make a new one, and pair every device again",
        || {
            let keypair = generate_keypair().map_err(|e| std::io::Error::other(e.to_string()))?;
            Ok(Zeroizing::new(
                [keypair.private.as_slice(), keypair.public.as_slice()].concat(),
            ))
        },
    )?;
    Ok(KeyPair {
        private: bytes[..32].to_vec().into(),
        public: bytes[32..].to_vec(),
    })
}

/// The key the bridge signs runtime-approval decisions with, at `path`,
/// made and written there the first time. It signs nothing else.
pub fn approval_key(path: &Path) -> std::io::Result<DecisionKey> {
    let bytes = kept(path, 32, REMADE, || {
        // A scalar of 0 or past the curve's order is not a key: draw again
        // (each draw fails once in about 2^32).
        loop {
            let bytes = Zeroizing::new(super::ids::random_bytes(32)?);
            if DecisionKey::from_bytes(&bytes).is_ok() {
                return Ok(bytes);
            }
        }
    })?;
    DecisionKey::from_bytes(&bytes).map_err(|e| std::io::Error::other(e.to_string()))
}

/// The key the bridge signs runtime-approval decisions with, when it has
/// been made: for a dry run, which writes nothing.
pub fn existing_approval_key(path: &Path) -> std::io::Result<Option<DecisionKey>> {
    match read(path, 32, REMADE)? {
        Some(bytes) => DecisionKey::from_bytes(&bytes)
            .map(Some)
            .map_err(|e| std::io::Error::other(e.to_string())),
        None => Ok(None),
    }
}

const REMADE: &str = "a key for runtime-approval decisions: remove it to make a new one, then run `enclos runtime configure <sandbox>/<agent> --channel app` again for each agent";

/// The `length` bytes kept at `path`, or None when there is no such file.
fn read(path: &Path, length: usize, what: &str) -> std::io::Result<Option<Zeroizing<Vec<u8>>>> {
    match std::fs::read(path) {
        Ok(bytes) if bytes.len() == length => Ok(Some(Zeroizing::new(bytes))),
        Ok(bytes) => {
            drop(Zeroizing::new(bytes));
            Err(std::io::Error::other(format!(
                "{} is not {what}",
                path.display()
            )))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// The `length` bytes kept at `path`, made with `make` and written there
/// the first time.
fn kept(
    path: &Path,
    length: usize,
    what: &str,
    make: impl Fn() -> std::io::Result<Zeroizing<Vec<u8>>>,
) -> std::io::Result<Zeroizing<Vec<u8>>> {
    if let Some(bytes) = read(path, length, what)? {
        return Ok(bytes);
    }
    let bytes = make()?;
    // Written whole beside it, then linked into place: a crash, or another
    // `enclos app` command at the same time, never leaves a short key
    let mut temporary = path.as_os_str().to_owned();
    temporary.push(format!(".{}.new", super::ids::new_id()?));
    let temporary = std::path::PathBuf::from(temporary);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)?;
    let written = file
        .write_all(&bytes)
        .and_then(|()| file.sync_all())
        .and_then(|()| std::fs::hard_link(&temporary, path));
    let _ = std::fs::remove_file(&temporary);
    match written {
        Ok(()) => Ok(bytes),
        // Another command made it first: that one is the key
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => kept(path, length, what, make),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn the_key_is_made_once_and_kept_for_the_user_alone() {
        let folder = tempfile::tempdir().unwrap();
        let path = folder.path().join("app-bridge.key");
        let first = bridge_keypair(&path).unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let again = bridge_keypair(&path).unwrap();
        assert_eq!((first.private, first.public), (again.private, again.public));
        std::fs::write(&path, b"short").unwrap();
        assert!(bridge_keypair(&path).is_err());
    }

    #[test]
    fn commands_making_the_key_at_once_all_get_the_same_whole_key() {
        let folder = tempfile::tempdir().unwrap();
        let path = folder.path().join("app-bridge.key");
        let keys: Vec<_> = (0..8)
            .map(|_| {
                let path = path.clone();
                std::thread::spawn(move || bridge_keypair(&path).unwrap())
            })
            .map(|thread| thread.join().unwrap().public)
            .collect();
        assert!(keys.iter().all(|k| *k == keys[0]));
        assert_eq!(std::fs::read(&path).unwrap().len(), 64);
        // Nothing left beside it
        assert_eq!(std::fs::read_dir(folder.path()).unwrap().count(), 1);
    }

    #[test]
    fn the_approval_key_is_made_once_for_the_user_alone_and_read_without_making_it() {
        let folder = tempfile::tempdir().unwrap();
        let path = folder.path().join("app-approvals.key");
        // A dry run reads it, and makes nothing.
        assert!(existing_approval_key(&path).unwrap().is_none());
        assert!(!path.exists());
        let first = approval_key(&path).unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(first.public().len(), 65);
        assert_eq!(approval_key(&path).unwrap().public(), first.public());
        assert_eq!(
            existing_approval_key(&path).unwrap().unwrap().public(),
            first.public()
        );
        // Its own key, not the bridge's Noise key.
        let noise = bridge_keypair(&folder.path().join("app-bridge.key")).unwrap();
        assert_ne!(noise.public, first.public());
        std::fs::write(&path, [0u8; 32]).unwrap();
        assert!(approval_key(&path).is_err());
        std::fs::write(&path, b"short").unwrap();
        let error = approval_key(&path).err().unwrap().to_string();
        assert!(error.contains("runtime configure"), "{error}");
    }
}
