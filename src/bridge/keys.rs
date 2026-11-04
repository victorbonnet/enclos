//! The bridge's static X25519 key pair, which every paired device pins:
//! made once, kept in `app-bridge.key` (0600) beside enclos's state.

use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use enclos_protocol::noise::{KeyPair, generate_keypair};

/// The key pair at `path`, made and written there the first time.
pub fn bridge_keypair(path: &Path) -> std::io::Result<KeyPair> {
    match std::fs::read(path) {
        Ok(bytes) if bytes.len() == 64 => {
            return Ok(KeyPair {
                private: bytes[..32].to_vec(),
                public: bytes[32..].to_vec(),
            });
        }
        Ok(_) => {
            return Err(std::io::Error::other(format!(
                "{} is not a bridge key: remove it to make a new one, and pair every device again",
                path.display()
            )));
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let keypair = generate_keypair().map_err(|e| std::io::Error::other(e.to_string()))?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(&keypair.private)?;
    file.write_all(&keypair.public)?;
    file.sync_all()?;
    Ok(keypair)
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
}
