//! Secrets in one `0600` file of the enclos data folder, for a host where no
//! Secret Service answers (design §12): a JSON object of `<sandbox>/<name>`
//! to value. It is on the sandboxes' hidden files, under the protected paths,
//! and any process of the user can read it, as with the Keychain (ADR 0014).
//!
//! Its mode and owner are checked on every read, through the open file: a
//! wider mode or another owner is refused, naming the file. Every write
//! holds the state lock, and replaces the file whole by a rename, so a read
//! sees one state or the other.

use std::collections::BTreeMap;
use std::fs::{File, Metadata, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use rustix::fs::OFlags;
use rustix::process::geteuid;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use super::{SecretError, SecretStore};
use crate::model::secret::{SecretRef, SecretValue, StoreName};

const MODE: u32 = 0o600;

pub struct FileStore {
    file: PathBuf,
}

/// The file's values, by secret, zeroed once done with: reading one secret
/// holds every sandbox's.
#[derive(Default, Serialize, Deserialize)]
#[serde(transparent)]
struct Values(BTreeMap<String, String>);

impl Values {
    fn zero(&mut self) {
        self.0.values_mut().for_each(Zeroize::zeroize);
    }
}

impl Drop for Values {
    fn drop(&mut self) {
        self.zero();
    }
}

impl FileStore {
    pub fn new(file: PathBuf) -> FileStore {
        FileStore { file }
    }

    /// Every error here leaves the file as it was.
    fn refused(&self, why: impl std::fmt::Display) -> SecretError {
        SecretError {
            what: format!("the secrets file {}: {why}", self.file.display()),
            untouched: true,
        }
    }

    /// Opens the file, never through a link, and blocks on nothing that
    /// stands in for it; `None` when there is none yet.
    fn open(&self) -> Result<Option<File>, SecretError> {
        let flags = OFlags::NOFOLLOW | OFlags::NONBLOCK;
        match OpenOptions::new()
            .read(true)
            .custom_flags(flags.bits() as i32)
            .open(&self.file)
        {
            Ok(file) => Ok(Some(file)),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
            Err(e) => {
                let me = geteuid().as_raw();
                match std::fs::symlink_metadata(&self.file) {
                    Ok(about) if about.uid() != me => Err(self.foreign(about.uid(), me)),
                    _ => {
                        Err(self.refused(format!("cannot open it ({e}); a link is never followed")))
                    }
                }
            }
        }
    }

    fn foreign(&self, owner: u32, me: u32) -> SecretError {
        self.refused(format!(
            "it belongs to user id {owner}, not to this user ({me}), as when enclos ran under `sudo`; check it, then give it back with `chown`"
        ))
    }

    /// Refuses `file` unless it is a plain file only this user reads.
    fn check(&self, file: &File) -> Result<(), SecretError> {
        let about = file
            .metadata()
            .map_err(|e| self.refused(format!("cannot look at it ({e})")))?;
        self.check_about(&about, geteuid().as_raw())
    }

    /// Refuses `about` unless it is of a plain file `uid` alone reads.
    fn check_about(&self, about: &Metadata, uid: u32) -> Result<(), SecretError> {
        if !about.is_file() {
            return Err(self.refused("it is not a plain file"));
        }
        if about.uid() != uid {
            return Err(self.foreign(about.uid(), uid));
        }
        let mode = about.mode() & 0o7777;
        if mode & !MODE != 0 {
            return Err(self.refused(format!(
                "its mode is {mode:04o}, wider than {MODE:04o}, so its values may have been read; check them, then run `chmod 600` on it"
            )));
        }
        Ok(())
    }

    fn load(&self) -> Result<Values, SecretError> {
        let Some(mut file) = self.open()? else {
            return Ok(Values::default());
        };
        self.check(&file)?;
        let mut text = Zeroizing::new(String::new());
        file.read_to_string(&mut text)
            .map_err(|e| self.refused(format!("cannot read it ({e})")))?;
        // Not the parser's words, which can quote what the file holds.
        serde_json::from_str(&text).map_err(|_| self.refused("it is not a file enclos wrote"))
    }

    /// Writes `values` whole beside the file, then renames over it.
    fn save(&self, values: &Values) -> Result<(), SecretError> {
        let text = Zeroizing::new(
            serde_json::to_string_pretty(values)
                .map_err(|_| self.refused("its values cannot be written"))?,
        );
        let mut new = self.file.clone().into_os_string();
        new.push(".new");
        let new = PathBuf::from(new);
        let cannot = |path: &Path, e: std::io::Error| {
            self.refused(format!("cannot write {} ({e})", path.display()))
        };
        match std::fs::remove_file(&new) {
            Ok(()) => {}
            Err(e) if e.kind() == ErrorKind::NotFound => {}
            Err(e) => return Err(cannot(&new, e)),
        }
        write_new(&new, text.as_bytes(), &self.file).map_err(|e| {
            // Whatever part of the values it holds does not stay behind.
            let _ = std::fs::remove_file(&new);
            cannot(&self.file, e)
        })
    }
}

/// Writes `text` to `new`, a file it creates with the store's mode, and
/// renames it to `file`.
fn write_new(new: &Path, text: &[u8], file: &Path) -> std::io::Result<()> {
    let mut out = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(MODE)
        .open(new)?;
    out.write_all(text)?;
    out.sync_all()?;
    std::fs::rename(new, file)
}

impl SecretStore for FileStore {
    fn name(&self) -> StoreName {
        StoreName::File
    }

    fn set(&self, secret: &SecretRef, value: &SecretValue) -> Result<(), SecretError> {
        let mut values = self.load()?;
        let replaced = values
            .0
            .insert(secret.to_string(), value.expose().to_owned());
        drop(replaced.map(Zeroizing::new));
        self.save(&values)
    }

    fn get(&self, secret: &SecretRef) -> Result<Option<SecretValue>, SecretError> {
        self.load()?
            .0
            .remove(&secret.to_string())
            .map(|value| {
                SecretValue::new(value)
                    .map_err(|e| self.refused(format!("the value of {secret}: {e}")))
            })
            .transpose()
    }

    fn remove(&self, secret: &SecretRef) -> Result<bool, SecretError> {
        let mut values = self.load()?;
        let had = values.0.remove(&secret.to_string()).map(Zeroizing::new);
        match had.is_some() {
            true => self.save(&values).map(|()| true),
            false => Ok(false),
        }
    }

    fn whereabouts(&self, secret: &SecretRef) -> String {
        format!(
            "the entry {secret} of the secrets file {}; remove it from that file with an editor",
            self.file.display()
        )
    }

    fn removed_before_record(&self) -> bool {
        true
    }

    /// A file of a mode it would refuse is found before a service starts.
    fn readable(&self) -> Result<(), SecretError> {
        self.load().map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn v(text: &str) -> SecretValue {
        SecretValue::new(text.to_owned()).unwrap()
    }

    fn secret() -> SecretRef {
        "home/telegram".parse().unwrap()
    }

    fn store() -> (tempfile::TempDir, FileStore) {
        let dir = tempfile::tempdir().unwrap();
        let store = FileStore::new(dir.path().join("secrets.json"));
        (dir, store)
    }

    fn chmod(path: &Path, mode: u32) {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn a_secret_is_stored_read_replaced_and_removed() {
        let (_dir, store) = store();
        assert_eq!(store.get(&secret()).unwrap(), None);
        assert!(!store.remove(&secret()).unwrap());
        store.set(&secret(), &v("123:abc \"é\"\nnext\n")).unwrap();
        assert_eq!(
            store.get(&secret()).unwrap(),
            Some(v("123:abc \"é\"\nnext\n"))
        );
        store.set(&secret(), &v("456")).unwrap();
        assert_eq!(store.get(&secret()).unwrap(), Some(v("456")));
        assert!(store.remove(&secret()).unwrap());
        assert_eq!(store.get(&secret()).unwrap(), None);
    }

    #[test]
    fn removing_one_secret_leaves_the_others() {
        let (_dir, store) = store();
        let other: SecretRef = "home/mail".parse().unwrap();
        store.set(&secret(), &v("a")).unwrap();
        store.set(&other, &v("b")).unwrap();
        store.remove(&secret()).unwrap();
        assert_eq!(store.get(&other).unwrap(), Some(v("b")));
    }

    #[test]
    fn the_file_is_0600_and_nothing_stays_beside_it() {
        let (dir, store) = store();
        store.set(&secret(), &v("a")).unwrap();
        store.set(&secret(), &v("b")).unwrap();
        let about = std::fs::metadata(&store.file).unwrap();
        assert_eq!(about.mode() & 0o7777, 0o600);
        let names: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, ["secrets.json"]);
    }

    /// Every way in reads the mode: `get`, `set`, `remove` and `readable`
    /// each refuse a wider one, naming the file, and leave it as it was.
    #[test]
    fn a_wider_mode_is_refused_on_every_read_naming_the_file() {
        for mode in [0o640, 0o604, 0o660, 0o700, 0o4600] {
            let (_dir, store) = store();
            store.set(&secret(), &v("a")).unwrap();
            chmod(&store.file, mode);
            let tries = [
                store.get(&secret()).map(|_| ()).unwrap_err(),
                store.set(&secret(), &v("b")).unwrap_err(),
                store.remove(&secret()).map(|_| ()).unwrap_err(),
                store.readable().unwrap_err(),
            ];
            for err in tries {
                assert!(err.untouched, "{err}");
                assert!(
                    err.what.contains(&store.file.display().to_string()),
                    "{err}"
                );
                assert!(err.what.contains(&format!("{mode:04o}")), "{err}");
            }
            chmod(&store.file, 0o600);
            assert_eq!(store.get(&secret()).unwrap(), Some(v("a")));
        }
    }

    #[test]
    fn a_narrower_mode_is_read() {
        let (_dir, store) = store();
        store.set(&secret(), &v("a")).unwrap();
        chmod(&store.file, 0o400);
        assert_eq!(store.get(&secret()).unwrap(), Some(v("a")));
    }

    #[test]
    fn a_link_is_never_followed() {
        let (dir, store) = store();
        let elsewhere = dir.path().join("elsewhere.json");
        std::fs::write(&elsewhere, "{}").unwrap();
        chmod(&elsewhere, 0o600);
        std::os::unix::fs::symlink(&elsewhere, &store.file).unwrap();
        let err = store.get(&secret()).unwrap_err();
        assert!(err.what.contains("a link is never followed"), "{err}");
        assert!(store.set(&secret(), &v("a")).is_err());
        assert_eq!(std::fs::read_to_string(&elsewhere).unwrap(), "{}");
    }

    /// What it says of a damaged file quotes nothing the file holds.
    #[test]
    fn a_damaged_file_is_refused_without_quoting_it() {
        let (_dir, store) = store();
        std::fs::write(&store.file, "{\"home/telegram\": \"cut-off-valu").unwrap();
        chmod(&store.file, 0o600);
        let err = store.get(&secret()).unwrap_err();
        assert!(err.what.contains("not a file enclos wrote"), "{err}");
        assert!(!err.what.contains("cut-off"), "{err}");
    }

    /// As `sudo -E enclos secret set` would leave it.
    #[test]
    fn a_file_of_another_owner_is_refused_naming_the_owner() {
        let (_dir, store) = store();
        store.set(&secret(), &v("a")).unwrap();
        let about = std::fs::metadata(&store.file).unwrap();
        store.check_about(&about, about.uid()).unwrap();
        let err = store.check_about(&about, about.uid() + 1).unwrap_err();
        assert!(err.untouched, "{err}");
        assert!(err.what.contains("belongs to user id"), "{err}");
        assert!(!err.what.contains("link"), "{err}");
    }

    #[test]
    fn a_write_that_fails_leaves_the_file_and_nothing_beside_it() {
        let (dir, store) = store();
        store.set(&secret(), &v("a")).unwrap();
        chmod(dir.path(), 0o500);
        let err = store.set(&secret(), &v("b")).unwrap_err();
        chmod(dir.path(), 0o700);
        assert!(err.untouched, "{err}");
        assert!(err.what.contains("cannot write"), "{err}");
        assert_eq!(store.get(&secret()).unwrap(), Some(v("a")));
        let names: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, ["secrets.json"]);
    }

    /// What `Drop` runs, and it reaches every value.
    #[test]
    fn the_values_are_zeroed_all_of_them() {
        let mut values = Values::default();
        values.0.insert("home/a".to_owned(), "one".to_owned());
        values.0.insert("lab/b".to_owned(), "two".to_owned());
        values.zero();
        assert!(values.0.values().all(String::is_empty));
    }

    /// The form a file has on disk is the plain object it always was.
    #[test]
    fn the_file_holds_one_plain_object() {
        let (_dir, store) = store();
        store.set(&secret(), &v("a")).unwrap();
        let text = std::fs::read_to_string(&store.file).unwrap();
        let read: BTreeMap<String, String> = serde_json::from_str(&text).unwrap();
        assert_eq!(read["home/telegram"], "a");
    }

    #[test]
    fn its_whereabouts_name_the_file() {
        let (_dir, store) = store();
        assert!(
            store
                .whereabouts(&secret())
                .contains(&store.file.display().to_string())
        );
    }
}
