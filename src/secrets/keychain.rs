//! Secrets in the macOS Keychain, through `/usr/bin/security`: generic
//! passwords whose service names the enclos install and whose account is
//! `<sandbox>/<name>`.
//!
//! An item `security` adds trusts `security` itself, so reading it back
//! through `security` asks nothing, whichever program runs it, a service
//! started by launchd included, and whatever enclos's own code signature is
//! after an upgrade. Any program of the user can read it the same way: the
//! Keychain keeps secrets away from sandboxes, which reach neither the
//! security daemon nor the keychain files (design §5), not from the user's
//! other programs (ADR 0014).
//!
//! A value goes to `security -i` on its input, never as an argument, which
//! other processes could list; and as hex, which reads back the same, since
//! `security` prints a value that is not plain ASCII as hex of its own.
//!
//! Nothing here may ask anything: a service has nobody to answer. A user
//! with no default keychain (a throwaway `HOME`) is refused before anything
//! is written, since writing would ask where to create one, and every call
//! is ended after [`ANSWER_WAIT`].

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use super::{SecretError, SecretStore};
use crate::model::secret::SecretRef;

const SECURITY: &str = "/usr/bin/security";
/// What `security` exits with when no such item exists.
const NOT_FOUND: i32 = 44;
/// How long a call to `security` may take: long past any answer, short of
/// a wait on a dialog nobody sees.
const ANSWER_WAIT: Duration = Duration::from_secs(30);

pub struct Keychain {
    /// The service of every item: `enclos.<install>`.
    service: String,
    /// The keychain file to use instead of the user's default one.
    file: Option<PathBuf>,
}

impl Keychain {
    pub fn new(service: String, file: Option<PathBuf>) -> Keychain {
        Keychain { service, file }
    }

    /// The default keychain, or the file `ENCLOS_KEYCHAIN` names.
    pub fn from_env(service: String) -> Keychain {
        let file = std::env::var_os("ENCLOS_KEYCHAIN")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from);
        Keychain::new(service, file)
    }

    /// The keychain file it uses instead of the user's default one.
    pub fn file(&self) -> Option<&Path> {
        self.file.as_deref()
    }

    fn file_args(&self) -> Vec<String> {
        self.file.iter().map(|f| f.display().to_string()).collect()
    }

    fn fail(&self, what: &str, secret: &SecretRef, why: impl std::fmt::Display) -> SecretError {
        SecretError {
            what: format!("cannot {what} secret {secret} in the Keychain: {why}"),
        }
    }

    /// Refuses a keychain that is not there: a write to it would ask where
    /// to make one.
    fn require_keychain(&self, secret: &SecretRef) -> Result<(), SecretError> {
        let file = match &self.file {
            Some(file) => file.clone(),
            None => {
                let out = run(
                    Command::new(SECURITY).args(["default-keychain", "-d", "user"]),
                    None,
                )
                .map_err(|e| self.fail("store", secret, e))?;
                let text = String::from_utf8_lossy(&out.stdout);
                match (out.status.success(), text.trim().trim_matches('"')) {
                    (true, path) if !path.is_empty() => PathBuf::from(path),
                    _ => {
                        return Err(self.fail(
                            "store",
                            secret,
                            "this user has no default keychain; set ENCLOS_KEYCHAIN to a keychain file to use one",
                        ));
                    }
                }
            }
        };
        match file.exists() {
            true => Ok(()),
            false => Err(self.fail(
                "store",
                secret,
                format!("the keychain {} does not exist", file.display()),
            )),
        }
    }
}

impl SecretStore for Keychain {
    fn set(&self, secret: &SecretRef, value: &str) -> Result<(), SecretError> {
        self.require_keychain(secret)?;
        let file = match &self.file {
            Some(file) => {
                let file = file.display().to_string();
                if file.contains(['"', '\\', '\n']) {
                    return Err(self.fail(
                        "store",
                        secret,
                        "the keychain file's path holds a quote",
                    ));
                }
                format!(" \"{file}\"")
            }
            None => String::new(),
        };
        let line = format!(
            "add-generic-password -U -s {} -a {secret} -l \"enclos secret {secret}\" -w {}{file}\n",
            self.service,
            hex(value.as_bytes())
        );
        let out = run(Command::new(SECURITY).arg("-i"), Some(line.as_bytes()))
            .map_err(|e| self.fail("store", secret, e))?;
        if !out.status.success() {
            return Err(self.fail("store", secret, stderr(&out.stderr, out.status)));
        }
        // `security -i` exits 0 whatever its command did: only reading the
        // value back shows it was stored.
        match self.get(secret)? {
            Some(stored) if stored == value => Ok(()),
            _ => Err(self.fail(
                "store",
                secret,
                match stderr(&out.stderr, out.status).as_str() {
                    "" => "the Keychain refused it".to_owned(),
                    why => why.to_owned(),
                },
            )),
        }
    }

    fn get(&self, secret: &SecretRef) -> Result<Option<String>, SecretError> {
        let out = run(
            Command::new(SECURITY)
                .args(["find-generic-password", "-s", &self.service, "-a"])
                .arg(secret.to_string())
                .arg("-w")
                .args(self.file_args()),
            None,
        )
        .map_err(|e| self.fail("read", secret, e))?;
        if out.status.code() == Some(NOT_FOUND) {
            return Ok(None);
        }
        if !out.status.success() {
            return Err(self.fail("read", secret, stderr(&out.stderr, out.status)));
        }
        let text = String::from_utf8_lossy(&out.stdout);
        let bytes = unhex(text.trim_end_matches('\n'))
            .ok_or_else(|| self.fail("read", secret, "its value was not stored by enclos"))?;
        String::from_utf8(bytes)
            .map(Some)
            .map_err(|_| self.fail("read", secret, "its value is not text"))
    }

    fn remove(&self, secret: &SecretRef) -> Result<bool, SecretError> {
        let out = run(
            Command::new(SECURITY)
                .args(["delete-generic-password", "-s", &self.service, "-a"])
                .arg(secret.to_string())
                .args(self.file_args()),
            None,
        )
        .map_err(|e| self.fail("remove", secret, e))?;
        match out.status.code() {
            Some(0) => Ok(true),
            Some(NOT_FOUND) => Ok(false),
            _ => Err(self.fail("remove", secret, stderr(&out.stderr, out.status))),
        }
    }
}

/// Runs `command` with `input` on its standard input, ending it after
/// [`ANSWER_WAIT`]: past that, it waits on something nobody will answer.
fn run(command: &mut Command, input: Option<&[u8]>) -> Result<Output, String> {
    run_for(command, input, ANSWER_WAIT)
}

fn run_for(command: &mut Command, input: Option<&[u8]>, wait: Duration) -> Result<Output, String> {
    let mut child = command
        .stdin(match input {
            Some(_) => Stdio::piped(),
            None => Stdio::null(),
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("cannot run {SECURITY}: {e}"))?;
    if let Some(input) = input {
        let wrote = child.stdin.take().expect("piped").write_all(input);
        if let Err(e) = wrote {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!("cannot give {SECURITY} its input: {e}"));
        }
    }
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if started.elapsed() < wait => std::thread::sleep(Duration::from_millis(20)),
            Ok(None) => {
                // The child this call started, and nothing else.
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!(
                    "{SECURITY} did not answer within {} seconds, as if it waited on a dialog; it was ended",
                    wait.as_secs()
                ));
            }
            Err(e) => return Err(format!("lost {SECURITY}: {e}")),
        }
    }
    child
        .wait_with_output()
        .map_err(|e| format!("lost {SECURITY}: {e}"))
}

fn stderr(bytes: &[u8], status: std::process::ExitStatus) -> String {
    match String::from_utf8_lossy(bytes).trim() {
        "" if status.success() => String::new(),
        "" => status.to_string(),
        why => why.to_owned(),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_go_as_hex_and_come_back_whole() {
        let value = "tok:en \"quoted\" é\n";
        assert_eq!(unhex(&hex(value.as_bytes())).unwrap(), value.as_bytes());
        assert_eq!(unhex("abc"), None);
        assert_eq!(unhex("zz"), None);
        assert_eq!(unhex(""), Some(Vec::new()));
    }

    #[test]
    fn a_call_that_does_not_answer_in_time_is_ended() {
        let out = run_for(&mut Command::new("/bin/echo"), None, ANSWER_WAIT).unwrap();
        assert!(out.status.success());
        let begun = Instant::now();
        let err = run_for(
            Command::new("/bin/sleep").arg("30"),
            None,
            Duration::from_millis(200),
        )
        .unwrap_err();
        assert!(err.contains("did not answer"), "{err}");
        assert!(begun.elapsed() < Duration::from_secs(5));
    }

    /// A keychain file in a folder of this test's own, which `security`
    /// does not add to the user's search list, removed at the end.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_secret_is_stored_read_replaced_and_removed() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("test.keychain-db");
        let ok = |args: &[&str]| {
            assert!(
                Command::new(SECURITY)
                    .args(args)
                    .status()
                    .unwrap()
                    .success()
            )
        };
        let path = file.to_str().unwrap();
        ok(&["create-keychain", "-p", "test", path]);
        ok(&["unlock-keychain", "-p", "test", path]);
        let store = Keychain::new("enclos.test".into(), Some(file.clone()));
        let secret: SecretRef = "home/telegram".parse().unwrap();
        assert_eq!(store.get(&secret).unwrap(), None);
        store.set(&secret, "123:abc \"é\"").unwrap();
        assert_eq!(
            store.get(&secret).unwrap().as_deref(),
            Some("123:abc \"é\"")
        );
        store.set(&secret, "456").unwrap();
        assert_eq!(store.get(&secret).unwrap().as_deref(), Some("456"));
        assert!(store.remove(&secret).unwrap());
        assert!(!store.remove(&secret).unwrap());
        assert_eq!(store.get(&secret).unwrap(), None);
        // A keychain that is not there is refused before anything runs.
        let gone = Keychain::new("enclos.test".into(), Some(dir.path().join("none")));
        let err = gone.set(&secret, "x").unwrap_err();
        assert!(err.what.contains("does not exist"), "{err}");
        ok(&["delete-keychain", path]);
    }
}
