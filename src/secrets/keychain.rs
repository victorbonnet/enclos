//! Secrets in the macOS Keychain, through `/usr/bin/security`: generic
//! passwords whose service names the enclos install and whose account is
//! `<sandbox>/<name>`.
//!
//! An item `security` adds trusts `security` itself, so reading it back
//! through `security` asks nothing, whichever program runs it: shown for
//! `exec` across two builds of enclos with different code signatures; for
//! a service launchd starts, still to verify (design §14). Any program of the user can read it the same way: the
//! Keychain keeps secrets away from sandboxes, which reach neither the
//! security daemon nor the keychain files (design §5), not from the user's
//! other programs (ADR 0014).
//!
//! A value goes to `security -i` on its input, never as an argument, which
//! other processes could list; and as hex, which reads back the same, since
//! `security` prints a value that is not plain ASCII as hex of its own.
//! `security -i` reads a line in pieces of at most [`MAX_LINE`] bytes and
//! runs each piece as a command, so a longer line is refused before it is
//! sent: its tail would run as a command of its own, which `security` then
//! prints back.
//!
//! Nothing here may ask anything: a service has nobody to answer. A user
//! with no default keychain (a throwaway `HOME`) is refused before anything
//! is written, since writing would ask where to create one, and every call
//! is ended after [`ANSWER_WAIT`].

use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::time::{Duration, Instant};

use super::{SecretError, SecretStore};
use crate::model::secret::{SecretRef, SecretValue};

const SECURITY: &str = "/usr/bin/security";
/// What `security` exits with when no such item exists.
const NOT_FOUND: i32 = 44;
/// How long a call to `security` may take: long past any answer, short of
/// a wait on a dialog nobody sees.
const ANSWER_WAIT: Duration = Duration::from_secs(30);
/// The longest line `security -i` reads as one command, its line ending
/// included (macOS 26.5.2: a longer one runs as two).
const MAX_LINE: usize = 4095;
/// Names a keychain file to use in place of the default one.
const KEYCHAIN_VAR: &str = "ENCLOS_KEYCHAIN";

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

    /// The default keychain, or the file `ENCLOS_KEYCHAIN` names, taken
    /// from the current folder when relative, so every call names the same
    /// file.
    pub fn from_env(service: String) -> Keychain {
        let file = std::env::var_os(KEYCHAIN_VAR)
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .map(|f| match std::path::absolute(&f) {
                Ok(absolute) => absolute,
                Err(e) => {
                    eprintln!(
                        "warning: cannot tell where {KEYCHAIN_VAR}={} is from here ({e}); services enclos installs may not find it",
                        f.display()
                    );
                    f
                }
            });
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
            untouched: false,
        }
    }

    /// Whether the keychain can be read without a dialog: `security
    /// show-keychain-info` answers at once, with no dialog, and fails on a
    /// locked keychain (exit 152 on macOS 26.5.2, "Unable to obtain
    /// authorization").
    fn check_unlocked(&self) -> Result<(), SecretError> {
        let which = match &self.file {
            Some(file) => format!("keychain {}", file.display()),
            None => "default keychain".to_owned(),
        };
        let fail = |why: String| SecretError {
            what: format!("the {which} cannot be read without asking: {why}"),
            untouched: true,
        };
        let out = run(
            Command::new(SECURITY)
                .arg("show-keychain-info")
                .args(self.file_args()),
            None,
        )
        .map_err(fail)?;
        match out.status.success() {
            true => Ok(()),
            false => Err(fail(format!(
                "it is locked ({})",
                String::from_utf8_lossy(&out.stderr).trim()
            ))),
        }
    }

    /// Refuses a keychain file that is not there, which `security` would
    /// answer as it answers an item that is not there.
    fn require_file(&self, what: &str, secret: &SecretRef) -> Result<(), SecretError> {
        match self.file.as_ref().map(|f| (f, f.try_exists())) {
            Some((file, Ok(false))) => Err(self.fail(
                what,
                secret,
                format!(
                    "the keychain {} ({KEYCHAIN_VAR}) does not exist",
                    file.display()
                ),
            )),
            Some((file, Err(e))) => Err(self.fail(
                what,
                secret,
                format!("cannot look at the keychain {} ({e})", file.display()),
            )),
            _ => Ok(()),
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
                match default_keychain(&out) {
                    Ok(path) => path,
                    Err(why) => return Err(self.fail("store", secret, why)),
                }
            }
        };
        match file.try_exists() {
            Ok(true) => Ok(()),
            Ok(false) => Err(self.fail(
                "store",
                secret,
                format!("the keychain {} does not exist", file.display()),
            )),
            Err(e) => Err(self.fail(
                "store",
                secret,
                format!("cannot look at the keychain {} ({e})", file.display()),
            )),
        }
    }

    /// The line that stores `value` for `secret`, for `security -i`.
    fn store_line(&self, secret: &SecretRef, value: &str) -> Result<String, SecretError> {
        // Every word but the value goes into the line unquoted: the service
        // is enclos's own, and a secret's name holds no space or quote.
        if !self
            .service
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
        {
            return Err(self.fail(
                "store",
                secret,
                format!("the service name {:?} is not plain", self.service),
            ));
        }
        let file = match &self.file {
            Some(file) => {
                let file = file.display().to_string();
                if file.contains(['"', '\\', '\n']) {
                    return Err(self.fail(
                        "store",
                        secret,
                        "the keychain file's path holds a quote, a backslash or a line break",
                    ));
                }
                format!(" \"{file}\"")
            }
            None => String::new(),
        };
        let head = format!(
            "add-generic-password -U -s {} -a {secret} -l \"enclos secret {secret}\" -w ",
            self.service
        );
        let length = head.len() + 2 * value.len() + file.len() + 1;
        if length > MAX_LINE {
            let most = MAX_LINE.saturating_sub(head.len() + file.len() + 1) / 2;
            return Err(self.fail(
                "store",
                secret,
                format!(
                    "its value is {} bytes; the Keychain takes at most {most} through `security`",
                    value.len()
                ),
            ));
        }
        Ok(format!("{head}{}{file}\n", hex(value.as_bytes())))
    }
}

impl SecretStore for Keychain {
    fn set(&self, secret: &SecretRef, value: &SecretValue) -> Result<(), SecretError> {
        // Refused before `security` runs: the keychain is as it was.
        let untouched = |e: SecretError| SecretError {
            untouched: true,
            ..e
        };
        let line = self.store_line(secret, value.expose()).map_err(untouched)?;
        self.require_keychain(secret).map_err(untouched)?;
        // What `security -i` prints may repeat its input, the value with
        // it: only its words are kept, never a run of the value's hex.
        let shown = hex(value.expose().as_bytes());
        let out = run(Command::new(SECURITY).arg("-i"), Some(line.as_bytes()))
            .map_err(|e| self.fail("store", secret, scrub(&e, &shown)))?;
        let why = scrub(&stderr(&out.stderr, out.status), &shown);
        if !out.status.success() {
            return Err(self.fail("store", secret, why));
        }
        // `security -i` can exit 0 though its command failed: only reading
        // the value back shows it was stored.
        match self.get(secret)? {
            Some(stored) if stored == *value => Ok(()),
            _ => Err(self.fail(
                "store",
                secret,
                match why.as_str() {
                    "" => "the Keychain refused it",
                    why => why,
                },
            )),
        }
    }

    fn get(&self, secret: &SecretRef) -> Result<Option<SecretValue>, SecretError> {
        self.require_file("read", secret)?;
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
        let text = String::from_utf8(bytes)
            .map_err(|_| self.fail("read", secret, "its value is not text"))?;
        SecretValue::new(text)
            .map(Some)
            .map_err(|e| self.fail("read", secret, e))
    }

    fn remove(&self, secret: &SecretRef) -> Result<bool, SecretError> {
        self.require_file("remove", secret)?;
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

    fn whereabouts(&self, secret: &SecretRef) -> String {
        let file = self
            .file
            .as_ref()
            .map(|f| format!(" {}", crate::probes::sh_quote(f)))
            .unwrap_or_default();
        format!(
            "the Keychain item of service {} and account {secret}; remove it with `security delete-generic-password -s {} -a {secret}{file}`",
            self.service, self.service
        )
    }

    fn env(&self) -> Vec<(String, String)> {
        self.file
            .iter()
            .map(|f| (KEYCHAIN_VAR.to_owned(), f.display().to_string()))
            .collect()
    }

    fn readable(&self) -> Result<(), SecretError> {
        self.check_unlocked()
    }
}

/// The user's default keychain, from what `security default-keychain -d
/// user` printed.
fn default_keychain(out: &Output) -> Result<PathBuf, String> {
    let path = String::from_utf8_lossy(&out.stdout);
    let path = path.trim().trim_matches('"');
    match (out.status.success(), path.is_empty()) {
        (true, false) => Ok(PathBuf::from(path)),
        (true, true) => Err(
            "this user has no default keychain; set ENCLOS_KEYCHAIN to a keychain file to use one"
                .to_owned(),
        ),
        (false, _) => Err(format!(
            "cannot find this user's default keychain ({}); set ENCLOS_KEYCHAIN to a keychain file to use one",
            stderr(&out.stderr, out.status)
        )),
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
    // Read as it writes, so a long answer never fills a pipe and stalls it.
    let drain = |pipe: Option<Box<dyn Read + Send>>| {
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            if let Some(mut pipe) = pipe {
                pipe.read_to_end(&mut bytes)?;
            }
            Ok::<_, io::Error>(bytes)
        })
    };
    let stdout = drain(
        child
            .stdout
            .take()
            .map(|p| Box::new(p) as Box<dyn Read + Send>),
    );
    let stderr = drain(
        child
            .stderr
            .take()
            .map(|p| Box::new(p) as Box<dyn Read + Send>),
    );
    let status = wait_for(&mut child, input, wait);
    if status.is_err() {
        // The child this call started, and nothing else.
        let _ = child.kill();
        let _ = child.wait();
    }
    let joined = |drain: std::thread::JoinHandle<io::Result<Vec<u8>>>| match drain.join() {
        Ok(read) => read.map_err(|e| format!("cannot read what {SECURITY} answered: {e}")),
        Err(_) => Err(format!("lost what {SECURITY} answered")),
    };
    let (stdout, stderr) = (joined(stdout), joined(stderr));
    // Why it failed, as `security` said it, when it said anything.
    let status = status.map_err(|e| match &stderr {
        Ok(said) if !said.is_empty() => {
            format!("{e} ({})", scrub(String::from_utf8_lossy(said).trim(), ""))
        }
        _ => e,
    })?;
    Ok(Output {
        status,
        stdout: stdout?,
        stderr: stderr?,
    })
}

/// Gives `child` its input, which fits in a pipe's buffer (a line of at
/// most [`MAX_LINE`] bytes), and waits for it to end, for at most `wait`.
fn wait_for(child: &mut Child, input: Option<&[u8]>, wait: Duration) -> Result<ExitStatus, String> {
    if let Some(input) = input {
        let mut stdin = child.stdin.take().expect("piped");
        stdin
            .write_all(input)
            .map_err(|e| format!("cannot give {SECURITY} its input: {e}"))?;
    }
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) if started.elapsed() < wait => std::thread::sleep(Duration::from_millis(20)),
            Ok(None) => {
                return Err(format!(
                    "{SECURITY} did not answer within {} seconds, as if it waited on a dialog; it was ended",
                    wait.as_secs()
                ));
            }
            Err(e) => return Err(format!("lost {SECURITY}: {e}")),
        }
    }
}

fn stderr(bytes: &[u8], status: ExitStatus) -> String {
    match String::from_utf8_lossy(bytes).trim() {
        "" if status.success() => String::new(),
        "" => status.to_string(),
        why => why.to_owned(),
    }
}

/// `text` with every run of hex digits that could be part of a value left
/// out: one of 16 or more digits, and one of 4 or more found in `value`,
/// the hex-encoded value.
fn scrub(text: &str, value: &str) -> String {
    let mut out = String::new();
    let mut run = String::new();
    for c in text.chars().chain(std::iter::once(' ')) {
        if c.is_ascii_hexdigit() {
            run.push(c);
            continue;
        }
        let lower = run.to_ascii_lowercase();
        let of_value =
            !run.is_empty() && (lower == value || (run.len() >= 4 && value.contains(&lower)));
        match run.len() >= 16 || of_value {
            true => out.push('…'),
            false => out.push_str(&run),
        }
        run.clear();
        out.push(c);
    }
    out.pop();
    out
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

    fn v(text: &str) -> SecretValue {
        SecretValue::new(text.to_owned()).unwrap()
    }

    #[test]
    fn values_go_as_hex_and_come_back_whole() {
        let value = "tok:en \"quoted\" é\n";
        assert_eq!(unhex(&hex(value.as_bytes())).unwrap(), value.as_bytes());
        assert_eq!(unhex("abc"), None);
        assert_eq!(unhex("zz"), None);
        assert_eq!(unhex(""), Some(Vec::new()));
    }

    #[test]
    fn what_security_prints_back_never_holds_a_value() {
        let printed = format!(
            "security: unknown command \"{}\"\nenclos.1a2b3c4d: returned 1",
            hex(b"a long secret value")
        );
        assert_eq!(
            scrub(&printed, ""),
            "security: unknown command \"…\"\nenclos.1a2b3c4d: returned 1"
        );
        assert_eq!(scrub("", ""), "");
        // A short value, cut anywhere, is left out too.
        assert_eq!(
            scrub("unknown command \"6b2d31\"", &hex(b"tok-1")),
            "unknown command \"…\""
        );
    }

    #[test]
    fn a_value_too_long_for_one_line_is_refused_before_anything_runs() {
        let store = Keychain::new("enclos.1a2b3c4d".into(), Some("/nowhere/k.db".into()));
        let secret: SecretRef = "home/key".parse().unwrap();
        let fits = store.store_line(&secret, &"x".repeat(1900)).unwrap();
        assert!(fits.len() <= MAX_LINE && fits.ends_with("\"/nowhere/k.db\"\n"));
        let err = store.store_line(&secret, &"x".repeat(2100)).unwrap_err();
        assert!(err.what.contains("its value is 2100 bytes"), "{err}");
        assert!(!err.what.contains("7878"), "{err}");
        // `set` refuses it before it looks for the keychain.
        let err = store.set(&secret, &v(&"x".repeat(2100))).unwrap_err();
        assert!(err.what.contains("at most"), "{err}");
        let odd = Keychain::new("enclos x".into(), None);
        assert!(odd.store_line(&secret, "v").is_err());
        let quoted = Keychain::new("enclos.t".into(), Some("/a\"b/k.db".into()));
        let err = quoted.store_line(&secret, "v").unwrap_err();
        assert!(err.what.contains("holds a quote"), "{err}");
    }

    #[test]
    fn the_default_keychain_is_read_from_what_security_prints() {
        use std::os::unix::process::ExitStatusExt;
        let out = |code: i32, stdout: &str, stderr: &str| Output {
            status: ExitStatus::from_raw(code << 8),
            stdout: stdout.into(),
            stderr: stderr.into(),
        };
        assert_eq!(
            default_keychain(&out(
                0,
                "    \"/Users/a/Library/Keychains/login.keychain-db\"\n",
                ""
            )),
            Ok(PathBuf::from(
                "/Users/a/Library/Keychains/login.keychain-db"
            ))
        );
        assert!(
            default_keychain(&out(0, "", ""))
                .unwrap_err()
                .contains("no default keychain")
        );
        assert!(
            default_keychain(&out(1, "", "SecKeychainCopyDefault: failed"))
                .unwrap_err()
                .contains("SecKeychainCopyDefault: failed")
        );
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

    #[test]
    fn a_long_answer_does_not_stall_the_call() {
        let out = run_for(
            Command::new("/bin/sh").args(["-c", "head -c 300000 /dev/zero"]),
            None,
            Duration::from_secs(10),
        )
        .unwrap();
        assert_eq!(out.stdout.len(), 300_000);
    }

    /// A keychain file in a folder of this test's own. `create-keychain`
    /// adds it to the user's search list; `delete-keychain`, run even when
    /// the test fails, takes it out again.
    #[cfg(target_os = "macos")]
    struct ThrowawayKeychain {
        _dir: tempfile::TempDir,
        file: PathBuf,
    }

    #[cfg(target_os = "macos")]
    impl ThrowawayKeychain {
        fn new() -> ThrowawayKeychain {
            let dir = tempfile::tempdir().unwrap();
            let file = dir.path().join("test.keychain-db");
            let path = file.to_str().unwrap();
            for args in [
                &["create-keychain", "-p", "test", path][..],
                &["unlock-keychain", "-p", "test", path][..],
            ] {
                assert!(
                    Command::new(SECURITY)
                        .args(args)
                        .status()
                        .unwrap()
                        .success()
                );
            }
            ThrowawayKeychain { _dir: dir, file }
        }
    }

    #[cfg(target_os = "macos")]
    impl Drop for ThrowawayKeychain {
        fn drop(&mut self) {
            let _ = Command::new(SECURITY)
                .arg("delete-keychain")
                .arg(&self.file)
                .status();
        }
    }

    /// A locked keychain is told apart at once, with no dialog, by the
    /// same call a service makes before reading its secrets.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_locked_keychain_is_found_without_a_dialog() {
        let keychain = ThrowawayKeychain::new();
        let store = Keychain::new("enclos.test".into(), Some(keychain.file.clone()));
        store.readable().unwrap();
        let file = keychain.file.to_str().unwrap();
        let security = |args: &[&str]| {
            assert!(
                Command::new(SECURITY)
                    .args(args)
                    .status()
                    .unwrap()
                    .success()
            );
        };
        security(&["lock-keychain", file]);
        let asked = std::time::Instant::now();
        let err = store.readable().unwrap_err();
        assert!(
            asked.elapsed() < Duration::from_secs(5),
            "{:?}",
            asked.elapsed()
        );
        assert!(err.untouched);
        assert!(err.what.contains("locked"), "{}", err.what);
        security(&["unlock-keychain", "-p", "test", file]);
        store.readable().unwrap();
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_secret_is_stored_read_replaced_and_removed() {
        let keychain = ThrowawayKeychain::new();
        let store = Keychain::new("enclos.test".into(), Some(keychain.file.clone()));
        let secret: SecretRef = "home/telegram".parse().unwrap();
        assert_eq!(store.get(&secret).unwrap(), None);
        store.set(&secret, &v("123:abc \"é\"")).unwrap();
        assert_eq!(store.get(&secret).unwrap(), Some(v("123:abc \"é\"")));
        store.set(&secret, &v("456")).unwrap();
        assert_eq!(store.get(&secret).unwrap(), Some(v("456")));
        // The longest value one line takes, stored whole.
        let long = v(&"k".repeat(1900));
        store.set(&secret, &long).unwrap();
        assert_eq!(store.get(&secret).unwrap(), Some(long));
        assert!(store.remove(&secret).unwrap());
        assert!(!store.remove(&secret).unwrap());
        assert_eq!(store.get(&secret).unwrap(), None);
        // An item enclos did not store is not taken for a value.
        let raw: SecretRef = "home/raw".parse().unwrap();
        let file = keychain.file.to_str().unwrap();
        assert!(
            Command::new(SECURITY)
                .args([
                    "add-generic-password",
                    "-s",
                    "enclos.test",
                    "-a",
                    "home/raw"
                ])
                .args(["-w", "plain", file])
                .status()
                .unwrap()
                .success()
        );
        let err = store.get(&raw).unwrap_err();
        assert!(err.what.contains("not stored by enclos"), "{err}");
        // A keychain that is not there is refused before anything runs.
        let gone = Keychain::new(
            "enclos.test".into(),
            Some(keychain.file.with_extension("x")),
        );
        let err = gone.set(&secret, &v("x")).unwrap_err();
        assert!(err.what.contains("does not exist"), "{err}");
        // Nor is it taken for one with no item.
        assert!(
            gone.get(&secret)
                .unwrap_err()
                .what
                .contains("does not exist")
        );
        assert!(
            gone.remove(&secret)
                .unwrap_err()
                .what
                .contains("does not exist")
        );
        // A file that is no keychain takes nothing: the read back shows it.
        let plain = keychain.file.with_file_name("plain.txt");
        std::fs::write(&plain, "not a keychain").unwrap();
        let wrong = Keychain::new("enclos.test".into(), Some(plain));
        assert!(wrong.set(&secret, &v("x")).is_err());
        assert!(!matches!(wrong.get(&secret), Ok(Some(_))));
    }
}
