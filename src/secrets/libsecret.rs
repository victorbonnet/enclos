//! Secrets in the Secret Service (GNOME Keyring, KWallet) through libsecret's
//! `secret-tool`: items whose attribute `service` names the enclos install
//! and whose `account` is `<sandbox>/<name>`, as in the Keychain.
//!
//! The session bus is the one `DBUS_SESSION_BUS_ADDRESS` names, never a
//! default: with none set, no Secret Service answers and nothing runs.
//!
//! A value goes to `secret-tool` on its input, never as an argument, which
//! other processes could list, and comes back as it went: the tool ends a
//! value with a line break only at a terminal. `secret-tool` fails with
//! words on standard error and finds nothing with none, both exit 1.
//!
//! Nothing here may ask anything: a service has nobody to answer. Reading a
//! locked collection would ask to unlock it, so [`Libsecret::readable`]
//! looks at its `Locked` property, which asks nothing, with `dbus-send`, and
//! every call is ended after a set wait. Whether a Secret Service is unlocked
//! when systemd starts a service at login is to verify (design §14).

use std::process::{Command, Output};
use std::time::Duration;

use super::tool::{run, run_for, stderr};
use super::{Prober, SecretError, SecretStore};
use crate::model::secret::{SecretRef, SecretValue};

const SECRET_TOOL: &str = "/usr/bin/secret-tool";
const DBUS_SEND: &str = "/usr/bin/dbus-send";
/// Names the session bus.
const BUS_VAR: &str = "DBUS_SESSION_BUS_ADDRESS";
/// How long the looks at whether a Secret Service answers and whether it is
/// locked may take: every enclos command that uses a secret waits on the
/// first, and a service on the second.
const LOOK_WAIT: Duration = Duration::from_secs(5);
/// An attribute no item has, so looking for it finds nothing, and so unlocks
/// nothing, whatever the service holds.
const NO_ITEM: [&str; 2] = ["enclos-probe", "answers"];

pub struct Libsecret {
    /// The attribute `service` of every item: `enclos.<install>`.
    service: String,
    bus: Option<String>,
    secret_tool: String,
    dbus_send: String,
}

impl Libsecret {
    pub fn new(service: String, bus: Option<String>) -> Libsecret {
        Libsecret {
            service,
            bus,
            secret_tool: SECRET_TOOL.to_owned(),
            dbus_send: DBUS_SEND.to_owned(),
        }
    }

    /// On the session bus the environment names.
    pub fn from_env(service: String) -> Libsecret {
        let bus = std::env::var(BUS_VAR).ok().filter(|v| !v.is_empty());
        Libsecret::new(service, bus)
    }

    fn fail(&self, what: &str, secret: &SecretRef, why: impl std::fmt::Display) -> SecretError {
        SecretError {
            what: format!("cannot {what} secret {secret} in the Secret Service: {why}"),
            untouched: false,
        }
    }

    /// A call of `program` on the bus the environment named. With none,
    /// there is no call: left to find its own, it would reach a bus nobody
    /// named.
    fn on_bus(&self, program: &str) -> Result<Command, String> {
        let bus = self
            .bus
            .as_ref()
            .ok_or_else(|| format!("no session bus: {BUS_VAR} is not set"))?;
        let mut command = Command::new(program);
        command.env(BUS_VAR, bus);
        Ok(command)
    }

    fn attributes(&self, secret: &SecretRef) -> [String; 4] {
        [
            "service".to_owned(),
            self.service.clone(),
            "account".to_owned(),
            secret.to_string(),
        ]
    }

    fn lookup(&self, secret: &SecretRef) -> Result<Output, String> {
        run(
            self.on_bus(&self.secret_tool)?
                .arg("lookup")
                .args(self.attributes(secret)),
            None,
        )
    }

    /// The collection's `Locked` property, as `dbus-send` printed it.
    fn locked(&self) -> Result<bool, String> {
        let out = run_for(
            self.on_bus(&self.dbus_send)?.args([
                "--session",
                "--print-reply",
                "--reply-timeout=4000",
                "--dest=org.freedesktop.secrets",
                "/org/freedesktop/secrets/aliases/default",
                "org.freedesktop.DBus.Properties.Get",
                "string:org.freedesktop.Secret.Collection",
                "string:Locked",
            ]),
            None,
            LOOK_WAIT,
        )?;
        if !out.status.success() {
            return Err(stderr(&out.stderr, out.status));
        }
        parse_locked(&String::from_utf8_lossy(&out.stdout))
            .ok_or_else(|| "its answer does not say".to_owned())
    }
}

/// Whether what `dbus-send --print-reply` printed says locked.
fn parse_locked(printed: &str) -> Option<bool> {
    match (
        printed.contains("boolean true"),
        printed.contains("boolean false"),
    ) {
        (true, false) => Some(true),
        (false, true) => Some(false),
        _ => None,
    }
}

impl SecretStore for Libsecret {
    fn set(&self, secret: &SecretRef, value: &SecretValue) -> Result<(), SecretError> {
        let mut command = self.on_bus(&self.secret_tool).map_err(|e| SecretError {
            untouched: true,
            ..self.fail("store", secret, e)
        })?;
        command
            .arg("store")
            .arg(format!("--label=enclos secret {secret}"))
            .args(self.attributes(secret));
        let out = run(&mut command, Some(value.expose().as_bytes()))
            .map_err(|e| self.fail("store", secret, e))?;
        if !out.status.success() {
            return Err(self.fail("store", secret, stderr(&out.stderr, out.status)));
        }
        // Only reading the value back shows it was stored whole.
        match self.get(secret)? {
            Some(stored) if stored == *value => Ok(()),
            _ => Err(self.fail("store", secret, "it did not read back the same")),
        }
    }

    fn get(&self, secret: &SecretRef) -> Result<Option<SecretValue>, SecretError> {
        let out = self
            .lookup(secret)
            .map_err(|e| self.fail("read", secret, e))?;
        if !out.status.success() {
            return match out.stderr.is_empty() {
                true => Ok(None),
                false => Err(self.fail("read", secret, stderr(&out.stderr, out.status))),
            };
        }
        let text = String::from_utf8(out.stdout)
            .map_err(|_| self.fail("read", secret, "its value is not text"))?;
        SecretValue::new(text)
            .map(Some)
            .map_err(|e| self.fail("read", secret, e))
    }

    fn remove(&self, secret: &SecretRef) -> Result<bool, SecretError> {
        // `secret-tool clear` exits 0 whether or not it found one.
        let had = self.get(secret)?.is_some();
        let out = run(
            self.on_bus(&self.secret_tool)
                .map_err(|e| self.fail("remove", secret, e))?
                .arg("clear")
                .args(self.attributes(secret)),
            None,
        )
        .map_err(|e| self.fail("remove", secret, e))?;
        match out.status.success() {
            true => Ok(had),
            false => Err(self.fail("remove", secret, stderr(&out.stderr, out.status))),
        }
    }

    fn whereabouts(&self, secret: &SecretRef) -> String {
        format!(
            "the Secret Service item of service {} and account {secret}; remove it with `secret-tool clear service {} account {secret}`",
            self.service, self.service
        )
    }

    fn env(&self) -> Vec<(String, String)> {
        self.bus
            .iter()
            .map(|bus| (BUS_VAR.to_owned(), bus.clone()))
            .collect()
    }

    fn readable(&self) -> Result<(), SecretError> {
        let fail = |why: String| SecretError {
            what: format!("the Secret Service cannot be read without asking: {why}"),
            untouched: true,
        };
        match self.locked() {
            Ok(false) => Ok(()),
            Ok(true) => Err(fail("its default collection is locked".to_owned())),
            Err(e) => Err(fail(format!("cannot tell whether it is locked ({e})"))),
        }
    }
}

impl Prober for Libsecret {
    /// Whether anything answers for the Secret Service: a lookup that finds
    /// nothing says nothing, where one nobody served fails with words. No
    /// bus, no `secret-tool` or no answer in time all count as none.
    fn answers(&self) -> bool {
        let Ok(mut command) = self.on_bus(&self.secret_tool) else {
            return false;
        };
        match run_for(command.arg("lookup").args(NO_ITEM), None, LOOK_WAIT) {
            Ok(out) => out.status.success() || out.stderr.is_empty(),
            Err(_) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    fn v(text: &str) -> SecretValue {
        SecretValue::new(text.to_owned()).unwrap()
    }

    fn secret() -> SecretRef {
        "home/telegram".parse().unwrap()
    }

    /// A stand-in for `secret-tool` and `dbus-send`, in a folder of the
    /// test's own: nothing here reaches any bus, the address being made up.
    struct Stub {
        dir: tempfile::TempDir,
        store: Libsecret,
    }

    impl Stub {
        fn new(secret_tool: &str, dbus_send: &str) -> Stub {
            let dir = tempfile::tempdir().unwrap();
            let script = |name: &str, text: &str| {
                let path = dir.path().join(name);
                std::fs::write(&path, format!("#!/bin/sh\n{text}\n")).unwrap();
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
                path.display().to_string()
            };
            let store = Libsecret {
                service: "enclos.test".to_owned(),
                bus: Some("unix:path=/nowhere/bus".to_owned()),
                secret_tool: script("secret-tool", secret_tool),
                dbus_send: script("dbus-send", dbus_send),
            };
            Stub { dir, store }
        }

        /// A `secret-tool` keeping one value in a file; it records its
        /// arguments and bus, and its value's bytes as it read them.
        fn keeping() -> Stub {
            Stub::new(
                r#"here=$(dirname "$0")
echo "$*" >>"$here/calls"
echo "$DBUS_SESSION_BUS_ADDRESS" >"$here/bus"
case "$1" in
store) cat >"$here/value" ;;
lookup) [ -f "$here/value" ] || exit 1; cat "$here/value" ;;
clear) rm -f "$here/value" ;;
esac"#,
                "exit 1",
            )
        }

        fn file(&self, name: &str) -> String {
            std::fs::read_to_string(self.dir.path().join(name)).unwrap()
        }

        fn exists(&self, name: &str) -> bool {
            Path::exists(&self.dir.path().join(name))
        }
    }

    #[test]
    fn a_secret_is_stored_read_replaced_and_removed() {
        let stub = Stub::keeping();
        let store = &stub.store;
        assert_eq!(store.get(&secret()).unwrap(), None);
        assert!(!store.remove(&secret()).unwrap());
        let value = "123:abc \"é\"\nnext\n";
        store.set(&secret(), &v(value)).unwrap();
        assert_eq!(store.get(&secret()).unwrap(), Some(v(value)));
        store.set(&secret(), &v("456")).unwrap();
        assert_eq!(store.get(&secret()).unwrap(), Some(v("456")));
        assert!(store.remove(&secret()).unwrap());
        assert!(!stub.exists("value"));
    }

    #[test]
    fn a_value_goes_on_the_input_and_never_as_an_argument() {
        let stub = Stub::keeping();
        stub.store.set(&secret(), &v("tok-123")).unwrap();
        assert_eq!(stub.file("value"), "tok-123");
        let calls = stub.file("calls");
        assert!(
            calls.contains(
                "store --label=enclos secret home/telegram service enclos.test account home/telegram"
            ),
            "{calls}"
        );
        assert!(!calls.contains("tok-123"), "{calls}");
    }

    #[test]
    fn every_call_uses_the_bus_the_environment_named() {
        let stub = Stub::keeping();
        stub.store.get(&secret()).unwrap();
        assert_eq!(stub.file("bus").trim(), "unix:path=/nowhere/bus");
    }

    /// With no bus named, nothing runs: not even a look.
    #[test]
    fn no_bus_means_nothing_runs() {
        let mut stub = Stub::keeping();
        stub.store.bus = None;
        assert!(!stub.store.answers());
        assert!(stub.store.get(&secret()).is_err());
        let err = stub.store.set(&secret(), &v("a")).unwrap_err();
        assert!(err.untouched, "{err}");
        assert!(err.what.contains("DBUS_SESSION_BUS_ADDRESS"), "{err}");
        assert!(!stub.exists("calls"));
        assert!(stub.store.env().is_empty());
    }

    #[test]
    fn a_failure_is_not_taken_for_a_secret_with_no_value() {
        let stub = Stub::new("echo 'secret-tool: the service broke' >&2; exit 1", "");
        let err = stub.store.get(&secret()).unwrap_err();
        assert!(err.what.contains("the service broke"), "{err}");
    }

    #[test]
    fn a_value_that_does_not_read_back_the_same_is_not_stored() {
        let stub = Stub::new(
            r#"case "$1" in store) cat >/dev/null ;; lookup) printf other ;; esac"#,
            "",
        );
        let err = stub.store.set(&secret(), &v("a")).unwrap_err();
        assert!(!err.untouched, "{err}");
        assert!(err.what.contains("did not read back"), "{err}");
    }

    #[test]
    fn a_lookup_that_finds_nothing_is_a_service_that_answers() {
        assert!(Stub::new("exit 1", "").store.answers());
    }

    #[test]
    fn a_lookup_failing_with_words_is_no_service() {
        let stub = Stub::new(
            "echo 'secret-tool: The name is not activatable' >&2; exit 1",
            "",
        );
        assert!(!stub.store.answers());
    }

    #[test]
    fn no_secret_tool_is_no_service() {
        let mut stub = Stub::new("", "");
        stub.store.secret_tool = "/nowhere/secret-tool".to_owned();
        assert!(!stub.store.answers());
    }

    #[test]
    fn a_service_that_does_not_answer_in_time_is_no_service() {
        let begun = std::time::Instant::now();
        assert!(!Stub::new("exec sleep 30", "").store.answers());
        assert!(begun.elapsed() < LOOK_WAIT + Duration::from_secs(5));
    }

    #[test]
    fn readable_says_what_the_collection_says() {
        let reply = |value: &str| {
            format!(
                "echo 'method return time=1 sender=:1.3 -> destination=:1.4 serial=9 reply_serial=2'; echo '   variant       boolean {value}'"
            )
        };
        assert!(Stub::new("", &reply("false")).store.readable().is_ok());
        let err = Stub::new("", &reply("true")).store.readable().unwrap_err();
        assert!(err.untouched, "{err}");
        assert!(err.what.contains("locked"), "{err}");
    }

    /// Unable to tell is refused too: reading on would ask.
    #[test]
    fn a_collection_that_cannot_be_looked_at_is_not_readable() {
        let stub = Stub::new("", "echo 'Error: No such object' >&2; exit 1");
        let err = stub.store.readable().unwrap_err();
        assert!(err.what.contains("No such object"), "{err}");
    }

    #[test]
    fn services_reach_the_same_bus() {
        assert_eq!(
            Libsecret::new("enclos.t".into(), Some("unix:path=/b".into())).env(),
            [(BUS_VAR.to_owned(), "unix:path=/b".to_owned())]
        );
    }

    /// Whether to run the tests below, which need a Secret Service, so only
    /// in CI's `libsecret` job, on a private bus with a throwaway keyring:
    /// it sets `ENCLOS_LIBSECRET_TESTS`, and they refuse anywhere else, for
    /// any other bus is a user's real one.
    fn on_a_runner() -> bool {
        if std::env::var("ENCLOS_LIBSECRET_TESTS").as_deref() != Ok("1") {
            eprintln!("libsecret tests not run: CI's libsecret job runs them");
            return false;
        }
        let var = |name: &str| std::env::var(name).unwrap_or_default();
        assert!(
            var("GITHUB_ACTIONS") == "true" && var("RUNNER_ENVIRONMENT") == "github-hosted",
            "these tests write to a Secret Service: they run only on a GitHub-hosted runner"
        );
        true
    }

    fn on_the_runners_bus() -> Libsecret {
        Libsecret::from_env(format!("enclos.ci-{}", std::process::id()))
    }

    #[test]
    fn on_a_runner_a_secret_is_stored_read_replaced_and_removed() {
        if !on_a_runner() {
            return;
        }
        let store = on_the_runners_bus();
        assert!(store.answers());
        store.readable().unwrap();
        assert_eq!(store.get(&secret()).unwrap(), None);
        assert!(!store.remove(&secret()).unwrap());
        // Quotes, accents and line breaks come back as they went.
        let value = "123:abc \"é\"\nnext\n";
        store.set(&secret(), &v(value)).unwrap();
        assert_eq!(store.get(&secret()).unwrap(), Some(v(value)));
        store.set(&secret(), &v("456")).unwrap();
        assert_eq!(store.get(&secret()).unwrap(), Some(v("456")));
        assert!(store.remove(&secret()).unwrap());
        assert_eq!(store.get(&secret()).unwrap(), None);
    }

    /// Run on a bus of its own by CI: a locked collection stays locked.
    #[test]
    fn on_a_runner_a_locked_collection_is_told_without_asking() {
        if !on_a_runner() {
            return;
        }
        let store = on_the_runners_bus();
        store.readable().unwrap();
        let locked = Command::new(DBUS_SEND)
            .args([
                "--session",
                "--print-reply",
                "--dest=org.freedesktop.secrets",
                "/org/freedesktop/secrets",
                "org.freedesktop.Secret.Service.Lock",
                "array:objpath:/org/freedesktop/secrets/collection/login",
            ])
            .status()
            .unwrap();
        assert!(locked.success());
        let begun = std::time::Instant::now();
        let err = store.readable().unwrap_err();
        assert!(begun.elapsed() < LOOK_WAIT, "{:?}", begun.elapsed());
        assert!(err.what.contains("locked"), "{err}");
    }
}
