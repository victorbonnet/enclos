//! Secrets granted per sandbox (design §12, ADR 0022), with a secret store
//! in memory in place of the Keychain.

use std::rc::Rc;

use super::sandbox::{Sleeping, put, session_of};
use super::*;
use crate::engine::ChangeOutcome;
use crate::model::sandbox::SandboxName;
use crate::model::secret::{SecretRef, SecretValue};
use crate::secrets::{InMemory, SecretStore, Unavailable};

const VALUE: &str = "123456:telegram-token-value";

fn with_store() -> (TempDir, Engine, Rc<InMemory>, SandboxName) {
    let store = Rc::new(InMemory::default());
    let (dir, engine) = engine_with(vec![Box::new(FakeBackend::available(
        BackendKind::Seatbelt,
    ))]);
    let engine = engine.with_secrets(Box::new(Rc::clone(&store)));
    done(engine.init(&alice(), Confirm::Yes).unwrap());
    let name: SandboxName = "home".parse().unwrap();
    for sandbox in ["home", "lab"] {
        let spec = crate::engine::SandboxSpec {
            name: sandbox.parse().unwrap(),
            backend: BackendKind::Seatbelt,
            template: "assistant".parse().unwrap(),
        };
        done(engine.create_sandbox(&alice(), spec, Confirm::Yes).unwrap());
    }
    (dir, engine, store, name)
}

fn secret(text: &str) -> SecretRef {
    text.parse().unwrap()
}

fn value(text: &str) -> SecretValue {
    SecretValue::new(text.to_owned()).unwrap()
}

/// Sets `secret` to `text`.
fn set(engine: &Engine, secret: &SecretRef, text: &str) -> crate::engine::SecretSet {
    done(
        engine
            .secret_set(&alice(), secret, Some(&value(text)), Confirm::Yes)
            .unwrap(),
    )
}

/// `policy.toml` granting `grants` (`VAR = "secret:..."`), as an edit.
fn grant(
    engine: &Engine,
    name: &SandboxName,
    grants: &str,
) -> Result<crate::engine::PolicyApplied> {
    let before = engine.layout.read_policy(name.as_str()).unwrap();
    let after = format!("{before}\n[secrets]\nenv = {{ {grants} }}\n");
    engine
        .policy_edit(&alice(), name, &before, &after, Confirm::Ask)
        .map(done)
}

/// `policy.toml` as it was before any grant, as an edit.
fn ungrant(engine: &Engine, name: &SandboxName) -> crate::engine::PolicyApplied {
    let before = engine.layout.read_policy(name.as_str()).unwrap();
    let after = before.split("\n[secrets]").next().unwrap().to_owned();
    done(
        engine
            .policy_edit(&alice(), name, &before, &after, Confirm::Yes)
            .unwrap(),
    )
}

#[test]
fn a_secret_is_stored_listed_and_removed_and_its_value_goes_nowhere_else() {
    let (_dir, engine, store, name) = with_store();
    let telegram = secret("home/telegram");
    let first = set(&engine, &telegram, VALUE);
    assert!(first.new && first.granted_as.is_empty(), "{first:?}");
    assert_eq!(store.get(&telegram).unwrap(), Some(value(VALUE)));
    let again = set(&engine, &telegram, "other");
    assert!(!again.new);
    let listed = engine.secret_list(&name).unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].record.secret, telegram);
    assert!(
        engine
            .secret_list(&"lab".parse().unwrap())
            .unwrap()
            .is_empty()
    );

    // Neither the audit log, nor the state, nor policy.toml hold a value.
    for (what, bytes) in [
        (
            "audit.jsonl",
            std::fs::read(engine.layout.audit_log()).unwrap(),
        ),
        ("state.db", std::fs::read(engine.layout.state_db()).unwrap()),
        (
            "policy.toml",
            std::fs::read(engine.layout.policy_file("home")).unwrap(),
        ),
    ] {
        let text = String::from_utf8_lossy(&bytes);
        assert!(
            !text.contains(VALUE) && !text.contains("other"),
            "{what} holds the value"
        );
    }
    let audit = engine.audit(None).unwrap();
    assert_eq!(audit.last().unwrap().intent.command, "secret set");

    let err = engine
        .secret_rm(&alice(), &telegram, Confirm::Ask)
        .unwrap_err();
    assert!(matches!(err, Error::NeedsConfirmation { .. }), "{err}");
    done(engine.secret_rm(&alice(), &telegram, Confirm::Yes).unwrap());
    assert_eq!(store.get(&telegram).unwrap(), None);
    assert!(engine.secret_list(&name).unwrap().is_empty());
    let err = engine
        .secret_rm(&alice(), &telegram, Confirm::Yes)
        .unwrap_err();
    assert!(matches!(err, Error::SecretUnknown { .. }), "{err}");
    assert!(
        err.to_string().contains("`enclos secret list home`"),
        "{err}"
    );
}

#[test]
fn a_set_needs_a_value_and_a_sandbox() {
    let (_dir, engine, store, _name) = with_store();
    let err = engine
        .secret_set(&alice(), &secret("home/telegram"), None, Confirm::Yes)
        .unwrap_err();
    assert!(matches!(err, Error::Session { .. }), "{err}");
    assert!(store.0.borrow().is_empty());
    let err = engine
        .secret_set(
            &alice(),
            &secret("nope/telegram"),
            Some(&value(VALUE)),
            Confirm::Yes,
        )
        .unwrap_err();
    assert!(matches!(err, Error::NoSuchSandbox { .. }), "{err}");
}

#[test]
fn a_policy_grants_only_the_sandboxs_own_secrets_once_they_are_set() {
    let (_dir, engine, _store, name) = with_store();
    let err = grant(&engine, &name, "TOKEN = \"secret:home/telegram\"").unwrap_err();
    assert!(matches!(err, Error::NoSuchSecret { .. }), "{err}");
    assert!(
        err.to_string().contains("enclos secret set home/telegram"),
        "{err}"
    );
    set(&engine, &secret("lab/telegram"), VALUE);
    let err = grant(&engine, &name, "TOKEN = \"secret:lab/telegram\"").unwrap_err();
    assert_eq!(err.exit_code(), 2, "{err}");
    set(&engine, &secret("home/telegram"), VALUE);
    for reserved in ["HOME", "XDG_CONFIG_HOME", "NODE_USE_ENV_PROXY"] {
        let err = grant(
            &engine,
            &name,
            &format!("{reserved} = \"secret:home/telegram\""),
        )
        .unwrap_err();
        assert_eq!(err.exit_code(), 2, "{reserved}: {err}");
    }
    let applied = grant(&engine, &name, "TOKEN = \"secret:home/telegram\"").unwrap();
    assert!(applied.changed, "{applied:?}");
    assert_eq!(
        applied.also,
        ["give it secret home/telegram as $TOKEN (sessions started from now on)"]
    );
    let view = engine.policy(&name).unwrap();
    assert_eq!(
        view.snapshot.policy.secrets["TOKEN"].to_string(),
        "secret:home/telegram"
    );
    let listed = engine.secret_list(&name).unwrap();
    assert_eq!(listed[0].granted_as, ["TOKEN"]);
    // Resolved again, the grant is no change: it is stored as written.
    let refreshed = done(
        engine
            .policy_refresh(&alice(), &name, Confirm::Ask)
            .unwrap(),
    );
    assert!(!refreshed.changed, "{refreshed:?}");
    // Taken out, it says so.
    let removed = ungrant(&engine, &name);
    assert_eq!(
        removed.also,
        ["stop giving it $TOKEN (sessions started from now on)"]
    );
}

#[test]
fn a_rollback_to_a_version_granting_a_removed_secret_is_refused() {
    let (_dir, engine, _store, name) = with_store();
    let telegram = secret("home/telegram");
    set(&engine, &telegram, VALUE);
    let granted = grant(&engine, &name, "TOKEN = \"secret:home/telegram\"").unwrap();
    ungrant(&engine, &name);
    done(engine.secret_rm(&alice(), &telegram, Confirm::Yes).unwrap());
    let before = engine.policy(&name).unwrap().version.version;
    let err = engine
        .policy_rollback(&alice(), &name, granted.version.version, Confirm::Yes)
        .unwrap_err();
    assert!(
        err.to_string().contains("enclos secret set home/telegram"),
        "{err}"
    );
    assert_eq!(engine.policy(&name).unwrap().version.version, before);
}

#[test]
fn a_grant_while_a_session_runs_waits_for_the_restart() {
    let (_dir, engine, _store, name) = with_store();
    let telegram = secret("home/telegram");
    set(&engine, &telegram, VALUE);
    let sleeping = Sleeping::new();
    let mut session = session_of(&engine, &name, sleeping.process());
    session.compiled = Some("/compiled/at-launch.sb".into());
    put(&engine, &session);
    let applied = grant(&engine, &name, "TOKEN = \"secret:home/telegram\"").unwrap();
    assert!(
        matches!(applied.outcome, ChangeOutcome::Pending(_)),
        "{applied:?}"
    );
    let listed = engine.secret_list(&name).unwrap();
    assert!(listed[0].granted_as.is_empty());
    assert_eq!(
        listed[0].pending_as.as_deref(),
        Some(&["TOKEN".to_owned()][..])
    );
    // A new value says the pending policy gives it.
    let again = set(&engine, &telegram, "other");
    assert!(
        again.granted_as.is_empty() && again.running == 0,
        "{again:?}"
    );
    assert_eq!(again.pending_as, ["TOKEN"]);
    // Granted by the pending policy: it cannot go, and discarding that
    // policy is one way out.
    let err = engine
        .secret_rm(&alice(), &telegram, Confirm::Yes)
        .unwrap_err();
    assert!(matches!(err, Error::SecretGranted { .. }), "{err}");
    assert!(
        err.to_string().contains("enclos policy discard home"),
        "{err}"
    );
    drop(sleeping);
}

#[test]
fn a_new_value_counts_the_sessions_keeping_the_old_one() {
    let (_dir, engine, _store, name) = with_store();
    let telegram = secret("home/telegram");
    set(&engine, &telegram, VALUE);
    grant(&engine, &name, "TOKEN = \"secret:home/telegram\"").unwrap();
    let sleeping = Sleeping::new();
    let mut session = session_of(&engine, &name, sleeping.process());
    session.compiled = Some("/compiled/at-launch.sb".into());
    put(&engine, &session);
    let again = set(&engine, &telegram, "other");
    assert!(!again.new, "{again:?}");
    assert_eq!(again.granted_as, ["TOKEN"]);
    assert_eq!(again.running, 1);
    let err = engine
        .secret_rm(&alice(), &telegram, Confirm::Yes)
        .unwrap_err();
    assert!(err.to_string().contains("$TOKEN"), "{err}");
    assert!(err.to_string().contains("enclos policy edit home"), "{err}");
    drop(sleeping);
}

#[test]
fn a_session_gets_the_values_of_what_its_policy_grants() {
    let (_dir, engine, store, name) = with_store();
    let telegram = secret("home/telegram");
    set(&engine, &telegram, VALUE);
    grant(&engine, &name, "TOKEN = \"secret:home/telegram\"").unwrap();
    let policy = engine.policy(&name).unwrap().snapshot.policy;
    assert_eq!(
        engine.secret_env(&policy).unwrap(),
        [("TOKEN".to_owned(), value(VALUE))]
    );
    // Gone from the store but still granted: the session does not start.
    store.remove(&telegram).unwrap();
    let err = engine.secret_env(&policy).unwrap_err();
    assert!(matches!(err, Error::SecretMissing { .. }), "{err}");
    assert!(err.to_string().contains("$TOKEN"), "{err}");
    let err = engine
        .secret_rm(&alice(), &telegram, Confirm::Yes)
        .unwrap_err();
    assert!(matches!(err, Error::SecretGranted { .. }), "{err}");
}

#[test]
fn a_removed_sandbox_takes_its_secrets_with_it() {
    let (_dir, engine, store, name) = with_store();
    let telegram = secret("home/telegram");
    let lab = secret("lab/telegram");
    set(&engine, &telegram, VALUE);
    set(&engine, &lab, VALUE);
    // Its secrets go even with its data kept: that is asked first.
    let err = engine
        .remove_sandbox(&alice(), &name, true, Confirm::Ask)
        .unwrap_err();
    assert!(err.to_string().contains("1 secret(s)"), "{err}");
    let Planned::DryRun(plan) = engine
        .remove_sandbox(&alice(), &name, true, Confirm::DryRun)
        .unwrap()
    else {
        panic!("a dry run removed the sandbox");
    };
    assert!(
        plan.changes
            .contains(&"remove its 1 secret(s) from the secret store".to_owned()),
        "{plan:?}"
    );
    let left = done(
        engine
            .remove_sandbox(&alice(), &name, true, Confirm::Yes)
            .unwrap(),
    );
    assert!(left.is_empty(), "{left:?}");
    assert_eq!(store.get(&telegram).unwrap(), None);
    assert_eq!(store.get(&lab).unwrap(), Some(value(VALUE)));
}

#[test]
fn a_removed_sandbox_says_which_secrets_stay_when_the_store_fails() {
    let (dir, engine, _store, name) = with_store();
    set(&engine, &secret("home/telegram"), VALUE);
    let engine = engine.with_secrets(Box::new(Unavailable {
        why: "the store is away".to_owned(),
    }));
    let left = done(
        engine
            .remove_sandbox(&alice(), &name, false, Confirm::Yes)
            .unwrap(),
    );
    assert_eq!(left.len(), 1, "{left:?}");
    assert_eq!(left[0].secret, secret("home/telegram"));
    assert!(left[0].why.contains("the store is away"), "{left:?}");
    let summary = engine
        .audit(None)
        .unwrap()
        .into_iter()
        .rfind(|e| e.intent.command == "sandbox rm")
        .and_then(|e| e.finished)
        .unwrap()
        .outcome
        .message;
    assert!(
        summary.contains("could not remove from the secret store: home/telegram"),
        "{summary}"
    );
    // A sandbox made again under the name has no secret of the old one.
    let spec = crate::engine::SandboxSpec {
        name: name.clone(),
        backend: BackendKind::Seatbelt,
        template: "assistant".parse().unwrap(),
    };
    done(engine.create_sandbox(&alice(), spec, Confirm::Yes).unwrap());
    assert!(engine.secret_list(&name).unwrap().is_empty());
    drop(dir);
}

#[test]
fn a_dry_run_of_set_stores_nothing() {
    let (_dir, engine, store, _name) = with_store();
    let telegram = secret("home/telegram");
    let planned = engine
        .secret_set(&alice(), &telegram, None, Confirm::DryRun)
        .unwrap();
    assert!(matches!(planned, Planned::DryRun(_)), "{planned:?}");
    assert_eq!(store.get(&telegram).unwrap(), None);
}
