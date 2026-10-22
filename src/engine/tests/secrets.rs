//! Secrets granted per sandbox (design §12, ADR 0022), with a secret store
//! in memory in place of the Keychain.

use std::rc::Rc;

use super::sandbox::{Sleeping, put, session_of};
use super::*;
use crate::engine::ChangeOutcome;
use crate::model::sandbox::SandboxName;
use crate::model::secret::SecretRef;
use crate::secrets::{InMemory, SecretStore};

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

#[test]
fn a_secret_is_stored_listed_and_removed_and_its_value_goes_nowhere_else() {
    let (_dir, engine, store, name) = with_store();
    let telegram = secret("home/telegram");
    let set = done(
        engine
            .secret_set(&alice(), &telegram, VALUE, Confirm::Ask)
            .unwrap(),
    );
    assert!(set.new && set.granted_as.is_empty(), "{set:?}");
    assert_eq!(store.get(&telegram).unwrap().as_deref(), Some(VALUE));
    let again = done(
        engine
            .secret_set(&alice(), &telegram, "other", Confirm::Ask)
            .unwrap(),
    );
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
    assert!(matches!(err, Error::NoSuchSecret { .. }), "{err}");
}

#[test]
fn a_value_that_is_no_environment_variable_is_refused() {
    let (_dir, engine, _store, _name) = with_store();
    for bad in ["", "a\0b"] {
        assert!(
            engine
                .secret_set(&alice(), &secret("home/telegram"), bad, Confirm::Yes)
                .is_err(),
            "{bad:?}"
        );
    }
    let err = engine
        .secret_set(&alice(), &secret("nope/telegram"), VALUE, Confirm::Yes)
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
    done(
        engine
            .secret_set(&alice(), &secret("lab/telegram"), VALUE, Confirm::Yes)
            .unwrap(),
    );
    let err = grant(&engine, &name, "TOKEN = \"secret:lab/telegram\"").unwrap_err();
    assert_eq!(err.exit_code(), 2, "{err}");
    done(
        engine
            .secret_set(&alice(), &secret("home/telegram"), VALUE, Confirm::Yes)
            .unwrap(),
    );
    let err = grant(&engine, &name, "HOME = \"secret:home/telegram\"").unwrap_err();
    assert_eq!(err.exit_code(), 2, "{err}");
    let applied = grant(&engine, &name, "TOKEN = \"secret:home/telegram\"").unwrap();
    assert!(applied.changed, "{applied:?}");
    assert_eq!(
        applied.also,
        ["give it secret home/telegram as $TOKEN (sessions started from now on)"]
    );
    let view = engine.policy(&name).unwrap();
    assert_eq!(
        view.snapshot.policy.secrets["TOKEN"],
        "secret:home/telegram"
    );
    let listed = engine.secret_list(&name).unwrap();
    assert_eq!(listed[0].granted_as, ["TOKEN"]);
}

#[test]
fn a_grant_while_a_session_runs_waits_for_the_restart() {
    let (_dir, engine, _store, name) = with_store();
    done(
        engine
            .secret_set(&alice(), &secret("home/telegram"), VALUE, Confirm::Yes)
            .unwrap(),
    );
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
    // Granted by the pending policy: it cannot go.
    let err = engine
        .secret_rm(&alice(), &secret("home/telegram"), Confirm::Yes)
        .unwrap_err();
    assert!(matches!(err, Error::SecretGranted { .. }), "{err}");
    drop(sleeping);
}

#[test]
fn a_session_gets_the_values_of_what_its_policy_grants() {
    let (_dir, engine, store, name) = with_store();
    let telegram = secret("home/telegram");
    done(
        engine
            .secret_set(&alice(), &telegram, VALUE, Confirm::Yes)
            .unwrap(),
    );
    grant(&engine, &name, "TOKEN = \"secret:home/telegram\"").unwrap();
    let policy = engine.policy(&name).unwrap().snapshot.policy;
    assert_eq!(
        engine.secret_env(&policy).unwrap(),
        [("TOKEN".to_owned(), VALUE.to_owned())]
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
    done(
        engine
            .secret_set(&alice(), &telegram, VALUE, Confirm::Yes)
            .unwrap(),
    );
    done(
        engine
            .secret_set(&alice(), &lab, VALUE, Confirm::Yes)
            .unwrap(),
    );
    let left = done(
        engine
            .remove_sandbox(&alice(), &name, true, Confirm::Yes)
            .unwrap(),
    );
    assert!(left.is_empty(), "{left:?}");
    assert_eq!(store.get(&telegram).unwrap(), None);
    assert_eq!(store.get(&lab).unwrap().as_deref(), Some(VALUE));
}

#[test]
fn a_dry_run_of_set_stores_nothing() {
    let (_dir, engine, store, _name) = with_store();
    let telegram = secret("home/telegram");
    let planned = engine
        .secret_set(&alice(), &telegram, VALUE, Confirm::DryRun)
        .unwrap();
    assert!(matches!(planned, Planned::DryRun(_)), "{planned:?}");
    assert_eq!(store.get(&telegram).unwrap(), None);
}
