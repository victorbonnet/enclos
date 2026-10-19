use tempfile::TempDir;

use super::*;
use crate::backend::fake::FakeBackend;
use crate::error::Error;
use crate::model::audit::AuditResult;

fn alice() -> Actor {
    Actor {
        user: "alice".into(),
        host: "mac".into(),
    }
}

fn engine_with(backends: Vec<Box<dyn Backend>>) -> (TempDir, Engine) {
    let dir = tempfile::tempdir().unwrap();
    let layout = Layout::at(dir.path().join("enclos"));
    let state = SqliteStateStore::new(layout.state_db(), layout.state_lock());
    let audit = JsonlAuditLog::new(layout.audit_log());
    let engine = Engine::new(layout, Box::new(state), Box::new(audit), backends);
    (dir, engine)
}

fn engine() -> (TempDir, Engine) {
    engine_with(Vec::new())
}

fn done<T>(planned: Planned<T>) -> T {
    match planned {
        Planned::Done(value) => value,
        Planned::DryRun(plan) => panic!("expected a change, got the plan {plan:?}"),
    }
}

#[test]
fn init_creates_the_layout_and_a_finished_audit_entry() {
    let (_dir, engine) = engine();
    let report = done(engine.init(&alice(), Confirm::Ask).unwrap());
    assert_eq!(report.created, engine.layout.paths());
    assert_eq!(report.migration.from, 0);
    assert!(engine.layout.missing().is_empty());

    let entries = engine.audit(None).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].intent.command, "init");
    assert_eq!(entries[0].intent.by, alice());
    let finished = entries[0].finished.as_ref().unwrap();
    assert_eq!(finished.outcome.result, AuditResult::Ok);
    assert_eq!(finished.outcome.message, "created 8 paths");
}

#[test]
fn init_is_idempotent() {
    let (_dir, engine) = engine();
    done(engine.init(&alice(), Confirm::Ask).unwrap());
    let config = std::fs::read_to_string(engine.layout.config_file()).unwrap();

    let again = done(engine.init(&alice(), Confirm::Yes).unwrap());
    assert!(again.created.is_empty());
    assert!(!again.migration.changed());
    assert_eq!(again.summary(), "already initialized; nothing changed");
    let after = std::fs::read_to_string(engine.layout.config_file()).unwrap();
    assert_eq!(config, after);
    assert_eq!(engine.audit(None).unwrap().len(), 2);
    assert!(engine.verify_audit().unwrap().intact());
}

#[test]
fn dry_run_changes_nothing() {
    let (_dir, engine) = engine();
    let planned = engine.init(&alice(), Confirm::DryRun).unwrap();
    assert_eq!(
        planned,
        Planned::DryRun(Plan {
            create: engine.layout.paths(),
            ..Plan::default()
        })
    );
    assert!(!engine.layout.data().exists());
}

#[test]
fn init_records_the_first_available_backend() {
    let (_dir, engine) = engine_with(vec![
        Box::new(FakeBackend::unavailable(
            BackendKind::Libkrun,
            "no VM support",
        )),
        Box::new(FakeBackend::available(BackendKind::Seatbelt)),
    ]);
    let report = done(engine.init(&alice(), Confirm::Ask).unwrap());
    assert_eq!(report.default_backend, Some(BackendKind::Seatbelt));
    let config = std::fs::read_to_string(engine.layout.config_file()).unwrap();
    assert!(
        config.contains("default_backend = \"seatbelt\""),
        "{config}"
    );
}

#[test]
fn a_failed_command_closes_its_audit_entry_as_failed() {
    let (_dir, engine) = engine();
    engine.layout.create_roots().unwrap();
    // A file where a folder must go makes init fail half-way.
    std::fs::write(engine.layout.data().join("runtimes"), "").unwrap();

    let err = engine.init(&alice(), Confirm::Ask).unwrap_err();
    assert!(matches!(err, Error::Layout(_)), "{err}");

    let entries = engine.audit(None).unwrap();
    let finished = entries[0].finished.as_ref().unwrap();
    assert_eq!(finished.outcome.result, AuditResult::Failed);
    assert!(finished.outcome.message.contains("runtimes"));
    assert!(engine.verify_audit().unwrap().unfinished.is_empty());
}

#[test]
fn reads_before_init_say_to_run_init() {
    let (_dir, engine) = engine();
    for err in [
        engine.audit(None).unwrap_err(),
        engine.verify_audit().unwrap_err(),
    ] {
        assert!(err.to_string().contains("enclos init"), "{err}");
        assert_eq!(err.exit_code(), 1);
    }
}

#[test]
fn audit_since_keeps_recent_entries() {
    let (_dir, engine) = engine();
    done(engine.init(&alice(), Confirm::Ask).unwrap());
    let recent = engine.audit(Some("1h".parse().unwrap())).unwrap();
    assert_eq!(recent.len(), 1);
}

mod policy {
    use super::*;
    use crate::model::sandbox::{SandboxName, SandboxRecord, SandboxState};

    /// An initialized engine with sandbox `home` and its first policy, made
    /// the way `sandbox create` will make it.
    fn with_sandbox() -> (TempDir, Engine, SandboxName) {
        let (dir, engine) = engine();
        done(engine.init(&alice(), Confirm::Yes).unwrap());
        let name: SandboxName = "home".parse().unwrap();
        engine
            .write(
                &alice(),
                "sandbox create",
                Some("home".into()),
                |_| String::new(),
                |lock| {
                    engine.state.put(
                        lock,
                        &SandboxRecord {
                            name: name.clone(),
                            backend: BackendKind::Seatbelt,
                            state: SandboxState::Created,
                            created_at: now(),
                        },
                    )?;
                    engine.create_policy(lock, &alice(), &name, &"assistant".parse().unwrap())
                },
            )
            .unwrap();
        (dir, engine, name)
    }

    #[test]
    fn a_new_sandbox_gets_version_1_of_its_template() {
        let (_dir, engine, name) = with_sandbox();
        let view = engine.policy(&name).unwrap();
        assert_eq!(view.version.version, 1);
        assert_eq!(view.snapshot.inputs.template.as_str(), "assistant");
        assert_eq!(view.snapshot.policy.fs.write, ["{home}"]);
        assert!(view.file.exists());
        assert!(engine.layout.sandbox_home("home").is_dir());
    }

    #[test]
    fn allow_adds_a_version_and_an_audit_entry() {
        let (_dir, engine, name) = with_sandbox();
        let applied = done(
            engine
                .policy_allow(&alice(), &name, "API.Example.com", Confirm::Ask)
                .unwrap(),
        );
        assert!(applied.changed);
        assert_eq!(applied.version.version, 2);
        let view = engine.policy(&name).unwrap();
        assert_eq!(view.snapshot.policy.net.allow, ["api.example.com"]);
        assert!(
            std::fs::read_to_string(&view.file)
                .unwrap()
                .contains("\"api.example.com\"")
        );

        // Allowing it again changes nothing.
        let again = done(
            engine
                .policy_allow(&alice(), &name, "api.example.com", Confirm::Ask)
                .unwrap(),
        );
        assert!(!again.changed);
        assert_eq!(engine.state.policy_history(&name).unwrap().len(), 2);

        let entries = engine.audit(None).unwrap();
        let last = entries.last().unwrap();
        assert_eq!(last.intent.command, "policy allow");
        assert_eq!(last.intent.target.as_deref(), Some("home api.example.com"));
    }

    #[test]
    fn unsafe_destinations_are_refused_and_change_nothing() {
        let (_dir, engine, name) = with_sandbox();
        for bad in ["*.com", "localhost", "169.254.169.254"] {
            let err = engine
                .policy_allow(&alice(), &name, bad, Confirm::Ask)
                .unwrap_err();
            assert!(matches!(err, Error::Policy(_)), "{bad}: {err}");
        }
        assert_eq!(engine.policy(&name).unwrap().version.version, 1);
    }

    #[test]
    fn a_dry_run_changes_nothing() {
        let (_dir, engine, name) = with_sandbox();
        let planned = engine
            .policy_allow(&alice(), &name, "api.example.com", Confirm::DryRun)
            .unwrap();
        assert!(
            matches!(planned, Planned::DryRun(ref plan) if plan.changes.len() == 1),
            "{planned:?}"
        );
        assert!(
            engine
                .policy(&name)
                .unwrap()
                .snapshot
                .policy
                .net
                .allow
                .is_empty()
        );
    }

    #[test]
    fn allowing_an_entry_the_file_already_lists_applies_it() {
        let (_dir, engine, name) = with_sandbox();
        let file = engine.layout.policy_file("home");
        let text = std::fs::read_to_string(&file)
            .unwrap()
            .replace("allow_add = []", "allow_add = [\"new.example.com\"]");
        std::fs::write(&file, text).unwrap();
        let applied = done(
            engine
                .policy_allow(&alice(), &name, "new.example.com", Confirm::Ask)
                .unwrap(),
        );
        assert!(applied.changed);
        let view = engine.policy(&name).unwrap();
        assert_eq!(view.version.version, 2);
        assert_eq!(view.snapshot.policy.net.allow, ["new.example.com"]);
    }

    #[test]
    fn a_hand_edit_that_grants_enclos_files_is_refused() {
        let (_dir, engine, name) = with_sandbox();
        let file = engine.layout.policy_file("home");
        let text = std::fs::read_to_string(&file)
            .unwrap()
            .replace("write_add = []", "write_add = [\"~\"]");
        std::fs::write(&file, text).unwrap();
        let err = engine
            .policy_allow(&alice(), &name, "api.example.com", Confirm::Ask)
            .unwrap_err();
        assert!(err.to_string().contains("enclos's own files"), "{err}");
        assert_eq!(engine.policy(&name).unwrap().version.version, 1);
    }

    #[test]
    fn unknown_sandboxes_are_named_in_the_error() {
        let (_dir, engine) = engine();
        done(engine.init(&alice(), Confirm::Yes).unwrap());
        let err = engine.policy(&"nope".parse().unwrap()).unwrap_err();
        assert!(matches!(err, Error::NoSuchSandbox { .. }), "{err}");
    }
}
