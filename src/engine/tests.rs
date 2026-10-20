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
    use crate::model::sandbox::SandboxName;

    /// An initialized engine with sandbox `home`, created as the CLI does.
    fn with_sandbox() -> (TempDir, Engine, SandboxName) {
        with_sandbox_on(FakeBackend::available(BackendKind::Seatbelt))
    }

    pub(super) fn with_sandbox_on(backend: FakeBackend) -> (TempDir, Engine, SandboxName) {
        let (dir, engine) = engine_with(vec![Box::new(backend)]);
        done(engine.init(&alice(), Confirm::Yes).unwrap());
        let name: SandboxName = "home".parse().unwrap();
        let spec = crate::engine::SandboxSpec {
            name: name.clone(),
            backend: BackendKind::Seatbelt,
            template: "assistant".parse().unwrap(),
        };
        done(engine.create_sandbox(&alice(), spec, Confirm::Yes).unwrap());
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

    /// Rewrites the sandbox's `policy.toml`, as a user editing it would.
    fn edit_policy(engine: &Engine, from: &str, to: &str) {
        let file = engine.layout.policy_file("home");
        let text = std::fs::read_to_string(&file).unwrap();
        assert!(text.contains(from), "{text}");
        std::fs::write(&file, text.replace(from, to)).unwrap();
    }

    #[test]
    fn allowing_with_other_edits_pending_asks_and_names_them() {
        let (dir, engine, name) = with_sandbox();
        std::fs::create_dir(dir.path().join("work")).unwrap();
        let work = dir.path().join("work").display().to_string();
        edit_policy(
            &engine,
            "write_add = []",
            &format!("write_add = [\"{work}\"]"),
        );

        let planned = engine
            .policy_allow(&alice(), &name, "api.example.com", Confirm::DryRun)
            .unwrap();
        let Planned::DryRun(plan) = planned else {
            panic!("{planned:?}")
        };
        assert_eq!(plan.changes.len(), 2, "{plan:?}");
        assert!(plan.changes[1].contains(&work), "{plan:?}");

        let err = engine
            .policy_allow(&alice(), &name, "api.example.com", Confirm::Ask)
            .unwrap_err();
        assert!(matches!(err, Error::NeedsConfirmation { .. }), "{err}");
        assert!(err.to_string().contains(&work), "{err}");
        assert_eq!(engine.policy(&name).unwrap().version.version, 1);

        let applied = done(
            engine
                .policy_allow(&alice(), &name, "api.example.com", Confirm::Yes)
                .unwrap(),
        );
        assert_eq!(applied.version.version, 2);
        assert_eq!(applied.also.len(), 1, "{:?}", applied.also);
        let summary = engine.audit(None).unwrap().pop().unwrap();
        assert!(format!("{summary:?}").contains(&work), "{summary:?}");
    }

    #[test]
    fn a_dry_run_reports_what_the_real_run_would() {
        let (_dir, engine, name) = with_sandbox();
        done(
            engine
                .policy_allow(&alice(), &name, "api.example.com", Confirm::Ask)
                .unwrap(),
        );
        let planned = engine
            .policy_allow(&alice(), &name, "api.example.com", Confirm::DryRun)
            .unwrap();
        assert!(
            matches!(&planned, Planned::DryRun(plan) if plan.changes[0].contains("change nothing")),
            "{planned:?}"
        );
        // A private address without its opt-in is refused by a dry run too.
        let err = engine
            .policy_allow(&alice(), &name, "192.168.1.5", Confirm::DryRun)
            .unwrap_err();
        assert!(matches!(err, Error::Policy(_)), "{err}");
    }

    #[test]
    fn a_failed_file_write_adds_no_version_and_the_retry_applies() {
        use std::os::unix::fs::PermissionsExt;
        let (_dir, engine, name) = with_sandbox();
        let folder = engine
            .layout
            .policy_file("home")
            .parent()
            .unwrap()
            .to_owned();
        let mode = |m| std::fs::set_permissions(&folder, std::fs::Permissions::from_mode(m));
        mode(0o500).unwrap();
        let failed = engine.policy_allow(&alice(), &name, "api.example.com", Confirm::Ask);
        mode(0o700).unwrap();
        assert!(failed.is_err(), "{failed:?}");
        assert_eq!(engine.policy(&name).unwrap().version.version, 1);

        let applied = done(
            engine
                .policy_allow(&alice(), &name, "api.example.com", Confirm::Ask)
                .unwrap(),
        );
        assert!(applied.changed);
        assert_eq!(applied.version.version, 2);
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

mod compile {
    use super::policy::with_sandbox_on;
    use super::*;

    #[test]
    fn the_active_policy_compiles_once_into_the_sandbox_folder() {
        let (_dir, engine, name) = with_sandbox_on(FakeBackend::available(BackendKind::Seatbelt));
        let file = engine.compile_policy(&name, 41001).unwrap();
        assert!(file.starts_with(engine.layout.sandbox_dir("home").join("compiled")));
        assert!(
            std::fs::read_to_string(&file)
                .unwrap()
                .contains("write {home}")
        );
        assert_eq!(engine.compile_policy(&name, 41001).unwrap(), file);
        // A new grant is a new compiled policy.
        done(
            engine
                .policy_allow(&alice(), &name, "api.example.com", Confirm::Yes)
                .unwrap(),
        );
        assert_ne!(engine.compile_policy(&name, 41001).unwrap(), file);
    }

    #[test]
    fn a_cut_off_compiled_policy_is_never_reused() {
        let (_dir, engine, name) = with_sandbox_on(FakeBackend::available(BackendKind::Seatbelt));
        let file = engine.compile_policy(&name, 41001).unwrap();
        let full = std::fs::read_to_string(&file).unwrap();

        // What an interrupted write would have left: a valid start, no end.
        std::fs::write(&file, &full[..full.len() / 2]).unwrap();
        assert_eq!(engine.compile_policy(&name, 41001).unwrap(), file);
        assert_eq!(std::fs::read_to_string(&file).unwrap(), full);

        // A write that fails, here because a folder stands where the file
        // goes (which fails for root too), leaves nothing of the policy, and
        // the retry succeeds.
        std::fs::remove_file(&file).unwrap();
        std::fs::create_dir_all(file.join("in-the-way")).unwrap();
        assert!(engine.compile_policy(&name, 41001).is_err());
        assert!(file.is_dir());
        std::fs::remove_dir_all(&file).unwrap();
        let compiled = file.parent().unwrap();
        assert_eq!(engine.compile_policy(&name, 41001).unwrap(), file);
        assert_eq!(std::fs::read_to_string(&file).unwrap(), full);
        assert_eq!(std::fs::read_dir(compiled).unwrap().count(), 1);
    }

    #[test]
    fn a_backend_this_host_cannot_run_is_refused_and_nothing_is_left() {
        let backend = FakeBackend::unavailable(BackendKind::Seatbelt, "not macOS");
        let (_dir, engine) = engine_with(vec![Box::new(backend)]);
        done(engine.init(&alice(), Confirm::Yes).unwrap());
        let spec = crate::engine::SandboxSpec {
            name: "home".parse().unwrap(),
            backend: BackendKind::Seatbelt,
            template: "assistant".parse().unwrap(),
        };
        let err = engine
            .create_sandbox(&alice(), spec, Confirm::Yes)
            .unwrap_err();
        assert!(matches!(err, Error::BackendUnavailable { .. }), "{err}");
        assert_eq!(err.exit_code(), 2);
        assert!(engine.list_sandboxes().unwrap().is_empty());
    }
}

mod sandbox {
    use super::policy::with_sandbox_on;
    use super::*;
    use crate::engine::SandboxSpec;

    fn spec(name: &str) -> SandboxSpec {
        SandboxSpec {
            name: name.parse().unwrap(),
            backend: BackendKind::Seatbelt,
            template: "assistant".parse().unwrap(),
        }
    }

    #[test]
    fn each_sandbox_gets_its_own_port_and_names_are_unique() {
        let (_dir, engine, _) = with_sandbox_on(FakeBackend::available(BackendKind::Seatbelt));
        let lab = done(
            engine
                .create_sandbox(&alice(), spec("lab"), Confirm::Yes)
                .unwrap(),
        );
        let home = engine
            .show_sandbox(&"home".parse().unwrap())
            .unwrap()
            .record;
        // A port another program listens on is skipped, so only the order is fixed.
        assert!(home.proxy_port >= 41000 && lab.proxy_port > home.proxy_port);
        let err = engine
            .create_sandbox(&alice(), spec("lab"), Confirm::Yes)
            .unwrap_err();
        assert!(matches!(err, Error::SandboxExists { .. }), "{err}");
        assert_eq!(engine.list_sandboxes().unwrap().len(), 2);
    }

    #[test]
    fn removing_asks_first_and_deletes_the_folder() {
        let (_dir, engine, name) = with_sandbox_on(FakeBackend::available(BackendKind::Seatbelt));
        let dir = engine.layout.sandbox_dir("home");
        assert!(dir.join("policy.toml").exists());
        let err = engine
            .remove_sandbox(&alice(), &name, false, Confirm::Ask)
            .unwrap_err();
        assert!(matches!(err, Error::NeedsConfirmation { .. }), "{err}");
        done(
            engine
                .remove_sandbox(&alice(), &name, false, Confirm::Yes)
                .unwrap(),
        );
        assert!(!dir.exists());
        assert!(engine.list_sandboxes().unwrap().is_empty());
    }

    #[test]
    fn dry_runs_of_stop_and_connect_change_nothing() {
        let (_dir, engine, name) = with_sandbox_on(FakeBackend::available(BackendKind::Seatbelt));
        let entries = engine.audit(None).unwrap().len();
        let Planned::DryRun(plan) = engine
            .stop_sandbox(&alice(), &name, Confirm::DryRun)
            .unwrap()
        else {
            panic!("a dry run stopped the sandbox");
        };
        assert_eq!(plan.changes, ["mark sandbox home stopped"]);
        let Planned::DryRun(plan) = engine
            .connect(&alice(), &name, Vec::new(), Confirm::DryRun)
            .unwrap()
        else {
            panic!("a dry run connected");
        };
        assert!(
            plan.changes
                .last()
                .is_some_and(|c| c.starts_with("run `/bin/zsh -l` in sandbox home")),
            "{plan:?}"
        );
        assert_eq!(
            engine.show_sandbox(&name).unwrap().record.state,
            crate::model::sandbox::SandboxState::Created
        );
        assert!(engine.state.sessions(&name, false).unwrap().is_empty());
        assert_eq!(engine.audit(None).unwrap().len(), entries);
    }

    #[test]
    fn stopping_a_sandbox_with_nothing_running_marks_it_stopped() {
        let (_dir, engine, name) = with_sandbox_on(FakeBackend::available(BackendKind::Seatbelt));
        let report = done(engine.stop_sandbox(&alice(), &name, Confirm::Yes).unwrap());
        assert!(report.stopped.is_empty() && report.survivors.is_empty());
        assert_eq!(
            engine.show_sandbox(&name).unwrap().record.state,
            crate::model::sandbox::SandboxState::Stopped
        );
    }
}
