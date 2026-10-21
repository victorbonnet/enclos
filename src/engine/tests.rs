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
    use crate::lifecycle::process::reference;
    use crate::model::sandbox::{SandboxRecord, SandboxState};
    use crate::model::session::{ProcessRef, SessionId, SessionKind, SessionRecord};

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
        // A port another program listens on is skipped (other tests run
        // proxies in the same range), so which port each gets is not fixed:
        // only that each has its own, in the range.
        let range = crate::model::sandbox::PORT_FIRST..=crate::model::sandbox::PORT_LAST;
        assert!(range.contains(&home.proxy_port) && range.contains(&lab.proxy_port));
        assert_ne!(home.proxy_port, lab.proxy_port);
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

    /// Runs `work` while another command holds the state lock: `work`
    /// passes its checks and waits, then `meanwhile` changes the state
    /// before the lock is released.
    fn while_waiting<T>(
        engine: &Engine,
        work: impl FnOnce() -> T,
        meanwhile: impl FnOnce(&Engine, &crate::state::StateLock) + Send,
    ) -> T {
        let layout = engine.layout.clone();
        let (held, wait) = std::sync::mpsc::channel();
        std::thread::scope(|scope| {
            scope.spawn(move || {
                let other = Engine::open(layout);
                let lock = other.state.lock().unwrap();
                held.send(()).unwrap();
                std::thread::sleep(std::time::Duration::from_millis(300));
                meanwhile(&other, &lock);
            });
            wait.recv().unwrap();
            work()
        })
    }

    #[test]
    fn a_create_that_waited_for_the_lock_checks_the_name_again() {
        let (_dir, engine, _) = with_sandbox_on(FakeBackend::available(BackendKind::Seatbelt));
        let first = SandboxRecord {
            name: "lab".parse().unwrap(),
            backend: BackendKind::Seatbelt,
            template: "assistant".parse().unwrap(),
            state: SandboxState::Created,
            proxy_port: 1,
            runtime: None,
            created_at: crate::model::now(),
        };
        let err = while_waiting(
            &engine,
            || engine.create_sandbox(&alice(), spec("lab"), Confirm::Yes),
            |other, lock| other.state.put(lock, &first).unwrap(),
        )
        .unwrap_err();
        assert!(matches!(err, Error::SandboxExists { .. }), "{err}");
        let lab = engine.state.get(&first.name).unwrap().unwrap();
        assert_eq!(lab.proxy_port, 1);
    }

    #[test]
    fn a_remove_that_waited_for_the_lock_checks_for_sessions_again() {
        let (_dir, engine, name) = with_sandbox_on(FakeBackend::available(BackendKind::Seatbelt));
        let session = SessionRecord {
            id: SessionId(0),
            sandbox: name.clone(),
            kind: SessionKind::Interactive,
            version: 1,
            snapshot: engine.policy(&name).unwrap().snapshot.id,
            compiled: None,
            // Matches no process: this test never stops it.
            root: ProcessRef {
                pid: u32::MAX,
                started: "never".into(),
            },
            pgid: None,
            tracked: Vec::new(),
            started_at: crate::model::now(),
            ended_at: None,
        };
        let err = while_waiting(
            &engine,
            || engine.remove_sandbox(&alice(), &name, false, Confirm::Yes),
            |other, lock| {
                other.state.put_session(lock, &session).unwrap();
            },
        )
        .unwrap_err();
        assert!(matches!(err, Error::SandboxRunning { .. }), "{err}");
        assert!(engine.layout.sandbox_home("home").is_dir());
    }

    #[test]
    fn a_create_with_an_unknown_template_leaves_nothing() {
        let (_dir, engine, _) = with_sandbox_on(FakeBackend::available(BackendKind::Seatbelt));
        let mut bad = spec("lab");
        bad.template = "does-not-exist".parse().unwrap();
        engine
            .create_sandbox(&alice(), bad, Confirm::Yes)
            .unwrap_err();
        assert!(!engine.layout.sandbox_dir("lab").exists());
        assert_eq!(engine.list_sandboxes().unwrap().len(), 1);
        done(
            engine
                .create_sandbox(&alice(), spec("lab"), Confirm::Yes)
                .unwrap(),
        );
    }

    #[test]
    fn a_failed_create_keeps_a_folder_kept_by_remove() {
        let (_dir, engine, name) = with_sandbox_on(FakeBackend::available(BackendKind::Seatbelt));
        done(
            engine
                .remove_sandbox(&alice(), &name, true, Confirm::Yes)
                .unwrap(),
        );
        let home = engine.layout.sandbox_home("home");
        std::fs::write(home.join("notes"), "kept").unwrap();
        let mut bad = spec("home");
        bad.template = "does-not-exist".parse().unwrap();
        engine
            .create_sandbox(&alice(), bad, Confirm::Yes)
            .unwrap_err();
        assert_eq!(std::fs::read_to_string(home.join("notes")).unwrap(), "kept");
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
    fn dry_runs_of_create_and_rm_change_nothing() {
        let (_dir, engine, name) = with_sandbox_on(FakeBackend::available(BackendKind::Seatbelt));
        let entries = engine.audit(None).unwrap().len();
        let Planned::DryRun(_) = engine
            .create_sandbox(&alice(), spec("lab"), Confirm::DryRun)
            .unwrap()
        else {
            panic!("a dry run created a sandbox");
        };
        let Planned::DryRun(_) = engine
            .remove_sandbox(&alice(), &name, false, Confirm::DryRun)
            .unwrap()
        else {
            panic!("a dry run removed a sandbox");
        };
        assert!(!engine.layout.sandbox_dir("lab").exists());
        assert!(engine.layout.sandbox_home("home").is_dir());
        assert_eq!(engine.list_sandboxes().unwrap().len(), 1);
        assert_eq!(engine.audit(None).unwrap().len(), entries);
    }

    #[test]
    fn members_a_stop_cannot_end_fail_the_sandbox_until_they_are_gone() {
        use std::io::Write;
        use std::os::unix::process::CommandExt;
        let (_dir, engine, name) = with_sandbox_on(FakeBackend::available(BackendKind::Seatbelt));
        // A program in a group made for it, which leaves a sleep there and
        // exits once its input closes: the sleep is only counted.
        let mut program = std::process::Command::new("/bin/sh")
            .args(["-c", "/bin/sleep 30 & read line"])
            .stdin(std::process::Stdio::piped())
            .process_group(0)
            .spawn()
            .unwrap();
        let session = SessionRecord {
            id: SessionId(0),
            sandbox: name.clone(),
            kind: SessionKind::Interactive,
            version: 1,
            snapshot: engine.policy(&name).unwrap().snapshot.id,
            compiled: None,
            root: reference(program.id()).unwrap().unwrap(),
            pgid: Some(program.id()),
            tracked: Vec::new(),
            started_at: crate::model::now(),
            ended_at: None,
        };
        let lock = engine.state.lock().unwrap();
        let id = engine.state.put_session(&lock, &session).unwrap();
        drop(lock);
        let start = std::time::Instant::now();
        let sleep = loop {
            let view = engine.show_sandbox(&name).unwrap();
            if let Some(m) = view.sessions[0]
                .members
                .iter()
                .find(|m| m.pid != program.id())
            {
                break m.clone();
            }
            assert!(start.elapsed() < std::time::Duration::from_secs(5));
            std::thread::sleep(std::time::Duration::from_millis(50));
        };
        program.stdin.take().unwrap().write_all(b"\n").unwrap();
        program.wait().unwrap();

        let report = done(engine.stop_sandbox(&alice(), &name, Confirm::Yes).unwrap());
        assert!(report.stopped.is_empty());
        let survivors = &report.survivors;
        assert_eq!(survivors.len(), 1);
        assert_eq!(survivors[0].0, id);
        assert_eq!(survivors[0].1[0].member, sleep);
        assert_eq!(
            survivors[0].1[0].why,
            crate::lifecycle::stop::Why::NotSignalled
        );
        assert!(matches!(
            engine.show_sandbox(&name).unwrap().record.state,
            SandboxState::Failed { .. }
        ));
        let err = engine
            .remove_sandbox(&alice(), &name, false, Confirm::Yes)
            .unwrap_err();
        assert!(matches!(err, Error::SandboxNotStopped { .. }), "{err}");

        // Once the user ends it, stop finds the session empty and ends it.
        let sleep = ProcessRef {
            pid: sleep.pid,
            started: sleep.started,
        };
        crate::lifecycle::process::signal_process(&sleep, crate::lifecycle::process::Signal::Kill)
            .unwrap();
        let start = std::time::Instant::now();
        while crate::lifecycle::process::is_same(&sleep).unwrap() {
            assert!(start.elapsed() < std::time::Duration::from_secs(5));
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        let report = done(engine.stop_sandbox(&alice(), &name, Confirm::Yes).unwrap());
        assert_eq!(report.stopped, [id]);
        assert_eq!(
            engine.show_sandbox(&name).unwrap().record.state,
            SandboxState::Stopped
        );
        done(
            engine
                .remove_sandbox(&alice(), &name, false, Confirm::Yes)
                .unwrap(),
        );
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

mod runtime {
    use super::policy::with_sandbox_on;
    use super::*;
    use crate::model::agent::{AgentName, AgentRecord};
    use crate::model::runtime::RuntimeKind;
    use crate::runtime::RuntimeAgentName;
    #[cfg(target_os = "macos")]
    use crate::runtime::{
        HomeFile, Installer, RuntimeAdapter, SandboxCommand, Unreadable, hermes::Hermes,
    };
    #[cfg(target_os = "macos")]
    use std::os::unix::fs::PermissionsExt;
    #[cfg(target_os = "macos")]
    use std::path::{Path, PathBuf};

    #[test]
    fn an_installed_runtime_adds_its_endpoints_as_a_new_policy_version() {
        let (_dir, engine, name) = with_sandbox_on(FakeBackend::available(BackendKind::Seatbelt));
        engine
            .write(
                &alice(),
                "test",
                None,
                |_| String::new(),
                |lock| {
                    let mut record = engine.state.get(&name)?.unwrap();
                    record.runtime = Some(RuntimeKind::Hermes);
                    engine.state.put(lock, &record)?;
                    let overrides = engine.layout.read_policy("home")?;
                    engine.save_policy(lock, &alice(), &name, &overrides)
                },
            )
            .unwrap();
        let view = engine.policy(&name).unwrap();
        assert_eq!(view.version.version, 2);
        assert!(
            view.snapshot
                .policy
                .net
                .allow
                .contains(&"chatgpt.com".to_owned())
        );
        assert_eq!(
            view.snapshot.inputs.adapter.as_ref().unwrap().runtime,
            "hermes"
        );
        // The adapter adds destinations and nothing else.
        let first = engine.state.policy_history(&name).unwrap()[0].clone();
        assert_eq!(first.version, 1);
        assert_eq!(view.snapshot.policy.fs.write, ["{home}"]);
        assert!(
            view.snapshot
                .policy
                .fs
                .read_deny
                .iter()
                .any(|p| p == "~/.ssh")
        );
    }

    #[test]
    fn saving_the_active_policy_again_adds_no_version() {
        let (_dir, engine, name) = with_sandbox_on(FakeBackend::available(BackendKind::Seatbelt));
        for _ in 0..2 {
            engine
                .write(
                    &alice(),
                    "test",
                    None,
                    |_| String::new(),
                    |lock| {
                        let overrides = engine.layout.read_policy("home")?;
                        engine.save_policy(lock, &alice(), &name, &overrides)
                    },
                )
                .unwrap();
        }
        assert_eq!(engine.policy(&name).unwrap().version.version, 1);
        assert_eq!(engine.state.policy_history(&name).unwrap().len(), 1);
    }

    #[test]
    fn agents_need_a_runtime_first() {
        let (_dir, engine, name) = with_sandbox_on(FakeBackend::available(BackendKind::Seatbelt));
        let err = engine.agents(&name).unwrap_err();
        assert!(err.to_string().contains("no runtime yet"), "{err}");
        assert!(
            err.to_string()
                .contains("enclos runtime install hermes --sandbox home"),
            "{err}"
        );
    }

    #[cfg(target_os = "macos")]
    /// Hermes's adapter with an installer of the test's own, read from a
    /// file; `sha256` is its real hash unless the test says otherwise.
    struct TestRuntime {
        installer: PathBuf,
        sha256: String,
    }

    #[cfg(target_os = "macos")]
    impl TestRuntime {
        fn new(dir: &Path, script: &str) -> TestRuntime {
            let installer = dir.join("install.sh");
            std::fs::write(&installer, script).unwrap();
            let digest = <sha2::Sha256 as sha2::Digest>::digest(script.as_bytes());
            let sha256 = digest.iter().map(|b| format!("{b:02x}")).collect();
            TestRuntime { installer, sha256 }
        }
    }

    #[cfg(target_os = "macos")]
    impl RuntimeAdapter for TestRuntime {
        fn kind(&self) -> RuntimeKind {
            RuntimeKind::Hermes
        }
        fn version(&self) -> &'static str {
            Hermes.version()
        }
        fn endpoints(&self) -> &'static str {
            Hermes.endpoints()
        }
        fn installer(&self) -> Installer {
            Installer {
                url: format!("file://{}", self.installer.display()),
                sha256: self.sha256.clone(),
                args: vec!["--non-interactive".into()],
            }
        }
        fn home_files(&self) -> Vec<HomeFile> {
            Hermes.home_files()
        }
        fn login(&self) -> String {
            Hermes.login()
        }
        fn create_agent(&self, name: &AgentName) -> SandboxCommand {
            Hermes.create_agent(name)
        }
        fn agent_files(&self, name: &AgentName) -> String {
            Hermes.agent_files(name)
        }
        fn talk(&self, agent: &AgentName) -> String {
            Hermes.talk(agent)
        }
        fn services(&self) -> Vec<crate::runtime::RuntimeService> {
            Hermes.services()
        }
        fn agents_in(&self, home: &Path) -> std::result::Result<Vec<RuntimeAgentName>, Unreadable> {
            Hermes.agents_in(home)
        }
    }

    #[cfg(target_os = "macos")]
    /// An installer that puts a `hermes` stub on the sandbox's PATH, which
    /// records its calls in the home and fails while `hermes-fails` exists.
    const INSTALLS: &str = "#!/bin/sh
mkdir -p \"$HOME/.local/bin\"
cat > \"$HOME/.local/bin/hermes\" <<'STUB'
#!/bin/sh
printf '%s\\n' \"$*\" >> \"$HOME/hermes-calls\"
[ -f \"$HOME/hermes-fails\" ] && exit 3
if [ \"$1 $2\" = \"profile delete\" ] && [ ! -f \"$HOME/hermes-keeps\" ]; then
  rm -rf \"$HOME/.hermes/profiles/$3\"
fi
[ \"$2\" = import ] && cat \"$3\" > \"$HOME/imported-$5\"
exit 0
STUB
chmod 700 \"$HOME/.local/bin/hermes\"
echo \"installed $*\" > \"$HOME/installed\"
";

    #[cfg(target_os = "macos")]
    /// Engine tests start real proxies on this host's ports: one at a time.
    static HOST_PORTS: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[cfg(target_os = "macos")]
    /// A sandbox whose proxy is a listener this test stands in (`nc`), so
    /// that sessions can run through the fake backend; stopped when dropped,
    /// so the listener never outlives the test.
    struct Lab {
        _dir: TempDir,
        engine: Engine,
        name: SandboxName,
        home: PathBuf,
    }

    #[cfg(target_os = "macos")]
    impl Lab {
        fn new() -> Lab {
            Lab::with_services(None)
        }

        /// A lab whose engine installs services through `services`.
        fn with_services(services: Option<Box<dyn crate::service::ServiceManager>>) -> Lab {
            let (dir, engine, name) =
                with_sandbox_on(FakeBackend::available(BackendKind::Seatbelt));
            let engine = match services {
                Some(services) => engine.with_services(services),
                None => engine,
            };
            let proxy = dir.path().join("proxy.sh");
            std::fs::write(
                &proxy,
                "#!/bin/sh\nexec /usr/bin/nc -lk 127.0.0.1 \"${5#*:}\"\n",
            )
            .unwrap();
            std::fs::set_permissions(&proxy, std::fs::Permissions::from_mode(0o700)).unwrap();
            let home = engine.layout.sandbox_home("home");
            Lab {
                _dir: dir,
                engine: engine.with_exe(proxy),
                name,
                home,
            }
        }

        fn install(&self, script: &str, confirm: Confirm) -> Result<Planned<InstallEnd>> {
            let runtime = TestRuntime::new(self._dir.path(), script);
            self.engine
                .install_runtime_with(&alice(), &self.name, &runtime, confirm)
        }

        fn runtime(&self) -> Option<RuntimeKind> {
            self.engine.state.get(&self.name).unwrap().unwrap().runtime
        }

        fn allows(&self, host: &str) -> bool {
            self.engine
                .policy(&self.name)
                .unwrap()
                .snapshot
                .policy
                .net
                .allow
                .contains(&host.to_owned())
        }

        fn audit(&self) -> String {
            self.engine
                .audit(None)
                .unwrap()
                .iter()
                .map(|e| format!("{} {:?}", e.intent.command, e.finished))
                .collect::<Vec<_>>()
                .join("\n")
        }

        /// The summary of the last finished audit entry for `command`.
        fn summary(&self, command: &str) -> String {
            self.engine
                .audit(None)
                .unwrap()
                .into_iter()
                .rfind(|e| e.intent.command == command)
                .and_then(|e| e.finished)
                .map(|f| f.outcome.message)
                .unwrap_or_else(|| panic!("no finished {command} entry"))
        }
    }

    #[cfg(target_os = "macos")]
    impl Drop for Lab {
        fn drop(&mut self) {
            let _ = self.engine.stop_sandbox(&alice(), &self.name, Confirm::Yes);
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_dry_run_of_an_install_says_what_it_would_change_and_changes_nothing() {
        let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
        let lab = Lab::new();
        let entries = lab.engine.audit(None).unwrap().len();
        let Planned::DryRun(plan) = lab.install(INSTALLS, Confirm::DryRun).unwrap() else {
            panic!("a dry run installed");
        };
        let plan = plan.changes.join("\n");
        assert!(
            plan.contains("allow the 13 destinations hermes needs"),
            "{plan}"
        );
        assert!(
            plan.contains("download the hermes installer from file://"),
            "{plan}"
        );
        assert!(plan.contains("start the proxy"), "{plan}");
        assert_eq!(lab.engine.audit(None).unwrap().len(), entries);
        assert_eq!(lab.runtime(), None);
        assert_eq!(lab.engine.policy(&lab.name).unwrap().version.version, 1);
        assert!(!lab.home.join("bin/mktemp").exists());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_changed_installer_is_refused_before_anything_changes() {
        let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
        let lab = Lab::new();
        let mut runtime = TestRuntime::new(lab._dir.path(), INSTALLS);
        runtime.sha256 = "0".repeat(64);
        let err = lab
            .engine
            .install_runtime_with(&alice(), &lab.name, &runtime, Confirm::Yes)
            .unwrap_err();
        let text = err.to_string();
        assert!(
            text.contains("changed") && text.contains(&"0".repeat(64)),
            "{text}"
        );
        assert_eq!(lab.runtime(), None);
        assert!(!lab.allows("chatgpt.com"));
        assert_eq!(lab.engine.policy(&lab.name).unwrap().version.version, 1);
        let installers = lab.engine.layout.sandbox_dir("home").join("installers");
        assert!(!installers.join("hermes-install.sh").exists());
        assert!(
            std::fs::read_dir(&installers)
                .unwrap()
                .all(|e| { !e.unwrap().file_name().to_string_lossy().ends_with(".part") })
        );
        assert!(!lab.audit().contains("runtime install"), "{}", lab.audit());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn an_installer_that_fails_leaves_the_sandbox_as_before() {
        let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
        let lab = Lab::new();
        let end = done(lab.install("#!/bin/sh\nexit 3\n", Confirm::Yes).unwrap());
        assert!(!end.installed);
        assert_eq!(end.recorded, None);
        assert_eq!(end.end.exit, 3);
        assert_eq!(lab.runtime(), None);
        assert!(!lab.allows("chatgpt.com"));
        // The destinations came and went: two versions, back to the first's content.
        let history = lab.engine.state.policy_history(&lab.name).unwrap();
        assert_eq!(history.len(), 3);
        assert_eq!(end.policy, 3);
        let audit = lab.audit();
        assert!(audit.contains("runtime install failed"), "{audit}");
        assert!(!audit.contains("runtime installed"), "{audit}");
        assert_eq!(
            lab.summary("runtime install failed"),
            "the installer exited with 3; policy v3 without hermes's destinations"
        );
        // The home file was put in place from inside the sandbox before.
        assert!(lab.home.join("bin/mktemp").is_file());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_reinstall_that_fails_keeps_the_runtime_and_its_destinations() {
        let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
        let lab = Lab::new();
        assert!(done(lab.install(INSTALLS, Confirm::Yes).unwrap()).installed);
        let before = lab.engine.policy(&lab.name).unwrap();
        assert_eq!(before.version.version, 2);

        let end = done(lab.install("#!/bin/sh\nexit 3\n", Confirm::Yes).unwrap());
        assert!(!end.installed);
        assert_eq!(end.recorded, Some(RuntimeKind::Hermes));
        assert_eq!(end.end.exit, 3);
        // The sandbox is as before the reinstall: the runtime still
        // recorded, and the same active policy, which allows its endpoints.
        assert_eq!(lab.runtime(), Some(RuntimeKind::Hermes));
        assert!(lab.allows("chatgpt.com"));
        assert!(lab.allows("github.com"));
        let after = lab.engine.policy(&lab.name).unwrap();
        assert_eq!(end.policy, 2);
        assert_eq!(after.version.version, 2);
        assert_eq!(after.snapshot.id, before.snapshot.id);
        assert_eq!(lab.engine.state.policy_history(&lab.name).unwrap().len(), 2);
        assert_eq!(
            lab.summary("runtime install failed"),
            "the installer exited with 3; hermes still recorded as installed, under policy v2"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn an_install_records_the_runtime_once_its_installer_exits_0_and_agents_follow() {
        let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
        let lab = Lab::new();
        let end = done(lab.install(INSTALLS, Confirm::Yes).unwrap());
        assert!(end.installed);
        assert_eq!(end.policy, 2);
        assert_eq!(lab.runtime(), Some(RuntimeKind::Hermes));
        assert!(lab.allows("chatgpt.com") && lab.allows("github.com"));
        assert_eq!(
            std::fs::read_to_string(lab.home.join("installed")).unwrap(),
            "installed --non-interactive\n"
        );
        let mode = std::fs::metadata(lab.home.join("bin/mktemp"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o700);
        assert!(lab.audit().contains("runtime installed"), "{}", lab.audit());

        // A second install of the same runtime is allowed, another refused.
        let main: AgentName = "main".parse().unwrap();
        let Planned::DryRun(plan) = lab
            .engine
            .add_agent(&alice(), &lab.name, main.clone(), Confirm::DryRun)
            .unwrap()
        else {
            panic!("a dry run added");
        };
        assert_eq!(
            plan.changes,
            [
                "run `hermes profile create main` in sandbox home under policy v2",
                "record agent home/main"
            ]
        );
        assert!(!lab.home.join("hermes-calls").exists());

        let added = done(
            lab.engine
                .add_agent(&alice(), &lab.name, main.clone(), Confirm::Yes)
                .unwrap(),
        );
        assert_eq!(added.agent.name, main);
        let Added::Created(end) = &added.how else {
            panic!("adopted: {added:?}");
        };
        assert_eq!(end.exit, 0);
        assert_eq!(
            std::fs::read_to_string(lab.home.join("hermes-calls")).unwrap(),
            "profile create main\n"
        );
        assert_eq!(lab.engine.agents(&lab.name).unwrap().len(), 1);
        // Twice is refused before the runtime runs again.
        let err = lab
            .engine
            .add_agent(&alice(), &lab.name, main.clone(), Confirm::Yes)
            .unwrap_err();
        assert!(err.to_string().contains("already has agent main"), "{err}");
        assert_eq!(
            std::fs::read_to_string(lab.home.join("hermes-calls")).unwrap(),
            "profile create main\n"
        );
        // A name that is a command on the sandbox's PATH is refused.
        let err = lab
            .engine
            .add_agent(&alice(), &lab.name, "curl".parse().unwrap(), Confirm::Yes)
            .unwrap_err();
        assert!(
            err.to_string().contains("command on the sandbox's PATH"),
            "{err}"
        );
        let err = lab
            .engine
            .add_agent(&alice(), &lab.name, "hermes".parse().unwrap(), Confirm::Yes)
            .unwrap_err();
        assert!(err.to_string().contains(".local/bin/hermes"), "{err}");

        // The runtime failing leaves no record, and says how to recover.
        std::fs::write(lab.home.join("hermes-fails"), "").unwrap();
        let err = lab
            .engine
            .add_agent(&alice(), &lab.name, "other".parse().unwrap(), Confirm::Yes)
            .unwrap_err();
        let text = err.to_string();
        assert!(
            text.contains("exit 3") && text.contains("~/.hermes/profiles/other"),
            "{text}"
        );
        assert_eq!(lab.engine.agents(&lab.name).unwrap().len(), 1);

        // The stub made no profile folder: nothing for Hermes to delete.
        let Planned::DryRun(plan) = lab
            .engine
            .remove_agent(&alice(), &lab.name, &main, false, Confirm::DryRun)
            .unwrap()
        else {
            panic!("a dry run removed");
        };
        assert_eq!(
            plan.changes,
            ["remove the record of agent home/main, which Hermes no longer has"]
        );
        assert_eq!(lab.engine.agents(&lab.name).unwrap().len(), 1);
        let removed = done(
            lab.engine
                .remove_agent(&alice(), &lab.name, &main, false, Confirm::Yes)
                .unwrap(),
        );
        assert_eq!(
            removed,
            AgentRemoved::RecordOnly {
                kind: RuntimeKind::Hermes,
                files: "~/.hermes/profiles/main".into(),
                why: FilesKept::RuntimeLacksIt,
            }
        );
        assert!(lab.engine.agents(&lab.name).unwrap().is_empty());
        let err = lab
            .engine
            .remove_agent(&alice(), &lab.name, &main, false, Confirm::Yes)
            .unwrap_err();
        assert!(err.to_string().contains("has no agent `main`"), "{err}");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn removing_an_agent_runs_the_runtimes_delete_then_removes_the_record() {
        let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
        let lab = Lab::new();
        assert!(done(lab.install(INSTALLS, Confirm::Yes).unwrap()).installed);
        let profile = |a: &str| {
            let dir = lab.home.join(".hermes/profiles").join(a);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("config.yaml"), "").unwrap();
            dir
        };
        let calls = || std::fs::read_to_string(lab.home.join("hermes-calls")).unwrap();
        for a in ["main", "kept", "broken"] {
            profile(a);
            done(
                lab.engine
                    .add_agent(&alice(), &lab.name, a.parse().unwrap(), Confirm::Yes)
                    .unwrap(),
            );
        }
        let main: AgentName = "main".parse().unwrap();

        // It asks first, and the dry run says what would go.
        let err = lab
            .engine
            .remove_agent(&alice(), &lab.name, &main, false, Confirm::Ask)
            .unwrap_err();
        assert!(matches!(err, Error::NeedsConfirmation { .. }), "{err}");
        let Planned::DryRun(plan) = lab
            .engine
            .remove_agent(&alice(), &lab.name, &main, false, Confirm::DryRun)
            .unwrap()
        else {
            panic!("a dry run removed");
        };
        assert_eq!(
            plan.changes,
            ["delete agent home/main and its files, with Hermes's own command"]
        );

        let removed = done(
            lab.engine
                .remove_agent(&alice(), &lab.name, &main, false, Confirm::Yes)
                .unwrap(),
        );
        assert_eq!(
            removed,
            AgentRemoved::Deleted {
                kind: RuntimeKind::Hermes
            }
        );
        assert!(
            calls().ends_with("profile delete main --yes\n"),
            "{}",
            calls()
        );
        assert!(!lab.home.join(".hermes/profiles/main").exists());
        let names: Vec<String> = lab
            .engine
            .agents(&lab.name)
            .unwrap()
            .iter()
            .map(|a| a.name.to_string())
            .collect();
        assert_eq!(names, ["broken", "kept"]);
        let audit = lab.audit();
        assert!(audit.contains("agent rm run"), "{audit}");
        assert!(audit.contains("deleted"), "{audit}");

        // Hermes failing leaves the record, and says how it ended.
        std::fs::write(lab.home.join("hermes-fails"), "").unwrap();
        let err = lab
            .engine
            .remove_agent(
                &alice(),
                &lab.name,
                &"broken".parse().unwrap(),
                false,
                Confirm::Yes,
            )
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("exited with 3") && err.contains("its record stays"),
            "{err}"
        );
        std::fs::remove_file(lab.home.join("hermes-fails")).unwrap();

        // Hermes saying it deleted an agent it still lists leaves the record.
        std::fs::write(lab.home.join("hermes-keeps"), "").unwrap();
        let err = lab
            .engine
            .remove_agent(
                &alice(),
                &lab.name,
                &"kept".parse().unwrap(),
                false,
                Confirm::Yes,
            )
            .unwrap_err()
            .to_string();
        assert!(err.contains("still lists it"), "{err}");
        assert_eq!(lab.engine.agents(&lab.name).unwrap().len(), 2);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn an_agent_is_imported_with_the_runtime_s_own_import_and_its_archive_recorded() {
        use sha2::{Digest, Sha256};
        let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
        let lab = Lab::new();
        done(lab.install(INSTALLS, Confirm::Yes).unwrap());
        // Larger than one read of the hashing buffer.
        let bytes: Vec<u8> = (0..200 * 1024).map(|i| (i % 251) as u8).collect();
        let archive = lab._dir.path().join("main-20261020.tar.gz");
        std::fs::write(&archive, &bytes).unwrap();
        let sha256 = crate::engine::runtime::hex(&Sha256::digest(&bytes));
        let installers = lab.engine.layout.sandbox_dir("home").join("installers");
        let staged = installers.join(format!("agent-main.{}.tar.gz", std::process::id()));
        let planned = installers.join("agent-main.<pid>.tar.gz");
        let copies = || {
            std::fs::read_dir(&installers)
                .unwrap()
                .filter(|e| {
                    e.as_ref()
                        .unwrap()
                        .file_name()
                        .to_string_lossy()
                        .starts_with("agent-")
                })
                .count()
        };
        let main: AgentName = "main".parse().unwrap();

        // A dry run says what would happen and copies nothing.
        let Planned::DryRun(plan) = lab
            .engine
            .import_agent(&alice(), &lab.name, main.clone(), &archive, Confirm::DryRun)
            .unwrap()
        else {
            panic!("a dry run imported");
        };
        assert_eq!(
            plan.changes,
            [
                format!(
                    "copy {} (sha256 {sha256} now) to a new file such as {}, beside the home of sandbox home, where the sandbox reads it and cannot write",
                    archive.display(),
                    planned.display()
                ),
                format!(
                    "run `hermes profile import {} --name main` in sandbox home under policy v2: Hermes extracts the archive inside the sandbox",
                    planned.display()
                ),
                "record agent home/main as imported from that archive".to_owned(),
            ]
        );
        assert_eq!(copies(), 0);
        assert!(!lab.home.join("hermes-calls").exists());

        // The runtime imports the staged copy inside the sandbox: the bytes
        // it reads are the archive's, and the copy goes once it served. The
        // archive and its hash are audited before the runtime runs, and
        // again with the record.
        let added = done(
            lab.engine
                .import_agent(&alice(), &lab.name, main.clone(), &archive, Confirm::Yes)
                .unwrap(),
        );
        assert_eq!(added.agent.name, main);
        let Added::Imported {
            end,
            archive: imported,
            copy_left,
        } = &added.how
        else {
            panic!("not imported: {:?}", added.how);
        };
        assert_eq!(end.exit, 0);
        assert_eq!(
            (imported.path.as_path(), imported.sha256.as_str()),
            (archive.as_path(), sha256.as_str())
        );
        assert!(copy_left.is_none());
        assert_eq!(
            std::fs::read_to_string(lab.home.join("hermes-calls")).unwrap(),
            format!("profile import {} --name main\n", staged.display())
        );
        assert_eq!(
            std::fs::read(lab.home.join("imported-main")).unwrap(),
            bytes
        );
        assert!(!staged.exists());
        assert_eq!(lab.engine.agents(&lab.name).unwrap().len(), 1);
        // Read afresh each time: the audit log grows below.
        let outcome = |command: &str| {
            lab.engine
                .audit(None)
                .unwrap()
                .iter()
                .filter(|e| e.intent.command == command)
                .map(|e| e.finished.as_ref().unwrap().outcome.message.clone())
                .collect::<Vec<_>>()
        };
        assert_eq!(
            outcome("agent import"),
            [format!(
                "copied {} (sha256 {sha256}) to {}",
                archive.display(),
                staged.display()
            )]
        );
        assert_eq!(outcome("agent import session").len(), 1);
        assert_eq!(
            outcome("agent add"),
            [format!(
                "imported from {} (sha256 {sha256})",
                archive.display()
            )]
        );
        // In that order: the copy is audited before the runtime runs.
        let commands: Vec<String> = lab
            .engine
            .audit(None)
            .unwrap()
            .into_iter()
            .map(|e| e.intent.command)
            .filter(|c| c.starts_with("agent "))
            .collect();
        assert_eq!(
            commands,
            ["agent import", "agent import session", "agent add"]
        );

        // Refused before the archive is read: a known name, and a name that
        // is a command on the sandbox's PATH.
        let err = lab
            .engine
            .import_agent(&alice(), &lab.name, main.clone(), &archive, Confirm::Yes)
            .unwrap_err();
        assert!(err.to_string().contains("already has agent main"), "{err}");
        let missing = lab._dir.path().join("missing.tar.gz");
        let err = lab
            .engine
            .import_agent(
                &alice(),
                &lab.name,
                "curl".parse().unwrap(),
                &missing,
                Confirm::Yes,
            )
            .unwrap_err();
        assert!(
            err.to_string().contains("command on the sandbox's PATH"),
            "{err}"
        );

        // An archive that is not a plain file of the user's own is refused.
        let other: AgentName = "other".parse().unwrap();
        let refused = |path: &Path, what: &str| {
            let err = lab
                .engine
                .import_agent(&alice(), &lab.name, other.clone(), path, Confirm::Yes)
                .unwrap_err();
            assert!(err.to_string().contains(what), "{what}: {err}");
        };
        refused(&missing, "missing.tar.gz");
        refused(&missing, "Name an export");
        refused(lab._dir.path(), "is not a file");
        let link = lab._dir.path().join("link.tar.gz");
        std::os::unix::fs::symlink(&archive, &link).unwrap();
        refused(&link, "is a link");
        let inside = lab.home.join("export.tar.gz");
        std::fs::write(&inside, &bytes).unwrap();
        refused(&inside, "under a sandbox's folder");
        // Also through a link in a parent folder, and through `..`: only
        // where the opened file really is counts.
        let linked = lab._dir.path().join("exports");
        std::os::unix::fs::symlink(&lab.home, &linked).unwrap();
        refused(&linked.join("export.tar.gz"), "under a sandbox's folder");
        let sandboxes = lab.engine.layout.sandboxes_dir();
        refused(
            &sandboxes.join("../sandboxes/home/home/export.tar.gz"),
            "under a sandbox's folder",
        );
        assert_eq!(
            std::fs::read_to_string(lab.home.join("hermes-calls")).unwrap(),
            format!("profile import {} --name main\n", staged.display())
        );

        // A failing import records nothing, leaves no copy, and says how
        // to delete what the runtime may have kept.
        std::fs::write(lab.home.join("hermes-fails"), "").unwrap();
        let err = lab
            .engine
            .import_agent(&alice(), &lab.name, other.clone(), &archive, Confirm::Yes)
            .unwrap_err();
        let text = err.to_string();
        assert!(
            text.contains("exit 3")
                && text.contains("enclos agent list home")
                && text.contains("hermes profile delete other --yes"),
            "{text}"
        );
        assert_eq!(copies(), 0);
        assert_eq!(lab.engine.agents(&lab.name).unwrap().len(), 1);
        // The copy is audited again, with its hash; no record is.
        let copied = outcome("agent import");
        assert_eq!(copied.len(), 2);
        assert!(
            copied[1].contains(&format!("(sha256 {sha256})")),
            "{copied:?}"
        );
        assert_eq!(outcome("agent add").len(), 1);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn an_install_with_unapplied_policy_edits_asks_first() {
        let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
        let lab = Lab::new();
        let file = lab.engine.layout.policy_file("home");
        let edited = std::fs::read_to_string(&file)
            .unwrap()
            .replace("allow_add = []", "allow_add = [\"example.com\"]");
        std::fs::write(&file, edited).unwrap();
        let err = lab.install(INSTALLS, Confirm::Ask).unwrap_err();
        assert!(matches!(err, Error::NeedsConfirmation { .. }), "{err}");
        assert!(err.to_string().contains("allow example.com"), "{err}");
        assert_eq!(lab.runtime(), None);
        let Planned::DryRun(plan) = lab.install(INSTALLS, Confirm::DryRun).unwrap() else {
            panic!("a dry run installed");
        };
        assert!(
            plan.changes.iter().any(|c| c == "also allow example.com"),
            "{plan:?}"
        );
        // Said yes: both apply.
        let end = done(lab.install(INSTALLS, Confirm::Yes).unwrap());
        assert!(end.installed);
        assert!(lab.allows("example.com") && lab.allows("chatgpt.com"));
    }

    /// A sandbox with Hermes recorded as its runtime, and a way to make a
    /// Hermes profile in its home as `hermes profile create` would.
    fn with_hermes() -> (TempDir, Engine, SandboxName, impl Fn(&str)) {
        let (dir, engine, name) = with_sandbox_on(FakeBackend::available(BackendKind::Seatbelt));
        engine
            .write(
                &alice(),
                "test",
                None,
                |_| String::new(),
                |lock| {
                    let mut record = engine.state.get(&name)?.unwrap();
                    record.runtime = Some(RuntimeKind::Hermes);
                    engine.state.put(lock, &record)?;
                    Ok(())
                },
            )
            .unwrap();
        let profiles = engine.sandbox_home(&name).join(".hermes/profiles");
        let make = move |agent: &str| {
            std::fs::create_dir_all(profiles.join(agent)).unwrap();
            std::fs::write(profiles.join(agent).join("config.yaml"), "").unwrap();
        };
        (dir, engine, name, make)
    }

    fn compared(check: AgentCheck) -> AgentDiff {
        match check {
            AgentCheck::Compared(diff) => diff,
            AgentCheck::Unreadable(why) => panic!("unreadable: {why}"),
        }
    }

    fn agent(name: &str) -> AgentName {
        name.parse().unwrap()
    }

    #[test]
    fn an_agent_made_inside_the_sandbox_is_reported_then_adopted() {
        let (_dir, engine, name, make) = with_hermes();
        make("scout");
        make("my_bot");
        let diff = compared(engine.check_agents(&name).unwrap());
        assert_eq!(diff.untracked, [agent("scout")]);
        assert_eq!(diff.untrackable, [RuntimeAgentName::new("my_bot").unwrap()]);
        assert!(diff.missing.is_empty());
        let err = engine
            .remove_agent(&alice(), &name, &agent("scout"), false, Confirm::Yes)
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("enclos does not track agent `scout`, which Hermes has"),
            "{err}"
        );
        assert!(
            err.to_string().contains("or remove it with Hermes's own"),
            "{err}"
        );

        // The alias Hermes made for it is on the sandbox's PATH, which does
        // not count as a command the agent would shadow.
        let bin = engine.sandbox_home(&name).join(".local/bin");
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::write(bin.join("scout"), "#!/bin/sh\n").unwrap();
        let audited = engine.audit(None).unwrap().len();
        let Planned::DryRun(plan) = engine
            .add_agent(&alice(), &name, agent("scout"), Confirm::DryRun)
            .unwrap()
        else {
            panic!("a dry run adopted");
        };
        assert_eq!(
            plan.changes,
            ["record agent home/scout, which Hermes already has in the sandbox"]
        );
        assert!(engine.agents(&name).unwrap().is_empty());
        assert_eq!(engine.audit(None).unwrap().len(), audited);

        let added = done(
            engine
                .add_agent(&alice(), &name, agent("scout"), Confirm::Yes)
                .unwrap(),
        );
        assert_eq!(added.how, Added::Adopted);
        assert_eq!(added.agent.name, agent("scout"));
        assert!(
            compared(engine.check_agents(&name).unwrap())
                .untracked
                .is_empty()
        );
        // Adopting runs nothing in the sandbox: one audit entry, the record's,
        // and no session (the fake backend could not have run one anyway).
        let entries = engine.audit(None).unwrap();
        assert_eq!(entries.len(), audited + 1);
        let last = entries.last().unwrap();
        assert_eq!(last.intent.command, "agent add");
        assert_eq!(last.intent.target.as_deref(), Some("home/scout"));
        let outcome = &last.finished.as_ref().unwrap().outcome;
        assert_eq!(outcome.result, AuditResult::Ok);
        assert_eq!(outcome.message, "adopted");
        assert!(engine.show_sandbox(&name).unwrap().sessions.is_empty());
    }

    #[test]
    fn an_import_is_refused_before_anything_runs_and_a_dry_run_copies_nothing() {
        let (dir, engine, name, make) = with_hermes();
        make("scout");
        let archive = dir.path().join("scout.tar.gz");
        std::fs::write(&archive, b"an export").unwrap();
        // Refused before anything runs: the fake backend would fail.
        let err = engine
            .import_agent(
                &alice(),
                &name,
                "scout".parse().unwrap(),
                &archive,
                Confirm::Yes,
            )
            .unwrap_err();
        let text = err.to_string();
        assert!(
            text.contains("needs a fresh name") && text.contains("enclos agent add home/scout"),
            "{text}"
        );
        let err = engine
            .import_agent(
                &alice(),
                &name,
                "default".parse().unwrap(),
                &archive,
                Confirm::Yes,
            )
            .unwrap_err();
        assert!(err.to_string().contains("built-in agent"), "{err}");
        // A dry run of a fresh name copies nothing and makes no folder.
        let Planned::DryRun(plan) = engine
            .import_agent(
                &alice(),
                &name,
                "fresh".parse().unwrap(),
                &archive,
                Confirm::DryRun,
            )
            .unwrap()
        else {
            panic!("a dry run imported");
        };
        assert!(
            plan.changes[0].starts_with(&format!("copy {} (sha256 ", archive.display())),
            "{plan:?}"
        );
        assert_eq!(
            plan.changes[2],
            "record agent home/fresh as imported from that archive"
        );
        assert!(engine.agents(&name).unwrap().is_empty());
        assert!(
            !engine
                .layout
                .sandbox_dir("home")
                .join("installers")
                .exists()
        );
    }

    #[test]
    fn an_import_preserves_the_exit_code_when_the_backend_is_unavailable() {
        let (dir, mut engine, name, _make) = with_hermes();
        engine.backends = vec![Box::new(FakeBackend::unavailable(
            BackendKind::Seatbelt,
            "this host cannot run the backend",
        ))];
        let archive = dir.path().join("fresh.tar.gz");
        std::fs::write(&archive, b"an export").unwrap();
        let err = engine
            .import_agent(&alice(), &name, agent("fresh"), &archive, Confirm::Yes)
            .unwrap_err();
        assert_eq!(err.exit_code(), crate::error::exit::REFUSED, "{err}");
        let text = err.to_string();
        assert!(
            text.contains("this host cannot run the backend")
                && text.contains("did not finish")
                && text.contains("Nothing was recorded")
                && text.contains("enclos agent add home/fresh"),
            "{text}"
        );
        assert!(engine.agents(&name).unwrap().is_empty());
        let installers = engine.layout.sandbox_dir("home").join("installers");
        assert_eq!(std::fs::read_dir(installers).unwrap().count(), 0);
    }

    #[test]
    fn an_import_whose_session_fails_records_nothing_and_leaves_no_copy() {
        let (dir, engine, name, _make) = with_hermes();
        let archive = dir.path().join("fresh.tar.gz");
        std::fs::write(&archive, b"an export").unwrap();
        // The fake backend cannot start a session: the copy is made and
        // audited, then the session fails.
        let err = engine
            .import_agent(&alice(), &name, agent("fresh"), &archive, Confirm::Yes)
            .unwrap_err();
        let text = err.to_string();
        assert!(
            text.contains("did not finish")
                && text.contains("Nothing was recorded")
                && text.contains("enclos agent add home/fresh"),
            "{text}"
        );
        assert!(engine.agents(&name).unwrap().is_empty());
        let installers = engine.layout.sandbox_dir("home").join("installers");
        assert_eq!(std::fs::read_dir(&installers).unwrap().count(), 0);
        let entries = engine.audit(None).unwrap();
        let copied: Vec<_> = entries
            .iter()
            .filter(|e| e.intent.command == "agent import")
            .collect();
        assert_eq!(copied.len(), 1);
        let outcome = &copied[0].finished.as_ref().unwrap().outcome;
        assert_eq!(outcome.result, AuditResult::Ok);
        assert!(
            outcome.message.contains(&archive.display().to_string())
                && outcome.message.contains("(sha256 "),
            "{}",
            outcome.message
        );
        assert!(!entries.iter().any(|e| e.intent.command == "agent add"));
    }

    #[test]
    fn an_import_is_refused_when_the_runtimes_agents_cannot_be_read() {
        let (dir, engine, name, _make) = with_hermes();
        // Something in the sandbox replaced ~/.hermes with a link.
        let home = engine.sandbox_home(&name);
        std::os::unix::fs::symlink(dir.path(), home.join(".hermes")).unwrap();
        let archive = dir.path().join("fresh.tar.gz");
        std::fs::write(&archive, b"an export").unwrap();
        let err = engine
            .import_agent(&alice(), &name, agent("fresh"), &archive, Confirm::Yes)
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("cannot tell whether agent fresh is already there"),
            "{err}"
        );
        assert!(
            !engine
                .layout
                .sandbox_dir("home")
                .join("installers")
                .exists()
        );
    }

    #[test]
    fn an_agent_deleted_inside_the_sandbox_is_reported_missing() {
        let (_dir, engine, name, make) = with_hermes();
        make("scout");
        make("ranger");
        for a in ["scout", "ranger"] {
            done(
                engine
                    .add_agent(&alice(), &name, agent(a), Confirm::Yes)
                    .unwrap(),
            );
        }
        let profiles = engine.sandbox_home(&name).join(".hermes/profiles");
        // As `hermes profile delete` does: a tombstone, the folder kept.
        std::fs::create_dir_all(profiles.join(".deleted/scout")).unwrap();
        std::fs::remove_dir_all(profiles.join("ranger")).unwrap();
        let diff = compared(engine.check_agents(&name).unwrap());
        assert_eq!(diff.missing, [agent("ranger"), agent("scout")]);
        assert!(diff.untracked.is_empty());
        // Nothing left to delete: removing them takes only the record, and
        // runs nothing in the sandbox (the fake backend would fail).
        for a in ["scout", "ranger"] {
            done(
                engine
                    .remove_agent(&alice(), &name, &agent(a), false, Confirm::Yes)
                    .unwrap(),
            );
        }
        assert!(engine.agents(&name).unwrap().is_empty());
    }

    #[test]
    fn removing_an_agent_with_its_files_asks_first() {
        let (_dir, engine, name, make) = with_hermes();
        make("scout");
        done(
            engine
                .add_agent(&alice(), &name, agent("scout"), Confirm::Yes)
                .unwrap(),
        );
        let scout = agent("scout");
        let err = engine
            .remove_agent(&alice(), &name, &scout, false, Confirm::Ask)
            .unwrap_err();
        assert!(matches!(err, Error::NeedsConfirmation { .. }), "{err}");
        let Planned::DryRun(plan) = engine
            .remove_agent(&alice(), &name, &scout, false, Confirm::DryRun)
            .unwrap()
        else {
            panic!("a dry run plans");
        };
        assert_eq!(
            plan.changes,
            ["delete agent home/scout and its files, with Hermes's own command"]
        );
        // `--keep-data` needs no confirmation and leaves the files.
        done(
            engine
                .remove_agent(&alice(), &name, &scout, true, Confirm::Ask)
                .unwrap(),
        );
        assert!(engine.agents(&name).unwrap().is_empty());
        assert!(
            engine
                .sandbox_home(&name)
                .join(".hermes/profiles/scout")
                .exists()
        );
    }

    #[test]
    fn a_linked_hermes_folder_is_reported_unreadable_and_agent_add_refuses_to_guess() {
        let (_dir, engine, name, make) = with_hermes();
        make("scout");
        done(
            engine
                .add_agent(&alice(), &name, agent("scout"), Confirm::Yes)
                .unwrap(),
        );
        let hermes = engine.sandbox_home(&name).join(".hermes");
        let kept = engine.sandbox_home(&name).join("hermes-kept");
        std::fs::rename(&hermes, &kept).unwrap();
        std::os::unix::fs::symlink(&kept, &hermes).unwrap();
        let AgentCheck::Unreadable(why) = engine.check_agents(&name).unwrap() else {
            panic!("compared through a link");
        };
        assert_eq!(why.to_string(), "~/.hermes is a link");
        let audited = engine.audit(None).unwrap().len();
        let err = engine
            .add_agent(&alice(), &name, agent("ranger"), Confirm::Yes)
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("cannot read Hermes's agents in sandbox home (~/.hermes is a link)"),
            "{err}"
        );
        assert_eq!(engine.audit(None).unwrap().len(), audited);
        let err = engine
            .remove_agent(&alice(), &name, &agent("ranger"), false, Confirm::Yes)
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("has no agent `ranger`, and enclos cannot read"),
            "{err}"
        );
        // Deleting a tracked agent's files would need the list; the record
        // alone can still go, since it is enclos's.
        let err = engine
            .remove_agent(&alice(), &name, &agent("scout"), false, Confirm::Yes)
            .unwrap_err();
        assert!(
            err.to_string().contains("cannot read Hermes's agents")
                && err.to_string().contains("--keep-data"),
            "{err}"
        );
        done(
            engine
                .remove_agent(&alice(), &name, &agent("scout"), true, Confirm::Yes)
                .unwrap(),
        );
        assert!(engine.agents(&name).unwrap().is_empty());
    }

    #[test]
    fn the_check_compares_names_both_ways() {
        let tracked = |n: &str| AgentRecord {
            name: n.parse().unwrap(),
            created_at: "2026-01-02T03:04:05Z".parse().unwrap(),
        };
        let names = |names: &[&str]| -> Vec<RuntimeAgentName> {
            names
                .iter()
                .map(|n| RuntimeAgentName::new(n).unwrap())
                .collect()
        };
        let found = names(&["main", "scout", "a"]);
        let diff = AgentDiff::compare(&found, &[tracked("main"), tracked("gone")], None);
        assert_eq!(diff.untracked, [agent("scout")]);
        assert_eq!(diff.untrackable, [RuntimeAgentName::new("a").unwrap()]);
        assert_eq!(diff.missing, [agent("gone")]);
        assert!(!diff.is_clean());
        assert!(AgentDiff::compare(&found[..1], &[tracked("main")], None).is_clean());
        // A runtime that lists its built-in agent: never untracked.
        let both = names(&["main", "default"]);
        let default = crate::runtime::BuiltinAgent::new("default");
        assert!(AgentDiff::compare(&both, &[tracked("main")], Some(default)).is_clean());
    }

    #[cfg(target_os = "macos")]
    /// An installer whose `hermes gateway run` starts a second process and
    /// waits, writing both pids to `gateway-pids` in the home.
    const GATEWAY: &str = "#!/bin/sh
mkdir -p \"$HOME/.local/bin\"
cat > \"$HOME/.local/bin/hermes\" <<'STUB'
#!/bin/sh
[ \"$1\" = gateway ] || exit 0
/bin/sleep 600 &
printf '%s\\n%s\\n' $! $$ > \"$HOME/gateway-pids.part\"
mv \"$HOME/gateway-pids.part\" \"$HOME/gateway-pids\"
exec /bin/sleep 600
STUB
chmod 700 \"$HOME/.local/bin/hermes\"
";

    #[cfg(target_os = "macos")]
    /// An installer whose `hermes gateway run` starts a second process,
    /// writes both pids to `gateway-pids` in the home, and exits 0 a moment
    /// later, leaving the second running.
    const LEAVES: &str = "#!/bin/sh
mkdir -p \"$HOME/.local/bin\"
cat > \"$HOME/.local/bin/hermes\" <<'STUB'
#!/bin/sh
[ \"$1\" = gateway ] || exit 0
/bin/sleep 600 &
printf '%s\\n%s\\n' $! $$ > \"$HOME/gateway-pids.part\"
mv \"$HOME/gateway-pids.part\" \"$HOME/gateway-pids\"
/bin/sleep 1
exit 0
STUB
chmod 700 \"$HOME/.local/bin/hermes\"
";

    #[cfg(target_os = "macos")]
    fn pids_in(file: &Path) -> Vec<u32> {
        std::fs::read_to_string(file)
            .unwrap()
            .lines()
            .map(|l| l.parse().unwrap())
            .collect()
    }

    #[cfg(target_os = "macos")]
    fn assert_gone(pids: &[u32]) {
        for pid in pids {
            let running = crate::lifecycle::process::reference(*pid).unwrap();
            assert!(running.is_none(), "pid {pid} still runs");
        }
    }

    #[cfg(target_os = "macos")]
    fn open_service_sessions(lab: &Lab) -> Vec<crate::model::session::SessionRecord> {
        lab.engine
            .state
            .sessions(&lab.name, true)
            .unwrap()
            .into_iter()
            .filter(|s| s.kind == crate::model::session::SessionKind::Service)
            .collect()
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_runtime_service_told_to_end_stops_its_runtime_and_records_the_end() {
        use std::time::{Duration, Instant};

        let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
        let _term = crate::engine::service::TERM_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let lab = Lab::new();
        assert!(done(lab.install(GATEWAY, Confirm::Yes).unwrap()).installed);
        let pids_file = lab.home.join("gateway-pids");
        // TERM to this process, as the service manager's stop sends it to
        // `enclos launch`, once the runtime runs: `launch` must catch it,
        // not die of it.
        let teller = {
            let pids_file = pids_file.clone();
            std::thread::spawn(move || {
                let start = Instant::now();
                while !pids_file.exists() {
                    assert!(
                        start.elapsed() < Duration::from_secs(30),
                        "the stub gateway did not start"
                    );
                    std::thread::sleep(Duration::from_millis(50));
                }
                signal_hook::low_level::raise(signal_hook::consts::SIGTERM).unwrap();
            })
        };
        let end = lab.engine.launch(&alice(), &lab.name, "gateway").unwrap();
        teller.join().unwrap();
        // TERM ends `sleep` within the first grace period: KILL would show
        // as signal 9, after `STOP_GRACE`.
        assert_eq!(end.signal, Some(15), "{end:?}");
        assert_eq!(end.left, Left::Nothing, "{end:?}");
        assert_gone(&pids_in(&pids_file));
        assert!(open_service_sessions(&lab).is_empty());
        assert!(lab.audit().contains("service end"), "{}", lab.audit());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn what_a_runtime_service_leaves_running_is_stopped_when_it_exits() {
        let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
        let lab = Lab::new();
        assert!(done(lab.install(LEAVES, Confirm::Yes).unwrap()).installed);
        let ended = std::sync::atomic::AtomicBool::new(false);
        let end = lab
            .engine
            .launch_until(&alice(), &lab.name, "gateway", &ended)
            .unwrap();
        assert_eq!(end.exit, 0, "{end:?}");
        // The service manager would start the service again: what this run
        // left would run beside the next.
        assert_eq!(end.left, Left::Nothing, "{end:?}");
        assert_gone(&pids_in(&lab.home.join("gateway-pids")));
        assert!(open_service_sessions(&lab).is_empty());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_launch_ends_a_service_session_whose_launch_was_killed() {
        let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
        let lab = Lab::new();
        assert!(done(lab.install(LEAVES, Confirm::Yes).unwrap()).installed);
        // As the service manager's timeout leaves it: a session open, its
        // process gone.
        let dead = std::process::Command::new("/usr/bin/true").spawn().unwrap();
        let root = crate::lifecycle::process::reference_of_child(&dead).unwrap();
        let mut dead = dead;
        dead.wait().unwrap();
        lab.engine
            .write(
                &alice(),
                "test",
                None,
                |_| String::new(),
                |lock| {
                    let (version, snapshot) = lab.engine.state.active_policy(&lab.name)?.unwrap();
                    let session = crate::model::session::SessionRecord {
                        id: crate::model::session::SessionId(0),
                        sandbox: lab.name.clone(),
                        kind: crate::model::session::SessionKind::Service,
                        version: version.version,
                        snapshot: snapshot.id,
                        compiled: None,
                        pgid: None,
                        root,
                        tracked: Vec::new(),
                        started_at: crate::model::now(),
                        ended_at: None,
                    };
                    lab.engine.state.put_session(lock, &session)?;
                    Ok(())
                },
            )
            .unwrap();
        assert_eq!(open_service_sessions(&lab).len(), 1);
        let ended = std::sync::atomic::AtomicBool::new(false);
        lab.engine
            .launch_until(&alice(), &lab.name, "gateway", &ended)
            .unwrap();
        assert!(open_service_sessions(&lab).is_empty());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_start_ends_the_proxy_a_connect_started_and_leaves_other_sessions() {
        use crate::model::session::SessionKind;
        use crate::service::fake::FakeServices;

        let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
        let fake = std::rc::Rc::new(FakeServices::default());
        let lab = Lab::with_services(Some(Box::new(std::rc::Rc::clone(&fake))));
        // The install starts a proxy as `connect` would, and records it.
        assert!(done(lab.install(INSTALLS, Confirm::Yes).unwrap()).installed);
        let sessions = lab.engine.state.sessions(&lab.name, true).unwrap();
        let proxy = sessions
            .iter()
            .find(|s| s.kind == SessionKind::Proxy)
            .expect("the install recorded a proxy")
            .clone();
        // Another session, which `start` has no reason to end.
        let mut other = std::process::Command::new("/bin/sleep")
            .arg("60")
            .spawn()
            .unwrap();
        let root = crate::lifecycle::process::reference_of_child(&other).unwrap();
        lab.engine
            .write(
                &alice(),
                "test",
                None,
                |_| String::new(),
                |lock| {
                    let (version, snapshot) = lab.engine.state.active_policy(&lab.name)?.unwrap();
                    let session = crate::model::session::SessionRecord {
                        id: crate::model::session::SessionId(0),
                        sandbox: lab.name.clone(),
                        kind: SessionKind::Interactive,
                        version: version.version,
                        snapshot: snapshot.id,
                        compiled: None,
                        pgid: None,
                        root,
                        tracked: Vec::new(),
                        started_at: crate::model::now(),
                        ended_at: None,
                    };
                    lab.engine.state.put_session(lock, &session)?;
                    Ok(())
                },
            )
            .unwrap();

        lab.engine.start_sandbox(&alice(), &lab.name).unwrap();
        assert_eq!(fake.started.borrow().len(), 2);
        assert_gone(&[proxy.root.pid]);
        let open = lab.engine.state.sessions(&lab.name, true).unwrap();
        assert!(
            open.iter().all(|s| s.kind != SessionKind::Proxy),
            "{open:?}"
        );
        assert_eq!(
            open.iter()
                .filter(|s| s.kind == SessionKind::Interactive)
                .count(),
            1
        );
        assert!(
            other.try_wait().unwrap().is_none(),
            "the other session's program was ended"
        );
        other.kill().unwrap();
        other.wait().unwrap();
    }
}

mod services {
    use std::rc::Rc;
    use std::time::Duration;

    use super::*;
    use crate::engine::service::Unit;
    use crate::model::runtime::RuntimeKind;
    use crate::model::sandbox::SandboxState;
    use crate::model::session::SessionKind;
    use crate::runtime::ServiceName;
    use crate::service::fake::FakeServices;
    use crate::service::{ServiceLabel, ServiceStatus};

    const GATEWAY: ServiceName = ServiceName::new("gateway");

    fn sandbox_with_services(
        runtime: Option<RuntimeKind>,
    ) -> (TempDir, Engine, Rc<FakeServices>, SandboxName) {
        let fake = Rc::new(FakeServices::default());
        let (dir, engine) = engine_with(vec![Box::new(FakeBackend::available(
            BackendKind::Seatbelt,
        ))]);
        let engine = engine.with_services(Box::new(Rc::clone(&fake)));
        done(engine.init(&alice(), Confirm::Yes).unwrap());
        let name: SandboxName = "home".parse().unwrap();
        let spec = crate::engine::SandboxSpec {
            name: name.clone(),
            backend: BackendKind::Seatbelt,
            template: "assistant".parse().unwrap(),
        };
        done(engine.create_sandbox(&alice(), spec, Confirm::Yes).unwrap());
        if runtime.is_some() {
            engine
                .write(
                    &alice(),
                    "test",
                    None,
                    |_| String::new(),
                    |lock| {
                        let mut record = engine.state.get(&name)?.unwrap();
                        record.runtime = runtime;
                        engine.state.put(lock, &record)?;
                        Ok(())
                    },
                )
                .unwrap();
        }
        (dir, engine, fake, name)
    }

    fn state_of(engine: &Engine, name: &SandboxName) -> SandboxState {
        engine.state.get(name).unwrap().unwrap().state
    }

    fn labels_of(status: &[(ServiceLabel, ServiceStatus)]) -> Vec<String> {
        status.iter().map(|(l, _)| l.to_string()).collect()
    }

    #[test]
    fn a_sandbox_without_a_runtime_starts_only_its_proxy() {
        let (_dir, engine, fake, name) = sandbox_with_services(None);
        let labels = engine.start_sandbox(&alice(), &name).unwrap();
        assert_eq!(labels, [engine.label(&name, Unit::Proxy).unwrap()]);
        assert_eq!(engine.service_labels(&name).unwrap(), labels);
        assert_eq!(state_of(&engine, &name), SandboxState::Running);
        let unit = &fake.started.borrow()[0];
        let args: Vec<_> = unit
            .args
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(args[..4], ["proxy", "run", "home", "--record"]);
        let port = engine.show_sandbox(&name).unwrap().record.proxy_port;
        assert!(args.contains(&format!("127.0.0.1:{port}")), "{args:?}");
        assert!(unit.env.iter().any(|(k, _)| k == "ENCLOS_HOME"));
        assert!(unit.log.ends_with("sandboxes/home/logs/proxy.log"));
        assert_eq!(unit.stop_timeout, crate::engine::service::STOP_TIMEOUT);
    }

    #[test]
    fn hermes_adds_one_gateway_for_the_whole_sandbox_and_stop_removes_both() {
        let (_dir, engine, fake, name) = sandbox_with_services(Some(RuntimeKind::Hermes));
        let labels = engine.start_sandbox(&alice(), &name).unwrap();
        let (proxy_label, gateway_label) = (
            engine.label(&name, Unit::Proxy).unwrap(),
            engine.label(&name, Unit::Runtime(GATEWAY)).unwrap(),
        );
        assert!(
            gateway_label.as_str().ends_with(".home.gateway"),
            "{gateway_label}"
        );
        assert_eq!(labels, [proxy_label.clone(), gateway_label.clone()]);
        assert_eq!(engine.service_labels(&name).unwrap(), labels);
        let gateway = fake.started.borrow()[1].clone();
        assert_eq!(
            gateway.args,
            ["launch", "home", "gateway"].map(std::ffi::OsString::from)
        );
        assert!(gateway.log.ends_with("sandboxes/home/logs/gateway.log"));
        assert_eq!(
            engine.service_status(&name).unwrap(),
            [
                (gateway_label.clone(), ServiceStatus::Loaded),
                (proxy_label.clone(), ServiceStatus::Loaded)
            ]
        );

        let Planned::DryRun(plan) = engine
            .stop_sandbox(&alice(), &name, Confirm::DryRun)
            .unwrap()
        else {
            panic!("a dry run stopped the sandbox");
        };
        assert!(
            plan.changes
                .contains(&format!("stop service {gateway_label}")),
            "{plan:?}"
        );
        assert_eq!(fake.started.borrow().len(), 2);
        let report = done(engine.stop_sandbox(&alice(), &name, Confirm::Yes).unwrap());
        assert_eq!(
            report.services,
            [gateway_label.clone(), proxy_label.clone()]
        );
        assert!(fake.started.borrow().is_empty());
        // The gateway first, so it never runs without its proxy.
        assert_eq!(*fake.stopped.borrow(), [gateway_label, proxy_label]);
        assert_eq!(state_of(&engine, &name), SandboxState::Stopped);
    }

    #[test]
    fn services_run_with_the_layout_of_the_enclos_that_started_them() {
        let (_dir, engine, fake, name) = sandbox_with_services(Some(RuntimeKind::Hermes));
        engine.start_sandbox(&alice(), &name).unwrap();
        for unit in fake.started.borrow().iter() {
            assert_eq!(unit.env, engine.layout.env(), "{}", unit.label);
        }
    }

    #[test]
    fn starting_again_replaces_the_services_and_a_failed_start_leaves_none() {
        let (_dir, engine, fake, name) = sandbox_with_services(Some(RuntimeKind::Hermes));
        let labels = engine.start_sandbox(&alice(), &name).unwrap();
        engine.start_sandbox(&alice(), &name).unwrap();
        // The earlier ones were removed first, so their processes end.
        assert_eq!(
            *fake.stopped.borrow(),
            [labels[1].clone(), labels[0].clone()]
        );
        assert_eq!(fake.started.borrow().len(), 2);

        *fake.refuse.borrow_mut() = Some(".gateway".to_owned());
        let err = engine.start_sandbox(&alice(), &name).unwrap_err();
        assert!(matches!(err, Error::Service(_)), "{err:?}");
        assert!(err.to_string().contains("refused"), "{err}");
        assert!(
            fake.started.borrow().is_empty(),
            "the proxy stayed installed"
        );
        assert!(engine.service_status(&name).unwrap().is_empty());
        assert!(
            matches!(state_of(&engine, &name), SandboxState::Failed { ref reason } if reason.contains("refused")),
            "{:?}",
            state_of(&engine, &name)
        );
        assert!(
            engine
                .audit(None)
                .unwrap()
                .last()
                .unwrap()
                .finished
                .is_some()
        );

        // When the rollback fails too, both are said.
        *fake.refuse_stop.borrow_mut() = Some(".proxy".to_owned());
        let err = engine.start_sandbox(&alice(), &name).unwrap_err();
        let Error::CleanupFailed { error, left } = err else {
            panic!("{err:?}");
        };
        assert!(error.to_string().contains("refused"), "{error}");
        assert!(left.contains("would not stop"), "{left}");
    }

    #[test]
    fn a_start_needs_the_service_manager_before_it_stops_anything() {
        let (_dir, engine, name) =
            super::policy::with_sandbox_on(FakeBackend::available(BackendKind::Seatbelt));
        let entries = engine.audit(None).unwrap().len();
        let err = engine.start_sandbox(&alice(), &name).unwrap_err();
        assert!(err.to_string().contains("no service manager"), "{err}");
        // Refused before the audited start, with nothing changed.
        assert_eq!(engine.audit(None).unwrap().len(), entries);
        assert_eq!(state_of(&engine, &name), SandboxState::Created);
    }

    #[test]
    fn a_damaged_audit_log_refuses_start_and_stop_before_they_remove_services() {
        let (_dir, engine, fake, name) = sandbox_with_services(Some(RuntimeKind::Hermes));
        engine.start_sandbox(&alice(), &name).unwrap();
        let path = engine.layout.audit_log();
        let text = std::fs::read_to_string(&path).unwrap();
        let damaged = text.replacen("\"init\"", "\"edited\"", 1);
        assert_ne!(damaged, text);
        std::fs::write(&path, &damaged).unwrap();

        let err = engine.start_sandbox(&alice(), &name).unwrap_err();
        assert!(err.to_string().contains("is damaged"), "{err}");
        let err = engine
            .stop_sandbox(&alice(), &name, Confirm::Yes)
            .unwrap_err();
        assert!(err.to_string().contains("is damaged"), "{err}");
        // Nothing was removed, so the sandbox keeps running.
        assert_eq!(fake.started.borrow().len(), 2);
        assert!(fake.stopped.borrow().is_empty());
        assert_eq!(state_of(&engine, &name), SandboxState::Running);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), damaged);
    }

    #[test]
    fn a_sandbox_with_services_installed_is_not_removed() {
        let (_dir, engine, fake, name) = sandbox_with_services(None);
        engine.start_sandbox(&alice(), &name).unwrap();
        // Installed, though no proxy session was ever recorded: the proxy
        // could not take its port, and the service manager keeps restarting
        // it.
        assert!(engine.state.sessions(&name, true).unwrap().is_empty());
        let err = engine
            .remove_sandbox(&alice(), &name, false, Confirm::Yes)
            .unwrap_err();
        assert!(matches!(err, Error::SandboxHasServices { .. }), "{err}");
        assert!(
            err.to_string().contains("enclos sandbox stop home"),
            "{err}"
        );
        assert_eq!(fake.started.borrow().len(), 1);

        done(engine.stop_sandbox(&alice(), &name, Confirm::Yes).unwrap());
        done(
            engine
                .remove_sandbox(&alice(), &name, false, Confirm::Yes)
                .unwrap(),
        );
    }

    #[test]
    fn stop_removes_every_service_under_the_sandbox_prefix_the_proxy_last() {
        let (_dir, engine, fake, name) = sandbox_with_services(Some(RuntimeKind::Hermes));
        let labels = engine.start_sandbox(&alice(), &name).unwrap();
        let prefix = labels[0].as_str().strip_suffix("proxy").unwrap().to_owned();
        // Left by a runtime that no longer declares it, and by hand.
        fake.seed(&format!("{prefix}old-mail"));
        fake.seed(&format!("{prefix}archive"));
        fake.seed(&format!("{prefix}x.other"));
        // Another sandbox's, which shares the start of the prefix.
        let homework = format!("{}homework.proxy", prefix.strip_suffix("home.").unwrap());
        fake.seed(&homework);
        assert_eq!(
            labels_of(&engine.service_status(&name).unwrap()),
            [
                format!("{prefix}archive"),
                format!("{prefix}gateway"),
                format!("{prefix}old-mail"),
                format!("{prefix}x.other"),
                format!("{prefix}proxy"),
            ]
        );
        fake.stopped.borrow_mut().clear();
        done(engine.stop_sandbox(&alice(), &name, Confirm::Yes).unwrap());
        let stopped: Vec<String> = fake
            .stopped
            .borrow()
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(
            stopped,
            [
                format!("{prefix}archive"),
                format!("{prefix}gateway"),
                format!("{prefix}old-mail"),
                format!("{prefix}x.other"),
                format!("{prefix}proxy"),
            ]
        );
        let left: Vec<String> = fake
            .started
            .borrow()
            .iter()
            .map(|u| u.label.to_string())
            .collect();
        assert_eq!(left, [homework]);
        assert!(engine.service_status(&name).unwrap().is_empty());
    }

    #[test]
    fn every_spelling_of_the_enclos_folder_names_the_same_services() {
        let (dir, engine, fake, name) = sandbox_with_services(None);
        engine.start_sandbox(&alice(), &name).unwrap();
        let proxy = engine.label(&name, Unit::Proxy).unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(dir.path().join("enclos"), &link).unwrap();
        let other = |alias: PathBuf| {
            let layout = Layout::at(alias);
            let state = SqliteStateStore::new(layout.state_db(), layout.state_lock());
            let audit = JsonlAuditLog::new(layout.audit_log());
            Engine::new(layout, Box::new(state), Box::new(audit), Vec::new())
                .with_services(Box::new(Rc::clone(&fake)))
        };
        for alias in [dir.path().join("enclos/."), link] {
            let other = other(alias);
            assert_eq!(other.label(&name, Unit::Proxy).unwrap(), proxy);
            assert_eq!(
                labels_of(&other.service_status(&name).unwrap()),
                [proxy.to_string()]
            );
        }
        // Stopped through another spelling, nothing stays installed.
        done(
            other(dir.path().join("enclos/."))
                .stop_sandbox(&alice(), &name, Confirm::Yes)
                .unwrap(),
        );
        assert!(fake.started.borrow().is_empty());
    }

    #[test]
    fn two_installs_never_share_a_service_label() {
        let (_one, first, _, name) = sandbox_with_services(None);
        let (_two, second, _, _) = sandbox_with_services(None);
        let (a, b) = (
            first.label(&name, Unit::Proxy).unwrap(),
            second.label(&name, Unit::Proxy).unwrap(),
        );
        assert_ne!(a, b);
        assert!(
            a.as_str().starts_with("enclos.") && a.as_str().ends_with(".home.proxy"),
            "{a}"
        );
        assert_eq!(a.as_str().len(), "enclos.12345678.home.proxy".len());
    }

    #[test]
    fn a_service_the_runtime_does_not_declare_is_refused() {
        let (_dir, engine, _, name) = sandbox_with_services(Some(RuntimeKind::Hermes));
        let ended = std::sync::atomic::AtomicBool::new(false);
        let err = engine
            .launch_until(&alice(), &name, "mail", &ended)
            .unwrap_err();
        assert!(
            err.to_string().contains("no background service named mail"),
            "{err}"
        );
    }

    #[test]
    fn a_launch_told_to_end_before_its_proxy_runs_starts_nothing() {
        let (_dir, engine, _, name) = sandbox_with_services(Some(RuntimeKind::Hermes));
        let entries = engine.audit(None).unwrap().len();
        let ended = std::sync::atomic::AtomicBool::new(true);
        let err = engine
            .launch_until(&alice(), &name, "gateway", &ended)
            .unwrap_err();
        assert!(err.to_string().contains("told to end before"), "{err}");
        assert!(engine.state.sessions(&name, true).unwrap().is_empty());
        assert_eq!(engine.audit(None).unwrap().len(), entries);
    }

    #[test]
    fn the_proxy_is_started_once_a_live_proxy_session_is_recorded() {
        let (_dir, engine, _, name) = sandbox_with_services(None);
        assert!(
            !engine
                .proxy_started(&name, Duration::from_millis(50))
                .unwrap()
        );
        // This process stands in for the proxy.
        let me = std::process::id();
        engine
            .write(
                &alice(),
                "test",
                None,
                |_| String::new(),
                |lock| {
                    let (version, snapshot) = engine.state.active_policy(&name)?.unwrap();
                    let session = crate::model::session::SessionRecord {
                        id: crate::model::session::SessionId(0),
                        sandbox: name.clone(),
                        kind: SessionKind::Proxy,
                        version: version.version,
                        snapshot: snapshot.id,
                        compiled: None,
                        pgid: None,
                        root: crate::lifecycle::process::reference(me)?.unwrap(),
                        tracked: Vec::new(),
                        started_at: crate::model::now(),
                        ended_at: None,
                    };
                    engine.state.put_session(lock, &session)?;
                    Ok(())
                },
            )
            .unwrap();
        assert!(engine.proxy_started(&name, Duration::ZERO).unwrap());
        let err = engine
            .proxy_started(&"nope".parse().unwrap(), Duration::ZERO)
            .unwrap_err();
        assert!(matches!(err, Error::NoSuchSandbox { .. }), "{err}");
    }

    #[test]
    fn the_logs_are_the_log_files_of_the_sandbox_the_proxy_first() {
        let (_dir, engine, _, name) = sandbox_with_services(None);
        let err = engine.log_files(&"nope".parse().unwrap()).unwrap_err();
        assert!(matches!(err, Error::NoSuchSandbox { .. }), "{err}");
        assert!(engine.log_files(&name).unwrap().is_empty());
        let logs = engine.layout.sandbox_dir("home").join("logs");
        std::fs::create_dir_all(&logs).unwrap();
        for file in [
            "gateway.log",
            "proxy.log",
            "mail.log",
            "proxy.log.1",
            "notes",
        ] {
            std::fs::write(logs.join(file), "").unwrap();
        }
        let files: Vec<String> = engine
            .log_files(&name)
            .unwrap()
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(files, ["proxy.log", "gateway.log", "mail.log"]);
    }
}

mod status {
    use std::path::Path;

    use super::policy::with_sandbox_on;
    use super::*;
    use crate::engine::status::suggest;
    use crate::engine::{AgentKind, AgentList, AgentStatus, Fact, Presence, SandboxStatus};
    use crate::model::Timestamp;
    use crate::model::agent::AgentName;
    use crate::model::runtime::RuntimeKind;
    use crate::model::session::{SessionId, SessionKind, SessionRecord};
    use crate::runtime::{
        HomeFile, Installer, RuntimeAdapter, RuntimeAgentName, SandboxCommand, Unreadable,
    };

    /// A runtime adapter that implements none of the `status` methods.
    struct Bare;

    impl RuntimeAdapter for Bare {
        fn kind(&self) -> RuntimeKind {
            RuntimeKind::Hermes
        }
        fn version(&self) -> &'static str {
            "0"
        }
        fn endpoints(&self) -> &'static str {
            ""
        }
        fn installer(&self) -> Installer {
            Installer {
                url: String::new(),
                sha256: String::new(),
                args: Vec::new(),
            }
        }
        fn home_files(&self) -> Vec<HomeFile> {
            Vec::new()
        }
        fn login(&self) -> String {
            String::new()
        }
        fn create_agent(&self, _: &AgentName) -> SandboxCommand {
            SandboxCommand::from_words(&[])
        }
        fn agent_files(&self, _: &AgentName) -> String {
            String::new()
        }
        fn talk(&self, _: &AgentName) -> String {
            String::new()
        }
        fn services(&self) -> Vec<crate::runtime::RuntimeService> {
            Vec::new()
        }
        fn agents_in(&self, _: &Path) -> std::result::Result<Vec<RuntimeAgentName>, Unreadable> {
            Ok(Vec::new())
        }
    }

    fn with_runtime() -> (TempDir, Engine, SandboxName) {
        let (dir, engine, name) = with_sandbox_on(FakeBackend::available(BackendKind::Seatbelt));
        engine
            .write(
                &alice(),
                "test",
                None,
                |_| String::new(),
                |lock| {
                    let mut record = engine.state.get(&name)?.unwrap();
                    record.runtime = Some(RuntimeKind::Hermes);
                    engine.state.put(lock, &record)?;
                    Ok(())
                },
            )
            .unwrap();
        (dir, engine, name)
    }

    fn days(n: i64) -> jiff::SignedDuration {
        jiff::SignedDuration::from_hours(24 * n)
    }

    fn commands(s: &[Suggestion]) -> Vec<String> {
        s.iter().map(Suggestion::command).collect()
    }

    #[test]
    fn a_runtime_that_names_nothing_gets_sizes_no_agents_and_suggestions() {
        let (_dir, engine, name) = with_runtime();
        std::fs::write(engine.sandbox_home(&name).join("data"), vec![b'x'; 300_000]).unwrap();
        let record = engine.state.get(&name).unwrap().unwrap();
        let created = record.created_at;
        let status = engine.sandbox_status(record, Some(&Bare), created).unwrap();
        assert_eq!(status.disk.incomplete, None);
        assert!(status.disk.total >= 300_000);
        assert_eq!(status.disk.other, status.disk.total);
        assert_eq!(
            (status.disk.runtime, status.disk.caches, status.disk.agents),
            (None, None, None)
        );
        // A runtime that lists none: no agents, which is not "cannot tell".
        assert_eq!(
            status.agents,
            Some(AgentList {
                agents: Vec::new(),
                unreadable: None
            })
        );
        let rt = status.runtime.as_ref().unwrap();
        assert_eq!(
            (&rt.version, &rt.logged_in, &rt.installed),
            (&Fact::NotProvided, &Fact::NotProvided, &Fact::NotProvided)
        );
        assert_eq!(
            commands(&suggest(std::slice::from_ref(&status), created)),
            ["enclos agent add home/main"]
        );

        // Unused for 30 days, exactly, it is worth removing; a second less,
        // not yet.
        let at = |d| created.checked_add(d).unwrap();
        let almost = at(days(30) - jiff::SignedDuration::from_secs(1));
        assert_eq!(suggest(std::slice::from_ref(&status), almost).len(), 1);
        let s = suggest(std::slice::from_ref(&status), at(days(30)));
        assert_eq!(
            commands(&s),
            ["enclos agent add home/main", "enclos sandbox rm home"]
        );
        assert!(
            s[1].reason()
                .starts_with("unused for 30 days; removing it frees ")
        );
        assert!(!s[1].reason().contains('≥'), "{}", s[1].reason());
    }

    #[test]
    fn hermes_agents_logins_and_models_show_with_what_to_do() {
        let (_dir, engine, name) = with_runtime();
        let home = engine.sandbox_home(&name);
        let scout = home.join(".hermes/profiles/scout");
        std::fs::create_dir_all(&scout).unwrap();
        std::fs::write(
            scout.join("config.yaml"),
            "model:\n  default: gpt-6.1-sol\n",
        )
        .unwrap();
        std::fs::write(scout.join(".hermes_history"), "hello").unwrap();
        std::fs::create_dir_all(home.join(".hermes/hermes-agent")).unwrap();
        std::fs::write(home.join(".hermes/hermes-agent/big"), vec![b'x'; 200_000]).unwrap();
        // Hermes's own `default` profile, at the root of its home.
        std::fs::write(
            home.join(".hermes/config.yaml"),
            "model:\n  model: gpt-6.1-terra\n",
        )
        .unwrap();
        std::fs::write(home.join(".hermes/state.db"), vec![b'x'; 50_000]).unwrap();

        let view = engine.status(None).unwrap();
        let s = &view.sandboxes[0];
        let rt = s.runtime.as_ref().unwrap();
        assert_eq!(
            (&rt.logged_in, &rt.installed),
            (&Fact::Known(false), &Fact::Known(true))
        );
        let list = s.agents.as_ref().unwrap();
        assert_eq!(list.unreadable, None);
        assert_eq!(list.agents.len(), 2);
        let d = &list.agents[0];
        assert_eq!(
            (d.name.as_str(), d.kind, &d.model),
            (
                "default",
                AgentKind::Builtin,
                &Fact::Known("gpt-6.1-terra".into())
            )
        );
        // Its size is the root data, not the runtime install under it.
        let size = *d.bytes.known().unwrap();
        assert!((50_000..200_000).contains(&size), "{size}");
        assert!(d.last_active.known().is_some());
        let a = &list.agents[1];
        assert_eq!(
            (a.name.as_str(), a.kind, &a.model),
            (
                "scout",
                AgentKind::Untracked,
                &Fact::Known("gpt-6.1-sol".into())
            )
        );
        assert!(a.last_active.known().is_some() && *a.bytes.known().unwrap() > 0);
        assert!(s.disk.runtime.unwrap() >= 200_000);
        assert_eq!(
            commands(&view.suggestions),
            [
                "enclos agent add home/scout",
                "enclos connect home -- hermes -p default setup"
            ]
        );
        assert_eq!(view.agent_count(), 1);
        assert_eq!(engine.status(Some(&name)).unwrap().sandboxes.len(), 1);
        let err = engine.status(Some(&"nope".parse().unwrap())).unwrap_err();
        assert!(matches!(err, Error::NoSuchSandbox { .. }), "{err}");

        // Logged in, the suggestion goes.
        std::fs::write(home.join(".hermes/auth.json"), "{}").unwrap();
        let view = engine.status(None).unwrap();
        assert_eq!(
            view.sandboxes[0].runtime.as_ref().unwrap().logged_in,
            Fact::Known(true)
        );
        assert_eq!(commands(&view.suggestions), ["enclos agent add home/scout"]);
    }

    #[test]
    fn enclos_neither_adds_nor_removes_the_built_in_agent() {
        let (_dir, engine, name) = with_runtime();
        let default: AgentName = "default".parse().unwrap();
        let audited = engine.audit(None).unwrap().len();
        let err = engine
            .add_agent(&alice(), &name, default.clone(), Confirm::Yes)
            .unwrap_err();
        assert!(
            err.to_string().contains("is Hermes's built-in agent")
                && err
                    .to_string()
                    .contains("enclos connect home -- hermes -p default`"),
            "{err}"
        );
        let err = engine
            .remove_agent(&alice(), &name, &default, false, Confirm::Yes)
            .unwrap_err();
        assert!(
            err.to_string().contains("is Hermes's built-in agent"),
            "{err}"
        );
        assert!(engine.agents(&name).unwrap().is_empty());
        assert_eq!(engine.audit(None).unwrap().len(), audited);
        assert_eq!(
            engine.builtin_agent(&name).unwrap().map(|b| b.as_str()),
            Some("default")
        );
    }

    #[test]
    fn an_unreadable_agent_list_is_said_and_nothing_is_called_gone() {
        let (_dir, engine, name) = with_runtime();
        let home = engine.sandbox_home(&name);
        std::fs::create_dir_all(home.join(".hermes/profiles/scout")).unwrap();
        std::fs::write(home.join(".hermes/profiles/scout/config.yaml"), "").unwrap();
        done(
            engine
                .add_agent(&alice(), &name, "scout".parse().unwrap(), Confirm::Yes)
                .unwrap(),
        );
        std::fs::rename(home.join(".hermes"), home.join("kept")).unwrap();
        std::os::unix::fs::symlink(home.join("kept"), home.join(".hermes")).unwrap();
        let view = engine.status(None).unwrap();
        let list = view.sandboxes[0].agents.as_ref().unwrap();
        assert_eq!(list.unreadable.as_deref(), Some("~/.hermes is a link"));
        let kinds: Vec<(&str, AgentKind)> = list
            .agents
            .iter()
            .map(|a| (a.name.as_str(), a.kind))
            .collect();
        assert_eq!(
            kinds,
            [
                ("default", AgentKind::Builtin),
                (
                    "scout",
                    AgentKind::Tracked {
                        in_runtime: Presence::Unknown
                    }
                )
            ]
        );
        // Facts behind the link are not read either.
        assert!(matches!(&list.agents[1].model, Fact::CannotTell(why) if why.contains("link")));
        let rt = view.sandboxes[0].runtime.as_ref().unwrap();
        assert_eq!(rt.logged_in, Fact::CannotTell("~/.hermes is a link".into()));
        let s = &view.suggestions;
        assert_eq!(commands(s), ["enclos connect home"]);
        assert_eq!(
            s[0].reason(),
            "enclos cannot read Hermes's agents: ~/.hermes is a link"
        );
    }

    #[test]
    fn missing_runtime_files_suggest_installing_again_rather_than_logging_in() {
        let (_dir, engine, name) = with_runtime();
        std::fs::create_dir_all(engine.sandbox_home(&name).join(".hermes")).unwrap();
        let view = engine.status(None).unwrap();
        let rt = view.sandboxes[0].runtime.as_ref().unwrap();
        assert_eq!(rt.installed, Fact::Known(false));
        assert_eq!(
            commands(&view.suggestions),
            ["enclos runtime install hermes --sandbox home"]
        );
        assert_eq!(
            view.suggestions[0].reason(),
            "Hermes's files are missing from the home"
        );
    }

    /// A session of `kind`, started at `start`, ended at `end`.
    fn put_session(
        engine: &Engine,
        name: &SandboxName,
        kind: SessionKind,
        compiled: Option<&str>,
        start: Timestamp,
        end: Option<Timestamp>,
    ) {
        let session = SessionRecord {
            id: SessionId(0),
            sandbox: name.clone(),
            kind,
            version: 1,
            snapshot: engine.policy(name).unwrap().snapshot.id,
            compiled: compiled.map(str::to_owned),
            root: crate::lifecycle::process::reference(std::process::id())
                .unwrap()
                .unwrap(),
            pgid: None,
            tracked: Vec::new(),
            started_at: start,
            ended_at: end,
        };
        let lock = engine.state.lock().unwrap();
        engine.state.put_session(&lock, &session).unwrap();
    }

    fn net_event(name: &SandboxName, at: Timestamp, denied: bool) -> crate::model::net::NetEvent {
        use crate::model::net::{NetEvent, Reason, Verdict};
        NetEvent {
            at,
            sandbox: name.clone(),
            host: "example.com".into(),
            port: 443,
            method: "CONNECT".into(),
            address: None,
            verdict: if denied {
                Verdict::Denied
            } else {
                Verdict::Allowed
            },
            reason: denied.then_some(Reason::NotAllowed),
            bytes_up: 0,
            bytes_down: 0,
            duration_ms: 0,
        }
    }

    #[test]
    fn the_last_use_counts_connect_and_service_sessions_and_the_network_not_the_proxy() {
        use crate::engine::status::last_used;
        let t0: Timestamp = "2026-01-01T00:00:00Z".parse().unwrap();
        let at = |d: i64| t0.checked_add(days(d)).unwrap();
        let session = |kind, start, end| SessionRecord {
            id: SessionId(0),
            sandbox: "home".parse().unwrap(),
            kind,
            version: 1,
            snapshot: crate::model::policy::SnapshotId("x".into()),
            compiled: None,
            root: crate::lifecycle::process::reference(std::process::id())
                .unwrap()
                .unwrap(),
            pgid: None,
            tracked: Vec::new(),
            started_at: start,
            ended_at: end,
        };
        assert_eq!(last_used(t0, &[], None), t0);
        // A `connect` from day 1 to day 5, a service that ended on day 9, a
        // proxy that ran until day 20, and a connection tried on day 7.
        let sessions = [
            session(SessionKind::Interactive, at(1), Some(at(5))),
            session(SessionKind::Service, at(2), Some(at(9))),
            session(SessionKind::Proxy, at(3), Some(at(20))),
        ];
        assert_eq!(last_used(t0, &sessions, Some(at(7))), at(9));
        assert_eq!(last_used(t0, &sessions[2..], Some(at(7))), at(7));
        assert_eq!(last_used(t0, &sessions[..1], None), at(5));
    }

    #[test]
    fn sessions_and_the_network_log_give_last_connect_and_what_needs_a_restart() {
        let (_dir, engine, name) = with_runtime();
        let record = engine.state.get(&name).unwrap().unwrap();
        let t0 = record.created_at;
        let fresh = engine
            .sandbox_status(record.clone(), Some(&Bare), t0)
            .unwrap();
        assert_eq!(
            (fresh.last_connect, fresh.last_network, fresh.last_used),
            (None, None, t0)
        );
        assert!(!fresh.restart_needed && fresh.running_sessions == 0);
        assert!(!fresh.in_use());

        let later = t0.checked_add(jiff::SignedDuration::from_secs(60)).unwrap();
        put_session(&engine, &name, SessionKind::Interactive, None, later, None);
        engine
            .state
            .record(&net_event(&name, later, false))
            .unwrap();
        let status = engine
            .sandbox_status(record.clone(), Some(&Bare), later)
            .unwrap();
        assert_eq!(
            (status.last_connect, status.last_network, status.last_used),
            (Some(later), Some(later), later)
        );
        assert_eq!(status.running_sessions, 1);
        assert!(status.in_use());
        // A session without a compiled file, as the proxy runs, applies
        // network rules live: no restart. One on a compiled file the active
        // policy replaced needs one.
        assert!(!status.restart_needed);
        put_session(
            &engine,
            &name,
            SessionKind::Interactive,
            Some("/old/compiled.sb"),
            later,
            None,
        );
        let status = engine.sandbox_status(record, Some(&Bare), later).unwrap();
        assert!(status.restart_needed);
        assert!(
            commands(&suggest(&[status], later)).contains(&"enclos sandbox restart home".into())
        );
    }

    #[test]
    fn a_sandbox_that_cannot_be_read_is_listed_with_why_and_the_total_is_a_lower_bound() {
        let (_dir, engine, name) = with_runtime();
        let spec = crate::engine::SandboxSpec {
            name: "spare".parse().unwrap(),
            backend: BackendKind::Seatbelt,
            template: "assistant".parse().unwrap(),
        };
        done(engine.create_sandbox(&alice(), spec, Confirm::Yes).unwrap());
        assert!(engine.status(None).unwrap().complete);
        put_session(
            &engine,
            &name,
            SessionKind::Interactive,
            None,
            crate::model::now(),
            None,
        );
        let db = rusqlite::Connection::open(engine.layout.state_db()).unwrap();
        db.execute("UPDATE sessions SET started_at = 'not a time'", [])
            .unwrap();
        let view = engine.status(None).unwrap();
        let listed: Vec<&str> = view.sandboxes.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(listed, ["spare"]);
        assert_eq!(view.unlisted.len(), 1);
        assert_eq!(view.unlisted[0].name, name);
        assert!(!view.unlisted[0].error.is_empty());
        // Its folder is not in `bytes`, so the total is a lower bound.
        assert!(!view.complete);
    }

    #[test]
    fn refused_destinations_count_for_seven_days_exactly() {
        let (_dir, engine, name) = with_runtime();
        let record = engine.state.get(&name).unwrap().unwrap();
        let now = record.created_at.checked_add(days(20)).unwrap();
        let week = now.checked_sub(days(7)).unwrap();
        engine.state.record(&net_event(&name, week, true)).unwrap();
        let status = engine
            .sandbox_status(record.clone(), Some(&Bare), now)
            .unwrap();
        assert_eq!(status.refused_recently, 1);
        let s = suggest(std::slice::from_ref(&status), now);
        assert!(
            commands(&s).contains(&"enclos net denied home".into()),
            "{s:?}"
        );
        let later = now.checked_add(jiff::SignedDuration::from_secs(1)).unwrap();
        let status = engine.sandbox_status(record, Some(&Bare), later).unwrap();
        assert_eq!(status.refused_recently, 0);
    }

    #[test]
    fn each_rule_names_its_command_and_nothing_fires_without_its_fact() {
        let (_dir, engine, name) = with_runtime();
        let record = engine.state.get(&name).unwrap().unwrap();
        let t0 = record.created_at;
        let base = engine.sandbox_status(record, Some(&Bare), t0).unwrap();
        let with_agents = |agents: Vec<(&str, AgentKind)>| SandboxStatus {
            agents: Some(AgentList {
                agents: agents
                    .into_iter()
                    .map(|(n, kind)| AgentStatus {
                        name: crate::runtime::RuntimeAgentName::new(n).unwrap(),
                        kind,
                        last_active: Fact::NotProvided,
                        bytes: Fact::NotProvided,
                        model: Fact::NotProvided,
                    })
                    .collect(),
                unreadable: None,
            }),
            ..base.clone()
        };
        let s = with_agents(vec![
            ("default", AgentKind::Builtin),
            (
                "main",
                AgentKind::Tracked {
                    in_runtime: Presence::Present,
                },
            ),
            (
                "gone",
                AgentKind::Tracked {
                    in_runtime: Presence::Gone,
                },
            ),
            (
                "lost",
                AgentKind::Tracked {
                    in_runtime: Presence::Unknown,
                },
            ),
            ("scout", AgentKind::Untracked),
            ("my_bot", AgentKind::Untrackable),
        ]);
        assert_eq!(
            commands(&suggest(&[s], t0)),
            ["enclos agent rm home/gone", "enclos agent add home/scout"]
        );
        let none = SandboxStatus {
            runtime: None,
            agents: None,
            ..base.clone()
        };
        assert_eq!(
            commands(&suggest(&[none], t0)),
            ["enclos runtime install <runtime> --sandbox home"]
        );

        // Something running, or a service manager that cannot say, keeps an
        // old sandbox from being called unused.
        let old = t0.checked_add(days(40)).unwrap();
        let idle = with_agents(vec![("default", AgentKind::Builtin)]);
        assert_eq!(
            commands(&suggest(std::slice::from_ref(&idle), old)),
            ["enclos sandbox rm home"]
        );
        let running = SandboxStatus {
            running_sessions: 1,
            ..idle.clone()
        };
        let unknown = SandboxStatus {
            services: Fact::CannotTell("no GUI domain".into()),
            ..idle.clone()
        };
        let service = SandboxStatus {
            services: Fact::Known(vec![crate::engine::ServiceLine {
                label: "enclos.x.home.gateway".into(),
                service: "gateway".into(),
                state: crate::engine::ServiceState::Running { pid: 1 },
            }]),
            ..idle.clone()
        };
        for busy in [running, unknown, service] {
            assert!(suggest(&[busy], old).is_empty());
        }
        // A walk that stopped early says the size is a lower bound.
        let partial = SandboxStatus {
            disk: crate::engine::Disk {
                incomplete: Some("stopped after 1000000 entries".into()),
                ..idle.disk.clone()
            },
            ..idle
        };
        let s = suggest(&[partial], old);
        assert!(s[0].reason().contains("frees ≥ "), "{}", s[0].reason());
    }

    #[test]
    fn the_json_view_names_each_state_and_fact() {
        let (_dir, engine, name) = with_runtime();
        let home = engine.sandbox_home(&name);
        std::fs::create_dir_all(home.join(".hermes/hermes-agent")).unwrap();
        let json = serde_json::to_value(engine.status(None).unwrap()).unwrap();
        let s = &json["sandboxes"][0];
        assert_eq!(s["name"], "home");
        assert_eq!(s["state"], "created");
        assert_eq!(s["services"], serde_json::json!({"known": []}));
        assert_eq!(s["runtime"]["kind"], "hermes");
        assert_eq!(s["runtime"]["version"], "not_provided");
        assert_eq!(
            s["runtime"]["logged_in"],
            serde_json::json!({"known": false})
        );
        let default = &s["agents"]["agents"][0];
        assert_eq!(default["name"], "default");
        assert_eq!(default["kind"], "builtin");
        assert_eq!(default["model"], "absent");
        assert!(s["disk"]["total"].is_u64());
        assert_eq!(s["disk"]["incomplete"], serde_json::Value::Null);
        assert_eq!(json["complete"], true);
        assert_eq!(json["idle_days"], 30);
        assert!(json["bytes"].is_u64());
        assert_eq!(json["unlisted"], serde_json::json!([]));
        assert_eq!(
            json["suggestions"][0],
            serde_json::json!({
                "kind": "log_in",
                "target": "home",
                "reason": "Hermes is not logged in",
                "command": "enclos connect home -- hermes -p default setup"
            })
        );
    }
}
