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
    fn stopping_a_sandbox_with_nothing_running_marks_it_stopped() {
        let (_dir, engine, name) = with_sandbox_on(FakeBackend::available(BackendKind::Seatbelt));
        let report = engine.stop_sandbox(&alice(), &name).unwrap();
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

    #[test]
    fn an_agent_made_inside_the_sandbox_is_reported_then_adopted() {
        let (_dir, engine, name, make) = with_hermes();
        make("scout");
        make("my_bot");
        let check = engine.check_agents(&name).unwrap();
        assert_eq!(check.untracked, ["scout".parse::<AgentName>().unwrap()]);
        assert_eq!(check.unnamed, ["my_bot"]);
        let err = engine
            .remove_agent(
                &alice(),
                &name,
                &"scout".parse().unwrap(),
                false,
                Confirm::Yes,
            )
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("enclos does not track agent `scout`, which Hermes has"),
            "{err}"
        );

        // Adopting runs nothing in the sandbox: the fake backend would fail.
        let added = engine
            .add_agent(&alice(), &name, "scout".parse().unwrap())
            .unwrap();
        assert!(added.adopted);
        assert!(engine.check_agents(&name).unwrap().untracked.is_empty());
        let entries = engine.audit(None).unwrap();
        let last = entries.last().unwrap();
        assert_eq!(last.intent.command, "agent add");
        let message = &last.finished.as_ref().unwrap().outcome.message;
        assert_eq!(message, "adopted");
    }

    #[test]
    fn an_agent_deleted_inside_the_sandbox_is_reported_missing() {
        let (_dir, engine, name, make) = with_hermes();
        make("scout");
        engine
            .add_agent(&alice(), &name, "scout".parse().unwrap())
            .unwrap();
        std::fs::remove_dir_all(engine.sandbox_home(&name).join(".hermes/profiles/scout")).unwrap();
        let check = engine.check_agents(&name).unwrap();
        assert_eq!(check.missing, ["scout".parse::<AgentName>().unwrap()]);
        assert!(check.untracked.is_empty());
        // Nothing left to delete: removing it takes only the record, and
        // runs nothing in the sandbox (the fake backend would fail).
        let scout = "scout".parse().unwrap();
        done(
            engine
                .remove_agent(&alice(), &name, &scout, false, Confirm::Yes)
                .unwrap(),
        );
        assert!(engine.agents(&name).unwrap().is_empty());
    }

    #[test]
    fn removing_an_agent_with_its_files_asks_first() {
        let (_dir, engine, name, make) = with_hermes();
        make("scout");
        engine
            .add_agent(&alice(), &name, "scout".parse().unwrap())
            .unwrap();
        let scout = "scout".parse().unwrap();
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
        assert!(
            plan.changes[0].contains("its files, with hermes's own command"),
            "{plan:?}"
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
    fn the_check_compares_names_both_ways() {
        let tracked = |n: &str| AgentRecord {
            name: n.parse().unwrap(),
            created_at: "2026-01-02T03:04:05Z".parse().unwrap(),
        };
        let found = ["main", "scout", "a"].map(String::from).to_vec();
        let check = AgentCheck::compare(found, &[tracked("main"), tracked("gone")], None);
        assert_eq!(check.untracked, ["scout".parse::<AgentName>().unwrap()]);
        assert_eq!(check.unnamed, ["a"]);
        assert_eq!(check.missing, ["gone".parse::<AgentName>().unwrap()]);
        assert!(!check.is_clean());
        assert!(AgentCheck::compare(vec!["main".into()], &[tracked("main")], None).is_clean());
        // A runtime that lists its built-in agent: never untracked.
        let both = vec!["main".into(), "default".into()];
        assert!(AgentCheck::compare(both, &[tracked("main")], Some("default")).is_clean());
    }
}

mod services {
    use std::rc::Rc;

    use super::*;
    use crate::engine::service::Unit;
    use crate::model::runtime::RuntimeKind;
    use crate::service::fake::FakeServices;

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

    #[test]
    fn a_sandbox_without_a_runtime_starts_only_its_proxy() {
        let (_dir, engine, fake, name) = sandbox_with_services(None);
        let labels = engine.start_sandbox(&alice(), &name).unwrap();
        assert_eq!(labels, [engine.label(&name, Unit::Proxy)]);
        assert_eq!(engine.service_labels(&name).unwrap(), labels);
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
    }

    #[test]
    fn hermes_adds_one_gateway_for_the_whole_sandbox_and_stop_removes_both() {
        let (_dir, engine, fake, name) = sandbox_with_services(Some(RuntimeKind::Hermes));
        let labels = engine.start_sandbox(&alice(), &name).unwrap();
        let (proxy_label, gateway_label) = (
            engine.label(&name, Unit::Proxy),
            engine.label(&name, Unit::Gateway),
        );
        assert_eq!(labels, [proxy_label.clone(), gateway_label.clone()]);
        assert_eq!(engine.service_labels(&name).unwrap(), labels);
        let gateway = fake.started.borrow()[1].clone();
        assert_eq!(
            gateway.args,
            ["launch", "home"].map(std::ffi::OsString::from)
        );
        assert_eq!(engine.service_status(&name).len(), 2);

        engine.stop_sandbox(&alice(), &name).unwrap();
        assert!(fake.started.borrow().is_empty());
        assert!(fake.stopped.borrow().contains(&gateway_label));
        assert!(fake.stopped.borrow().contains(&proxy_label));
    }

    #[test]
    fn two_installs_never_share_a_launchd_label() {
        let (_one, first, _, name) = sandbox_with_services(None);
        let (_two, second, _, _) = sandbox_with_services(None);
        let (a, b) = (
            first.label(&name, Unit::Proxy),
            second.label(&name, Unit::Proxy),
        );
        assert_ne!(a, b);
        assert!(
            a.starts_with("enclos.") && a.ends_with(".home.proxy"),
            "{a}"
        );
        assert_eq!(a.len(), "enclos.12345678.home.proxy".len());
    }

    #[test]
    fn an_engine_without_a_service_manager_never_starts_services() {
        let (_dir, engine, name) =
            super::policy::with_sandbox_on(FakeBackend::available(BackendKind::Seatbelt));
        let err = engine.start_sandbox(&alice(), &name).unwrap_err();
        assert!(err.to_string().contains("no service manager"), "{err}");
    }
}

mod status {
    use std::ffi::OsString;
    use std::path::Path;

    use super::policy::with_sandbox_on;
    use super::*;
    use crate::engine::status::suggest;
    use crate::model::agent::AgentName;
    use crate::model::runtime::RuntimeKind;
    use crate::runtime::{HomeFile, Installer, RuntimeAdapter};

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
                url: "",
                sha256: "",
                args: &[],
            }
        }
        fn home_files(&self) -> Vec<HomeFile> {
            Vec::new()
        }
        fn login(&self) -> Vec<OsString> {
            Vec::new()
        }
        fn create_agent(&self, _: &AgentName) -> Vec<OsString> {
            Vec::new()
        }
        fn talk(&self, _: &AgentName) -> String {
            String::new()
        }
        fn service(&self) -> Option<Vec<OsString>> {
            None
        }
        fn agents_in(&self, _: &Path) -> Option<Vec<String>> {
            None
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

    #[test]
    fn a_runtime_that_names_nothing_still_gets_sizes_and_suggestions() {
        let (_dir, engine, name) = with_runtime();
        std::fs::write(engine.sandbox_home(&name).join("data"), vec![0u8; 300_000]).unwrap();
        let record = engine.state.get(&name).unwrap().unwrap();
        let created = record.created_at;
        let status = engine.sandbox_status(record, Some(&Bare), created).unwrap();
        assert!(status.disk.total.complete);
        assert!(status.disk.total.bytes >= 300_000);
        assert_eq!(status.disk.other, status.disk.total.bytes);
        assert_eq!(
            (status.disk.runtime, status.disk.caches, status.disk.agents),
            (None, None, None)
        );
        assert_eq!(status.agents, None);
        let rt = status.runtime.as_ref().unwrap();
        assert_eq!((rt.version.as_deref(), rt.logged_in), (None, None));

        // Forty days later, an unused sandbox is worth removing.
        let later = created
            .checked_add(jiff::SignedDuration::from_hours(24 * 40))
            .unwrap();
        let s = suggest(std::slice::from_ref(&status), later);
        assert_eq!(s.len(), 1, "{s:?}");
        assert_eq!(s[0].command, "enclos sandbox rm home");
        assert!(s[0].reason.starts_with("unused for 40 days"), "{s:?}");
        assert!(suggest(&[status], created).is_empty());
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
        std::fs::write(home.join(".hermes/hermes-agent/big"), vec![0u8; 200_000]).unwrap();
        // Hermes's own `default` profile, at the root of its home.
        std::fs::write(
            home.join(".hermes/config.yaml"),
            "model:\n  model: gpt-6.1-terra\n",
        )
        .unwrap();
        std::fs::write(home.join(".hermes/state.db"), vec![0u8; 50_000]).unwrap();

        let view = engine.status(None).unwrap();
        let s = &view.sandboxes[0];
        assert_eq!(s.runtime.as_ref().unwrap().logged_in, Some(false));
        let agents = s.agents.as_ref().unwrap();
        assert_eq!(agents.len(), 2);
        let d = &agents[0];
        assert_eq!(
            (d.name.as_str(), d.builtin, d.tracked, d.model.as_deref()),
            ("default", true, false, Some("gpt-6.1-terra"))
        );
        // Its size is the root data, not the runtime install under it.
        let size = d.bytes.unwrap();
        assert!((50_000..200_000).contains(&size), "{size}");
        assert!(d.last_active.is_some());
        let a = &agents[1];
        assert_eq!(
            (a.name.as_str(), a.tracked, a.in_runtime, a.model.as_deref()),
            ("scout", false, Some(true), Some("gpt-6.1-sol"))
        );
        assert!(a.last_active.is_some() && a.bytes.unwrap() > 0);
        assert!(s.disk.runtime.unwrap() >= 200_000);
        let commands: Vec<&str> = view
            .suggestions
            .iter()
            .map(|s| s.command.as_str())
            .collect();
        assert!(
            commands.contains(&"enclos agent add home/scout"),
            "{commands:?}"
        );
        assert!(
            commands.contains(&"enclos runtime login home"),
            "{commands:?}"
        );
        assert!(
            !commands.contains(&"enclos agent add home/main"),
            "{commands:?}"
        );
        assert_eq!(view.agent_count(), 1);
        assert_eq!(engine.status(Some(&name)).unwrap().sandboxes.len(), 1);

        // enclos neither adds nor removes the built-in agent.
        let default: AgentName = "default".parse().unwrap();
        let err = engine
            .add_agent(&alice(), &name, default.clone())
            .unwrap_err();
        assert!(err.to_string().contains("built-in agent"), "{err}");
        let err = engine
            .remove_agent(&alice(), &name, &default, false, Confirm::Yes)
            .unwrap_err();
        assert!(err.to_string().contains("built-in agent"), "{err}");
        assert_eq!(engine.builtin_agent(&name).unwrap(), Some("default"));
        assert!(engine.status(Some(&"nope".parse().unwrap())).is_err());
    }
}
