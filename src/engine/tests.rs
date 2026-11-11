use tempfile::TempDir;

use super::*;
use crate::backend::fake::FakeBackend;
use crate::error::{Error, HomeFound};
use crate::model::audit::AuditResult;

/// The shell `connect` runs when given no command, as a plan shows it.
fn default_shell() -> String {
    crate::backend::environment::shell_command()
        .iter()
        .map(|word| word.to_string_lossy())
        .collect::<Vec<_>>()
        .join(" ")
}

fn alice() -> Actor {
    Actor {
        user: "alice".into(),
        host: "mac".into(),
    }
}

fn engine_with(backends: Vec<Box<dyn Backend>>) -> (TempDir, Engine) {
    let dir = tempfile::tempdir().unwrap();
    let layout = Layout::at(dir.path().join("enclos"));
    let state = SqliteStateStore::new(
        layout.state_db(),
        layout.state_lock(),
        crate::state::Wait::Command,
    );
    let audit = JsonlAuditLog::new(layout.audit_log());
    let engine = Engine::new(layout, Box::new(state), Box::new(audit), backends)
        .with_downloader(Box::new(LocalFiles));
    (dir, engine)
}

/// Copies a test's `file://` installer, which curl refuses, and leaves any
/// other URL to curl.
struct LocalFiles;

impl super::staging::Downloader for LocalFiles {
    fn download(
        &self,
        url: &str,
        to: &std::path::Path,
    ) -> std::result::Result<(), super::staging::DownloadFailed> {
        match url.strip_prefix("file://") {
            Some(from) => std::fs::copy(from, to)
                .map(|_| ())
                .map_err(|e| super::staging::DownloadFailed::NotRun(format!("{from}: {e}"))),
            None => super::staging::Curl.download(url, to),
        }
    }
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
    assert_eq!(
        report.unavailable,
        [crate::engine::Unavailable {
            backend: BackendKind::Libkrun,
            reason: "no VM support".to_owned(),
        }]
    );
    assert_eq!(report.config_backend, None);
    let config = std::fs::read_to_string(engine.layout.config_file()).unwrap();
    assert!(
        config.contains("default_backend = \"seatbelt\""),
        "{config}"
    );
}

/// A `config.toml` written while no backend was available gets the one
/// available now, in place of init's own line for that; one changed by
/// hand is said to name none and left; one that does not parse is said, and
/// does not fail init.
#[test]
fn init_names_a_backend_in_a_config_written_while_none_was_available() {
    use crate::engine::ConfigBackend;
    let (_dir, mut engine) = engine_with(vec![Box::new(FakeBackend::unavailable(
        BackendKind::Seatbelt,
        "a bad setting",
    ))]);
    let report = done(engine.init(&alice(), Confirm::Yes).unwrap());
    assert_eq!(report.default_backend, None);
    assert_eq!(report.config_backend, None);
    let written = engine.layout.read_config().unwrap();
    engine.backends = vec![Box::new(FakeBackend::available(BackendKind::Seatbelt))];
    let report = done(engine.init(&alice(), Confirm::Yes).unwrap());
    assert_eq!(report.default_backend, Some(BackendKind::Seatbelt));
    assert!(report.unavailable.is_empty());
    assert_eq!(
        report.config_backend,
        Some(ConfigBackend::Written(BackendKind::Seatbelt))
    );
    assert_eq!(
        engine.layout.read_config().unwrap(),
        crate::config::initial(Some(BackendKind::Seatbelt))
    );
    assert_ne!(engine.layout.read_config().unwrap(), written);
    // Named now: nothing to say.
    let report = done(engine.init(&alice(), Confirm::Yes).unwrap());
    assert_eq!(report.config_backend, None);

    // Changed by hand: said, and left as it is.
    let mine = "# mine\nschema_version = 1\n";
    std::fs::write(engine.layout.config_file(), mine).unwrap();
    let report = done(engine.init(&alice(), Confirm::Yes).unwrap());
    assert_eq!(
        report.config_backend,
        Some(ConfigBackend::NotNamed(BackendKind::Seatbelt))
    );
    assert_eq!(engine.layout.read_config().unwrap(), mine);

    // Not TOML: said why, and init still succeeds.
    std::fs::write(engine.layout.config_file(), "not = [toml").unwrap();
    let report = done(engine.init(&alice(), Confirm::Yes).unwrap());
    let Some(ConfigBackend::Unchecked(why)) = &report.config_backend else {
        panic!("{report:?}");
    };
    assert!(why.contains("does not parse"), "{why}");
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

#[cfg(target_os = "linux")]
mod bubblewrap;
mod compile;
mod dashboard;
mod doctor;
mod exec;
mod history;
/// The runtime's own service, whose port the sandbox's sessions reach (ADR
/// 0028). The stand-in gateways are `perl`.
mod listener;
mod pending;
mod policy;
mod proxy_socket;
mod runtime;
mod sandbox;
mod secrets;
mod services;
mod state_check;
mod status;
mod unenforced;
