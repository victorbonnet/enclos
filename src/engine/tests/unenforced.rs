//! A field this host does not enforce, run not enforced only once accepted
//! (ADR 0038): `memory` on a bubblewrap sandbox, on a fake whose host has no
//! memory controller.

use super::services::sandbox_with_services_on;
use super::*;
use crate::model::sandbox::SandboxName;
use crate::model::unenforced::{Accepted, UnenforcedField};

const NO_CONTROLLER: &str = "this host's kernel has no memory controller";

/// An initialized engine with bubblewrap sandbox `home` on `backend`.
fn bubblewrap_sandbox(backend: FakeBackend) -> (TempDir, Engine, SandboxName) {
    let (dir, engine) = engine_with(vec![Box::new(backend)]);
    done(engine.init(&alice(), Confirm::Yes).unwrap());
    let name: SandboxName = "home".parse().unwrap();
    let spec = crate::engine::SandboxSpec {
        name: name.clone(),
        backend: BackendKind::Bubblewrap,
        template: "assistant".parse().unwrap(),
    };
    done(engine.create_sandbox(&alice(), spec, Confirm::Yes).unwrap());
    (dir, engine, name)
}

fn on_a_host_without_the_memory_controller() -> (TempDir, Engine, SandboxName) {
    bubblewrap_sandbox(
        FakeBackend::available(BackendKind::Bubblewrap).without_memory_controller(NO_CONTROLLER),
    )
}

/// The sandbox's `policy.toml` with `memory` set to `value`.
fn edit_memory(engine: &Engine, name: &SandboxName, value: &str) -> Result<()> {
    let before = engine.layout.read_policy(name.as_str()).unwrap();
    let after = format!("{before}\n[resources]\nmemory = \"{value}\"\n");
    engine
        .policy_edit(&alice(), name, &before, &after, Confirm::Ask)
        .map(|_| ())
}

fn accepting(engine: Engine) -> Engine {
    engine.accepting_unenforced(vec![UnenforcedField::Memory])
}

fn entries(engine: &Engine, command: &str) -> Vec<crate::model::audit::AuditEntry> {
    let all = engine.audit(None).unwrap();
    all.into_iter()
        .filter(|e| e.intent.command == command)
        .collect()
}

#[test]
fn a_memory_limit_the_host_does_not_hold_is_refused_without_an_acceptance() {
    let (_dir, engine, name) = on_a_host_without_the_memory_controller();
    let err = edit_memory(&engine, &name, "1G").unwrap_err();
    assert_eq!(err.exit_code(), 2, "{err}");
    let said = err.to_string();
    assert!(said.contains("resources.memory = 1G"), "{said}");
    assert!(said.contains(NO_CONTROLLER), "{said}");
    assert!(said.contains("--accept-unenforced memory"), "{said}");
    assert_eq!(engine.policy(&name).unwrap().version.version, 1);
    assert!(engine.state.acceptances(&name).unwrap().is_empty());
}

#[test]
fn an_acceptance_is_recorded_and_audited_with_the_policy_it_is_for() {
    let (_dir, engine, name) = on_a_host_without_the_memory_controller();
    let engine = accepting(engine);
    edit_memory(&engine, &name, "1G").unwrap();
    assert_eq!(engine.policy(&name).unwrap().version.version, 2);
    let kept = engine.state.acceptances(&name).unwrap();
    assert_eq!(kept.len(), 1);
    assert_eq!(
        (kept[0].field, kept[0].value.as_str()),
        (UnenforcedField::Memory, "1G")
    );
    assert_eq!(kept[0].why, NO_CONTROLLER);
    let accepted = entries(&engine, "accept-unenforced");
    assert_eq!(accepted.len(), 1);
    assert_eq!(accepted[0].intent.target.as_deref(), Some("home"));
    let message = &accepted[0].finished.as_ref().unwrap().outcome.message;
    for part in [
        "resources.memory = 1G",
        "sandbox home",
        "policy v2",
        NO_CONTROLLER,
    ] {
        assert!(message.contains(part), "{part}: {message}");
    }
}

/// Kept with the sandbox at its value: a change that keeps it needs no
/// acceptance; one that changes it needs another.
#[test]
fn an_acceptance_holds_until_the_value_changes() {
    let (_dir, engine, name) = on_a_host_without_the_memory_controller();
    let engine = accepting(engine);
    edit_memory(&engine, &name, "1G").unwrap();
    let engine = engine.accepting_unenforced(Vec::new());
    done(
        engine
            .policy_allow(&alice(), &name, "api.example.com", Confirm::Ask)
            .unwrap(),
    );
    assert_eq!(entries(&engine, "accept-unenforced").len(), 1);
    let before = engine.layout.read_policy(name.as_str()).unwrap();
    let after = before.replace("memory = \"1G\"", "memory = \"2G\"");
    let err = engine
        .policy_edit(&alice(), &name, &before, &after, Confirm::Ask)
        .unwrap_err();
    assert!(err.to_string().contains("resources.memory = 2G"), "{err}");
}

/// Not applied, so the sandbox's slice is not given it; the rest are.
#[test]
fn an_accepted_memory_limit_is_left_out_of_what_a_session_runs_under() {
    let (_dir, engine, name) = on_a_host_without_the_memory_controller();
    let engine = accepting(engine);
    let before = engine.layout.read_policy(name.as_str()).unwrap();
    let after =
        format!("{before}\n[resources]\nmemory = \"1G\"\ncpu = \"0.5\"\nopen_files = 256\n");
    engine
        .policy_edit(&alice(), &name, &before, &after, Confirm::Ask)
        .unwrap();
    let engine = engine.accepting_unenforced(Vec::new());
    let record = engine.record(&name).unwrap();
    let policy = engine.active_policy(&name).unwrap().1.policy;
    let limits = engine.launch_limits(&record, &policy).unwrap();
    assert_eq!(limits.memory(), None);
    assert_eq!(limits.cpu().map(|c| c.percent()), Some(50));
    assert_eq!(limits.open_files(), Some(256));
}

/// A host that held it when the policy was stored, and holds it no more:
/// each start refuses, naming the command that accepts it.
#[test]
fn a_start_with_no_acceptance_names_sandbox_start_to_accept_it() {
    let (dir, mut engine, name) =
        bubblewrap_sandbox(FakeBackend::available(BackendKind::Bubblewrap));
    edit_memory(&engine, &name, "1G").unwrap();
    let record = engine.record(&name).unwrap();
    let policy = engine.active_policy(&name).unwrap().1.policy;
    assert_eq!(
        engine.launch_limits(&record, &policy).unwrap().memory(),
        Some(1 << 30)
    );
    engine.backends = vec![Box::new(
        FakeBackend::available(BackendKind::Bubblewrap).without_memory_controller(NO_CONTROLLER),
    )];
    let err = engine.launch_limits(&record, &policy).unwrap_err();
    assert!(
        err.to_string()
            .contains("`enclos sandbox start home --accept-unenforced memory`"),
        "{err}"
    );
    let engine = accepting(engine);
    assert_eq!(
        engine.launch_limits(&record, &policy).unwrap().memory(),
        None
    );
    drop(dir);
}

/// Where the host holds it, nothing is asked and nothing recorded.
#[test]
fn a_host_that_holds_memory_asks_no_acceptance() {
    let (_dir, engine, name) = bubblewrap_sandbox(FakeBackend::available(BackendKind::Bubblewrap));
    edit_memory(&engine, &name, "1G").unwrap();
    assert!(engine.state.acceptances(&name).unwrap().is_empty());
    assert!(entries(&engine, "accept-unenforced").is_empty());
}

/// The sandbox's `policy.toml` with `memory` changed from `from` to `to`.
fn change_memory(engine: &Engine, name: &SandboxName, from: &str, to: &str) -> Result<()> {
    let before = engine.layout.read_policy(name.as_str()).unwrap();
    let after = before.replace(
        &format!("memory = \"{from}\""),
        &format!("memory = \"{to}\""),
    );
    engine
        .policy_edit(&alice(), name, &before, &after, Confirm::Ask)
        .map(|_| ())
}

fn held() -> FakeBackend {
    FakeBackend::available(BackendKind::Bubblewrap)
}

fn not_held() -> FakeBackend {
    held().without_memory_controller(NO_CONTROLLER)
}

/// The one assessment each start, `policy test` and `doctor` read: a
/// field accepted at its value, one never accepted, and one accepted at
/// another value, as when the host held it while the value changed.
#[test]
fn the_assessment_tells_accepted_missing_and_stale_apart() {
    let (_dir, mut engine, _fake, name) = sandbox_with_services_on(held(), None);
    edit_memory(&engine, &name, "1G").unwrap();
    let assessed = |engine: &Engine| {
        let policy = engine.active_policy(&name).unwrap().1.policy;
        engine
            .not_enforced(&name, BackendKind::Bubblewrap, &policy)
            .unwrap()
    };
    // Held here: nothing to report.
    assert!(assessed(&engine).is_empty());

    // The host lost the controller: not accepted.
    engine.backends = vec![Box::new(not_held())];
    let [missing] = <[_; 1]>::try_from(assessed(&engine)).unwrap();
    assert_eq!(missing.accepted, Accepted::Missing);
    assert_eq!(
        (missing.gap.value.as_str(), missing.gap.why.as_str()),
        ("1G", NO_CONTROLLER)
    );

    // Accepted at 1G by `sandbox start --accept-unenforced memory`.
    let engine = accepting(engine);
    engine.start_sandbox(&alice(), &name).unwrap();
    let mut engine = engine.accepting_unenforced(Vec::new());
    let [kept] = <[_; 1]>::try_from(assessed(&engine)).unwrap();
    assert!(
        matches!(&kept.accepted, Accepted::Kept(a) if a.value == "1G"),
        "{kept:?}"
    );

    // Changed to 2G while the host held it, then lost again: the
    // acceptance kept is for 1G only.
    engine.backends = vec![Box::new(held())];
    change_memory(&engine, &name, "1G", "2G").unwrap();
    engine.backends = vec![Box::new(not_held())];
    let [stale] = <[_; 1]>::try_from(assessed(&engine)).unwrap();
    assert!(
        matches!(&stale.accepted, Accepted::Stale(a) if a.value == "1G"),
        "{stale:?}"
    );
    // And a start says so.
    let err = engine.check_start_limits(&name).unwrap_err().to_string();
    assert!(err.contains("resources.memory = 2G"), "{err}");
    assert!(
        err.contains("The acceptance kept is for resources.memory = 1G"),
        "{err}"
    );
}

/// `sandbox start` says each field not applied in the foreground, once
/// its services are installed: here a sandbox with no runtime, so no
/// session of its own would say it.
#[test]
fn sandbox_start_says_what_is_not_applied_with_no_runtime() {
    let (_dir, engine, fake, name) = sandbox_with_services_on(not_held(), None);
    let engine = accepting(engine);
    edit_memory(&engine, &name, "1G").unwrap();
    let engine = engine.accepting_unenforced(Vec::new());
    let (started, said) = crate::notes::heard(|| engine.start_sandbox(&alice(), &name));
    let started = started.unwrap();
    assert_eq!(
        said,
        [format!(
            "sandbox home: resources.memory = 1G is not applied: {NO_CONTROLLER} (enclos doctor)"
        )]
    );
    let [n] = started.not_enforced.as_slice() else {
        panic!("{started:?}");
    };
    assert!(
        matches!(&n.accepted, Accepted::Kept(a) if a.value == "1G"),
        "{n:?}"
    );
    assert_eq!(started.labels.len(), fake.started.borrow().len());
    let entry = entries(&engine, "sandbox start").pop().unwrap();
    let message = entry.finished.unwrap().outcome.message;
    assert!(
        message.ends_with("; not enforced on this host: resources.memory (accepted)"),
        "{message}"
    );
}

/// With a runtime, whose service says it in its own log, the foreground
/// start says it too, once. Here the host lost the controller after the
/// policy was stored, and the start's `--accept-unenforced` accepts it.
#[test]
fn sandbox_start_says_what_is_not_applied_with_a_runtime_service() {
    let (_dir, mut engine, _fake, name) =
        sandbox_with_services_on(held(), Some(crate::model::runtime::RuntimeKind::Hermes));
    edit_memory(&engine, &name, "1G").unwrap();
    engine.backends = vec![Box::new(not_held())];
    let engine = accepting(engine);
    let (started, said) = crate::notes::heard(|| engine.start_sandbox(&alice(), &name));
    let started = started.unwrap();
    assert!(
        started
            .labels
            .iter()
            .any(|l| l.as_str().ends_with(".gateway")),
        "{started:?}"
    );
    let lines: Vec<&String> = said
        .iter()
        .filter(|s| s.contains("resources.memory = 1G is not applied"))
        .collect();
    assert_eq!(lines.len(), 1, "{said:?}");
    // Given by this command, and recorded by it.
    assert_eq!(engine.state.acceptances(&name).unwrap().len(), 1);
    assert_eq!(entries(&engine, "accept-unenforced").len(), 1);
}
