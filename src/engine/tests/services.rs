//! A sandbox's services under the service manager (ADR 0021).

use std::cell::RefCell;
use std::rc::Rc;
use std::time::Duration;

use super::*;
use crate::audit::{AuditError, AuditTicket};
use crate::engine::ServiceWait;
use crate::engine::listener::ServiceTimes;
use crate::engine::service::Unit;
use crate::model::audit::{AuditEntry, AuditFilter, Intent, VerifyReport};
use crate::model::plan::Planned;
use crate::model::runtime::RuntimeKind;
use crate::model::sandbox::SandboxState;
use crate::model::session::SessionKind;
use crate::runtime::ServiceName;
use crate::service::fake::FakeServices;
use crate::service::{ServiceLabel, ServiceStatus};
use crate::state::{StateError, StateLock};

const GATEWAY: ServiceName = ServiceName::new("gateway");

pub(super) fn sandbox_with_services(
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

/// `connect`'s wait, in milliseconds rather than a minute.
const QUICK: ServiceTimes = ServiceTimes {
    start: Duration::from_millis(600),
    gone: Duration::from_millis(200),
    poll: Duration::from_millis(20),
};

/// A Hermes sandbox whose runtime's files are there.
pub(super) fn hermes_with_services() -> (TempDir, Engine, Rc<FakeServices>, SandboxName) {
    let (dir, engine, fake, name) = sandbox_with_services(Some(RuntimeKind::Hermes));
    let home = engine.layout.sandbox_home(name.as_str());
    std::fs::create_dir_all(home.join(".hermes/hermes-agent")).unwrap();
    (dir, engine, fake, name)
}

fn wait_for_gateway(engine: &Engine, name: &SandboxName) -> (ServiceWait, Vec<String>) {
    let mut said = Vec::new();
    let waited = engine
        .start_listener_service_in(&alice(), name, &mut |what| said.push(what), QUICK)
        .unwrap()
        .expect("a gateway to wait for");
    (waited, said)
}

fn dry_run(engine: &Engine, name: &SandboxName) -> Vec<String> {
    let planned = engine
        .connect(&alice(), name, Vec::new(), Confirm::DryRun)
        .unwrap();
    let Planned::DryRun(plan) = planned else {
        panic!("a dry run ran");
    };
    plan.changes
}

/// Nothing of the sandbox installed: `connect` installs its services,
/// says so before it waits, and gives up early when no gateway session
/// opens, connecting anyway (ADR 0028).
#[test]
fn connect_starts_the_services_when_none_are_installed() {
    let (_dir, engine, _fake, name) = hermes_with_services();
    let plan = dry_run(&engine, &name);
    assert!(
        plan.iter()
            .any(|c| c.starts_with("start the services of sandbox home")),
        "{plan:?}"
    );
    // The proxy is the services' to start.
    assert!(
        !plan.iter().any(|c| c.contains("start the proxy")),
        "{plan:?}"
    );

    let begun = std::time::Instant::now();
    let (waited, said) = wait_for_gateway(&engine, &name);
    assert!(waited.started, "{waited:?}");
    assert_eq!(waited.late.as_deref(), Some("the gateway is not running"));
    // Given up at `gone`, not `start`.
    assert!(begun.elapsed() < QUICK.start, "{:?}", begun.elapsed());
    assert!(
        said[0].starts_with("starting the services of sandbox home"),
        "{said:?}"
    );
    assert!(said[0].contains("at each login until `enclos sandbox stop home`"));
    assert_eq!(
        said[1],
        "waiting for the gateway of sandbox home to listen…"
    );
    let started = labels_of(&engine.service_status(&name).unwrap());
    assert!(
        started.iter().any(|l| l.ends_with(".gateway")),
        "{started:?}"
    );
}

/// Installed already, the services are the service manager's to start
/// again: `connect` waits, and installs nothing, which would stop the
/// proxy open sessions use.
#[test]
fn connect_waits_for_installed_services_and_starts_nothing() {
    let (_dir, engine, fake, name) = hermes_with_services();
    engine.start_sandbox(&alice(), &name).unwrap();
    let installed = fake.started.borrow().len();
    let stopped = fake.stopped.borrow().len();
    assert_eq!(
        dry_run(&engine, &name),
        [
            "wait for the gateway of sandbox home to listen".to_owned(),
            format!("run `{}` in sandbox home under policy v1", default_shell())
        ]
    );
    let (waited, said) = wait_for_gateway(&engine, &name);
    assert!(!waited.started, "{waited:?}");
    assert_eq!(waited.late.as_deref(), Some("the gateway is not running"));
    assert_eq!(said, ["waiting for the gateway of sandbox home to listen…"]);
    assert_eq!(fake.started.borrow().len(), installed);
    assert_eq!(fake.stopped.borrow().len(), stopped);
}

/// A manager that reads another folder than this shell lists nothing here,
/// and its units keep running: `stop` says so rather than saying it stopped.
#[test]
fn stopping_a_running_sandbox_whose_manager_looks_elsewhere_fails() {
    let (_dir, engine, fake, name) = sandbox_with_services(None);
    engine.start_sandbox(&alice(), &name).unwrap();
    fake.started.borrow_mut().clear();
    *fake.refuse_list.borrow_mut() = true;
    let err = engine
        .stop_sandbox(&alice(), &name, Confirm::Yes)
        .err()
        .unwrap();
    assert!(err.to_string().contains("looks elsewhere"), "{err}");
    assert_eq!(state_of(&engine, &name), SandboxState::Running);
}

#[test]
fn a_stopped_sandbox_with_nothing_installed_does_not_ask_the_manager() {
    let (_dir, engine, fake, name) = sandbox_with_services(None);
    *fake.refuse_list.borrow_mut() = true;
    assert!(engine.installed_labels(&name).unwrap().is_empty());
}

/// A limit no program could start under refuses the start before any
/// service is removed or installed.
#[cfg(target_os = "macos")]
#[test]
fn a_start_under_a_limit_no_program_could_run_under_installs_nothing() {
    let (_dir, engine, fake, name) = sandbox_with_services(None);
    let most = crate::backend::max_files_per_process().unwrap();
    if most >= 1 << 20 {
        return;
    }
    let before = engine.layout.read_policy(name.as_str()).unwrap();
    let after = format!("{before}\n[resources]\nopen_files = {}\n", most + 1);
    // Refused as the policy is stored.
    let err = engine
        .policy_edit(&alice(), &name, &before, &after, Confirm::Yes)
        .unwrap_err();
    assert!(
        err.exit_code() == 2 && err.to_string().contains("kern.maxfilesperproc"),
        "{err}"
    );
    // And at start, for one stored past that, as by another build or on
    // a host whose ceiling was higher.
    let id = engine.policy(&name).unwrap().snapshot.id;
    let conn = rusqlite::Connection::open(engine.layout.state_db()).unwrap();
    conn.execute(
        "UPDATE policy_snapshots SET policy = json_set(policy, '$.resources.open_files', ?1) WHERE id = ?2",
        rusqlite::params![(most + 1) as i64, id.0],
    )
    .unwrap();
    let err = engine.start_sandbox(&alice(), &name).unwrap_err();
    assert!(err.to_string().contains("kern.maxfilesperproc"), "{err}");
    assert!(fake.started.borrow().is_empty());
    assert!(fake.stopped.borrow().is_empty());
}

/// A sandbox started before its runtime was installed: its proxy
/// service and no gateway service.
fn only_the_proxy_installed() -> (TempDir, Engine, Rc<FakeServices>, SandboxName) {
    let (dir, engine, fake, name) = sandbox_with_services(None);
    engine.start_sandbox(&alice(), &name).unwrap();
    engine
        .write(
            &alice(),
            "test",
            None,
            |_| String::new(),
            |lock| {
                let mut record = engine.state.get(&name)?.unwrap();
                record.runtime = Some(RuntimeKind::Hermes);
                Ok(engine.state.put(lock, &record)?)
            },
        )
        .unwrap();
    let home = engine.layout.sandbox_home(name.as_str());
    std::fs::create_dir_all(home.join(".hermes/hermes-agent")).unwrap();
    let installed = labels_of(&engine.service_status(&name).unwrap());
    assert!(
        installed.iter().any(|l| l.ends_with(".proxy"))
            && !installed.iter().any(|l| l.ends_with(".gateway")),
        "{installed:?}"
    );
    (dir, engine, fake, name)
}

/// A sleep stands in for the proxy service's job, recorded as the
/// sandbox's running proxy; stopping the service ends it.
fn proxy_service_running(engine: &Engine, fake: &FakeServices, name: &SandboxName) {
    let label = engine.label(name, Unit::Proxy).unwrap();
    let job = std::process::Command::new("/bin/sleep")
        .arg("30")
        .spawn()
        .unwrap();
    let root = crate::lifecycle::process::reference(job.id())
        .unwrap()
        .unwrap();
    fake.jobs.borrow_mut().push((label, job));
    engine
        .write(
            &alice(),
            "test",
            None,
            |_| String::new(),
            |lock| {
                let (version, snapshot) = engine.state.active_policy(name)?.unwrap();
                let session = crate::model::session::SessionRecord {
                    id: crate::model::session::SessionId(0),
                    sandbox: name.clone(),
                    kind: SessionKind::Proxy,
                    service: None,
                    version: version.version,
                    snapshot: snapshot.id,
                    compiled: None,
                    pgid: None,
                    root: root.clone(),
                    cgroup: None,
                    tracked: Vec::new(),
                    started_at: crate::model::now(),
                    ended_at: None,
                };
                Ok(engine.state.put_session(lock, &session)?)
            },
        )
        .unwrap();
}

/// Nothing would ever start the gateway of a sandbox with only its proxy
/// service, so `connect` starts the services, says beforehand that its
/// running proxy starts again and cuts the open sessions' connections,
/// and installs the gateway's service.
#[test]
fn connect_starts_the_services_when_only_the_proxy_is_installed() {
    let (_dir, engine, fake, name) = only_the_proxy_installed();
    proxy_service_running(&engine, &fake, &name);

    let plan = dry_run(&engine, &name);
    assert!(
        plan[0].starts_with("start the services of sandbox home"),
        "{plan:?}"
    );
    assert!(
        plan[1].contains("cuts the connections of its open sessions"),
        "{plan:?}"
    );
    let (waited, said) = wait_for_gateway(&engine, &name);
    assert!(waited.started, "{waited:?}");
    assert!(
        said[0].starts_with("starting the services of sandbox home")
            && said[0].contains("the connections of its open sessions are cut"),
        "{said:?}"
    );
    let proxy = engine.label(&name, Unit::Proxy).unwrap();
    assert!(fake.stopped.borrow().contains(&proxy));
    let installed = labels_of(&engine.service_status(&name).unwrap());
    assert!(
        installed.iter().any(|l| l.ends_with(".gateway")),
        "{installed:?}"
    );
    assert!(
        fake.started
            .borrow()
            .iter()
            .any(|u| u.label.as_str().ends_with(".gateway"))
    );
}

/// A start that fails before the proxy service is removed says nothing
/// of it: it is still there.
#[test]
fn a_failed_start_that_kept_the_proxy_service_does_not_say_it_is_gone() {
    let (_dir, engine, fake, name) = only_the_proxy_installed();
    *fake.refuse_stop.borrow_mut() = Some(".proxy".to_owned());
    let (waited, _) = wait_for_gateway(&engine, &name);
    assert!(!waited.started, "{waited:?}");
    let late = waited.late.unwrap();
    assert!(late.starts_with("its services could not start:"), "{late}");
    assert!(!late.contains("proxy service was removed"), "{late}");
    let installed = labels_of(&engine.service_status(&name).unwrap());
    assert!(
        installed.iter().any(|l| l.ends_with(".proxy")),
        "{installed:?}"
    );
}

/// A start that fails removes every service it replaced: the session is
/// told that the proxy service is gone too, and how to get it back.
#[test]
fn a_failed_start_says_the_proxy_service_it_replaced_is_gone() {
    let (_dir, engine, fake, name) = only_the_proxy_installed();
    *fake.refuse.borrow_mut() = Some(".gateway".to_owned());
    let (waited, _) = wait_for_gateway(&engine, &name);
    assert!(!waited.started, "{waited:?}");
    let late = waited.late.unwrap();
    assert!(late.starts_with("its services could not start:"), "{late}");
    assert!(
        late.contains("its proxy service was removed with them")
            && late.contains("`enclos sandbox start home`"),
        "{late}"
    );
    assert!(
        labels_of(&engine.service_status(&name).unwrap()).is_empty(),
        "the proxy service is still installed"
    );
}

/// A start that fails is no reason not to connect: it is said, and the
/// session goes ahead.
#[test]
fn a_failed_start_is_a_note_not_an_error() {
    let (_dir, engine, fake, name) = hermes_with_services();
    *fake.refuse.borrow_mut() = Some(".gateway".to_owned());
    let (waited, _) = wait_for_gateway(&engine, &name);
    assert!(!waited.started, "{waited:?}");
    let late = waited.late.unwrap();
    assert!(late.starts_with("its services could not start:"), "{late}");
    assert!(late.contains("refused"), "{late}");
}

#[test]
fn connect_starts_nothing_for_a_runtime_whose_files_are_gone() {
    // Recorded, but `.hermes/hermes-agent` is not in the home: its
    // gateway could not run, so nothing is started or waited for.
    let (_dir, engine, fake, name) = sandbox_with_services(Some(RuntimeKind::Hermes));
    let got = engine.start_listener_service_in(&alice(), &name, &mut |_| {}, QUICK);
    assert_eq!(got.unwrap(), None);
    assert!(fake.started.borrow().is_empty());
    assert!(
        !dry_run(&engine, &name)
            .iter()
            .any(|c| c.contains("gateway"))
    );
}

/// Whether the runtime is there cannot be told: nothing is started, and
/// the session is told why.
#[test]
fn connect_starts_nothing_when_the_runtimes_files_cannot_be_read() {
    let (_dir, engine, fake, name) = sandbox_with_services(Some(RuntimeKind::Hermes));
    let home = engine.layout.sandbox_home(name.as_str());
    std::fs::create_dir_all(home.join(".hermes")).unwrap();
    std::os::unix::fs::symlink("/tmp", home.join(".hermes/hermes-agent")).unwrap();
    let (waited, said) = wait_for_gateway(&engine, &name);
    assert!(!waited.started && said.is_empty(), "{waited:?} {said:?}");
    let late = waited.late.unwrap();
    assert!(
        late.starts_with("whether hermes is installed cannot be told"),
        "{late}"
    );
    assert!(fake.started.borrow().is_empty());
    let plan = dry_run(&engine, &name);
    assert!(
        plan[0].starts_with("leave the gateway of sandbox home as it is, since whether hermes"),
        "{plan:?}"
    );
}

fn labels_of(status: &[(ServiceLabel, ServiceStatus)]) -> Vec<String> {
    status.iter().map(|(l, _)| l.to_string()).collect()
}

/// A gateway whose session is open but which binds its listener only a
/// second later, as one still starting: a `connect` then waits for it,
/// and never starts the services again, which would stop it (ADR 0028).
#[test]
fn connect_waits_for_a_gateway_still_starting_and_starts_nothing() {
    let (_dir, engine, fake, name) = sandbox_with_services(Some(RuntimeKind::Hermes));
    let home = engine.layout.sandbox_home(name.as_str());
    std::fs::create_dir_all(home.join(".hermes/hermes-agent")).unwrap();
    let mut gateway = std::process::Command::new("/usr/bin/perl")
        .args([
            "-MSocket",
            "-e",
            &format!(
                "{}sleep 1; my $s = listener(INADDR_LOOPBACK); sleep 30",
                crate::test_ports::perl_listener()
            ),
        ])
        .spawn()
        .unwrap();
    let root = crate::lifecycle::process::reference_of_child(&gateway).unwrap();
    engine
        .write(
            &alice(),
            "test",
            None,
            |_| String::new(),
            |lock| {
                let record = engine.state.get(&name)?.unwrap();
                let session = SessionRecord {
                    id: crate::model::session::SessionId(0),
                    sandbox: name.clone(),
                    kind: SessionKind::Service,
                    service: Some(GATEWAY.as_str().to_owned()),
                    version: 1,
                    snapshot: engine.policy(&name)?.snapshot.id,
                    compiled: None,
                    root,
                    pgid: None,
                    cgroup: None,
                    tracked: Vec::new(),
                    started_at: crate::model::now(),
                    ended_at: None,
                };
                engine.state.start_session(lock, &session, &record)?;
                Ok(())
            },
        )
        .unwrap();
    let waited = engine.start_listener_service(&alice(), &name, &mut |_| {});
    let _ = gateway.kill();
    let _ = gateway.wait();
    let waited = waited.unwrap().expect("it listened only after the look");
    assert!(!waited.started, "{waited:?}");
    assert_eq!(waited.late, None);
    assert!(fake.started.borrow().is_empty());
    assert!(fake.stopped.borrow().is_empty());
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
    assert!(args.contains(&port.to_string()), "{args:?}");
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
        // That alone: never the comparison baseline (ADR 0006).
        assert_eq!(unit.env, engine.layout.env(), "{}", unit.label);
        assert!(
            unit.env
                .iter()
                .all(|(k, _)| k != crate::backend::seatbelt::BASELINE_VAR)
        );
    }
}

/// The keychain file `ENCLOS_KEYCHAIN` named reaches the services, which
/// read their secrets from it: their value, never.
#[test]
fn services_reach_the_keychain_of_the_enclos_that_started_them() {
    let (_dir, engine, fake, name) = sandbox_with_services(Some(RuntimeKind::Hermes));
    let engine = engine.with_secrets(Box::new(crate::secrets::keychain::Keychain::new(
        "enclos.test".into(),
        Some("/Users/alice/test.keychain-db".into()),
    )));
    engine.start_sandbox(&alice(), &name).unwrap();
    let mut expected = engine.layout.env();
    expected.push((
        "ENCLOS_KEYCHAIN".to_owned(),
        "/Users/alice/test.keychain-db".to_owned(),
    ));
    for unit in fake.started.borrow().iter() {
        assert_eq!(unit.env, expected, "{}", unit.label);
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

/// The command, result and message of each audit entry from index
/// `from` on; panics on an entry left open or about another target.
fn entries_after(engine: &Engine, from: usize) -> Vec<(String, AuditResult, String)> {
    engine.audit(None).unwrap()[from..]
        .iter()
        .map(|e| {
            assert_eq!(e.intent.target.as_deref(), Some("home"), "{e:?}");
            let outcome = &e.finished.as_ref().expect("a closed entry").outcome;
            (
                e.intent.command.clone(),
                outcome.result,
                outcome.message.clone(),
            )
        })
        .collect()
}

/// The audit log, except that entries of the commands listed in
/// `refused` cannot be opened, as when the disk is full.
struct RefusingAudit {
    inner: JsonlAuditLog,
    refused: Rc<RefCell<Vec<&'static str>>>,
}

impl AuditLog for RefusingAudit {
    fn begin<'l>(
        &self,
        lock: &'l StateLock,
        intent: Intent,
    ) -> crate::audit::Result<AuditTicket<'l>> {
        if self.refused.borrow().contains(&intent.command.as_str()) {
            return Err(AuditError::Io {
                path: "audit.jsonl".into(),
                source: std::io::Error::other("disk full"),
            });
        }
        self.inner.begin(lock, intent)
    }

    fn finish(&self, ticket: AuditTicket<'_>, outcome: Outcome) -> crate::audit::Result<()> {
        self.inner.finish(ticket, outcome)
    }

    fn entries(&self, filter: &AuditFilter) -> crate::audit::Result<Vec<AuditEntry>> {
        self.inner.entries(filter)
    }

    fn verify(&self) -> crate::audit::Result<VerifyReport> {
        self.inner.verify()
    }

    fn check(&self) -> crate::audit::Result<()> {
        self.inner.check()
    }
}

/// Gives the engine an audit log that refuses the commands in the list
/// returned, empty at first.
fn refusing_audit(engine: &mut Engine) -> Rc<RefCell<Vec<&'static str>>> {
    let refused = Rc::default();
    engine.audit = Box::new(RefusingAudit {
        inner: JsonlAuditLog::new(engine.layout.audit_log()),
        refused: Rc::clone(&refused),
    });
    refused
}

#[test]
fn a_restart_and_a_stop_record_their_removals_in_order() {
    let (_dir, engine, _fake, name) = sandbox_with_services(Some(RuntimeKind::Hermes));
    let [proxy, gateway] =
        [Unit::Proxy, Unit::Runtime(GATEWAY)].map(|u| engine.label(&name, u).unwrap());
    engine.start_sandbox(&alice(), &name).unwrap();

    let from = engine.audit(None).unwrap().len();
    engine.start_sandbox(&alice(), &name).unwrap();
    assert_eq!(
        entries_after(&engine, from),
        [
            (
                "services remove".to_owned(),
                AuditResult::Ok,
                format!("removing {gateway}, {proxy} before sandbox start")
            ),
            (
                "services removed".to_owned(),
                AuditResult::Ok,
                format!("removed {gateway}, {proxy}")
            ),
            (
                "sandbox start".to_owned(),
                AuditResult::Ok,
                format!("{proxy}, {gateway}")
            ),
        ]
    );

    let from = engine.audit(None).unwrap().len();
    done(engine.stop_sandbox(&alice(), &name, Confirm::Yes).unwrap());
    assert_eq!(
        entries_after(&engine, from),
        [
            (
                "services remove".to_owned(),
                AuditResult::Ok,
                format!("removing {gateway}, {proxy} for sandbox stop")
            ),
            (
                "services removed".to_owned(),
                AuditResult::Ok,
                format!("removed {gateway}, {proxy}")
            ),
            (
                "sandbox stop".to_owned(),
                AuditResult::Ok,
                "removed 2 services, stopped 0 sessions".to_owned()
            ),
        ]
    );
    assert!(engine.verify_audit().unwrap().intact());
}

#[test]
fn a_stop_or_start_whose_first_entry_cannot_be_written_removes_nothing() {
    let (_dir, mut engine, fake, name) = sandbox_with_services(Some(RuntimeKind::Hermes));
    engine.start_sandbox(&alice(), &name).unwrap();
    let from = engine.audit(None).unwrap().len();
    refusing_audit(&mut engine)
        .borrow_mut()
        .push("services remove");

    let err = engine
        .stop_sandbox(&alice(), &name, Confirm::Yes)
        .unwrap_err();
    assert!(matches!(err, Error::Audit(_)), "{err:?}");
    let err = engine.start_sandbox(&alice(), &name).unwrap_err();
    assert!(matches!(err, Error::Audit(_)), "{err:?}");
    assert_eq!(fake.started.borrow().len(), 2);
    assert!(fake.stopped.borrow().is_empty());
    assert_eq!(state_of(&engine, &name), SandboxState::Running);
    assert_eq!(entries_after(&engine, from), []);
}

#[test]
fn a_stop_whose_removal_fails_part_way_records_what_was_removed_and_what_is_left() {
    let (_dir, engine, fake, name) = sandbox_with_services(Some(RuntimeKind::Hermes));
    let [proxy, gateway] =
        [Unit::Proxy, Unit::Runtime(GATEWAY)].map(|u| engine.label(&name, u).unwrap());
    engine.start_sandbox(&alice(), &name).unwrap();
    let from = engine.audit(None).unwrap().len();

    *fake.refuse_stop.borrow_mut() = Some(".proxy".to_owned());
    let err = engine
        .stop_sandbox(&alice(), &name, Confirm::Yes)
        .unwrap_err();
    assert!(matches!(err, Error::Service(_)), "{err:?}");
    assert!(err.to_string().contains("would not stop"), "{err}");
    assert_eq!(
        entries_after(&engine, from),
        [
            (
                "services remove".to_owned(),
                AuditResult::Ok,
                format!("removing {gateway}, {proxy} for sandbox stop")
            ),
            (
                "services removed".to_owned(),
                AuditResult::Failed,
                format!(
                    "removed {gateway}; could not remove {proxy}: would not stop {proxy}; still installed: {proxy}"
                )
            ),
        ]
    );
    assert!(engine.verify_audit().unwrap().intact());
}

#[test]
fn a_removal_that_fails_and_cannot_be_recorded_says_both() {
    let (_dir, mut engine, fake, name) = sandbox_with_services(Some(RuntimeKind::Hermes));
    let [proxy, gateway] =
        [Unit::Proxy, Unit::Runtime(GATEWAY)].map(|u| engine.label(&name, u).unwrap());
    engine.start_sandbox(&alice(), &name).unwrap();
    let from = engine.audit(None).unwrap().len();
    refusing_audit(&mut engine)
        .borrow_mut()
        .push("services removed");

    *fake.refuse_stop.borrow_mut() = Some(".proxy".to_owned());
    let err = engine
        .stop_sandbox(&alice(), &name, Confirm::Yes)
        .unwrap_err();
    assert!(matches!(err, Error::Unrecorded { .. }), "{err:?}");
    let text = err.to_string();
    assert!(
        text.starts_with(&format!(
            "would not stop {proxy}, but the audit log could not record it: "
        )),
        "{text}"
    );
    assert!(text.contains("disk full"), "{text}");
    assert_eq!(
        entries_after(&engine, from),
        [(
            "services remove".to_owned(),
            AuditResult::Ok,
            format!("removing {gateway}, {proxy} for sandbox stop")
        )]
    );
    assert!(engine.verify_audit().unwrap().intact());
}

#[test]
fn a_failed_start_records_the_removal_that_undoes_it() {
    let (_dir, engine, fake, name) = sandbox_with_services(Some(RuntimeKind::Hermes));
    let proxy = engine.label(&name, Unit::Proxy).unwrap();
    let from = engine.audit(None).unwrap().len();

    // The proxy is installed, then the gateway is refused.
    *fake.refuse.borrow_mut() = Some(".gateway".to_owned());
    engine.start_sandbox(&alice(), &name).unwrap_err();
    let entries = entries_after(&engine, from);
    assert_eq!(entries.len(), 3, "{entries:?}");
    assert_eq!(entries[0].0, "sandbox start");
    assert_eq!(entries[0].1, AuditResult::Failed);
    assert_eq!(
        entries[1..],
        [
            (
                "services remove".to_owned(),
                AuditResult::Ok,
                format!("removing {proxy} after a failed sandbox start")
            ),
            (
                "services removed".to_owned(),
                AuditResult::Ok,
                format!("removed {proxy}")
            ),
        ]
    );

    // An undo that fails is recorded too.
    let from = engine.audit(None).unwrap().len();
    *fake.refuse_stop.borrow_mut() = Some(".proxy".to_owned());
    engine.start_sandbox(&alice(), &name).unwrap_err();
    let entries = entries_after(&engine, from);
    assert_eq!(entries.len(), 3, "{entries:?}");
    assert_eq!(entries[0].0, "sandbox start");
    assert_eq!(entries[0].1, AuditResult::Failed);
    assert_eq!(
        entries[1..],
        [
            (
                "services remove".to_owned(),
                AuditResult::Ok,
                format!("removing {proxy} after a failed sandbox start")
            ),
            (
                "services removed".to_owned(),
                AuditResult::Failed,
                format!(
                    "removed none; could not remove {proxy}: would not stop {proxy}; still installed: {proxy}"
                )
            ),
        ]
    );
    assert!(engine.verify_audit().unwrap().intact());
}

#[test]
fn a_failed_start_removes_what_it_installed_even_when_that_cannot_be_recorded() {
    let (_dir, mut engine, fake, name) = sandbox_with_services(Some(RuntimeKind::Hermes));
    let proxy = engine.label(&name, Unit::Proxy).unwrap();
    let refused = refusing_audit(&mut engine);
    *fake.refuse.borrow_mut() = Some(".gateway".to_owned());

    // Without its first entry, the second records the whole removal.
    refused.borrow_mut().push("services remove");
    let from = engine.audit(None).unwrap().len();
    let err = engine.start_sandbox(&alice(), &name).unwrap_err();
    assert!(matches!(err, Error::Service(_)), "{err:?}");
    assert!(
        fake.started.borrow().is_empty(),
        "the proxy stayed installed"
    );
    let entries = entries_after(&engine, from);
    assert_eq!(entries.len(), 2, "{entries:?}");
    assert_eq!(entries[0].0, "sandbox start");
    assert_eq!(entries[0].1, AuditResult::Failed);
    assert_eq!(
        entries[1],
        (
            "services removed".to_owned(),
            AuditResult::Ok,
            format!("removed {proxy}")
        )
    );

    // Without either, the error says the cleanup worked.
    refused.borrow_mut().push("services removed");
    let from = engine.audit(None).unwrap().len();
    let err = engine.start_sandbox(&alice(), &name).unwrap_err();
    let Error::CleanupUnrecorded { error, .. } = &err else {
        panic!("{err:?}");
    };
    assert!(matches!(**error, Error::Service(_)), "{error:?}");
    assert!(
        fake.started.borrow().is_empty(),
        "the proxy stayed installed"
    );
    let text = err.to_string();
    assert!(
        text.contains(&format!(
            "; cleaning up after it removed {proxy}, but the audit log could not record that: "
        )),
        "{text}"
    );
    assert!(!text.contains("failed too"), "{text}");
    let entries = entries_after(&engine, from);
    assert_eq!(entries.len(), 1, "{entries:?}");
    assert_eq!(entries[0].0, "sandbox start");
    assert!(engine.verify_audit().unwrap().intact());
}

#[test]
fn a_removal_whose_lock_then_times_out_leaves_the_entry_naming_it() {
    let (_dir, engine, fake, name) = sandbox_with_services(Some(RuntimeKind::Hermes));
    let [proxy, gateway] =
        [Unit::Proxy, Unit::Runtime(GATEWAY)].map(|u| engine.label(&name, u).unwrap());
    engine.start_sandbox(&alice(), &name).unwrap();
    let from = engine.audit(None).unwrap().len();

    // Another command takes the lock while the services are removed,
    // and keeps it past the wait.
    let other = SqliteStateStore::new(engine.layout.state_db(), engine.layout.state_lock());
    let held = Rc::new(RefCell::new(None));
    let holder = Rc::clone(&held);
    *fake.on_stop.borrow_mut() = Some(Box::new(move |_: &ServiceLabel| {
        if holder.borrow().is_none() {
            *holder.borrow_mut() = Some(other.lock().unwrap());
        }
    }));
    let err = engine
        .stop_sandbox(&alice(), &name, Confirm::Yes)
        .unwrap_err();
    // Every service is gone; only the record of it is missing.
    let Error::Unrecorded { what, audit } = &err else {
        panic!("{err:?}");
    };
    assert_eq!(*what, format!("removed {gateway}, {proxy}"));
    assert!(
        matches!(**audit, Error::State(StateError::Locked { .. })),
        "{audit:?}"
    );
    assert!(fake.started.borrow().is_empty());
    held.borrow_mut().take();
    // `sandbox stop` never ran, so the record still says running.
    assert_eq!(state_of(&engine, &name), SandboxState::Running);

    assert_eq!(
        entries_after(&engine, from),
        [(
            "services remove".to_owned(),
            AuditResult::Ok,
            format!("removing {gateway}, {proxy} for sandbox stop")
        )]
    );
    assert!(engine.verify_audit().unwrap().intact());
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
    stand_in_proxy(&engine, &name);
    assert!(engine.proxy_started(&name, Duration::ZERO).unwrap());
    let err = engine
        .proxy_started(&"nope".parse().unwrap(), Duration::ZERO)
        .unwrap_err();
    assert!(matches!(err, Error::NoSuchSandbox { .. }), "{err}");
}

/// Records this process as the sandbox's proxy, which it stands in for.
fn stand_in_proxy(engine: &Engine, name: &SandboxName) {
    let me = std::process::id();
    engine
        .write(
            &alice(),
            "test",
            None,
            |_| String::new(),
            |lock| {
                let (version, snapshot) = engine.state.active_policy(name)?.unwrap();
                let session = crate::model::session::SessionRecord {
                    id: crate::model::session::SessionId(0),
                    sandbox: name.clone(),
                    kind: SessionKind::Proxy,
                    service: None,
                    version: version.version,
                    snapshot: snapshot.id,
                    compiled: None,
                    pgid: None,
                    root: crate::lifecycle::process::reference(me)?.unwrap(),
                    cgroup: None,
                    tracked: Vec::new(),
                    started_at: crate::model::now(),
                    ended_at: None,
                };
                engine.state.put_session(lock, &session)?;
                Ok(())
            },
        )
        .unwrap();
}

#[test]
fn a_stop_counts_the_session_of_a_service_it_removed_as_stopped_not_gone() {
    let (_dir, engine, fake, name) = sandbox_with_services(None);
    let label = engine.label(&name, Unit::Proxy).unwrap();
    fake.seed(label.as_str());
    // A sleep stands in for the proxy service's job, which ends when its
    // service is removed, before the stop looks at the sessions.
    let job = std::process::Command::new("/bin/sleep")
        .arg("30")
        .spawn()
        .unwrap();
    let root = crate::lifecycle::process::reference(job.id())
        .unwrap()
        .unwrap();
    fake.jobs.borrow_mut().push((label.clone(), job));
    let id = engine
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
                    service: None,
                    version: version.version,
                    snapshot: snapshot.id,
                    compiled: None,
                    pgid: None,
                    root: root.clone(),
                    cgroup: None,
                    tracked: Vec::new(),
                    started_at: crate::model::now(),
                    ended_at: None,
                };
                Ok(engine.state.put_session(lock, &session)?)
            },
        )
        .unwrap();

    let Planned::DryRun(plan) = engine
        .stop_sandbox(&alice(), &name, Confirm::DryRun)
        .unwrap()
    else {
        panic!("a dry run stopped the sandbox");
    };
    assert!(
        plan.changes
            .contains(&format!("stop session {id} (proxy, 1 processes)")),
        "{plan:?}"
    );
    let report = done(engine.stop_sandbox(&alice(), &name, Confirm::Yes).unwrap());
    assert!(fake.jobs.borrow().is_empty());
    assert_eq!(report.services, [label]);
    assert_eq!(report.stopped, [id]);
    assert!(report.gone.is_empty() && report.survivors.is_empty());
    let entries = engine.audit(None).unwrap();
    let finished = entries.last().unwrap().finished.as_ref().unwrap();
    assert_eq!(
        finished.outcome.message,
        "removed 1 services, stopped 1 sessions"
    );
    assert_eq!(state_of(&engine, &name), SandboxState::Stopped);
}

#[test]
fn a_launch_that_fails_marks_the_sandbox_failed_in_its_audited_write() {
    use super::sandbox::{assert_failed_by, without_backend};
    let (_dir, engine, _, name) = sandbox_with_services(Some(RuntimeKind::Hermes));
    stand_in_proxy(&engine, &name);
    let ended = std::sync::atomic::AtomicBool::new(false);
    let err = without_backend(&engine)
        .launch_until(&alice(), &name, GATEWAY.as_str(), &ended)
        .unwrap_err();
    assert!(matches!(err, Error::BackendUnavailable { .. }), "{err}");
    assert_failed_by(&engine, &name, "launch");
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
