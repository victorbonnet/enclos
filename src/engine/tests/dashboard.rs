//! `enclos dashboard` where it has nothing to serve. CI's `bubblewrap` job
//! runs it for real (`tests/dashboard.rs`).

use std::sync::atomic::AtomicBool;

use super::policy::with_sandbox;
use super::*;
use crate::model::runtime::RuntimeKind;

/// A sandbox whose runtime's listeners the host reaches itself, as on
/// Seatbelt: no session starts, nothing is recorded, and `status` is named.
#[test]
fn a_sandbox_the_host_reaches_is_pointed_to_status_and_nothing_starts() {
    let (_dir, engine, name) = with_sandbox();
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
    let audited = engine.audit(None).unwrap().len();
    let mut opened = |_: &crate::engine::DashboardOpen| panic!("it served");
    let refused = engine
        .dashboard_until(&alice(), &name, &AtomicBool::new(false), &mut opened)
        .unwrap_err();
    let Error::Dashboard { what } = refused else {
        panic!("{refused}");
    };
    assert!(what.contains("`enclos status home`"), "{what}");
    assert!(engine.state.sessions(&name, true).unwrap().is_empty());
    assert_eq!(engine.audit(None).unwrap().len(), audited);
    assert!(!engine.layout.dashboard_lock("home").exists());
}
