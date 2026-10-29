//! `enclos exec`: one command as a session of its own. Running it is shown
//! by the CLI test, under Seatbelt and with the sandbox's proxy.

use super::policy::with_sandbox;
use super::*;
use crate::model::session::SessionKind;

#[test]
fn exec_needs_a_command_and_its_dry_run_runs_nothing() {
    let (_dir, engine, name) = with_sandbox();
    let err = engine
        .exec(&alice(), &name, Vec::new(), Confirm::Yes)
        .unwrap_err();
    assert!(err.to_string().contains("after `--`"), "{err}");
    let planned = engine
        .exec(&alice(), &name, vec!["/bin/ls".into()], Confirm::DryRun)
        .unwrap();
    let Planned::DryRun(plan) = planned else {
        panic!("{planned:?}")
    };
    assert!(
        plan.changes.last().unwrap().starts_with("run `/bin/ls`"),
        "{plan:?}"
    );
    assert!(engine.state.sessions(&name, false).unwrap().is_empty());
}

#[test]
fn the_exec_kind_round_trips_through_its_name() {
    assert_eq!(SessionKind::Exec.as_str(), "exec");
    assert_eq!("exec".parse::<SessionKind>(), Ok(SessionKind::Exec));
}
