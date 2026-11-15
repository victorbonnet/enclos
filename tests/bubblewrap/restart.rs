//! A settings restart of a bubblewrap sandbox's service (ADR 0031). The
//! session's root is `enclos holder join`, on the host; the runtime's
//! program runs below it, bubblewrap and `enclos inside`, as the second
//! process of the session's PID namespace. The restart signal must reach
//! that program. Before the fix for issue #292 it was sent to the root,
//! which it ended (exit 138), and `launch` then stopped the program with
//! TERM, so a Hermes gateway did not drain.

use std::time::Duration;

use super::{Lab, on_a_runner};

/// A setting changed while the stand-in gateway runs: the gateway itself
/// gets `USR1` and exits 75, `launch` records that end, and the service
/// manager starts a new gateway.
#[test]
fn on_a_runner_a_settings_change_signals_the_runtimes_own_program() {
    if !on_a_runner() {
        return;
    }
    let lab = Lab::new();
    lab.with_stand_in_hermes();
    lab.ok(&["sandbox", "start", "lab"]);
    let home = lab.sandbox_home();
    let (_, first) = lab.gateway(None, Duration::from_secs(60));
    std::fs::write(home.join(".hermes/.env"), "TELEGRAM_BOT_TOKEN=x\n").unwrap();
    let (_, second) = lab.gateway(Some(&first), Duration::from_secs(90));
    let entries = {
        use enclos::audit::AuditLog;
        enclos::audit::jsonl::JsonlAuditLog::new(lab.layout().audit_log())
            .entries(&enclos::model::audit::AuditFilter::default())
            .unwrap()
    };
    let said = |command: &str| -> Vec<String> {
        entries
            .iter()
            .filter(|e| e.intent.command == command)
            .map(|e| match &e.finished {
                Some(finished) => finished.outcome.message.clone(),
                None => "unfinished".to_owned(),
            })
            .collect()
    };
    let signalled = std::fs::read_to_string(home.join("gateway.usr1")).unwrap_or_default();
    assert_eq!(
        signalled.lines().collect::<Vec<_>>(),
        [first.as_str()],
        "the gateway {first} was not the one signalled (then {second}); restarts {:?}, ends {:?}",
        said("service restart"),
        said("service end"),
    );
    assert_eq!(
        said("service restart"),
        ["~/.hermes/.env changed: sent USR1"]
    );
    let ends = said("service end");
    assert!(
        ends.first().is_some_and(|end| end.starts_with("exit 75")),
        "{ends:?}"
    );
}
