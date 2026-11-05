//! What `enclos policy test` reports, in text and in JSON.

use serde_json::{Value, json};

use enclos::engine::TestReport;
use enclos::error::exit;
use enclos::model::sandbox::SandboxName;
use enclos::probes::Outcome;

pub(super) fn test_code(report: &TestReport) -> u8 {
    match report.passed() {
        true => exit::OK,
        false => exit::ERROR,
    }
}

pub(super) fn test_json(sandbox: &SandboxName, report: &TestReport) -> Value {
    json!({
        "sandbox": sandbox.to_string(),
        "ready": report.passed(),
        "verdict": verdict(sandbox, report, true),
        "probes": report.results.iter().map(|r| {
            let (outcome, why) = match &r.outcome {
                Outcome::Closed => ("closed", r.closed_by.map(|by| by.why().to_owned())),
                Outcome::Open(why) => ("open", Some(why.clone())),
                Outcome::Inconclusive(why) => ("inconclusive", Some(why.clone())),
                Outcome::NotRun(why) => ("not_run", Some(why.clone())),
            };
            json!({
                "route": r.route,
                "name": r.name,
                "outcome": outcome,
                "why": why,
                "closed_by": r.closed_by.map(enclos::probes::ClosedBy::key),
            })
        }).collect::<Vec<_>>(),
        "host_services_probed": report.host_services,
        "not_here": report.not_here,
        "not_probed": report.notes.not_probed,
        "listens": report.listens,
        "baseline": report.notes.baseline_key,
    })
}

pub(super) fn print_test(sandbox: &SandboxName, report: &TestReport) -> u8 {
    print!("{}", test_text(sandbox, report));
    // Last, after a blank line, so it is what the user reads.
    println!();
    match report.passed() {
        true => {
            println!("{}", verdict(sandbox, report, false));
            exit::OK
        }
        false => {
            eprintln!("{}", verdict(sandbox, report, false));
            exit::ERROR
        }
    }
}

/// The text report, every line of it but the verdict.
fn test_text(sandbox: &SandboxName, report: &TestReport) -> String {
    use std::fmt::Write;
    let mut text = String::new();
    let mut line = |said: String| writeln!(text, "{said}").expect("a String takes any text");
    line(format!(
        "Escape probes in sandbox {sandbox}: each tries one way out and must fail."
    ));
    for r in &report.results {
        let (mark, detail) = match &r.outcome {
            Outcome::Closed => (
                "closed      ",
                r.closed_by
                    .map(|by| format!("  ({})", by.why()))
                    .unwrap_or_default(),
            ),
            Outcome::Open(why) => ("OPEN        ", format!("  <- {why}")),
            Outcome::Inconclusive(why) => ("inconclusive", format!("  ({why})")),
            Outcome::NotRun(why) => ("NOT RUN     ", format!("  <- {why}")),
        };
        line(format!("  {mark}  {:<16} {}{detail}", r.route, r.name));
    }
    if !report.host_services && !report.notes.host_service_routes.is_empty() {
        line(format!(
            "Host-service routes ({}) were not probed; CI probes them with --host-services.",
            report.notes.host_service_routes.join(", ")
        ));
    }
    if !report.not_here.is_empty() {
        line(format!(
            "Not probed, as it is not on this host: {}.",
            report.not_here.join("; ")
        ));
    }
    if !report.notes.not_probed.is_empty() {
        line(format!(
            "No probe tries these routes yet: {}.",
            report.notes.not_probed.join(", ")
        ));
    }
    if report.listens {
        line(report.notes.listening.to_owned());
    }
    line("Closed means the probe was refused in the sandbox while its control, a harmless check, worked on this host (for the probes through the proxy: the proxy answered 403). It does not mean no other way out exists.".to_owned());
    if report.inconclusive() > 0 {
        line(format!(
            "{} probes were inconclusive: they failed for a reason other than the policy, so they show nothing about it.",
            report.inconclusive()
        ));
    }
    text
}

/// Whether the sandbox is ready, in one line: READY when the test passed,
/// with what it showed, or NOT READY with every reason it did not. Each
/// probe is listed above it in text, and in the document's `probes` in
/// `json`.
pub(super) fn verdict(sandbox: &SandboxName, report: &TestReport, json: bool) -> String {
    let total = report.results.len();
    let listed = |text: &str, value: &str| match json {
        true => format!("\"{value}\" in probes"),
        false => format!("{text} above"),
    };
    if report.passed() {
        let platform = report.closed_apart();
        let shown = match report.closed() == total {
            true => format!("all {total} shown closed{platform}"),
            false => format!(
                "{} of {total} shown closed{platform}, {} could not be checked on {} ({}), none open",
                report.closed(),
                report.inconclusive(),
                report.notes.host,
                listed("inconclusive", "inconclusive")
            ),
        };
        let baseline = report
            .notes
            .comparison
            .map(|c| format!(" On {c}, which only a debug build compiles and no service runs on."))
            .unwrap_or_default();
        return format!("READY: no probe got out of sandbox {sandbox}: {shown}.{baseline}");
    }
    let mut why = Vec::new();
    if report.open() > 0 {
        why.push(format!(
            "{} of {total} probes got out ({})",
            report.open(),
            listed("OPEN", "open")
        ));
    }
    if report.not_run() > 0 {
        why.push(format!(
            "{} could not run or be checked, so their routes were not tested ({})",
            report.not_run(),
            listed("NOT RUN", "not_run")
        ));
    }
    if report.open() == 0 && report.not_run() == 0 {
        why.push(format!(
            "no probe was shown closed by its route's rule{}, so the test showed nothing about the policy's rules",
            report.notes.only_apart
        ));
    }
    let stop = match report.open() > 0 {
        true => " Do not use it until this is fixed.",
        false => "",
    };
    format!("NOT READY: sandbox {sandbox}: {}.{stop}", why.join("; "))
}

#[cfg(test)]
mod tests {
    use super::*;
    use enclos::backend::seatbelt::Baseline;
    use enclos::backend::seatbelt::probes::{BEFORE_THE_RULE, ITSELF, notes_on};
    use enclos::probes::ProbeResult;

    fn report(outcome: Outcome) -> TestReport {
        reports(vec![outcome])
    }

    fn reports(outcomes: Vec<Outcome>) -> TestReport {
        TestReport {
            results: outcomes
                .into_iter()
                .map(|outcome| ProbeResult {
                    route: "writes",
                    name: "write outside the home".into(),
                    outcome,
                    closed_by: None,
                })
                .collect(),
            host_services: false,
            not_here: Vec::new(),
            listens: false,
            notes: notes_on(Baseline::DenyDefault),
        }
    }

    #[test]
    fn the_test_ends_saying_whether_the_sandbox_is_ready() {
        let lab: SandboxName = "lab".parse().unwrap();
        let closed = || Outcome::Closed;
        assert_eq!(
            verdict(&lab, &reports(vec![closed(), closed()]), false),
            "READY: no probe got out of sandbox lab: all 2 shown closed."
        );
        assert_eq!(
            verdict(
                &lab,
                &reports(vec![closed(), closed(), Outcome::Inconclusive("x".into())]),
                false
            ),
            "READY: no probe got out of sandbox lab: 2 of 3 shown closed, 1 could not be checked on this Mac (inconclusive above), none open."
        );
        assert_eq!(
            verdict(
                &lab,
                &reports(vec![
                    closed(),
                    Outcome::Open("x".into()),
                    Outcome::NotRun("y".into())
                ]),
                false
            ),
            "NOT READY: sandbox lab: 1 of 3 probes got out (OPEN above); 1 could not run or be checked, so their routes were not tested (NOT RUN above). Do not use it until this is fixed."
        );
        // In JSON, nothing is above: the verdict points at `probes`.
        assert_eq!(
            verdict(
                &lab,
                &reports(vec![
                    closed(),
                    Outcome::Open("x".into()),
                    Outcome::NotRun("y".into())
                ]),
                true
            ),
            "NOT READY: sandbox lab: 1 of 3 probes got out (\"open\" in probes); 1 could not run or be checked, so their routes were not tested (\"not_run\" in probes). Do not use it until this is fixed."
        );
        assert_eq!(
            verdict(&lab, &report(Outcome::Inconclusive("x".into())), false),
            "NOT READY: sandbox lab: no probe was shown closed by its route's rule, only by Seatbelt itself or the (deny default) baseline if any, so the test showed nothing about the policy's rules."
        );
    }

    #[test]
    fn the_exit_code_fails_on_an_open_route_a_probe_not_run_or_nothing_closed() {
        let home: SandboxName = "home".parse().unwrap();
        assert_eq!(print_test(&home, &report(Outcome::Closed)), exit::OK);
        for failing in [
            Outcome::Open("x".into()),
            Outcome::NotRun("x".into()),
            Outcome::Inconclusive("x".into()),
        ] {
            assert_eq!(print_test(&home, &report(failing)), exit::ERROR);
        }
    }

    /// A sentence true of one backend's probes is that backend's to say.
    #[test]
    fn what_a_report_says_of_listening_is_the_backend_s() {
        let mut listens = report(Outcome::Closed);
        listens.listens = true;
        listens.notes.listening = "Open by the policy: another backend's sentence.";
        let name = "lab".parse().unwrap();
        let text = test_text(&name, &listens);
        assert!(text.contains(listens.notes.listening), "{text}");
        assert!(!text.contains("bind probes"), "{text}");
    }

    /// The baseline a report names, in its verdict and its JSON, is the
    /// backend's to say; a backend that names none says nothing of it.
    #[test]
    fn the_baseline_a_report_names_is_the_backend_s() {
        let lab: SandboxName = "lab".parse().unwrap();
        let mut other = report(Outcome::Closed);
        other.notes.baseline_key = Some("another_baseline");
        other.notes.comparison = Some("another backend's comparison baseline");
        assert_eq!(
            verdict(&lab, &other, false),
            "READY: no probe got out of sandbox lab: all 1 shown closed. On another backend's comparison baseline, which only a debug build compiles and no service runs on."
        );
        assert_eq!(test_json(&lab, &other)["baseline"], "another_baseline");
        let mut none = report(Outcome::Closed);
        none.notes.baseline_key = None;
        none.notes.comparison = None;
        assert_eq!(
            verdict(&lab, &none, false),
            "READY: no probe got out of sandbox lab: all 1 shown closed."
        );
        assert_eq!(test_json(&lab, &none)["baseline"], Value::Null);
    }

    /// The report of each kind of test on Seatbelt, as it was before the
    /// probes were split per backend (M3-06): text, verdict and JSON.
    #[test]
    fn the_seatbelt_report_is_as_it_was() {
        let row = |route, name: &str, outcome, closed_by| ProbeResult {
            route,
            name: name.to_owned(),
            outcome,
            closed_by,
        };
        let ready = vec![
            row("writes", "write outside the home", Outcome::Closed, None),
            row("at", "list the `at` queue", Outcome::Closed, Some(ITSELF)),
            row(
                "launchservices",
                "open a folder through LaunchServices",
                Outcome::Closed,
                Some(BEFORE_THE_RULE),
            ),
        ];
        let mut mixed = ready.clone();
        mixed.push(row(
            "crontab",
            "read the crontab",
            Outcome::Inconclusive("it fails outside the sandbox too".into()),
            None,
        ));
        let mut failing = mixed.clone();
        failing.push(row(
            "network",
            "a direct connection, around the proxy",
            Outcome::Open("it succeeded: ".into()),
            None,
        ));
        failing.push(row(
            "dns",
            "DNS on port 53",
            Outcome::NotRun("could not run it".into()),
            None,
        ));
        let only_apart = vec![ready[1].clone()];
        let lab: SandboxName = "lab".parse().unwrap();
        let mut got = String::new();
        for (results, host_services, not_here, listens, baseline) in [
            (ready, true, vec![], false, Baseline::DenyDefault),
            (
                mixed,
                false,
                vec!["keychain (no login keychain here)".to_owned()],
                true,
                Baseline::AllowDefault,
            ),
            (failing, false, vec![], false, Baseline::DenyDefault),
            (only_apart, false, vec![], false, Baseline::DenyDefault),
        ] {
            let report = TestReport {
                results,
                host_services,
                not_here,
                listens,
                notes: notes_on(baseline),
            };
            got.push_str(&test_text(&lab, &report));
            got.push_str(&verdict(&lab, &report, false));
            got.push('\n');
            got.push_str(&serde_json::to_string_pretty(&test_json(&lab, &report)).unwrap());
            got.push_str("\n\n");
        }
        if std::env::var_os("ENCLOS_WRITE_SNAPSHOTS").is_some() {
            let file = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("src/cli/policy-test.snapshot");
            std::fs::write(file, &got).unwrap();
            return;
        }
        assert_eq!(got, include_str!("../policy-test.snapshot"));
    }
}
