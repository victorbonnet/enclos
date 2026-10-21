//! `enclos policy`: show a sandbox's policy, allow a destination, or test it.

use clap::{Args, Subcommand};

use enclos::engine::{Engine, PolicyApplied, PolicyView, TestReport};
use enclos::error::{Result, exit};
use enclos::model::audit::Actor;
use enclos::model::plan::{Confirm, Planned};
use enclos::model::policy::NetMode;
use enclos::model::sandbox::SandboxName;
use enclos::probes::{HOST_SERVICE_ROUTES, NOT_PROBED, Outcome};

#[derive(Args)]
pub struct PolicyArgs {
    #[command(subcommand)]
    verb: PolicyVerb,
}

#[derive(Subcommand)]
enum PolicyVerb {
    /// Show the sandbox's active policy.
    Show { sandbox: SandboxName },
    /// Let the sandbox reach a destination: host, host:port or *.domain. Applies at once.
    Allow {
        sandbox: SandboxName,
        destination: String,
    },
    /// Try each way out of the sandbox from inside it; every probe must fail.
    Test {
        sandbox: SandboxName,
        /// Also probe routes that could act on this Mac if a rule did not
        /// hold (open, Apple Events, launchd, preferences). For CI and VMs.
        #[arg(long)]
        host_services: bool,
    },
}

pub fn run(engine: &Engine, by: &Actor, confirm: Confirm, args: PolicyArgs) -> Result<u8> {
    match args.verb {
        PolicyVerb::Test {
            sandbox,
            host_services,
        } => {
            return Ok(
                match engine.policy_test(by, &sandbox, host_services, confirm)? {
                    Planned::DryRun(plan) => {
                        plan.changes.iter().for_each(|c| println!("Would {c}."));
                        exit::OK
                    }
                    Planned::Done(report) => print_test(&sandbox, &report),
                },
            );
        }
        PolicyVerb::Show { sandbox } => print_policy(&engine.policy(&sandbox)?),
        PolicyVerb::Allow {
            sandbox,
            destination,
        } => print_allowed(
            &sandbox,
            &destination,
            engine.policy_allow(by, &sandbox, &destination, confirm)?,
        ),
    }
    Ok(exit::OK)
}

fn print_policy(view: &PolicyView) {
    let (version, snap) = (&view.version, &view.snapshot);
    let policy = &snap.policy;
    println!(
        "Sandbox {}: policy v{} (snapshot {}), template {}, by {}@{} at {}",
        view.sandbox,
        version.version,
        snap.id.short(),
        snap.inputs.template,
        version.by.user,
        version.by.host,
        version.at.strftime("%Y-%m-%d %H:%M:%S UTC"),
    );
    println!("\nFiles (everything else is readable)");
    println!("  writable:   {}", policy.fs.write.join(", "));
    println!(
        "  unreadable: {} paths, and enclos's own files",
        policy.fs.read_deny.len()
    );
    for path in &policy.fs.read_deny {
        println!("    {path}");
    }
    match policy.net.mode {
        NetMode::Public => {
            println!("\nNetwork: public web (every connection is logged)");
            println!("  mode:    public: any public address on ports 80 and 443");
            println!(
                "           never loopback, link-local or metadata addresses, nor private ones unless listed below"
            );
        }
        NetMode::Allowlist => {
            println!("\nNetwork: allowlist (every other destination is denied and logged)");
            println!("  mode:    allowlist: only the destinations below");
        }
    }
    if policy.net.allow.is_empty() {
        println!("  allowed: nothing listed");
    } else {
        println!("  allowed: {}", policy.net.allow.join(", "));
    }
    if !policy.net.private.is_empty() {
        println!(
            "  private addresses allowed for: {}",
            policy.net.private.join(", ")
        );
    }
    if policy.net.listen {
        println!(
            "  listening: allowed on TCP, any port but enclos's proxy ports, on every address: what listens in this sandbox can serve the network"
        );
    }
    println!("\nEdit {} to change it.", view.file.display());
}

fn print_allowed(sandbox: &SandboxName, destination: &str, planned: Planned<PolicyApplied>) {
    match planned {
        Planned::DryRun(plan) => {
            for change in plan.changes {
                println!("Would {change}.");
            }
        }
        Planned::Done(PolicyApplied {
            changed: false,
            version,
            ..
        }) => {
            println!(
                "Sandbox {sandbox} already allows {destination} (policy v{}).",
                version.version
            );
        }
        Planned::Done(PolicyApplied { version, also, .. }) => {
            println!(
                "Sandbox {sandbox} now allows {destination}: policy v{}, in force at once.",
                version.version
            );
            if !also.is_empty() {
                println!("Policy v{} also changes this:", version.version);
                for change in also {
                    println!("  {change}");
                }
            }
        }
    }
}

fn print_test(sandbox: &SandboxName, report: &TestReport) -> u8 {
    println!("Escape probes in sandbox {sandbox}: each tries one way out and must fail.");
    for r in &report.results {
        let (mark, detail) = match &r.outcome {
            Outcome::Closed => (
                "closed      ",
                r.closed_by_platform
                    .map(|why| format!("  ({why})"))
                    .unwrap_or_default(),
            ),
            Outcome::Open(why) => ("OPEN        ", format!("  <- {why}")),
            Outcome::Inconclusive(why) => ("inconclusive", format!("  ({why})")),
            Outcome::NotRun(why) => ("NOT RUN     ", format!("  <- {why}")),
        };
        println!("  {mark}  {:<16} {}{detail}", r.route, r.name);
    }
    if !report.host_services {
        println!(
            "Host-service routes ({}) were not probed; CI probes them with --host-services.",
            HOST_SERVICE_ROUTES.join(", ")
        );
    }
    if !report.not_here.is_empty() {
        println!(
            "Not probed, as it is not on this host: {}.",
            report.not_here.join("; ")
        );
    }
    println!(
        "No probe tries these routes yet: {}.",
        NOT_PROBED.join(", ")
    );
    if report.listens {
        println!(
            "Open by the policy: listening on TCP, on any port but enclos's proxy ports, on every address (ADR 0028); the bind probes show only that the proxy ports stay closed. What listens in this sandbox can serve the network."
        );
    }
    println!(
        "Closed means the probe was refused in the sandbox while its control, a harmless check, worked on this host (for the probes through the proxy: the proxy answered 403). It does not mean no other way out exists."
    );
    if report.inconclusive() > 0 {
        println!(
            "{} probes were inconclusive: they failed for a reason other than the policy, so they show nothing about it.",
            report.inconclusive()
        );
    }
    if report.open() > 0 {
        eprintln!(
            "error: {} probes got through. Do not use this sandbox until this is fixed.",
            report.open()
        );
    }
    if report.not_run() > 0 {
        eprintln!(
            "error: {} probes could not run or be checked, so their routes were not tested.",
            report.not_run()
        );
    }
    if report.open() == 0 && report.not_run() == 0 && report.closed_by_enclos() == 0 {
        eprintln!(
            "error: no probe was shown closed by an enclos rule, so this test showed nothing about the policy."
        );
    }
    match report.passed() {
        true => {
            let platform = match report.closed_by_platform() {
                0 => String::new(),
                n => format!(", {n} of them by Seatbelt itself rather than by an enclos rule"),
            };
            println!(
                "{} of {} probes were shown closed{platform}.",
                report.closed(),
                report.results.len()
            );
            exit::OK
        }
        false => exit::ERROR,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use enclos::probes::ProbeResult;

    fn report(outcome: Outcome) -> TestReport {
        TestReport {
            results: vec![ProbeResult {
                route: "writes",
                name: "write outside the home".into(),
                outcome,
                closed_by_platform: None,
            }],
            host_services: false,
            not_here: Vec::new(),
            listens: false,
        }
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
}
