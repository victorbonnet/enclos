//! `enclos policy`: show a sandbox's policy, allow a destination, or test it.

use clap::{Args, Subcommand};

use enclos::engine::{Engine, PolicyApplied, PolicyView, TestReport};
use enclos::error::{Result, exit};
use enclos::model::audit::Actor;
use enclos::model::plan::{Confirm, Planned};
use enclos::model::sandbox::SandboxName;
use enclos::probes::Outcome;

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
            let report = engine.policy_test(by, &sandbox, host_services)?;
            return Ok(print_test(&sandbox, &report));
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
    println!("\nNetwork (every other destination is denied and logged)");
    if policy.net.allow.is_empty() {
        println!("  allowed: nothing yet");
    } else {
        println!("  allowed: {}", policy.net.allow.join(", "));
    }
    if !policy.net.private.is_empty() {
        println!(
            "  private addresses allowed for: {}",
            policy.net.private.join(", ")
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
        }) => {
            println!(
                "Sandbox {sandbox} already allows {destination} (policy v{}).",
                version.version
            );
        }
        Planned::Done(PolicyApplied { version, .. }) => {
            println!(
                "Sandbox {sandbox} now allows {destination}: policy v{}, in force at once.",
                version.version
            );
        }
    }
}

fn print_test(sandbox: &SandboxName, report: &TestReport) -> u8 {
    println!("Escape probes in sandbox {sandbox}: each tries one way out and must fail.");
    for r in &report.results {
        let (mark, detail) = match &r.outcome {
            Outcome::Closed => ("closed ", String::new()),
            Outcome::Open(why) => ("OPEN   ", format!("  <- {why}")),
            Outcome::Skipped(why) => ("skipped", format!("  ({why})")),
        };
        println!("  {mark}  {:<16} {}{detail}", r.route, r.name);
    }
    if !report.host_services {
        println!(
            "Host-service routes (open, Apple Events, launchd, preferences) were not probed; CI probes them with --host-services."
        );
    }
    println!(
        "Only the routes listed were probed: closed means each probe failed as it should, not that no other way out exists."
    );
    match report.open() {
        0 => {
            println!("All {} probes failed as they should.", report.results.len());
            exit::OK
        }
        n => {
            eprintln!(
                "error: {n} probes got through. Do not use this sandbox until this is fixed."
            );
            exit::ERROR
        }
    }
}
