//! `enclos policy`: show a sandbox's policy, or allow a destination.

use clap::{Args, Subcommand};

use enclos::engine::{Engine, PolicyApplied, PolicyView};
use enclos::error::{Result, exit};
use enclos::model::audit::Actor;
use enclos::model::plan::{Confirm, Planned};
use enclos::model::sandbox::SandboxName;

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
}

pub fn run(engine: &Engine, by: &Actor, confirm: Confirm, args: PolicyArgs) -> Result<u8> {
    match args.verb {
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
