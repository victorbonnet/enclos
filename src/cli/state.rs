//! `enclos state`: compare enclos's records with the host, and repair what
//! can be (design §11).

use clap::{Args, Subcommand};

use enclos::engine::{Engine, Finding, Remedy};
use enclos::error::{Result, exit};
use enclos::model::audit::Actor;
use enclos::model::plan::{Confirm, Planned};
use enclos::model::sandbox::SandboxName;

#[derive(Args)]
pub struct StateArgs {
    #[command(subcommand)]
    verb: StateVerb,
}

#[derive(Subcommand)]
enum StateVerb {
    /// Say where enclos's records and the host differ; change nothing.
    /// Exits 1 when they do.
    Check {
        /// One sandbox; every sandbox, and folders with no record, when
        /// left out.
        sandbox: Option<SandboxName>,
    },
    /// Fix what `state check` finds that enclos can fix, and name the rest.
    /// Exits 1 when something is left for you.
    Repair { sandbox: Option<SandboxName> },
}

pub fn run(engine: &Engine, by: &Actor, confirm: Confirm, args: StateArgs) -> Result<u8> {
    match args.verb {
        StateVerb::Check { sandbox } => {
            let found = engine.state_check(sandbox.as_ref())?;
            if found.is_empty() {
                println!("enclos's records match the host.");
                return Ok(exit::OK);
            }
            for f in &found {
                print_finding(f);
            }
            let repairable = found.iter().any(|f| matches!(f.remedy, Remedy::Repairs(_)));
            if repairable {
                println!("`enclos state repair` fixes those marked \"repair:\".");
            }
            Ok(exit::ERROR)
        }
        StateVerb::Repair { sandbox } => {
            let found = match engine.state_repair(by, sandbox.as_ref(), confirm)? {
                Planned::DryRun(plan) => {
                    if plan.changes.is_empty() {
                        println!("Nothing to repair.");
                    }
                    plan.changes.iter().for_each(|c| println!("Would {c}."));
                    return Ok(exit::OK);
                }
                Planned::Done(found) => found,
            };
            let mut left = false;
            for f in &found {
                match &f.remedy {
                    Remedy::Repairs(what) => {
                        println!("{}: {}: repaired: {what}.", f.sandbox, f.what)
                    }
                    Remedy::Manual(_) => {
                        left = true;
                        print_finding(f);
                    }
                }
            }
            if found.is_empty() {
                println!("enclos's records match the host: nothing to repair.");
            }
            Ok(if left { exit::ERROR } else { exit::OK })
        }
    }
}

fn print_finding(f: &Finding) {
    match &f.remedy {
        Remedy::Repairs(what) => println!("{}: {}.\n  repair: {what}", f.sandbox, f.what),
        Remedy::Manual(what) => println!("{}: {}.\n  for you: {what}", f.sandbox, f.what),
    }
}
