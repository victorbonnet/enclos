//! `enclos state`: compare enclos's records with the host, and repair what
//! can be (design §11).

use clap::{Args, Subcommand};

use enclos::engine::{Engine, Finding, Remedy};
use enclos::error::{Result, exit};
use enclos::model::audit::Actor;
use enclos::model::plan::Confirm;
use enclos::model::sandbox::SandboxName;

#[derive(Args)]
pub struct StateArgs {
    #[command(subcommand)]
    verb: StateVerb,
}

#[derive(Subcommand)]
enum StateVerb {
    /// Say where enclos's records and the host differ; change nothing.
    /// Exits 1 when they differ. A sandbox it cannot look at is named among
    /// them; a failure that stops the whole check exits 1 with an error on
    /// stderr.
    Check {
        /// One sandbox; every sandbox, and folders with no record, when
        /// left out.
        sandbox: Option<SandboxName>,
    },
    /// Fix what `state check` finds that enclos can fix, and name the rest;
    /// with --dry-run, say what it would do. Exits 1 when something is left
    /// for you.
    Repair {
        /// One sandbox; every sandbox, and folders with no record, when
        /// left out.
        sandbox: Option<SandboxName>,
    },
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
                print_finding(f, "repair");
            }
            if found.iter().any(|f| f.remedy.repair().is_some()) {
                let repair = match &sandbox {
                    Some(name) => format!("enclos state repair {name}"),
                    None => "enclos state repair".to_owned(),
                };
                println!("`{repair}` fixes those marked \"repair:\".");
            }
            Ok(exit::ERROR)
        }
        StateVerb::Repair { sandbox } => {
            // A dry run shows what is left as well as what it would fix,
            // and exits as the repair would if each repair it names succeeds.
            let found = match confirm {
                Confirm::DryRun => engine.state_check(sandbox.as_ref())?,
                _ => engine.state_repair(by, sandbox.as_ref())?,
            };
            if found.is_empty() {
                println!("enclos's records match the host: nothing to repair.");
            }
            for f in &found {
                print_finding(f, "would repair");
            }
            let left = found.iter().any(|f| f.remedy.is_left());
            Ok(if left { exit::ERROR } else { exit::OK })
        }
    }
}

/// One finding and what is done about it, `fix` naming a repair still to
/// make.
fn print_finding(f: &Finding, fix: &str) {
    println!("{}: {}.", f.subject, f.what);
    match &f.remedy {
        Remedy::Repairs(repair) => println!("  {fix}: {repair}"),
        Remedy::Repaired(repair) => println!("  repaired: {repair}"),
        Remedy::Failed { repair, error } => println!("  repair failed: {repair}: {error}"),
        Remedy::Manual(what) => println!("  for you: {what}"),
    }
}
