//! `enclos state`: compare enclos's records with the host, and repair what
//! can be (design §11).

use clap::{Args, Subcommand};
use serde_json::{Value, json};

use super::output;

use enclos::engine::{Engine, Finding, Remedy, Subject};
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
            if output::json() {
                let code = match found.is_empty() {
                    true => exit::OK,
                    false => exit::ERROR,
                };
                output::emit(&output::with_error(
                    findings_json(&found, false),
                    code,
                    || "enclos's records and the host differ".to_owned(),
                ));
                return Ok(code);
            }
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
            let left = found.iter().any(|f| f.remedy.is_left());
            if output::json() {
                let code = if left { exit::ERROR } else { exit::OK };
                output::emit(&output::with_error(
                    findings_json(&found, confirm == Confirm::DryRun),
                    code,
                    || {
                        let failed = found
                            .iter()
                            .filter(|f| matches!(f.remedy, Remedy::Failed { .. }))
                            .count();
                        let manual = found
                            .iter()
                            .filter(|f| matches!(f.remedy, Remedy::Manual(_)))
                            .count();
                        format!("{failed} repairs failed and {manual} findings need you")
                    },
                ));
                return Ok(code);
            }
            if found.is_empty() {
                println!("enclos's records match the host: nothing to repair.");
            }
            for f in &found {
                print_finding(f, "would repair");
            }
            Ok(if left { exit::ERROR } else { exit::OK })
        }
    }
}

/// The findings as JSON, each with what is done about it: a remedy of kind
/// `repair` is one `state repair` would make, of kind `repaired` one it
/// made; `dry_run` when the repairs are only planned. Names are as they
/// are: JSON escapes what a terminal would not show.
fn findings_json(found: &[Finding], dry_run: bool) -> Value {
    json!({
        "match": found.is_empty(),
        "dry_run": dry_run,
        "findings": found.iter().map(|f| {
            let (kind, name) = match &f.subject {
                Subject::Sandbox(name) => ("sandbox", name.to_string()),
                Subject::Folder(folder) => ("folder", folder.clone()),
                Subject::Record(name) => ("record", name.clone()),
            };
            let remedy = match &f.remedy {
                Remedy::Repairs(what) => json!({"kind": "repair", "what": what.to_string()}),
                Remedy::Repaired(what) => json!({"kind": "repaired", "what": what.to_string()}),
                Remedy::Failed { repair, error } => json!({
                    "kind": "repair_failed",
                    "what": repair.to_string(),
                    "error": error,
                }),
                Remedy::Manual(what) => json!({"kind": "manual", "what": what}),
            };
            json!({
                "subject": {"kind": kind, "name": name},
                "what": f.what,
                "remedy": remedy,
            })
        }).collect::<Vec<_>>(),
    })
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
