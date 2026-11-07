//! `enclos policy`: show a sandbox's policy, allow a destination, edit
//! `policy.toml`, apply or discard the pending change, list, compare, roll
//! back or refresh its versions, or test the policy.

mod edit;
mod report;
mod show;

use clap::{Args, Subcommand};
use serde_json::{Value, json};

use super::output;
use edit::edit;
use report::{print_test, test_code, test_json, verdict};
use show::{history_json, pending_json, print_diff, print_history, print_policy, show_json};

use enclos::engine::{ChangeOutcome, Discarded, Engine, PendingEnd, PolicyApplied, Restarted};
use enclos::error::{Result, exit};
use enclos::model::audit::Actor;
use enclos::model::plan::{Confirm, Planned};
use enclos::model::sandbox::SandboxName;
use enclos::model::unenforced::UnenforcedField;

#[derive(Args)]
pub struct PolicyArgs {
    #[command(subcommand)]
    verb: PolicyVerb,
}

#[derive(Subcommand)]
enum PolicyVerb {
    /// Show the sandbox's active policy, and the change pending if there is one.
    Show {
        sandbox: SandboxName,
        /// Show the pending policy in full instead.
        #[arg(long)]
        pending: bool,
        /// Show what the active policy compiles to for the sandbox's backend.
        #[arg(long, conflicts_with = "pending")]
        compiled: bool,
    },
    /// Let the sandbox reach a destination: host, host:port or *.domain. Applies at once, or
    /// waits with a pending change it cannot be separated from.
    Allow {
        sandbox: SandboxName,
        destination: String,
    },
    /// Edit the sandbox's policy.toml in $VISUAL or $EDITOR, then apply it:
    /// at once, or pending while sessions run under rules it changes.
    Edit {
        sandbox: SandboxName,
        /// Run with this field not applied where this host does not enforce
        /// it, such as `memory` without the memory controller; recorded in
        /// the audit log, and kept until the field's value changes.
        #[arg(long, value_name = "FIELD")]
        accept_unenforced: Vec<UnenforcedField>,
    },
    /// Restart the sandbox into its pending policy.
    Apply { sandbox: SandboxName },
    /// Drop the pending policy, and any edit of policy.toml not applied.
    Discard { sandbox: SandboxName },
    /// List every version of the sandbox's policy.
    History { sandbox: SandboxName },
    /// Show what one policy version changes from another: by default the
    /// pending policy from the active one, or the active one from the one before.
    Diff {
        sandbox: SandboxName,
        /// The version compared from: by default the active one when the
        /// pending policy is compared, else the version before the one compared.
        #[arg(long, value_name = "VERSION")]
        from: Option<u32>,
        /// The version compared: by default the pending policy, when there
        /// is one and --from is not given or is the active version; else
        /// the active version.
        #[arg(long, value_name = "VERSION")]
        to: Option<u32>,
    },
    /// Make an earlier version's policy the sandbox's again, as a new version.
    Rollback {
        sandbox: SandboxName,
        #[arg(long, value_name = "VERSION")]
        to: u32,
        /// Run with this field not applied where this host does not enforce
        /// it, such as `memory` without the memory controller; recorded in
        /// the audit log, and kept until the field's value changes.
        #[arg(long, value_name = "FIELD")]
        accept_unenforced: Vec<UnenforcedField>,
    },
    /// Resolve the active policy's policy.toml again against this enclos's
    /// templates, built-in defaults and the runtime's adapter; with --yes,
    /// apply what that changes, in place of a pending change.
    Refresh {
        sandbox: SandboxName,
        /// Run with this field not applied where this host does not enforce
        /// it, such as `memory` without the memory controller; recorded in
        /// the audit log, and kept until the field's value changes.
        #[arg(long, value_name = "FIELD")]
        accept_unenforced: Vec<UnenforcedField>,
    },
    /// Try each way out of the sandbox from inside it; every probe must fail.
    Test {
        sandbox: SandboxName,
        /// Also probe the backend's host-service routes (`policy test` lists
        /// them), which could act on this host if a rule did not hold. For
        /// CI and VMs.
        #[arg(long)]
        host_services: bool,
    },
}

/// The fields `args` accepts running not enforced (ADR 0038).
pub fn accepted_unenforced(args: &PolicyArgs) -> Vec<UnenforcedField> {
    match &args.verb {
        PolicyVerb::Edit {
            accept_unenforced, ..
        }
        | PolicyVerb::Rollback {
            accept_unenforced, ..
        }
        | PolicyVerb::Refresh {
            accept_unenforced, ..
        } => accept_unenforced.clone(),
        _ => Vec::new(),
    }
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
                        output::show_plan(&plan);
                        exit::OK
                    }
                    Planned::Done(report) if output::json() => {
                        let code = test_code(&report);
                        output::conclude(test_json(&sandbox, &report), code, || {
                            verdict(&sandbox, &report, true)
                        })
                    }
                    Planned::Done(report) => print_test(&sandbox, &report),
                },
            );
        }
        PolicyVerb::Show {
            sandbox, compiled, ..
        } if compiled => {
            let text = engine.compiled_text(&sandbox)?;
            match output::json() {
                true => output::emit(&json!({"sandbox": sandbox.to_string(), "compiled": text})),
                false => print!("{text}"),
            }
        }
        PolicyVerb::Show {
            sandbox, pending, ..
        } => {
            let view = engine.policy(&sandbox)?;
            match output::json() {
                true => output::emit(&show_json(&view, pending)?),
                false => print_policy(&view, pending)?,
            }
        }
        PolicyVerb::Allow {
            sandbox,
            destination,
        } => {
            return print_allowed(
                engine,
                &sandbox,
                &destination,
                engine.policy_allow(by, &sandbox, &destination, confirm)?,
            );
        }
        PolicyVerb::Edit { sandbox, .. } => return edit(engine, by, &sandbox, confirm),
        PolicyVerb::Apply { sandbox } => {
            return match engine.policy_apply(by, &sandbox, confirm)? {
                Planned::DryRun(plan) => {
                    output::show_plan(&plan);
                    Ok(exit::OK)
                }
                Planned::Done(restarted) => {
                    let (code, value) = print_restarted(engine, &sandbox, &restarted)?;
                    if output::json() {
                        return Ok(output::conclude(
                            json!({"sandbox": sandbox.to_string(), "restarted": value}),
                            code,
                            || restart_failed(&sandbox),
                        ));
                    }
                    Ok(code)
                }
            };
        }
        PolicyVerb::Discard { sandbox } => {
            print_discarded(&sandbox, engine.policy_discard(by, &sandbox, confirm)?)
        }
        PolicyVerb::History { sandbox } => {
            let history = engine.policy_history(&sandbox)?;
            match output::json() {
                true => output::emit(&history_json(&history)),
                false => print_history(&history),
            }
        }
        PolicyVerb::Diff { sandbox, from, to } => {
            let diff = engine.policy_diff(&sandbox, from, to)?;
            match output::json() {
                true => output::emit(&json!({
                    "sandbox": sandbox.to_string(),
                    "from": diff.from,
                    "to": diff.to.to_string(),
                    "changes": diff.changes,
                    "inputs": diff.inputs,
                })),
                false => print_diff(&sandbox, &diff),
            }
        }
        PolicyVerb::Rollback { sandbox, to, .. } => {
            let planned = engine.policy_rollback(by, &sandbox, to, confirm)?;
            return print_replaced(engine, &sandbox, &format!("v{to}"), planned);
        }
        PolicyVerb::Refresh { sandbox, .. } => {
            let planned = engine.policy_refresh(by, &sandbox, confirm)?;
            return print_replaced(engine, &sandbox, "a refresh", planned);
        }
    }
    Ok(exit::OK)
}

/// Why a change that restarted the sandbox fails: its stop or its start
/// failed, as `restarted` says.
fn restart_failed(sandbox: &SandboxName) -> String {
    format!(
        "the restart of sandbox {sandbox} did not complete: its stop or its start failed, as `restarted` says (under `outcome` for a change other than `policy apply`); `enclos sandbox show {sandbox}` shows where it is"
    )
}

/// A change that was applied, or not: its version, whether it changed,
/// what else it does, and how it took effect.
fn applied_json(sandbox: &SandboxName, applied: &PolicyApplied, outcome: Value) -> Value {
    json!({
        "sandbox": sandbox.to_string(),
        "version": applied.version.version,
        "changed": applied.changed,
        "also": applied.also,
        "outcome": outcome,
    })
}

fn print_allowed(
    engine: &Engine,
    sandbox: &SandboxName,
    destination: &str,
    planned: Planned<PolicyApplied>,
) -> Result<u8> {
    let applied = match planned {
        Planned::DryRun(plan) => {
            output::show_plan(&plan);
            return Ok(exit::OK);
        }
        Planned::Done(applied) => applied,
    };
    if output::json() {
        let (code, outcome) = print_outcome(engine, sandbox, &applied)?;
        let mut shown = applied_json(sandbox, &applied, outcome);
        shown["destination"] = json!(destination);
        return Ok(output::conclude(shown, code, || restart_failed(sandbox)));
    }
    let version = applied.version.version;
    match (applied.changed, &applied.outcome) {
        (true, _) => println!(
            "Sandbox {sandbox} now allows {destination}: policy v{version}, in force at once."
        ),
        // Waits with the pending policy, unless the policy in force
        // allows it already (a pending change that dropped it, say).
        (false, ChangeOutcome::Pending(_)) if engine.allows(sandbox, destination)? => println!(
            "Sandbox {sandbox} allows {destination} under policy v{version}; the change waits with its pending policy."
        ),
        (false, ChangeOutcome::Pending(_)) => println!(
            "Sandbox {sandbox} does not allow {destination} yet: the change waits with its pending policy, and policy v{version} stays in force."
        ),
        (false, _) => {
            println!("Sandbox {sandbox} already allows {destination} (policy v{version}).")
        }
    }
    if !applied.also.is_empty() {
        println!("The change also does this:");
        for change in &applied.also {
            println!("  {change}");
        }
    }
    Ok(print_outcome(engine, sandbox, &applied)?.0)
}

/// Says whether a change waits as the pending policy, or how the restart
/// that applied it went; returns its code and, for JSON, the outcome.
fn print_outcome(
    engine: &Engine,
    sandbox: &SandboxName,
    applied: &PolicyApplied,
) -> Result<(u8, Value)> {
    let text = !output::json();
    match &applied.outcome {
        ChangeOutcome::InForce {
            pending: Some(PendingEnd::Dropped(p)),
        } => {
            if text {
                println!(
                    "The pending policy of sandbox {sandbox} (snapshot {}) is dropped: the file is back to the policy in force.",
                    p.snapshot.short()
                );
            }
            Ok((
                exit::OK,
                json!({"in_force": true, "dropped_pending": pending_json(p)}),
            ))
        }
        ChangeOutcome::InForce {
            pending: Some(PendingEnd::Applied(p)),
        } => {
            if text {
                println!(
                    "The pending policy of sandbox {sandbox} (snapshot {}) is in force with this change: no session runs under rules it changes any more.",
                    p.snapshot.short()
                );
            }
            Ok((
                exit::OK,
                json!({"in_force": true, "dropped_pending": null, "applied_pending": pending_json(p)}),
            ))
        }
        ChangeOutcome::InForce { pending: None } => {
            Ok((exit::OK, json!({"in_force": true, "dropped_pending": null})))
        }
        ChangeOutcome::Pending(p) => {
            if text {
                println!(
                    "A change waits as the pending policy of sandbox {sandbox} (snapshot {}): sessions run under rules it changes, and keep them until they restart.",
                    p.snapshot.short()
                );
                println!(
                    "`enclos policy apply {sandbox}` restarts the sandbox into it; `enclos policy discard {sandbox}` drops it."
                );
            }
            Ok((
                exit::OK,
                json!({"in_force": false, "pending": pending_json(p)}),
            ))
        }
        ChangeOutcome::Restarted(restarted) => {
            let (code, value) = print_restarted(engine, sandbox, restarted)?;
            Ok((code, json!({"in_force": true, "restarted": value})))
        }
    }
}

/// How a restart into the pending policy went: what stopped, the version
/// now in force, and the services started again; returns its code and,
/// for JSON, the restart. The version is in force once this is reached, so
/// a start that cannot be checked is said beside it, in JSON, rather than
/// losing it.
fn print_restarted(engine: &Engine, sandbox: &SandboxName, r: &Restarted) -> Result<(u8, Value)> {
    let stopped = r
        .stopped
        .as_ref()
        .map(|stopped| super::sandbox::print_stop(sandbox, stopped));
    if !output::json() {
        println!(
            "Sandbox {sandbox} runs under policy v{} from now on.",
            r.version.version
        );
        if r.stopped.as_ref().is_some_and(|s| !s.stopped.is_empty()) {
            println!("To use it in a terminal again: `enclos connect {sandbox}`.");
        }
    }
    let (code, started) = match r.started.labels.is_empty() {
        true => (exit::OK, Value::Null),
        // In JSON, a start that cannot be checked is said in its value.
        false => super::sandbox::print_started(engine, sandbox, &r.started)?,
    };
    let code = code.max(stopped.as_ref().map_or(exit::OK, |(c, _)| *c));
    Ok((
        code,
        json!({
            "version": r.version.version,
            "stopped": stopped.map(|(_, v)| v),
            "started": started,
        }),
    ))
}

/// How a rollback or refresh went: the version in force, the pending
/// change it made, or the restart.
fn print_replaced(
    engine: &Engine,
    sandbox: &SandboxName,
    from: &str,
    planned: Planned<PolicyApplied>,
) -> Result<u8> {
    let applied = match planned {
        Planned::DryRun(plan) => {
            output::show_plan(&plan);
            return Ok(exit::OK);
        }
        Planned::Done(applied) => applied,
    };
    if output::json() {
        let (code, outcome) = print_outcome(engine, sandbox, &applied)?;
        return Ok(output::conclude(
            applied_json(sandbox, &applied, outcome),
            code,
            || restart_failed(sandbox),
        ));
    }
    let version = applied.version.version;
    match (&applied.outcome, applied.changed) {
        (ChangeOutcome::Pending(_), true) => println!(
            "Sandbox {sandbox} has policy v{version}: the network part of {from} is in force at once."
        ),
        (ChangeOutcome::Pending(_), false) => {
            println!("Sandbox {sandbox} keeps policy v{version} for now.")
        }
        (ChangeOutcome::InForce { pending: None }, false) => {
            println!("Sandbox {sandbox} already has that policy: v{version}, nothing changed.")
        }
        (_, false) => println!("Sandbox {sandbox} keeps policy v{version}."),
        (_, true) => println!("Sandbox {sandbox} has policy v{version}, from {from}."),
    }
    if !applied.also.is_empty() {
        println!("What it changes from the policy that was in force:");
    }
    for change in &applied.also {
        println!("  {change}");
    }
    Ok(print_outcome(engine, sandbox, &applied)?.0)
}

fn print_discarded(sandbox: &SandboxName, planned: Planned<Discarded>) {
    let discarded = match planned {
        Planned::DryRun(plan) => {
            output::show_plan(&plan);
            return;
        }
        Planned::Done(d) => d,
    };
    if output::json() {
        output::emit(&json!({
            "sandbox": sandbox.to_string(),
            "version": discarded.version.version,
            "dropped_pending": discarded.pending.as_ref().map(pending_json),
            "kept": discarded.kept.as_deref().map(output::path),
            "edit_moved_to": discarded.edit.as_deref().map(output::path),
        }));
        return;
    }
    let version = discarded.version.version;
    match (&discarded.pending, &discarded.kept, &discarded.edit) {
        (None, None, None) => println!(
            "Sandbox {sandbox} has nothing pending: its policy.toml is policy v{version}'s."
        ),
        (Some(p), ..) => println!(
            "Dropped the pending policy of sandbox {sandbox} (snapshot {}); policy v{version} stays in force.",
            p.snapshot.short()
        ),
        (None, Some(_), _) => println!(
            "Put back the policy.toml of policy v{version} in sandbox {sandbox}, dropping the edits not applied."
        ),
        (None, None, Some(_)) => {
            println!("Dropped the edit `policy edit` kept for sandbox {sandbox}.")
        }
    }
    if let Some(kept) = &discarded.kept {
        println!("What policy.toml held is kept in {}.", kept.display());
    }
    if let Some(edit) = &discarded.edit {
        println!(
            "The edit `policy edit` kept is moved to {}.",
            edit.display()
        );
    }
}
