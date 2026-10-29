//! `enclos policy`: show a sandbox's policy, allow a destination, edit
//! `policy.toml`, apply or discard the pending change, list, compare, roll
//! back or refresh its versions, or test the policy.

use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use clap::{Args, Subcommand};
use serde_json::{Value, json};

use super::output;

use enclos::backend::seatbelt::Baseline;
use enclos::engine::{
    ChangeOutcome, Discarded, EditFiles, Engine, PendingEnd, PolicyApplied, PolicyDiff,
    PolicyHistory, PolicyView, Restarted, TestReport,
};
use enclos::error::{Error, Result, exit};
use enclos::layout::LayoutError;
use enclos::model::audit::Actor;
use enclos::model::plan::{Confirm, Planned};
use enclos::model::policy::{NetMode, PendingPolicy, Policy, PolicyVersion};
use enclos::model::sandbox::SandboxName;
use enclos::probes::{HOST_SERVICE_ROUTES, NOT_PROBED, Outcome};

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
    },
    /// Let the sandbox reach a destination: host, host:port or *.domain. Applies at once, or
    /// waits with a pending change it cannot be separated from.
    Allow {
        sandbox: SandboxName,
        destination: String,
    },
    /// Edit the sandbox's policy.toml in $VISUAL or $EDITOR, then apply it:
    /// at once, or pending while sessions run under rules it changes.
    Edit { sandbox: SandboxName },
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
    },
    /// Resolve the active policy's policy.toml again against this enclos's
    /// templates, built-in defaults and the runtime's adapter; with --yes,
    /// apply what that changes, in place of a pending change.
    Refresh { sandbox: SandboxName },
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
        PolicyVerb::Show { sandbox, pending } => {
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
        PolicyVerb::Edit { sandbox } => return edit(engine, by, &sandbox, confirm),
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
        PolicyVerb::Rollback { sandbox, to } => {
            let planned = engine.policy_rollback(by, &sandbox, to, confirm)?;
            return print_replaced(engine, &sandbox, &format!("v{to}"), planned);
        }
        PolicyVerb::Refresh { sandbox } => {
            let planned = engine.policy_refresh(by, &sandbox, confirm)?;
            return print_replaced(engine, &sandbox, "a refresh", planned);
        }
    }
    Ok(exit::OK)
}

fn version_json(v: &PolicyVersion) -> Value {
    json!({
        "version": v.version,
        "snapshot": v.snapshot.0,
        "by": output::actor(&v.by),
        "at": v.at.to_string(),
        "restores": v.restores,
    })
}

fn pending_json(p: &PendingPolicy) -> Value {
    json!({
        "snapshot": p.snapshot.0,
        "by": output::actor(&p.by),
        "at": p.at.to_string(),
        "restores": p.restores,
    })
}

fn policy_json(policy: &enclos::model::policy::Policy) -> Result<Value> {
    serde_json::to_value(policy).map_err(|source| Error::Json {
        what: "the policy",
        source,
    })
}

/// The policy in force, or with `pending` the pending one, field by field.
fn show_json(view: &PolicyView, pending: bool) -> Result<Value> {
    let snap = &view.snapshot;
    if pending {
        let Some((p, pending)) = &view.pending else {
            return Err(Error::NoPendingPolicy {
                sandbox: view.sandbox.to_string(),
            });
        };
        return Ok(json!({
            "sandbox": view.sandbox.to_string(),
            "pending": pending_json(p),
            "template": pending.inputs.template.to_string(),
            "active_version": view.version.version,
            "policy": policy_json(&pending.policy)?,
        }));
    }
    Ok(json!({
        "sandbox": view.sandbox.to_string(),
        "version": version_json(&view.version),
        "template": snap.inputs.template.to_string(),
        "file": output::path(&view.file),
        "policy": policy_json(&snap.policy)?,
        "pending": view.pending.as_ref().map(|(p, pending)| {
            let mut shown = pending_json(p);
            shown["changes"] = json!(enclos::engine::policy_differences(&snap.policy, &pending.policy));
            shown
        }),
    }))
}

fn history_json(history: &PolicyHistory) -> Value {
    json!({
        "sandbox": history.sandbox.to_string(),
        "active": history.active().map(|a| a.version),
        "versions": history.versions.iter().map(version_json).collect::<Vec<_>>(),
        "pending": history.pending.as_ref().map(pending_json),
    })
}

fn test_code(report: &TestReport) -> u8 {
    match report.passed() {
        true => exit::OK,
        false => exit::ERROR,
    }
}

fn test_json(sandbox: &SandboxName, report: &TestReport) -> Value {
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
        "not_probed": NOT_PROBED,
        "listens": report.listens,
        "baseline": match report.baseline {
            Baseline::AllowDefault => "allow_default",
            Baseline::DenyDefault => "deny_default",
        },
    })
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

fn print_policy(view: &PolicyView, pending: bool) -> Result<()> {
    let (version, snap) = (&view.version, &view.snapshot);
    if pending {
        let Some((p, pending)) = &view.pending else {
            return Err(Error::NoPendingPolicy {
                sandbox: view.sandbox.to_string(),
            });
        };
        println!(
            "Sandbox {}: pending policy (snapshot {}), template {}, by {}@{} at {}; v{} is in force until `enclos policy apply {}`",
            view.sandbox,
            p.snapshot.short(),
            pending.inputs.template,
            p.by.user,
            p.by.host,
            p.at.strftime("%Y-%m-%d %H:%M:%S UTC"),
            version.version,
            view.sandbox,
        );
        print_rules(&pending.policy);
        return Ok(());
    }
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
    print_rules(&snap.policy);
    match &view.pending {
        Some((p, pending)) => {
            println!(
                "\nPending (snapshot {}, by {}@{} at {}): saved while sessions ran under rules it changes, it waits for `enclos policy apply`:",
                p.snapshot.short(),
                p.by.user,
                p.by.host,
                p.at.strftime("%Y-%m-%d %H:%M:%S UTC"),
            );
            for change in enclos::engine::policy_differences(&snap.policy, &pending.policy) {
                println!("  {change}");
            }
            println!(
                "`enclos policy apply {0}` restarts the sandbox into it; `enclos policy discard {0}` drops it. `enclos policy show {0} --pending` shows it in full.",
                view.sandbox
            );
        }
        None => println!(
            "\nChange it with `enclos policy edit {}` (it edits {}).",
            view.sandbox,
            view.file.display()
        ),
    }
    Ok(())
}

fn print_rules(policy: &Policy) {
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
    let r = &policy.resources;
    // Every field named, so one added is decided on here.
    let enclos::model::policy::Resources {
        open_files: _,
        file_size: _,
        cpu_seconds: _,
        memory: _,
        cpu: _,
    } = r;
    if !r.is_unset() {
        println!("\nLimits (each process, from its start; memory and CPU share for the sandbox)");
        if let Some(files) = r.open_files {
            println!("  open files: {files}");
        }
        if let Some(seconds) = r.cpu_seconds {
            println!("  CPU time:   {seconds} s");
        }
        if let Some(size) = r.file_size {
            println!("  file size:  {size}");
        }
        if let Some(memory) = &r.memory {
            println!("  memory:     {memory}");
        }
        if let Some(cpu) = &r.cpu {
            println!("  CPU share:  {cpu}");
        }
    }
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
    let (code, started) = match r.started.is_empty() {
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

fn print_history(history: &PolicyHistory) {
    println!("Policy versions of sandbox {}:", history.sandbox);
    let rows: Vec<[String; 5]> = history
        .versions
        .iter()
        .map(|v| {
            let active = history.active().map(|a| a.version);
            let note = match (Some(v.version) == active, v.restores) {
                (true, Some(r)) => format!("in force; restores v{r}"),
                (true, None) => "in force".to_owned(),
                (false, Some(r)) => format!("restores v{r}"),
                (false, None) => String::new(),
            };
            [
                format!("v{}", v.version),
                v.at.strftime("%Y-%m-%d %H:%M:%S").to_string(),
                format!("{}@{}", v.by.user, v.by.host),
                v.snapshot.short().to_owned(),
                note,
            ]
        })
        .collect();
    let header = ["VERSION", "TIME (UTC)", "BY", "SNAPSHOT", ""].map(str::to_owned);
    let mut widths = [0; 4];
    for cells in std::iter::once(&header).chain(&rows) {
        for (width, cell) in widths.iter_mut().zip(cells) {
            *width = (*width).max(cell.chars().count());
        }
    }
    for [version, at, by, snapshot, note] in std::iter::once(&header).chain(&rows) {
        let [w0, w1, w2, w3] = widths;
        let line = format!("  {version:<w0$}  {at:<w1$}  {by:<w2$}  {snapshot:<w3$}  {note}");
        println!("{}", line.trim_end());
    }
    if let Some(p) = &history.pending {
        let restores = p
            .restores
            .map(|r| format!(", restoring v{r}"))
            .unwrap_or_default();
        println!(
            "Pending: snapshot {}, by {}@{} at {}{restores}; `enclos policy apply {}` restarts the sandbox into it.",
            p.snapshot.short(),
            p.by.user,
            p.by.host,
            p.at.strftime("%Y-%m-%d %H:%M:%S UTC"),
            history.sandbox
        );
    }
}

fn print_diff(sandbox: &SandboxName, diff: &PolicyDiff) {
    if diff.changes.is_empty() && diff.inputs.is_empty() {
        println!(
            "Sandbox {sandbox}: {} grants the same as v{}.",
            diff.to, diff.from
        );
        return;
    }
    println!(
        "Sandbox {sandbox}: what {} changes from v{}:",
        diff.to, diff.from
    );
    if diff.changes.is_empty() {
        println!("  it grants the same");
    }
    for change in &diff.changes {
        println!("  {change}");
    }
    for input in &diff.inputs {
        println!("  {input}");
    }
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

/// `policy edit`: a copy of `policy.toml` beside it, opened in the user's
/// editor, then applied. An edit kept by an earlier `policy edit` (one not
/// applied: refused, cut short, or a dry run) is opened again instead, as
/// long as `policy.toml` is still the file it started from.
fn edit(engine: &Engine, by: &Actor, sandbox: &SandboxName, confirm: Confirm) -> Result<u8> {
    let file = engine.policy(sandbox)?.file;
    let files = engine.edit_files(sandbox);
    let io = |path: &Path| {
        let path = path.to_owned();
        move |source| Error::Layout(LayoutError::Io { path, source })
    };
    let current = std::fs::read_to_string(&file).map_err(io(&file))?;
    let (before, start) = match std::fs::read_to_string(&files.copy) {
        Ok(kept) => {
            let base = match std::fs::read_to_string(&files.base) {
                Ok(base) => Some(base),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
                Err(source) => return Err(io(&files.base)(source)),
            };
            // Without the file it started from, or with another one, the
            // kept edit would undo what changed since.
            if base.as_deref() != Some(current.as_str()) {
                return Err(Error::PolicyFileChanged {
                    sandbox: sandbox.to_string(),
                    file,
                });
            }
            if !output::json() {
                println!("Continuing the edit kept in {}.", files.copy.display());
            }
            (current, kept)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            write_private(&files.base, &current).map_err(io(&files.base))?;
            (current.clone(), current)
        }
        Err(source) => return Err(io(&files.copy)(source)),
    };
    write_private(&files.copy, &start).map_err(io(&files.copy))?;
    run_editor(&files.copy)?;
    let after = std::fs::read_to_string(&files.copy).map_err(io(&files.copy))?;
    // Saved unchanged, an edit records nothing, unless the file holds what
    // the state does not record yet: an edit not applied, such as one made
    // by hand, which closing the editor applies.
    if after == before && engine.policy_file_recorded(sandbox)? {
        let left = forget_edit(&files);
        let code = edit_left_code(&left, exit::OK);
        if output::json() {
            return Ok(output::conclude(
                json!({
                    "sandbox": sandbox.to_string(),
                    "changed": false,
                    "edit_left": left,
                }),
                code,
                || left.join("; "),
            ));
        }
        println!("No change to the policy of sandbox {sandbox}.");
        return Ok(code);
    }
    let applied = match engine.policy_edit(by, sandbox, &before, &after, confirm) {
        Ok(Planned::DryRun(plan)) => {
            if output::json() {
                let mut planned = output::plan(&plan);
                planned["edit_kept_in"] = output::path(&files.copy);
                output::emit(&planned);
                return Ok(exit::OK);
            }
            plan.changes.iter().for_each(|c| println!("Would {c}."));
            println!(
                "Your edit is kept in {}; `enclos policy edit {sandbox}` opens it again.",
                files.copy.display()
            );
            return Ok(exit::OK);
        }
        Ok(Planned::Done(applied)) => applied,
        // Recorded before it failed (a restart with --yes, say): the edit
        // is the file now, and keeping it would only open it again.
        Err(e) if std::fs::read_to_string(&file).is_ok_and(|now| now == after) => {
            let left = forget_edit(&files);
            // In JSON, what was left is said in the error's message, as
            // `edit_left` says it in a document.
            if output::json() && !left.is_empty() {
                return Err(Error::WithContext {
                    what: format!("{e}; {}", left.join("; ")),
                    error: Box::new(e),
                });
            }
            return Err(e);
        }
        Err(e @ Error::PolicyFileChanged { .. }) => return Err(e),
        Err(error) => {
            return Err(Error::WithContext {
                what: format!(
                    "{error}\nYour edit is kept in {}; `enclos policy edit {sandbox}` opens it again, and `enclos policy discard {sandbox}` drops it.",
                    files.copy.display()
                ),
                error: Box::new(error),
            });
        }
    };
    let left = forget_edit(&files);
    if output::json() {
        let (restarted, outcome) = print_outcome(engine, sandbox, &applied)?;
        let mut shown = applied_json(sandbox, &applied, outcome);
        shown["edit_left"] = json!(left);
        let code = edit_left_code(&left, restarted);
        return Ok(output::conclude(shown, code, || {
            let mut why = Vec::new();
            if restarted != exit::OK {
                why.push(restart_failed(sandbox));
            }
            why.extend(left.iter().cloned());
            why.join("; ")
        }));
    }
    let version = applied.version.version;
    match (&applied.outcome, applied.changed) {
        (ChangeOutcome::Pending(_), true) => println!(
            "Sandbox {sandbox} has policy v{version}, with the network part of the edit in force at once."
        ),
        (ChangeOutcome::Pending(_), false) => {
            println!("Sandbox {sandbox} keeps policy v{version} for now.")
        }
        (_, true) => println!(
            "Sandbox {sandbox} has policy v{version}, in force at once for the network and for sessions started from now on."
        ),
        (_, false) => println!("Sandbox {sandbox} keeps policy v{version}."),
    }
    for change in &applied.also {
        println!("  {change}");
    }
    let restarted = print_outcome(engine, sandbox, &applied)?.0;
    Ok(edit_left_code(&left, restarted))
}

/// `code`, or a failure when the edit's copy or base stays: the next `policy
/// edit` would take it up again, though the policy has changed since.
fn edit_left_code(left: &[String], code: u8) -> u8 {
    match left.is_empty() {
        true => code,
        false => code.max(exit::ERROR),
    }
}

/// Removes the copy `policy edit` edited and its base, saying so when it
/// cannot, in text: the next `policy edit` would open it again, and refuse
/// it, made from a policy that has changed since. Returns what it says, or
/// in JSON would say, for the caller to carry in its document and its
/// error; a copy left fails the command.
fn forget_edit(files: &EditFiles) -> Vec<String> {
    let mut left = Vec::new();
    for path in [&files.copy, &files.base] {
        if let Err(e) = std::fs::remove_file(path)
            && e.kind() != std::io::ErrorKind::NotFound
        {
            let said = format!(
                "could not remove {} ({e}); remove it: until then the next `enclos policy edit` opens it again, and refuses it as made from the policy before this edit",
                path.display()
            );
            if !output::json() {
                eprintln!("error: {said}");
            }
            left.push(said);
        }
    }
    left
}

fn write_private(path: &Path, contents: &str) -> std::io::Result<()> {
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .and_then(|mut f| std::io::Write::write_all(&mut f, contents.as_bytes()))
}

/// Opens `path` in `$VISUAL`, else `$EDITOR`, else `vi`, through `sh` so
/// that an editor given with its options (`code --wait`) works.
fn run_editor(path: &Path) -> Result<()> {
    let editor = ["VISUAL", "EDITOR"]
        .into_iter()
        .filter_map(|var| std::env::var(var).ok())
        .find(|v| !v.trim().is_empty())
        .unwrap_or_else(|| "vi".to_owned());
    let status = std::process::Command::new("/bin/sh")
        .arg("-c")
        .arg(format!("{editor} \"$1\""))
        .arg("sh")
        .arg(path)
        .status()
        .map_err(|e| Error::Session {
            what: format!(
                "cannot run the editor `{editor}`: {e}. Your edit is kept in {}",
                path.display()
            ),
        })?;
    if !status.success() {
        return Err(Error::Session {
            what: format!(
                "the editor `{editor}` did not exit cleanly ({status}), so nothing was applied. Your edit is kept in {}",
                path.display()
            ),
        });
    }
    Ok(())
}

fn print_test(sandbox: &SandboxName, report: &TestReport) -> u8 {
    println!("Escape probes in sandbox {sandbox}: each tries one way out and must fail.");
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

/// Whether the sandbox is ready, in one line: READY when the test passed,
/// with what it showed, or NOT READY with every reason it did not. Each
/// probe is listed above it in text, and in the document's `probes` in
/// `json`.
fn verdict(sandbox: &SandboxName, report: &TestReport, json: bool) -> String {
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
                "{} of {total} shown closed{platform}, {} could not be checked on this Mac ({}), none open",
                report.closed(),
                report.inconclusive(),
                listed("inconclusive", "inconclusive")
            ),
        };
        let baseline = match report.baseline {
            Baseline::AllowDefault => {
                " On the (allow default) comparison baseline, which only a debug build compiles and no service runs on."
            }
            Baseline::DenyDefault => "",
        };
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
        why.push("no probe was shown closed by something enclos compiles, so the test showed nothing about the policy".to_owned());
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
            baseline: Baseline::DenyDefault,
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
            "NOT READY: sandbox lab: no probe was shown closed by something enclos compiles, so the test showed nothing about the policy."
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
}
