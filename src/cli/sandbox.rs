//! `enclos sandbox`: create, list, show, start, stop, restart and remove
//! sandboxes.

use clap::{Args, Subcommand};
use serde_json::{Value, json};

use super::output;
use enclos::engine::{Engine, PROXY_WAIT, SandboxSpec, SandboxView, StopReport};
use enclos::error::{Result, exit};
use enclos::model::audit::Actor;
use enclos::model::plan::{Confirm, Planned};
use enclos::model::policy::TemplateName;
use enclos::model::sandbox::{BackendKind, SandboxName, SandboxState};
use enclos::model::session::SessionKind;
use enclos::service::{ServiceLabel, ServiceStatus};

#[derive(Args)]
pub struct SandboxArgs {
    #[command(subcommand)]
    verb: SandboxVerb,
}

#[derive(Subcommand)]
enum SandboxVerb {
    /// Create a sandbox with its own home, policy and proxy port.
    Create {
        name: SandboxName,
        /// The isolation technology.
        #[arg(long, default_value = "seatbelt")]
        backend: BackendKind,
        /// The policy it starts from.
        #[arg(long, default_value = "assistant")]
        template: TemplateName,
    },
    /// List sandboxes.
    List,
    /// Show a sandbox: its state, policy version, sessions and their processes.
    Show { name: SandboxName },
    /// Run each sandbox's proxy and its runtime's services in the background, now and at each login.
    Start {
        #[arg(required = true)]
        names: Vec<SandboxName>,
    },
    /// Stop every service, session and process of each sandbox.
    Stop {
        #[arg(required = true)]
        names: Vec<SandboxName>,
    },
    /// Stop each sandbox, then start its services again under the active policy.
    Restart {
        #[arg(required = true)]
        names: Vec<SandboxName>,
    },
    /// Remove a stopped sandbox and its secrets, and its home unless
    /// --keep-data.
    Rm {
        name: SandboxName,
        /// Keep the sandbox's folder and home on disk; its secrets go
        /// still.
        #[arg(long)]
        keep_data: bool,
    },
}

pub fn run(engine: &Engine, by: &Actor, confirm: Confirm, args: SandboxArgs) -> Result<u8> {
    match args.verb {
        SandboxVerb::Create {
            name,
            backend,
            template,
        } => {
            let planned = engine.create_sandbox(
                by,
                SandboxSpec {
                    name,
                    backend,
                    template,
                },
                confirm,
            )?;
            match (planned, output::json()) {
                (Planned::DryRun(plan), true) => output::emit(&output::plan(&plan)),
                (Planned::DryRun(plan), false) => {
                    plan.changes.iter().for_each(|c| println!("Would {c}."))
                }
                (Planned::Done(r), true) => output::emit(&json!({
                    "sandbox": r.name.to_string(),
                    "backend": r.backend.to_string(),
                    "template": r.template.to_string(),
                    "policy_version": 1,
                    "proxy_port": r.proxy_port,
                })),
                (Planned::Done(r), false) => println!(
                    "Created sandbox {} ({}, template {}), policy v1, proxy port {}.\nConnect with `enclos connect {}`.",
                    r.name, r.backend, r.template, r.proxy_port, r.name
                ),
            }
        }
        SandboxVerb::List => {
            let views = engine.list_sandboxes()?;
            match output::json() {
                true => output::emit(&json!({
                    "sandboxes": views.iter().map(list_json).collect::<Vec<_>>(),
                })),
                false => print_list(&views),
            }
        }
        SandboxVerb::Show { name } => {
            let view = engine.show_sandbox(&name)?;
            let services = engine.service_status(&name)?;
            // Agents are the runtime's: nothing to list without one.
            let agents = match engine.runtime(&name)?.is_some() {
                true => Some((
                    engine.agents(&name)?,
                    super::agent::check_notes(engine, &name, true)?,
                )),
                false => None,
            };
            if output::json() {
                let mut shown = show_json(&view);
                shown["services"] = services
                    .iter()
                    .map(|(label, status)| {
                        let (state, pid) = match status {
                            ServiceStatus::Running { pid } => ("running", Some(*pid)),
                            ServiceStatus::Loaded => ("loaded", None),
                            ServiceStatus::NotLoaded => ("not_loaded", None),
                        };
                        json!({"label": label.to_string(), "state": state, "pid": pid})
                    })
                    .collect();
                shown["agents"] = match &agents {
                    Some((agents, _)) => agents.iter().map(|a| json!(a.name.to_string())).collect(),
                    None => Value::Null,
                };
                shown["notes"] = agents
                    .as_ref()
                    .map_or_else(Vec::new, |(_, notes)| notes.clone())
                    .into();
                output::emit(&shown);
                return Ok(exit::OK);
            }
            print_show(&view);
            for (label, status) in services {
                let state = match status {
                    ServiceStatus::Running { pid } => format!("running (pid {pid})"),
                    ServiceStatus::Loaded => "loaded, not running".to_owned(),
                    ServiceStatus::NotLoaded => "not loaded".to_owned(),
                };
                println!("  service {label}: {state}");
            }
            if let Some((agents, notes)) = agents {
                let list: Vec<String> = agents.iter().map(|a| a.name.to_string()).collect();
                println!(
                    "  agents: {}",
                    if list.is_empty() {
                        "none".to_owned()
                    } else {
                        list.join(", ")
                    }
                );
                for note in notes {
                    println!("  {note}");
                }
            }
        }
        SandboxVerb::Start { names } => {
            return each(
                &names,
                |n| engine.require_sandbox(n),
                |name| start(engine, by, name, confirm),
            );
        }
        SandboxVerb::Stop { names } => {
            return each(
                &names,
                |n| engine.require_sandbox(n),
                |name| stop(engine, by, name, confirm),
            );
        }
        SandboxVerb::Restart { names } => {
            return each(
                &names,
                |n| engine.require_sandbox(n),
                |name| restart(engine, by, name, confirm),
            );
        }
        SandboxVerb::Rm { name, keep_data } => {
            match engine.remove_sandbox(by, &name, keep_data, confirm)? {
                Planned::DryRun(plan) if output::json() => output::emit(&output::plan(&plan)),
                Planned::DryRun(plan) => plan.changes.iter().for_each(|c| println!("Would {c}.")),
                Planned::Done(left) => {
                    if output::json() {
                        output::emit(&json!({
                            "sandbox": name.to_string(),
                            "removed": true,
                            "secrets_left": left.iter().map(|l| json!({
                                "secret": l.secret.to_string(),
                                "why": l.why,
                            })).collect::<Vec<_>>(),
                        }));
                    } else {
                        println!("Removed sandbox {name}.");
                        for left in &left {
                            eprintln!(
                                "error: secret {} stays, and no enclos command reaches it any more: {}",
                                left.secret, left.why
                            );
                        }
                    }
                    // Removed, but not all of it: a script must see that.
                    if !left.is_empty() {
                        return Ok(exit::ERROR);
                    }
                }
            }
        }
    }
    Ok(exit::OK)
}

fn state(s: &SandboxState) -> String {
    match s {
        SandboxState::Created => "created".into(),
        SandboxState::Running => "running".into(),
        SandboxState::Stopped => "stopped".into(),
        SandboxState::Failed { reason } => format!("failed: {reason}"),
    }
}

/// A state as JSON: its word, and why for a failed one.
fn state_json(s: &SandboxState) -> Value {
    match s {
        SandboxState::Failed { reason } => json!({"state": "failed", "reason": reason}),
        other => json!({"state": state(other)}),
    }
}

fn list_json(v: &SandboxView) -> Value {
    let running = v.sessions.iter().filter(|s| !s.gone()).count();
    json!({
        "name": v.record.name.to_string(),
        "backend": v.record.backend.to_string(),
        "template": v.record.template.to_string(),
        "policy_version": v.policy.as_ref().map(|p| p.version),
        "state": state_json(&v.record.state),
        "sessions_running": running,
        "sessions_gone": v.sessions.len() - running,
    })
}

fn show_json(v: &SandboxView) -> Value {
    let r = &v.record;
    json!({
        "name": r.name.to_string(),
        "state": state_json(&r.state),
        "backend": r.backend.to_string(),
        "template": r.template.to_string(),
        "proxy_port": r.proxy_port,
        "active_policy": v.policy.as_ref().map(|p| json!({
            "version": p.version,
            "snapshot": p.snapshot.0,
        })),
        "pending_policy": v.pending.as_ref().map(|p| json!({"snapshot": p.snapshot.0})),
        "policy_refused": v.policy_refused,
        "sessions": v.sessions.iter().map(|view| {
            let s = &view.session;
            json!({
                "id": s.id.0,
                "kind": s.kind.as_str(),
                "service": s.service,
                "gone": view.gone(),
                "version": s.version,
                "needs_restart": view.needs_restart,
                "members": view.members.iter().map(|m| json!({
                    "pid": m.pid,
                    "command": m.command,
                })).collect::<Vec<_>>(),
            })
        }).collect::<Vec<_>>(),
    })
}

fn print_list(views: &[SandboxView]) {
    if views.is_empty() {
        println!("No sandboxes yet. Create one with `enclos sandbox create <name>`.");
        return;
    }
    let widest = |header: &str, cell: fn(&SandboxView) -> &str| {
        views
            .iter()
            .map(|v| cell(v).len())
            .fold(header.len(), usize::max)
    };
    let name = widest("NAME", |v| v.record.name.as_str());
    let template = widest("TEMPLATE", |v| v.record.template.as_str());
    println!(
        "{:<name$}  {:<10}  {:<template$}  {:<8}  STATE",
        "NAME", "BACKEND", "TEMPLATE", "POLICY"
    );
    for v in views {
        let policy = v
            .policy
            .as_ref()
            .map_or("-".to_owned(), |p| format!("v{}", p.version));
        let running = v.sessions.iter().filter(|s| !s.gone()).count();
        let gone = v.sessions.len() - running;
        let sessions = match (running, gone) {
            (0, 0) => String::new(),
            (n, 0) => format!(" ({n} sessions)"),
            (n, g) => format!(" ({n} sessions, {g} gone, not recorded)"),
        };
        println!(
            "{:<name$}  {:<10}  {:<template$}  {:<8}  {}{sessions}",
            v.record.name,
            v.record.backend,
            v.record.template,
            policy,
            state(&v.record.state)
        );
    }
}

fn print_show(v: &SandboxView) {
    let r = &v.record;
    println!("Sandbox {}: {}", r.name, state(&r.state));
    println!(
        "  backend {}, template {}, proxy port {}",
        r.backend, r.template, r.proxy_port
    );
    if let Some(p) = &v.policy {
        println!(
            "  active policy v{} (snapshot {})",
            p.version,
            p.snapshot.short()
        );
    }
    if let Some(p) = &v.pending {
        println!(
            "  pending policy (snapshot {}), waiting for `enclos policy apply {}`, which restarts the sandbox into it; `enclos policy show {} --pending` shows it",
            p.snapshot.short(),
            r.name,
            r.name
        );
    }
    if let Some(why) = &v.policy_refused {
        println!("  nothing new starts here, and what runs keeps its policy: {why}");
    }
    let all_gone = v.sessions.iter().all(|s| s.gone());
    if all_gone {
        println!("  no sessions running");
    }
    // `stop` also ends the sessions still running: said, since it asks
    // nothing first.
    let records = match all_gone {
        true => format!("`enclos sandbox stop {}` records its end", r.name),
        false => format!(
            "`enclos sandbox stop {}` records its end, and also stops the sessions still running",
            r.name
        ),
    };
    let active = v.policy.as_ref().map_or(0, |p| p.version);
    for view in &v.sessions {
        let s = &view.session;
        if view.gone() {
            // Nothing ran to record its end (a crash, a restart of the Mac,
            // `enclos` killed): a read records nothing.
            println!(
                "  session {} {}: gone, not recorded; {records}",
                s.id,
                s.kind.as_str(),
            );
        } else if s.kind == SessionKind::Proxy {
            // Outside the sandbox, with the network policy, which is live.
            println!(
                "  proxy, session {}: port {}, network v{active} (live)",
                s.id, r.proxy_port
            );
        } else {
            let restart = match view.needs_restart {
                true => "  (restart to apply the active policy's file and program rules)",
                false => "",
            };
            println!(
                "  session {} {}: network v{active} (live)  files, programs, resources v{} (at launch){restart}",
                s.id,
                s.kind.as_str(),
                s.version
            );
        }
        for m in &view.members {
            println!("    pid {:<7} {}", m.pid, m.command);
        }
    }
}

/// Runs `verb` on each sandbox named, in order, once `known` accepted every
/// name, so a mistyped name changes nothing. A sandbox named twice is done
/// once. A sandbox that fails is said, as for a single one, and the next
/// one is still done: one that cannot stop does not keep the others
/// running. The exit code is the highest of theirs. In JSON, each one's
/// result, or error, is one element of `sandboxes`.
fn each(
    names: &[SandboxName],
    known: impl Fn(&SandboxName) -> Result<()>,
    mut verb: impl FnMut(&SandboxName) -> Result<(u8, Value)>,
) -> Result<u8> {
    let mut seen = Vec::new();
    for name in names {
        if !seen.contains(&name) {
            known(name)?;
            seen.push(name);
        }
    }
    let mut code = exit::OK;
    let mut results = Vec::new();
    for name in seen {
        code = code.max(match verb(name) {
            Ok((code, result)) => {
                results.push(result);
                code
            }
            Err(e) => {
                let code = e.exit_code();
                match output::json() {
                    true => {
                        let mut failed = output::error(&e, code);
                        failed["sandbox"] = json!(name.to_string());
                        results.push(failed);
                    }
                    false => eprintln!("error: {e}"),
                }
                code
            }
        });
    }
    if output::json() {
        output::emit(&json!({ "sandboxes": results }));
    }
    Ok(code)
}

fn start(engine: &Engine, by: &Actor, name: &SandboxName, confirm: Confirm) -> Result<(u8, Value)> {
    if confirm == Confirm::DryRun {
        let labels = engine.service_labels(name)?;
        print_would_start(name, &labels);
        return Ok((exit::OK, would_start_json(name, &labels)));
    }
    print_started(engine, name, &engine.start_sandbox(by, name)?)
}

fn stop(engine: &Engine, by: &Actor, name: &SandboxName, confirm: Confirm) -> Result<(u8, Value)> {
    Ok(match engine.stop_sandbox(by, name, confirm)? {
        Planned::DryRun(plan) => {
            if !output::json() {
                plan.changes.iter().for_each(|c| println!("Would {c}."));
            }
            let mut planned = output::plan(&plan);
            planned["sandbox"] = json!(name.to_string());
            (exit::OK, planned)
        }
        Planned::Done(report) => print_stop(name, &report),
    })
}

fn restart(
    engine: &Engine,
    by: &Actor,
    name: &SandboxName,
    confirm: Confirm,
) -> Result<(u8, Value)> {
    match engine.stop_sandbox(by, name, confirm)? {
        Planned::DryRun(plan) => {
            let labels = engine.service_labels(name)?;
            if !output::json() {
                plan.changes.iter().for_each(|c| println!("Would {c}."));
            }
            print_would_start(name, &labels);
            let mut planned = output::plan(&plan);
            planned["sandbox"] = json!(name.to_string());
            planned["would_start"] = would_start_json(name, &labels)["would_start"].clone();
            Ok((exit::OK, planned))
        }
        Planned::Done(report) => match print_stop(name, &report) {
            (exit::OK, stopped) => {
                let (code, mut started) =
                    print_started(engine, name, &engine.start_sandbox(by, name)?)?;
                started["stopped"] = stopped;
                Ok((code, started))
            }
            failed => Ok(failed),
        },
    }
}

/// Says how a stop went, in text; returns its code and, for JSON, its
/// report.
pub(super) fn print_stop(name: &SandboxName, report: &StopReport) -> (u8, Value) {
    let code = match report.survivors.is_empty() {
        true => exit::OK,
        false => exit::ERROR,
    };
    let value = json!({
        "sandbox": name.to_string(),
        "stopped": report.survivors.is_empty(),
        "services_removed": report.services.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "sessions_ended": report.stopped.iter().map(|s| s.0).collect::<Vec<_>>(),
        "sessions_gone": report.gone.iter().map(|s| s.0).collect::<Vec<_>>(),
        "survivors": report.survivors.iter().flat_map(|(session, survivors)| {
            survivors.iter().map(move |s| json!({
                "session": session.0,
                "pid": s.member.pid,
                "command": s.member.command,
                "why": s.why.describe(),
            }))
        }).collect::<Vec<_>>(),
    });
    if output::json() {
        return (code, value);
    }
    let gone = match report.gone.len() {
        0 => String::new(),
        n => format!(", {n} found gone and recorded"),
    };
    if report.survivors.is_empty() {
        println!(
            "Stopped sandbox {name}: {} services removed, {} sessions ended{gone}.",
            report.services.len(),
            report.stopped.len()
        );
        return (code, value);
    }
    eprintln!(
        "error: sandbox {name} is marked failed: some processes survived stop ({} sessions ended{gone}):",
        report.stopped.len()
    );
    for (session, survivors) in &report.survivors {
        for s in survivors {
            eprintln!(
                "  session {session}: pid {} {}: {}",
                s.member.pid,
                s.member.command,
                s.why.describe()
            );
        }
    }
    eprintln!(
        "End them, then run `enclos sandbox stop {name}` again; until then `enclos sandbox rm {name}` refuses."
    );
    (code, value)
}

fn would_start_json(name: &SandboxName, labels: &[ServiceLabel]) -> Value {
    json!({
        "sandbox": name.to_string(),
        "dry_run": true,
        "would_start": labels.iter().map(ToString::to_string).collect::<Vec<_>>(),
    })
}

fn print_would_start(name: &SandboxName, labels: &[ServiceLabel]) {
    if output::json() {
        return;
    }
    for label in labels {
        println!("Would install and start the service {label} of sandbox {name}.");
    }
}

/// Reports the services installed, once the proxy runs: the services start
/// on their own, and a proxy whose port is taken never does.
pub(super) fn print_started(
    engine: &Engine,
    name: &SandboxName,
    labels: &[ServiceLabel],
) -> Result<(u8, Value)> {
    let started = engine.proxy_started(name, PROXY_WAIT)?;
    let value = json!({
        "sandbox": name.to_string(),
        "services": labels.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "proxy_started": started,
    });
    let code = match started {
        true => exit::OK,
        false => exit::ERROR,
    };
    if output::json() {
        return Ok((code, value));
    }
    let labels = labels
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    if started {
        println!("Started sandbox {name} in the background: {labels}.");
        println!(
            "It starts again at each login until `enclos sandbox stop {name}`. Logs: `enclos logs {name}`."
        );
        return Ok((code, value));
    }
    println!("Installed the services of sandbox {name}: {labels}.");
    eprintln!(
        "error: the proxy of sandbox {name} has not started after {} seconds. See `enclos logs {name}` and `enclos sandbox show {name}`; the services stay installed and are tried again until `enclos sandbox stop {name}`.",
        PROXY_WAIT.as_secs()
    );
    Ok((code, value))
}

#[cfg(test)]
mod tests {
    use super::*;
    use enclos::error::Error;

    fn names(list: &[&str]) -> Vec<SandboxName> {
        list.iter().map(|n| n.parse().unwrap()).collect()
    }

    fn known(name: &SandboxName) -> Result<()> {
        match name.as_str() {
            "nope" => Err(Error::NoSuchSandbox {
                name: name.to_string(),
            }),
            _ => Ok(()),
        }
    }

    #[test]
    fn each_sandbox_is_done_once_in_order() {
        let mut done = Vec::new();
        let code = each(&names(&["home", "lab", "home"]), known, |n| {
            done.push(n.to_string());
            Ok((exit::OK, Value::Null))
        });
        assert_eq!(code.unwrap(), exit::OK);
        assert_eq!(done, ["home", "lab"]);
    }

    #[test]
    fn a_name_that_is_no_sandbox_does_nothing() {
        let mut done = Vec::new();
        let got = each(&names(&["home", "nope"]), known, |n| {
            done.push(n.to_string());
            Ok((exit::OK, Value::Null))
        });
        assert!(matches!(got, Err(Error::NoSuchSandbox { .. })), "{got:?}");
        assert!(done.is_empty(), "{done:?}");
    }

    #[test]
    fn one_that_fails_does_not_stop_the_others_and_sets_the_code() {
        let mut done = Vec::new();
        let code = each(&names(&["home", "lab", "work"]), known, |n| {
            done.push(n.to_string());
            match n.as_str() {
                "home" => Err(Error::NoSuchSandbox {
                    name: n.to_string(),
                }),
                "lab" => Ok((exit::ERROR, Value::Null)),
                _ => Ok((exit::OK, Value::Null)),
            }
        });
        assert_eq!(code.unwrap(), exit::ERROR);
        assert_eq!(done, ["home", "lab", "work"]);
    }
}
