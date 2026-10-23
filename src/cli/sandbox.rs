//! `enclos sandbox`: create, list, show, start, stop, restart and remove
//! sandboxes.

use clap::{Args, Subcommand};
use serde_json::{Value, json};

use super::output;
use enclos::engine::{Engine, PROXY_WAIT, SandboxSpec, SandboxView, ServiceLine, StopReport};
use enclos::error::{Result, exit};
use enclos::model::audit::Actor;
use enclos::model::plan::{Confirm, Plan, Planned};
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
        /// The policy it starts from: minimal, mcp-only or assistant (design §7).
        #[arg(long, default_value = enclos::policy::DEFAULT_TEMPLATE)]
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
                (Planned::DryRun(plan), _) => output::show_plan(&plan),
                (Planned::Done(r), true) => output::emit(&json!({
                    "sandbox": r.name.to_string(),
                    "backend": r.backend.to_string(),
                    "template": r.template.to_string(),
                    "policy_version": 1,
                    "proxy_port": r.proxy_port,
                })),
                (Planned::Done(r), false) => println!(
                    "Created sandbox {} ({}, template {}), policy v1, proxy port {}.\nConnect with `enclos connect {}`.",
                    r.name, r.backend, r.created_from, r.proxy_port, r.name
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
            // The view first: what follows can fail, and the view is what
            // is read when state is broken. In JSON, such a failure is an
            // `error` beside the view, what was read kept and the rest left
            // null.
            if !output::json() {
                print_show(&view);
            }
            // Agents are the runtime's: nothing to list without one.
            let agents = || -> Result<_> {
                Ok(match engine.runtime(&name)?.is_some() {
                    true => Some((
                        engine.agents(&name)?,
                        super::agent::check_notes(engine, &name, true)?,
                    )),
                    false => None,
                })
            };
            if output::json() {
                let mut shown = show_json(&view);
                for field in ["services", "agents", "notes"] {
                    shown[field] = Value::Null;
                }
                let read = engine.service_status(&name).and_then(|services| {
                    shown["services"] = json!(
                        services
                            .iter()
                            .map(|(label, status)| ServiceLine::new(label, status.clone()))
                            .collect::<Vec<_>>()
                    );
                    agents()
                });
                let (code, shown) = match read {
                    Ok(agents) => {
                        shown["agents"] = match &agents {
                            Some((agents, _)) => {
                                agents.iter().map(|a| json!(a.name.to_string())).collect()
                            }
                            None => Value::Null,
                        };
                        shown["notes"] = agents
                            .as_ref()
                            .map_or_else(Vec::new, |(_, notes)| notes.clone())
                            .into();
                        (exit::OK, shown)
                    }
                    Err(e) => output::with_failure(shown, &e),
                };
                output::emit(&shown);
                return Ok(code);
            }
            let services = engine.service_status(&name)?;
            let agents = agents()?;
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
                Planned::DryRun(plan) => output::show_plan(&plan),
                Planned::Done(left) => {
                    // Removed, but not all of it: a script must see that.
                    let code = match left.is_empty() {
                        true => exit::OK,
                        false => exit::ERROR,
                    };
                    if output::json() {
                        output::emit(&output::with_error(
                            json!({
                                "sandbox": name.to_string(),
                                "removed": true,
                                "secrets_left": left.iter().map(|l| json!({
                                    "secret": l.secret.to_string(),
                                    "why": l.why,
                                })).collect::<Vec<_>>(),
                            }),
                            code,
                            || {
                                format!(
                                    "sandbox {name} is removed, but {} of its secrets stay, and no enclos command reaches them any more",
                                    left.len()
                                )
                            },
                        ));
                    } else {
                        println!("Removed sandbox {name}.");
                        for left in &left {
                            eprintln!(
                                "error: secret {} stays, and no enclos command reaches it any more: {}",
                                left.secret, left.why
                            );
                        }
                    }
                    return Ok(code);
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

/// A state as JSON: its word, and why for a failed one, as in `status`.
fn state_json(s: &SandboxState) -> Value {
    json!(s)
}

fn list_json(v: &SandboxView) -> Value {
    let running = v.sessions.iter().filter(|s| !s.gone()).count();
    json!({
        "name": v.record.name.to_string(),
        "backend": v.record.backend.to_string(),
        "template": v.template.to_string(),
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
        "template": v.template.to_string(),
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
                "members": view.members.iter().map(|m| output::member(m.pid, &m.command)).collect::<Vec<_>>(),
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
    let template = widest("TEMPLATE", |v| v.template.as_str());
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
            v.template,
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
        r.backend, v.template, r.proxy_port
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
/// result, or error, is one element of `sandboxes`, and an `error` beside
/// them says how many failed.
fn each(
    names: &[SandboxName],
    known: impl Fn(&SandboxName) -> Result<()>,
    verb: impl FnMut(&SandboxName) -> Result<(u8, Value)>,
) -> Result<u8> {
    let (code, document) = each_into(names, known, verb, output::json())?;
    if output::json() {
        output::emit(&document);
    }
    Ok(code)
}

/// [`each`] without emitting the document: returns the code and the
/// document; with `json` false, each failure of `verb` is said on stderr as
/// it happens.
fn each_into(
    names: &[SandboxName],
    known: impl Fn(&SandboxName) -> Result<()>,
    mut verb: impl FnMut(&SandboxName) -> Result<(u8, Value)>,
    json: bool,
) -> Result<(u8, Value)> {
    let mut seen = Vec::new();
    for name in names {
        if !seen.contains(&name) {
            known(name)?;
            seen.push(name);
        }
    }
    let mut code = exit::OK;
    let mut failed = 0;
    let mut results = Vec::new();
    let count = seen.len();
    for name in seen {
        let one = match verb(name) {
            Ok((code, result)) => {
                results.push(result);
                code
            }
            Err(e) => {
                let (code, failed) = output::with_failure(json!({"sandbox": name.to_string()}), &e);
                results.push(failed);
                if !json {
                    eprintln!("error: {e}");
                }
                code
            }
        };
        failed += usize::from(one != exit::OK);
        code = code.max(one);
    }
    let document = output::with_error(json!({ "sandboxes": results }), code, || match count {
        1 => "the sandbox failed: see its error".to_owned(),
        count => format!("{failed} of the {count} sandboxes failed: see each one's error"),
    });
    Ok((code, document))
}

fn start(engine: &Engine, by: &Actor, name: &SandboxName, confirm: Confirm) -> Result<(u8, Value)> {
    if confirm == Confirm::DryRun {
        let labels = engine.service_labels(name)?;
        let plan = Plan {
            changes: would_start(name, &labels),
            ..Plan::default()
        };
        return Ok((exit::OK, planned_start(name, &plan, &labels)));
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
        Planned::DryRun(mut plan) => {
            // One plan: the stop's changes, then the start's.
            let labels = engine.service_labels(name)?;
            plan.changes.extend(would_start(name, &labels));
            Ok((exit::OK, planned_start(name, &plan, &labels)))
        }
        Planned::Done(report) => match print_stop(name, &report) {
            (exit::OK, stopped) => {
                let started = engine
                    .start_sandbox(by, name)
                    .and_then(|labels| print_started(engine, name, &labels));
                match started {
                    Ok((code, mut started)) => {
                        started["stop"] = stopped;
                        Ok((code, started))
                    }
                    // Stopped, then not started: in JSON, both are said.
                    Err(e) if output::json() => Ok(output::with_failure(
                        json!({"sandbox": name.to_string(), "stop": stopped}),
                        &e,
                    )),
                    Err(e) => Err(e),
                }
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
    // The same words in text and in JSON.
    let what_now = format!(
        "End them, then run `enclos sandbox stop {name}` again; until then `enclos sandbox rm {name}` refuses."
    );
    let survivors = report.survivors.iter().map(|(_, s)| s.len()).sum::<usize>();
    let value = output::with_error(value, code, || {
        format!("sandbox {name} is marked failed: {survivors} processes survived stop. {what_now}")
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
    eprintln!("{what_now}");
    (code, value)
}

/// The services a start would install and start, as sentences.
fn would_start(name: &SandboxName, labels: &[ServiceLabel]) -> Vec<String> {
    labels
        .iter()
        .map(|label| format!("install and start the service {label} of sandbox {name}"))
        .collect()
}

/// A dry run of a start or a restart: in text, its `Would …` lines; for
/// JSON, the plan with the sandbox and the services it would start.
fn planned_start(name: &SandboxName, plan: &Plan, labels: &[ServiceLabel]) -> Value {
    if !output::json() {
        plan.changes.iter().for_each(|c| println!("Would {c}."));
    }
    let mut planned = output::plan(plan);
    planned["sandbox"] = json!(name.to_string());
    planned["would_start"] = labels.iter().map(ToString::to_string).collect();
    planned
}

/// Reports the services installed, once the proxy runs: the services start
/// on their own, and a proxy whose port is taken never does. Returns its
/// code and, for JSON, the start; the services are said installed even
/// when whether the proxy started cannot be checked.
pub(super) fn print_started(
    engine: &Engine,
    name: &SandboxName,
    labels: &[ServiceLabel],
) -> Result<(u8, Value)> {
    let mut value = json!({
        "sandbox": name.to_string(),
        "services": labels.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "proxy_started": null,
    });
    let shown = labels
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    let started = match engine.proxy_started(name, PROXY_WAIT) {
        Ok(started) => started,
        Err(e) => {
            let e = enclos::error::Error::WithContext {
                what: format!(
                    "the services of sandbox {name} are installed, and are tried again at each login until `enclos sandbox stop {name}`; whether its proxy started could not be checked: {e}"
                ),
                error: Box::new(e),
            };
            if output::json() {
                return Ok(output::with_failure(value, &e));
            }
            println!("Installed the services of sandbox {name}: {shown}.");
            return Err(e);
        }
    };
    value["proxy_started"] = json!(started);
    let code = match started {
        true => exit::OK,
        false => exit::ERROR,
    };
    // The same words in text and in JSON.
    let not_started = format!(
        "the proxy of sandbox {name} has not started after {} seconds. See `enclos logs {name}` and `enclos sandbox show {name}`; the services stay installed and are tried again until `enclos sandbox stop {name}`",
        PROXY_WAIT.as_secs()
    );
    let value = output::with_error(value, code, || not_started.clone());
    if output::json() {
        return Ok((code, value));
    }
    let labels = shown;
    if started {
        println!("Started sandbox {name} in the background: {labels}.");
        println!(
            "It starts again at each login until `enclos sandbox stop {name}`. Logs: `enclos logs {name}`."
        );
        return Ok((code, value));
    }
    println!("Installed the services of sandbox {name}: {labels}.");
    eprintln!("error: {not_started}.");
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

    /// A stop that leaves processes running is said in its value whatever
    /// the output: not stopped, each survivor, and an `error` with code 1.
    #[test]
    fn a_stop_that_leaves_processes_says_so_with_an_error() {
        use enclos::lifecycle::stop::{Survivor, Why};
        use enclos::model::session::{Member, SessionId};
        let report = StopReport {
            services: Vec::new(),
            stopped: vec![SessionId(3)],
            gone: Vec::new(),
            survivors: vec![(
                SessionId(3),
                vec![Survivor {
                    member: Member {
                        pid: 4242,
                        started: "x".into(),
                        command: "sleep".into(),
                    },
                    why: Why::Survived,
                }],
            )],
        };
        let (code, value) = print_stop(&"home".parse().unwrap(), &report);
        assert_eq!(code, exit::ERROR);
        assert_eq!(value["stopped"], false);
        assert_eq!(value["survivors"][0]["pid"], 4242);
        assert_eq!(value["survivors"][0]["session"], 3);
        assert_eq!(value["error"]["exit_code"], 1);
        assert!(
            value["error"]["message"]
                .as_str()
                .unwrap()
                .contains("1 processes survived stop"),
            "{value}"
        );
    }

    /// One sandbox named: its failure is not counted as one of one.
    #[test]
    fn one_sandbox_that_fails_is_said_as_one() {
        let (_, document) = each_into(
            &names(&["home"]),
            known,
            |_| Ok((exit::ERROR, json!({"sandbox": "home"}))),
            true,
        )
        .unwrap();
        assert_eq!(
            document["error"]["message"],
            "the sandbox failed: see its error"
        );
    }

    /// In JSON, each one's result or error is an element, in order, and an
    /// `error` beside them says how many failed.
    #[test]
    fn in_json_each_one_is_an_element_and_the_failures_are_counted() {
        let (code, document) = each_into(
            &names(&["home", "lab", "work"]),
            known,
            |n| match n.as_str() {
                "home" => Err(Error::NoSuchSandbox {
                    name: n.to_string(),
                }),
                "lab" => Ok((exit::ERROR, json!({"sandbox": "lab", "stopped": false}))),
                _ => Ok((exit::OK, json!({"sandbox": "work", "stopped": true}))),
            },
            true,
        )
        .unwrap();
        assert_eq!(code, exit::ERROR);
        let elements = document["sandboxes"].as_array().unwrap();
        assert_eq!(elements[0]["sandbox"], "home");
        assert_eq!(elements[0]["error"]["kind"], "error");
        assert_eq!(elements[1]["stopped"], false);
        assert!(elements[2].get("error").is_none());
        assert_eq!(
            document["error"]["message"],
            "2 of the 3 sandboxes failed: see each one's error"
        );
        assert_eq!(document["error"]["exit_code"], 1);
    }
}
