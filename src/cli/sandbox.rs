//! `enclos sandbox`: create, list, show, start, stop, restart and remove
//! sandboxes.

use clap::{Args, Subcommand};

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
    /// Remove a stopped sandbox, and its home unless --keep-data.
    Rm {
        name: SandboxName,
        /// Keep the sandbox's folder and home on disk.
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
            match engine.create_sandbox(
                by,
                SandboxSpec {
                    name,
                    backend,
                    template,
                },
                confirm,
            )? {
                Planned::DryRun(plan) => plan.changes.iter().for_each(|c| println!("Would {c}.")),
                Planned::Done(r) => println!(
                    "Created sandbox {} ({}, template {}), policy v1, proxy port {}.\nConnect with `enclos connect {}`.",
                    r.name, r.backend, r.template, r.proxy_port, r.name
                ),
            }
        }
        SandboxVerb::List => print_list(&engine.list_sandboxes()?),
        SandboxVerb::Show { name } => {
            print_show(&engine.show_sandbox(&name)?);
            for (label, status) in engine.service_status(&name)? {
                let state = match status {
                    ServiceStatus::Running { pid } => format!("running (pid {pid})"),
                    ServiceStatus::Loaded => "loaded, not running".to_owned(),
                    ServiceStatus::NotLoaded => "not loaded".to_owned(),
                };
                println!("  service {label}: {state}");
            }
            // Agents are the runtime's: nothing to list without one.
            if engine.runtime(&name)?.is_some() {
                let agents = engine.agents(&name)?;
                let list: Vec<String> = agents.iter().map(|a| a.name.to_string()).collect();
                println!(
                    "  agents: {}",
                    if list.is_empty() {
                        "none".to_owned()
                    } else {
                        list.join(", ")
                    }
                );
                for note in super::agent::check_notes(engine, &name, true)? {
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
                Planned::DryRun(plan) => plan.changes.iter().for_each(|c| println!("Would {c}.")),
                Planned::Done(()) => println!("Removed sandbox {name}."),
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
/// running. The exit code is the highest of theirs.
fn each(
    names: &[SandboxName],
    known: impl Fn(&SandboxName) -> Result<()>,
    mut verb: impl FnMut(&SandboxName) -> Result<u8>,
) -> Result<u8> {
    let mut seen = Vec::new();
    for name in names {
        if !seen.contains(&name) {
            known(name)?;
            seen.push(name);
        }
    }
    let mut code = exit::OK;
    for name in seen {
        code = code.max(match verb(name) {
            Ok(code) => code,
            Err(e) => {
                eprintln!("error: {e}");
                e.exit_code()
            }
        });
    }
    Ok(code)
}

fn start(engine: &Engine, by: &Actor, name: &SandboxName, confirm: Confirm) -> Result<u8> {
    if confirm == Confirm::DryRun {
        print_would_start(name, &engine.service_labels(name)?);
        return Ok(exit::OK);
    }
    print_started(engine, name, &engine.start_sandbox(by, name)?)
}

fn stop(engine: &Engine, by: &Actor, name: &SandboxName, confirm: Confirm) -> Result<u8> {
    Ok(match engine.stop_sandbox(by, name, confirm)? {
        Planned::DryRun(plan) => {
            plan.changes.iter().for_each(|c| println!("Would {c}."));
            exit::OK
        }
        Planned::Done(report) => print_stop(name, &report),
    })
}

fn restart(engine: &Engine, by: &Actor, name: &SandboxName, confirm: Confirm) -> Result<u8> {
    match engine.stop_sandbox(by, name, confirm)? {
        Planned::DryRun(plan) => {
            plan.changes.iter().for_each(|c| println!("Would {c}."));
            print_would_start(name, &engine.service_labels(name)?);
            Ok(exit::OK)
        }
        Planned::Done(report) => match print_stop(name, &report) {
            exit::OK => print_started(engine, name, &engine.start_sandbox(by, name)?),
            code => Ok(code),
        },
    }
}

pub(super) fn print_stop(name: &SandboxName, report: &StopReport) -> u8 {
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
        return exit::OK;
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
    exit::ERROR
}

fn print_would_start(name: &SandboxName, labels: &[ServiceLabel]) {
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
) -> Result<u8> {
    let labels = labels
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    if engine.proxy_started(name, PROXY_WAIT)? {
        println!("Started sandbox {name} in the background: {labels}.");
        println!(
            "It starts again at each login until `enclos sandbox stop {name}`. Logs: `enclos logs {name}`."
        );
        return Ok(exit::OK);
    }
    println!("Installed the services of sandbox {name}: {labels}.");
    eprintln!(
        "error: the proxy of sandbox {name} has not started after {} seconds. See `enclos logs {name}` and `enclos sandbox show {name}`; the services stay installed and are tried again until `enclos sandbox stop {name}`.",
        PROXY_WAIT.as_secs()
    );
    Ok(exit::ERROR)
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
            Ok(exit::OK)
        });
        assert_eq!(code.unwrap(), exit::OK);
        assert_eq!(done, ["home", "lab"]);
    }

    #[test]
    fn a_name_that_is_no_sandbox_does_nothing() {
        let mut done = Vec::new();
        let got = each(&names(&["home", "nope"]), known, |n| {
            done.push(n.to_string());
            Ok(exit::OK)
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
                "lab" => Ok(exit::ERROR),
                _ => Ok(exit::OK),
            }
        });
        assert_eq!(code.unwrap(), exit::ERROR);
        assert_eq!(done, ["home", "lab", "work"]);
    }
}
