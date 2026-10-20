//! `enclos sandbox`: create, list, show, stop and remove sandboxes.

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
    /// Run the sandbox's proxy and its runtime's services in the background, now and at each login.
    Start { name: SandboxName },
    /// Stop every service, session and process of a sandbox.
    Stop { name: SandboxName },
    /// Stop the sandbox, then start its services again under the active policy.
    Restart { name: SandboxName },
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
        }
        SandboxVerb::Start { name } if confirm == Confirm::DryRun => {
            print_would_start(&name, &engine.service_labels(&name)?)
        }
        SandboxVerb::Start { name } => {
            return print_started(engine, &name, &engine.start_sandbox(by, &name)?);
        }
        SandboxVerb::Stop { name } => match engine.stop_sandbox(by, &name, confirm)? {
            Planned::DryRun(plan) => plan.changes.iter().for_each(|c| println!("Would {c}.")),
            Planned::Done(report) => return Ok(print_stop(&name, &report)),
        },
        SandboxVerb::Restart { name } => match engine.stop_sandbox(by, &name, confirm)? {
            Planned::DryRun(plan) => {
                plan.changes.iter().for_each(|c| println!("Would {c}."));
                print_would_start(&name, &engine.service_labels(&name)?);
            }
            Planned::Done(report) => {
                let code = print_stop(&name, &report);
                if code != exit::OK {
                    return Ok(code);
                }
                return print_started(engine, &name, &engine.start_sandbox(by, &name)?);
            }
        },
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
    println!(
        "{:<20}  {:<10}  {:<10}  {:<8}  STATE",
        "NAME", "BACKEND", "TEMPLATE", "POLICY"
    );
    for v in views {
        let policy = v
            .policy
            .as_ref()
            .map_or("-".to_owned(), |p| format!("v{}", p.version));
        let sessions = match v.sessions.len() {
            0 => String::new(),
            n => format!(" ({n} sessions)"),
        };
        println!(
            "{:<20}  {:<10}  {:<10}  {:<8}  {}{sessions}",
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
    if v.sessions.is_empty() {
        println!("  no sessions running");
    }
    let active = v.policy.as_ref().map_or(0, |p| p.version);
    for view in &v.sessions {
        let s = &view.session;
        if s.kind == SessionKind::Proxy {
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

fn print_stop(name: &SandboxName, report: &StopReport) -> u8 {
    if report.survivors.is_empty() {
        println!(
            "Stopped sandbox {name}: {} services removed, {} sessions ended.",
            report.services.len(),
            report.stopped.len()
        );
        return exit::OK;
    }
    eprintln!("error: sandbox {name} is marked failed: some processes survived stop:");
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
fn print_started(engine: &Engine, name: &SandboxName, labels: &[ServiceLabel]) -> Result<u8> {
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
