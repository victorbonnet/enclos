//! `enclos sandbox`: create, list, show, stop and remove sandboxes.

use clap::{Args, Subcommand};

use enclos::engine::{Engine, SandboxSpec, SandboxView, StopReport};
use enclos::error::{Result, exit};
use enclos::model::audit::Actor;
use enclos::model::plan::{Confirm, Planned};
use enclos::model::policy::TemplateName;
use enclos::model::sandbox::{BackendKind, SandboxName, SandboxState};

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
    /// Stop every session and process of a sandbox.
    Stop { name: SandboxName },
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
        SandboxVerb::Show { name } => print_show(&engine.show_sandbox(&name)?),
        SandboxVerb::Stop { name } => match engine.stop_sandbox(by, &name, confirm)? {
            Planned::DryRun(plan) => plan.changes.iter().for_each(|c| println!("Would {c}.")),
            Planned::Done(report) => return Ok(print_stop(&name, &report)),
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
    for (s, members) in &v.sessions {
        let active = v.policy.as_ref().map_or(0, |p| p.version);
        let stale = if s.version != active {
            "  (files: restart to apply the active policy)"
        } else {
            ""
        };
        println!(
            "  session {} {}: network v{active} (live), files v{} (at launch){stale}",
            s.id,
            s.kind.as_str(),
            s.version
        );
        for m in members {
            println!("    pid {:<7} {}", m.pid, m.command);
        }
    }
}

fn print_stop(name: &SandboxName, report: &StopReport) -> u8 {
    if report.survivors.is_empty() {
        println!(
            "Stopped sandbox {name}: {} sessions ended.",
            report.stopped.len()
        );
        return exit::OK;
    }
    eprintln!("error: sandbox {name} is marked failed: some processes survived stop:");
    for (session, members) in &report.survivors {
        for m in members {
            eprintln!("  session {session}: pid {} {}", m.pid, m.command);
        }
    }
    exit::ERROR
}
