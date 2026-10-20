//! `enclos connect`: a shell, or a command, inside a sandbox, in this terminal.

use std::ffi::OsString;

use clap::Args;

use enclos::engine::Engine;
use enclos::engine::Left;
use enclos::error::{Result, exit};
use enclos::model::audit::Actor;
use enclos::model::plan::{Confirm, Planned};
use enclos::model::sandbox::SandboxName;

#[derive(Args)]
pub struct ConnectArgs {
    sandbox: SandboxName,
    /// A command to run instead of a shell, after `--`, such as the
    /// runtime's own: `enclos connect lab -- hermes -p scout`.
    #[arg(last = true)]
    command: Vec<OsString>,
}

pub fn run(engine: &Engine, by: &Actor, confirm: Confirm, args: ConnectArgs) -> Result<u8> {
    let end = match engine.connect(by, &args.sandbox, args.command, confirm)? {
        Planned::DryRun(plan) => {
            plan.changes.iter().for_each(|c| println!("Would {c}."));
            return Ok(exit::OK);
        }
        Planned::Done(end) => end,
    };
    let shown = format!("sandbox {}", args.sandbox);
    for note in &end.notes {
        eprintln!("enclos: session {} in {shown}: {note}", end.session);
    }
    if let Some(signal) = end.signal {
        eprintln!("enclos: the command was ended by signal {signal}");
    }
    let stays_open = format!(
        "Session {} stays open until `enclos sandbox stop {}` finds them gone",
        end.session, args.sandbox
    );
    match &end.left {
        Left::Nothing => {}
        Left::Running(left) => {
            let pids: Vec<String> = left
                .iter()
                .map(|m| format!("{} ({})", m.pid, m.command))
                .collect();
            eprintln!(
                "enclos: the command exited, but it left {} processes running in {shown}: {}. {stays_open}; `enclos sandbox show {}` lists them.",
                left.len(),
                pids.join(", "),
                args.sandbox
            );
        }
        Left::Unknown(why) => {
            eprintln!(
                "enclos: the command exited, but enclos could not look at what it left running in {shown}: {why}. {stays_open}."
            );
        }
    }
    Ok(u8::try_from(end.exit).unwrap_or(1))
}
