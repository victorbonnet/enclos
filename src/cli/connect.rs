//! `enclos connect`: a shell, or a command, inside a sandbox, in this terminal.

use std::ffi::OsString;

use clap::Args;

use enclos::engine::Engine;
use enclos::error::Result;
use enclos::model::audit::Actor;
use enclos::model::sandbox::SandboxName;

#[derive(Args)]
pub struct ConnectArgs {
    sandbox: SandboxName,
    /// A command to run instead of a shell, after `--`, such as the
    /// runtime's own: `enclos connect lab -- hermes -p scout`.
    #[arg(last = true)]
    command: Vec<OsString>,
}

pub fn run(engine: &Engine, by: &Actor, args: ConnectArgs) -> Result<u8> {
    let end = engine.connect(by, &args.sandbox, args.command)?;
    if !end.left.is_empty() {
        let pids: Vec<String> = end
            .left
            .iter()
            .map(|m| format!("{} ({})", m.pid, m.command))
            .collect();
        eprintln!(
            "enclos: the command exited, but it left {} processes running in sandbox {}: {}. Session {} stays open until they end; `enclos sandbox show {}` lists them.",
            end.left.len(),
            args.sandbox,
            pids.join(", "),
            end.session,
            args.sandbox
        );
    }
    Ok(u8::try_from(end.exit).unwrap_or(1))
}
