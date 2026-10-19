//! `enclos launch` and `enclos logs`: a sandbox's background service, as
//! launchd runs it, and its logs.

use std::process::Command;

use clap::Args;

use enclos::engine::Engine;
use enclos::error::{Error, Result};
use enclos::model::audit::Actor;
use enclos::model::sandbox::SandboxName;

#[derive(Args)]
pub struct LaunchArgs {
    sandbox: SandboxName,
}

/// Runs the runtime's gateway in the sandbox until it exits.
pub fn run(engine: &Engine, by: &Actor, args: LaunchArgs) -> Result<u8> {
    let end = engine.launch(by, &args.sandbox)?;
    Ok(u8::try_from(end.exit).unwrap_or(1))
}

#[derive(Args)]
pub struct LogsArgs {
    sandbox: SandboxName,
    /// Keep printing as the services write.
    #[arg(short, long)]
    follow: bool,
}

pub fn logs(engine: &Engine, args: LogsArgs) -> Result<u8> {
    let files = engine.log_files(&args.sandbox)?;
    if files.is_empty() {
        println!(
            "Sandbox {} has no service logs yet. Start it with `enclos sandbox start {}`.",
            args.sandbox, args.sandbox
        );
        return Ok(0);
    }
    let mut tail = Command::new("/usr/bin/tail");
    tail.args(["-n", "40"]);
    if args.follow {
        tail.arg("-F");
    }
    let status = tail.args(&files).status().map_err(|e| Error::Session {
        what: format!("cannot run tail: {e}"),
    })?;
    Ok(if status.success() { 0 } else { 1 })
}
