//! `enclos connect`: a shell, or a command, inside a sandbox, in this terminal.

use std::ffi::OsString;

use clap::Args;

use enclos::engine::Engine;
use enclos::error::Result;
use enclos::model::audit::Actor;

use super::target::Target;

#[derive(Args)]
pub struct ConnectArgs {
    /// The sandbox, or one profile of it: `home` or `home/main`.
    target: Target,
    /// A command to run instead of a shell, after `--`.
    #[arg(last = true)]
    command: Vec<OsString>,
}

pub fn run(engine: &Engine, by: &Actor, args: ConnectArgs) -> Result<u8> {
    let end = engine.connect(
        by,
        &args.target.sandbox,
        args.target.profile.as_deref(),
        args.command,
    )?;
    Ok(u8::try_from(end.exit).unwrap_or(1))
}
