//! `enclos inside`: what bubblewrap runs first in a session (design §5,
//! What a session runs first). What it applies stays for the life of the
//! process and of all it runs.

use std::ffi::OsString;
use std::path::PathBuf;

use clap::Args;

use enclos::error::{Error, Result};

#[derive(Args)]
pub struct InsideArgs {
    /// The session's file in `compiled/`.
    #[arg(long, value_name = "PATH")]
    compiled: PathBuf,
    /// Be the session's relay: what a session starts of itself, on stdin the
    /// port it holds.
    #[arg(long, conflicts_with = "command")]
    relay: bool,
    /// The session's command.
    #[arg(last = true, required_unless_present = "relay")]
    command: Vec<OsString>,
}

#[cfg(target_os = "linux")]
pub fn run(args: InsideArgs) -> Result<u8> {
    use enclos::backend::bubblewrap::inside;
    let failed = match args.relay {
        true => inside::relay(&args.compiled),
        false => inside::session(&args.compiled, &args.command),
    };
    Err(Error::Inside {
        why: failed.to_string(),
    })
}

#[cfg(not(target_os = "linux"))]
pub fn run(_: InsideArgs) -> Result<u8> {
    Err(Error::Inside {
        why: "`enclos inside` is the bubblewrap backend's, on Linux".to_owned(),
    })
}
