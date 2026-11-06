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
    /// Hand Ctrl-C and Ctrl-\ back to the command, which bubblewrap's outer
    /// process was started ignoring, in a terminal's session.
    #[arg(long)]
    restore_interrupts: bool,
    /// The session's command.
    #[arg(last = true, required = true)]
    command: Vec<OsString>,
}

#[cfg(target_os = "linux")]
pub fn run(args: InsideArgs) -> Result<u8> {
    use enclos::backend::bubblewrap::inside;
    inside::session(&args.compiled, &args.command, args.restore_interrupts)
        .map_err(|e| Error::Inside { why: e.to_string() })
}

#[cfg(not(target_os = "linux"))]
pub fn run(args: InsideArgs) -> Result<u8> {
    drop((args.compiled, args.restore_interrupts, args.command));
    Err(Error::Inside {
        why: "`enclos inside` is the bubblewrap backend's, on Linux".to_owned(),
    })
}
