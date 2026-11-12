//! `enclos holder`: a bubblewrap sandbox's namespace holder (ADR 0039;
//! design §5, A session's namespaces). Hidden: the service manager runs
//! `holder run`, which runs bubblewrap running `holder serve` in the
//! sandbox's namespaces, and every session of the sandbox starts with
//! `holder join`, which runs `holder enter`, which becomes the session's
//! bubblewrap. `run` and `join` start bubblewrap again while its setup
//! meets a mount that changed (design §5, What `wrap` does at each launch).

use std::ffi::OsString;
use std::fs::File;
use std::os::fd::AsFd;
use std::os::unix::process::ExitStatusExt;
use std::path::PathBuf;
use std::process::ExitStatus;

use clap::{Args, Subcommand};

use enclos::error::{Error, Result};
use enclos::model::sandbox::SandboxName;

#[derive(Args)]
pub struct HolderArgs {
    #[command(subcommand)]
    verb: HolderVerb,
}

#[derive(Subcommand)]
enum HolderVerb {
    /// Run the sandbox's namespace holder in bubblewrap; started by the
    /// service manager.
    Run { sandbox: SandboxName },
    /// Serve as the namespace holder in the namespaces bubblewrap made, on
    /// the sockets handed over on stdin; run by `holder run`.
    Serve {
        /// The sandbox's proxy port, where the relay listens on 127.0.0.1.
        #[arg(long, value_parser = clap::value_parser!(u16).range(1..))]
        port: u16,
        /// The proxy's Unix socket, which the relay passes each connection to.
        #[arg(long, value_name = "PATH")]
        proxy: PathBuf,
    },
    /// Run `holder enter` with the command, a session's bubblewrap, to its
    /// end.
    Join {
        /// The namespace holder's socket.
        #[arg(long, value_name = "PATH")]
        socket: PathBuf,
        #[arg(last = true, required = true)]
        command: Vec<OsString>,
    },
    /// Enter the namespace holder's user and network namespaces, then
    /// become the command, a session's bubblewrap; run by `holder join`.
    Enter {
        /// The namespace holder's socket.
        #[arg(long, value_name = "PATH")]
        socket: PathBuf,
        #[arg(last = true, required = true)]
        command: Vec<OsString>,
    },
}

impl HolderArgs {
    /// Whether this is a session's `holder join` or `holder enter`, which
    /// pass on to the session's bubblewrap what they inherited, the
    /// session's marker among it.
    pub fn joins(&self) -> bool {
        matches!(
            self.verb,
            HolderVerb::Join { .. } | HolderVerb::Enter { .. }
        )
    }
}

/// Runs `args`, opening enclos's state only for `holder run`: `enter` must
/// start no thread before it enters a user namespace, and `serve` sees none
/// of enclos's files.
pub fn run(args: HolderArgs) -> Result<u8> {
    match args.verb {
        HolderVerb::Run { sandbox } => {
            // Run by the service manager: no person waits on its writes.
            let engine = enclos::engine::Engine::open(
                enclos::layout::Layout::from_env()?,
                enclos::state::Wait::Background,
            );
            Ok(ended_as(engine.run_holder(&sandbox, &stderr()?)?))
        }
        HolderVerb::Serve { port, proxy } => Err(serve(port, &proxy)),
        HolderVerb::Join { socket, command } => join(&socket, &command),
        HolderVerb::Enter { socket, command } => Err(enter(&socket, &command)),
    }
}

/// Runs the session's bubblewrap through `holder enter`, with this
/// program's stderr, and ends as it did.
fn join(socket: &std::path::Path, command: &[OsString]) -> Result<u8> {
    let failed = |e: std::io::Error| Error::Holder {
        why: format!("cannot run the session's bubblewrap: {e}"),
    };
    let enclos = std::env::current_exe().map_err(failed)?;
    let status = enclos::backend::bubblewrap::holder::join(&enclos, socket, command, &stderr()?)
        .map_err(failed)?;
    Ok(ended_as(status))
}

/// A copy of this program's stderr, for bubblewrap and what it runs.
fn stderr() -> Result<File> {
    std::io::stderr()
        .as_fd()
        .try_clone_to_owned()
        .map(File::from)
        .map_err(|e| Error::Holder {
            why: format!("cannot pass its stderr on to bubblewrap: {e}"),
        })
}

/// The exit code bubblewrap ended with. Ended by a signal, this program
/// ends by the same one, so that whoever waits for it sees what it would
/// have seen of bubblewrap; one that does not end it gives 128 and its
/// number, as a shell does.
fn ended_as(status: ExitStatus) -> u8 {
    match (status.code(), status.signal()) {
        (Some(code), _) => code.clamp(0, 255) as u8,
        (None, Some(signal)) => {
            let _ = signal_hook::low_level::emulate_default_handler(signal);
            (128 + signal).clamp(0, 255) as u8
        }
        (None, None) => 1,
    }
}

#[cfg(target_os = "linux")]
fn serve(port: u16, proxy: &std::path::Path) -> Error {
    let why = match std::io::stdin().as_fd().try_clone_to_owned() {
        Ok(sockets) => enclos::backend::bubblewrap::holder::serve(sockets, port, proxy),
        Err(e) => format!("the namespace holder's sockets are not on its stdin: {e}"),
    };
    Error::Holder { why }
}

#[cfg(target_os = "linux")]
fn enter(socket: &std::path::Path, command: &[OsString]) -> Error {
    Error::Holder {
        why: enclos::backend::bubblewrap::holder::enter(socket, command),
    }
}

#[cfg(not(target_os = "linux"))]
fn serve(_port: u16, _proxy: &std::path::Path) -> Error {
    on_linux()
}

#[cfg(not(target_os = "linux"))]
fn enter(_socket: &std::path::Path, _command: &[OsString]) -> Error {
    on_linux()
}

#[cfg(not(target_os = "linux"))]
fn on_linux() -> Error {
    Error::Holder {
        why: "the namespace holder is the bubblewrap backend's, on Linux".to_owned(),
    }
}
