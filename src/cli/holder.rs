//! `enclos holder`: a bubblewrap sandbox's namespace holder (ADR 0039;
//! design §5, A session's namespaces). Hidden: the service manager runs
//! `holder run`, which becomes bubblewrap running `holder serve` in the
//! sandbox's namespaces, and every session of the sandbox starts with
//! `holder join`.

use std::ffi::OsString;
use std::path::PathBuf;

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
    /// the socket bound on stdin; run by `holder run`.
    Serve {
        /// The sandbox's proxy port, where the relay listens on 127.0.0.1.
        #[arg(long, value_parser = clap::value_parser!(u16).range(1..))]
        port: u16,
        /// The proxy's Unix socket, which the relay passes each connection to.
        #[arg(long, value_name = "PATH")]
        proxy: PathBuf,
    },
    /// Enter the namespace holder's user and network namespaces, then run
    /// the command, a session's bubblewrap.
    Join {
        /// The namespace holder's socket.
        #[arg(long, value_name = "PATH")]
        socket: PathBuf,
        #[arg(last = true, required = true)]
        command: Vec<OsString>,
    },
}

impl HolderArgs {
    /// Whether this is a session's `holder join`, which passes on to the
    /// session's bubblewrap what it inherited, the session's marker among it.
    pub fn joins(&self) -> bool {
        matches!(self.verb, HolderVerb::Join { .. })
    }
}

/// Runs `args`, opening enclos's state only for `holder run`: `join` must
/// start no thread before it enters a user namespace, and `serve` sees none
/// of enclos's files.
pub fn run(args: HolderArgs) -> Result<u8> {
    match args.verb {
        HolderVerb::Run { sandbox } => {
            let engine = enclos::engine::Engine::open(enclos::layout::Layout::from_env()?);
            Err(engine.run_holder(&sandbox))
        }
        HolderVerb::Serve { port, proxy } => Err(serve(port, &proxy)),
        HolderVerb::Join { socket, command } => Err(join(&socket, &command)),
    }
}

#[cfg(target_os = "linux")]
fn serve(port: u16, proxy: &std::path::Path) -> Error {
    use std::os::fd::AsFd;
    let why = match std::io::stdin().as_fd().try_clone_to_owned() {
        Ok(socket) => enclos::backend::bubblewrap::holder::serve(socket, port, proxy),
        Err(e) => format!("the namespace holder's socket is not on its stdin: {e}"),
    };
    Error::Holder { why }
}

#[cfg(target_os = "linux")]
fn join(socket: &std::path::Path, command: &[OsString]) -> Error {
    Error::Holder {
        why: enclos::backend::bubblewrap::holder::join(socket, command),
    }
}

#[cfg(not(target_os = "linux"))]
fn serve(_port: u16, _proxy: &std::path::Path) -> Error {
    on_linux()
}

#[cfg(not(target_os = "linux"))]
fn join(_socket: &std::path::Path, _command: &[OsString]) -> Error {
    on_linux()
}

#[cfg(not(target_os = "linux"))]
fn on_linux() -> Error {
    Error::Holder {
        why: "the namespace holder is the bubblewrap backend's, on Linux".to_owned(),
    }
}
