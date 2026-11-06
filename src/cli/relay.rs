//! `enclos relay`: a session's way to the proxy's Unix socket from its own
//! 127.0.0.1 (design §5, Linux networking). Started by enclos itself inside
//! the session, not typed by people. It runs where the enclos folder is out
//! of sight, so it opens none of it.

use std::net::{Ipv4Addr, TcpListener};
use std::os::unix::net::SocketAddr;
use std::path::PathBuf;

use clap::Args;

use enclos::error::{Error, Result};

#[derive(Args)]
pub struct RelayArgs {
    /// The port to listen on, on 127.0.0.1 alone.
    #[arg(long, value_parser = clap::value_parser!(u16).range(1..))]
    port: u16,
    /// The Unix socket each connection is passed to.
    #[arg(long, value_name = "PATH")]
    socket: PathBuf,
}

pub fn run(RelayArgs { port, socket }: RelayArgs) -> Result<u8> {
    // Said now: on the first connection it would reach no one.
    SocketAddr::from_pathname(&socket).map_err(|source| Error::RelaySocket {
        path: socket.clone(),
        source,
    })?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, port))
        .map_err(|source| Error::RelayListen { port, source })?;
    enclos::relay::serve(listener, &socket)
}
