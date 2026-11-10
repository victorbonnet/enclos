//! `enclos relay`: a way to the proxy's Unix socket from 127.0.0.1 (design
//! §5, Linux networking), on its own. Hidden: enclos starts none, as a
//! bubblewrap sandbox's namespace holder serves the same relay in its own
//! process (`enclos holder serve`); the tests run this one. It opens nothing
//! of the enclos folder.

use std::path::PathBuf;

use clap::Args;

use enclos::error::Result;

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
    enclos::relay::serve(enclos::relay::listen(port, &socket)?, &socket)
}
