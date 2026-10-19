//! `enclos proxy run`: a sandbox's egress proxy. Started by enclos itself
//! (the sandbox's service, or `connect`), not typed by people.

use std::net::SocketAddr;
use std::str::FromStr;

use clap::{Args, Subcommand};

use enclos::engine::Engine;
use enclos::error::{Result, exit};
use enclos::model::audit::Actor;
use enclos::model::sandbox::SandboxName;

#[derive(Args)]
pub struct ProxyArgs {
    #[command(subcommand)]
    verb: ProxyVerb,
}

#[derive(Subcommand)]
enum ProxyVerb {
    /// Run the sandbox's proxy until stopped.
    Run {
        sandbox: SandboxName,
        /// Where to listen: the sandbox's port on loopback, such as 127.0.0.1:41000.
        #[arg(long, value_name = "ADDR")]
        listen: ListenArg,
        /// Record this proxy as the sandbox's, as its service does.
        #[arg(long)]
        record: bool,
    },
}

#[derive(Debug, Clone)]
struct ListenArg(SocketAddr);

impl FromStr for ListenArg {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let addr: SocketAddr = s
            .parse()
            .map_err(|_| format!("`{s}` is not an address such as 127.0.0.1:41000"))?;
        if !addr.ip().is_loopback() {
            return Err(format!(
                "the proxy listens on loopback only, not {}",
                addr.ip()
            ));
        }
        Ok(ListenArg(addr))
    }
}

pub fn run(engine: &Engine, by: &Actor, args: ProxyArgs) -> Result<u8> {
    match args.verb {
        ProxyVerb::Run {
            sandbox,
            listen,
            record,
        } => {
            engine.run_proxy(&sandbox, listen.0, record.then_some(by))?;
        }
    }
    Ok(exit::OK)
}
