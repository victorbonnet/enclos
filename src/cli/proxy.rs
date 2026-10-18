//! `enclos proxy run`: a sandbox's egress proxy. Started by enclos itself
//! (the sandbox's service, or `connect`), not typed by people.

use std::net::SocketAddr;
use std::str::FromStr;

use clap::{Args, Subcommand};

use enclos::engine::Engine;
use enclos::error::{Result, exit};
use enclos::model::sandbox::SandboxName;
use enclos::proxy::Listener;

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
        /// Where to listen, with the agent it serves: 127.0.0.1:41001=main. Repeatable.
        #[arg(long = "listen", required = true, value_name = "ADDR[=AGENT]")]
        listeners: Vec<ListenArg>,
    },
}

#[derive(Debug, Clone)]
struct ListenArg(Listener);

impl FromStr for ListenArg {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let (addr, agent) = match s.split_once('=') {
            Some((a, p)) => (a, Some(p.to_owned())),
            None => (s, None),
        };
        let addr: SocketAddr = addr
            .parse()
            .map_err(|_| format!("`{addr}` is not an address such as 127.0.0.1:41001"))?;
        if !addr.ip().is_loopback() {
            return Err(format!(
                "the proxy listens on loopback only, not {}",
                addr.ip()
            ));
        }
        Ok(ListenArg(Listener { addr, agent }))
    }
}

pub fn run(engine: &Engine, args: ProxyArgs) -> Result<u8> {
    match args.verb {
        ProxyVerb::Run { sandbox, listeners } => {
            let listeners: Vec<Listener> = listeners.into_iter().map(|l| l.0).collect();
            engine.run_proxy(&sandbox, &listeners)?;
        }
    }
    Ok(exit::OK)
}
