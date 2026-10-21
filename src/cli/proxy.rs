//! `enclos proxy run`: a sandbox's egress proxy. Started by enclos itself
//! (the sandbox's service, or `connect`), not typed by people.

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
        /// The sandbox's proxy port, such as 41000: the proxy listens on it
        /// on 127.0.0.1 and [::1].
        #[arg(long, value_parser = clap::value_parser!(u16).range(1..))]
        port: u16,
        /// Record this proxy as the sandbox's, as its service does.
        #[arg(long)]
        record: bool,
    },
}

pub fn run(engine: &Engine, by: &Actor, args: ProxyArgs) -> Result<u8> {
    match args.verb {
        ProxyVerb::Run {
            sandbox,
            port,
            record,
        } => {
            engine.run_proxy(&sandbox, port, record.then_some(by))?;
        }
    }
    Ok(exit::OK)
}
