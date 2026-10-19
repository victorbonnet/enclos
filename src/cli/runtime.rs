//! `enclos runtime`: install a runtime in a sandbox and log it in.

use clap::{Args, Subcommand};

use enclos::engine::Engine;
use enclos::error::{Result, exit};
use enclos::model::audit::Actor;
use enclos::model::runtime::RuntimeKind;
use enclos::model::sandbox::SandboxName;

#[derive(Args)]
pub struct RuntimeArgs {
    #[command(subcommand)]
    verb: RuntimeVerb,
}

#[derive(Subcommand)]
enum RuntimeVerb {
    /// Install a runtime in a sandbox with its own installer, run inside the sandbox.
    Install {
        runtime: RuntimeKind,
        #[arg(long)]
        sandbox: SandboxName,
    },
    /// Log the sandbox's runtime in and pick its model, with the runtime's own flow.
    Login {
        sandbox: SandboxName,
        /// Log in with a subscription, through the runtime's own flow; the
        /// only way for now, so it is the default.
        #[arg(long)]
        subscription: bool,
    },
}

pub fn run(engine: &Engine, by: &Actor, args: RuntimeArgs) -> Result<u8> {
    let end = match args.verb {
        RuntimeVerb::Install { runtime, sandbox } => {
            let end = engine.install_runtime(by, &sandbox, runtime)?;
            if end.exit == 0 {
                println!(
                    "{runtime} is installed in sandbox {sandbox}. Log it in with `enclos runtime login {sandbox}`."
                );
            }
            end
        }
        RuntimeVerb::Login { sandbox, .. } => engine.runtime_login(by, &sandbox)?,
    };
    Ok(if end.exit == 0 { exit::OK } else { exit::ERROR })
}
