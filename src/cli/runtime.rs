//! `enclos runtime`: install a runtime in a sandbox. Logging it in is the
//! runtime's own command, through `enclos connect` (ADR 0024).

use clap::{Args, Subcommand};

use enclos::engine::Engine;
use enclos::error::{Result, exit};
use enclos::model::audit::Actor;
use enclos::model::plan::Confirm;
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
}

pub fn run(engine: &Engine, by: &Actor, confirm: Confirm, args: RuntimeArgs) -> Result<u8> {
    let RuntimeVerb::Install { runtime, sandbox } = args.verb;
    if confirm == Confirm::DryRun {
        engine.show_sandbox(&sandbox)?;
        println!(
            "Would download the {} installer and run it in sandbox {sandbox}, under its policy.",
            runtime.display_name()
        );
        return Ok(exit::OK);
    }
    let end = engine.install_runtime(by, &sandbox, runtime)?;
    super::connect::report_end(&sandbox, &end);
    if end.exit == 0 {
        println!(
            "{} is installed in sandbox {sandbox}. Log it in and set it up with its own command: `enclos connect {sandbox} -- {}`.",
            runtime.display_name(),
            enclos::runtime::adapter(runtime).login()
        );
    }
    Ok(if end.exit == 0 { exit::OK } else { exit::ERROR })
}
