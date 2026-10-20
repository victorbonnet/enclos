//! `enclos runtime`: install a runtime in a sandbox. Logging it in is the
//! runtime's own command, through `enclos connect` (ADR 0024).

use clap::{Args, Subcommand};

use enclos::engine::Engine;
use enclos::error::{Result, exit};
use enclos::model::audit::Actor;
use enclos::model::plan::{Confirm, Planned};
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
    let end = match engine.install_runtime(by, &sandbox, runtime, confirm)? {
        Planned::DryRun(plan) => {
            plan.changes.iter().for_each(|c| println!("Would {c}."));
            return Ok(exit::OK);
        }
        Planned::Done(end) => end,
    };
    super::connect::report_end(&sandbox, &end.end);
    let shown = runtime.display_name();
    if !end.installed {
        eprintln!(
            "enclos: the {shown} installer exited with {} in sandbox {sandbox}; its output above says why. Nothing is recorded as installed, and the policy is back to v{} without {shown}'s destinations. Fix the cause, then run `enclos runtime install {runtime} --sandbox {sandbox}` again.",
            end.end.exit, end.policy
        );
        return Ok(exit::ERROR);
    }
    println!(
        "{shown} is installed in sandbox {sandbox} (policy v{}). Log it in and set it up with its own command: `enclos connect {sandbox} -- {}`.",
        end.policy,
        enclos::runtime::adapter(runtime).login()
    );
    Ok(exit::OK)
}
