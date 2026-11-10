//! Running a program under bubblewrap, in the sandbox's network namespace:
//! the compiled arguments, with the masks that depend on the host made from
//! what it holds at this launch (design §5, What `wrap` does at each
//! launch).
//!
//! [`host`] reads the host, with [`masks`] saying where each mask goes;
//! [`arguments`] only uses what they give, so the order of the masks is
//! tested without a host to read.

mod arguments;
mod host;
mod masks;

use std::path::{Path, PathBuf};
use std::process::Command;

use super::compile::CompiledSandbox;
use super::holder::join_args;
use crate::backend::environment::{self, Loopback};
use crate::backend::{Launch, SandboxContext, WrapError, under_limits};
use crate::policy::paths::is_within;
use arguments::arguments;
pub(super) use host::{Host, read_host};

fn paths(texts: &[String]) -> impl Iterator<Item = PathBuf> + '_ {
    texts.iter().map(PathBuf::from)
}

/// Refuses a staged file the sandbox would read that is not one of the
/// sandbox's `installers/` folder, where the host alone writes: a bind of
/// anything else would show the sandbox more than enclos staged for it.
pub(super) fn staged_only(installers: &Path, reads: &[PathBuf]) -> Result<(), WrapError> {
    for file in reads {
        let named = file.parent() == Some(installers)
            && matches!(
                file.components().next_back(),
                Some(std::path::Component::Normal(_))
            );
        if !named {
            return Err(WrapError(format!(
                "{} is not a file enclos stages in {}, so the sandbox is not shown it",
                file.display(),
                installers.display()
            )));
        }
    }
    Ok(())
}

/// Where enclos and bubblewrap are, for one launch.
pub(super) struct Programs<'a> {
    pub bwrap: &'a Path,
    /// This program, which bubblewrap runs first as `enclos inside`.
    pub enclos: &'a Path,
}

/// The command that runs `launch` under bubblewrap, in the sandbox's network
/// namespace: `enclos holder join` runs `enclos holder enter`, which enters
/// the namespace holder's user and network namespaces (ADR 0039), then
/// becomes bubblewrap, which makes the session's own namespaces inside them
/// and runs `enclos inside` first; `join` starts it again while
/// bubblewrap's setup meets a mount that changed (`setup`). The
/// sandbox's environment is set on the first process, which passes it on as
/// it is given, never with `--setenv`, so no secret is ever on a command
/// line another process can read.
pub(super) fn command(
    programs: &Programs<'_>,
    compiled_path: &Path,
    compiled: &CompiledSandbox,
    host: &Host,
    ctx: &SandboxContext,
    launch: &Launch,
) -> Result<Command, WrapError> {
    let enclos = programs.enclos;
    let root_masks = &compiled.bubblewrap.root_masks;
    if let Some(hidden) = paths(&root_masks.denied)
        .chain(paths(&root_masks.denied_elsewhere))
        .find(|d| is_within(enclos, d))
    {
        return Err(WrapError(format!(
            "enclos runs from {}, inside {}, which the sandbox does not see: install it outside the deny list",
            enclos.display(),
            hidden.display()
        )));
    }
    staged_only(&ctx.installers, &launch.reads)?;
    let mut session = Command::new(enclos);
    session
        .args(join_args(&ctx.holder_socket))
        .arg(programs.bwrap)
        .args(arguments(compiled, host, &launch.reads))
        .arg(enclos)
        .args(["inside", "--compiled"])
        .arg(compiled_path);
    if launch.in_terminal {
        session.arg(super::INTERRUPTS_FLAG);
    }
    session.arg("--").arg(&launch.program).args(&launch.args);
    let command = match launch.in_terminal {
        true => out_of_reach_of_interrupts(session),
        false => session,
    };
    let mut command = under_limits(command, &launch.limits);
    environment::apply(&mut command, ctx, launch, Loopback::Own);
    command.current_dir(&ctx.home);
    Ok(command)
}

/// Runs `session` under `sh` with SIGINT and SIGQUIT ignored, as they stay
/// through each `exec` up to bubblewrap: its outer process is in the
/// terminal's foreground group, and Ctrl-C ending it would end the session
/// through `--die-with-parent`. `enclos inside --restore-interrupts` gives
/// both back to the command (design §5). `/bin/sh` reads no startup file
/// when it runs a command, and none of the sandbox's variables can name a
/// function.
fn out_of_reach_of_interrupts(session: Command) -> Command {
    let mut sh = Command::new("/bin/sh");
    sh.arg("-c")
        .arg("trap '' INT QUIT; exec \"$0\" \"$@\"")
        .arg(session.get_program())
        .args(session.get_args());
    sh
}

#[cfg(test)]
mod tests;
