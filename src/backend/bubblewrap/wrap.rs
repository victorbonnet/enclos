//! Running a program under bubblewrap: the compiled arguments, with the
//! masks that depend on the host made from what it holds at this launch
//! (design §5, What `wrap` does at each launch).
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
use crate::backend::{Launch, SandboxContext, WrapError, environment, under_limits};
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

/// The command that runs `launch` under bubblewrap: `enclos inside` first,
/// in the sandbox's environment, which bubblewrap passes on as it is given.
/// It is set on bubblewrap's own process, never with `--setenv`, so no
/// secret is ever on a command line another process can read.
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
    let mut bwrap = Command::new(programs.bwrap);
    bwrap
        .args(arguments(compiled, host, &launch.reads))
        .arg(enclos)
        .args(["inside", "--compiled"])
        .arg(compiled_path);
    if launch.in_terminal {
        bwrap.arg(super::INTERRUPTS_FLAG);
    }
    bwrap.arg("--").arg(&launch.program).args(&launch.args);
    let command = match launch.in_terminal {
        true => out_of_reach_of_interrupts(bwrap),
        false => bwrap,
    };
    let mut command = under_limits(command, &launch.limits);
    environment::apply(&mut command, ctx, launch);
    command.current_dir(&ctx.home);
    Ok(command)
}

/// `bwrap` with Ctrl-C and Ctrl-\ ignored, for a command's session, which
/// a terminal may run in, or `connect` passes the signals it catches to.
/// bubblewrap's outer process stays in the session's process group, which a
/// terminal's Ctrl-C reaches, and
/// handles only SIGCHLD: ended so, it would take the whole session with it
/// through `--die-with-parent`, a program that catches SIGINT included,
/// where `connect` waits for its program through Ctrl-C (design §8). An
/// ignored signal stays ignored through `exec`, so `enclos inside` hands
/// both back to the command ([`super::INTERRUPTS_FLAG`]). `/bin/sh` reads no
/// startup file when it runs a command, and none of the sandbox's
/// variables can name a function.
fn out_of_reach_of_interrupts(bwrap: Command) -> Command {
    let mut sh = Command::new("/bin/sh");
    sh.arg("-c")
        .arg("trap '' INT QUIT; exec \"$0\" \"$@\"")
        .arg(bwrap.get_program())
        .args(bwrap.get_args());
    sh
}

#[cfg(test)]
mod tests;
