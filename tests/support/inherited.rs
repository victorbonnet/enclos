//! A caller's descriptor, beyond its standard streams, passed on to a
//! command, as `flock` passes on its lock to the command it runs: shared by
//! the tests that check what enclos starts does not hold it.

use std::path::Path;
use std::process::{Command, Stdio};

/// `command`, run by a shell that first opens `file` as descriptor 9, which
/// `command` inherits.
pub fn holding_open(file: &Path, command: &Command) -> Command {
    let mut sh = Command::new("/bin/sh");
    sh.args(["-c", "exec 9<\"$0\"; exec \"$@\""])
        .arg(file)
        .arg(command.get_program())
        .args(command.get_args());
    for (key, value) in command.get_envs() {
        match value {
            Some(value) => sh.env(key, value),
            None => sh.env_remove(key),
        };
    }
    sh.stdin(Stdio::null());
    sh
}

/// Says whether the shell running it holds descriptor 9.
pub const HOLDS_NINE: &str = "if (: <&9) 2>/dev/null; then echo held; else echo none; fi";
