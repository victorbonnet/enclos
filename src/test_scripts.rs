//! Stand-in programs for tests, written as shell scripts.

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

/// Writes `body` as an executable `/bin/sh` script at `path`, through a
/// program of its own: a descriptor this process held open for writing could
/// reach a child a parallel test is starting, and the script then could not
/// run (ETXTBSY). A script already there is replaced in one step.
pub(crate) fn write_script(path: &Path, body: &str) {
    let mut sh = Command::new("/bin/sh")
        .arg("-c")
        .arg("cat > \"$0.new\" && chmod 755 \"$0.new\" && mv \"$0.new\" \"$0\"")
        .arg(path)
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    sh.stdin
        .take()
        .unwrap()
        .write_all(format!("#!/bin/sh\n{body}\n").as_bytes())
        .unwrap();
    assert!(sh.wait().unwrap().success(), "{}", path.display());
}
