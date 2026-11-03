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

/// Copies the program at `from` to `to`, executable, through a program of
/// its own, for the reason [`write_script`] gives.
pub(crate) fn copy_program(from: &Path, to: &Path) {
    let copied = Command::new("/bin/sh")
        .arg("-c")
        .arg("cp \"$1\" \"$0.new\" && chmod 755 \"$0.new\" && mv \"$0.new\" \"$0\"")
        .arg(to)
        .arg(from)
        .status()
        .unwrap();
    assert!(copied.success(), "{} to {}", from.display(), to.display());
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    /// Every script written, and every program copied, runs at once, while
    /// another thread starts programs all along, as parallel tests do.
    #[test]
    fn what_is_written_runs_at_once_while_other_threads_start_programs() {
        let dir = tempfile::tempdir().unwrap();
        let done = Arc::new(AtomicBool::new(false));
        let forking = {
            let done = done.clone();
            std::thread::spawn(move || {
                while !done.load(Ordering::Relaxed) {
                    Command::new("/bin/true").status().unwrap();
                }
            })
        };
        for n in 0..100 {
            let script = dir.path().join(format!("script-{n}"));
            write_script(&script, "exit 7");
            assert_eq!(Command::new(&script).status().unwrap().code(), Some(7));
            let copy = dir.path().join(format!("copy-{n}"));
            copy_program(&script, &copy);
            assert_eq!(Command::new(&copy).status().unwrap().code(), Some(7));
        }
        done.store(true, Ordering::Relaxed);
        forking.join().unwrap();
    }
}
