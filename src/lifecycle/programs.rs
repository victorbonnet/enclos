//! The program files each process runs, as `lsof` names them: its
//! executable and the libraries it mapped (`txt`). The command `ps` lists
//! is the process's argv[0] on macOS, which it chooses and which names no
//! path when it was started through `PATH`; these are the files the kernel
//! mapped, by their real paths (macOS 26.5.2).

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

/// `lsof` could not say which program files the processes run.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("cannot look at the programs processes run with /usr/sbin/lsof: {0}")]
pub struct ProgramsError(String);

/// The program files of each process `lsof` can see (the user's; root's
/// are not listed), by pid.
pub fn program_files() -> Result<BTreeMap<u32, Vec<PathBuf>>, ProgramsError> {
    // `-w`: a warning about another file system (an unreachable network
    // mount) is not a failure to list the processes.
    let out = Command::new("/usr/sbin/lsof")
        .env("LC_ALL", "C")
        .args(["-nP", "-w", "-d", "txt", "-Fpn"])
        .stdin(Stdio::null())
        .output()
        .map_err(|e| ProgramsError(e.to_string()))?;
    parse(&out)
}

/// What `lsof -d txt -Fpn` answered: a `p<pid>` line for each process, then
/// an `n<path>` line for each of its program files. `lsof` itself is always
/// listed, so an empty answer is a failure; it exits 1 when a process it
/// listed went away meanwhile, which is not.
fn parse(out: &Output) -> Result<BTreeMap<u32, Vec<PathBuf>>, ProgramsError> {
    let text = String::from_utf8_lossy(&out.stdout);
    let why = String::from_utf8_lossy(&out.stderr).trim().to_owned();
    match (out.status.code(), text.trim().is_empty(), why.is_empty()) {
        (Some(0), false, _) | (Some(1), false, true) => {}
        _ => return Err(ProgramsError(format!("{}: {why}", out.status))),
    }
    let mut files: BTreeMap<u32, Vec<PathBuf>> = BTreeMap::new();
    let mut pid = None;
    for line in text.lines() {
        if let Some(p) = line.strip_prefix('p') {
            let p = p
                .parse::<u32>()
                .map_err(|_| ProgramsError(format!("unexpected process `{p}`")))?;
            files.entry(p).or_default();
            pid = Some(p);
        } else if let (Some(name), Some(pid)) = (line.strip_prefix('n'), pid) {
            files.entry(pid).or_default().push(PathBuf::from(name));
        }
    }
    Ok(files)
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt;
    use std::process::ExitStatus;

    fn output(code: i32, stdout: &str, stderr: &str) -> Output {
        Output {
            status: ExitStatus::from_raw(code << 8),
            stdout: stdout.as_bytes().to_vec(),
            stderr: stderr.as_bytes().to_vec(),
        }
    }

    #[test]
    fn each_process_gets_its_program_files() {
        let listed = parse(&output(
            0,
            "p10\nftxt\nn/bin/zsh\nftxt\nn/usr/lib/dyld\np11\nftxt\nn/a b/c\n",
            "",
        ))
        .unwrap();
        assert_eq!(
            listed[&10],
            [PathBuf::from("/bin/zsh"), PathBuf::from("/usr/lib/dyld")]
        );
        assert_eq!(listed[&11], [PathBuf::from("/a b/c")]);
    }

    #[test]
    fn a_listing_that_did_not_run_is_an_error() {
        assert!(parse(&output(1, "", "")).is_err());
        assert!(parse(&output(1, "p1\nn/x\n", "lsof: status error")).is_err());
        assert!(parse(&output(0, "pnot-a-pid\n", "")).is_err());
        assert!(parse(&output(1, "p1\nn/x\n", "")).is_ok());
    }

    #[test]
    fn this_process_is_listed_with_its_executable() {
        let listed = program_files().unwrap();
        let me = std::fs::canonicalize(std::env::current_exe().unwrap()).unwrap();
        assert!(
            listed[&std::process::id()].contains(&me),
            "{:?}",
            listed.get(&std::process::id())
        );
    }
}
