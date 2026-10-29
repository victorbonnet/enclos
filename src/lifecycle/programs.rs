//! The files each process has mapped, as `lsof` names them (`txt`): its
//! executable (shown on macOS 26.5.2), and, as `lsof` documents it, the
//! libraries it loaded and other files it maps (not shown yet). The
//! command `ps` lists (`comm`) is the process's argv[0] on macOS, which it
//! chooses and which names no path when it was started through `PATH`;
//! these are the files the kernel mapped, by their real paths (macOS
//! 26.5.2).

use std::collections::BTreeMap;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
#[cfg(test)]
use std::process::Stdio;
use std::process::{Command, Output};

/// `lsof` could not say which program files the processes run.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("cannot look at the programs processes run with /usr/sbin/lsof: {0}")]
pub struct ProgramsError(String);

/// The program files of each process `lsof` can see (the user's; root's
/// are not listed), by pid, each named as `lsof` writes it: compare one with
/// a path through [`lsof_name`].
pub fn program_files() -> Result<BTreeMap<u32, Vec<String>>, ProgramsError> {
    let before = readable_own()?;
    // `-b`: no call that can block, such as on a network mount that does not
    // answer, which would hold the state lock with it; `-w`: its warnings
    // about such a mount are not a failure to list the processes.
    let out = super::bounded::output_within(
        Command::new("/usr/sbin/lsof")
            .env("LC_ALL", "C")
            .args(["-nP", "-b", "-w", "-d", "txt", "-Fpn"]),
        super::bounded::LIMIT,
    )
    .map_err(|e| ProgramsError(e.to_string()))?;
    let files = parse(&out)?;
    // With `-w` a failure to read some processes can pass unsaid: a listing
    // without enclos itself, whose program is mapped, is not complete.
    if !files.contains_key(&std::process::id()) {
        return Err(ProgramsError(format!(
            "{}, and its listing left out this process",
            out.status
        )));
    }
    // Nor one that left out another process of the user it could read,
    // there before and after it looked: `-b`, `-w` and an exit of 1 could
    // otherwise pass a part of the listing for the whole.
    let left = left_out(&before, &readable_own()?, &files);
    if !left.is_empty() {
        let pids: Vec<String> = left.iter().map(ToString::to_string).collect();
        return Err(ProgramsError(format!(
            "{}, and its listing left out processes of this user it could read: {}",
            out.status,
            pids.join(", ")
        )));
    }
    Ok(files)
}

/// `P_SUGID` (`sys/proc.h`): a process that changed its user or group as
/// it ran a set-user-id program, such as `/usr/bin/login`, which macOS lets
/// no other process of the user look into, so `lsof` lists it not. A
/// sandbox runs no such program: Seatbelt refuses to start one (`/bin/ps`,
/// shown on macOS 26.5.2).
const P_SUGID: u32 = 0x100;

/// The processes of this user, by effective user, that `lsof` can read:
/// neither zombies nor `P_SUGID` ones.
fn readable_own() -> Result<std::collections::BTreeSet<u32>, ProgramsError> {
    let uid = rustix::process::geteuid().as_raw().to_string();
    let out = super::bounded::output_within(
        Command::new("/bin/ps")
            .env("LC_ALL", "C")
            .args(["-u", &uid, "-o", "pid=,flags=,stat="]),
        super::bounded::LIMIT,
    )
    .map_err(|e| ProgramsError(format!("/bin/ps: {e}")))?;
    if !out.status.success() {
        return Err(ProgramsError(format!(
            "/bin/ps {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    parse_readable(&String::from_utf8_lossy(&out.stdout))
}

/// `ps -o pid=,flags=,stat=` lines, as the pids `lsof` can read.
fn parse_readable(text: &str) -> Result<std::collections::BTreeSet<u32>, ProgramsError> {
    let mut pids = std::collections::BTreeSet::new();
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let mut words = line.split_whitespace();
        let fields = (words.next(), words.next(), words.next());
        let (Some(pid), Some(flags), Some(stat)) = fields else {
            return Err(ProgramsError(format!("unexpected ps line `{line}`")));
        };
        let pid: u32 = pid
            .parse()
            .map_err(|_| ProgramsError(format!("unexpected ps line `{line}`")))?;
        let flags = u32::from_str_radix(flags, 16)
            .map_err(|_| ProgramsError(format!("unexpected ps line `{line}`")))?;
        if flags & P_SUGID == 0 && !stat.starts_with('Z') {
            pids.insert(pid);
        }
    }
    Ok(pids)
}

/// The pids readable both before and after the listing that it left out.
fn left_out(
    before: &std::collections::BTreeSet<u32>,
    after: &std::collections::BTreeSet<u32>,
    listed: &BTreeMap<u32, Vec<String>>,
) -> Vec<u32> {
    before
        .intersection(after)
        .filter(|p| !listed.contains_key(p))
        .copied()
        .collect()
}

/// `path` as `lsof` writes a file name in the C locale (macOS 26.5.2): a
/// backslash doubled, tab, newline and the like as `\t`, `\n`, other control
/// characters as `^A`, and DEL and bytes past ASCII as `\x7f`, `\xc3`. A
/// name holding `^` followed by a capital or one of `@[\]^_` is written as a
/// control character would be, so two names can read the same: matched this
/// way, such a name may be taken for another, never missed.
pub fn lsof_name(path: &Path) -> String {
    let mut name = String::new();
    for &b in path.as_os_str().as_bytes() {
        match b {
            b'\\' => name.push_str("\\\\"),
            b'\t' => name.push_str("\\t"),
            b'\n' => name.push_str("\\n"),
            b'\r' => name.push_str("\\r"),
            0x08 => name.push_str("\\b"),
            0x0c => name.push_str("\\f"),
            0x00..=0x1f => {
                name.push('^');
                name.push(char::from(b + 0x40));
            }
            0x7f..=0xff => name.push_str(&format!("\\x{b:02x}")),
            _ => name.push(char::from(b)),
        }
    }
    name
}

/// What `lsof -d txt -Fpn` answered: a `p<pid>` line for each process, then
/// an `n<name>` line for each of its program files. `lsof` itself is always
/// listed, so an empty answer is a failure; it exits 1 when a process it
/// listed went away meanwhile, which is not.
fn parse(out: &Output) -> Result<BTreeMap<u32, Vec<String>>, ProgramsError> {
    let text = String::from_utf8_lossy(&out.stdout);
    let why = String::from_utf8_lossy(&out.stderr).trim().to_owned();
    match (out.status.code(), text.trim().is_empty(), why.is_empty()) {
        (Some(0), false, _) | (Some(1), false, true) => {}
        _ if why.is_empty() => {
            return Err(ProgramsError(format!("{}, with no output", out.status)));
        }
        _ => return Err(ProgramsError(format!("{}: {why}", out.status))),
    }
    let mut files: BTreeMap<u32, Vec<String>> = BTreeMap::new();
    let mut pid = None;
    for line in text.lines() {
        if let Some(p) = line.strip_prefix('p') {
            let p = p
                .parse::<u32>()
                .map_err(|_| ProgramsError(format!("unexpected process `{p}`")))?;
            files.entry(p).or_default();
            pid = Some(p);
        } else if let (Some(name), Some(pid)) = (line.strip_prefix('n'), pid) {
            files.entry(pid).or_default().push(name.to_owned());
        }
    }
    Ok(files)
}

#[cfg(all(test, target_os = "macos"))]
pub(crate) mod tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt;
    use std::process::ExitStatus;

    /// The variable that has [`sleeps_when_asked`] sleep.
    pub(crate) const SLEEP: &str = "ENCLOS_TEST_SLEEP";

    /// A program run from `dir` that sleeps: a copy of this test program,
    /// running only [`sleeps_when_asked`], started by a relative path, which,
    /// like a start through `PATH`, names no real path, so that `ps` lists it
    /// as `./sleeper`. A copy of
    /// `/bin/sleep` would not do: macOS kills a copied platform program as
    /// it runs. Ended and reaped when dropped; the test's own child.
    pub(crate) struct Sleeper(std::process::Child);

    impl Sleeper {
        pub(crate) fn in_folder(dir: &Path) -> Sleeper {
            std::fs::copy(std::env::current_exe().unwrap(), dir.join("sleeper")).unwrap();
            let child = Command::new("./sleeper")
                .args([
                    "--exact",
                    "lifecycle::programs::tests::sleeps_when_asked",
                    "--test-threads=1",
                ])
                .env(SLEEP, "1")
                .current_dir(dir)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            let mut started = Sleeper(child);
            // Running, and past its start: listed with its own program file.
            std::thread::sleep(std::time::Duration::from_millis(200));
            assert!(started.runs(), "the sleeper exited at once");
            started
        }

        pub(crate) fn pid(&self) -> u32 {
            self.0.id()
        }

        pub(crate) fn runs(&mut self) -> bool {
            self.0.try_wait().unwrap().is_none()
        }
    }

    impl Drop for Sleeper {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    /// What [`Sleeper`] runs: sleeps when asked to, passes at once otherwise.
    #[test]
    fn sleeps_when_asked() {
        if std::env::var_os(SLEEP).is_some() {
            std::thread::sleep(std::time::Duration::from_secs(30));
        }
    }

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
        assert_eq!(listed[&10], ["/bin/zsh", "/usr/lib/dyld"]);
        assert_eq!(listed[&11], ["/a b/c"]);
    }

    #[test]
    fn a_listing_that_did_not_run_is_an_error() {
        let empty = parse(&output(1, "", "")).unwrap_err().to_string();
        assert!(empty.contains("with no output"), "{empty}");
        assert!(parse(&output(1, "p1\nn/x\n", "lsof: status error")).is_err());
        assert!(parse(&output(0, "pnot-a-pid\n", "")).is_err());
        assert!(parse(&output(1, "p1\nn/x\n", "")).is_ok());
    }

    /// A process `lsof` could read, there before and after it looked, and
    /// left out makes the listing a part, not the whole; one gone meanwhile,
    /// one set-user-id (`P_SUGID`) or a zombie does not.
    #[test]
    fn a_listing_that_leaves_out_a_readable_process_is_not_whole() {
        let readable =
            parse_readable("  10     4004 Ss\n  11 4004104 S\n  12     4004 Z\n  13     4004 S\n")
                .unwrap();
        assert_eq!(readable.into_iter().collect::<Vec<_>>(), [10, 13]);
        assert!(parse_readable("x 4004 S\n").is_err());
        let before = [10, 13, 14].into_iter().collect();
        let after = [10, 13].into_iter().collect();
        let mut listed = BTreeMap::new();
        listed.insert(10, Vec::new());
        assert_eq!(left_out(&before, &after, &listed), [13]);
        listed.insert(13, Vec::new());
        assert!(left_out(&before, &after, &listed).is_empty());
    }

    /// On this host, the whole listing leaves out no process it can read.
    #[test]
    fn the_listing_of_this_host_is_whole() {
        program_files().unwrap();
    }

    /// A program in a folder whose name holds what `lsof` escapes is listed
    /// as `lsof_name` writes its path.
    #[test]
    fn a_program_file_is_named_as_lsof_name_writes_it() {
        let dir = tempfile::tempdir().unwrap();
        let odd = dir.path().join("é \\ \t \x01 \x7f dir");
        std::fs::create_dir(&odd).unwrap();
        let sleeper = Sleeper::in_folder(&odd);
        let listed = program_files().unwrap();
        let real = std::fs::canonicalize(odd.join("sleeper")).unwrap();
        let expected = lsof_name(&real);
        assert!(
            expected.contains("\\xc3\\xa9 \\\\ \\t ^A \\x7f dir"),
            "{expected}"
        );
        assert!(
            listed[&sleeper.pid()].contains(&expected),
            "{expected} not in {:?}",
            listed.get(&sleeper.pid())
        );
    }
}
