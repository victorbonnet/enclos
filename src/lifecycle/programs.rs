//! How macOS says which files each process has mapped, through `lsof`
//! (`proc::program_files` says it on Linux), as `lsof` names them (`txt`): its
//! executable (shown on macOS 26.5.2), and, as `lsof` documents it, the
//! libraries it loaded and other files it maps (not shown yet). The
//! command `ps` lists (`comm`) is the process's argv[0] on macOS, which it
//! chooses and which names no path when it was started through `PATH`;
//! these are the files the kernel mapped, by their real paths (macOS
//! 26.5.2).

use std::collections::{BTreeMap, BTreeSet};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
#[cfg(all(test, target_os = "macos"))]
use std::process::Stdio;
use std::process::{Command, ExitStatus, Output};

/// The host could not say which program files the processes run.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("cannot look at the programs processes run with {with}: {why}")]
pub struct ProgramsError {
    /// What enclos looked with: `/usr/sbin/lsof` or `/proc`.
    with: &'static str,
    why: String,
}

impl ProgramsError {
    /// `lsof`, or the `ps` that checks it, could not answer.
    fn lsof(why: String) -> ProgramsError {
        ProgramsError {
            with: "/usr/sbin/lsof",
            why,
        }
    }

    /// `/proc` could not be read.
    pub(super) fn proc(why: String) -> ProgramsError {
        ProgramsError { with: "/proc", why }
    }
}

/// The program files of each process `lsof` can see (the user's; root's
/// are not listed), by pid, each named as `lsof` writes it: compare one with
/// a path through [`lsof_name`].
pub fn program_files() -> Result<BTreeMap<u32, Vec<String>>, ProgramsError> {
    whole(readable_own, list)
}

/// Every process's program files through `list`, checked whole against
/// what `readable` says `lsof` can read. A process replacing its program
/// has, for a moment, no program file for `lsof` to list (shown on macOS
/// 26.5.2), so it can be there before and after a listing that left it out:
/// those alone are looked at again. An empty answer does not say why it
/// listed none, so the last `ps`, not `lsof`, says which have gone, and only
/// one still there and still left out makes the listing a part.
fn whole(
    readable: impl Fn(Option<&[u32]>) -> Result<BTreeSet<u32>, ProgramsError>,
    list: impl Fn(Option<&[u32]>) -> Result<Listing, ProgramsError>,
) -> Result<BTreeMap<u32, Vec<String>>, ProgramsError> {
    let before = readable(None)?;
    let Listing { status, mut files } = list(None)?;
    // With `-w` a failure to read some processes can pass unsaid: a listing
    // without enclos itself, whose program is mapped, is not complete.
    if !files.contains_key(&std::process::id()) {
        return Err(ProgramsError::lsof(format!(
            "{status}, and its listing left out this process"
        )));
    }
    // Nor one that left out another process of the user it could read,
    // there before and after it looked: `-b`, `-w` and an exit of 1 could
    // otherwise pass a part of the listing for the whole.
    let mut left = left_out(&before, &readable(None)?, &files);
    if left.is_empty() {
        return Ok(files);
    }
    let again = list(Some(&left)).map_err(|e| {
        ProgramsError::lsof(format!(
            "{status}, and its listing left out processes of this user it could read: {}; looking at them again: {}",
            joined(&left, ", "),
            e.why
        ))
    })?;
    files.extend(again.files);
    let still = readable(Some(&left))?;
    left.retain(|p| still.contains(p) && !files.contains_key(p));
    if !left.is_empty() {
        return Err(ProgramsError::lsof(format!(
            "{status}, then {} looked at again, and its listings left out processes of this user it could read: {}",
            again.status,
            joined(&left, ", ")
        )));
    }
    Ok(files)
}

/// `pids` as words between `separator`s.
fn joined(pids: &[u32], separator: &str) -> String {
    let pids: Vec<String> = pids.iter().map(ToString::to_string).collect();
    pids.join(separator)
}

/// What one `lsof` answered: how it exited, and the program files it listed.
struct Listing {
    status: ExitStatus,
    files: BTreeMap<u32, Vec<String>>,
}

/// The program files of every process `lsof` can see, or of `only` those.
fn list(only: Option<&[u32]>) -> Result<Listing, ProgramsError> {
    let mut lsof = Command::new("/usr/sbin/lsof");
    // `-b`: no call that can block, such as on a network mount that does not
    // answer, which would hold the state lock with it; `-w`: its warnings
    // about such a mount are not a failure to list the processes.
    lsof.env("LC_ALL", "C").args(["-nP", "-b", "-w"]);
    if let Some(pids) = only {
        lsof.args(["-a", "-p", &joined(pids, ",")]);
    }
    let out =
        super::bounded::output_within(lsof.args(["-d", "txt", "-Fpn"]), super::bounded::LIMIT)
            .map_err(|e| ProgramsError::lsof(e.to_string()))?;
    Ok(Listing {
        status: out.status,
        files: parse(&out, only.is_some())?,
    })
}

/// `P_SUGID` (`sys/proc.h`): a process that changed its user or group as
/// it ran a set-user-id program, such as `/usr/bin/login`, which macOS lets
/// no other process of the user look into, so `lsof` lists it not. A
/// sandbox runs no such program: Seatbelt refuses to start a set-user-id
/// one (design §5, shown for `crontab` and `at` on macOS 26.5.2).
const P_SUGID: u32 = 0x100;

/// The processes of this user, by effective user, that `lsof` can read, or
/// those of `only`, known to be this user's: neither zombies, nor ones
/// exiting, nor `P_SUGID` ones.
fn readable_own(only: Option<&[u32]>) -> Result<BTreeSet<u32>, ProgramsError> {
    let uid = rustix::process::geteuid().as_raw().to_string();
    let mut ps = Command::new("/bin/ps");
    ps.env("LC_ALL", "C");
    match only {
        Some(pids) => ps.args(["-p", &joined(pids, ",")]),
        None => ps.args(["-u", &uid]),
    };
    let out =
        super::bounded::output_within(ps.args(["-o", "pid=,flags=,stat="]), super::bounded::LIMIT)
            .map_err(|e| ProgramsError::lsof(format!("/bin/ps: {e}")))?;
    answered(&out, only.is_some())
}

/// What `ps -o pid=,flags=,stat=` answered. Asked for `some` processes that
/// have all gone, it prints nothing and exits 1 (macOS 26.5.2). Any other
/// failure, or a success that prints nothing, means it could not look:
/// [`whole`] takes a process `ps` does not show for one gone, so an empty
/// answer must not pass for that.
fn answered(out: &Output, some: bool) -> Result<BTreeSet<u32>, ProgramsError> {
    let text = String::from_utf8_lossy(&out.stdout);
    let why = String::from_utf8_lossy(&out.stderr).trim().to_owned();
    match (out.status.code(), text.trim().is_empty(), why.is_empty()) {
        (Some(0), false, _) => parse_readable(&text),
        (Some(1), true, true) if some => Ok(BTreeSet::new()),
        (_, true, true) => Err(ProgramsError::lsof(format!(
            "/bin/ps {}, with no output",
            out.status
        ))),
        _ => Err(ProgramsError::lsof(format!(
            "/bin/ps {}: {why}",
            out.status
        ))),
    }
}

/// `ps -o pid=,flags=,stat=` lines, as the pids `lsof` can read. One exiting,
/// which `ps` marks `E`, was left out by every `lsof` while it tore down (a
/// killed process, macOS 26.5.2; design §14).
fn parse_readable(text: &str) -> Result<BTreeSet<u32>, ProgramsError> {
    let mut pids = BTreeSet::new();
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let mut words = line.split_whitespace();
        let fields = (words.next(), words.next(), words.next());
        let (Some(pid), Some(flags), Some(stat)) = fields else {
            return Err(ProgramsError::lsof(format!("unexpected ps line `{line}`")));
        };
        let pid: u32 = pid
            .parse()
            .map_err(|_| ProgramsError::lsof(format!("unexpected ps line `{line}`")))?;
        let flags = u32::from_str_radix(flags, 16)
            .map_err(|_| ProgramsError::lsof(format!("unexpected ps line `{line}`")))?;
        if flags & P_SUGID == 0 && !stat.starts_with('Z') && !stat.contains('E') {
            pids.insert(pid);
        }
    }
    Ok(pids)
}

/// The pids readable both before and after the listing that it left out.
fn left_out(
    before: &BTreeSet<u32>,
    after: &BTreeSet<u32>,
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
/// an `n<name>` line for each of its program files. In a listing of every
/// process `lsof` itself is listed, so an empty answer is a failure. Asked
/// for `some` processes, it prints nothing, and says nothing, when it lists
/// none: exiting 1 for one gone or exiting, 0 for one replacing its program
/// (macOS 26.5.2). It exits 1 when a process it listed went away meanwhile,
/// which is no failure either.
fn parse(out: &Output, some: bool) -> Result<BTreeMap<u32, Vec<String>>, ProgramsError> {
    let text = String::from_utf8_lossy(&out.stdout);
    let why = String::from_utf8_lossy(&out.stderr).trim().to_owned();
    match (out.status.code(), text.trim().is_empty(), why.is_empty()) {
        (Some(0 | 1), true, true) if some => return Ok(BTreeMap::new()),
        (Some(0), false, _) | (Some(1), false, true) => {}
        _ if why.is_empty() => {
            return Err(ProgramsError::lsof(format!(
                "{}, with no output",
                out.status
            )));
        }
        _ => return Err(ProgramsError::lsof(format!("{}: {why}", out.status))),
    }
    let mut files: BTreeMap<u32, Vec<String>> = BTreeMap::new();
    let mut pid = None;
    for line in text.lines() {
        if let Some(p) = line.strip_prefix('p') {
            let p = p
                .parse::<u32>()
                .map_err(|_| ProgramsError::lsof(format!("unexpected process `{p}`")))?;
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
    use std::cell::RefCell;
    use std::os::unix::process::ExitStatusExt;

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
            crate::test_scripts::copy_program(
                &std::env::current_exe().unwrap(),
                &dir.join("sleeper"),
            );
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
        let listed = parse(
            &output(
                0,
                "p10\nftxt\nn/bin/zsh\nftxt\nn/usr/lib/dyld\np11\nftxt\nn/a b/c\n",
                "",
            ),
            false,
        )
        .unwrap();
        assert_eq!(listed[&10], ["/bin/zsh", "/usr/lib/dyld"]);
        assert_eq!(listed[&11], ["/a b/c"]);
    }

    #[test]
    fn a_listing_that_did_not_run_is_an_error() {
        let empty = parse(&output(1, "", ""), false).unwrap_err().to_string();
        assert!(empty.contains("with no output"), "{empty}");
        assert!(parse(&output(0, "", ""), false).is_err());
        assert!(parse(&output(1, "p1\nn/x\n", "lsof: status error"), false).is_err());
        assert!(parse(&output(0, "pnot-a-pid\n", ""), false).is_err());
        assert!(parse(&output(1, "p1\nn/x\n", ""), false).is_ok());
    }

    /// A process `lsof` could read, there before and after it looked, and
    /// left out makes the listing a part, not the whole; one gone meanwhile,
    /// one set-user-id (`P_SUGID`), a zombie or one exiting does not.
    #[test]
    fn a_listing_that_leaves_out_a_readable_process_is_not_whole() {
        let readable = parse_readable(
            "  10     4004 Ss\n  11 4004104 S\n  12     4004 Z\n  13     4004 S\n  14     4004 ?E\n",
        )
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

    fn listing(pids: &[u32]) -> Listing {
        Listing {
            status: ExitStatus::from_raw(0),
            files: pids.iter().map(|p| (*p, vec![format!("/p{p}")])).collect(),
        }
    }

    type Found = Result<BTreeMap<u32, Vec<String>>, ProgramsError>;
    type Asked = Vec<Option<Vec<u32>>>;

    /// The processes in `passed` are readable before and after a listing
    /// that left them out. Each is looked at again, alone: `again` are
    /// listed then, and `after` are still there. Gives what came of it and
    /// which processes `lsof`, then `ps`, were asked about.
    fn passed_over(passed: &[u32], again: &[u32], after: &[u32]) -> (Found, Asked, Asked) {
        let me = std::process::id();
        let around: BTreeSet<u32> = passed.iter().copied().chain([me]).collect();
        let looks = RefCell::new(Vec::new());
        let asked = RefCell::new(Vec::new());
        let readable = RefCell::new(vec![
            around.clone(),
            around,
            after.iter().copied().collect(),
        ]);
        let found = whole(
            |only| {
                asked.borrow_mut().push(only.map(<[u32]>::to_vec));
                Ok(readable.borrow_mut().remove(0))
            },
            |only| {
                looks.borrow_mut().push(only.map(<[u32]>::to_vec));
                Ok(match only {
                    None => listing(&[me]),
                    Some(_) => listing(again),
                })
            },
        );
        (found, looks.into_inner(), asked.into_inner())
    }

    /// Looked at again, a process passed over is listed, or gone, or still
    /// left out: only that last is an error.
    #[test]
    fn a_process_passed_over_is_looked_at_again_alone() {
        let (found, looks, asked) = passed_over(&[13], &[13], &[13]);
        assert_eq!(found.unwrap()[&13], ["/p13"]);
        assert_eq!(looks, [None, Some(vec![13])]);
        assert_eq!(asked, [None, None, Some(vec![13])]);

        let (found, _, _) = passed_over(&[13], &[], &[]);
        assert!(!found.unwrap().contains_key(&13));

        let (found, _, _) = passed_over(&[13], &[], &[13]);
        let err = found.unwrap_err().to_string();
        assert!(
            err.ends_with("then exit status: 0 looked at again, and its listings left out processes of this user it could read: 13"),
            "{err}"
        );
    }

    /// Of several passed over, one listed the second time and one gone are
    /// not named: only the one still left out is.
    #[test]
    fn only_the_process_still_left_out_is_named() {
        let (found, looks, _) = passed_over(&[13, 14, 15], &[13], &[13, 15]);
        assert_eq!(looks, [None, Some(vec![13, 14, 15])]);
        let err = found.unwrap_err().to_string();
        assert!(err.ends_with("it could read: 15"), "{err}");
    }

    /// A second look that fails says it was one, what the first exited
    /// with, and which processes it asked about.
    #[test]
    fn a_failed_second_look_says_it_was_one() {
        let me = std::process::id();
        let around = BTreeSet::from([me, 13, 14]);
        let err = whole(
            |_| Ok(around.clone()),
            |only| match only {
                None => Ok(listing(&[me])),
                Some(_) => Err(ProgramsError::lsof("did not answer within 5 s".to_owned())),
            },
        )
        .unwrap_err()
        .to_string();
        assert!(
            err.ends_with("exit status: 0, and its listing left out processes of this user it could read: 13, 14; looking at them again: did not answer within 5 s"),
            "{err}"
        );
    }

    /// Asked for some processes, `lsof` printing nothing, on either exit it
    /// gives then, lists none; anything else stays what it was.
    #[test]
    fn asked_for_some_an_empty_answer_lists_none() {
        assert!(parse(&output(1, "", ""), true).unwrap().is_empty());
        assert!(parse(&output(0, "", ""), true).unwrap().is_empty());
        assert!(parse(&output(1, " \n", " \n"), true).unwrap().is_empty());
        assert!(parse(&output(1, "", "lsof: can't read"), true).is_err());
        assert!(parse(&output(0, "", "lsof: can't read"), true).is_err());
        assert!(parse(&output(2, "", ""), true).is_err());
        assert_eq!(
            parse(&output(1, "p10\nn/x\n", ""), true).unwrap()[&10],
            ["/x"]
        );
    }

    /// The last `ps` says which processes have gone, so only an answer that
    /// says so counts: lines, or for some processes a silent exit of 1. An
    /// empty success is not "all gone", which would let a partial listing
    /// pass as whole.
    #[test]
    fn ps_that_says_nothing_has_not_looked() {
        let line = "  13     4004 S\n";
        assert_eq!(answered(&output(0, line, ""), true).unwrap(), [13].into());
        assert_eq!(answered(&output(0, line, ""), false).unwrap(), [13].into());
        assert!(answered(&output(1, "", ""), true).unwrap().is_empty());

        let empty = answered(&output(0, "", ""), true).unwrap_err().to_string();
        assert!(empty.contains("with no output"), "{empty}");
        assert!(answered(&output(0, " \n", ""), true).is_err());
        assert!(answered(&output(0, "", ""), false).is_err());
        assert!(answered(&output(1, "", ""), false).is_err());
        assert!(answered(&output(1, "", "ps: bad option"), true).is_err());
        assert!(answered(&output(0, "", "ps: bad option"), true).is_err());
        assert!(answered(&output(1, line, ""), true).is_err());
    }

    /// Asked for processes that have all gone, `lsof` lists none and `ps`
    /// shows none, and neither is an error. Asked about this process too,
    /// `lsof` lists its program and `ps` shows it alone.
    #[test]
    fn a_second_look_at_gone_processes_lists_none() {
        let mut gone = Command::new("/usr/bin/true").spawn().unwrap();
        let pid = gone.id();
        gone.wait().unwrap();
        assert!(list(Some(&[pid])).unwrap().files.is_empty());
        assert!(readable_own(Some(&[pid])).unwrap().is_empty());
        let me = std::process::id();
        assert!(!list(Some(&[me, pid])).unwrap().files[&me].is_empty());
        assert_eq!(
            readable_own(Some(&[me, pid])).unwrap(),
            BTreeSet::from([me])
        );
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
