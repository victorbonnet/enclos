use std::path::{Path, PathBuf};

use super::*;

/// What bubblewrap 0.9.0 to 0.12 prints when a mount it read is gone as it
/// remounts it (`die_with_bind_result` in `bind-mount.c`).
const VANISHED: &str = "bwrap: Can't bind mount /oldroot/ on /newroot/: Unable to apply mount flags: remount \"/newroot/run/credentials/systemd-tmpfiles-setup.service\": No such file or directory";

/// The same, for a folder still there that no longer holds a mount.
const UNMOUNTED: &str = "bwrap: Can't bind mount /oldroot/ on /newroot/: Unable to apply mount flags: remount \"/newroot/tmp/snap-private-tmp\": Invalid argument";

#[test]
fn a_mount_that_changed_is_bubblewraps_remount_failing_before_its_program_ran() {
    for said in [VANISHED, UNMOUNTED] {
        assert!(
            mount_changed(Some(1), format!("{said}\n").as_bytes()),
            "{said}"
        );
    }
    let refused = [
        // bubblewrap exits 1 on every failure; only this one is a race.
        (
            Some(1),
            "bwrap: No permissions to create a new namespace, likely because the kernel does not allow non-privileged user namespaces.",
        ),
        (
            Some(1),
            "bwrap: Can't find source path /nowhere: No such file or directory",
        ),
        (Some(1), "bwrap: setting up uid map: Permission denied"),
        // A mount there, which bubblewrap may not remount: it would fail
        // again.
        (
            Some(1),
            "bwrap: Can't bind mount /oldroot/ on /newroot/: Unable to apply mount flags: remount \"/newroot/proc/fs/nfsd\": Operation not permitted",
        ),
        // Said by anything but bubblewrap.
        (Some(1), &VANISHED["bwrap: ".len()..]),
        // Another end than bubblewrap's failure.
        (Some(0), VANISHED),
        (Some(125), VANISHED),
        (None, VANISHED),
    ];
    for (code, said) in refused {
        assert!(!mount_changed(code, said.as_bytes()), "{code:?} {said}");
    }
}

#[test]
fn starts_end_at_the_first_that_did_not_meet_a_changed_mount() {
    let mut starts = 0;
    let ended = again(
        &[Duration::ZERO; PAUSES.len()],
        || {
            starts += 1;
            Ok(starts)
        },
        |n| *n < 2,
    )
    .unwrap();
    assert_eq!((ended, starts), (2, 2));
}

#[test]
fn starts_end_once_the_pauses_run_out() {
    let mut starts = 0;
    let ended = again(
        &[Duration::ZERO; PAUSES.len()],
        || {
            starts += 1;
            Ok(starts)
        },
        |_| true,
    )
    .unwrap();
    assert_eq!((ended, starts), (5, 5));
}

/// One read at a time, as a pipe may give them.
struct ByteByByte<'a>(&'a [u8]);

impl Read for ByteByByte<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let Some((first, rest)) = self.0.split_first() else {
            return Ok(0);
        };
        buf[0] = *first;
        self.0 = rest;
        Ok(1)
    }
}

#[test]
fn the_words_that_say_the_program_runs_are_found_split_over_reads() {
    let mut sent = b"bwrap: a warning\n".to_vec();
    sent.extend_from_slice(RUNS);
    sent.extend_from_slice(b"after");
    let mut pipe = ByteByByte(&sent);
    let mut said = Vec::new();
    assert!(read_until_set_up(&mut pipe, &mut said).unwrap());
    assert_eq!(said, b"bwrap: a warning\n");
    let mut said = Vec::new();
    assert!(!read_until_set_up(&mut ByteByByte(b"bwrap: failed\n"), &mut said).unwrap());
    assert_eq!(said, b"bwrap: failed\n");
}

/// A stand-in for bubblewrap and the program it runs first, in bash, which
/// takes a descriptor of any number. Each start adds a line to `starts`;
/// while `starts` has no more than `fails` lines, it says `failure` and
/// exits 1, as bubblewrap does. Else, as `enclos inside` does, it says it
/// runs and takes back its stderr, then, as the command, adds a line to
/// `ran`, says on stderr what that is, and exits `code`, after saying
/// `failure` again when `code` is 1.
const STAND_IN: &str = r#"
starts="$1" fails="$2" failure="$3" ran="$4" code="$5" runs="$6"
echo start >>"$starts"
if [ "$(wc -l <"$starts")" -le "$fails" ]; then
    echo "$failure" >&2
    exit 1
fi
printf "$runs" >&2
exec 2>&"$ENCLOS_BUBBLEWRAP_STDERR"
echo ran >>"$ran"
if [ -f /dev/fd/2 ]; then echo "the command's own stderr" >&2; else echo "a pipe" >&2; fi
[ "$code" = 1 ] && echo "$failure" >&2
exit "$code"
"#;

/// A stand-in's files, and the stderr `run` is given.
struct Stand {
    dir: tempfile::TempDir,
}

impl Stand {
    fn new() -> Stand {
        Stand {
            dir: tempfile::tempdir().unwrap(),
        }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    /// Runs the stand-in through `run`: how it ended, and what reached the
    /// stderr `run` was given.
    fn run(&self, fails: usize, failure: &str, code: i32) -> (ExitStatus, String) {
        let stderr = File::create(self.path("stderr")).unwrap();
        let runs: String = RUNS.iter().map(|b| format!("\\{b:03o}")).collect();
        let status = run(
            || {
                let mut bash = Command::new("/bin/bash");
                bash.arg("-c")
                    .arg(STAND_IN)
                    .arg("stand-in")
                    .arg(self.path("starts"))
                    .arg(fails.to_string())
                    .arg(failure)
                    .arg(self.path("ran"))
                    .arg(code.to_string())
                    .arg(&runs);
                Ok(bash)
            },
            &stderr,
            &[Duration::ZERO; PAUSES.len()],
        )
        .unwrap();
        (
            status,
            std::fs::read_to_string(self.path("stderr")).unwrap(),
        )
    }

    fn lines(&self, name: &str) -> usize {
        lines(&self.path(name))
    }
}

fn lines(path: &Path) -> usize {
    std::fs::read_to_string(path).map_or(0, |text| text.lines().count())
}

#[test]
fn bubblewrap_that_met_a_changed_mount_once_is_started_again_and_runs_its_program_once() {
    let stand = Stand::new();
    let (status, said) = stand.run(1, VANISHED, 0);
    assert!(status.success(), "{said}");
    assert_eq!(stand.lines("starts"), 2);
    assert_eq!(stand.lines("ran"), 1);
    // What the first start said is not passed on; the start again is, once,
    // before the program; and the program wrote to the stderr given, not to
    // the pipe.
    assert_eq!(said, format!("{AGAIN}\nthe command's own stderr\n"));
}

/// What `run` says before its second start.
const AGAIN: &str =
    "enclos: a mount of the host changed while bubblewrap set up, so it starts again";

#[test]
fn bubblewrap_that_meets_a_changed_mount_at_every_start_is_reported_once_its_starts_run_out() {
    let stand = Stand::new();
    let (status, said) = stand.run(1000, VANISHED, 0);
    assert_eq!(status.code(), Some(1));
    assert_eq!(stand.lines("starts"), 5);
    assert_eq!(stand.lines("ran"), 0);
    assert_eq!(
        said,
        format!(
            "{AGAIN}\nenclos: bubblewrap was started 5 times, and each time a mount of the host changed while it set up:\n{VANISHED}\n"
        )
    );
}

/// The command ran: whatever it says and however it ends, it is never run
/// a second time.
#[test]
fn a_program_that_ran_is_never_started_again() {
    let stand = Stand::new();
    let (status, said) = stand.run(0, VANISHED, 1);
    assert_eq!(status.code(), Some(1));
    assert_eq!(stand.lines("starts"), 1);
    assert_eq!(stand.lines("ran"), 1);
    assert_eq!(said, format!("the command's own stderr\n{VANISHED}\n"));
}

/// Any other failure of bubblewrap's is no race: it is said as it is, at
/// the first start.
#[test]
fn bubblewrap_that_fails_for_another_reason_is_not_started_again() {
    let stand = Stand::new();
    let other = "bwrap: setting up uid map: Permission denied";
    let (status, said) = stand.run(1000, other, 0);
    assert_eq!(status.code(), Some(1));
    assert_eq!(stand.lines("starts"), 1);
    assert_eq!(stand.lines("ran"), 0);
    assert_eq!(said, format!("{other}\n"));
}

#[test]
fn a_program_that_does_not_start_is_said() {
    let stderr = tempfile::tempfile().unwrap();
    let e = run(
        || Ok(Command::new("/nonexistent/bwrap")),
        &stderr,
        &[Duration::ZERO; PAUSES.len()],
    )
    .unwrap_err();
    assert_eq!(e.kind(), io::ErrorKind::NotFound);
}
