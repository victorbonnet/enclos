//! How enclos lists processes on macOS: `/bin/ps`, read in UTC and the C
//! locale. `proc::processes` gives the same on Linux; `lifecycle` picks one
//! of the two as `host`.
//!
//! A `ps` that fails is an error, never an empty answer: "no process" from a
//! listing that did not run would end sessions whose members still run.

use std::process::{Command, Output};

use super::process::{Proc, PsError, Seen};

/// Runs `ps`, reading dates in UTC and the C locale, so that a start time
/// reads the same whoever asks.
fn ps(args: &[&str]) -> Result<Output, PsError> {
    super::bounded::output_within(
        Command::new("/bin/ps")
            .env("TZ", "UTC0")
            .env("LC_ALL", "C")
            .args(args),
        super::bounded::LIMIT,
    )
    .map_err(|e| PsError::Ps(format!("/bin/ps: {e}")))
}

/// The five words of `lstart`, one space apart. `ps` pads a day before the
/// 10th with a second space; start times are compared as text, so both
/// readers below must spell them alike.
fn lstart<'a>(words: &mut impl Iterator<Item = &'a str>) -> Option<String> {
    let words: Vec<&str> = words.take(5).collect();
    (words.len() == 5).then(|| words.join(" "))
}

/// The state and start time in one line of `ps -o stat=,lstart=`.
fn parse_start(line: &str) -> Option<(String, String)> {
    let mut words = line.split_whitespace();
    let stat = words.next()?.to_owned();
    Some((stat, lstart(&mut words)?))
}

/// What `ps -o ... -p <pid>` answered: its line, or `None` when no such
/// process exists. For a pid that does not exist, `ps` prints nothing and
/// exits 1, with nothing on stderr either (macOS and procps alike). Any other
/// failure, a success that prints nothing, or a failure that prints a line,
/// means it could not look.
fn listed(out: &Output) -> Result<Option<String>, PsError> {
    let text = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    let why = String::from_utf8_lossy(&out.stderr).trim().to_owned();
    match (out.status.code(), text.is_empty(), why.is_empty()) {
        (Some(0), false, _) => Ok(Some(text)),
        (Some(1), true, true) => Ok(None),
        _ => Err(PsError::Ps(format!(
            "{}{}{}",
            out.status,
            match why.as_str() {
                "" => String::new(),
                why => format!(": {why}"),
            },
            match text.as_str() {
                "" => " and printed nothing".to_owned(),
                text => format!(", printing `{text}`"),
            },
        ))),
    }
}

/// Whether `stat`, a state as `ps` writes it, is a zombie's: a process that
/// exited but was not yet reaped by its parent. procps writes `Zl` for one
/// whose main thread exited while others run on, which is no zombie.
fn is_zombie(stat: &str) -> bool {
    stat.starts_with('Z') && !stat.contains('l')
}

/// Whether `pid` is a zombie and when it started, or `None` when no such
/// process exists.
pub fn seen(pid: u32) -> Result<Option<Seen>, PsError> {
    let Some(text) = listed(&ps(&["-o", "stat=,lstart=", "-p", &pid.to_string()])?)? else {
        return Ok(None);
    };
    let (stat, started) =
        parse_start(&text).ok_or_else(|| PsError::Ps(format!("unexpected output `{text}`")))?;
    Ok(Some(Seen {
        zombie: is_zombie(&stat),
        started,
    }))
}

/// The process group of `pid`, or `None` when no such process exists.
pub fn group_of(pid: u32) -> Result<Option<u32>, PsError> {
    let Some(pgid) = listed(&ps(&["-o", "pgid=", "-p", &pid.to_string()])?)? else {
        return Ok(None);
    };
    pgid.parse()
        .map(Some)
        .map_err(|_| PsError::Ps(format!("unexpected group `{pgid}`")))
}

/// One line of `ps -o pid=,ppid=,pgid=,stat=,lstart=,comm=`, and whether
/// the process is a zombie.
fn parse_listing(line: &str) -> Option<(Proc, bool)> {
    let mut words = line.split_whitespace();
    let pid: u32 = words.next()?.parse().ok()?;
    let ppid: u32 = words.next()?.parse().ok()?;
    let pgid: u32 = words.next()?.parse().ok()?;
    let zombie = is_zombie(words.next()?);
    let started = lstart(&mut words)?;
    let command = words.collect::<Vec<_>>().join(" ");
    let proc = Proc {
        pid,
        ppid,
        pgid,
        started,
        command,
    };
    Some((proc, zombie))
}

/// Each line of a whole listing, and whether its process is a zombie. A
/// line that does not parse fails the listing: a process left out would
/// read as gone.
fn parse_processes(text: &str) -> Result<Vec<(Proc, bool)>, PsError> {
    text.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            parse_listing(line).ok_or_else(|| {
                PsError::Ps(format!("unexpected line `{}` in the listing", line.trim()))
            })
        })
        .collect()
}

/// Every running process. Zombies run nothing and are left out.
pub fn processes() -> Result<Vec<Proc>, PsError> {
    let out = ps(&["-A", "-o", "pid=,ppid=,pgid=,stat=,lstart=,comm="])?;
    if !out.status.success() {
        let why = String::from_utf8_lossy(&out.stderr);
        return Err(PsError::Ps(format!("{} {}", out.status, why.trim())));
    }
    let listed = parse_processes(&String::from_utf8_lossy(&out.stdout))?;
    // A listing that misses the process asking cannot be read, or is not
    // the whole listing.
    let me = std::process::id();
    if !listed.iter().any(|(p, _)| p.pid == me) {
        return Err(PsError::Ps(format!(
            "the listing does not show pid {me}, the caller"
        )));
    }
    Ok(listed
        .into_iter()
        .filter(|(_, zombie)| !zombie)
        .map(|(p, _)| p)
        .collect())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[test]
    fn a_day_before_the_10th_reads_the_same_in_both_readers() {
        // `ps` pads the day: the 8th prints as "Oct  8".
        let (stat, alone) = parse_start("Ss   Thu Oct  8 09:31:55 2026   ").unwrap();
        let (listed, zombie) =
            parse_listing(" 3701     1  3701 Ss   Thu Oct  8 09:31:55 2026     /usr/libexec/x y")
                .unwrap();
        assert_eq!(stat, "Ss");
        assert!(!zombie);
        assert_eq!(alone, "Thu Oct 8 09:31:55 2026");
        assert_eq!(listed.started, alone);
        assert_eq!((listed.pid, listed.ppid, listed.pgid), (3701, 1, 3701));
        assert_eq!(listed.command, "/usr/libexec/x y");
    }

    /// What `ps` returned, as `Command::output` gives it: `raw` is the wait
    /// status, the exit code shifted left by 8, or the signal alone.
    fn output(raw: i32, stdout: &str, stderr: &str) -> Output {
        use std::os::unix::process::ExitStatusExt;
        Output {
            status: std::process::ExitStatus::from_raw(raw),
            stdout: stdout.as_bytes().to_vec(),
            stderr: stderr.as_bytes().to_vec(),
        }
    }

    #[test]
    fn only_an_exit_1_with_no_output_means_no_such_process() {
        // As `ps -o stat=,lstart= -p <pid>` answers for a reaped pid.
        assert_eq!(listed(&output(1 << 8, "", "")).unwrap(), None);
        assert_eq!(
            listed(&output(0, "Ss   Thu Oct  8 09:31:55 2026   \n", "")).unwrap(),
            Some("Ss   Thu Oct  8 09:31:55 2026".to_owned())
        );
        // A `ps` that could not run its listing, was killed, failed another
        // way, or answered in a way it never does, could not look.
        for (out, says) in [
            (
                output(1 << 8, "", "ps: bogus: keyword not found\n"),
                "keyword not found",
            ),
            (output(9, "", ""), "signal"),
            (output(2 << 8, "", ""), "printed nothing"),
            (output(1 << 8, "  501\n", ""), "printing `501`"),
            (output(0, "", ""), "printed nothing"),
        ] {
            let err = listed(&out).unwrap_err();
            assert!(err.to_string().contains(says), "{err}");
        }
    }

    /// procps writes `Zl` for a process whose main thread exited while
    /// another runs on, and `Z` alone for one that is over.
    #[test]
    fn only_a_process_with_no_thread_left_is_a_zombie() {
        let line = |stat: &str| format!("7 1 7 {stat} Thu Oct  8 09:31:55 2026 x");
        for (stat, zombie) in [("Z", true), ("Z+", true), ("Zs", true), ("Zl", false)] {
            assert_eq!(parse_listing(&line(stat)).unwrap().1, zombie, "{stat}");
        }
        assert!(!parse_listing(&line("Ss")).unwrap().1);
        assert!(!parse_listing(&line("Sl")).unwrap().1);
    }

    #[test]
    fn a_listing_with_a_line_it_cannot_read_is_an_error() {
        let ok = "  1     0     1 Ss   Thu Oct  8 09:31:10 2026 /sbin/launchd\n\n";
        assert_eq!(parse_processes(ok).unwrap().len(), 1);
        let err = parse_processes(&format!("{ok}  12 garbled\n")).unwrap_err();
        assert!(err.to_string().contains("`12 garbled`"), "{err}");
    }

    /// Where `ps` is procps's, as on Linux, it gives every process the same
    /// start time `/proc` does: records `ps` made read the same with either.
    /// Parents and groups are compared for this process and init alone:
    /// other tests' processes may change theirs between the two listings.
    #[cfg(target_os = "linux")]
    #[test]
    fn ps_and_proc_give_each_process_the_same_start_time() {
        let me = std::process::id();
        let listed = processes().unwrap();
        let read = super::super::proc::processes().unwrap();
        let mut compared = 0;
        for p in &listed {
            if let Some(q) = read.iter().find(|q| q.pid == p.pid) {
                assert_eq!(q.started, p.started, "pid {}", p.pid);
                if p.pid == me || p.pid == 1 {
                    assert_eq!((q.ppid, q.pgid), (p.ppid, p.pgid), "pid {}", p.pid);
                }
                compared += 1;
            }
        }
        assert!(compared > 1, "{compared} processes compared");
        assert_eq!(
            seen(me).unwrap().unwrap(),
            super::super::proc::seen(me).unwrap().unwrap()
        );
    }
}
