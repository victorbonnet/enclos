//! Looking at and signalling processes, through `ps` and `kill`, with no
//! `unsafe` code (ADR 0012).
//!
//! Signalling is narrow on purpose. enclos signals only a session's sure
//! members (see `members`): processes it recorded, and what they started.
//! A group is signalled only through its leader. Right before each signal,
//! it checks that the target is still the same process, same pid and same
//! start time, so a pid already reused by an unrelated process is not
//! signalled. The check narrows the window to the moment between it and the
//! signal; it cannot close it.
//!
//! A `ps` that fails is an error, never an empty answer: "no process" from a
//! listing that did not run would end sessions whose members still run.

use std::process::{Child, Command, Output, Stdio};

use crate::model::session::ProcessRef;

/// `ps` could not answer.
#[derive(Debug, thiserror::Error)]
#[error("cannot look at processes with /bin/ps: {0}")]
pub struct PsError(String);

#[cfg(all(test, target_os = "macos"))]
impl PsError {
    /// A `ps` failure with this reason, for tests of what follows one.
    pub(crate) fn new(why: &str) -> PsError {
        PsError(why.to_owned())
    }
}

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
    .map_err(|e| PsError(format!("/bin/ps: {e}")))
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
        _ => Err(PsError(format!(
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

/// The state and start time of `pid`, or `None` when no such process exists.
fn stat_and_start(pid: u32) -> Result<Option<(String, String)>, PsError> {
    let Some(text) = listed(&ps(&["-o", "stat=,lstart=", "-p", &pid.to_string()])?)? else {
        return Ok(None);
    };
    parse_start(&text)
        .map(Some)
        .ok_or_else(|| PsError(format!("unexpected output `{text}`")))
}

/// The start time of `pid`, or `None` when no such process runs. A process
/// that exited but was not yet reaped by its parent (a zombie) runs
/// nothing and holds nothing, so it does not count as running.
pub fn start_time(pid: u32) -> Result<Option<String>, PsError> {
    Ok(
        stat_and_start(pid)?
            .and_then(|(stat, started)| (!stat.starts_with('Z')).then_some(started)),
    )
}

/// A reference to a process that is running now.
pub fn reference(pid: u32) -> Result<Option<ProcessRef>, PsError> {
    Ok(start_time(pid)?.map(|started| ProcessRef { pid, started }))
}

/// A reference to `child`, which this process started and has not waited
/// for. Until it is waited for, its pid cannot be reused, so it is read even
/// when the program already exited.
pub fn reference_of_child(child: &Child) -> Result<ProcessRef, PsError> {
    let pid = child.id();
    let (_, started) = stat_and_start(pid)?
        .ok_or_else(|| PsError(format!("pid {pid}, just started, is not listed")))?;
    Ok(ProcessRef { pid, started })
}

/// Whether `process` is still the very process that was recorded.
pub fn is_same(process: &ProcessRef) -> Result<bool, PsError> {
    Ok(start_time(process.pid)?.is_some_and(|now| now == process.started))
}

/// The process group of `pid`, or `None` when no such process exists.
pub fn group_of(pid: u32) -> Result<Option<u32>, PsError> {
    let Some(pgid) = listed(&ps(&["-o", "pgid=", "-p", &pid.to_string()])?)? else {
        return Ok(None);
    };
    pgid.parse()
        .map(Some)
        .map_err(|_| PsError(format!("unexpected group `{pgid}`")))
}

/// A process as one listing shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proc {
    pub pid: u32,
    pub ppid: u32,
    pub pgid: u32,
    pub started: String,
    pub command: String,
}

/// One line of `ps -o pid=,ppid=,pgid=,stat=,lstart=,comm=`, and whether
/// the process is a zombie.
fn parse_listing(line: &str) -> Option<(Proc, bool)> {
    let mut words = line.split_whitespace();
    let pid: u32 = words.next()?.parse().ok()?;
    let ppid: u32 = words.next()?.parse().ok()?;
    let pgid: u32 = words.next()?.parse().ok()?;
    let zombie = words.next()?.starts_with('Z');
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
            parse_listing(line)
                .ok_or_else(|| PsError(format!("unexpected line `{}` in the listing", line.trim())))
        })
        .collect()
}

/// Every running process. Read-only. Zombies run nothing and are left out.
pub fn processes() -> Result<Vec<Proc>, PsError> {
    let out = ps(&["-A", "-o", "pid=,ppid=,pgid=,stat=,lstart=,comm="])?;
    if !out.status.success() {
        let why = String::from_utf8_lossy(&out.stderr);
        return Err(PsError(format!("{} {}", out.status, why.trim())));
    }
    let listed = parse_processes(&String::from_utf8_lossy(&out.stdout))?;
    // A listing that misses the process asking cannot be read, or is not
    // the whole listing.
    let me = std::process::id();
    if !listed.iter().any(|(p, _)| p.pid == me) {
        return Err(PsError(format!(
            "the listing does not show pid {me}, the caller"
        )));
    }
    Ok(listed
        .into_iter()
        .filter(|(_, zombie)| !zombie)
        .map(|(p, _)| p)
        .collect())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signal {
    Term,
    Kill,
    Usr1,
    Int,
    Quit,
    Hup,
}

impl Signal {
    pub fn name(self) -> &'static str {
        match self {
            Signal::Term => "TERM",
            Signal::Kill => "KILL",
            Signal::Usr1 => "USR1",
            Signal::Int => "INT",
            Signal::Quit => "QUIT",
            Signal::Hup => "HUP",
        }
    }
}

/// What became of a signal enclos meant to send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Signalled {
    Sent,
    /// The target is no longer the recorded process: it exited, or its pid
    /// was reused. Nothing was sent.
    Gone,
    /// The leader no longer leads the group. Nothing was sent.
    NotLeader,
    /// `kill` refused or failed, with why.
    Failed(String),
}

/// Sends `signal` to the process group whose leader is `leader`, only if
/// that leader is still the recorded process and leads its own group.
pub fn signal_group(leader: &ProcessRef, pgid: u32, signal: Signal) -> Result<Signalled, PsError> {
    if leader.pid != pgid {
        return Ok(Signalled::NotLeader);
    }
    if !is_same(leader)? {
        return Ok(Signalled::Gone);
    }
    if group_of(leader.pid)? != Some(pgid) {
        return Ok(Signalled::NotLeader);
    }
    Ok(kill(signal, -i64::from(pgid)))
}

/// Sends `signal` to `process` alone, only if it is still the recorded
/// process.
pub fn signal_process(process: &ProcessRef, signal: Signal) -> Result<Signalled, PsError> {
    if !is_same(process)? {
        return Ok(Signalled::Gone);
    }
    Ok(kill(signal, i64::from(process.pid)))
}

/// Targets `kill` reads as more than one process of a session: 0 is the
/// caller's own group and -1 every process the user owns; 1 is launchd.
fn never_signalled(target: i64) -> bool {
    target.abs() <= 1
}

fn kill(signal: Signal, target: i64) -> Signalled {
    if never_signalled(target) {
        return Signalled::Failed(format!("enclos never signals {target}"));
    }
    match Command::new("/bin/kill")
        .args(["-s", signal.name(), "--", &target.to_string()])
        .stdin(Stdio::null())
        .output()
    {
        Ok(out) if out.status.success() => Signalled::Sent,
        Ok(out) => Signalled::Failed(match String::from_utf8_lossy(&out.stderr).trim() {
            "" => out.status.to_string(),
            why => why.to_owned(),
        }),
        Err(e) => Signalled::Failed(format!("cannot run /bin/kill: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::CommandExt;
    use std::time::{Duration, Instant};

    /// A `sleep` this test starts in a group of its own: the only kind of
    /// process these tests signal.
    fn own_group() -> Child {
        Command::new("/bin/sleep")
            .arg("30")
            .process_group(0)
            .spawn()
            .unwrap()
    }

    fn wait_gone(child: &mut Child) -> bool {
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(5) {
            if child.try_wait().unwrap().is_some() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        false
    }

    fn now(pid: u32) -> ProcessRef {
        reference(pid).unwrap().unwrap()
    }

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

    #[test]
    fn a_listing_with_a_line_it_cannot_read_is_an_error() {
        let ok = "  1     0     1 Ss   Thu Oct  8 09:31:10 2026 /sbin/launchd\n\n";
        assert_eq!(parse_processes(ok).unwrap().len(), 1);
        let err = parse_processes(&format!("{ok}  12 garbled\n")).unwrap_err();
        assert!(err.to_string().contains("`12 garbled`"), "{err}");
    }

    #[test]
    fn a_reaped_pid_has_no_start_time_and_no_group() {
        let mut child = Command::new("/usr/bin/true").spawn().unwrap();
        let pid = child.id();
        child.wait().unwrap();
        assert_eq!(stat_and_start(pid).unwrap(), None);
        assert_eq!(group_of(pid).unwrap(), None);
    }

    #[test]
    fn a_recorded_group_is_found_and_stopped() {
        let mut child = own_group();
        let leader = now(child.id());
        assert!(is_same(&leader).unwrap());
        assert_eq!(group_of(child.id()).unwrap(), Some(child.id()));
        assert!(
            processes().unwrap().iter().any(|p| p.pid == child.id()
                && p.pgid == child.id()
                && p.started == leader.started)
        );
        assert_eq!(
            signal_group(&leader, child.id(), Signal::Term).unwrap(),
            Signalled::Sent
        );
        assert!(wait_gone(&mut child));
        assert!(!is_same(&leader).unwrap());
    }

    #[test]
    fn a_process_that_exited_is_not_the_same_even_unreaped() {
        let mut child = own_group();
        let recorded = now(child.id());
        child.kill().unwrap();
        // Not waited for: the process stays a zombie, with its pid and
        // start time, until `wait` below.
        let start = Instant::now();
        while is_same(&recorded).unwrap() && start.elapsed() < Duration::from_secs(5) {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(!is_same(&recorded).unwrap());
        assert!(!processes().unwrap().iter().any(|p| p.pid == child.id()));
        let _ = child.wait();
    }

    #[test]
    fn a_child_that_exited_at_once_still_has_a_reference_until_waited_for() {
        let mut child = Command::new("/usr/bin/true").spawn().unwrap();
        let start = Instant::now();
        while start_time(child.id()).unwrap().is_some() {
            assert!(start.elapsed() < Duration::from_secs(5));
            std::thread::sleep(Duration::from_millis(20));
        }
        let recorded = reference_of_child(&child).unwrap();
        assert_eq!(recorded.pid, child.id());
        let _ = child.wait();
        assert_eq!(start_time(recorded.pid).unwrap(), None);
    }

    #[test]
    fn start_times_read_in_utc_whatever_the_callers_time_zone() {
        let mut child = own_group();
        let started = start_time(child.id()).unwrap().unwrap();
        let read = jiff::civil::DateTime::strptime("%a %b %e %H:%M:%S %Y", &started)
            .unwrap()
            .to_zoned(jiff::tz::TimeZone::UTC)
            .unwrap()
            .timestamp();
        let off = (jiff::Timestamp::now() - read).get_seconds().abs();
        assert!(off < 60, "{started} is {off}s away from now in UTC");
        let _ = child.kill();
        let _ = child.wait();
    }

    #[test]
    fn a_process_is_signalled_alone_only_while_it_is_the_recorded_one() {
        let mut child = own_group();
        let recorded = now(child.id());
        let stale = ProcessRef {
            pid: child.id(),
            started: "Thu Jan 1 00:00:00 1970".into(),
        };
        assert_eq!(
            signal_process(&stale, Signal::Term).unwrap(),
            Signalled::Gone
        );
        assert!(child.try_wait().unwrap().is_none());
        assert_eq!(
            signal_process(&recorded, Signal::Term).unwrap(),
            Signalled::Sent
        );
        assert!(wait_gone(&mut child));
    }

    #[test]
    fn a_leader_with_another_start_time_is_never_signalled() {
        let mut child = own_group();
        // The same pid, recorded at another time: as after pid reuse.
        let stale = ProcessRef {
            pid: child.id(),
            started: "Thu Jan 1 00:00:00 1970".into(),
        };
        assert_eq!(
            signal_group(&stale, child.id(), Signal::Term).unwrap(),
            Signalled::Gone
        );
        assert!(child.try_wait().unwrap().is_none());
        let _ = child.kill();
        let _ = child.wait();
    }

    #[test]
    fn a_process_that_does_not_lead_the_group_is_never_used_to_signal_it() {
        let mut child = own_group();
        let leader = now(child.id());
        // Our own pid is not the group's leader.
        assert_eq!(
            signal_group(&leader, std::process::id(), Signal::Term).unwrap(),
            Signalled::NotLeader
        );
        let _ = child.kill();
        let _ = child.wait();
    }

    #[test]
    fn targets_meaning_more_than_one_process_are_never_signalled() {
        // Checked on the rule alone: a test that sent them would signal the
        // test runner's group, or every process of the user.
        for target in [0, -1, 1] {
            assert!(never_signalled(target), "{target}");
        }
        assert!(!never_signalled(-4242));
        assert!(!never_signalled(4242));
    }
}
