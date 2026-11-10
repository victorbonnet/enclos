//! Processes from `/proc/<pid>/stat`, with no program to run: each read is
//! the kernel's answer, so a host under load cannot keep it from coming, as
//! it can a `ps` that must start first.
//!
//! A start time is written as procps's `ps -o lstart` writes it in UTC, from
//! the same numbers (`btime` in `/proc/stat`, plus the start in clock ticks
//! since boot), so a time `ps` recorded reads the same here.

use std::io;
use std::path::Path;

use jiff::Timestamp;
use jiff::tz::TimeZone;

use super::super::descriptors::is_gone;
use super::super::process::{Proc, PsError, Seen};

/// `PF_EXITING` (`include/linux/sched.h`): the task has begun to exit.
const PF_EXITING: u64 = 0x4;

/// What `/proc/<pid>/stat` says of a process.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Stat {
    ppid: u32,
    pgid: u32,
    /// Exiting, exited or ended, with no other thread left: it runs no code
    /// any more. A process killed leaves its cgroup while it exits, before
    /// it is a zombie. A process whose main thread exited is shown exiting,
    /// then `Z`, while its other threads run on: that one still runs.
    zombie: bool,
    /// When it started, in clock ticks since boot.
    ticks: u64,
    /// Its name (`comm`), cut at 15 bytes by the kernel.
    command: String,
}

/// One `/proc/<pid>/stat`. Its name is between the first `(` and the last
/// `)`, and may hold either, or spaces; the fields after it are numbers but
/// for the state.
fn parse_stat(text: &str) -> Option<Stat> {
    let (head, rest) = text.trim_end().rsplit_once(')')?;
    let (_, command) = head.split_once('(')?;
    let fields: Vec<&str> = rest.split_whitespace().collect();
    let number = |n: usize| fields.get(n)?.parse::<u64>().ok();
    let state = fields.first()?.chars().next()?;
    let exiting = number(6)? & PF_EXITING != 0;
    let threads = number(17)?;
    Some(Stat {
        ppid: u32::try_from(number(1)?).ok()?,
        pgid: u32::try_from(number(2)?).ok()?,
        zombie: (exiting || matches!(state, 'Z' | 'X')) && threads <= 1,
        ticks: number(19)?,
        command: command.to_owned(),
    })
}

/// Whether the task is dead (`X`): exited and being removed, it shows `-1`
/// for its group and session, and is as gone as one already removed.
fn is_dead(text: &str) -> bool {
    let state = text.rsplit_once(')').map(|(_, rest)| rest.trim_start());
    state.is_some_and(|rest| rest.starts_with('X'))
}

/// The `stat` of `pid` under `proc`, or `None` when it is gone. Its name may
/// be any bytes, so it is read lossily.
fn read_stat(proc: &Path, pid: u32) -> io::Result<Option<Stat>> {
    let path = proc.join(pid.to_string()).join("stat");
    let bytes = match std::fs::read(&path) {
        Err(e) if is_gone(&e) => return Ok(None),
        bytes => bytes?,
    };
    let text = String::from_utf8_lossy(&bytes);
    if is_dead(&text) {
        return Ok(None);
    }
    parse_stat(&text).map(Some).ok_or_else(|| {
        io::Error::other(format!(
            "{} does not read: `{}`",
            path.display(),
            text.trim()
        ))
    })
}

/// When the system booted, in seconds since the epoch, from `/proc/stat`.
fn boot_time(proc: &Path) -> Result<u64, PsError> {
    let path = proc.join("stat");
    let text = std::fs::read_to_string(&path)
        .map_err(|e| PsError::Proc(format!("{}: {e}", path.display())))?;
    text.lines()
        .find_map(|line| line.strip_prefix("btime ")?.trim().parse().ok())
        .ok_or_else(|| PsError::Proc(format!("{} shows no btime", path.display())))
}

/// How long after `boot` a process started `ticks` in, as `ps -o lstart`
/// writes it in UTC, its words one space apart: `Thu Oct 8 09:31:55 2026`.
fn started(boot: u64, ticks: u64, per_second: u64) -> Result<String, PsError> {
    let seconds = boot + ticks / per_second.max(1);
    let at = i64::try_from(seconds)
        .ok()
        .and_then(|s| Timestamp::from_second(s).ok())
        .ok_or_else(|| PsError::Proc(format!("a start time of {seconds} s is out of range")))?;
    Ok(at
        .to_zoned(TimeZone::UTC)
        .strftime("%a %b %-d %H:%M:%S %Y")
        .to_string())
}

/// What `/proc` shows of `pid`, or `None` when it is gone.
pub(super) fn seen_under(proc: &Path, pid: u32, per_second: u64) -> Result<Option<Seen>, PsError> {
    let error = |e: io::Error| PsError::Proc(format!("pid {pid}: {e}"));
    let Some(stat) = read_stat(proc, pid).map_err(error)? else {
        return Ok(None);
    };
    Ok(Some(Seen {
        zombie: stat.zombie,
        started: started(boot_time(proc)?, stat.ticks, per_second)?,
    }))
}

/// The group of `pid`, or `None` when it is gone.
pub(super) fn group_under(proc: &Path, pid: u32) -> Result<Option<u32>, PsError> {
    let stat = read_stat(proc, pid).map_err(|e| PsError::Proc(format!("pid {pid}: {e}")))?;
    Ok(stat.map(|s| s.pgid))
}

/// Every process under `proc` but zombies. One that exits meanwhile is left
/// out; so is one `/proc` refuses, which is another user's on a `/proc`
/// mounted with `hidepid`, as `ps` leaves it out. A listing that does not
/// show the caller is an error: it cannot be the whole listing.
pub(super) fn processes_under(proc: &Path, per_second: u64) -> Result<Vec<Proc>, PsError> {
    let error = |e: io::Error| PsError::Proc(format!("{}: {e}", proc.display()));
    let boot = boot_time(proc)?;
    let mut listed = Vec::new();
    let mut me_seen = false;
    let me = std::process::id();
    for entry in std::fs::read_dir(proc).map_err(error)? {
        let Some(pid) = entry
            .map_err(error)?
            .file_name()
            .to_str()
            .and_then(|n| n.parse::<u32>().ok())
        else {
            continue;
        };
        let stat = match read_stat(proc, pid) {
            Ok(Some(stat)) => stat,
            Ok(None) => continue,
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => continue,
            Err(e) => return Err(error(e)),
        };
        me_seen |= pid == me;
        if stat.zombie {
            continue;
        }
        listed.push(Proc {
            pid,
            ppid: stat.ppid,
            pgid: stat.pgid,
            started: started(boot, stat.ticks, per_second)?,
            command: stat.command,
        });
    }
    if !me_seen {
        return Err(PsError::Proc(format!(
            "{} does not show pid {me}, the caller",
            proc.display()
        )));
    }
    Ok(listed)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `stat` line of a test's own `/proc`.
    fn line(pid: u32, command: &str, state: char, ppid: u32, threads: u32, ticks: u64) -> String {
        format!(
            "{pid} ({command}) {state} {ppid} {pid} {pid} 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 {threads} 0 {ticks} 1234 56 18446744073709551615\n"
        )
    }

    fn fake(proc: &Path, pid: u32, stat: &str) {
        let dir = proc.join(pid.to_string());
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("stat"), stat).unwrap();
    }

    fn fake_boot(proc: &Path, btime: u64) {
        let text = format!("cpu  1 2 3\nintr 9\nctxt 7\nbtime {btime}\nprocesses 99\n");
        std::fs::write(proc.join("stat"), text).unwrap();
    }

    #[test]
    fn a_name_with_parentheses_and_spaces_is_read_whole() {
        let stat = parse_stat(&line(7, "a) (b c", 'S', 1, 1, 250)).unwrap();
        assert_eq!(stat.command, "a) (b c");
        assert_eq!((stat.ppid, stat.pgid, stat.ticks), (1, 7, 250));
        assert!(!stat.zombie);
        assert!(parse_stat("7 (x) S 1").is_none());
        assert!(parse_stat("garbled").is_none());
    }

    /// As `ps` writes `Zl` for one whose main thread exited while others
    /// run on, which is no zombie, and `Z` for one that is over.
    #[test]
    fn only_a_process_with_no_thread_left_is_a_zombie() {
        for (state, threads, zombie) in [
            ('Z', 1, true),
            ('X', 1, true),
            ('Z', 3, false),
            ('S', 1, false),
            ('R', 4, false),
        ] {
            let stat = parse_stat(&line(7, "x", state, 1, threads, 0)).unwrap();
            assert_eq!(stat.zombie, zombie, "{state} with {threads} threads");
        }
    }

    /// A process that has begun to exit runs no code, unless it is only its
    /// main thread that exits while others run on.
    #[test]
    fn a_process_exiting_with_no_other_thread_runs_no_more() {
        let exiting = |threads| line(7, "x", 'R', 1, threads, 0).replace(" 4194560 ", " 4194564 ");
        assert!(parse_stat(&exiting(1)).unwrap().zombie);
        assert!(!parse_stat(&exiting(3)).unwrap().zombie);
    }

    /// procps pads a day before the 10th; the text compared has one space.
    #[test]
    fn a_start_time_is_written_as_ps_writes_it_in_utc() {
        // 2026-10-08 09:31:00 UTC, then 55 s and a fraction after it.
        assert_eq!(
            started(1_791_451_860, 5_550, 100).unwrap(),
            "Thu Oct 8 09:31:55 2026"
        );
        assert_eq!(
            started(1_791_451_860, 5_599, 100).unwrap(),
            "Thu Oct 8 09:31:55 2026"
        );
        assert_eq!(
            started(1_792_316_400, 0, 100).unwrap(),
            "Sun Oct 18 09:40:00 2026"
        );
    }

    #[test]
    fn the_listing_leaves_out_zombies_and_what_is_gone_and_needs_the_caller() {
        let dir = tempfile::tempdir().unwrap();
        let proc = dir.path();
        fake_boot(proc, 1_791_451_860);
        let me = std::process::id();
        fake(proc, me, &line(me, "enclos", 'S', 1, 1, 100));
        fake(proc, 7, &line(7, "a-program-with-", 'S', me, 2, 5_550));
        fake(proc, 8, &line(8, "over", 'Z', me, 1, 0));
        // Gone between the listing and the read.
        std::fs::create_dir_all(proc.join("9")).unwrap();
        std::fs::create_dir_all(proc.join("self")).unwrap();
        let listed = processes_under(proc, 100).unwrap();
        let pids: Vec<u32> = listed.iter().map(|p| p.pid).collect();
        assert!(pids.contains(&7) && pids.contains(&me), "{pids:?}");
        assert!(!pids.contains(&8) && !pids.contains(&9), "{pids:?}");
        let seven = listed.iter().find(|p| p.pid == 7).unwrap();
        assert_eq!(
            (seven.ppid, seven.pgid, seven.command.as_str()),
            (me, 7, "a-program-with-")
        );
        assert_eq!(seven.started, "Thu Oct 8 09:31:55 2026");

        std::fs::remove_dir_all(proc.join(me.to_string())).unwrap();
        let err = processes_under(proc, 100).unwrap_err().to_string();
        assert!(err.contains("does not show pid"), "{err}");
    }

    /// A dead task, as main's CI saw one (`-1` for its group and session),
    /// is gone: left out of the listing, with no group and nothing seen.
    #[test]
    fn a_dead_process_is_gone() {
        let dir = tempfile::tempdir().unwrap();
        let proc = dir.path();
        fake_boot(proc, 1_791_451_860);
        let me = std::process::id();
        fake(proc, me, &line(me, "enclos", 'S', 1, 1, 100));
        fake(
            proc,
            5150,
            "5150 (sleep) X 0 -1 -1 0 -1 4228108 73 0 0 0 0 0 0 0 20 0 0 0 41386 0 0 0 0 0 0 0 0 0 0 0 0 1 0 0 17 1 0 0 0 0 0 0 0 0 0 0 0 0 9",
        );
        let pids: Vec<u32> = processes_under(proc, 100)
            .unwrap()
            .iter()
            .map(|p| p.pid)
            .collect();
        assert_eq!(pids, [me]);
        assert_eq!(group_under(proc, 5150).unwrap(), None);
        assert_eq!(seen_under(proc, 5150, 100).unwrap(), None);
    }

    #[test]
    fn a_stat_that_does_not_read_fails_the_listing() {
        let dir = tempfile::tempdir().unwrap();
        let proc = dir.path();
        fake_boot(proc, 1_791_451_860);
        let me = std::process::id();
        fake(proc, me, &line(me, "enclos", 'S', 1, 1, 100));
        fake(proc, 7, "7 (x) S");
        let err = processes_under(proc, 100).unwrap_err().to_string();
        assert!(err.contains("does not read"), "{err}");
        std::fs::remove_file(proc.join("stat")).unwrap();
        assert!(processes_under(proc, 100).is_err());
    }

    #[test]
    fn one_process_is_seen_with_its_group_or_not_at_all() {
        let dir = tempfile::tempdir().unwrap();
        let proc = dir.path();
        fake_boot(proc, 1_791_451_860);
        fake(proc, 7, &line(7, "x", 'Z', 1, 3, 5_550));
        let seen = seen_under(proc, 7, 100).unwrap().unwrap();
        assert_eq!(
            seen,
            Seen {
                zombie: false,
                started: "Thu Oct 8 09:31:55 2026".to_owned(),
            }
        );
        assert_eq!(group_under(proc, 7).unwrap(), Some(7));
        assert_eq!(seen_under(proc, 8, 100).unwrap(), None);
        assert_eq!(group_under(proc, 8).unwrap(), None);
    }
}
