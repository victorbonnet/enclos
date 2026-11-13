//! One `enclos dashboard` per sandbox at a time (ADR 0040): a lock in the
//! sandbox's host-only run folder, which the kernel releases however the
//! command ends, so none is left behind. The run that holds it writes there
//! what a second run names.

use std::fs::{File, OpenOptions, TryLockError};
use std::io::{self, Read, Seek, Write};
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::layout::LayoutError;
use crate::model::Timestamp;
use crate::model::sandbox::SandboxName;

/// The run that holds the lock, as it says.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct Running {
    /// The `enclos dashboard` process.
    pub pid: u32,
    /// Its session, once recorded.
    pub session: Option<i64>,
    pub since: Timestamp,
}

/// The lock, held until dropped.
pub(super) struct DashboardLock {
    file: File,
}

impl DashboardLock {
    /// Takes the lock at `path` for `running`, or refuses, naming the run
    /// that holds it.
    pub(super) fn take(
        path: &Path,
        name: &SandboxName,
        running: &Running,
    ) -> Result<DashboardLock> {
        let io = |source| LayoutError::Io {
            path: path.to_owned(),
            source,
        };
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(path)
            .map_err(io)?;
        match file.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => {
                let mut said = String::new();
                let first = match file.read_to_string(&mut said) {
                    Ok(_) => serde_json::from_str(&said).ok(),
                    Err(_) => None,
                };
                return Err(Error::Dashboard {
                    what: refusal(name, first.as_ref()),
                });
            }
            Err(TryLockError::Error(e)) => return Err(io(e).into()),
        }
        let mut lock = DashboardLock { file };
        lock.say(running).map_err(io)?;
        Ok(lock)
    }

    /// Writes what a second run names, in place of what was there.
    pub(super) fn say(&mut self, running: &Running) -> io::Result<()> {
        let text = serde_json::to_string(running).map_err(io::Error::other)?;
        self.file.set_len(0)?;
        self.file.rewind()?;
        self.file.write_all(text.as_bytes())
    }
}

/// Why a second run on `name` is refused, naming the `first`, as it said.
fn refusal(name: &SandboxName, first: Option<&Running>) -> String {
    let Some(first) = first else {
        return format!(
            "sandbox {name} already has a dashboard starting: another `enclos dashboard {name}` holds its lock"
        );
    };
    let session = match first.session {
        Some(id) => format!(", session {id}"),
        None => String::new(),
    };
    format!(
        "sandbox {name} already has a dashboard: `enclos dashboard {name}` (pid {}{session}) started at {}. Use the address printed by that run, or end it with Ctrl-C where it runs",
        first.pid,
        first.since.strftime("%Y-%m-%d %H:%M:%S UTC"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn running(session: Option<i64>) -> Running {
        Running {
            pid: 4242,
            session,
            since: "2026-11-06T10:20:30Z".parse().unwrap(),
        }
    }

    #[test]
    fn a_second_run_is_refused_naming_the_first() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dashboard.lock");
        let name: SandboxName = "lab".parse().unwrap();
        let mut first = DashboardLock::take(&path, &name, &running(None)).unwrap();
        first.say(&running(Some(12))).unwrap();
        let Err(Error::Dashboard { what }) = DashboardLock::take(&path, &name, &running(None))
        else {
            panic!("a second run took the lock");
        };
        assert_eq!(
            what,
            "sandbox lab already has a dashboard: `enclos dashboard lab` (pid 4242, session 12) started at 2026-11-06 10:20:30 UTC. Use the address printed by that run, or end it with Ctrl-C where it runs"
        );
        // Released once the first ends, whatever it left written: soon, as a
        // program another test starts meanwhile holds a copy until it runs.
        drop(first);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while DashboardLock::take(&path, &name, &running(None)).is_err() {
            assert!(std::time::Instant::now() < deadline, "never released");
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }

    #[test]
    fn a_first_run_that_said_nothing_yet_is_named_all_the_same() {
        let name: SandboxName = "lab".parse().unwrap();
        let said = refusal(&name, None);
        assert!(said.contains("already has a dashboard starting"), "{said}");
        let said = refusal(&name, Some(&running(None)));
        assert!(said.contains("(pid 4242)"), "{said}");
    }

    #[test]
    fn a_lock_written_by_an_older_version_does_not_disclose_its_url() {
        let mut old = serde_json::to_value(running(Some(12))).unwrap();
        old["url"] = "http://127.0.0.1:41003/private-capability/".into();
        let first: Running = serde_json::from_value(old).unwrap();
        let name = "lab".parse().unwrap();
        assert!(!refusal(&name, Some(&first)).contains("private-capability"));
        assert!(!serde_json::to_string(&first).unwrap().contains("url"));
    }
}
