//! Restarts a runtime service once its settings files change (ADR 0031).

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use super::Engine;
use crate::error::Result;
use crate::lifecycle::process::{Signalled, is_same, signal_process};
use crate::model::audit::{Actor, Intent, Outcome};
use crate::model::runtime::RuntimeKind;
use crate::model::sandbox::SandboxName;
use crate::model::session::{SessionKind, SessionRecord};
use crate::runtime::home::read_text;
use crate::runtime::{HomePath, Signal, Unreadable, adapter};
use crate::state::StateLock;

const READ_EVERY: Duration = Duration::from_secs(2);
/// Hermes's setup writes `.env` and `config.yaml` one after the other.
const SETTLE: Duration = Duration::from_secs(5);
const MAX_SETTINGS: u64 = 1024 * 1024;
/// Doubled after each failure, so one that lasts does not fill the audit log.
const RETRY: Duration = Duration::from_secs(60);
const RETRY_MAX: Duration = Duration::from_secs(64 * 60);

type Read = std::result::Result<Option<String>, Unreadable>;

pub(super) struct SettingsWatch {
    home: PathBuf,
    files: Vec<HomePath>,
    started: Vec<Read>,
    /// The last read that differs from `started`, and since when.
    changed: Option<(Vec<Read>, Instant)>,
    read_at: Option<Instant>,
    retry_at: Option<Instant>,
    retry: Duration,
}

impl SettingsWatch {
    pub(super) fn new(home: PathBuf, files: Vec<HomePath>) -> Option<SettingsWatch> {
        if files.is_empty() {
            return None;
        }
        let started = read_all(&home, &files);
        Some(SettingsWatch {
            home,
            files,
            started,
            changed: None,
            read_at: None,
            retry_at: None,
            retry: RETRY,
        })
    }

    /// The files that differ from the start, once unchanged for `SETTLE`.
    pub(super) fn settled(&mut self, now: Instant) -> Option<Vec<HomePath>> {
        if self
            .read_at
            .is_some_and(|at| now.duration_since(at) < READ_EVERY)
        {
            return None;
        }
        self.read_at = Some(now);
        let read = read_all(&self.home, &self.files);
        if read == self.started {
            self.changed = None;
            self.retry_at = None;
            return None;
        }
        match &self.changed {
            Some((last, since)) if *last == read => {
                if self.retry_at.is_some_and(|at| now < at) {
                    return None;
                }
                (now.duration_since(*since) >= SETTLE).then(|| {
                    self.files
                        .iter()
                        .zip(read.iter().zip(&self.started))
                        .filter(|(_, (now, then))| now != then)
                        .map(|(file, _)| file.clone())
                        .collect()
                })
            }
            _ => {
                self.changed = Some((read, now));
                self.retry_at = None;
                None
            }
        }
    }

    pub(super) fn failed(&mut self, now: Instant) {
        self.retry_at = Some(now + self.retry);
        self.retry = (self.retry * 2).min(RETRY_MAX);
    }
}

fn read_all(home: &Path, files: &[HomePath]) -> Vec<Read> {
    files
        .iter()
        .map(|file| read_text(home, file, MAX_SETTINGS))
        .collect()
}

impl Engine {
    /// `None` when the service has no restart signal or its runtime no files.
    pub(super) fn settings_watch(
        &self,
        name: &SandboxName,
        kind: RuntimeKind,
        service: &str,
    ) -> Option<(SettingsWatch, Signal)> {
        let runtime = adapter(kind);
        let signal = runtime
            .services()
            .into_iter()
            .find(|s| s.name.as_str() == service)?
            .restart?;
        let home = self.sandbox_home(name);
        let agents = runtime.agents_in(&home).unwrap_or_default();
        let watch = SettingsWatch::new(home, runtime.settings_files(&agents))?;
        Some((watch, signal))
    }

    /// A setup or TUI may still be in use (ADR 0031). Under the state lock,
    /// which `connect` holds to start its program, so none starts before
    /// the restart.
    fn someone_connected(&self, _lock: &StateLock, name: &SandboxName) -> Result<bool> {
        Ok(self
            .state
            .sessions(name, true)?
            .iter()
            .any(|s| s.kind == SessionKind::Interactive && is_same(&s.root).unwrap_or(true)))
    }

    /// `Ok(None)`: the lock is busy or someone is connected; ask later.
    pub(super) fn ask_restart(
        &self,
        by: &Actor,
        session: &SessionRecord,
        signal: Signal,
        changed: &[HomePath],
    ) -> Result<Option<std::result::Result<(), String>>> {
        // Never waits: the wait loop would miss the program's exit.
        let Some(lock) = self.state.try_lock()? else {
            return Ok(None);
        };
        if self.someone_connected(&lock, &session.sandbox)? {
            return Ok(None);
        }
        let intent = Intent {
            by: by.clone(),
            command: "service restart".to_owned(),
            target: Some(format!("{} session {}", session.sandbox, session.id)),
        };
        let ticket = self.audit.begin(&lock, intent)?;
        let files: Vec<String> = changed.iter().map(ToString::to_string).collect();
        let changed = format!("{} changed", files.join(", "));
        let sent = match signal_process(&session.root, signal) {
            Ok(Signalled::Sent) => Ok(()),
            Ok(Signalled::Gone) => Err("its program had already exited".to_owned()),
            Ok(Signalled::NotLeader) => Err("its program no longer leads its group".to_owned()),
            Ok(Signalled::Failed(why)) => Err(why),
            Err(e) => Err(e.to_string()),
        };
        let outcome = match &sent {
            Ok(()) => Outcome::ok(format!("{changed}: sent {}", signal.name())),
            Err(why) => Outcome::failed(format!(
                "{changed}, but {} was not sent: {why}",
                signal.name()
            )),
        };
        // The signal is already sent; `audit verify` reports the unfinished entry.
        let _ = self.audit.finish(ticket, outcome);
        Ok(Some(sent))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rel(p: &str) -> HomePath {
        HomePath::new(p).unwrap()
    }

    fn watched() -> (tempfile::TempDir, SettingsWatch) {
        let home = tempfile::tempdir().unwrap();
        std::fs::write(home.path().join("a"), "1").unwrap();
        let watch = SettingsWatch::new(home.path().to_owned(), vec![rel("a"), rel("b")]).unwrap();
        (home, watch)
    }

    #[test]
    fn a_change_restarts_once_it_has_stayed_the_same() {
        let (home, mut watch) = watched();
        let t = Instant::now();
        assert_eq!(watch.settled(t), None);
        std::fs::write(home.path().join("b"), "token").unwrap();
        assert_eq!(watch.settled(t + Duration::from_secs(1)), None);
        assert_eq!(watch.settled(t + READ_EVERY), None);
        std::fs::write(home.path().join("b"), "token2").unwrap();
        let again = t + 2 * READ_EVERY;
        assert_eq!(watch.settled(again), None);
        assert_eq!(
            watch.settled(again + SETTLE - Duration::from_millis(1)),
            None
        );
        assert_eq!(watch.settled(again + 2 * SETTLE), Some(vec![rel("b")]));
    }

    #[test]
    fn a_file_rewritten_the_same_or_changed_back_restarts_nothing() {
        let (home, mut watch) = watched();
        let t = Instant::now();
        std::fs::write(home.path().join("a"), "2").unwrap();
        assert_eq!(watch.settled(t), None);
        std::fs::write(home.path().join("a"), "1").unwrap();
        assert_eq!(watch.settled(t + READ_EVERY), None);
        assert_eq!(watch.settled(t + READ_EVERY + 2 * SETTLE), None);
    }

    #[test]
    fn a_file_replaced_by_a_link_counts_as_changed_and_is_not_followed() {
        let (home, mut watch) = watched();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("a"), "1").unwrap();
        std::fs::remove_file(home.path().join("a")).unwrap();
        std::os::unix::fs::symlink(outside.path().join("a"), home.path().join("a")).unwrap();
        let t = Instant::now();
        assert_eq!(watch.settled(t), None);
        assert_eq!(watch.settled(t + SETTLE + READ_EVERY), Some(vec![rel("a")]));
    }

    #[test]
    fn a_restart_not_sent_is_asked_again_after_a_change_or_a_while() {
        let (home, mut watch) = watched();
        let t = Instant::now();
        std::fs::write(home.path().join("b"), "token").unwrap();
        assert_eq!(watch.settled(t), None);
        let first = t + SETTLE;
        assert_eq!(watch.settled(first), Some(vec![rel("b")]));
        watch.failed(first);
        assert_eq!(watch.settled(first + READ_EVERY), None);
        assert_eq!(watch.settled(first + RETRY), Some(vec![rel("b")]));
        let second = first + RETRY;
        watch.failed(second);
        assert_eq!(watch.settled(second + RETRY), None);
        assert_eq!(watch.settled(second + 2 * RETRY), Some(vec![rel("b")]));
        watch.failed(second + 2 * RETRY);
        std::fs::write(home.path().join("b"), "token2").unwrap();
        let later = second + 2 * RETRY + READ_EVERY;
        assert_eq!(watch.settled(later), None);
        assert_eq!(watch.settled(later + SETTLE), Some(vec![rel("b")]));
    }

    #[test]
    fn no_files_is_no_watch() {
        let home = tempfile::tempdir().unwrap();
        assert!(SettingsWatch::new(home.path().to_owned(), Vec::new()).is_none());
    }
}
