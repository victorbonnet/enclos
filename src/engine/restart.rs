//! Restarts a runtime service once its settings files change (ADR 0031).

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use super::Engine;
use crate::error::Result;
use crate::lifecycle::proc::program_in_pid_namespace;
use crate::lifecycle::process::{Signalled, is_same, reference, signal_process};
use crate::model::audit::{Actor, Intent, Outcome};
use crate::model::runtime::RuntimeKind;
use crate::model::sandbox::SandboxName;
use crate::model::session::{ProcessRef, SessionKind, SessionRecord};
use crate::runtime::home::read_text;
use crate::runtime::{HomePath, Signal, Unreadable, adapter};
use crate::state::StateLock;

const READ_EVERY: Duration = Duration::from_secs(2);
/// Hermes's setup writes `.env` and `config.yaml` one after the other.
const SETTLE: Duration = Duration::from_secs(5);
/// The largest settings file read, here and by `doctor`.
pub(super) const MAX_SETTINGS: u64 = 1024 * 1024;
/// Doubled after each failure, so one that lasts does not fill the audit log.
const RETRY: Duration = Duration::from_secs(60);
const RETRY_MAX: Duration = Duration::from_secs(64 * 60);

type Read = std::result::Result<Option<String>, Unreadable>;
/// The part of a settings file whose change needs a restart, as the
/// runtime says ([`crate::runtime::RuntimeAdapter::restart_relevant`]).
type Relevant = Box<dyn Fn(&HomePath, &str) -> String>;

/// Where a service session's program runs, which the restart signal must
/// reach (ADR 0031).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ProgramAt {
    /// The session's root: `sandbox-exec`, and the `ulimit` shell when
    /// limits are set, `exec` it, so the root's pid is the program's.
    Root,
    /// The second process of the session's own PID namespace (design §5,
    /// What a session runs first). The root is `enclos holder join`, on the
    /// host, whose child is bubblewrap's outer process: a signal sent there
    /// would end `holder join`, and `launch` would then stop the program
    /// with TERM, a restart that waits for nothing.
    PidNamespace,
}

pub(super) struct SettingsWatch {
    home: PathBuf,
    files: Vec<HomePath>,
    relevant: Relevant,
    started: Vec<Read>,
    /// The last read that differs from `started`, and since when.
    changed: Option<(Vec<Read>, Instant)>,
    read_at: Option<Instant>,
    retry_at: Option<Instant>,
    retry: Duration,
}

impl SettingsWatch {
    pub(super) fn new(
        home: PathBuf,
        files: Vec<HomePath>,
        relevant: Relevant,
    ) -> Option<SettingsWatch> {
        if files.is_empty() {
            return None;
        }
        let started = read_all(&home, &files, &relevant);
        Some(SettingsWatch {
            home,
            files,
            relevant,
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
        let read = read_all(&self.home, &self.files, &self.relevant);
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

/// Each file's part that needs a restart: a change the runtime applies on
/// its own (ADR 0069, proposed) compares equal.
fn read_all(home: &Path, files: &[HomePath], relevant: &Relevant) -> Vec<Read> {
    files
        .iter()
        .map(|file| {
            read_text(home, file, MAX_SETTINGS).map(|text| text.map(|text| relevant(file, &text)))
        })
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
        let files = runtime.settings_files(&agents);
        let relevant: Relevant = Box::new(move |file, text| runtime.restart_relevant(file, text));
        let watch = SettingsWatch::new(home, files, relevant)?;
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
        at: ProgramAt,
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
        let sent = match program(session, at)
            .and_then(|program| signal_process(&program, signal).map_err(|e| e.to_string()))
        {
            Ok(Signalled::Sent) => Ok(()),
            Ok(Signalled::Gone) => Err("its program had already exited".to_owned()),
            Ok(Signalled::NotLeader) => Err("its program no longer leads its group".to_owned()),
            Ok(Signalled::Failed(why)) | Err(why) => Err(why),
        };
        let outcome = match &sent {
            Ok(()) => Outcome::ok(format!("{changed}: sent {}", signal.name())),
            Err(why) => Outcome::failed(format!(
                "{changed}, but {} was not sent: {why}",
                signal.name()
            )),
        };
        // Sent or not, `launch` notes the outcome, and an error here must not
        // ask again for a restart already sent; `audit verify` reports the
        // unfinished entry.
        let _ = self.audit.finish(ticket, outcome);
        Ok(Some(sent))
    }
}

const GONE: &str = "its program had already exited";

/// The program of `session`, as it runs `at`, from the host's `/proc` when
/// in a PID namespace ([`program_found`]).
fn program(session: &SessionRecord, at: ProgramAt) -> std::result::Result<ProcessRef, String> {
    let root = &session.root;
    if at == ProgramAt::Root {
        return Ok(root.clone());
    }
    program_found(
        root.pid,
        || is_same(root).map_err(|e| e.to_string()),
        || program_in_pid_namespace(root.pid).map_err(|e| e.to_string()),
        |pid| reference(pid).map_err(|e| e.to_string()),
    )
}

/// The program of the root `root`, which `alive` says is still the recorded
/// process, as `find` gives its pid and `refer` its start time. The pid is
/// read, its start time taken, then the pid read again: only when both
/// reads agree is the reference returned, so it names the root's program
/// as of the second read, and `signal_process` signals only a process with
/// that start time.
fn program_found(
    root: u32,
    alive: impl Fn() -> std::result::Result<bool, String>,
    mut find: impl FnMut() -> std::result::Result<Option<u32>, String>,
    refer: impl Fn(u32) -> std::result::Result<Option<ProcessRef>, String>,
) -> std::result::Result<ProcessRef, String> {
    let mut look = || -> std::result::Result<Option<u32>, String> {
        if !alive()? {
            return Err(GONE.to_owned());
        }
        find()
    };
    let Some(pid) = look()? else {
        // The root may have ended during the look.
        if !alive()? {
            return Err(GONE.to_owned());
        }
        return Err(format!(
            "no program runs in the PID namespace below pid {root} (not started yet, or already exited)"
        ));
    };
    let program = refer(pid)?.ok_or_else(|| GONE.to_owned())?;
    match look()? {
        Some(again) if again == pid => Ok(program),
        _ => Err(GONE.to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rel(p: &str) -> HomePath {
        HomePath::new(p).unwrap()
    }

    /// The watch `launch` builds for a Hermes gateway compares what Hermes's
    /// adapter says needs a restart: an agent's model alone does not.
    #[test]
    fn a_hermes_gateways_watch_leaves_out_an_agents_model() {
        let dir = tempfile::tempdir().unwrap();
        let layout = crate::layout::Layout::at(dir.path().join("enclos"));
        let state = crate::state::sqlite::SqliteStateStore::new(
            layout.state_db(),
            layout.state_lock(),
            crate::state::Wait::Command,
        );
        let audit = crate::audit::jsonl::JsonlAuditLog::new(layout.audit_log());
        let engine = Engine::new(layout, Box::new(state), Box::new(audit), Vec::new());
        let name: SandboxName = "lab".parse().unwrap();
        let config = engine.sandbox_home(&name).join(".hermes/config.yaml");
        std::fs::create_dir_all(config.parent().unwrap()).unwrap();
        let text = "model:\n  default: model-1\nterminal:\n  backend: local\n";
        std::fs::write(&config, text).unwrap();
        let (mut watch, signal) = engine
            .settings_watch(&name, RuntimeKind::Hermes, "gateway")
            .unwrap();
        assert_eq!(signal, Signal::Usr1);
        let t = Instant::now();
        std::fs::write(&config, text.replace("model-1", "model-2")).unwrap();
        assert_eq!(watch.settled(t), None);
        assert_eq!(watch.settled(t + READ_EVERY + 2 * SETTLE), None);
        std::fs::write(&config, text.replace("local", "docker")).unwrap();
        let later = t + 2 * READ_EVERY + 2 * SETTLE;
        assert_eq!(watch.settled(later), None);
        assert_eq!(
            watch.settled(later + 2 * SETTLE),
            Some(vec![rel(".hermes/config.yaml")])
        );
    }

    fn watched() -> (tempfile::TempDir, SettingsWatch) {
        let home = tempfile::tempdir().unwrap();
        std::fs::write(home.path().join("a"), "1").unwrap();
        let watch = SettingsWatch::new(
            home.path().to_owned(),
            vec![rel("a"), rel("b")],
            Box::new(|_, text| text.to_owned()),
        )
        .unwrap();
        (home, watch)
    }

    #[test]
    fn a_change_the_runtime_applies_on_its_own_restarts_nothing() {
        let home = tempfile::tempdir().unwrap();
        std::fs::write(home.path().join("a"), "model: 1\nother: 1").unwrap();
        // As a runtime that reads its model again for each turn says.
        let relevant: Relevant = Box::new(|_, text| {
            text.lines()
                .filter(|l| !l.starts_with("model:"))
                .collect::<Vec<_>>()
                .join("\n")
        });
        let mut watch =
            SettingsWatch::new(home.path().to_owned(), vec![rel("a")], relevant).unwrap();
        let t = Instant::now();
        std::fs::write(home.path().join("a"), "model: 2\nother: 1").unwrap();
        assert_eq!(watch.settled(t), None);
        assert_eq!(watch.settled(t + READ_EVERY + 2 * SETTLE), None);
        std::fs::write(home.path().join("a"), "model: 2\nother: 2").unwrap();
        let later = t + 2 * READ_EVERY + 2 * SETTLE;
        assert_eq!(watch.settled(later), None);
        assert_eq!(watch.settled(later + 2 * SETTLE), Some(vec![rel("a")]));
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

    fn process(pid: u32) -> ProcessRef {
        ProcessRef {
            pid,
            started: format!("started {pid}"),
        }
    }

    /// `program_found` with the root alive as `alive` says each time, the
    /// pids `found` gives in turn, and every pid referred to.
    fn found(alive: &[bool], found: &[Option<u32>]) -> std::result::Result<ProcessRef, String> {
        let alive = std::cell::RefCell::new(alive.iter().copied());
        let mut found = found.iter().copied();
        program_found(
            7,
            || Ok(alive.borrow_mut().next().expect("asked once too often")),
            || Ok(found.next().expect("looked once too often")),
            |pid| Ok(Some(process(pid))),
        )
    }

    #[test]
    fn the_program_is_returned_when_both_looks_agree() {
        assert_eq!(found(&[true, true], &[Some(12), Some(12)]), Ok(process(12)));
    }

    #[test]
    fn a_root_gone_has_no_program() {
        assert_eq!(found(&[false], &[]), Err(GONE.to_owned()));
        assert_eq!(found(&[true, false], &[Some(12)]), Err(GONE.to_owned()));
    }

    #[test]
    fn a_pid_that_changed_or_went_between_the_looks_is_not_returned() {
        assert_eq!(
            found(&[true, true], &[Some(12), Some(13)]),
            Err(GONE.to_owned())
        );
        assert_eq!(
            found(&[true, true], &[Some(12), None]),
            Err(GONE.to_owned())
        );
    }

    #[test]
    fn no_program_found_says_where_it_was_looked_for() {
        let missing = found(&[true, true], &[None]).unwrap_err();
        assert!(missing.contains("below pid 7"), "{missing}");
        assert!(
            missing.contains("not started yet, or already exited"),
            "{missing}"
        );
        // A root that ended during the look has no program, whatever it says.
        assert_eq!(found(&[true, false], &[None]), Err(GONE.to_owned()));
    }

    #[test]
    fn a_pid_with_no_start_time_is_a_program_gone() {
        let alive = || Ok(true);
        let gone = program_found(7, alive, || Ok(Some(12)), |_| Ok(None));
        assert_eq!(gone, Err(GONE.to_owned()));
    }

    #[test]
    fn a_look_that_fails_says_why() {
        let failed = program_found(
            7,
            || Ok(true),
            || Err("proc refused".to_owned()),
            |pid| Ok(Some(process(pid))),
        );
        assert_eq!(failed, Err("proc refused".to_owned()));
    }

    #[test]
    fn no_files_is_no_watch() {
        let home = tempfile::tempdir().unwrap();
        assert!(
            SettingsWatch::new(
                home.path().to_owned(),
                Vec::new(),
                Box::new(|_, t| t.to_owned())
            )
            .is_none()
        );
    }
}
