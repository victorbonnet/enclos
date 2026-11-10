//! `enclos launch`, what the service manager runs for a runtime's service,
//! and the proxy recording itself (design §8, ADR 0021).

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use signal_hook::consts::{SIGHUP, SIGINT, SIGTERM};

use super::Engine;
use super::service::PROXY_WAIT;
use super::session::SessionEnd;
use super::start::{Started, Starting};
use crate::error::{Error, Result};
use crate::lifecycle::process::{group_of, is_same, reference};
use crate::model::audit::Actor;
use crate::model::now;
use crate::model::sandbox::SandboxName;
use crate::model::session::{SessionId, SessionKind, SessionRecord};
use crate::runtime::adapter;

/// What `launch` did before starting `service`, for its audit entry: the
/// sessions of `service` it stopped and ended, if any.
fn replaced_earlier(service: &str, ids: &[SessionId]) -> Option<String> {
    let list = ids
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    match ids {
        [] => None,
        [_] => Some(format!(
            "stopping and ending {service} service session {list}, left by an earlier launch"
        )),
        _ => Some(format!(
            "stopping and ending {service} service sessions {list}, left by earlier launches"
        )),
    }
}

/// Sets `ended` on TERM, INT and HUP while it lives, instead of ending this
/// process: `launch` and `dashboard` outlive them to stop their program,
/// which runs in a group of its own that neither the service manager nor
/// the terminal signals, and to record its end.
pub(super) struct EndOn(Vec<signal_hook::SigId>);

impl EndOn {
    pub(super) fn new(ended: &Arc<AtomicBool>) -> Result<Self> {
        // The guard first, so what is registered is unregistered even when a
        // later registration fails.
        let mut guard = EndOn(Vec::new());
        for signal in [SIGTERM, SIGINT, SIGHUP] {
            let id = signal_hook::flag::register(signal, Arc::clone(ended)).map_err(|e| {
                Error::Session {
                    what: format!("cannot handle signal {signal}: {e}"),
                }
            })?;
            guard.0.push(id);
        }
        Ok(guard)
    }
}

impl Drop for EndOn {
    fn drop(&mut self) {
        for id in self.0.drain(..) {
            signal_hook::low_level::unregister(id);
        }
    }
}

impl Engine {
    /// A runtime service's process: runs the command the sandbox's runtime
    /// declares under `service` in the sandbox, in a process group of its
    /// own, recorded as a session of `service`, once it has stopped any
    /// session of `service` still open. Told to end (TERM, as the service
    /// manager does, INT or HUP), it stops the session's members and records
    /// the end, as failed when the program outlives that.
    pub fn launch(&self, by: &Actor, name: &SandboxName, service: &str) -> Result<SessionEnd> {
        use crate::backend::seatbelt::{BASELINE_VAR, Baseline};
        // A service runs only on `(deny default)` (ADR 0006): the job file
        // never carries the comparison baseline, and one the service
        // manager's own environment carries, or a hand-run `launch`, is
        // refused here, before anything is recorded.
        let why = match Baseline::from_env() {
            Ok(Baseline::DenyDefault) => None,
            Ok(Baseline::AllowDefault) => Some(format!("{BASELINE_VAR} asks for allow-default")),
            Err(why) => Some(why),
        };
        if let Some(why) = why {
            return Err(Error::Session {
                what: format!(
                    "{why}: a service runs only on (deny default) (`{}` unsets it in the service manager's environment)",
                    self.services.unset_env_command(BASELINE_VAR),
                ),
            });
        }
        let ended = Arc::new(AtomicBool::new(false));
        let _ending = EndOn::new(&ended)?;
        self.launch_until(by, name, service, &ended)
    }

    /// `launch`, ending once `ended` is set.
    pub(super) fn launch_until(
        &self,
        by: &Actor,
        name: &SandboxName,
        service: &str,
        ended: &AtomicBool,
    ) -> Result<SessionEnd> {
        let kind = self.runtime_of(name)?;
        let command = adapter(kind)
            .services()
            .into_iter()
            .find(|s| s.name.as_str() == service)
            .ok_or_else(|| Error::Session {
                what: format!("{kind} has no background service named {service}"),
            })?
            .command
            .into_words();
        if command.is_empty() {
            return Err(Error::Session {
                what: format!("{kind} declares the {service} service with no command"),
            });
        }
        let record = self.record(name)?;
        // The sandbox's own proxy, not whatever listens on its port: a proxy
        // records itself only once it holds the port, so a recorded proxy
        // session whose process still runs is the proof (`proxy run --record`).
        let start = Instant::now();
        while !self.proxy_runs(name)? {
            if ended.load(Ordering::Relaxed) {
                return Err(Error::Session {
                    what: format!("told to end before the {service} service of {name} started"),
                });
            }
            if start.elapsed() > PROXY_WAIT {
                return Err(Error::Session {
                    what: format!(
                        "the proxy of sandbox {name} did not start on port {}; see `enclos logs {name}`",
                        record.proxy_port
                    ),
                });
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        // The service manager starts the namespace holder beside this
        // service, whose session joins it (ADR 0039); one missing, as in
        // services a version of enclos without it installed, is installed.
        self.ensure_holder(&record)?;
        let mut watch = self.settings_watch(name, kind, service);
        let summary = |(started, replaced): &(Started<()>, Vec<SessionId>)| {
            let session = started.session.id;
            match replaced_earlier(service, replaced) {
                Some(earlier) => format!("session {session}, after {earlier}"),
                None => format!("session {session}"),
            }
        };
        let (Started { session, mut child, .. }, _) =
            self.write(by, "launch", Some(name.to_string()), summary, |lock| {
                // Sessions stopped and ended before a failure are named in
                // the failed entry too.
                let mut replaced = Vec::new();
                let started = (|| -> Result<Started<()>> {
                    // A `launch` killed before it recorded its end leaves its
                    // session open, and maybe its runtime running (design §4).
                    self.stop_sessions(
                        lock,
                        name,
                        |s| s.kind == SessionKind::Service && s.service.as_deref() == Some(service),
                        &format!(
                            "a second {service} was not started. End what still runs, and the service manager starts the service again on its own; `enclos sandbox stop {name}` removes the service instead"
                        ),
                        &mut replaced,
                    )?;
                    if ended.load(Ordering::Relaxed) {
                        return Err(Error::Session {
                            what: format!("told to end before the {service} service of {name} started"),
                        });
                    }
                    // A service session whose `launch` was killed before it
                    // recorded its end, at logout or by the service manager's
                    // timeout: its process is gone, so it ends here.
                    self.end_dead_sessions(lock, name, SessionKind::Service)?;
                    let starting = Starting::Service { service };
                    self.start_session(lock, name, &command, starting, || Ok(()))
                })();
                let started = match (started, replaced_earlier(service, &replaced)) {
                    (Ok(started), _) => Ok((started, replaced)),
                    (Err(error), None) => Err(error),
                    (Err(error), Some(done)) => Err(Error::FailedAfter {
                        error: Box::new(error),
                        done,
                    }),
                };
                self.failed_on_error(lock, name, "launch", started)
            })?;
        // Asked to restart once its settings change (ADR 0031).
        let mut restarting = false;
        let mut look = |notes: &mut Vec<String>| {
            let Some((settings, signal)) = watch.as_mut() else {
                return;
            };
            let Some(changed) = settings.settled(Instant::now()) else {
                return;
            };
            let files: Vec<String> = changed.iter().map(ToString::to_string).collect();
            let files = files.join(", ");
            let why = match self.ask_restart(by, &session, *signal, &changed) {
                Ok(None) => return,
                Ok(Some(Ok(()))) => {
                    restarting = true;
                    super::session::note(
                        notes,
                        format!("{files} changed: asked the {service} service to restart"),
                    );
                    watch = None;
                    return;
                }
                Ok(Some(Err(why))) => why,
                Err(e) => e.to_string(),
            };
            settings.failed(Instant::now());
            super::session::note(
                notes,
                format!(
                    "{files} changed, but the {service} service was not asked to restart: {why}"
                ),
            );
        };
        // As for `connect`, the members the service starts are recorded.
        // Unlike `connect`, what it leaves running is stopped: under a
        // service manager the service is its program, which the manager
        // starts again, and what it last left would run beside it.
        let mut waited = match self.wait_session(&session, &mut child, Some(ended), &mut look) {
            Ok(waited) => waited,
            Err(error) => return Err(self.record_unended(by, "service end", &session, error)),
        };
        self.stop_left(&session, &mut waited);
        let mut end = self.finish_session(by, "service end", &session, waited)?;
        end.restarting = restarting;
        Ok(end)
    }

    /// Ends the sandbox's sessions of `kind` whose root process is gone.
    pub(super) fn end_dead_sessions(
        &self,
        lock: &crate::state::StateLock,
        name: &SandboxName,
        kind: SessionKind,
    ) -> Result<()> {
        for session in self.state.sessions(name, true)? {
            if session.kind != kind || is_same(&session.root)? {
                continue;
            }
            // What it tracked, or what holds its marker (ADR 0030), still
            // runs: the session stays open, for a stop to end it.
            // One that cannot be looked at stays open too, rather than
            // keep the new service from starting.
            let Ok(look) = self.look_now(name) else {
                continue;
            };
            if !look.is_gone(&session) {
                continue;
            }
            self.state.end_session(lock, session.id)?;
            self.forget_marker(&session);
        }
        Ok(())
    }

    /// Records this process as the sandbox's proxy: `proxy run --record`
    /// calls it once it holds the port, so `connect` and `launch` know it
    /// runs. A recorded proxy whose process is gone ends here: at logout or
    /// a crash, a proxy service dies with its session open.
    pub(super) fn record_proxy(&self, by: &Actor, name: &SandboxName) -> Result<SessionId> {
        let me = std::process::id();
        self.write(
            by,
            "proxy start",
            Some(name.to_string()),
            |id| format!("session {id}"),
            |lock| {
                self.end_dead_sessions(lock, name, SessionKind::Proxy)?;
                let (version, snapshot) = self.active_policy(name)?;
                let session = SessionRecord {
                    id: SessionId(0),
                    sandbox: name.clone(),
                    kind: SessionKind::Proxy,
                    service: None,
                    version: version.version,
                    snapshot: snapshot.id,
                    compiled: None,
                    root: reference(me)?.ok_or_else(|| Error::Session {
                        what: "cannot read this process's start time".into(),
                    })?,
                    // Its group only when it leads it, as under a service
                    // manager: otherwise the group is its caller's.
                    pgid: (group_of(me)? == Some(me)).then_some(me),
                    cgroup: None,
                    tracked: Vec::new(),
                    started_at: now(),
                    ended_at: None,
                };
                Ok(self.state.put_session(lock, &session)?)
            },
        )
    }
}

/// Tests that raise TERM at this process take this first: the flag of every
/// `EndOn` registered then would be set.
#[cfg(test)]
pub(crate) static TERM_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn end_on_sets_the_flag_on_term_and_the_process_lives() {
        let _term = TERM_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let ended = Arc::new(AtomicBool::new(false));
        let _ending = EndOn::new(&ended).unwrap();
        signal_hook::low_level::raise(SIGTERM).unwrap();
        let start = Instant::now();
        while !ended.load(Ordering::Relaxed) {
            assert!(
                start.elapsed() < Duration::from_secs(5),
                "the flag was not set"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
