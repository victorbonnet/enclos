//! `enclos dashboard` (ADR 0040; design §6): a runtime's dashboard, opened
//! to the user running the command, for a sandbox whose listeners the host
//! cannot reach, as a bubblewrap sandbox in a network namespace of its own.
//! The runtime's dashboard runs as a recorded session under the sandbox's
//! policy, its port read from the host as the runtime's service's is
//! (`listener`), and the host's 127.0.0.1 at the sandbox's reserved port is
//! opened to this user alone (`host_listener`), each connection passed to
//! that port through the namespace holder's way in. It lives as long as the
//! command: told to end, it ends the session and the listener and records
//! the end. One runs per sandbox at a time (`lock`).

mod host_listener;
mod lock;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use super::Engine;
use super::launch::EndOn;
use super::listener::{NoPort, in_namespace};
use super::session::{SessionEnd, exit_code};
use super::start::{Started, Starting};
use crate::backend::NamespaceHolder;
use crate::error::{Error, Result};
use crate::model::audit::Actor;
use crate::model::now;
use crate::model::sandbox::{SandboxName, SandboxRecord};
use crate::model::session::SessionId;
use crate::runtime::{RuntimeDashboard, adapter};
use lock::{DashboardLock, Running};

/// How long the dashboard has to listen once its session started: a
/// runtime may build its pages first.
const LISTEN_WAIT: Duration = Duration::from_secs(300);

/// What `enclos dashboard` serves, once it does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DashboardOpen {
    pub sandbox: SandboxName,
    pub session: SessionId,
    /// The sandbox's reserved port, on the host's 127.0.0.1.
    pub port: u16,
    /// The dashboard's page there.
    pub url: String,
    /// The uid it serves alone: the user running it.
    pub user: u32,
}

/// How `enclos dashboard` ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DashboardEnd {
    pub end: SessionEnd,
    /// Why it ended on its own, which is a failure; none when it was told
    /// to end.
    pub failed: Option<String>,
}

impl Engine {
    /// `enclos dashboard`: runs the dashboard of `name`'s runtime as a
    /// session and serves it to this user on the host's 127.0.0.1 at the
    /// sandbox's reserved port, telling `opened` once it does, until told to
    /// end (TERM, INT or HUP), or until the dashboard ends or cannot be
    /// served. Then it closes the listener, ends the session and records
    /// the end.
    pub fn dashboard(
        &self,
        by: &Actor,
        name: &SandboxName,
        opened: &mut dyn FnMut(&DashboardOpen),
    ) -> Result<DashboardEnd> {
        let ended = Arc::new(AtomicBool::new(false));
        let _ending = EndOn::new(&ended)?;
        self.dashboard_until(by, name, &ended, opened)
    }

    pub(super) fn dashboard_until(
        &self,
        by: &Actor,
        name: &SandboxName,
        ended: &AtomicBool,
        opened: &mut dyn FnMut(&DashboardOpen),
    ) -> Result<DashboardEnd> {
        let record = self.record(name)?;
        let (holder, dashboard) = self.dashboard_of(&record)?;
        let url = format!("http://127.0.0.1:{}{}", record.proxy_port, dashboard.page);
        self.layout
            .create_sandbox_run_dir(name.as_str())
            .map_err(|source| crate::layout::LayoutError::Io {
                path: self.layout.sandbox_run_dir(name.as_str()),
                source,
            })?;
        let mut running = Running {
            pid: std::process::id(),
            session: None,
            since: now(),
            url: url.clone(),
        };
        let mut lock =
            DashboardLock::take(&self.layout.dashboard_lock(name.as_str()), name, &running)?;
        self.wait_service_proxy(name)?;
        self.ensure_holder(&record)?;
        let ctx = self.sandbox_context(name, record.proxy_port);
        let way_in = holder.way_in(&ctx);
        way_in.answers().map_err(|e| Error::Dashboard {
            what: format!(
                "the namespace holder of sandbox {name} has no way in from the host ({e}), as one started by an earlier enclos: `enclos sandbox restart {name}` starts it again with the sandbox's sessions and services"
            ),
        })?;
        let held = holder.ask(&ctx).map_err(|why| Error::Dashboard {
            what: format!("the namespace holder of sandbox {name} does not answer: {why}"),
        })?;
        let log = self.dashboard_log(name);
        let command = dashboard.command.into_words();
        let Started {
            session, mut child, ..
        } = self.write(
            by,
            "dashboard",
            Some(name.to_string()),
            |started: &Started<()>| format!("session {}", started.session.id),
            |state| {
                let starting = Starting::Dashboard { log: &log };
                let started = self.start_session(state, name, &command, starting, || Ok(()));
                self.failed_on_error(state, name, "dashboard", started)
            },
        )?;
        running.session = Some(session.id.0);
        // What a second run names; without it, it names this process alone.
        let _ = lock.say(&running);
        crate::notes::say(&format!(
            "waiting for the dashboard of sandbox {name} to listen; its output goes to `enclos logs {name}`…"
        ));

        let user = rustix::process::getuid().as_raw();
        let begun = Instant::now();
        let mut listening = None;
        let mut failed = None;
        let mut look = |_: &mut Vec<String>| {
            if listening.is_some() || failed.is_some() {
                return;
            }
            let why = match in_namespace("dashboard", &session.root, &held) {
                Ok(port) => match host_listener::open(
                    record.proxy_port,
                    user,
                    host_listener::owner_on_host,
                    way_in.clone(),
                    port,
                ) {
                    Ok(serving) => {
                        listening = Some(serving);
                        opened(&DashboardOpen {
                            sandbox: name.clone(),
                            session: session.id,
                            port: record.proxy_port,
                            url: url.clone(),
                            user,
                        });
                        return;
                    }
                    Err(e) => format!(
                        "cannot listen on 127.0.0.1:{}, the sandbox's reserved port: {e}",
                        record.proxy_port
                    ),
                },
                Err(NoPort::NotYet(_) | NoPort::NotRunning(_)) if begun.elapsed() < LISTEN_WAIT => {
                    return;
                }
                Err(NoPort::NotYet(why) | NoPort::NotRunning(why)) => format!(
                    "the dashboard did not listen within {} s ({why}); `enclos logs {name}` shows its output",
                    LISTEN_WAIT.as_secs()
                ),
                Err(NoPort::Refused(why)) => why,
            };
            failed = Some(why);
            ended.store(true, Ordering::Relaxed);
        };
        let waited = self.wait_session(&session, &mut child, Some(ended), &mut look);
        // Closed before the end is recorded, which may wait for the state.
        drop(listening);
        let waited = match waited {
            Ok(waited) => waited,
            Err(error) => return Err(self.record_unended(by, "dashboard end", &session, error)),
        };
        let failed = match failed {
            Some(why) => Some(why),
            None if ended.load(Ordering::Relaxed) => None,
            None => Some(format!(
                "the dashboard exited on its own (exit {}); `enclos logs {name}` shows its output",
                exit_code(waited.status)
            )),
        };
        let why = failed.as_deref().unwrap_or("told to end");
        let end = self.finish_session_saying(by, "dashboard end", &session, waited, Some(why))?;
        Ok(DashboardEnd { end, failed })
    }

    /// The namespace holder whose way in reaches `record`'s sandbox, and its
    /// runtime's dashboard, or why `enclos dashboard` has none to serve.
    fn dashboard_of(
        &self,
        record: &SandboxRecord,
    ) -> Result<(&dyn NamespaceHolder, RuntimeDashboard)> {
        let name = &record.name;
        let refused = |what: String| Error::Dashboard { what };
        let holder = self.holder_of(record.backend).ok_or_else(|| {
            refused(format!(
                "sandbox {name} is on {}, whose runtime's listeners the host reaches itself: `enclos status {name}` shows its dashboard's address while its service runs (ADR 0028)",
                record.backend
            ))
        })?;
        let kind = self.runtime_of(name)?;
        let dashboard = adapter(kind).dashboard().ok_or_else(|| {
            refused(format!(
                "{kind}, the runtime of sandbox {name}, has no dashboard"
            ))
        })?;
        Ok((holder, dashboard))
    }
}
