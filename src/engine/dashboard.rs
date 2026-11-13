//! `enclos dashboard` (ADR 0040; design §6): a runtime's dashboard, opened
//! to the user running the command. Linux uses its namespace relay;
//! macOS inherits a host-bound private Unix listener (ADR 0063, proposed).
//! The runtime's dashboard runs as a recorded session under the sandbox's
//! policy, its port read from the host as the runtime's service's is
//! (`listener`), and the host's 127.0.0.1 at the sandbox's reserved port is
//! opened to this user alone (`host_listener`), each connection passed to
//! that port through the namespace holder's way in. It lives as long as the
//! command: told to end, it ends the session and the listener and records
//! the end. One runs per sandbox at a time (`lock`).

mod host_listener;
mod http;
mod local;
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
use crate::runtime::{RuntimeAdapter, RuntimeDashboard, adapter};
use local::Local;
use lock::{DashboardLock, Running};

/// How long the dashboard has to listen once its session started: a
/// runtime may build its pages first.
const LISTEN_WAIT: Duration = Duration::from_secs(300);

/// What `enclos dashboard` serves, once it does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DashboardOpen {
    pub sandbox: SandboxName,
    pub session: SessionId,
    /// A host loopback port: the sandbox's reserved proxy-range port on
    /// Linux, a kernel-chosen port outside that range on macOS.
    pub port: u16,
    /// The host-verified URL. On macOS its random path is a credential.
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
        let runtime = adapter(self.runtime_of(name)?);
        let (holder, dashboard) = self.dashboard_of(
            &record,
            runtime.as_ref(),
            &super::listener::HostServices::default(),
        )?;
        let mut url = format!("http://127.0.0.1:{}{}", record.proxy_port, dashboard.page);
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
        };
        let mut lock =
            DashboardLock::take(&self.layout.dashboard_lock(name.as_str()), name, &running)?;
        let mut local = match holder {
            None => Some(Local::prepare(
                self,
                name,
                dashboard.socket.clone().ok_or_else(|| Error::Dashboard {
                    what: "this runtime has no dashboard on a private Unix socket".into(),
                })?,
            )?),
            Some(_) => None,
        };
        if let Some(local) = &local {
            url = format!(
                "http://127.0.0.1:{}{}{}",
                local.port,
                local.prefix,
                dashboard.page.trim_start_matches('/')
            );
        }
        self.wait_service_proxy(name)?;
        let namespace = if let Some(holder) = holder {
            self.ensure_holder(&record)?;
            let ctx = self.sandbox_context(name, record.proxy_port);
            let way_in = holder.way_in(&ctx);
            way_in.answers().map_err(|e| Error::Dashboard {
                what: format!(
                    "the namespace holder of sandbox {name} has no way in from the host ({e}): `enclos sandbox restart {name}` starts it again"
                ),
            })?;
            let held = holder.ask(&ctx).map_err(|why| Error::Dashboard {
                what: format!("the namespace holder of sandbox {name} does not answer: {why}"),
            })?;
            Some((way_in, held))
        } else {
            None
        };
        // Told to end while the proxy or the namespace holder started.
        if ended.load(Ordering::Relaxed) {
            return Err(Error::Dashboard {
                what: format!("told to end before the dashboard of sandbox {name} started"),
            });
        }
        let log = self.dashboard_log(name);
        let command = local
            .as_ref()
            .map(|local| local.command.clone())
            .unwrap_or(dashboard.command);
        let (command, reads) = command.into_parts();
        let Started {
            session, mut child, ..
        } = self.write(
            by,
            "dashboard",
            Some(name.to_string()),
            |started: &Started<()>| format!("session {}", started.session.id),
            |state| {
                let starting = Starting::Dashboard {
                    log: &log,
                    listener: local.as_ref().map(|local| &local.listener),
                    reads: &reads,
                };
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
            let serving = if let Some(local) = &mut local {
                if !local.ready() {
                    if begun.elapsed() < LISTEN_WAIT {
                        return;
                    }
                    Err(format!(
                        "the private dashboard did not answer within {} s; `enclos logs {name}` shows its output",
                        LISTEN_WAIT.as_secs()
                    ))
                } else {
                    host_listener::open_local(
                        local.front.take().expect("opened once"),
                        user,
                        host_listener::owner_on_host,
                        local.socket.clone(),
                        local.prefix.clone(),
                    )
                    .map_err(|e| format!("cannot serve the private dashboard: {e}"))
                }
            } else {
                let (way_in, held) = namespace.as_ref().expect("a namespace or a private socket");
                match in_namespace("dashboard", &session.root, held) {
                    Ok(port) => host_listener::open(
                        record.proxy_port,
                        user,
                        host_listener::owner_on_host,
                        way_in.clone(),
                        port,
                    )
                    .map_err(|e| {
                        format!(
                            "cannot listen on 127.0.0.1:{}, the sandbox's reserved port: {e}",
                            record.proxy_port
                        )
                    }),
                    Err(NoPort::NotYet(_) | NoPort::NotRunning(_))
                        if begun.elapsed() < LISTEN_WAIT =>
                    {
                        return;
                    }
                    Err(why) => Err(format!(
                        "the dashboard did not listen: {why}; `enclos logs {name}` shows its output"
                    )),
                }
            };
            let why = match serving {
                Ok(serving) => {
                    listening = Some(serving);
                    let port = local.as_ref().map_or(record.proxy_port, |local| local.port);
                    opened(&DashboardOpen {
                        sandbox: name.clone(),
                        session: session.id,
                        port,
                        url: url.clone(),
                        user,
                    });
                    return;
                }
                Err(why) => why,
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
    pub(super) fn dashboard_of(
        &self,
        record: &SandboxRecord,
        runtime: &dyn RuntimeAdapter,
        services: &super::listener::HostServices,
    ) -> Result<(Option<&dyn NamespaceHolder>, RuntimeDashboard)> {
        let name = &record.name;
        let refused = |what: String| Error::Dashboard { what };
        let holder = self.holder_of(record.backend);
        let kind = runtime.kind();
        if holder.is_none() && record.state != crate::model::sandbox::SandboxState::Running {
            return Err(refused(format!(
                "sandbox {name} is not running: run `enclos sandbox start {name}` first"
            )));
        }
        if holder.is_none() {
            let installed = runtime.runtime_facts().install.ok_or_else(|| {
                refused(format!(
                    "cannot verify that {kind} is installed in sandbox {name}"
                ))
            })?;
            match crate::runtime::home::stat(&self.sandbox_home(name), &installed) {
                Ok(Some(_)) => {}
                Ok(None) => {
                    return Err(refused(format!(
                        "{kind}'s files are missing: run `enclos runtime install {kind} --sandbox {name}` first"
                    )));
                }
                Err(why) => {
                    return Err(refused(format!(
                        "cannot verify {kind}'s files in sandbox {name}: {why}"
                    )));
                }
            }
        }
        let dashboard = runtime.dashboard().ok_or_else(|| {
            refused(format!(
                "{kind}, the runtime of sandbox {name}, has no dashboard"
            ))
        })?;
        if holder.is_none()
            && (record.backend != crate::model::sandbox::BackendKind::Seatbelt
                || dashboard.socket.is_none())
        {
            return Err(refused(format!(
                "{kind} has no protected dashboard transport on {}",
                record.backend
            )));
        }
        if holder.is_none() {
            match services.port(self.state.as_ref(), record) {
                Ok(Some(_)) => {}
                Ok(None) => {
                    return Err(refused(format!(
                        "the runtime service of sandbox {name} is not listening"
                    )));
                }
                Err(why) => {
                    return Err(refused(format!(
                        "the runtime service of sandbox {name} is not ready: {why}"
                    )));
                }
            }
        }
        Ok((holder, dashboard))
    }
}
