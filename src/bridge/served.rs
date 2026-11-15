//! The agents the bridge serves, kept in step with enclos's state while it
//! runs (issue #303). Every change of that state is audited, so the audit
//! log grows with each: a thread of the bridge's own looks at it every few
//! seconds, and reads the agents again only once it changed, as reading a
//! token can run a program (the macOS Keychain's `security`), which may
//! take its time. No device's session waits on it: devices are sent the
//! list again once it changed.
use std::os::unix::fs::MetadataExt as _;
use std::time::{Instant, SystemTime};

use super::*;

#[cfg(test)]
#[path = "served_tests.rs"]
mod tests;

/// How often agents left out for a token that could not be read, or all of
/// them when they could not be listed, are read again with no change of
/// state to say they might be readable now.
const RETRY_UNREAD: Duration = Duration::from_secs(if cfg!(test) { 1 } else { 60 });

/// What one reading of enclos's state found.
pub struct Served {
    /// Each agent with an app channel whose endpoint was read.
    pub agents: Vec<AgentEndpoint>,
    pub left_out: Vec<LeftOut>,
}

/// An agent with an app channel the bridge cannot open now.
#[derive(Clone, PartialEq, Eq)]
pub struct LeftOut {
    /// `<sandbox>/<agent>`; or `<sandbox>` alone for each of its agents,
    /// when its policy could not be read to tell which they are.
    pub agent: String,
    pub why: String,
    /// It could not be read, though it may well be there: a token in a
    /// Keychain that does not answer, a policy that cannot be read. An
    /// agent served already stays served as it was, rather than leave
    /// every device for as long as that lasts.
    pub unreadable: bool,
}

impl LeftOut {
    /// Whether this is about `agent` (`<sandbox>/<agent>`).
    fn covers(&self, agent: &str) -> bool {
        agent == self.agent
            || agent
                .split_once('/')
                .is_some_and(|(sandbox, _)| sandbox == self.agent)
    }
}

/// Where the bridge learns which agents it serves.
pub struct AgentSource {
    /// A file that changes with every change of enclos's state.
    changes: PathBuf,
    /// The agents as enclos's state has them now; `Err` when they cannot
    /// be listed at all.
    read: Box<dyn Fn() -> Result<Served, String> + Send + Sync>,
}

impl AgentSource {
    pub fn new(
        changes: PathBuf,
        read: impl Fn() -> Result<Served, String> + Send + Sync + 'static,
    ) -> AgentSource {
        AgentSource {
            changes,
            read: Box::new(read),
        }
    }

    /// The agents of enclos's state at `layout`: every agent whose active
    /// policy grants it an app channel token, read through an engine opened
    /// for each reading; changed with the audit log.
    pub fn of_state(layout: crate::layout::Layout) -> AgentSource {
        AgentSource::new(layout.audit_log(), move || {
            served(&crate::engine::Engine::open(
                layout.clone(),
                crate::state::Wait::Background,
            ))
        })
    }
}

/// The agents `engine`'s state gives an app channel, with their endpoints.
pub fn served(engine: &crate::engine::Engine) -> Result<Served, String> {
    let mut served = Served {
        agents: Vec::new(),
        left_out: Vec::new(),
    };
    let listed = engine
        .app_agents()
        .map_err(|e| format!("the agents with an app channel cannot be listed: {e}"))?;
    for (sandbox, why) in listed.unreadable {
        served.left_out.push(LeftOut {
            agent: sandbox.to_string(),
            why: format!("its policy cannot be read: {why}"),
            unreadable: true,
        });
    }
    for (sandbox, agent, runtime) in listed.agents {
        let name = format!("{sandbox}/{agent}");
        match engine.app_endpoint(&sandbox, &agent) {
            Ok(endpoint) => served.agents.push(AgentEndpoint {
                name,
                runtime,
                socket: endpoint.socket,
                token: endpoint.token.expose().to_owned(),
            }),
            Err(e) => served.left_out.push(LeftOut {
                agent: name,
                // The secret store or enclos's state failing to answer; a
                // secret not set, or a grant or sandbox gone meanwhile, is
                // as the user left it.
                unreadable: matches!(
                    e,
                    crate::error::Error::Secret(_)
                        | crate::error::Error::SecretsLocked { .. }
                        | crate::error::Error::State(_)
                ),
                why: e.to_string(),
            }),
        }
    }
    Ok(served)
}

/// Which version of a file: told apart by its identity, size and time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Mark {
    device: u64,
    inode: u64,
    len: u64,
    modified: Option<SystemTime>,
}

fn mark(path: &Path) -> Option<Mark> {
    let metadata = std::fs::metadata(path).ok()?;
    Some(Mark {
        device: metadata.dev(),
        inode: metadata.ino(),
        len: metadata.len(),
        modified: metadata.modified().ok(),
    })
}

/// An [`AgentSource`], and what the bridge saw of it last.
pub struct AgentWatch {
    source: AgentSource,
    /// Held through a reading and its change of the hub: one at a time,
    /// so that an older reading never replaces a newer one.
    seen: Mutex<Seen>,
}

struct Seen {
    /// The changes file when last read.
    mark: Option<Mark>,
    read_at: Instant,
    /// Whether something could not be read then, to read again after
    /// [`RETRY_UNREAD`].
    unread: bool,
    /// What was said on stderr of the agents left out, not said again
    /// while it stays the same.
    said: Vec<LeftOut>,
}

impl AgentWatch {
    /// Reads `source` a first time: the agents to serve, the watch to
    /// serve them with, or why they cannot be listed.
    pub fn start(source: AgentSource) -> Result<(AgentWatch, Vec<AgentEndpoint>), String> {
        // Marked before reading: a change made meanwhile is read again.
        let mark = mark(&source.changes);
        let served = (source.read)()?;
        let mut seen = Seen {
            mark,
            read_at: Instant::now(),
            unread: false,
            said: Vec::new(),
        };
        let agents = seen.take(served, &[]);
        Ok((
            AgentWatch {
                source,
                seen: Mutex::new(seen),
            },
            agents,
        ))
    }
}

impl Seen {
    /// The agents to serve from `served`, given those served `now`; says
    /// on stderr each agent left out, when that changed.
    fn take(&mut self, served: Served, now: &[AgentEndpoint]) -> Vec<AgentEndpoint> {
        let Served {
            mut agents,
            left_out,
        } = served;
        for kept in now.iter().filter(|a| {
            left_out
                .iter()
                .any(|left| left.unreadable && left.covers(&a.name))
        }) {
            if !agents.iter().any(|a| a.name == kept.name) {
                agents.push(kept.clone());
            }
        }
        if left_out != self.said {
            for left in &left_out {
                let kept = if left.unreadable && now.iter().any(|a| left.covers(&a.name)) {
                    "still served as before"
                } else {
                    "left out"
                };
                eprintln!("enclos app: {} {kept}: {}", left.agent, left.why);
            }
        }
        self.unread = left_out.iter().any(|left| left.unreadable);
        self.said = left_out;
        agents.sort_by(|a, b| a.name.cmp(&b.name));
        agents
    }
}

impl Hub {
    /// The hub, reading its agents again from `watch` as enclos's state
    /// changes ([`Hub::refresh_agents`]).
    pub(super) fn with_agent_watch(self, watch: AgentWatch) -> Hub {
        Hub {
            watch: Some(watch),
            ..self
        }
    }

    /// Reads the agents again if enclos's state changed since they were
    /// last read, or something could not be read then, and serves them
    /// ([`Hub::serve_agents`]). A reading that fails changes nothing: the
    /// agents stay served as they were, and are read again later.
    pub(super) fn refresh_agents(self: &Arc<Hub>) {
        let Some(watch) = &self.watch else {
            return;
        };
        let mut seen = watch.seen.lock().expect("not poisoned");
        let now = mark(&watch.source.changes);
        let retry = seen.unread && seen.read_at.elapsed() >= RETRY_UNREAD;
        if now == seen.mark && !retry {
            return;
        }
        seen.mark = now;
        seen.read_at = Instant::now();
        match (watch.source.read)() {
            Ok(served) => {
                let agents = seen.take(served, &self.agents());
                self.serve_agents(agents);
            }
            Err(why) => {
                if !seen.unread {
                    eprintln!("enclos app: the agents are served as they were: {why}");
                }
                seen.unread = true;
            }
        }
    }

    /// Serves `agents` from now on, in place of those served. An agent no
    /// longer among them, or whose socket or token changed, has its plugin
    /// connection ended: one removed goes as an agent the bridge does not
    /// serve, one changed is opened again with its new endpoint. A new one
    /// gets its Home. Each connected device is sent the agents' list again.
    pub(super) fn serve_agents(self: &Arc<Hub>, mut agents: Vec<AgentEndpoint>) {
        agents.sort_by(|a, b| a.name.cmp(&b.name));
        let before = self.agents();
        if *before == agents {
            return;
        }
        let changed: Vec<String> = before
            .iter()
            .filter(|old| !agents.contains(old))
            .map(|old| old.name.clone())
            .collect();
        let added: Vec<String> = agents
            .iter()
            .filter(|new| !before.iter().any(|old| old.name == new.name))
            .map(|new| new.name.clone())
            .collect();
        let removed: Vec<String> = before
            .iter()
            .filter(|old| !agents.iter().any(|new| new.name == old.name))
            .map(|old| old.name.clone())
            .collect();
        *self.agents.write().expect("not poisoned") = Arc::new(agents);
        // After the change, with `plugins` locked: a connection still being
        // opened with an old endpoint either is found here, or finds the
        // change itself (`Hub::plugin`).
        // Its reader ends as with any closed connection: what it was doing
        // ends, its turns fail, and it leaves `plugins`. A shutdown does
        // not wait, so it is done with `plugins` locked.
        {
            let plugins = self.plugins.lock().expect("not poisoned");
            for plugin in changed.iter().filter_map(|agent| plugins.get(agent)) {
                plugin.closer.shutdown();
            }
        }
        let store = self.store();
        for (agents, event) in [
            (&added, "agent served"),
            (&removed, "agent no longer served"),
        ] {
            for agent in agents {
                eprintln!("enclos app: {event}: {agent}");
                if let Ok(store) = &store {
                    let _ = store.log(None, None, event, Some(agent));
                }
            }
        }
        for agent in changed.iter().filter(|a| !removed.contains(a)) {
            eprintln!("enclos app: {agent}'s app channel changed: its connection opens again");
        }
        if let Ok(store) = &store {
            self.ensure_homes(store);
            self.deliver_agents(store);
        }
        self.open_plugins();
    }

    /// Sends each connected device the agents' list again, as it would be
    /// answered asking for it.
    fn deliver_agents(&self, store: &Store) {
        let people: HashSet<String> = self
            .devices
            .lock()
            .expect("not poisoned")
            .values()
            .map(|(person, _, _)| person.clone())
            .collect();
        for person in people {
            match self.agents_answer(store, &person) {
                Ok(Ok(answer)) => {
                    for message in answer {
                        self.deliver(&person, message);
                    }
                }
                // The device has the list it had; it asks again when it
                // connects again.
                Ok(Err(why)) | Err(why) => {
                    eprintln!("enclos app: the agents' list not sent again to {person}: {why}")
                }
            }
        }
    }
}
