//! The agents the bridge serves, kept in step with enclos's state while it
//! runs (issue #303). Every change of that state is audited, so the audit
//! log grows with each: a thread of the bridge's own looks at it every few
//! seconds, and reads the agents again only once it changed, as reading a
//! token can run a program (the macOS Keychain's `security`), which may
//! take its time. No device's connection waits on it: devices are sent the
//! list again once it changed.
use std::os::unix::fs::MetadataExt as _;
use std::time::{Instant, SystemTime};

use super::*;

#[cfg(test)]
#[path = "served_tests.rs"]
mod tests;

/// How often the bridge looks for a change of enclos's state.
pub(super) const LOOK_EVERY: Duration = Duration::from_millis(if cfg!(test) { 100 } else { 3_000 });

/// How long after a reading that failed, or that could not read a token or
/// a sandbox's policy, or with an audit log that cannot be looked at, the
/// agents are read again with no audited change to say they might be
/// readable now.
const RETRY_UNREAD: Duration = Duration::from_secs(if cfg!(test) { 1 } else { 60 });

/// What one reading of enclos's state found.
pub(super) struct Served {
    /// Each agent with an app channel whose endpoint was read.
    pub(super) agents: Vec<AgentEndpoint>,
    pub(super) left_out: Vec<LeftOut>,
}

/// Agents with an app channel the bridge cannot open now.
#[derive(Clone, PartialEq, Eq)]
pub(super) enum LeftOut {
    /// One agent (`<sandbox>/<agent>`) whose endpoint could not be read.
    Agent {
        agent: String,
        why: String,
        /// It may well be there, but could not be read: a token in a
        /// Keychain that does not answer, say. An agent served already
        /// stays served as it was, rather than leave every device for as
        /// long as that lasts. Otherwise it is gone: a token not set, a
        /// grant dropped.
        unreadable: bool,
    },
    /// Every agent of a sandbox whose policy or runtime could not be read
    /// to tell which they are: unreadable, so kept as served.
    Sandbox { sandbox: String, why: String },
}

impl LeftOut {
    fn unreadable(&self) -> bool {
        match self {
            LeftOut::Agent { unreadable, .. } => *unreadable,
            LeftOut::Sandbox { .. } => true,
        }
    }

    /// Whether this is about `agent` (`<sandbox>/<agent>`).
    fn covers(&self, agent: &str) -> bool {
        match self {
            LeftOut::Agent { agent: left, .. } => left == agent,
            LeftOut::Sandbox { sandbox, .. } => {
                agent.split_once('/').is_some_and(|(of, _)| of == sandbox)
            }
        }
    }

    /// What stderr is told of it: `kept`, whether agents it covers stay
    /// served as they were.
    fn said(&self, kept: bool) -> String {
        let fate = if kept {
            "still served as before"
        } else {
            "left out"
        };
        match self {
            LeftOut::Agent { agent, why, .. } => format!("{agent} {fate}: {why}"),
            LeftOut::Sandbox { sandbox, why } => {
                format!("the agents of sandbox {sandbox} {fate}: {why}")
            }
        }
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
    pub(super) fn new(
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
fn served(engine: &crate::engine::Engine) -> Result<Served, String> {
    use crate::error::Error;
    let listed = engine
        .app_agents()
        .map_err(|e| format!("the agents with an app channel cannot be listed: {e}"))?;
    let mut served = Served {
        agents: Vec::new(),
        left_out: listed
            .unreadable
            .into_iter()
            .map(|(sandbox, why)| LeftOut::Sandbox {
                sandbox: sandbox.to_string(),
                why,
            })
            .collect(),
    };
    for found in listed.agents {
        let name = format!("{}/{}", found.sandbox, found.agent);
        match engine.app_endpoint(&found.sandbox, &found.agent) {
            Ok(endpoint) => served.agents.push(AgentEndpoint {
                name,
                runtime: found.runtime,
                socket: endpoint.socket,
                token: endpoint.token.expose().to_owned(),
            }),
            Err(e) => served.left_out.push(LeftOut::Agent {
                agent: name,
                // Gone as the user left it: the sandbox removed meanwhile,
                // the grant dropped (`Session`: no app channel), the token
                // not set. Anything else is enclos's state or the secret
                // store failing to answer, which may pass.
                unreadable: !matches!(
                    e,
                    Error::NoSuchSandbox { .. }
                        | Error::NoPolicy { .. }
                        | Error::SecretMissing { .. }
                        | Error::Session { .. }
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

/// The mark of the file at `path`: none while there is no file (enclos not
/// set up yet), an error when it cannot be looked at.
fn mark(path: &Path) -> Result<Option<Mark>, String> {
    match std::fs::metadata(path) {
        Ok(metadata) => Ok(Some(Mark {
            device: metadata.dev(),
            inode: metadata.ino(),
            len: metadata.len(),
            modified: metadata.modified().ok(),
        })),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

/// An [`AgentSource`], what it gave first, and what the bridge saw of it
/// last.
pub struct AgentWatch {
    source: AgentSource,
    /// The agents of the first reading, which the bridge starts with.
    first: Vec<AgentEndpoint>,
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
    /// Why the agents could not be listed, or served, last, as said.
    failed: Option<String>,
    /// Why the changes file could not be looked at last, as said: the
    /// agents are then read again every [`RETRY_UNREAD`].
    blind: Option<String>,
}

impl AgentWatch {
    /// Reads `source` a first time: the watch, whose [`AgentWatch::agents`]
    /// the bridge starts with, or why they cannot be listed.
    pub fn start(source: AgentSource) -> Result<AgentWatch, String> {
        // Marked before reading: a change made meanwhile is read again.
        let mut seen = Seen {
            mark: None,
            read_at: Instant::now(),
            unread: false,
            said: Vec::new(),
            failed: None,
            blind: None,
        };
        seen.mark = seen.look(&source.changes);
        let served = (source.read)()?;
        let first = seen.take(served, &[]);
        Ok(AgentWatch {
            source,
            first,
            seen: Mutex::new(seen),
        })
    }

    /// The agents the first reading found.
    pub fn agents(&self) -> &[AgentEndpoint] {
        &self.first
    }
}

impl Seen {
    /// The changes file's mark now; says once on stderr that it cannot be
    /// looked at, and when it can again.
    fn look(&mut self, changes: &Path) -> Option<Mark> {
        match mark(changes) {
            Ok(mark) => {
                if self.blind.take().is_some() {
                    eprintln!("enclos app: the audit log can be looked at again");
                }
                mark
            }
            Err(why) => {
                if self.blind.as_ref() != Some(&why) {
                    eprintln!(
                        "enclos app: the audit log cannot be looked at, so the agents are read again every {} s: {why}",
                        RETRY_UNREAD.as_secs()
                    );
                }
                self.blind = Some(why);
                None
            }
        }
    }

    /// Whether to read again: the changes file changed since (`now`), or
    /// something could not be read or looked at then, a while ago.
    fn due(&self, now: Option<Mark>) -> bool {
        now != self.mark
            || ((self.unread || self.blind.is_some()) && self.read_at.elapsed() >= RETRY_UNREAD)
    }

    /// `why` the agents could not be listed or served, said on stderr
    /// unless it was last time; they are read again after a while.
    fn failed(&mut self, why: String) {
        if self.failed.as_ref() != Some(&why) {
            eprintln!("enclos app: the agents are served as they were: {why}");
        }
        self.failed = Some(why);
        self.unread = true;
    }

    /// The agents to serve from `served`, given those served `now`; says
    /// on stderr each agent left out, when that changed.
    fn take(&mut self, served: Served, now: &[AgentEndpoint]) -> Vec<AgentEndpoint> {
        let Served {
            mut agents,
            left_out,
        } = served;
        let kept = |agent: &AgentEndpoint| {
            left_out
                .iter()
                .any(|left| left.unreadable() && left.covers(&agent.name))
        };
        for agent in now.iter().filter(|a| kept(a)) {
            if !agents.iter().any(|a| a.name == agent.name) {
                agents.push(agent.clone());
            }
        }
        if left_out != self.said {
            for left in &left_out {
                let kept = left.unreadable() && now.iter().any(|a| left.covers(&a.name));
                eprintln!("enclos app: {}", left.said(kept));
            }
        }
        self.unread = left_out.iter().any(LeftOut::unreadable);
        self.said = left_out;
        sorted(agents)
    }
}

/// `agents` by name, the one order the bridge keeps them in, so that two
/// lists of the same agents compare equal.
pub(super) fn sorted(mut agents: Vec<AgentEndpoint>) -> Vec<AgentEndpoint> {
    agents.sort_by(|a, b| a.name.cmp(&b.name));
    agents
}

impl Hub {
    /// The hub, serving `watch`'s first agents, then reading them again
    /// as enclos's state changes ([`Hub::refresh_agents`]).
    pub(super) fn with_agent_watch(self, watch: AgentWatch) -> Hub {
        Hub {
            agents: RwLock::new(Arc::new(sorted(watch.first.clone()))),
            watch: Some(watch),
            ..self
        }
    }

    /// Reads the agents again if enclos's state changed since they were
    /// last read, or if something could not be read then and
    /// [`RETRY_UNREAD`] has passed since, and serves them
    /// ([`Hub::serve_agents`]). A reading that fails changes nothing: the
    /// agents stay served as they were, and are read again later.
    pub(super) fn refresh_agents(self: &Arc<Hub>) {
        let Some(watch) = &self.watch else {
            return;
        };
        // A reading that panicked left nothing half done in it.
        let mut seen = watch
            .seen
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let now = seen.look(&watch.source.changes);
        if !seen.due(now) {
            return;
        }
        seen.mark = now;
        seen.read_at = Instant::now();
        let served = match (watch.source.read)() {
            Ok(served) => served,
            Err(why) => return seen.failed(why),
        };
        let agents = seen.take(served, &self.agents());
        match self.serve_agents(agents) {
            Ok(()) => {
                if seen.failed.take().is_some() {
                    eprintln!("enclos app: the agents are read and served again");
                }
            }
            Err(why) => seen.failed(why),
        }
    }

    /// Serves `agents` from now on, in place of those served. An agent no
    /// longer among them, or whose socket or token changed, has its plugin
    /// connection ended: one removed goes as an agent the bridge does not
    /// serve, one changed is opened again with its new endpoint. A new one
    /// gets its Home. Each connected device is sent the agents' list again.
    /// `Err`, with nothing changed, when the bridge's database cannot be
    /// opened to do so.
    pub(super) fn serve_agents(self: &Arc<Hub>, agents: Vec<AgentEndpoint>) -> Result<(), String> {
        let agents = sorted(agents);
        let before = self.agents();
        if *before == agents {
            return Ok(());
        }
        // Before anything changes: without it, no Home is made and no
        // device told, and the next pass would find nothing to change.
        let store = self.store()?;
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
        // change itself (`Hub::plugin`). Its reader ends as with any closed
        // connection: what it was doing ends, its turns fail, and it leaves
        // `plugins`. A shutdown does not wait, so it is done locked.
        {
            let plugins = self.plugins.lock().expect("not poisoned");
            for plugin in changed.iter().filter_map(|agent| plugins.get(agent)) {
                plugin.closer.shutdown();
            }
        }
        // An agent no longer served is a stranger to this run again: if it
        // comes back, a channel that answered before is not remembered as
        // having answered in this run (#376).
        if !removed.is_empty() {
            let mut answered = self.answered.lock().expect("not poisoned");
            for agent in &removed {
                answered.remove(agent);
            }
        }
        for (agents, event) in [
            (&added, "agent served"),
            (&removed, "agent no longer served"),
        ] {
            for agent in agents {
                eprintln!("enclos app: {event}: {agent}");
                if let Err(e) = store.log(None, None, event, Some(agent)) {
                    eprintln!("enclos app: {event}: {agent}: not in the bridge's log: {e}");
                }
            }
        }
        for agent in changed.iter().filter(|a| !removed.contains(a)) {
            eprintln!(
                "enclos app: {agent}'s app channel changed: it is opened again with its new endpoint"
            );
        }
        self.ensure_homes(&store);
        self.deliver_agents(&store);
        self.open_plugins();
        Ok(())
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
