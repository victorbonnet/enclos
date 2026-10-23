//! `enclos status`: what is on this host, what it costs on disk, and what
//! the user could do about it (issue #29). A read: no lock, no audit
//! entry, and nothing runs in a sandbox, so it works on stopped ones.
//!
//! Facts come from enclos's own records (trusted), from the service
//! manager, and from the sandbox home, which the sandbox writes. The
//! runtime adapter only names paths; every read of the home goes through
//! descriptors that never follow a link (`runtime::home`, ADR 0023), sizes
//! and counts are bounded, and "cannot tell", with why, is an answer.

mod printable;

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::ffi::{CString, OsStr};
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use rustix::fs::{AtFlags, Dir, FileType, Mode, OFlags, Stat};
use rustix::io::Errno;
use serde::{Serialize, Serializer};

use super::Engine;
use super::listener::{NoPort, outside_proxy_range, service_listener};
use super::sandbox::{compile_refused, needs_restart};
use super::session::marked_in;
use crate::error::{Error, Result};
use crate::lifecycle::listeners::tcp_listeners_of;
use crate::lifecycle::members::{find, is_gone};
use crate::lifecycle::process::{Proc, is_same, processes};
use crate::model::Timestamp;
use crate::model::agent::AgentName;
use crate::model::net::Reason;
use crate::model::now;
use crate::model::runtime::RuntimeKind;
use crate::model::sandbox::{SandboxName, SandboxRecord, SandboxState};
use crate::model::session::{ProcessRef, SessionKind, SessionRecord};
use crate::runtime::home::{self, is_dot, wide};
use crate::runtime::{
    DiskPart, HomePath, RuntimeAdapter, RuntimeAgentName, RuntimeListener, ValueAt, adapter,
};
use crate::service::ServiceStatus;
use crate::state::StateStore;
use printable::printable;
pub use printable::printable_line;

/// Past this, a sandbox nobody used is worth a suggestion.
pub const IDLE_DAYS: i64 = 30;
/// How far back refused destinations count.
const REFUSED_DAYS: i64 = 7;
/// The most entries the walker reads in one sandbox before it stops and
/// says its sizes are lower bounds.
const MAX_ENTRIES: usize = 1_000_000;
/// The largest file of the sandbox home read for a fact.
const MAX_FACT_FILE: u64 = 256 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StatusView {
    /// The enclos data folder.
    pub data: PathBuf,
    pub sandboxes: Vec<SandboxStatus>,
    /// Sandboxes enclos could not look at, with why; the others still show.
    pub unlisted: Vec<Unlisted>,
    pub suggestions: Vec<Suggestion>,
    /// Every sandbox folder together, in bytes.
    pub bytes: u64,
    /// `false`: some sandbox's walk did not see everything, or a sandbox is
    /// unlisted, so `bytes` is a lower bound.
    pub complete: bool,
    /// Days without use after which a sandbox is suggested for removal.
    pub idle_days: i64,
}

impl StatusView {
    /// The agents in every sandbox: tracked, or built into their runtime.
    pub fn agent_count(&self) -> usize {
        self.agents().filter(|a| !a.kind.is_untracked()).count()
    }

    /// The agents the runtimes have and enclos does not track: untracked
    /// agents, and those under a name enclos cannot track.
    pub fn untracked_count(&self) -> usize {
        self.agents().filter(|a| a.kind.is_untracked()).count()
    }

    fn agents(&self) -> impl Iterator<Item = &AgentStatus> {
        self.sandboxes
            .iter()
            .flat_map(|s| s.agents.iter().flat_map(|l| &l.agents))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Unlisted {
    #[serde(serialize_with = "as_text")]
    pub name: SandboxName,
    pub error: String,
}

/// A fact enclos looked for: what it found, or why it has no answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Fact<T> {
    Known(T),
    /// Where to look is known, and nothing is there.
    Absent,
    /// It could not be read safely, or at all: why (ADR 0023).
    CannotTell(String),
    /// The runtime names nowhere to look.
    NotProvided,
}

impl<T> Fact<T> {
    pub fn known(&self) -> Option<&T> {
        match self {
            Fact::Known(v) => Some(v),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SandboxStatus {
    #[serde(serialize_with = "as_text")]
    pub name: SandboxName,
    #[serde(flatten)]
    pub state: SandboxState,
    pub created_at: Timestamp,
    pub runtime: Option<RuntimeStatus>,
    /// The sandbox's installed services, with the state the service
    /// manager reports.
    pub services: Fact<Vec<ServiceLine>>,
    pub policy_version: Option<u32>,
    /// Running sessions, the proxy's included.
    pub running_sessions: usize,
    /// Sessions of which nothing runs any more, as after a crash or a
    /// restart of the Mac, whose end is not recorded: a read records
    /// nothing, and `sandbox stop` or `sandbox rm` does.
    pub gone_sessions: usize,
    /// Some running session started under a compiled policy the active one
    /// replaced: it needs a restart to run under it. The proxy applies
    /// network rules live and never does.
    pub restart_needed: bool,
    /// Why enclos now refuses to compile the active policy, if it does:
    /// nothing new starts in the sandbox until the user fixes it.
    pub policy_refused: Option<String>,
    /// When a `connect` last started.
    pub last_connect: Option<Timestamp>,
    /// When the sandbox last tried a connection, allowed or refused.
    pub last_network: Option<Timestamp>,
    /// The latest of: its creation, a `connect` or service session starting
    /// or ending, and a connection tried. The proxy alone does not count.
    pub last_used: Timestamp,
    /// Destinations refused in the last 7 days, leaving out refusals that
    /// left nothing to allow.
    pub refused_recently: usize,
    /// The last refusal, within the last 7 days, because the proxy could
    /// not read the sandbox's policy.
    pub policy_unreadable_at: Option<Timestamp>,
    /// `None` when the sandbox has no runtime.
    pub agents: Option<AgentList>,
    pub disk: Disk,
    /// The address of the page the runtime's service serves on the host,
    /// such as Hermes's dashboard (ADR 0028), at the port sessions are
    /// given: absent while no session of the service runs, "cannot tell"
    /// while it holds no such port or one that cannot be trusted, not
    /// provided for a runtime with no such page.
    pub dashboard: Fact<String>,
    /// Members listening on an address beyond loopback, which the host's
    /// network can reach: nothing narrows a sandbox's listener to loopback
    /// (ADR 0028).
    pub network_listeners: Fact<Vec<NetworkListener>>,
}

/// A member listening where the host's network can reach it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NetworkListener {
    pub pid: u32,
    /// Its command, escaped: the sandbox names it.
    pub command: String,
    /// `*:8000` for every address, or the address it names.
    pub address: String,
}

impl SandboxStatus {
    /// Something of the sandbox runs, or might: a session, a service, or
    /// services the service manager could not report on.
    pub fn in_use(&self) -> bool {
        self.running_sessions > 0
            || match &self.services {
                Fact::Known(list) => list
                    .iter()
                    .any(|s| matches!(s.state, ServiceState::Running { .. })),
                _ => true,
            }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RuntimeStatus {
    #[serde(serialize_with = "as_text")]
    pub kind: RuntimeKind,
    /// The runtime's name as people write it.
    pub name: &'static str,
    pub version: Fact<String>,
    pub logged_in: Fact<bool>,
    /// Whether the runtime's own files are still in the home.
    pub installed: Fact<bool>,
    /// The runtime's own command that logs it in, run through `connect`.
    pub login: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ServiceLine {
    pub label: String,
    /// `proxy`, or the runtime's name for the service.
    pub service: String,
    #[serde(flatten)]
    pub state: ServiceState,
}

impl ServiceLine {
    /// A service as the service manager says it is, the same in `status`
    /// and `sandbox show`.
    pub fn new(label: &crate::service::ServiceLabel, status: ServiceStatus) -> ServiceLine {
        ServiceLine {
            service: label.service().to_owned(),
            label: label.to_string(),
            state: match status {
                ServiceStatus::Running { pid } => ServiceState::Running { pid },
                ServiceStatus::Loaded => ServiceState::Loaded,
                ServiceStatus::NotLoaded => ServiceState::NotLoaded,
            },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ServiceState {
    Running {
        pid: u32,
    },
    /// Loaded, and not running.
    Loaded,
    /// Installed, and the service manager does not have it.
    NotLoaded,
}

/// A runtime's agents in a sandbox.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AgentList {
    pub agents: Vec<AgentStatus>,
    /// Why the runtime's own list could not be read (ADR 0023): then only
    /// the built-in agent and enclos's records are known, and none of them
    /// can be said present or gone.
    pub unreadable: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AgentStatus {
    #[serde(serialize_with = "as_text")]
    pub name: RuntimeAgentName,
    #[serde(flatten)]
    pub kind: AgentKind,
    pub last_active: Fact<Timestamp>,
    pub bytes: Fact<u64>,
    pub model: Fact<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AgentKind {
    /// The runtime's built-in agent: no record, never added or removed.
    Builtin,
    /// enclos has a record of it.
    Tracked { in_runtime: Presence },
    /// The runtime has it and enclos does not track it: `agent add` would.
    Untracked,
    /// The runtime has it under a name that is not a valid agent name.
    Untrackable,
}

impl AgentKind {
    /// Whether enclos has no record of it and it is not built in: what
    /// [`StatusView::untracked_count`] counts, and
    /// [`StatusView::agent_count`] leaves out.
    fn is_untracked(self) -> bool {
        match self {
            AgentKind::Builtin | AgentKind::Tracked { .. } => false,
            AgentKind::Untracked | AgentKind::Untrackable => true,
        }
    }
}

/// Whether the runtime still has a tracked agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Presence {
    Present,
    Gone,
    /// Its list could not be read.
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Disk {
    /// Why the walk did not see everything: then every size here is a
    /// lower bound.
    pub incomplete: Option<String>,
    /// The whole sandbox folder.
    pub total: u64,
    /// Of `total`, hard-linked files that also have links outside the
    /// sandbox folder: removing it does not free them. APFS clones are not
    /// told apart and count in full.
    pub shared: u64,
    /// The parts the adapter names; `None` when it names none.
    pub runtime: Option<u64>,
    pub caches: Option<u64>,
    pub agents: Option<u64>,
    pub other: u64,
}

impl Disk {
    /// What `enclos sandbox rm` frees.
    pub fn frees(&self) -> u64 {
        self.total - self.shared
    }

    /// The field for `part`: every part has one, or this does not compile.
    fn part_mut(&mut self, part: DiskPart) -> &mut Option<u64> {
        match part {
            DiskPart::Runtime => &mut self.runtime,
            DiskPart::Cache => &mut self.caches,
        }
    }
}

/// Something the user could do, each with the existing command that does
/// it. enclos never acts on its own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Suggestion {
    AdoptAgent {
        sandbox: SandboxName,
        agent: AgentName,
    },
    RemoveGoneAgent {
        sandbox: SandboxName,
        agent: AgentName,
    },
    LookAtAgents {
        sandbox: SandboxName,
        runtime: &'static str,
        why: String,
    },
    ReviewRefused {
        sandbox: SandboxName,
        refused: usize,
    },
    LookAtProxy {
        sandbox: SandboxName,
        last: Timestamp,
    },
    Restart {
        sandbox: SandboxName,
    },
    InstallRuntime {
        sandbox: SandboxName,
    },
    Reinstall {
        sandbox: SandboxName,
        runtime: RuntimeKind,
    },
    LogIn {
        sandbox: SandboxName,
        runtime: &'static str,
        login: String,
    },
    AddFirstAgent {
        sandbox: SandboxName,
    },
    RemoveIdle {
        sandbox: SandboxName,
        idle_days: i64,
        frees: u64,
        complete: bool,
    },
}

impl Suggestion {
    /// A name for the rule, for `--json`.
    pub fn kind(&self) -> &'static str {
        match self {
            Suggestion::AdoptAgent { .. } => "adopt_agent",
            Suggestion::RemoveGoneAgent { .. } => "remove_gone_agent",
            Suggestion::LookAtAgents { .. } => "look_at_agents",
            Suggestion::ReviewRefused { .. } => "review_refused",
            Suggestion::LookAtProxy { .. } => "look_at_proxy",
            Suggestion::Restart { .. } => "restart",
            Suggestion::InstallRuntime { .. } => "install_runtime",
            Suggestion::Reinstall { .. } => "reinstall",
            Suggestion::LogIn { .. } => "log_in",
            Suggestion::AddFirstAgent { .. } => "add_first_agent",
            Suggestion::RemoveIdle { .. } => "remove_idle",
        }
    }

    fn sandbox(&self) -> &SandboxName {
        match self {
            Suggestion::AdoptAgent { sandbox, .. }
            | Suggestion::RemoveGoneAgent { sandbox, .. }
            | Suggestion::LookAtAgents { sandbox, .. }
            | Suggestion::ReviewRefused { sandbox, .. }
            | Suggestion::LookAtProxy { sandbox, .. }
            | Suggestion::Restart { sandbox }
            | Suggestion::InstallRuntime { sandbox }
            | Suggestion::Reinstall { sandbox, .. }
            | Suggestion::LogIn { sandbox, .. }
            | Suggestion::AddFirstAgent { sandbox }
            | Suggestion::RemoveIdle { sandbox, .. } => sandbox,
        }
    }

    /// `lab` or `lab/writer`.
    pub fn target(&self) -> String {
        match self {
            Suggestion::AdoptAgent { sandbox, agent }
            | Suggestion::RemoveGoneAgent { sandbox, agent } => format!("{sandbox}/{agent}"),
            other => other.sandbox().to_string(),
        }
    }

    pub fn reason(&self) -> String {
        match self {
            Suggestion::AdoptAgent { .. } => "made inside the sandbox, not tracked".into(),
            Suggestion::RemoveGoneAgent { .. } => "the runtime no longer has it".into(),
            Suggestion::LookAtAgents { runtime, why, .. } => {
                format!("enclos cannot read {runtime}'s agents: {why}")
            }
            Suggestion::ReviewRefused { refused, .. } => {
                format!("{refused} destinations refused in the last {REFUSED_DAYS} days")
            }
            Suggestion::LookAtProxy { last, .. } => format!(
                "the proxy could not read the policy and refused every connection, last at {}",
                last.strftime("%Y-%m-%d %H:%M UTC")
            ),
            Suggestion::Restart { .. } => {
                "sessions run under a policy the active one replaced".into()
            }
            Suggestion::InstallRuntime { .. } => "no runtime yet".into(),
            Suggestion::Reinstall { runtime, .. } => {
                format!(
                    "{}'s files are missing from the home",
                    runtime.display_name()
                )
            }
            Suggestion::LogIn { runtime, .. } => format!("{runtime} is not logged in"),
            Suggestion::AddFirstAgent { .. } => "has a runtime but no agents".into(),
            Suggestion::RemoveIdle {
                idle_days,
                frees,
                complete,
                ..
            } => format!(
                "unused for {idle_days} days; removing it frees {}{}",
                if *complete { "" } else { "≥ " },
                human_bytes(*frees)
            ),
        }
    }

    pub fn command(&self) -> String {
        let sb = self.sandbox();
        match self {
            Suggestion::AdoptAgent { agent, .. } => format!("enclos agent add {sb}/{agent}"),
            Suggestion::RemoveGoneAgent { agent, .. } => format!("enclos agent rm {sb}/{agent}"),
            Suggestion::LookAtAgents { .. } => format!("enclos connect {sb}"),
            Suggestion::ReviewRefused { .. } => format!("enclos net denied {sb}"),
            Suggestion::LookAtProxy { .. } => format!("enclos logs {sb}"),
            Suggestion::Restart { .. } => format!("enclos sandbox restart {sb}"),
            Suggestion::InstallRuntime { .. } => {
                format!("enclos runtime install <runtime> --sandbox {sb}")
            }
            Suggestion::Reinstall { runtime, .. } => {
                format!("enclos runtime install {runtime} --sandbox {sb}")
            }
            Suggestion::LogIn { login, .. } => format!("enclos connect {sb} -- {login}"),
            Suggestion::AddFirstAgent { .. } => format!("enclos agent add {sb}/main"),
            Suggestion::RemoveIdle { .. } => format!("enclos sandbox rm {sb}"),
        }
    }
}

/// In `--json`: the rule, and the text the user reads.
impl Serialize for Suggestion {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        struct Shown {
            kind: &'static str,
            target: String,
            reason: String,
            command: String,
        }
        Shown {
            kind: self.kind(),
            target: self.target(),
            reason: self.reason(),
            command: self.command(),
        }
        .serialize(s)
    }
}

impl Engine {
    /// The overview of every sandbox, or of one. A sandbox enclos cannot
    /// look at is listed with why, and the others still show.
    pub fn status(&self, only: Option<&SandboxName>) -> Result<StatusView> {
        let records = match only {
            Some(name) => vec![self.state.get(name)?.ok_or_else(|| Error::NoSuchSandbox {
                name: name.to_string(),
            })?],
            None => self.state.list()?,
        };
        let now = now();
        let mut sandboxes = Vec::new();
        let mut unlisted = Vec::new();
        for record in records {
            let name = record.name.clone();
            let runtime = record.runtime.map(adapter);
            match self.sandbox_status(record, runtime.as_deref(), now) {
                Ok(s) => sandboxes.push(s),
                Err(e) => unlisted.push(Unlisted {
                    name,
                    error: e.to_string(),
                }),
            }
        }
        let suggestions = suggest(&sandboxes, now);
        Ok(StatusView {
            data: self.layout.data().to_owned(),
            bytes: sandboxes.iter().map(|s| s.disk.total).sum(),
            // A sandbox left out is left out of `bytes` too.
            complete: unlisted.is_empty() && sandboxes.iter().all(|s| s.disk.incomplete.is_none()),
            idle_days: IDLE_DAYS,
            sandboxes,
            unlisted,
            suggestions,
        })
    }

    pub(super) fn sandbox_status(
        &self,
        record: SandboxRecord,
        runtime: Option<&dyn RuntimeAdapter>,
        now: Timestamp,
    ) -> Result<SandboxStatus> {
        let name = record.name.clone();
        let dir = self.layout.sandbox_dir(name.as_str());
        let home = self.layout.sandbox_home(name.as_str());
        let active = self.state.active_policy(&name)?.map(|(v, _)| v.version);
        let compiled = self.active_compiled(&record);
        let open = self.state.sessions(&name, true)?;
        // Looked at only when a session is open: most sandboxes have none.
        let procs = match open.is_empty() {
            true => Vec::new(),
            false => processes()?,
        };
        // With what holds each session's marker, its members too (ADR 0030).
        let open: Vec<SessionRecord> = match open.is_empty() {
            true => open,
            false => {
                let held = self.held(&name)?;
                open.into_iter()
                    .map(|mut s| {
                        s.tracked = marked_in(&s, &s.tracked, &procs, &held);
                        s
                    })
                    .collect()
            }
        };
        let (gone, running): (Vec<_>, Vec<_>) = open.into_iter().partition(|s| is_gone(&procs, s));
        let sessions = self.state.sessions(&name, false)?;
        let last_connect = sessions
            .iter()
            .filter(|s| s.kind == SessionKind::Interactive)
            .map(|s| s.started_at)
            .max();
        let last_network = self.state.last_event(&name)?;
        let last_used = last_used(record.created_at, &sessions, last_network);
        let since = now
            .checked_sub(jiff::SignedDuration::from_hours(24 * REFUSED_DAYS))
            .unwrap_or(now);
        let denied: Vec<_> = self
            .state
            .denied(&name)?
            .into_iter()
            .filter(|d| d.last >= since)
            .collect();
        let refused_recently = denied
            .iter()
            .filter(|d| !d.reason.nothing_to_allow())
            .count();
        let policy_unreadable_at = denied
            .iter()
            .filter(|d| d.reason == Reason::PolicyUnreadable)
            .map(|d| d.last)
            .max();
        let services = match self.service_status(&name) {
            Ok(list) => Fact::Known(
                list.into_iter()
                    .map(|(label, status)| ServiceLine::new(&label, status))
                    .collect(),
            ),
            Err(e) => Fact::CannotTell(e.to_string()),
        };

        let agents = runtime
            .map(|rt| self.agent_list(&name, &home, rt))
            .transpose()?;
        let network_listeners = network_listeners(&procs, &running);
        let dashboard = match runtime.and_then(|rt| rt.listener()) {
            Some(listener) => dashboard(self.state.as_ref(), &name, &listener, &running),
            None => Fact::NotProvided,
        };
        let (disk, agent_bytes) = disk_usage(&dir, &home, runtime, agents.as_ref());
        let agents = agents.map(|mut list| {
            for a in &mut list.agents {
                if let Some(bytes) = agent_bytes.get(&a.name) {
                    a.bytes = bytes.clone();
                }
            }
            list
        });

        Ok(SandboxStatus {
            runtime: match (record.runtime, runtime) {
                (Some(kind), Some(rt)) => {
                    let facts = rt.runtime_facts();
                    Some(RuntimeStatus {
                        kind,
                        name: kind.display_name(),
                        version: facts
                            .version
                            .map_or(Fact::NotProvided, |v| read_value(&home, &v)),
                        logged_in: facts.login.map_or(Fact::NotProvided, |f| exists(&home, &f)),
                        installed: facts
                            .install
                            .map_or(Fact::NotProvided, |f| exists(&home, &f)),
                        login: rt.login(),
                    })
                }
                _ => None,
            },
            state: record.state,
            created_at: record.created_at,
            services,
            policy_version: active,
            running_sessions: running.len(),
            gone_sessions: gone.len(),
            restart_needed: running
                .iter()
                .any(|s| needs_restart(s, compiled.as_ref().ok().map(PathBuf::as_path))),
            policy_refused: compile_refused(&compiled),
            last_connect,
            last_network,
            last_used,
            refused_recently,
            policy_unreadable_at,
            agents,
            disk,
            dashboard,
            network_listeners,
            name,
        })
    }

    /// The agents of a sandbox: the runtime's built-in one, enclos's
    /// records, and the runtime's own list, or why it could not be read.
    fn agent_list(
        &self,
        name: &SandboxName,
        home: &Path,
        runtime: &dyn RuntimeAdapter,
    ) -> Result<AgentList> {
        let tracked = self.state.agents(name)?;
        let found = runtime.agents_in(home);
        let builtin = runtime.builtin_agent().map(|b| b.runtime_name());
        let mut names: Vec<RuntimeAgentName> = builtin.iter().cloned().collect();
        for n in tracked
            .iter()
            .map(|t| RuntimeAgentName::from(&t.name))
            .chain(found.iter().flatten().cloned())
        {
            if !names.contains(&n) {
                names.push(n);
            }
        }
        let agents = names
            .into_iter()
            .map(|agent| {
                let listed = found.as_ref().map(|f| f.contains(&agent));
                let kind = if Some(&agent) == builtin.as_ref() {
                    AgentKind::Builtin
                } else if tracked
                    .iter()
                    .any(|t| RuntimeAgentName::from(&t.name) == agent)
                {
                    AgentKind::Tracked {
                        in_runtime: match listed {
                            Ok(true) => Presence::Present,
                            Ok(false) => Presence::Gone,
                            Err(_) => Presence::Unknown,
                        },
                    }
                } else if agent.as_str().parse::<AgentName>().is_ok() {
                    AgentKind::Untracked
                } else {
                    AgentKind::Untrackable
                };
                let facts = runtime.agent_facts(&agent);
                AgentStatus {
                    kind,
                    last_active: newest(home, &facts.activity),
                    model: facts
                        .model
                        .map_or(Fact::NotProvided, |v| read_value(home, &v)),
                    // Filled in from the walk.
                    bytes: Fact::NotProvided,
                    name: agent,
                }
            })
            .collect();
        Ok(AgentList {
            agents,
            unreadable: found.err().map(|why| why.to_string()),
        })
    }
}

/// The latest of: `created`, a `connect` or service session starting or
/// ending, and `last_network`. The proxy alone does not count as use.
pub(super) fn last_used(
    created: Timestamp,
    sessions: &[SessionRecord],
    last_network: Option<Timestamp>,
) -> Timestamp {
    sessions
        .iter()
        .filter(|s| s.kind != SessionKind::Proxy)
        .flat_map(|s| [Some(s.started_at), s.ended_at])
        .flatten()
        .chain(last_network)
        .fold(created, Timestamp::max)
}

/// The sandbox folder's usage, and each agent's own, by the parts and
/// folders the adapter names.
fn disk_usage(
    dir: &Path,
    home: &Path,
    runtime: Option<&dyn RuntimeAdapter>,
    agents: Option<&AgentList>,
) -> (Disk, HashMap<RuntimeAgentName, Fact<u64>>) {
    // Paths as the walker sees them, from the sandbox folder.
    let home_rel = home.strip_prefix(dir).unwrap_or(Path::new("home"));
    let named_parts = runtime.map(|rt| rt.disk_parts()).unwrap_or_default();
    let mut parts: Vec<(PathBuf, Slot)> = named_parts
        .iter()
        .map(|(part, path)| (home_rel.join(path.as_path()), Slot::Part(*part)))
        .collect();
    let mut folders = Vec::new();
    if let (Some(rt), Some(list)) = (runtime, agents) {
        for a in &list.agents {
            if let Some(folder) = rt.agent_facts(&a.name).folder {
                let path = home_rel.join(folder.as_path());
                // A folder that is also a named part counts as that part.
                if !parts.iter().any(|(p, _)| *p == path) {
                    parts.push((path, Slot::Agent(a.name.clone())));
                    folders.push(a.name.clone());
                }
            }
        }
    }
    let usage = walk(dir, &parts, MAX_ENTRIES);
    let named = |slot: &Slot| usage.by_slot.get(slot).copied();
    let mut disk = Disk {
        incomplete: usage.incomplete.clone(),
        total: usage.total,
        shared: usage.shared,
        runtime: None,
        caches: None,
        agents: (!folders.is_empty()).then(|| {
            folders
                .iter()
                .filter_map(|n| named(&Slot::Agent(n.clone())))
                .sum()
        }),
        other: named(&Slot::Other).unwrap_or(0),
    };
    for (part, _) in &named_parts {
        *disk.part_mut(*part) = Some(named(&Slot::Part(*part)).unwrap_or(0));
    }
    let agent_bytes = folders
        .into_iter()
        .map(|n| {
            let bytes = match (named(&Slot::Agent(n.clone())), &usage.incomplete) {
                (Some(b), _) => Fact::Known(b),
                (None, None) => Fact::Absent,
                (None, Some(why)) => Fact::CannotTell(why.clone()),
            };
            (n, bytes)
        })
        .collect();
    (disk, agent_bytes)
}

fn as_text<S: Serializer>(
    value: &impl std::fmt::Display,
    s: S,
) -> std::result::Result<S::Ok, S::Error> {
    s.collect_str(value)
}

/// The rules behind "What you could do". Each names an existing command;
/// enclos never acts on its own, and "unused" uses enclos's own times.
pub fn suggest(sandboxes: &[SandboxStatus], now: Timestamp) -> Vec<Suggestion> {
    let mut out = Vec::new();
    for s in sandboxes {
        let sandbox = || s.name.clone();
        if let Some(list) = &s.agents {
            for a in &list.agents {
                let Ok(agent) = a.name.as_str().parse::<AgentName>() else {
                    continue;
                };
                match a.kind {
                    AgentKind::Untracked => out.push(Suggestion::AdoptAgent {
                        sandbox: sandbox(),
                        agent,
                    }),
                    AgentKind::Tracked {
                        in_runtime: Presence::Gone,
                    } => out.push(Suggestion::RemoveGoneAgent {
                        sandbox: sandbox(),
                        agent,
                    }),
                    _ => {}
                }
            }
            if let (Some(why), Some(rt)) = (&list.unreadable, &s.runtime) {
                out.push(Suggestion::LookAtAgents {
                    sandbox: sandbox(),
                    runtime: rt.name,
                    why: why.clone(),
                });
            }
        }
        if s.refused_recently > 0 {
            out.push(Suggestion::ReviewRefused {
                sandbox: sandbox(),
                refused: s.refused_recently,
            });
        }
        if let Some(last) = s.policy_unreadable_at {
            out.push(Suggestion::LookAtProxy {
                sandbox: sandbox(),
                last,
            });
        }
        if s.restart_needed {
            out.push(Suggestion::Restart { sandbox: sandbox() });
        }
        match &s.runtime {
            None => out.push(Suggestion::InstallRuntime { sandbox: sandbox() }),
            Some(rt) if rt.installed == Fact::Known(false) => out.push(Suggestion::Reinstall {
                sandbox: sandbox(),
                runtime: rt.kind,
            }),
            Some(rt) if rt.logged_in == Fact::Known(false) => out.push(Suggestion::LogIn {
                sandbox: sandbox(),
                runtime: rt.name,
                login: rt.login.clone(),
            }),
            Some(_) => {}
        }
        if s.agents
            .as_ref()
            .is_some_and(|l| l.agents.is_empty() && l.unreadable.is_none())
        {
            out.push(Suggestion::AddFirstAgent { sandbox: sandbox() });
        }
        let idle_days = (now.as_second() - s.last_used.as_second()) / 86_400;
        if !s.in_use() && idle_days >= IDLE_DAYS {
            out.push(Suggestion::RemoveIdle {
                sandbox: sandbox(),
                idle_days,
                frees: s.disk.frees(),
                complete: s.disk.incomplete.is_none(),
            });
        }
    }
    out
}

/// Bytes in decimal units, as Finder shows them.
pub fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1000.0 && unit < UNITS.len() - 1 {
        value /= 1000.0;
        unit += 1;
    }
    match unit {
        0 => format!("{bytes} B"),
        _ if value < 10.0 => format!("{value:.1} {}", UNITS[unit]),
        _ => format!("{value:.0} {}", UNITS[unit]),
    }
}

// ---- Reading the sandbox home (ADR 0023) ----

fn exists(home: &Path, rel: &HomePath) -> Fact<bool> {
    match home::stat(home, rel) {
        Ok(found) => Fact::Known(found.is_some()),
        Err(why) => Fact::CannotTell(why.to_string()),
    }
}

/// When `stat` says the entry last changed.
fn mtime(stat: &Stat) -> Option<Timestamp> {
    let seconds = i64::try_from(wide(stat.st_mtime)).ok()?;
    let nanos = i32::try_from(wide(stat.st_mtime_nsec)).ok()?;
    Timestamp::new(seconds, nanos).ok()
}

/// The newest change among `files`: absent when none exists, and "cannot
/// tell" when none could be read and one could not.
fn newest(home: &Path, files: &[HomePath]) -> Fact<Timestamp> {
    if files.is_empty() {
        return Fact::NotProvided;
    }
    let mut newest = None;
    let mut cannot = None;
    for file in files {
        match home::stat(home, file) {
            Ok(Some(stat)) => match mtime(&stat) {
                Some(t) => newest = newest.max(Some(t)),
                None => cannot = cannot.or(Some(format!("{file}: a time enclos cannot read"))),
            },
            Ok(None) => {}
            Err(why) => cannot = cannot.or(Some(why.to_string())),
        }
    }
    match (newest, cannot) {
        (Some(t), _) => Fact::Known(t),
        (None, Some(why)) => Fact::CannotTell(why),
        (None, None) => Fact::Absent,
    }
}

/// A value from a small YAML file of the home, made safe to print.
fn read_value(home: &Path, at: &ValueAt) -> Fact<String> {
    let text = match home::read_text(home, &at.file, MAX_FACT_FILE) {
        Ok(Some(text)) => text,
        Ok(None) => return Fact::Absent,
        Err(why) => return Fact::CannotTell(why.to_string()),
    };
    for key in at.keys {
        match yaml_value(&text, key) {
            Yaml::Found(v) => return Fact::Known(printable(&v)),
            Yaml::Missing => {}
            Yaml::Unsure => {
                return Fact::CannotTell(format!(
                    "{}: `{key}` is written in YAML enclos does not read",
                    at.file
                ));
            }
        }
    }
    Fact::Absent
}

/// What [`yaml_value`] found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Yaml {
    Found(String),
    Missing,
    /// The file uses YAML this reader does not handle, there or around the
    /// key, so any answer would be a guess.
    Unsure,
}

/// A scalar under a dotted key of a YAML mapping, such as `model.default`.
/// Enough YAML for a runtime's config: block mappings nested by spaces,
/// plain or quoted one-line scalars, and comments. Sequences and block
/// scalars are skipped whole. A tab in the indentation, a key given twice,
/// and a value that is a block scalar, an anchor, an alias, a tag, a flow
/// collection or a quoted scalar with escapes answer `Unsure`.
pub(super) fn yaml_value(text: &str, key: &str) -> Yaml {
    let want: Vec<&str> = key.split('.').collect();
    let mut path: Vec<(usize, String)> = Vec::new();
    // Lines deeper than this belong to a sequence or a block scalar.
    let mut skip_deeper: Option<usize> = None;
    let mut found = None;
    for line in text.lines() {
        let trimmed = line.trim_start_matches(' ');
        let indent = line.len() - trimmed.len();
        if trimmed.starts_with('\t') {
            return Yaml::Unsure;
        }
        let content = trimmed.trim_end();
        if content.is_empty() || content.starts_with('#') {
            continue;
        }
        if let Some(limit) = skip_deeper {
            if indent > limit {
                continue;
            }
            skip_deeper = None;
        }
        match content {
            "---" => continue,
            "..." => break,
            _ => {}
        }
        if content == "-" || content.starts_with("- ") {
            skip_deeper = Some(indent);
            continue;
        }
        let (k, rest) = match content.split_once(": ") {
            Some(pair) => pair,
            None => match content.strip_suffix(':') {
                Some(k) => (k, ""),
                // Not `key: value`: the rest of a scalar.
                None => continue,
            },
        };
        let k = k.trim().trim_matches(|c| c == '"' || c == '\'');
        while path.last().is_some_and(|(i, _)| *i >= indent) {
            path.pop();
        }
        path.push((indent, k.to_owned()));
        let rest = rest.trim();
        if rest.starts_with('|') || rest.starts_with('>') {
            skip_deeper = Some(indent);
        }
        if path
            .iter()
            .map(|(_, k)| k.as_str())
            .eq(want.iter().copied())
        {
            if found.is_some() {
                return Yaml::Unsure;
            }
            found = Some(scalar(rest));
        }
    }
    found.unwrap_or(Yaml::Missing)
}

/// The value after `key:`, on its line.
fn scalar(rest: &str) -> Yaml {
    let ends_cleanly = |after: &str| {
        let after = after.trim_start();
        after.is_empty() || after.starts_with('#')
    };
    let value = match rest.chars().next() {
        // Nothing, or a comment: the key holds a mapping, or nothing.
        None | Some('#') => return Yaml::Missing,
        Some('|' | '>' | '&' | '*' | '!' | '{' | '[' | '%' | '@' | '`') => return Yaml::Unsure,
        Some('"') => {
            let inner = &rest[1..];
            match inner.find('"') {
                Some(end) if !inner[..end].contains('\\') && ends_cleanly(&inner[end + 1..]) => {
                    &inner[..end]
                }
                _ => return Yaml::Unsure,
            }
        }
        Some('\'') => {
            let inner = &rest[1..];
            match inner.find('\'') {
                // `''` is an escaped quote.
                Some(end) if ends_cleanly(&inner[end + 1..]) => &inner[..end],
                _ => return Yaml::Unsure,
            }
        }
        Some(_) => rest.split(" #").next().unwrap_or("").trim(),
    };
    match value.is_empty() {
        true => Yaml::Missing,
        false => Yaml::Found(value.to_owned()),
    }
}

// ---- Disk usage ----

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum Slot {
    Part(DiskPart),
    Agent(RuntimeAgentName),
    Other,
}

struct Usage {
    total: u64,
    shared: u64,
    incomplete: Option<String>,
    by_slot: HashMap<Slot, u64>,
}

/// A folder found and not read yet: opened through its parent when its
/// turn comes, so only the folders on the way down stay open.
struct Pending {
    parent: Rc<OwnedFd>,
    name: CString,
    rel: PathBuf,
    slot: Slot,
}

/// A hard-linked file: its link count, the links seen, and its size.
struct Linked {
    nlink: i128,
    seen: i128,
    bytes: u64,
}

const FOLDER: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);

/// What `root` holds, as removing it would free: allocated blocks, each
/// entry `lstat`ed through its folder's descriptor (a link counts as
/// itself, and a folder swapped for a link is not entered), each
/// hard-linked file once, and at most `budget` entries, counted as they are
/// read. Everything under one of `parts` (paths from `root`) counts toward
/// it. A read that fails, other than for an entry gone meanwhile, or the
/// budget running out, makes every size a lower bound and says why. A file
/// with hard links in several parts counts toward the first one reached.
fn walk(root: &Path, parts: &[(PathBuf, Slot)], budget: usize) -> Usage {
    let mut usage = Usage {
        total: 0,
        shared: 0,
        incomplete: None,
        by_slot: HashMap::new(),
    };
    let mut linked: HashMap<(i128, i128), Linked> = HashMap::new();
    // `rel` holds names the sandbox chose: escaped before it is shown.
    let fail = |usage: &mut Usage, rel: &Path, e: Errno| {
        usage
            .incomplete
            .get_or_insert_with(|| match rel.as_os_str().is_empty() {
                true => format!("{}: {e}", root.display()),
                false => format!(
                    "{}/{}: {e}",
                    root.display(),
                    printable(&rel.to_string_lossy())
                ),
            });
    };
    let root_fd = match rustix::fs::open(
        root,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        // No folder: removing it frees nothing.
        Err(Errno::NOENT) => return usage,
        Err(e) => {
            fail(&mut usage, Path::new(""), e);
            return usage;
        }
    };
    match rustix::fs::fstat(&root_fd) {
        Ok(stat) => count(&mut usage, &mut linked, &Slot::Other, &stat),
        Err(e) => fail(&mut usage, Path::new(""), e),
    }
    let mut entries = 1;
    let mut folders = vec![(Rc::new(root_fd), PathBuf::new(), Slot::Other)];
    let mut pending: Vec<Pending> = Vec::new();
    'walk: loop {
        while let Some((fd, rel, slot)) = folders.pop() {
            let dir = match Dir::read_from(&*fd) {
                Ok(dir) => dir,
                Err(e) => {
                    fail(&mut usage, &rel, e);
                    continue;
                }
            };
            for entry in dir {
                let entry = match entry {
                    Ok(entry) => entry,
                    Err(e) => {
                        fail(&mut usage, &rel, e);
                        break;
                    }
                };
                let name = entry.file_name();
                if is_dot(name) {
                    continue;
                }
                entries += 1;
                if entries > budget {
                    usage.incomplete = Some(format!("stopped after {budget} entries"));
                    break 'walk;
                }
                let child = rel.join(OsStr::from_bytes(name.to_bytes()));
                let slot = parts
                    .iter()
                    .find(|(p, _)| *p == child)
                    .map_or_else(|| slot.clone(), |(_, s)| s.clone());
                match rustix::fs::statat(&*fd, name, AtFlags::SYMLINK_NOFOLLOW) {
                    Ok(stat) => {
                        count(&mut usage, &mut linked, &slot, &stat);
                        if FileType::from_raw_mode(stat.st_mode).is_dir() {
                            pending.push(Pending {
                                parent: Rc::clone(&fd),
                                name: name.to_owned(),
                                rel: child,
                                slot,
                            });
                        }
                    }
                    // Gone meanwhile: it frees nothing.
                    Err(Errno::NOENT) => {}
                    Err(e) => fail(&mut usage, &child, e),
                }
            }
        }
        let Some(next) = pending.pop() else {
            break;
        };
        match rustix::fs::openat(&*next.parent, next.name.as_c_str(), FOLDER, Mode::empty()) {
            Ok(fd) => folders.push((Rc::new(fd), next.rel, next.slot)),
            Err(Errno::NOENT) => {}
            // Swapped for a link, or unreadable: not entered.
            Err(e) => fail(&mut usage, &next.rel, e),
        }
    }
    usage.shared = linked
        .values()
        .filter(|l| l.seen < l.nlink)
        .map(|l| l.bytes)
        .sum();
    usage
}

/// Adds one entry's allocated blocks, a hard-linked file only the first
/// time it is seen.
fn count(usage: &mut Usage, linked: &mut HashMap<(i128, i128), Linked>, slot: &Slot, stat: &Stat) {
    let bytes = u64::try_from(wide(stat.st_blocks)).unwrap_or(0) * 512;
    let nlink = wide(stat.st_nlink);
    if nlink > 1 && !FileType::from_raw_mode(stat.st_mode).is_dir() {
        let key = (wide(stat.st_dev), wide(stat.st_ino));
        let entry = linked.entry(key).or_insert(Linked {
            nlink,
            seen: 0,
            bytes,
        });
        entry.seen += 1;
        if entry.seen > 1 {
            return;
        }
    }
    usage.total += bytes;
    *usage.by_slot.entry(slot.clone()).or_default() += bytes;
}

/// The address of the page `listener`'s service serves on the host, at the
/// port sessions are given (ADR 0028), found the same way.
fn dashboard(
    store: &dyn StateStore,
    name: &SandboxName,
    listener: &RuntimeListener,
    running: &[SessionRecord],
) -> Fact<String> {
    let Some(page) = listener.page else {
        return Fact::NotProvided;
    };
    let service = listener.service.as_str();
    let runs = running
        .iter()
        .any(|s| s.kind == SessionKind::Service && s.service.as_deref() == Some(service));
    if !runs {
        return Fact::Absent;
    }
    match service_listener(store, name, service).and_then(outside_proxy_range) {
        Ok(port) => Fact::Known(format!("http://127.0.0.1:{port}{page}")),
        Err(NoPort::NotRunning(_)) => Fact::Absent,
        Err(why) => Fact::CannotTell(why.to_string()),
    }
}

/// Members of the `running` sessions that run in the sandbox (the proxy runs
/// outside it) listening beyond loopback, which the host's network can
/// reach: nothing narrows a sandbox's listener to loopback (ADR 0028). Each
/// pid and address once, a listener on every address (`0.0.0.0` or `[::]`)
/// shown as `*:<port>`. A pid is named only while it is still the member
/// `procs` listed, checked after `lsof` looked, so a pid reused meanwhile
/// is not.
fn network_listeners(procs: &[Proc], running: &[SessionRecord]) -> Fact<Vec<NetworkListener>> {
    let mut members: BTreeMap<u32, (ProcessRef, String)> = BTreeMap::new();
    for session in running.iter().filter(|s| s.kind != SessionKind::Proxy) {
        for found in find(procs, session, &session.tracked) {
            let member = found.member;
            let at = ProcessRef {
                pid: member.pid,
                started: member.started,
            };
            members.insert(member.pid, (at, member.command));
        }
    }
    let pids: Vec<u32> = members.keys().copied().collect();
    let held = match tcp_listeners_of(&pids) {
        Ok(held) => held,
        Err(e) => return Fact::CannotTell(e.to_string()),
    };
    let mut shown: BTreeSet<(u32, String)> = BTreeSet::new();
    for (pid, addr) in held {
        // A v4-mapped address is the IPv4 one (`::ffff:127.0.0.1`).
        let ip = addr.ip().to_canonical();
        if ip.is_loopback() {
            continue;
        }
        let address = match ip.is_unspecified() {
            true => format!("*:{}", addr.port()),
            false => addr.to_string(),
        };
        shown.insert((pid, address));
    }
    let mut found = Vec::new();
    for (pid, address) in shown {
        let Some((at, command)) = members.get(&pid) else {
            return Fact::CannotTell(format!("lsof answered for pid {pid}, which was not asked"));
        };
        match is_same(at) {
            Ok(true) => found.push(NetworkListener {
                pid,
                command: printable(command),
                address,
            }),
            // Gone, or another process now: not the member's listener.
            Ok(false) => {}
            Err(e) => return Fact::CannotTell(e.to_string()),
        }
    }
    Fact::Known(found)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A running session of `kind` whose root is `root`.
    #[cfg(target_os = "macos")]
    fn session_of(kind: SessionKind, root: crate::model::session::ProcessRef) -> SessionRecord {
        SessionRecord {
            id: crate::model::session::SessionId(1),
            sandbox: "home".parse().unwrap(),
            kind,
            service: None,
            version: 1,
            snapshot: crate::model::policy::SnapshotId("s".into()),
            compiled: None,
            root,
            pgid: None,
            tracked: Vec::new(),
            started_at: now(),
            ended_at: None,
        }
    }

    /// Listens on every address and on loopback, and says both ports. Perl,
    /// which macOS signs, so the firewall asks nothing of whoever runs the
    /// tests.
    #[cfg(target_os = "macos")]
    const LISTENS: &str = "use Socket; for my $a (INADDR_ANY, INADDR_LOOPBACK) { socket(my $s, PF_INET, SOCK_STREAM, 0) or die; bind($s, sockaddr_in(0, $a)) or die; listen($s, 1) or die; push @s, $s; print((sockaddr_in(getsockname($s)))[0], qq(\\n)); } $| = 1; STDOUT->flush; sleep 30";

    // `lsof` at /usr/sbin is macOS's, where sandboxes listen (ADR 0028).
    #[cfg(target_os = "macos")]
    #[test]
    fn listeners_beyond_loopback_are_named_and_loopback_ones_are_not() {
        use std::io::BufRead;
        let mut child = std::process::Command::new("/usr/bin/perl")
            .args(["-e", LISTENS])
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let mut lines = std::io::BufReader::new(child.stdout.take().unwrap()).lines();
        let mut port = || lines.next().unwrap().unwrap();
        let (wide, narrow) = (port(), port());
        let root = crate::lifecycle::process::reference_of_child(&child).unwrap();
        let procs = processes().unwrap();
        let running = [session_of(SessionKind::Interactive, root.clone())];
        let found = network_listeners(&procs, &running);
        // The proxy runs on the host, not in the sandbox: never counted.
        let proxy = network_listeners(&procs, &[session_of(SessionKind::Proxy, root)]);
        let _ = child.kill();
        let _ = child.wait();
        let Fact::Known(found) = found else {
            panic!("lsof could not look: {found:?}");
        };
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].pid, child.id());
        assert_eq!(found[0].address, format!("*:{wide}"));
        assert!(found[0].command.ends_with("perl"), "{found:?}");
        assert!(
            !found
                .iter()
                .any(|l| l.address.ends_with(&format!(":{narrow}")))
        );
        assert_eq!(proxy, Fact::Known(Vec::new()));
    }

    fn file(path: &Path, bytes: usize) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, vec![b'x'; bytes]).unwrap();
    }

    fn rel(p: &str) -> HomePath {
        HomePath::new(p).unwrap()
    }

    #[test]
    fn the_walker_counts_parts_and_never_follows_a_link() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        file(&outside.path().join("big"), 2_000_000);
        file(&root.path().join("home/rt/lib"), 100_000);
        file(&root.path().join("home/other"), 10_000);
        std::os::unix::fs::symlink(outside.path(), root.path().join("home/rt/link")).unwrap();
        // A part that is itself a link counts as the link alone.
        std::os::unix::fs::symlink(outside.path(), root.path().join("home/cache")).unwrap();
        let parts = [
            (PathBuf::from("home/rt"), Slot::Part(DiskPart::Runtime)),
            (PathBuf::from("home/cache"), Slot::Part(DiskPart::Cache)),
        ];
        let usage = walk(root.path(), &parts, 1000);
        assert_eq!(usage.incomplete, None);
        let runtime = usage.by_slot[&Slot::Part(DiskPart::Runtime)];
        assert!((100_000..200_000).contains(&runtime), "{runtime}");
        assert!(usage.by_slot[&Slot::Part(DiskPart::Cache)] < 100_000);
        assert!(usage.total < 1_000_000, "a link's target was counted");
    }

    #[test]
    fn a_hard_linked_file_counts_once_and_one_linked_from_outside_is_shared() {
        let root = tempfile::tempdir().unwrap();
        file(&root.path().join("a"), 500_000);
        std::fs::hard_link(root.path().join("a"), root.path().join("b")).unwrap();
        let usage = walk(root.path(), &[], 1000);
        assert!(
            (500_000..1_000_000).contains(&usage.total),
            "{}",
            usage.total
        );
        assert_eq!(usage.shared, 0);
        // A third link outside the folder: removing it frees none of this.
        let outside = tempfile::tempdir_in(root.path().parent().unwrap()).unwrap();
        std::fs::hard_link(root.path().join("a"), outside.path().join("c")).unwrap();
        let usage = walk(root.path(), &[], 1000);
        assert!(usage.shared >= 500_000, "{}", usage.shared);
    }

    #[test]
    fn the_budget_counts_entries_as_they_are_read_and_says_when_it_stops() {
        let root = tempfile::tempdir().unwrap();
        for i in 0..9 {
            file(&root.path().join(format!("d/{i}")), 10);
        }
        // The root, `d` and its nine files.
        let all = 11;
        assert_eq!(walk(root.path(), &[], all).incomplete, None);
        let capped = walk(root.path(), &[], all - 1);
        assert_eq!(
            capped.incomplete.as_deref(),
            Some("stopped after 10 entries")
        );
        let full = walk(root.path(), &[], all).total;
        assert!(capped.total > 0 && capped.total <= full);
    }

    #[test]
    fn an_unreadable_folder_makes_every_size_a_lower_bound() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        file(&root.path().join("locked/inside"), 100_000);
        let locked = root.path().join("locked");
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
        if std::fs::read_dir(&locked).is_ok() {
            // Run as root, which reads everything.
            std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700)).unwrap();
            return;
        }
        let usage = walk(root.path(), &[], 1000);
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700)).unwrap();
        let why = usage.incomplete.unwrap();
        assert!(why.contains("locked"), "{why}");
        // A name the sandbox chose is escaped before it is shown.
        let forged = root.path().join("\u{1b}[2J\u{1b}[HFORGED\nline");
        std::fs::create_dir(&forged).unwrap();
        std::fs::set_permissions(&forged, std::fs::Permissions::from_mode(0o000)).unwrap();
        let usage = walk(root.path(), &[], 1000);
        std::fs::set_permissions(&forged, std::fs::Permissions::from_mode(0o700)).unwrap();
        let why = usage.incomplete.unwrap();
        assert!(!why.contains('\u{1b}') && !why.contains('\n'), "{why:?}");
        assert!(why.contains("\\u{1b}[2J\\u{1b}[HFORGED\\nline"), "{why}");
        // A missing folder is not a failure: it frees nothing.
        let gone = walk(&root.path().join("gone"), &[], 1000);
        assert_eq!((gone.total, gone.incomplete), (0, None));
    }

    #[test]
    fn facts_read_from_the_home_say_why_they_cannot_tell() {
        let home = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(
            outside.path().join("config.yaml"),
            "model:\n  default: host\n",
        )
        .unwrap();
        std::os::unix::fs::symlink(outside.path(), home.path().join("linked")).unwrap();
        let at = |file: &str| ValueAt {
            file: rel(file),
            keys: &["model.default", "model.model"],
        };
        assert_eq!(
            read_value(home.path(), &at("linked/config.yaml")),
            Fact::CannotTell("~/linked is a link".into())
        );
        assert_eq!(
            exists(home.path(), &rel("linked/config.yaml")),
            Fact::CannotTell("~/linked is a link".into())
        );
        assert_eq!(exists(home.path(), &rel("missing")), Fact::Known(false));
        assert_eq!(read_value(home.path(), &at("missing")), Fact::Absent);

        file(&home.path().join("a/config.yaml"), 0);
        std::fs::write(
            home.path().join("a/config.yaml"),
            "x: 1\nmodel:\n  # the model\n  default: \"gpt-6.1\u{1b}[2J\"\n  model: other\nother: 2\n",
        )
        .unwrap();
        // The first key wins, escaped.
        assert_eq!(
            read_value(home.path(), &at("a/config.yaml")),
            Fact::Known("gpt-6.1\\u{1b}[2J".into())
        );
        std::fs::write(home.path().join("a/config.yaml"), "model:\n  model: m2\n").unwrap();
        assert_eq!(
            read_value(home.path(), &at("a/config.yaml")),
            Fact::Known("m2".into())
        );
        std::fs::write(
            home.path().join("a/config.yaml"),
            "model:\n  default: |\n    x\n",
        )
        .unwrap();
        assert!(matches!(
            read_value(home.path(), &at("a/config.yaml")),
            Fact::CannotTell(why) if why.contains("YAML enclos does not read")
        ));
        file(
            &home.path().join("a/big.yaml"),
            (MAX_FACT_FILE + 1) as usize,
        );
        assert!(matches!(
            read_value(home.path(), &at("a/big.yaml")),
            Fact::CannotTell(why) if why.contains("larger than")
        ));

        // The newest activity, or why there is none.
        assert_eq!(newest(home.path(), &[]), Fact::NotProvided);
        assert_eq!(newest(home.path(), &[rel("nope")]), Fact::Absent);
        assert!(matches!(
            newest(home.path(), &[rel("linked/x")]),
            Fact::CannotTell(_)
        ));
        assert!(matches!(
            newest(home.path(), &[rel("linked/x"), rel("a/config.yaml")]),
            Fact::Known(_)
        ));
    }

    #[test]
    fn yaml_values_are_found_by_dotted_key_and_anything_unsure_says_so() {
        let found = |text: &str, key: &str| match yaml_value(text, key) {
            Yaml::Found(v) => Some(v),
            _ => None,
        };
        let text = "model:\n  default: gpt-6.1-sol # comment\n  provider: 'openai'\nother:\n  default: no\n";
        assert_eq!(found(text, "model.default").as_deref(), Some("gpt-6.1-sol"));
        assert_eq!(found(text, "model.provider").as_deref(), Some("openai"));
        assert_eq!(yaml_value(text, "model.missing"), Yaml::Missing);
        assert_eq!(found("model: gpt\n", "model").as_deref(), Some("gpt"));
        // Siblings after a nested mapping, a value with a colon, a `#` in quotes.
        let text = "a:\n  b:\n    c: x\n  d: y\nurl: http://x:1\nq: \"a # b\"\n\"k\": v\n";
        assert_eq!(found(text, "a.d").as_deref(), Some("y"));
        assert_eq!(found(text, "a.b.d"), None);
        assert_eq!(found(text, "url").as_deref(), Some("http://x:1"));
        assert_eq!(found(text, "q").as_deref(), Some("a # b"));
        assert_eq!(found(text, "k").as_deref(), Some("v"));
        // A sequence's items do not count toward the key above them.
        let text = "model:\n  - default: listed\n    x: 1\n  default: real\n";
        assert_eq!(found(text, "model.default").as_deref(), Some("real"));
        // A block scalar's lines are not keys.
        let text = "notes: |\n  default: inside\nmodel:\n  default: m\n";
        assert_eq!(found(text, "model.default").as_deref(), Some("m"));
        assert_eq!(found(text, "default"), None);
        for unsure in [
            "model:\n  default: |\n    x\n",
            "model:\n  default: >\n    x\n",
            "model:\n  default: &a gpt\n",
            "model:\n  default: *a\n",
            "model:\n  default: !!str x\n",
            "model: {default: x}\n",
            "model:\n\tdefault: x\n",
            "model:\n  default: a\n  default: b\n",
            "model:\n  default: \"a\\\"b\"\n",
            "model:\n  default: 'it''s'\n",
        ] {
            assert_eq!(
                yaml_value(unsure, "model.default"),
                if unsure.starts_with("model: {") {
                    Yaml::Missing
                } else {
                    Yaml::Unsure
                },
                "{unsure:?}"
            );
        }
        assert_eq!(yaml_value("model: {default: x}\n", "model"), Yaml::Unsure);
        assert_eq!(
            yaml_value("model:\n  default: # c\n", "model.default"),
            Yaml::Missing
        );
        assert_eq!(
            yaml_value("\"model.default\": x\n", "model.default"),
            Yaml::Missing
        );
    }

    #[test]
    fn sizes_read_like_finder() {
        assert_eq!(human_bytes(512), "512 B");
        assert_eq!(human_bytes(4_700_000), "4.7 MB");
        assert_eq!(human_bytes(2_400_000_000), "2.4 GB");
        assert_eq!(human_bytes(330_000_000), "330 MB");
    }
}
