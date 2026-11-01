//! What `enclos status` hands the CLI.

use std::path::PathBuf;

use serde::{Serialize, Serializer};

use super::{Disk, Suggestion};
use crate::model::Timestamp;
use crate::model::runtime::RuntimeKind;
use crate::model::sandbox::{SandboxName, SandboxState};
use crate::runtime::RuntimeAgentName;
use crate::service::ServiceStatus;

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

fn as_text<S: Serializer>(
    value: &impl std::fmt::Display,
    s: S,
) -> std::result::Result<S::Ok, S::Error> {
    s.collect_str(value)
}
