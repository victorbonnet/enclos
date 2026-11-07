//! What `enclos status` suggests: fixed rules, each naming an existing
//! command (design §9).

use serde::{Serialize, Serializer};

use super::{AgentKind, Fact, Presence, SandboxStatus, human_bytes};
use crate::model::Timestamp;
use crate::model::agent::AgentName;
use crate::model::runtime::RuntimeKind;
use crate::model::sandbox::SandboxName;

/// Past this, a sandbox nobody used is worth a suggestion.
pub const IDLE_DAYS: i64 = 30;

/// How far back refused destinations count.
pub(super) const REFUSED_DAYS: i64 = 7;

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
        refused: u64,
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
            Suggestion::LookAtProxy { refused, last, .. } => format!(
                "{refused} {} refused as the proxy could not read the policy, the last at {}",
                match refused {
                    1 => "connection",
                    _ => "connections",
                },
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
                refused: s.policy_unreadable_refused,
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
