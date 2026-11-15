//! `enclos usage` (issue #282, design §11, Usage): what each agent used of
//! its model providers, as its runtime recorded it.
//!
//! The record is the same for every runtime. Each runtime adapter supplies
//! a command that reads the runtime's own records inside the sandbox and
//! writes them as a usage report (format 1, below); enclos runs it as an
//! exec session and reads the report on the host, bounded, as it reads
//! anything the sandbox wrote (ADR 0023). A field the runtime does not
//! count is `null` (not provided), never 0.
//!
//! The numbers come from inside the sandbox, which the agent can change:
//! usage is advisory, for finding an agent that spends a lot, not an
//! account of what a provider bills.

use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize, Serializer};

use super::Engine;
use super::import::opened_path;
use super::status::{Fact, printable};
use crate::bridge::ids::new_id;
use crate::error::{Error, Result};
use crate::model::Timestamp;
use crate::model::audit::Actor;
use crate::model::runtime::RuntimeKind;
use crate::model::sandbox::{SandboxName, SandboxState};
use crate::runtime::{RuntimeAgentName, adapter};

/// The usage report's format, which every adapter's command writes.
pub const REPORT_FORMAT: u32 = 1;
/// The most bytes of a report enclos reads.
const MAX_REPORT_BYTES: u64 = 1 << 20;
/// The most models listed for one agent, and native chats in its top list.
const MAX_MODELS: usize = 50;
const MAX_TOP: usize = 5;

/// Token counts, each `None` when the runtime does not count it. `input`
/// is input not read from or written to the provider's cache.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tokens {
    #[serde(default)]
    pub input: Option<u64>,
    #[serde(default)]
    pub output: Option<u64>,
    #[serde(default)]
    pub cache_read: Option<u64>,
    #[serde(default)]
    pub cache_write: Option<u64>,
    #[serde(default)]
    pub reasoning: Option<u64>,
}

impl Tokens {
    /// What the model was sent: input, cache reads and cache writes.
    pub fn prompt(&self) -> u64 {
        [self.input, self.cache_read, self.cache_write]
            .into_iter()
            .flatten()
            .fold(0, u64::saturating_add)
    }

    /// Every token sent or received. Reasoning tokens are a part of
    /// output, as providers count them, so they are not added again.
    pub fn total(&self) -> u64 {
        self.prompt().saturating_add(self.output.unwrap_or(0))
    }

    /// The share of the prompt read from the cache, when the runtime
    /// counts cache reads and something was sent.
    pub fn cache_hit(&self) -> Option<f64> {
        let read = self.cache_read?;
        let prompt = self.prompt();
        (prompt > 0).then(|| read as f64 / prompt as f64)
    }

    fn add(&mut self, other: &Tokens) {
        let sum = |a: Option<u64>, b: Option<u64>| match (a, b) {
            (None, None) => None,
            (a, b) => Some(a.unwrap_or(0).saturating_add(b.unwrap_or(0))),
        };
        self.input = sum(self.input, other.input);
        self.output = sum(self.output, other.output);
        self.cache_read = sum(self.cache_read, other.cache_read);
        self.cache_write = sum(self.cache_write, other.cache_write);
        self.reasoning = sum(self.reasoning, other.reasoning);
    }
}

/// How a cost was arrived at.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CostKind {
    /// What the provider reported.
    Actual,
    /// Worked out by the runtime from its price list.
    Estimated,
    /// Covered by a subscription: tokens still count against its limits.
    Included,
    Unknown,
    /// Native chats of more than one kind.
    Mixed,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub struct Cost {
    /// In US dollars, when the runtime knows it.
    pub usd: Option<f64>,
    pub kind: CostKind,
}

/// What one agent used with one model.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ModelUsage {
    pub model: Option<String>,
    pub chats: u64,
    /// Requests to the provider.
    pub calls: Option<u64>,
    pub tokens: Tokens,
    pub cost: Cost,
}

impl ModelUsage {
    /// Tokens per request, which grows with the context.
    pub fn per_call(&self) -> Option<u64> {
        self.calls
            .filter(|&c| c > 0)
            .map(|c| self.tokens.total() / c)
    }
}

/// One of an agent's native chats that used the most.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ChatUsage {
    pub chat: Option<String>,
    /// Where it came from, in the runtime's words (Hermes: `enclos` for the
    /// app's channel, `cli`, `cron`, ...).
    pub source: Option<String>,
    pub title: Option<String>,
    pub started_at: Option<Timestamp>,
    pub model: Option<String>,
    pub calls: Option<u64>,
    pub tokens: Tokens,
}

/// What an agent's runtime recorded.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AgentRecords {
    pub models: Vec<ModelUsage>,
    /// Its native chats that used the most tokens, most first.
    pub top: Vec<ChatUsage>,
}

impl AgentRecords {
    pub fn tokens(&self) -> Tokens {
        let mut sum = Tokens::default();
        for m in &self.models {
            sum.add(&m.tokens);
        }
        sum
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AgentUsage {
    pub agent: String,
    /// Absent: the runtime has no records for it, as for an agent never used.
    pub usage: Fact<AgentRecords>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SandboxUsage {
    #[serde(serialize_with = "as_text")]
    pub name: SandboxName,
    pub runtime: Option<&'static str>,
    /// Absent: no runtime is installed. Not provided: its adapter reads no
    /// usage.
    pub agents: Fact<Vec<AgentUsage>>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct UsageView {
    /// Native chats active since then are counted, each whole.
    pub since: Timestamp,
    pub sandboxes: Vec<SandboxUsage>,
}

fn as_text<S: Serializer>(
    value: &impl std::fmt::Display,
    s: S,
) -> std::result::Result<S::Ok, S::Error> {
    s.collect_str(value)
}

impl Engine {
    /// What each agent of one sandbox, or of every running one, used of its
    /// model providers in native chats active since `since`. Named, a sandbox
    /// is read whatever its state, as `exec` would run in it; listed with
    /// the others, a sandbox that is not running is left unread, so that
    /// reading usage starts no proxy the user did not ask for.
    pub fn usage(
        &self,
        by: &Actor,
        only: Option<&SandboxName>,
        since: Timestamp,
    ) -> Result<UsageView> {
        let records = match only {
            Some(name) => vec![self.state.get(name)?.ok_or_else(|| Error::NoSuchSandbox {
                name: name.to_string(),
            })?],
            None => self.state.list()?,
        };
        let mut sandboxes = Vec::new();
        for record in records {
            let name = record.name.clone();
            let runtime = record.runtime;
            let agents = match runtime {
                None => Fact::Absent,
                Some(_) if only.is_none() && record.state != SandboxState::Running => {
                    Fact::CannotTell(format!(
                        "not running; `enclos usage {name}` reads it, starting its proxy"
                    ))
                }
                Some(kind) => match self.sandbox_usage(by, &name, kind, since) {
                    Ok(agents) => agents,
                    Err(e) if only.is_none() => Fact::CannotTell(e.to_string()),
                    Err(e) => return Err(e),
                },
            };
            sandboxes.push(SandboxUsage {
                name,
                runtime: runtime.map(RuntimeKind::display_name),
                agents,
            });
        }
        Ok(UsageView { since, sandboxes })
    }

    fn sandbox_usage(
        &self,
        by: &Actor,
        name: &SandboxName,
        kind: RuntimeKind,
        since: Timestamp,
    ) -> Result<Fact<Vec<AgentUsage>>> {
        let runtime = adapter(kind);
        let home = self.sandbox_home(name);
        let mut agents: Vec<RuntimeAgentName> = runtime
            .builtin_agent()
            .map(|b| b.runtime_name())
            .into_iter()
            .collect();
        match runtime.agents_in(&home) {
            Ok(found) => agents.extend(found),
            Err(why) => return Ok(Fact::CannotTell(why.to_string())),
        }
        let id = new_id().map_err(|e| Error::Session {
            what: format!("cannot name the usage report: {e}"),
        })?;
        let report = home.join(format!(".enclos-usage-{id}.json"));
        let Some(command) = runtime.usage(&agents, since.as_second(), &report) else {
            return Ok(Fact::NotProvided);
        };
        let _remove = Removed(report.clone());
        let ended = self.run_exec_in_sandbox(by, name, command, "usage session")?;
        if ended.exit != 0 {
            return Ok(Fact::CannotTell(format!(
                "{}'s usage reader exited with {}",
                kind.display_name(),
                ended.exit
            )));
        }
        Ok(
            match read_report(&report, &home).and_then(|t| parse(&t, &agents)) {
                Ok(agents) => Fact::Known(agents),
                Err(why) => Fact::CannotTell(format!("the usage report {why}")),
            },
        )
    }
}

/// Removes the report once read, or when the read failed.
struct Removed(PathBuf);

impl Drop for Removed {
    fn drop(&mut self) {
        match std::fs::remove_file(&self.0) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => eprintln!("enclos: remove {}: {e}", self.0.display()),
        }
    }
}

/// The report's text: a plain file in the sandbox home, not a link, of at
/// most `MAX_REPORT_BYTES`.
fn read_report(path: &Path, home: &Path) -> std::result::Result<String, String> {
    let flags = (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits();
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(flags as i32)
        .open(path)
        .map_err(|e| format!("cannot be opened: {e}"))?;
    let meta = file.metadata().map_err(|e| e.to_string())?;
    let home = home.canonicalize().map_err(|e| e.to_string())?;
    if !meta.is_file() || !opened_path(&file).is_ok_and(|p| p.starts_with(&home)) {
        return Err("is not a plain file in the sandbox home".into());
    }
    let mut text = String::new();
    file.take(MAX_REPORT_BYTES + 1)
        .read_to_string(&mut text)
        .map_err(|e| format!("cannot be read: {e}"))?;
    if text.len() as u64 > MAX_REPORT_BYTES {
        return Err(format!("is larger than {MAX_REPORT_BYTES} bytes"));
    }
    Ok(text)
}

// Format 1, as an adapter's command writes it.

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Report {
    format: u32,
    agents: Vec<ReportAgent>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReportAgent {
    agent: String,
    /// False: the runtime has no records for the agent.
    #[serde(default)]
    found: Option<bool>,
    /// Why its records could not be read.
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    models: Vec<ReportModel>,
    #[serde(default)]
    top: Vec<ReportChat>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReportModel {
    model: Option<String>,
    chats: u64,
    calls: Option<u64>,
    tokens: Tokens,
    cost: ReportCost,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReportCost {
    usd: Option<f64>,
    kind: CostKind,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReportChat {
    chat: Option<String>,
    source: Option<String>,
    title: Option<String>,
    started_at: Option<f64>,
    model: Option<String>,
    calls: Option<u64>,
    tokens: Tokens,
}

/// The report, checked: format 1, each agent asked for at most once and
/// nothing else, lists within their bounds, costs finite and not negative,
/// and every text the sandbox wrote made printable.
fn parse(text: &str, asked: &[RuntimeAgentName]) -> std::result::Result<Vec<AgentUsage>, String> {
    let report: Report = serde_json::from_str(text).map_err(|e| format!("is not valid: {e}"))?;
    if report.format != REPORT_FORMAT {
        return Err(format!("has format {}, not {REPORT_FORMAT}", report.format));
    }
    let mut seen = Vec::new();
    let mut agents = Vec::new();
    for a in report.agents {
        let Some(name) = asked.iter().find(|n| n.as_str() == a.agent) else {
            return Err("names an agent enclos did not ask for".into());
        };
        if seen.contains(&name) {
            return Err(format!("names agent {name} twice"));
        }
        seen.push(name);
        if a.models.len() > MAX_MODELS || a.top.len() > MAX_TOP {
            return Err(format!("lists too much for agent {name}"));
        }
        let usage = match (a.error, a.found) {
            (Some(why), _) => Fact::CannotTell(printable(&why)),
            (None, Some(false)) => Fact::Absent,
            (None, _) => Fact::Known(AgentRecords {
                models: a
                    .models
                    .into_iter()
                    .map(model)
                    .collect::<std::result::Result<_, _>>()?,
                top: a
                    .top
                    .into_iter()
                    .map(chat)
                    .collect::<std::result::Result<_, _>>()?,
            }),
        };
        agents.push(AgentUsage {
            agent: name.to_string(),
            usage,
        });
    }
    // An agent asked for and left out: the reader said nothing of it.
    for name in asked.iter().filter(|n| !seen.contains(n)) {
        agents.push(AgentUsage {
            agent: name.to_string(),
            usage: Fact::CannotTell("the runtime's usage reader left it out".into()),
        });
    }
    Ok(agents)
}

fn shown(text: Option<String>) -> Option<String> {
    text.map(|t| printable(&t))
}

fn model(m: ReportModel) -> std::result::Result<ModelUsage, String> {
    if m.cost.usd.is_some_and(|usd| !usd.is_finite() || usd < 0.0) {
        return Err("has a cost that is not a sum of money".into());
    }
    Ok(ModelUsage {
        model: shown(m.model),
        chats: m.chats,
        calls: m.calls,
        tokens: m.tokens,
        cost: Cost {
            usd: m.cost.usd,
            kind: m.cost.kind,
        },
    })
}

fn chat(s: ReportChat) -> std::result::Result<ChatUsage, String> {
    let started_at = match s.started_at {
        None => None,
        Some(t) if t.is_finite() => Timestamp::from_second(t as i64).ok(),
        Some(_) => return Err("has a start time that is not a time".into()),
    };
    Ok(ChatUsage {
        chat: shown(s.chat),
        source: shown(s.source),
        title: shown(s.title),
        started_at,
        model: shown(s.model),
        calls: s.calls,
        tokens: s.tokens,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(list: &[&str]) -> Vec<RuntimeAgentName> {
        list.iter()
            .map(|n| RuntimeAgentName::new(n).unwrap())
            .collect()
    }

    const REPORT: &str = r#"{"format": 1, "agents": [
        {"agent": "default", "found": true, "models": [
            {"model": "gpt-6.1-sol", "chats": 1, "calls": 26,
             "tokens": {"input": 83087, "output": 6084, "cache_read": 762752, "cache_write": 0, "reasoning": null},
             "cost": {"usd": 0.0, "kind": "included"}}],
         "top": [{"chat": "s1", "source": "enclos", "title": "Weather\u001b[31m", "started_at": 1763164800.5,
                  "model": "gpt-6.1-sol", "calls": 26,
                  "tokens": {"input": 83087, "output": 6084, "cache_read": 762752, "cache_write": 0, "reasoning": null}}]},
        {"agent": "scout", "found": false, "models": [], "top": []}
    ]}"#;

    #[test]
    fn a_report_becomes_each_agents_usage_with_what_the_runtime_does_not_count_left_unknown() {
        let agents = parse(REPORT, &names(&["default", "scout", "writer"])).unwrap();
        assert_eq!(agents.len(), 3);
        let Fact::Known(records) = &agents[0].usage else {
            panic!("{agents:?}")
        };
        let m = &records.models[0];
        assert_eq!(m.tokens.reasoning, None);
        assert_eq!(m.tokens.prompt(), 83087 + 762752);
        assert_eq!(m.tokens.total(), 83087 + 762752 + 6084);
        assert_eq!(m.per_call(), Some((83087 + 762752 + 6084) / 26));
        let hit = m.tokens.cache_hit().unwrap();
        assert!((hit - 762752.0 / 845839.0).abs() < 1e-9, "{hit}");
        assert_eq!(m.cost.kind, CostKind::Included);
        // Text the sandbox wrote is shown escaped.
        assert_eq!(records.top[0].title.as_deref(), Some("Weather\\u{1b}[31m"));
        assert_eq!(
            records.top[0].started_at,
            Some(Timestamp::from_second(1763164800).unwrap())
        );
        assert_eq!(agents[1].usage, Fact::Absent);
        assert!(matches!(agents[2].usage, Fact::CannotTell(_)));
    }

    #[test]
    fn a_report_naming_an_agent_not_asked_for_or_twice_or_in_another_format_is_refused() {
        let asked = names(&["default"]);
        let other = REPORT.replace("\"scout\"", "\"intruder\"");
        assert!(parse(&other, &names(&["default", "scout"])).is_err());
        let twice = r#"{"format":1,"agents":[{"agent":"default","found":false},{"agent":"default","found":false}]}"#;
        assert!(parse(twice, &asked).unwrap_err().contains("twice"));
        let format = r#"{"format":2,"agents":[]}"#;
        assert!(parse(format, &asked).unwrap_err().contains("format 2"));
        let extra = r#"{"format":1,"agents":[],"more":1}"#;
        assert!(parse(extra, &asked).is_err());
        let negative = r#"{"format":1,"agents":[{"agent":"default","models":[{"model":null,"chats":1,"calls":null,"tokens":{},"cost":{"usd":-1.0,"kind":"actual"}}]}]}"#;
        assert!(parse(negative, &asked).unwrap_err().contains("cost"));
        let error = r#"{"format":1,"agents":[{"agent":"default","error":"state.db: locked"}]}"#;
        assert_eq!(
            parse(error, &asked).unwrap()[0].usage,
            Fact::CannotTell("state.db: locked".into())
        );
    }

    #[test]
    fn tokens_add_up_leaving_a_count_no_model_had_unknown() {
        let mut sum = Tokens::default();
        sum.add(&Tokens {
            input: Some(1),
            output: Some(2),
            ..Tokens::default()
        });
        sum.add(&Tokens {
            input: Some(10),
            cache_read: Some(5),
            ..Tokens::default()
        });
        assert_eq!(sum.input, Some(11));
        assert_eq!(sum.output, Some(2));
        assert_eq!(sum.cache_read, Some(5));
        assert_eq!(sum.reasoning, None);
        assert_eq!(Tokens::default().cache_hit(), None);
    }
}
