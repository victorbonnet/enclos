//! `enclos status`: what is on this host, what it costs on disk, and what
//! the user could do about it (issue #29). A read: no lock, no audit
//! entry, and nothing runs in a sandbox, so it works on stopped ones.
//!
//! Facts come from enclos's own records (trusted) and from the sandbox
//! home, which the sandbox writes. The runtime adapter only names paths;
//! every read here follows ADR 0023: no link is followed, sizes and counts
//! are bounded, and "cannot tell" is an answer.

use std::collections::{HashMap, HashSet};
use std::io::ErrorKind;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

use serde::Serialize;

use super::Engine;
use crate::error::{Error, Result};
use crate::model::Timestamp;
use crate::model::now;
use crate::model::sandbox::{SandboxName, SandboxRecord, SandboxState};
use crate::model::session::SessionKind;
use crate::runtime::{DiskPart, RuntimeAdapter, ValueAt, adapter};
use crate::service::ServiceStatus;

/// Past this, a sandbox nobody used is worth a suggestion.
pub const IDLE_DAYS: i64 = 30;
/// How far back refused destinations count.
const REFUSED_DAYS: i64 = 7;
/// The most entries the walker reads in one sandbox before it stops and
/// says its total is a lower bound.
const MAX_ENTRIES: usize = 1_000_000;
/// The largest file of the sandbox home read for a fact.
const MAX_FACT_FILE: u64 = 256 * 1024;
/// The longest text of the sandbox home shown, such as a model name.
const MAX_FACT_TEXT: usize = 120;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StatusView {
    /// The enclos data folder.
    pub data: PathBuf,
    pub sandboxes: Vec<SandboxStatus>,
    pub suggestions: Vec<Suggestion>,
}

impl StatusView {
    /// Every sandbox's folder, together.
    pub fn bytes(&self) -> Size {
        self.sandboxes.iter().fold(
            Size {
                bytes: 0,
                complete: true,
            },
            |sum, s| Size {
                bytes: sum.bytes + s.disk.total.bytes,
                complete: sum.complete && s.disk.total.complete,
            },
        )
    }

    /// The agents in every sandbox: tracked, or built into their runtime.
    pub fn agent_count(&self) -> usize {
        self.sandboxes
            .iter()
            .flat_map(|s| s.agents.iter().flatten())
            .filter(|a| a.tracked || a.builtin)
            .count()
    }
}

/// A size, and whether the walk saw everything (`false`: at least this).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Size {
    pub bytes: u64,
    pub complete: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SandboxStatus {
    #[serde(serialize_with = "as_text")]
    pub name: SandboxName,
    /// `created`, `running`, `stopped`, or `failed: <reason>`.
    pub state: String,
    pub created_at: Timestamp,
    pub runtime: Option<RuntimeStatus>,
    /// The sandbox's services that launchd knows: label and state.
    pub services: Vec<ServiceLine>,
    pub policy_version: Option<u32>,
    pub running_sessions: usize,
    /// Some running session started under an older policy version.
    pub restart_needed: bool,
    pub last_connect: Option<Timestamp>,
    pub last_network: Option<Timestamp>,
    /// Destinations refused in the last 7 days.
    pub refused_recently: usize,
    /// `None` when the runtime cannot tell what agents it has.
    pub agents: Option<Vec<AgentStatus>>,
    pub disk: Disk,
}

impl SandboxStatus {
    /// Something of the sandbox runs: a session, or a service.
    pub fn in_use(&self) -> bool {
        self.running_sessions > 0 || self.services.iter().any(|s| s.state == "running")
    }

    /// The last time anything of the sandbox was used, by enclos's records.
    pub fn last_used(&self) -> Timestamp {
        [self.last_connect, self.last_network]
            .into_iter()
            .flatten()
            .fold(self.created_at, |a, b| a.max(b))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RuntimeStatus {
    pub kind: String,
    /// The runtime's name as people write it.
    pub name: &'static str,
    pub version: Option<String>,
    pub logged_in: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ServiceLine {
    pub label: String,
    /// `proxy` or `gateway`.
    pub unit: String,
    /// `running`, `loaded` (not running).
    pub state: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AgentStatus {
    pub name: String,
    /// The runtime's built-in agent: no record, never added or removed.
    pub builtin: bool,
    /// enclos has a record of it.
    pub tracked: bool,
    /// Whether the runtime has it; `None`: cannot tell.
    pub in_runtime: Option<bool>,
    /// Its name is a valid agent name, so `enclos agent add` can track it.
    pub trackable: bool,
    pub last_active: Option<Timestamp>,
    pub bytes: Option<u64>,
    pub model: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Disk {
    /// The whole sandbox folder: what `enclos sandbox rm` frees.
    pub total: Size,
    /// The parts the adapter names; `None` when it names none.
    pub runtime: Option<u64>,
    pub caches: Option<u64>,
    pub agents: Option<u64>,
    pub other: u64,
}

/// Something the user could do, with the existing command that does it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Suggestion {
    /// `lab` or `lab/writer`.
    pub target: String,
    pub reason: String,
    pub command: String,
}

impl Engine {
    /// The overview of every sandbox, or of one.
    pub fn status(&self, only: Option<&SandboxName>) -> Result<StatusView> {
        let records = match only {
            Some(name) => vec![self.state.get(name)?.ok_or_else(|| Error::NoSuchSandbox {
                name: name.to_string(),
            })?],
            None => self.state.list()?,
        };
        let now = now();
        let mut sandboxes = Vec::new();
        for record in records {
            let runtime = record.runtime.map(adapter);
            sandboxes.push(self.sandbox_status(record, runtime.as_deref(), now)?);
        }
        let suggestions = suggest(&sandboxes, now);
        Ok(StatusView {
            data: self.layout.data().to_owned(),
            sandboxes,
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
        let running = self.state.sessions(&name, true)?;
        let last_connect = self
            .state
            .sessions(&name, false)?
            .iter()
            .filter(|s| s.kind == SessionKind::Interactive)
            .map(|s| s.started_at)
            .max();
        let since = now
            .checked_sub(jiff::SignedDuration::from_hours(24 * REFUSED_DAYS))
            .unwrap_or(now);
        let refused_recently = self
            .state
            .denied(&name)?
            .iter()
            .filter(|d| d.last >= since)
            .count();
        let services = self
            .service_status(&name)
            .into_iter()
            .map(|(label, status)| ServiceLine {
                unit: label.rsplit('.').next().unwrap_or("").to_owned(),
                label,
                state: match status {
                    ServiceStatus::Running { .. } => "running",
                    ServiceStatus::Loaded => "loaded",
                    ServiceStatus::NotLoaded => "not loaded",
                }
                .to_owned(),
            })
            .collect();

        let agents = match runtime {
            Some(rt) => self.agent_statuses(&name, &home, rt)?,
            None => None,
        };
        let mut parts: Vec<(PathBuf, Slot)> = runtime
            .map(|rt| rt.disk_parts())
            .unwrap_or_default()
            .into_iter()
            .filter_map(|(part, rel)| Some((home.join(plain(&rel)?), Slot::Part(part))))
            .collect();
        let agent_folders: Vec<(String, PathBuf)> = match (runtime, &agents) {
            (Some(rt), Some(list)) => list
                .iter()
                .filter_map(|a| {
                    let rel = rt.agent_facts(&a.name).folder?;
                    Some((a.name.clone(), home.join(plain(&rel)?)))
                })
                .collect(),
            _ => Vec::new(),
        };
        parts.extend(
            agent_folders
                .iter()
                .map(|(agent, path)| (path.clone(), Slot::Agent(agent.clone()))),
        );
        let usage = walk(&dir, &parts, MAX_ENTRIES);
        let named = |slot: &Slot| usage.by_slot.get(slot).copied().unwrap_or(0);
        let has = |part: DiskPart| parts.iter().any(|(_, s)| *s == Slot::Part(part));
        let agents = agents.map(|list| {
            list.into_iter()
                .map(|mut a| {
                    if agent_folders.iter().any(|(n, _)| *n == a.name) {
                        a.bytes = Some(named(&Slot::Agent(a.name.clone())));
                    }
                    a
                })
                .collect::<Vec<_>>()
        });
        let agents_bytes = (!agent_folders.is_empty()).then(|| {
            agent_folders
                .iter()
                .map(|(n, _)| named(&Slot::Agent(n.clone())))
                .sum()
        });
        let disk = Disk {
            total: Size {
                bytes: usage.total,
                complete: usage.complete,
            },
            runtime: has(DiskPart::Runtime).then(|| named(&Slot::Part(DiskPart::Runtime))),
            caches: has(DiskPart::Cache).then(|| named(&Slot::Part(DiskPart::Cache))),
            agents: agents_bytes,
            other: named(&Slot::Other),
        };

        Ok(SandboxStatus {
            runtime: match (record.runtime, runtime) {
                (Some(kind), Some(rt)) => {
                    let facts = rt.runtime_facts();
                    Some(RuntimeStatus {
                        kind: kind.to_string(),
                        name: kind.display_name(),
                        version: facts.version.as_ref().and_then(|v| read_value(&home, v)),
                        logged_in: facts.login.as_deref().and_then(|f| exists(&home, f)),
                    })
                }
                _ => None,
            },
            state: state_text(&record.state),
            created_at: record.created_at,
            services,
            policy_version: active,
            running_sessions: running.len(),
            restart_needed: active.is_some_and(|v| running.iter().any(|s| s.version != v)),
            last_connect,
            last_network: self.state.last_event(&name)?,
            refused_recently,
            agents,
            disk,
            name,
        })
    }

    /// The agents of a sandbox, tracked or only in the runtime. `None` when
    /// the runtime has no named agents and enclos tracks none.
    fn agent_statuses(
        &self,
        name: &SandboxName,
        home: &Path,
        runtime: &dyn RuntimeAdapter,
    ) -> Result<Option<Vec<AgentStatus>>> {
        let tracked = self.state.agents(name)?;
        let found = runtime.agents_in(home);
        let builtin = runtime.builtin_agent();
        if found.is_none() && tracked.is_empty() && builtin.is_none() {
            return Ok(None);
        }
        let mut names: Vec<String> = builtin.into_iter().map(str::to_owned).collect();
        names.extend(tracked.iter().map(|a| a.name.to_string()));
        for n in found.iter().flatten() {
            if !names.contains(n) {
                names.push(n.clone());
            }
        }
        let statuses = names
            .into_iter()
            .map(|agent| {
                let facts = runtime.agent_facts(&agent);
                let is_builtin = builtin == Some(agent.as_str());
                AgentStatus {
                    builtin: is_builtin,
                    tracked: tracked.iter().any(|t| t.name.as_str() == agent),
                    in_runtime: match is_builtin {
                        true => Some(true),
                        false => found.as_ref().map(|f| f.contains(&agent)),
                    },
                    trackable: agent.parse::<crate::model::agent::AgentName>().is_ok(),
                    last_active: facts
                        .activity
                        .iter()
                        .filter_map(|f| modified(home, f))
                        .max(),
                    model: facts.model.as_ref().and_then(|v| read_value(home, v)),
                    bytes: None,
                    name: agent,
                }
            })
            .collect();
        Ok(Some(statuses))
    }
}

fn as_text<S: serde::Serializer>(
    value: &impl std::fmt::Display,
    s: S,
) -> std::result::Result<S::Ok, S::Error> {
    s.collect_str(value)
}

fn state_text(state: &SandboxState) -> String {
    match state {
        SandboxState::Created => "created".into(),
        SandboxState::Running => "running".into(),
        SandboxState::Stopped => "stopped".into(),
        SandboxState::Failed { reason } => format!("failed: {reason}"),
    }
}

/// The rules behind "What you could do". Each names an existing command;
/// enclos never acts on its own, and "unused" uses enclos's own times.
pub fn suggest(sandboxes: &[SandboxStatus], now: Timestamp) -> Vec<Suggestion> {
    let mut out = Vec::new();
    let mut add = |target: String, reason: String, command: String| {
        out.push(Suggestion {
            target,
            reason,
            command,
        })
    };
    for s in sandboxes {
        let sb = &s.name;
        for a in s.agents.iter().flatten() {
            let target = format!("{sb}/{}", a.name);
            match (a.tracked, a.in_runtime) {
                _ if a.builtin => {}
                (false, Some(true)) if a.trackable => add(
                    target.clone(),
                    "made inside the sandbox, not tracked".into(),
                    format!("enclos agent add {target}"),
                ),
                (true, Some(false)) => add(
                    target.clone(),
                    "the runtime no longer has it".into(),
                    format!("enclos agent rm {target}"),
                ),
                _ => {}
            }
        }
        if s.refused_recently > 0 {
            add(
                sb.to_string(),
                format!(
                    "{} destinations refused in the last {REFUSED_DAYS} days",
                    s.refused_recently
                ),
                format!("enclos net denied {sb}"),
            );
        }
        if s.restart_needed {
            add(
                sb.to_string(),
                "sessions run an older policy version".into(),
                format!("enclos sandbox restart {sb}"),
            );
        }
        match &s.runtime {
            None => add(
                sb.to_string(),
                "no runtime yet".into(),
                format!("enclos runtime install <runtime> --sandbox {sb}"),
            ),
            Some(rt) if rt.logged_in == Some(false) => add(
                sb.to_string(),
                format!("{} is not logged in", rt.name),
                format!("enclos runtime login {sb}"),
            ),
            Some(_) => {}
        }
        if s.agents.as_ref().is_some_and(|a| a.is_empty()) {
            add(
                sb.to_string(),
                "has a runtime but no agents".into(),
                format!("enclos agent add {sb}/main"),
            );
        }
        let idle_days = (now.as_second() - s.last_used().as_second()) / 86_400;
        if !s.in_use() && idle_days >= IDLE_DAYS {
            add(
                sb.to_string(),
                format!(
                    "unused for {idle_days} days; removing it frees {}{}",
                    if s.disk.total.complete { "~" } else { "≥" },
                    human_bytes(s.disk.total.bytes)
                ),
                format!("enclos sandbox rm {sb}"),
            );
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

/// `rel` as plain components only: no `..`, no root, no prefix.
fn plain(rel: &Path) -> Option<PathBuf> {
    rel.components()
        .all(|c| matches!(c, Component::Normal(_)))
        .then(|| rel.to_owned())
}

enum Lookup {
    Found(PathBuf, std::fs::Metadata),
    Missing,
    /// A link on the way, or something that cannot be read.
    CannotTell,
}

/// `rel` under `home`, walking one component at a time so no link is ever
/// followed, the last one included.
fn lookup(home: &Path, rel: &Path) -> Lookup {
    let Some(rel) = plain(rel) else {
        return Lookup::CannotTell;
    };
    let mut path = home.to_owned();
    let mut meta = None;
    for part in rel.components() {
        path.push(part);
        match path.symlink_metadata() {
            Ok(m) if m.file_type().is_symlink() => return Lookup::CannotTell,
            Ok(m) => meta = Some(m),
            Err(e) if e.kind() == ErrorKind::NotFound => return Lookup::Missing,
            Err(_) => return Lookup::CannotTell,
        }
    }
    match meta {
        Some(m) => Lookup::Found(path, m),
        None => Lookup::CannotTell,
    }
}

fn exists(home: &Path, rel: &Path) -> Option<bool> {
    match lookup(home, rel) {
        Lookup::Found(..) => Some(true),
        Lookup::Missing => Some(false),
        Lookup::CannotTell => None,
    }
}

fn modified(home: &Path, rel: &Path) -> Option<Timestamp> {
    match lookup(home, rel) {
        Lookup::Found(_, meta) => Timestamp::try_from(meta.modified().ok()?).ok(),
        _ => None,
    }
}

/// A value from a small YAML file of the home, made safe to print.
fn read_value(home: &Path, at: &ValueAt) -> Option<String> {
    let Lookup::Found(path, meta) = lookup(home, &at.file) else {
        return None;
    };
    if !meta.is_file() || meta.len() > MAX_FACT_FILE {
        return None;
    }
    let text = std::fs::read_to_string(path).ok()?;
    at.keys
        .iter()
        .find_map(|key| yaml_value(&text, key))
        .map(|v| printable(&v))
}

/// A scalar under a dotted key of a YAML mapping, such as `model.default`.
/// Enough YAML for a runtime's config: nested mappings by indentation,
/// quoted or plain scalars, comments.
pub(super) fn yaml_value(text: &str, key: &str) -> Option<String> {
    let want: Vec<&str> = key.split('.').collect();
    let mut path: Vec<(usize, String)> = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('-') {
            continue;
        }
        let indent = line.len() - trimmed.len();
        let Some((k, rest)) = trimmed.split_once(':') else {
            continue;
        };
        let k = k.trim().trim_matches(|c| c == '"' || c == '\'');
        while path.last().is_some_and(|(i, _)| *i >= indent) {
            path.pop();
        }
        path.push((indent, k.to_owned()));
        if path
            .iter()
            .map(|(_, k)| k.as_str())
            .eq(want.iter().copied())
        {
            let value = rest.trim();
            let value = if let Some(q) = value.strip_prefix('"') {
                q.split('"').next().unwrap_or("")
            } else if let Some(q) = value.strip_prefix('\'') {
                q.split('\'').next().unwrap_or("")
            } else {
                value.split(" #").next().unwrap_or("").trim()
            };
            return (!value.is_empty()).then(|| value.to_owned());
        }
    }
    None
}

/// Text the sandbox wrote, safe for a terminal: control characters escaped,
/// and cut to a length.
pub(super) fn printable(text: &str) -> String {
    let mut out = String::new();
    for c in text.chars().take(MAX_FACT_TEXT) {
        if c.is_control() {
            out.extend(c.escape_default());
        } else {
            out.push(c);
        }
    }
    out
}

// ---- Disk usage ----

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum Slot {
    Part(DiskPart),
    Agent(String),
    Other,
}

struct Usage {
    total: u64,
    complete: bool,
    by_slot: HashMap<Slot, u64>,
}

/// What removing `root` would free: allocated blocks, with `lstat` (a link
/// counts as itself, never its target), each hard-linked file once, and at
/// most `budget` entries. Everything under one of `parts` counts toward it.
fn walk(root: &Path, parts: &[(PathBuf, Slot)], budget: usize) -> Usage {
    let mut usage = Usage {
        total: 0,
        complete: true,
        by_slot: HashMap::new(),
    };
    let mut seen = HashSet::new();
    let mut entries = 0;
    let Ok(meta) = root.symlink_metadata() else {
        return usage;
    };
    let mut stack = vec![(root.to_owned(), Slot::Other, meta)];
    while let Some((path, slot, meta)) = stack.pop() {
        entries += 1;
        if entries > budget {
            usage.complete = false;
            break;
        }
        let counted = meta.nlink() <= 1 || meta.is_dir() || seen.insert((meta.dev(), meta.ino()));
        if counted {
            let bytes = meta.blocks() * 512;
            usage.total += bytes;
            *usage.by_slot.entry(slot.clone()).or_default() += bytes;
        }
        if !meta.is_dir() {
            continue;
        }
        let Ok(children) = std::fs::read_dir(&path) else {
            continue;
        };
        for child in children.flatten() {
            // `DirEntry::metadata` does not follow a link.
            let Ok(meta) = child.metadata() else {
                continue;
            };
            let child = child.path();
            let slot = parts
                .iter()
                .find(|(p, _)| *p == child)
                .map_or_else(|| slot.clone(), |(_, s)| s.clone());
            stack.push((child, slot, meta));
        }
    }
    usage
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(path: &Path, bytes: usize) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, vec![b'x'; bytes]).unwrap();
    }

    #[test]
    fn the_walker_counts_parts_and_never_follows_a_link() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        file(&outside.path().join("big"), 2_000_000);
        file(&root.path().join("home/rt/lib"), 100_000);
        file(&root.path().join("home/other"), 10_000);
        std::os::unix::fs::symlink(outside.path(), root.path().join("home/rt/link")).unwrap();
        let parts = [(root.path().join("home/rt"), Slot::Part(DiskPart::Runtime))];
        let usage = walk(root.path(), &parts, 1000);
        assert!(usage.complete);
        let runtime = usage.by_slot[&Slot::Part(DiskPart::Runtime)];
        assert!((100_000..200_000).contains(&runtime), "{runtime}");
        assert!(usage.total < 1_000_000, "the link's target was counted");
    }

    #[test]
    fn a_hard_linked_file_counts_once() {
        let root = tempfile::tempdir().unwrap();
        file(&root.path().join("a"), 500_000);
        std::fs::hard_link(root.path().join("a"), root.path().join("b")).unwrap();
        let usage = walk(root.path(), &[], 1000);
        assert!(usage.total < 1_000_000, "{}", usage.total);
        assert!(usage.total >= 500_000);
    }

    #[test]
    fn an_oversized_tree_stops_at_the_budget_and_says_so() {
        let root = tempfile::tempdir().unwrap();
        for i in 0..50 {
            file(&root.path().join(format!("d/{i}")), 10);
        }
        let usage = walk(root.path(), &[], 20);
        assert!(!usage.complete);
        assert!(walk(root.path(), &[], 1000).complete);
    }

    #[test]
    fn reads_never_follow_a_link_and_say_when_they_cannot_tell() {
        let home = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        file(&outside.path().join("config.yaml"), 0);
        std::fs::write(
            outside.path().join("config.yaml"),
            "model:\n  default: host\n",
        )
        .unwrap();
        std::os::unix::fs::symlink(outside.path(), home.path().join("linked")).unwrap();
        let at = |file: &str| ValueAt {
            file: file.into(),
            keys: vec!["model.default"],
        };
        assert_eq!(read_value(home.path(), &at("linked/config.yaml")), None);
        assert_eq!(exists(home.path(), Path::new("linked/config.yaml")), None);
        assert_eq!(exists(home.path(), Path::new("missing")), Some(false));
        assert_eq!(exists(home.path(), Path::new("../x")), None);
        file(&home.path().join("a/config.yaml"), 0);
        std::fs::write(
            home.path().join("a/config.yaml"),
            "x: 1\nmodel:\n  # the model\n  default: \"gpt-6.1\u{1b}[2J\"\nother: 2\n",
        )
        .unwrap();
        assert_eq!(
            read_value(home.path(), &at("a/config.yaml")).as_deref(),
            Some("gpt-6.1\\u{1b}[2J")
        );
    }

    #[test]
    fn yaml_values_are_found_by_dotted_key() {
        let text = "model:\n  default: gpt-6.1-sol # comment\n  provider: 'openai'\nother:\n  default: no\n";
        assert_eq!(
            yaml_value(text, "model.default").as_deref(),
            Some("gpt-6.1-sol")
        );
        assert_eq!(
            yaml_value(text, "model.provider").as_deref(),
            Some("openai")
        );
        assert_eq!(yaml_value(text, "model.missing"), None);
        assert_eq!(yaml_value("model: gpt\n", "model"), Some("gpt".into()));
        assert_eq!(printable("a\u{1b}[31mb\n"), "a\\u{1b}[31mb\\n");
    }

    #[test]
    fn sizes_read_like_finder() {
        assert_eq!(human_bytes(512), "512 B");
        assert_eq!(human_bytes(4_700_000), "4.7 MB");
        assert_eq!(human_bytes(2_400_000_000), "2.4 GB");
        assert_eq!(human_bytes(330_000_000), "330 MB");
    }
}
