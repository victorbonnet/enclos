//! `enclos status`: what is on this host, what it costs on disk, and what
//! you could do about it (issue #29).

use std::path::Path;

use clap::Args;

use enclos::engine::Engine;
use enclos::engine::{
    AgentKind, AgentStatus, Fact, Presence, SandboxStatus, ServiceState, StatusView, human_bytes,
};
use enclos::error::{Result, exit};
use enclos::model::sandbox::{SandboxName, SandboxState};
use enclos::model::{Timestamp, now};

#[derive(Args)]
pub struct StatusArgs {
    /// Only this sandbox.
    sandbox: Option<SandboxName>,
    /// Print JSON: sizes in bytes, times in RFC 3339, and each fact read
    /// from a sandbox as `{"known": …}`, `"absent"`, `{"cannot_tell": why}`
    /// or `"not_provided"`.
    #[arg(long)]
    json: bool,
}

pub fn run(engine: &Engine, args: StatusArgs) -> Result<u8> {
    let view = engine.status(args.sandbox.as_ref())?;
    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&view).expect("the view serializes")
        );
        return Ok(exit::OK);
    }
    print(&view, now(), std::env::var("HOME").ok().as_deref());
    Ok(exit::OK)
}

fn print(view: &StatusView, now: Timestamp, user_home: Option<&str>) {
    if view.sandboxes.is_empty() && view.unlisted.is_empty() {
        println!("No sandboxes yet. Create one with `enclos sandbox create lab`.");
        return;
    }
    println!(
        "{}, {}, {} in {}",
        count(
            view.sandboxes.len() + view.unlisted.len(),
            "sandbox",
            "sandboxes"
        ),
        agents(view.agent_count(), view.untracked_count()),
        size(view.bytes, view.complete),
        tilde(&view.data, user_home)
    );
    let width = view
        .sandboxes
        .iter()
        .map(|s| s.name.as_str())
        .chain(view.unlisted.iter().map(|u| u.name.as_str()))
        .map(str::len)
        .max()
        .unwrap_or(0);
    for s in &view.sandboxes {
        println!();
        print_sandbox(s, width, now);
    }
    for u in &view.unlisted {
        println!();
        println!("{:<width$}  cannot tell: {}", u.name.as_str(), u.error);
    }
    if !view.suggestions.is_empty() {
        println!("\nWhat you could do");
        let rows: Vec<(String, String, String)> = view
            .suggestions
            .iter()
            .map(|s| (s.target(), s.reason(), s.command()))
            .collect();
        let target = rows.iter().map(|r| r.0.len()).max().unwrap_or(0);
        let reason = rows.iter().map(|r| r.1.chars().count()).max().unwrap_or(0);
        for (t, r, c) in rows {
            println!("  {t:<target$}  {r:<reason$}  {c}");
        }
    }
}

fn state_text(state: &SandboxState) -> String {
    match state {
        SandboxState::Created => "created".into(),
        SandboxState::Running => "running".into(),
        SandboxState::Stopped => "stopped".into(),
        SandboxState::Failed { reason } => format!("failed: {reason}"),
    }
}

/// A fact as a word in a table: `-` when nothing names it or nothing is
/// there, `?` when it cannot tell.
fn fact<T>(f: &Fact<T>, shown: impl Fn(&T) -> String) -> String {
    match f {
        Fact::Known(v) => shown(v),
        Fact::Absent | Fact::NotProvided => "-".into(),
        Fact::CannotTell(_) => "?".into(),
    }
}

fn print_sandbox(s: &SandboxStatus, width: usize, now: Timestamp) {
    let complete = s.disk.incomplete.is_none();
    let runtime = match &s.runtime {
        None => "no runtime".to_owned(),
        Some(rt) => {
            let mut text = rt.name.to_owned();
            if let Fact::Known(v) = &rt.version {
                text.push(' ');
                text.push_str(v);
            }
            match (&rt.installed, &rt.logged_in) {
                (Fact::Known(false), _) => text.push_str(", files missing"),
                (_, Fact::Known(true)) => text.push_str(", logged in"),
                (_, Fact::Known(false)) => text.push_str(", not logged in"),
                (_, Fact::CannotTell(_)) => text.push_str(", login cannot tell"),
                _ => {}
            }
            text
        }
    };
    println!(
        "{:<width$}  {:<9} {:<34} {:>9}",
        s.name.as_str(),
        state_text(&s.state),
        runtime,
        size(s.disk.total, complete)
    );

    let mut facts = Vec::new();
    match &s.services {
        Fact::Known(list) if !list.is_empty() => {
            let services: Vec<String> = list
                .iter()
                .map(|l| {
                    let state = match l.state {
                        ServiceState::Running { .. } => "running",
                        ServiceState::Loaded => "loaded",
                        ServiceState::NotLoaded => "not loaded",
                    };
                    format!("{} {state}", l.service)
                })
                .collect();
            facts.push(services.join(", "));
        }
        Fact::CannotTell(why) => facts.push(format!("services: cannot tell ({why})")),
        _ => {}
    }
    if let Some(v) = s.policy_version {
        facts.push(format!("policy v{v}"));
    }
    if s.restart_needed {
        facts.push("sessions on a replaced policy".into());
    }
    if s.gone_sessions > 0 {
        facts.push(format!("{} sessions gone, not recorded", s.gone_sessions));
    }
    facts.push(format!("last connect {}", ago(s.last_connect, now)));
    facts.push(format!("last network {}", ago(s.last_network, now)));
    if s.agents
        .as_ref()
        .is_some_and(|l| l.agents.is_empty() && l.unreadable.is_none())
    {
        facts.push("no agents".into());
    }
    println!("  {}", facts.join(" · "));
    if let Some(why) = &s.policy_refused {
        println!("  nothing new starts here, and what runs keeps its policy: {why}");
    }

    if let Some(list) = &s.agents {
        if let Some(why) = &list.unreadable {
            let runtime = s.runtime.as_ref().map_or("the runtime", |r| r.name);
            println!("  enclos cannot read {runtime}'s agents: {why}");
        }
        if !list.agents.is_empty() {
            print_agents(&list.agents, complete, now);
        }
    }

    let d = &s.disk;
    let mut parts = Vec::new();
    for (label, bytes) in [
        ("runtime", d.runtime),
        ("caches", d.caches),
        ("agents", d.agents),
    ] {
        if let Some(b) = bytes {
            parts.push(format!("{label} {}", size(b, complete)));
        }
    }
    if !parts.is_empty() {
        parts.push(format!("other {}", size(d.other, complete)));
        println!("  disk: {}", parts.join(" · "));
    }
    if let Some(why) = &d.incomplete {
        println!("  sizes are lower bounds: {why}");
    }
}

fn print_agents(agents: &[AgentStatus], complete: bool, now: Timestamp) {
    let name = agents
        .iter()
        .map(|a| a.name.as_str().len())
        .max()
        .unwrap_or(0)
        .max(5);
    println!(
        "  {:<name$}  {:<12}  {:>9}  MODEL",
        "AGENT", "LAST ACTIVE", "SIZE"
    );
    for a in agents {
        let last = match &a.last_active {
            Fact::Known(t) => ago(Some(*t), now),
            Fact::Absent => "never".into(),
            other => fact(other, |_| String::new()),
        };
        let line = format!(
            "  {:<name$}  {:<12}  {:>9}  {}",
            a.name.as_str(),
            last,
            fact(&a.bytes, |b| size(*b, complete)),
            fact(&a.model, Clone::clone),
        );
        match note(a) {
            Some(note) => println!("{line}    {note}"),
            None => println!("{line}"),
        }
    }
}

fn note(a: &AgentStatus) -> Option<&'static str> {
    match a.kind {
        AgentKind::Builtin => Some("built in"),
        AgentKind::Untracked => Some("made inside the sandbox, not tracked"),
        AgentKind::Untrackable => Some("a name enclos cannot track"),
        AgentKind::Tracked {
            in_runtime: Presence::Gone,
        } => Some("the runtime no longer has it"),
        AgentKind::Tracked { .. } => None,
    }
}

fn size(bytes: u64, complete: bool) -> String {
    match complete {
        true => human_bytes(bytes),
        false => format!("≥ {}", human_bytes(bytes)),
    }
}

/// How long ago, roughly.
fn ago(at: Option<Timestamp>, now: Timestamp) -> String {
    let Some(at) = at else {
        return "never".into();
    };
    let seconds = now.as_second() - at.as_second();
    match seconds {
        ..0 => "in the future".into(),
        0..60 => "just now".into(),
        60..3_600 => format!("{}m ago", seconds / 60),
        3_600..86_400 => format!("{}h ago", seconds / 3_600),
        _ if seconds < 30 * 86_400 => format!("{}d ago", seconds / 86_400),
        _ => format!("{} days ago", seconds / 86_400),
    }
}

/// A path with the user's home folder written `~`.
fn tilde(path: &Path, user_home: Option<&str>) -> String {
    match user_home
        .filter(|h| !h.is_empty())
        .and_then(|h| path.strip_prefix(h).ok())
    {
        Some(rest) if rest.as_os_str().is_empty() => "~".into(),
        Some(rest) => format!("~/{}", rest.display()),
        None => path.display().to_string(),
    }
}

fn count(n: usize, one: &str, many: &str) -> String {
    match n {
        1 => format!("1 {one}"),
        n => format!("{n} {many}"),
    }
}

/// The header's agent count. The table also lists the agents enclos does
/// not track, so the header counts them apart to match it.
fn agents(tracked: usize, untracked: usize) -> String {
    let agents = count(tracked, "agent", "agents");
    match (tracked, untracked) {
        (_, 0) => agents,
        (0, n) => format!("{agents} ({n} not tracked)"),
        (_, n) => format!("{agents} ({n} more not tracked)"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_agent_count_says_how_many_are_not_tracked() {
        assert_eq!(agents(1, 0), "1 agent");
        assert_eq!(agents(2, 1), "2 agents (1 more not tracked)");
        assert_eq!(agents(0, 2), "0 agents (2 not tracked)");
    }

    #[test]
    fn times_read_as_how_long_ago() {
        let now: Timestamp = "2026-10-20T12:00:00Z".parse().unwrap();
        let before = |s: i64| Some(Timestamp::from_second(now.as_second() - s).unwrap());
        assert_eq!(ago(None, now), "never");
        assert_eq!(ago(before(-5), now), "in the future");
        assert_eq!(ago(before(59), now), "just now");
        assert_eq!(ago(before(60), now), "1m ago");
        assert_eq!(ago(before(3_600), now), "1h ago");
        assert_eq!(ago(before(29 * 86_400), now), "29d ago");
        assert_eq!(ago(before(30 * 86_400), now), "30 days ago");
    }

    #[test]
    fn the_home_folder_is_written_as_a_tilde_only_at_a_path_boundary() {
        let home = Some("/Users/alice");
        assert_eq!(tilde(Path::new("/Users/alice/.enclos"), home), "~/.enclos");
        assert_eq!(tilde(Path::new("/Users/alice"), home), "~");
        assert_eq!(
            tilde(Path::new("/Users/alicex/.enclos"), home),
            "/Users/alicex/.enclos"
        );
        assert_eq!(tilde(Path::new("/x"), None), "/x");
        assert_eq!(size(2_400_000_000, true), "2.4 GB");
        assert_eq!(size(2_400_000_000, false), "≥ 2.4 GB");
    }
}
