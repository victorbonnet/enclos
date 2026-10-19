//! `enclos status`: what is on this host, what it costs on disk, and what
//! you could do about it (issue #29).

use clap::Args;

use enclos::engine::{
    AgentStatus, Engine, IDLE_DAYS, SandboxStatus, Size, StatusView, human_bytes,
};
use enclos::error::{Result, exit};
use enclos::model::sandbox::SandboxName;
use enclos::model::{Timestamp, now};

#[derive(Args)]
pub struct StatusArgs {
    /// Only this sandbox.
    sandbox: Option<SandboxName>,
    /// Print JSON: sizes in bytes, times in RFC 3339, `null` for "cannot tell".
    #[arg(long)]
    json: bool,
}

pub fn run(engine: &Engine, args: StatusArgs) -> Result<u8> {
    let view = engine.status(args.sandbox.as_ref())?;
    if args.json {
        let mut json = serde_json::to_value(&view).expect("the view serializes");
        let total = view.bytes();
        json["bytes"] = total.bytes.into();
        json["complete"] = total.complete.into();
        json["idle_days"] = IDLE_DAYS.into();
        println!(
            "{}",
            serde_json::to_string_pretty(&json).expect("JSON prints")
        );
        return Ok(exit::OK);
    }
    print(&view);
    Ok(exit::OK)
}

fn print(view: &StatusView) {
    if view.sandboxes.is_empty() {
        println!("No sandboxes yet. Create one with `enclos sandbox create lab`.");
        return;
    }
    let count = |n: usize, one: &str, many: &str| match n {
        1 => format!("1 {one}"),
        n => format!("{n} {many}"),
    };
    println!(
        "{}, {}, {} in {}",
        count(view.sandboxes.len(), "sandbox", "sandboxes"),
        count(view.agent_count(), "agent", "agents"),
        size(view.bytes()),
        tilde(&view.data.display().to_string())
    );
    let now = now();
    let width = view
        .sandboxes
        .iter()
        .map(|s| s.name.as_str().len())
        .max()
        .unwrap_or(0);
    for s in &view.sandboxes {
        println!();
        print_sandbox(s, width, now);
    }
    if !view.suggestions.is_empty() {
        println!("\nWhat you could do");
        let target = view
            .suggestions
            .iter()
            .map(|s| s.target.len())
            .max()
            .unwrap_or(0);
        let reason = view
            .suggestions
            .iter()
            .map(|s| s.reason.chars().count())
            .max()
            .unwrap_or(0);
        for s in &view.suggestions {
            println!(
                "  {:<target$}  {:<reason$}  {}",
                s.target, s.reason, s.command
            );
        }
    }
}

fn print_sandbox(s: &SandboxStatus, width: usize, now: Timestamp) {
    let runtime = match &s.runtime {
        None => "no runtime".to_owned(),
        Some(rt) => {
            let mut text = rt.name.to_owned();
            if let Some(v) = &rt.version {
                text.push(' ');
                text.push_str(v);
            }
            match rt.logged_in {
                Some(true) => text.push_str(", logged in"),
                Some(false) => text.push_str(", not logged in"),
                None => {}
            }
            text
        }
    };
    println!(
        "{:<width$}  {:<9} {:<34} {:>9}",
        s.name.as_str(),
        s.state,
        runtime,
        size(s.disk.total)
    );

    let mut facts = Vec::new();
    if !s.services.is_empty() {
        let services: Vec<String> = s
            .services
            .iter()
            .map(|l| format!("{} {}", l.unit, l.state))
            .collect();
        facts.push(services.join(", "));
    }
    if let Some(v) = s.policy_version {
        facts.push(format!("policy v{v}"));
    }
    if s.restart_needed {
        facts.push("sessions on an older policy".into());
    }
    facts.push(format!("last connect {}", ago(s.last_connect, now)));
    facts.push(format!("last network {}", ago(s.last_network, now)));
    if s.agents.as_ref().is_some_and(|a| a.is_empty()) {
        facts.push("no agents".into());
    }
    println!("  {}", facts.join(" · "));

    if let Some(agents) = s.agents.as_ref().filter(|a| !a.is_empty()) {
        let name = agents
            .iter()
            .map(|a| a.name.len())
            .max()
            .unwrap_or(0)
            .max(5);
        println!(
            "  {:<name$}  {:<12}  {:>9}  MODEL",
            "AGENT", "LAST ACTIVE", "SIZE"
        );
        for a in agents {
            let line = format!(
                "  {:<name$}  {:<12}  {:>9}  {}",
                a.name,
                ago(a.last_active, now),
                a.bytes.map_or("-".to_owned(), human_bytes),
                a.model.as_deref().unwrap_or("-"),
            );
            match note(a) {
                Some(note) => println!("{line}    {note}"),
                None => println!("{line}"),
            }
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
            parts.push(format!("{label} {}", human_bytes(b)));
        }
    }
    if !parts.is_empty() {
        parts.push(format!("other {}", human_bytes(d.other)));
        println!("  disk: {}", parts.join(" · "));
    }
}

fn note(a: &AgentStatus) -> Option<&'static str> {
    if a.builtin {
        return Some("built in");
    }
    match (a.tracked, a.in_runtime) {
        (false, Some(true)) if a.trackable => Some("made inside the sandbox, not tracked"),
        (false, Some(true)) => Some("a name enclos cannot track"),
        (true, Some(false)) => Some("the runtime no longer has it"),
        _ => None,
    }
}

fn size(s: Size) -> String {
    match s.complete {
        true => human_bytes(s.bytes),
        false => format!("≥ {}", human_bytes(s.bytes)),
    }
}

/// How long ago, roughly.
fn ago(at: Option<Timestamp>, now: Timestamp) -> String {
    let Some(at) = at else {
        return "never".into();
    };
    let seconds = (now.as_second() - at.as_second()).max(0);
    match seconds {
        0..60 => "just now".into(),
        60..3_600 => format!("{}m ago", seconds / 60),
        3_600..86_400 => format!("{}h ago", seconds / 3_600),
        _ if seconds < 30 * 86_400 => format!("{}d ago", seconds / 86_400),
        _ => format!("{} days ago", seconds / 86_400),
    }
}

/// A path with the user's home folder written `~`.
fn tilde(path: &str) -> String {
    match std::env::var("HOME") {
        Ok(home) if !home.is_empty() && path.starts_with(&home) => {
            format!("~{}", &path[home.len()..])
        }
        _ => path.to_owned(),
    }
}
