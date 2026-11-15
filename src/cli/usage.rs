//! `enclos usage`: what each agent used of its model providers, as its
//! runtime recorded it (issue #282).

use clap::Args;

use enclos::engine::{
    AgentRecords, AgentUsage, CostKind, Engine, Fact, ModelUsage, SandboxUsage, UsageView,
};
use enclos::error::{Error, Result, exit};
use enclos::model::audit::{Actor, Since};
use enclos::model::now;
use enclos::model::sandbox::SandboxName;

#[derive(Args)]
pub struct UsageArgs {
    /// Only this sandbox, read even when it is not running. Without it,
    /// every running sandbox.
    sandbox: Option<SandboxName>,
    /// Native chats active in this past window, such as 24h or 30d; each
    /// counts whole.
    #[arg(long, value_name = "DURATION", default_value = "7d")]
    since: Since,
}

pub fn run(engine: &Engine, by: &Actor, args: UsageArgs) -> Result<u8> {
    // A window reaching before any time enclos can name counts everything.
    let since = now()
        .checked_sub(args.since.duration())
        .unwrap_or(jiff::Timestamp::MIN);
    let view = engine.usage(by, args.sandbox.as_ref(), since)?;
    if super::output::json() {
        let shown = serde_json::to_value(&view).map_err(|source| Error::Json {
            what: "the usage",
            source,
        })?;
        super::output::emit(&shown);
        return Ok(exit::OK);
    }
    print(&view);
    Ok(exit::OK)
}

const HEAD: [&str; 12] = [
    "AGENT",
    "MODEL",
    "CHATS",
    "CALLS",
    "INPUT",
    "CACHE READ",
    "CACHE WRITE",
    "OUTPUT",
    "REASONING",
    "PER CALL",
    "CACHE HIT",
    "COST",
];

fn print(view: &UsageView) {
    if view.sandboxes.is_empty() {
        println!("No sandboxes yet.");
        return;
    }
    let since = view.since.strftime("%Y-%m-%d %H:%M UTC");
    for (i, s) in view.sandboxes.iter().enumerate() {
        if i > 0 {
            println!();
        }
        print_sandbox(s, &since.to_string());
    }
    println!(
        "\nTokens as each runtime recorded them, inside its sandbox: a guide to what an agent spends, not a bill."
    );
}

fn print_sandbox(s: &SandboxUsage, since: &str) {
    let runtime = s.runtime.unwrap_or("no runtime");
    let agents = match &s.agents {
        Fact::Known(agents) => agents,
        Fact::Absent => return println!("{}: no runtime", s.name),
        Fact::NotProvided => {
            return println!("{}: {runtime} keeps no usage enclos can read", s.name);
        }
        Fact::CannotTell(why) => return println!("{}: cannot tell ({why})", s.name),
    };
    println!(
        "{}: {runtime}, native chats active since {since}, each counted whole",
        s.name
    );
    let mut rows = vec![HEAD.map(str::to_owned).to_vec()];
    let mut notes = Vec::new();
    for a in agents {
        match &a.usage {
            Fact::Known(records) if records.models.is_empty() => {
                notes.push(format!("{}: no chats in this window", a.agent));
            }
            Fact::Known(records) => rows.extend(records.models.iter().map(|m| row(&a.agent, m))),
            Fact::Absent => notes.push(format!("{}: never used", a.agent)),
            Fact::NotProvided => notes.push(format!("{}: not provided", a.agent)),
            Fact::CannotTell(why) => notes.push(format!("{}: cannot tell ({why})", a.agent)),
        }
    }
    if rows.len() > 1 {
        print_table(&rows);
    }
    for note in notes {
        println!("  {note}");
    }
    let top = top_chats(agents);
    if !top.is_empty() {
        println!("  Native chats that used the most");
        for line in top {
            println!("    {line}");
        }
    }
}

fn row(agent: &str, m: &ModelUsage) -> Vec<String> {
    let t = &m.tokens;
    vec![
        agent.to_owned(),
        m.model.clone().unwrap_or_else(|| "?".into()),
        m.chats.to_string(),
        count(m.calls),
        count(t.input),
        count(t.cache_read),
        count(t.cache_write),
        count(t.output),
        count(t.reasoning),
        count(m.per_call()),
        t.cache_hit()
            .map(|h| format!("{:.0}%", h * 100.0))
            .unwrap_or_else(|| "-".into()),
        cost(m),
    ]
}

/// Counts read at a glance: 950, 83.1k, 1.2M; `-` when not counted.
fn count(n: Option<u64>) -> String {
    match n {
        None => "-".into(),
        Some(n) if n < 1_000 => n.to_string(),
        Some(n) if n < 1_000_000 => format!("{:.1}k", n as f64 / 1e3),
        Some(n) if n < 1_000_000_000 => format!("{:.1}M", n as f64 / 1e6),
        Some(n) => format!("{:.1}G", n as f64 / 1e9),
    }
}

fn cost(m: &ModelUsage) -> String {
    let usd = |v: f64| format!("${v:.2}");
    match (m.cost.kind, m.cost.usd) {
        (CostKind::Included, _) => "included".into(),
        (CostKind::Actual, Some(v)) => usd(v),
        (CostKind::Estimated, Some(v)) => format!("~{}", usd(v)),
        (CostKind::Mixed, Some(v)) => format!("~{} (mixed)", usd(v)),
        _ => "?".into(),
    }
}

fn print_table(rows: &[Vec<String>]) {
    let widths: Vec<usize> = (0..rows[0].len())
        .map(|c| rows.iter().map(|r| r[c].chars().count()).max().unwrap_or(0))
        .collect();
    for r in rows {
        let cells: Vec<String> = r
            .iter()
            .enumerate()
            .map(|(c, cell)| match c {
                // Agent and model read left to right; numbers line up right.
                0 | 1 => format!("{cell:<w$}", w = widths[c]),
                _ => format!("{cell:>w$}", w = widths[c]),
            })
            .collect();
        println!("  {}", cells.join("  ").trim_end());
    }
}

/// The native chats that used the most tokens across the sandbox's agents.
fn top_chats(agents: &[AgentUsage]) -> Vec<String> {
    let mut all: Vec<(&str, &enclos::engine::ChatUsage)> = agents
        .iter()
        .filter_map(|a| match &a.usage {
            Fact::Known(AgentRecords { top, .. }) => Some((a.agent.as_str(), top)),
            _ => None,
        })
        .flat_map(|(agent, top)| top.iter().map(move |s| (agent, s)))
        .collect();
    all.sort_by_key(|(_, s)| std::cmp::Reverse(s.tokens.total()));
    all.into_iter()
        .take(5)
        .map(|(agent, s)| {
            let mut parts = vec![agent.to_owned()];
            parts.extend(
                s.started_at
                    .map(|t| t.strftime("%Y-%m-%d %H:%M").to_string()),
            );
            parts.extend(s.source.clone());
            parts.extend(s.title.as_ref().map(|t| format!("\"{t}\"")));
            parts.push(format!("{} tokens", count(Some(s.tokens.total()))));
            parts.extend(s.calls.map(|c| format!("{c} calls")));
            parts.extend(s.chat.as_ref().map(|id| format!("({id})")));
            parts.join("  ")
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use enclos::engine::{Cost, Tokens};

    #[test]
    fn counts_read_at_a_glance_and_a_count_not_kept_is_a_dash() {
        assert_eq!(count(None), "-");
        assert_eq!(count(Some(950)), "950");
        assert_eq!(count(Some(83_087)), "83.1k");
        assert_eq!(count(Some(1_234_567)), "1.2M");
    }

    #[test]
    fn a_subscription_shows_included_and_an_estimate_is_marked() {
        let m = |kind, usd| ModelUsage {
            model: None,
            chats: 1,
            calls: None,
            tokens: Tokens::default(),
            cost: Cost { usd, kind },
        };
        assert_eq!(cost(&m(CostKind::Included, Some(0.0))), "included");
        assert_eq!(cost(&m(CostKind::Estimated, Some(1.234))), "~$1.23");
        assert_eq!(cost(&m(CostKind::Actual, Some(2.0))), "$2.00");
        assert_eq!(cost(&m(CostKind::Unknown, None)), "?");
    }
}
