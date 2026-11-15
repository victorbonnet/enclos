//! `enclos usage`: what each agent used of its model providers, as its
//! runtime recorded it (issue #282).

use std::io::Write;

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
    // A reader that left ends this by SIGPIPE, as for `status`.
    let _ = print(&mut std::io::stdout().lock(), &view);
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

fn print(out: &mut impl Write, view: &UsageView) -> std::io::Result<()> {
    if view.sandboxes.is_empty() {
        return writeln!(out, "No sandboxes yet.");
    }
    let since = view.since.strftime("%Y-%m-%d %H:%M UTC").to_string();
    for (i, s) in view.sandboxes.iter().enumerate() {
        if i > 0 {
            writeln!(out)?;
        }
        print_sandbox(out, s, &since)?;
    }
    writeln!(
        out,
        "\nTokens as each runtime recorded them, inside its sandbox: a guide to what an agent used, not a bill. ≥: some of its records lacked that count."
    )
}

fn print_sandbox(out: &mut impl Write, s: &SandboxUsage, since: &str) -> std::io::Result<()> {
    let runtime = s.runtime.unwrap_or("no runtime");
    let agents = match &s.agents {
        Fact::Known(agents) => agents,
        Fact::Absent => return writeln!(out, "{}: no runtime", s.name),
        Fact::NotProvided => {
            return writeln!(out, "{}: {runtime} keeps no usage enclos can read", s.name);
        }
        Fact::CannotTell(why) => return writeln!(out, "{}: cannot tell ({why})", s.name),
    };
    writeln!(
        out,
        "{}: {runtime}, native chats active since {since}, each counted whole",
        s.name
    )?;
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
        print_table(out, &rows)?;
    }
    for note in notes {
        writeln!(out, "  {note}")?;
    }
    let top = top_chats(agents);
    if !top.is_empty() {
        writeln!(out, "  Native chats that used the most")?;
        for line in top {
            writeln!(out, "    {line}")?;
        }
    }
    Ok(())
}

fn row(agent: &str, m: &ModelUsage) -> Vec<String> {
    let t = &m.tokens;
    // A count some records lacked is at least what is shown.
    let at_least = |name: &str, n: Option<u64>| match (m.at_least(name), n) {
        (true, Some(_)) => format!("≥{}", count(n)),
        _ => count(n),
    };
    vec![
        agent.to_owned(),
        m.model.clone().unwrap_or_else(|| "?".into()),
        m.chats.to_string(),
        at_least("calls", m.calls),
        at_least("input", t.input),
        at_least("cache_read", t.cache_read),
        at_least("cache_write", t.cache_write),
        at_least("output", t.output),
        at_least("reasoning", t.reasoning),
        count(m.per_call()),
        t.cache_hit()
            .map(|h| format!("{:.0}%", h * 100.0))
            .unwrap_or_else(|| "-".into()),
        cost(m),
    ]
}

/// Counts read at a glance: 950, 83.1k, 1.2M; `-` when not counted. The
/// unit is chosen after rounding, so 999,950 reads 1.0M, not 1000.0k.
fn count(n: Option<u64>) -> String {
    let Some(n) = n else {
        return "-".into();
    };
    if n < 1_000 {
        return n.to_string();
    }
    let mut value = n as f64;
    for unit in ["k", "M", "G", "T"] {
        value /= 1e3;
        if (value * 10.0).round() < 10_000.0 || unit == "T" {
            return format!("{value:.1}{unit}");
        }
    }
    unreachable!("the last unit returns")
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

fn print_table(out: &mut impl Write, rows: &[Vec<String>]) -> std::io::Result<()> {
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
        writeln!(out, "  {}", cells.join("  ").trim_end())?;
    }
    Ok(())
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
    use enclos::engine::{ChatUsage, Cost, Tokens};
    use enclos::model::Timestamp;

    fn model(name: &str, input: Option<u64>, incomplete: Vec<&'static str>) -> ModelUsage {
        ModelUsage {
            model: Some(name.into()),
            chats: 1,
            calls: Some(26),
            tokens: Tokens {
                input,
                output: Some(6_084),
                cache_read: Some(762_752),
                cache_write: Some(0),
                reasoning: None,
            },
            cost: Cost {
                usd: Some(0.0),
                kind: CostKind::Included,
            },
            incomplete,
        }
    }

    fn chat(id: &str, input: u64) -> ChatUsage {
        ChatUsage {
            chat: Some(id.into()),
            source: Some("enclos".into()),
            title: Some("Weather".into()),
            started_at: Some(Timestamp::from_second(1_794_588_220).unwrap()),
            model: Some("gpt".into()),
            calls: Some(3),
            tokens: Tokens {
                input: Some(input),
                ..Tokens::default()
            },
        }
    }

    fn shown(view: &UsageView) -> String {
        let mut out = Vec::new();
        print(&mut out, view).unwrap();
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn counts_read_at_a_glance_and_a_count_not_kept_is_a_dash() {
        assert_eq!(count(None), "-");
        assert_eq!(count(Some(950)), "950");
        assert_eq!(count(Some(83_087)), "83.1k");
        assert_eq!(count(Some(1_234_567)), "1.2M");
        // Rounding up to the next unit takes that unit.
        assert_eq!(count(Some(999_949)), "999.9k");
        assert_eq!(count(Some(999_950)), "1.0M");
        assert_eq!(count(Some(999_950_000)), "1.0G");
        assert_eq!(count(Some(u64::MAX)), "18446744.1T");
    }

    #[test]
    fn a_subscription_shows_included_and_an_estimate_is_marked() {
        let m = |kind, usd| ModelUsage {
            cost: Cost { usd, kind },
            ..model("m", Some(1), Vec::new())
        };
        assert_eq!(cost(&m(CostKind::Included, Some(0.0))), "included");
        assert_eq!(cost(&m(CostKind::Estimated, Some(1.234))), "~$1.23");
        assert_eq!(cost(&m(CostKind::Actual, Some(2.0))), "$2.00");
        assert_eq!(cost(&m(CostKind::Unknown, None)), "?");
    }

    #[test]
    fn a_sandbox_shows_each_model_a_row_each_other_agent_a_note_and_the_chats_that_used_the_most() {
        let view = UsageView {
            since: Timestamp::from_second(1_794_000_000).unwrap(),
            sandboxes: vec![
                SandboxUsage {
                    name: "lab".parse().unwrap(),
                    runtime: Some("Hermes"),
                    agents: Fact::Known(vec![
                        AgentUsage {
                            agent: "default".into(),
                            usage: Fact::Known(AgentRecords {
                                models: vec![model("gpt", Some(83_087), vec!["input"])],
                                top: vec![chat("small", 10), chat("big", 900_000)],
                            }),
                        },
                        AgentUsage {
                            agent: "scout".into(),
                            usage: Fact::Known(AgentRecords {
                                models: Vec::new(),
                                top: vec![chat("middle", 5_000)],
                            }),
                        },
                        AgentUsage {
                            agent: "idle".into(),
                            usage: Fact::Absent,
                        },
                        AgentUsage {
                            agent: "broken".into(),
                            usage: Fact::CannotTell("state.db: locked".into()),
                        },
                    ]),
                },
                SandboxUsage {
                    name: "spare".parse().unwrap(),
                    runtime: Some("Hermes"),
                    agents: Fact::CannotTell("not running".into()),
                },
            ],
        };
        let text = shown(&view);
        assert!(
            text.contains("lab: Hermes, native chats active since 2026-11-06"),
            "{text}"
        );
        let row = text
            .lines()
            .find(|l| l.trim_start().starts_with("default"))
            .unwrap();
        // Input some records lacked is at least what is shown; reasoning not
        // kept is a dash; no tokens per call with input incomplete.
        assert!(row.contains("≥83.1k"), "{row}");
        assert!(
            row.contains("762.8k") && row.contains("6.1k") && row.contains("included"),
            "{row}"
        );
        assert!(text.contains("  scout: no chats in this window"), "{text}");
        assert!(text.contains("  idle: never used"), "{text}");
        assert!(
            text.contains("  broken: cannot tell (state.db: locked)"),
            "{text}"
        );
        assert!(text.contains("spare: cannot tell (not running)"), "{text}");
        // The chats across agents, the most first.
        let top: Vec<&str> = text
            .lines()
            .skip_while(|l| !l.contains("Native chats that used the most"))
            .skip(1)
            .take_while(|l| l.starts_with("    "))
            .collect();
        assert_eq!(top.len(), 3, "{text}");
        assert!(
            top[0].contains("(big)") && top[1].contains("scout") && top[2].contains("(small)"),
            "{top:?}"
        );
        assert!(top[0].contains("900.0k tokens  3 calls"), "{top:?}");
        // The header and the row line up column for column.
        let header = text.lines().find(|l| l.contains("AGENT")).unwrap();
        assert_eq!(header.chars().count(), row.chars().count(), "{text}");
    }

    #[test]
    fn no_sandboxes_says_so() {
        let view = UsageView {
            since: Timestamp::from_second(0).unwrap(),
            sandboxes: Vec::new(),
        };
        assert_eq!(shown(&view), "No sandboxes yet.\n");
    }
}
