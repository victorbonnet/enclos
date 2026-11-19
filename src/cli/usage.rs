//! `enclos usage`: what each agent used of its model providers, as its
//! runtime recorded it (issue #282), with enclos's estimate of the cost
//! (issue #343); and, by day, as the bridge kept it.

use std::io::Write;

use clap::{Args, ValueEnum};
use serde::Serialize;

use enclos::bridge::store::{Scope, Store, Window, WindowAsk};

use enclos::engine::{
    AgentRecords, AgentUsage, CostKind, Engine, Fact, ModelUsage, SandboxUsage, Total, UsageView,
};
use enclos::error::{Error, Result, exit};
use enclos::model::audit::{Actor, Since};
use enclos::model::now;
use enclos::model::sandbox::SandboxName;
use enclos::pricing::{OverrideRead, PriceList, UsageCost};

#[derive(Args)]
pub struct UsageArgs {
    /// Only this sandbox, read even when it is not running. Without it,
    /// every running sandbox.
    sandbox: Option<SandboxName>,
    /// Native chats active in this past window, such as 24h or 30d; each
    /// counts whole. By day: the days from the one that holds its start.
    #[arg(long, value_name = "DURATION", default_value = "7d")]
    since: Since,
    /// Each day's tokens and estimated cost, as the bridge kept them from the app's channel: of the host, the sandbox, or `--agent`. Reads no sandbox.
    #[arg(long, value_name = "PERIOD")]
    by: Option<Period>,
    /// With `--by day` and a sandbox, only this agent of it.
    #[arg(long, value_name = "AGENT", requires_all = ["sandbox", "by"])]
    agent: Option<String>,
}

/// What `--by` splits usage into.
#[derive(Clone, Copy, ValueEnum)]
enum Period {
    Day,
}

pub fn run(engine: &Engine, by: &Actor, args: UsageArgs) -> Result<u8> {
    // A window reaching before any time enclos can name counts everything.
    let since = now()
        .checked_sub(args.since.duration())
        .unwrap_or(jiff::Timestamp::MIN);
    if let Some(Period::Day) = args.by {
        return by_day(engine, args.sandbox.as_ref(), args.agent.as_deref(), since);
    }
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

const HEAD: [&str; 14] = [
    "AGENT",
    "MODEL",
    "MODEL PROVIDER",
    "CHATS",
    "CALLS",
    "INPUT",
    "CACHE READ",
    "CACHE WRITE",
    "OUTPUT",
    "REASONING",
    "PER CALL",
    "CACHE HIT",
    "EST. COST",
    "RUNTIME COST",
];

/// One day of `--by day`.
#[derive(Debug, Clone, PartialEq, Serialize)]
struct Day {
    /// The day, at the host's local time.
    day: String,
    /// Its start, Unix seconds.
    at: u64,
    calls: u64,
    /// Every token sent or received; none when the runtime counted none.
    tokens: Option<u64>,
    estimate: UsageCost,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
struct DaysView {
    /// Days from the one that holds this time are counted.
    since: jiff::Timestamp,
    /// The host's offset from UTC, in seconds, its days start at.
    offset: i32,
    sandbox: Option<String>,
    agent: Option<String>,
    /// False: the bridge has not run on this host, and kept nothing.
    bridge: bool,
    days: Vec<Day>,
    total: Option<Day>,
    /// The agents with usage here whose channel does not report their
    /// calls outside the app: those are not counted.
    outside_not_counted: Vec<String>,
    prices: enclos::engine::PricesRead,
}

/// `enclos usage --by day`: the bridge's hourly records, of every person's
/// app conversations and of the calls outside the app each agent's channel
/// reports, by the host's days, priced with the price list.
fn by_day(
    engine: &Engine,
    sandbox: Option<&SandboxName>,
    agent: Option<&str>,
    since: jiff::Timestamp,
) -> Result<u8> {
    let offset = jiff::Zoned::now().offset().seconds();
    // Whole days: from the start of the host's day that holds the
    // window's start, so the first row is not part of one.
    let since = day_start(since, offset);
    let loaded = PriceList::load(&engine.prices_path());
    let mut view = DaysView {
        since,
        offset,
        sandbox: sandbox.map(ToString::to_string),
        agent: agent.map(str::to_owned),
        bridge: false,
        days: Vec::new(),
        total: None,
        outside_not_counted: Vec::new(),
        prices: enclos::engine::PricesRead {
            override_file: loaded.override_file.clone(),
            override_read: loaded.override_read.clone(),
        },
    };
    let path = engine.app_store_path();
    // Opening it would make it: a host where the bridge never ran has none.
    if path.exists() {
        let store = Store::open(&path).map_err(|e| Error::Session {
            what: format!("cannot open the bridge's database: {e}"),
        })?;
        let sandbox_name = view.sandbox.clone();
        let scope = match (sandbox_name.as_deref(), agent) {
            (Some(sandbox), Some(agent)) => Scope::Agent { sandbox, agent },
            (Some(sandbox), None) => Scope::Sandbox(sandbox),
            _ => Scope::Host,
        };
        let read = |store: &Store| -> rusqlite::Result<(Window, Vec<String>)> {
            let window = store.usage_report(
                &WindowAsk {
                    owner: None,
                    since: since.as_second(),
                    outside: true,
                    series: Some((86_400, offset)),
                    scope,
                    sum: true,
                },
                &loaded.list,
            )?;
            Ok((window, store.outside_reporters()?))
        };
        let (window, reporters) = read(&store).map_err(|e| Error::Session {
            what: format!("cannot read the bridge's usage: {e}"),
        })?;
        view.bridge = true;
        view.days = days(&window, offset, since);
        view.total = total(&view.days);
        view.outside_not_counted = window
            .agents
            .iter()
            .map(|(agent, _, _)| agent.clone())
            .filter(|agent| !reporters.contains(agent))
            .collect();
    }
    if super::output::json() {
        let shown = serde_json::to_value(&view).map_err(|source| Error::Json {
            what: "the usage",
            source,
        })?;
        super::output::emit(&shown);
        return Ok(exit::OK);
    }
    // A reader that left ends this by SIGPIPE, as for `status`.
    let _ = print_days(&mut std::io::stdout().lock(), &view);
    Ok(exit::OK)
}

/// The start of the day, `offset` seconds from UTC, that holds `at`.
fn day_start(at: jiff::Timestamp, offset: i32) -> jiff::Timestamp {
    let offset = i64::from(offset);
    let start = (at.as_second() + offset).div_euclid(86_400) * 86_400 - offset;
    jiff::Timestamp::from_second(start).unwrap_or(at)
}

/// The window's sum from `since` on, a day a row, each named by the host's
/// date. The bridge keeps usage by the UTC hour, so with an offset not a
/// whole number of hours the hour that holds `since` may fall in the day
/// before: left out, not shown as a day of its own.
fn days(window: &Window, offset: i32, since: jiff::Timestamp) -> Vec<Day> {
    let from = u64::try_from(since.as_second()).unwrap_or(0);
    window
        .sum
        .iter()
        .filter(|p| p.at >= from)
        .map(|p| Day {
            day: i64::try_from(p.at)
                .ok()
                .and_then(|at| jiff::Timestamp::from_second(at + i64::from(offset)).ok())
                .map(|t| t.strftime("%Y-%m-%d").to_string())
                .unwrap_or_else(|| p.at.to_string()),
            at: p.at,
            calls: p.calls,
            tokens: p.tokens,
            estimate: p.cost.unwrap_or_default(),
        })
        .collect()
}

fn total(days: &[Day]) -> Option<Day> {
    let first = days.first()?;
    Some(days.iter().skip(1).fold(
        Day {
            day: "Total".into(),
            ..first.clone()
        },
        |sum, d| Day {
            calls: sum.calls.saturating_add(d.calls),
            tokens: match (sum.tokens, d.tokens) {
                (None, None) => None,
                (a, b) => Some(a.unwrap_or(0).saturating_add(b.unwrap_or(0))),
            },
            estimate: sum.estimate.plus(d.estimate),
            ..sum
        },
    ))
}

/// The widest bar, in characters.
const BAR: u64 = 30;

fn print_days(out: &mut impl Write, view: &DaysView) -> std::io::Result<()> {
    let of = match (&view.sandbox, &view.agent) {
        (Some(s), Some(a)) => format!("{s}/{a}"),
        (Some(s), None) => s.clone(),
        _ => "All sandboxes".into(),
    };
    if !view.bridge {
        return writeln!(
            out,
            "No usage by day: the bridge keeps it from the app's channel (`enclos app serve`), and it has not run on this host."
        );
    }
    let since = jiff::Timestamp::from_second(view.since.as_second() + i64::from(view.offset))
        .map(|t| t.strftime("%Y-%m-%d").to_string())
        .unwrap_or_default();
    if view.days.is_empty() {
        return writeln!(out, "{of}: no usage the bridge kept since {since}.");
    }
    writeln!(
        out,
        "{of}, by day since {since} (the host's time), as the bridge kept it:"
    )?;
    // The bars follow the estimate in dollars; with none, the tokens.
    let dollars_of = |d: &Day| d.estimate.usd_micros;
    let tokens_of = |d: &Day| d.tokens.unwrap_or(0);
    let by_dollars = view.days.iter().any(|d| dollars_of(d) > 0);
    let measure = |d: &Day| match by_dollars {
        true => dollars_of(d),
        false => tokens_of(d),
    };
    let most = view.days.iter().map(measure).max().unwrap_or(0).max(1);
    let mut rows = vec![vec![
        "DAY".to_owned(),
        "CALLS".to_owned(),
        "TOKENS".to_owned(),
        "EST. COST".to_owned(),
        String::new(),
    ]];
    for d in &view.days {
        let width = (u128::from(measure(d)) * u128::from(BAR)).div_ceil(u128::from(most));
        rows.push(vec![
            d.day.clone(),
            d.calls.to_string(),
            count(d.tokens),
            estimate(&d.estimate),
            "█".repeat(usize::try_from(width).unwrap_or(0)),
        ]);
    }
    if let Some(t) = &view.total {
        rows.push(vec![
            t.day.clone(),
            t.calls.to_string(),
            count(t.tokens),
            estimate(&t.estimate),
            String::new(),
        ]);
    }
    let widths: Vec<usize> = (0..4)
        .map(|c| rows.iter().map(|r| r[c].chars().count()).max().unwrap_or(0))
        .collect();
    for r in &rows {
        let line = format!(
            "  {:<w0$}  {:>w1$}  {:>w2$}  {:>w3$}  {}",
            r[0],
            r[1],
            r[2],
            r[3],
            r[4],
            w0 = widths[0],
            w1 = widths[1],
            w2 = widths[2],
            w3 = widths[3]
        );
        writeln!(out, "{}", line.trim_end())?;
    }
    if !view.outside_not_counted.is_empty() {
        writeln!(
            out,
            "Calls outside the app are not counted for {}: its channel does not report them.",
            view.outside_not_counted.join(", ")
        )?;
    }
    writeln!(
        out,
        "\nEvery person's app conversations, and the calls outside the app each agent's channel reports, kept by the hour (those outside the app for 35 days). EST. COST: enclos's estimate from its price list (`enclos prices`). A guide, not a bill."
    )?;
    match &view.prices.override_read {
        OverrideRead::Refused(why) => writeln!(
            out,
            "{} was not read ({why}): the bundled prices alone are used.",
            view.prices.override_file.display()
        ),
        _ => Ok(()),
    }
}

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
    if view.sandboxes.iter().filter(|s| s.total.is_some()).count() > 1 {
        let t = &view.total;
        writeln!(
            out,
            "\nAll sandboxes: {} tokens, {} calls, estimated {}",
            count(Some(t.tokens.total())),
            count(t.calls),
            estimate(&t.estimate)
        )?;
    }
    writeln!(
        out,
        "\nTokens as each runtime recorded them, inside its sandbox: a guide to what an agent used, not a bill. ≥: some of its records lacked that count."
    )?;
    writeln!(
        out,
        "EST. COST: enclos's estimate from its price list (`enclos prices`), at base rates; included: on a subscription; ?: a model it has no price for. RUNTIME COST: the runtime's own figure."
    )?;
    match &view.prices.override_read {
        OverrideRead::Absent => Ok(()),
        OverrideRead::Read { .. } => writeln!(
            out,
            "Prices from {} override the bundled ones.",
            view.prices.override_file.display()
        ),
        OverrideRead::Refused(why) => writeln!(
            out,
            "{} was not read ({why}): the bundled prices alone are used.",
            view.prices.override_file.display()
        ),
    }
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
        if let Some(total) = &s.total {
            rows.push(total_row(total));
        }
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
        m.model_provider.clone().unwrap_or_else(|| "-".into()),
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
        estimate(&m.estimate),
        cost(m),
    ]
}

/// A sandbox's total, under its rows.
fn total_row(t: &Total) -> Vec<String> {
    let tokens = &t.tokens;
    vec![
        "total".to_owned(),
        String::new(),
        String::new(),
        String::new(),
        count(t.calls),
        count(tokens.input),
        count(tokens.cache_read),
        count(tokens.cache_write),
        count(tokens.output),
        count(tokens.reasoning),
        "-".into(),
        tokens
            .cache_hit()
            .map(|h| format!("{:.0}%", h * 100.0))
            .unwrap_or_else(|| "-".into()),
        estimate(&t.estimate),
        "-".into(),
    ]
}

/// enclos's estimate, read at a glance: `~$1.24`; `≥~$1.24` when some
/// tokens had no price; `included` for a subscription's alone; `?` when
/// nothing could be priced in dollars.
pub(crate) fn estimate(c: &UsageCost) -> String {
    if c.usd_micros == 0 && (c.included > 0 || c.unpriced > 0) {
        return match c.unpriced {
            0 => "included".into(),
            _ => "?".into(),
        };
    }
    let at_least = if c.unpriced > 0 { "≥" } else { "" };
    format!("{at_least}~{}", dollars(c.usd_micros))
}

/// Millionths of a dollar as dollars and cents: `$1.24`, `<$0.01` for
/// less than half a cent but more than nothing.
pub(crate) fn dollars(micros: u64) -> String {
    if micros > 0 && micros < 5_000 {
        return "<$0.01".into();
    }
    let cents = micros / 10_000 + u64::from(micros % 10_000 >= 5_000);
    format!("${}.{:02}", cents / 100, cents % 100)
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
            model_provider: Some("openai-codex".into()),
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
            estimate: UsageCost {
                included: 845_839,
                ..UsageCost::default()
            },
            incomplete,
        }
    }

    fn prices() -> enclos::engine::PricesRead {
        enclos::engine::PricesRead {
            override_file: "/c/enclos/prices.toml".into(),
            override_read: OverrideRead::Absent,
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
                    total: Some(Total {
                        calls: Some(26),
                        tokens: model("gpt", Some(83_087), Vec::new()).tokens,
                        estimate: UsageCost {
                            usd_micros: 1_234_567,
                            included: 0,
                            unpriced: 9,
                        },
                    }),
                },
                SandboxUsage {
                    name: "spare".parse().unwrap(),
                    runtime: Some("Hermes"),
                    agents: Fact::CannotTell("not running".into()),
                    total: None,
                },
            ],
            total: Total::default(),
            prices: prices(),
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
        assert!(row.contains("openai-codex"), "{row}");
        // The sandbox's total, under its rows: some tokens unpriced.
        let total = text
            .lines()
            .find(|l| l.trim_start().starts_with("total"))
            .unwrap();
        assert!(total.contains("≥~$1.23"), "{total}");
        // One sandbox with a total: no line for all of them.
        assert!(!text.contains("All sandboxes"), "{text}");
        assert!(text.contains("EST. COST: enclos's estimate"), "{text}");
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
            total: Total::default(),
            prices: prices(),
        };
        assert_eq!(shown(&view), "No sandboxes yet.\n");
    }

    fn days_view(days: Vec<Day>) -> DaysView {
        DaysView {
            since: Timestamp::from_second(1_794_000_000).unwrap(),
            offset: 3_600,
            sandbox: Some("lab".into()),
            agent: None,
            bridge: true,
            total: total(&days),
            days,
            outside_not_counted: vec!["lab/scout".into()],
            prices: prices(),
        }
    }

    fn day(day: &str, usd_micros: u64, unpriced: u64) -> Day {
        Day {
            day: day.into(),
            at: 0,
            calls: 2,
            tokens: Some(1_000),
            estimate: UsageCost {
                usd_micros,
                included: 0,
                unpriced,
            },
        }
    }

    #[test]
    fn by_day_each_day_is_a_row_with_a_bar_for_its_cost_then_the_total() {
        let view = days_view(vec![
            day("2026-11-17", 3_000_000, 0),
            day("2026-11-18", 1_000_000, 5),
            day("2026-11-19", 0, 0),
        ]);
        let mut out = Vec::new();
        print_days(&mut out, &view).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(
            text.starts_with("lab, by day since 2026-11-06 (the host's time)"),
            "{text}"
        );
        let row = |d: &str| {
            text.lines()
                .find(|l| l.trim_start().starts_with(d))
                .unwrap()
        };
        assert!(row("2026-11-17").ends_with(&"█".repeat(30)), "{text}");
        assert!(row("2026-11-18").contains("≥~$1.00"), "{text}");
        assert!(row("2026-11-18").ends_with(&"█".repeat(10)), "{text}");
        // A day of no dollars has no bar.
        assert!(!row("2026-11-19").contains('█'), "{text}");
        let total = row("Total");
        assert!(total.contains("6") && total.contains("3.0k"), "{total}");
        assert!(total.contains("≥~$4.00"), "{total}");
        assert!(
            text.contains("Calls outside the app are not counted for lab/scout"),
            "{text}"
        );
        // Days with no dollars at all: the bars follow the tokens.
        let tokens = days_view(vec![day("2026-11-17", 0, 9)]);
        let mut out = Vec::new();
        print_days(&mut out, &tokens).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains(&"█".repeat(30)), "{text}");
    }

    #[test]
    fn by_day_without_the_bridge_or_without_usage_says_so() {
        let mut view = days_view(Vec::new());
        let mut out = Vec::new();
        print_days(&mut out, &view).unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "lab: no usage the bridge kept since 2026-11-06.\n"
        );
        view.bridge = false;
        let mut out = Vec::new();
        print_days(&mut out, &view).unwrap();
        assert!(
            String::from_utf8(out)
                .unwrap()
                .starts_with("No usage by day: the bridge")
        );
    }

    #[test]
    fn a_window_sum_becomes_days_named_by_the_hosts_date() {
        let window = Window {
            sum: vec![enclos_protocol::usage::UsagePoint {
                // Midnight of 2026-11-07 at UTC+1: 23:00 UTC the day before.
                at: 1_794_006_000,
                calls: 1,
                tokens: None,
                cost: None,
            }],
            ..Window::default()
        };
        let since = Timestamp::from_second(1_794_006_000).unwrap();
        let days = days(&window, 3_600, since);
        assert_eq!(days[0].day, "2026-11-07");
        assert_eq!(days[0].tokens, None);
        assert!(days[0].estimate.is_nothing());
        // A bucket before the window's first day is left out.
        let later = Timestamp::from_second(1_794_006_000 + 86_400).unwrap();
        assert!(super::days(&window, 3_600, later).is_empty());
    }

    #[test]
    fn by_day_starts_at_the_hosts_midnight() {
        // 2026-11-12 15:00 UTC, at UTC+1: 2026-11-12 16:00, whose day starts
        // at 2026-11-11 23:00 UTC.
        let at = Timestamp::from_second(1_794_495_600).unwrap();
        assert_eq!(day_start(at, 3_600).as_second(), 1_794_438_000);
        // At UTC-5:30, 09:30: the day starts at 05:30 UTC.
        assert_eq!(day_start(at, -19_800).as_second(), 1_794_461_400);
        // Midnight itself is the start of its day.
        let midnight = Timestamp::from_second(1_794_438_000).unwrap();
        assert_eq!(day_start(midnight, 3_600), midnight);
    }

    #[test]
    fn an_estimate_reads_in_dollars_and_cents_and_says_what_it_leaves_out() {
        let c = |usd_micros, included, unpriced| UsageCost {
            usd_micros,
            included,
            unpriced,
        };
        assert_eq!(estimate(&c(1_234_567, 0, 0)), "~$1.23");
        assert_eq!(estimate(&c(1_235_000, 0, 0)), "~$1.24");
        assert_eq!(estimate(&c(1_234_567, 10, 0)), "~$1.23");
        assert_eq!(estimate(&c(1_234_567, 0, 10)), "≥~$1.23");
        assert_eq!(estimate(&c(0, 10, 0)), "included");
        assert_eq!(estimate(&c(0, 10, 3)), "?");
        assert_eq!(estimate(&c(0, 0, 3)), "?");
        assert_eq!(estimate(&c(0, 0, 0)), "~$0.00");
        assert_eq!(estimate(&c(4_999, 0, 0)), "~<$0.01");
        assert_eq!(estimate(&c(5_000, 0, 0)), "~$0.01");
        assert_eq!(dollars(123_456_789_000), "$123456.79");
        assert_eq!(dollars(u64::MAX), "$18446744073709.55");
    }

    #[test]
    fn several_sandboxes_with_usage_end_on_the_hosts_total_and_an_override_not_read_is_said() {
        let sandbox = |name: &str, usd_micros| SandboxUsage {
            name: name.parse().unwrap(),
            runtime: Some("Hermes"),
            agents: Fact::Known(vec![AgentUsage {
                agent: "default".into(),
                usage: Fact::Known(AgentRecords {
                    models: vec![model("gpt", Some(10), Vec::new())],
                    top: Vec::new(),
                }),
            }]),
            total: Some(Total {
                calls: Some(1),
                tokens: Tokens {
                    input: Some(500),
                    ..Tokens::default()
                },
                estimate: UsageCost {
                    usd_micros,
                    ..UsageCost::default()
                },
            }),
        };
        let view = UsageView {
            since: Timestamp::from_second(0).unwrap(),
            sandboxes: vec![sandbox("lab", 1_000_000), sandbox("work", 2_000_000)],
            total: Total {
                calls: Some(2),
                tokens: Tokens {
                    input: Some(1_000),
                    ..Tokens::default()
                },
                estimate: UsageCost {
                    usd_micros: 3_000_000,
                    ..UsageCost::default()
                },
            },
            prices: enclos::engine::PricesRead {
                override_file: "/c/enclos/prices.toml".into(),
                override_read: OverrideRead::Refused("is not a price list".into()),
            },
        };
        let text = shown(&view);
        assert!(
            text.contains("All sandboxes: 1.0k tokens, 2 calls, estimated ~$3.00"),
            "{text}"
        );
        assert!(
            text.contains("/c/enclos/prices.toml was not read (is not a price list)"),
            "{text}"
        );
    }
}
