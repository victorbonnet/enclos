//! Usage: what an agent's model calls consumed, as its runtime counts them
//! (`docs/protocol.md`, Usage). The plugin reports each call of an agent's
//! turn; the bridge keeps a total per conversation and passes each call on
//! to the conversation's owner. The runtime counts inside the sandbox, so
//! these numbers guide the person and bill nothing.

use serde::{Deserialize, Serialize};

use crate::ids::ConversationId;

/// The most tokens of one kind a call may report: far above any model's
/// context, low enough that no total of them overflows.
pub const MAX_CALL_TOKENS: u64 = 1 << 40;
/// The most calls one `usage` message may sum.
pub const MAX_CALLS: u32 = 1_000;
/// The most characters of a model's name passed on.
pub const MAX_MODEL_CHARS: usize = 120;
/// The most characters of a model provider's name passed on.
pub const MAX_MODEL_PROVIDER_CHARS: usize = 64;

/// Token counts. `None`: the runtime does not count it, which is not 0.
/// `input` is input not read from or written to the provider's cache.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsageTokens {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_read: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_write: Option<u64>,
    /// Part of `output`, as providers count it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reasoning: Option<u64>,
}

impl UsageTokens {
    /// Each count above [`MAX_CALL_TOKENS`] cut to it.
    pub fn bounded(self) -> UsageTokens {
        let cut = |n: Option<u64>| n.map(|n| n.min(MAX_CALL_TOKENS));
        UsageTokens {
            input: cut(self.input),
            output: cut(self.output),
            cache_read: cut(self.cache_read),
            cache_write: cut(self.cache_write),
            reasoning: cut(self.reasoning),
        }
    }

    /// The sum of both: a count either keeps is kept, one neither keeps
    /// stays `None`.
    pub fn plus(self, other: UsageTokens) -> UsageTokens {
        let sum = |a: Option<u64>, b: Option<u64>| match (a, b) {
            (None, None) => None,
            (a, b) => Some(a.unwrap_or(0).saturating_add(b.unwrap_or(0))),
        };
        UsageTokens {
            input: sum(self.input, other.input),
            output: sum(self.output, other.output),
            cache_read: sum(self.cache_read, other.cache_read),
            cache_write: sum(self.cache_write, other.cache_write),
            reasoning: sum(self.reasoning, other.reasoning),
        }
    }

    /// What the model was sent: input, cache reads and cache writes.
    pub fn prompt(&self) -> u64 {
        [self.input, self.cache_read, self.cache_write]
            .into_iter()
            .flatten()
            .fold(0, u64::saturating_add)
    }

    /// Every token sent or received.
    pub fn total(&self) -> u64 {
        self.prompt().saturating_add(self.output.unwrap_or(0))
    }
}

/// What usage cost, as the host estimates it from its price list (issue
/// #343): the dollars of the tokens it has a price for, and how many
/// tokens it could not price in dollars. An estimate, never a bill. Each
/// part adds up, so the cost of a sandbox or a day is the sum of its
/// agents' or hours'.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsageCost {
    /// Millionths of a US dollar, for the tokens priced: whole, so sums
    /// are exact. A rate per million tokens times a count of tokens is a
    /// count of millionths of a dollar.
    #[serde(default)]
    pub usd_micros: u64,
    /// Tokens on a subscription: they count against its limits, not in
    /// dollars.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub included: u64,
    /// What those of them with a list price would cost if they were paid
    /// for, in millionths of a US dollar: a measure of how heavy an agent
    /// on a subscription is, not what it is billed.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub included_usd_micros: u64,
    /// Tokens of a model the price list has no price for, paid or at list
    /// price on a subscription (those are in `included` too): their cost is
    /// unknown, which is not 0.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub unpriced: u64,
}

impl UsageCost {
    /// The sum of both, each part stopping at the most it can hold.
    pub fn plus(self, other: UsageCost) -> UsageCost {
        UsageCost {
            usd_micros: self.usd_micros.saturating_add(other.usd_micros),
            included: self.included.saturating_add(other.included),
            included_usd_micros: self
                .included_usd_micros
                .saturating_add(other.included_usd_micros),
            unpriced: self.unpriced.saturating_add(other.unpriced),
        }
    }

    /// Whether nothing was used: no dollars, and no token left unpriced or
    /// on a subscription.
    pub fn is_nothing(&self) -> bool {
        *self == UsageCost::default()
    }
}

fn is_zero(n: &u64) -> bool {
    *n == 0
}

fn one() -> u32 {
    1
}

fn is_one(n: &u32) -> bool {
    *n == 1
}

/// A plugin's report of one model call, or of a few, in a conversation of
/// its agent: plugin leg `usage`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallUsage {
    pub conversation: ConversationId,
    /// The model, as the runtime names it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// The model provider that served it, as the runtime names it
    /// (Hermes: `anthropic`, `openai-codex`), so that the bridge prices it
    /// (issue #343).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_provider: Option<String>,
    /// A call the runtime made on its own (a title, a summary of a long
    /// context), not one of the agent's answer.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub background: bool,
    /// How many calls it sums.
    #[serde(default = "one", skip_serializing_if = "is_one")]
    pub calls: u32,
    pub tokens: UsageTokens,
}

/// The most characters of a call's source passed on.
pub const MAX_SOURCE_CHARS: usize = 32;

/// A plugin's report of model calls of its agent outside any app
/// conversation: a routine's run, a talk in the sandbox, another channel's
/// chat. Plugin leg `usage.agent`, only to a bridge whose `hello` names
/// [`crate::plugin::Capability::AgentUsage`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentCallUsage {
    /// Where the call came from, in the runtime's words (Hermes: `cron`,
    /// `cli`, `telegram`). The bridge does not keep it yet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_provider: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub background: bool,
    #[serde(default = "one", skip_serializing_if = "is_one")]
    pub calls: u32,
    pub tokens: UsageTokens,
}

/// What a conversation used, as the bridge summed its plugins' reports
/// since it started keeping them.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsageTotal {
    pub calls: u64,
    pub tokens: UsageTokens,
}

/// The most agents one `usage.report` lists: far more than a host runs,
/// and few enough to fit one device message.
pub const MAX_REPORT_AGENTS: usize = 190;
/// The most agents a report with costs lists (`usage.get`'s `cost`), whose
/// rows are longer: the heaviest, by name.
pub const MAX_COSTED_AGENTS: usize = 110;
/// The most sandboxes a report with costs gives a total of: the heaviest.
pub const MAX_REPORT_SANDBOXES: usize = 20;

/// What one agent used over a window, in a `usage.report`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentUsage {
    /// `<sandbox>/<agent>`.
    pub agent: String,
    pub total: UsageTotal,
    /// Whether its calls outside app conversations are counted too: in a
    /// report for the host's person, for an agent whose plugin said it
    /// reports them (`agent_usage`). Another agent's are not, which a
    /// device says.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub outside: bool,
    /// What it cost, as the bridge estimates it from the host's price
    /// list: from a bridge that names `usage.cost`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost: Option<UsageCost>,
}

/// What one sandbox's agents used over a window, all of them summed, in a
/// `usage.report` from a bridge that names `usage.cost`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxTotal {
    pub sandbox: String,
    pub total: UsageTotal,
    pub cost: UsageCost,
}

/// The bucket sizes a device may ask a series in: an hour, or a day.
pub const BUCKETS: [u32; 2] = [3_600, 86_400];
/// The most agents a `usage.report` with series lists totals of: the
/// heaviest, so that they and the series fit one device message.
pub const MAX_REPORT_AGENTS_WITH_SERIES: usize = 50;
/// The same, for a report with costs.
pub const MAX_COSTED_AGENTS_WITH_SERIES: usize = 20;
/// The most agents a `usage.report` gives a series of: the heaviest.
pub const MAX_SERIES: usize = 8;
/// The most agents a report for one sandbox or agent gives a series of,
/// beside the series of their sum.
pub const MAX_SCOPED_SERIES: usize = 4;
/// The most buckets in one series: the latest.
pub const MAX_POINTS: usize = 62;
/// The furthest a device's offset from UTC may be, in seconds.
pub const MAX_OFFSET: i32 = 14 * 3_600;

/// What an agent used in one bucket of a series.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsagePoint {
    /// The bucket's start, Unix seconds.
    pub at: u64,
    pub calls: u64,
    /// Every token sent or received ([`UsageTokens::total`]); none when the
    /// runtime counted no token, which is not 0.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tokens: Option<u64>,
    /// What it cost, in a report's `sum` series alone (`usage.cost`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost: Option<UsageCost>,
}

/// One agent's usage over time, in a `usage.report`: its buckets that saw
/// a call, oldest first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsageSeries {
    /// `<sandbox>/<agent>`.
    pub agent: String,
    pub points: Vec<UsagePoint>,
}

/// The device leg's `usage`: a call, and the conversation's new total.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsageUpdate {
    #[serde(flatten)]
    pub call: CallUsage,
    pub total: UsageTotal,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_count_not_kept_stays_unknown_through_a_sum_and_a_call_is_bounded() {
        let a = UsageTokens {
            input: Some(10),
            cache_read: Some(90),
            ..UsageTokens::default()
        };
        let b = UsageTokens {
            input: Some(5),
            output: Some(u64::MAX),
            ..UsageTokens::default()
        }
        .bounded();
        let sum = a.plus(b);
        assert_eq!(sum.input, Some(15));
        assert_eq!(sum.output, Some(MAX_CALL_TOKENS));
        assert_eq!(sum.cache_read, Some(90));
        assert_eq!(sum.cache_write, None);
        assert_eq!(sum.reasoning, None);
        assert_eq!(a.prompt(), 100);
    }

    #[test]
    fn a_call_reads_as_one_unless_it_says_otherwise_and_writes_only_what_it_has() {
        let call: CallUsage =
            serde_json::from_str(r#"{"conversation":"c1","tokens":{"input":3,"output":4}}"#)
                .unwrap();
        assert_eq!(call.calls, 1);
        assert!(!call.background);
        assert_eq!(call.tokens.cache_read, None);
        assert_eq!(
            serde_json::to_string(&call).unwrap(),
            r#"{"conversation":"c1","tokens":{"input":3,"output":4}}"#
        );
    }

    #[test]
    fn a_cost_adds_up_part_by_part_and_writes_only_the_parts_it_has() {
        let a = UsageCost {
            usd_micros: 1_250_000,
            included: 0,
            included_usd_micros: 0,
            unpriced: 40,
        };
        let b = UsageCost {
            usd_micros: u64::MAX,
            included: 7,
            included_usd_micros: 9,
            unpriced: 0,
        };
        let sum = a.plus(b);
        assert_eq!(
            (sum.usd_micros, sum.included, sum.unpriced),
            (u64::MAX, 7, 40)
        );
        assert_eq!(
            serde_json::to_string(&a).unwrap(),
            r#"{"usd_micros":1250000,"unpriced":40}"#
        );
        let read: UsageCost = serde_json::from_str(r#"{"included":3}"#).unwrap();
        assert_eq!(read.usd_micros, 0);
        assert!(UsageCost::default().is_nothing() && !read.is_nothing());
    }
}
