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
    /// A call the runtime made on its own (a title, a summary of a long
    /// context), not one of the agent's answer.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub background: bool,
    /// How many calls it sums.
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
pub const MAX_REPORT_AGENTS: usize = 200;

/// What one agent used over a window, in a `usage.report`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentUsage {
    /// `<sandbox>/<agent>`.
    pub agent: String,
    pub total: UsageTotal,
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
}
