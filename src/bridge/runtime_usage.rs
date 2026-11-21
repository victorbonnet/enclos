//! The agents' usage as their runtimes recorded it, for the host's person
//! (issue #366).
//!
//! A plugin reports the calls made in its runtime's gateway alone: Hermes's
//! board workers, and talks in the sandbox, are processes of their own that
//! it never sees. `enclos usage` reads each agent's own records instead,
//! with the runtime's usage reader run in the sandbox. The bridge reads the
//! same, so that the app shows what the CLI does: once at a time, kept for
//! [`FRESH`], of the running sandboxes only, so that opening a usage page
//! starts no proxy the user did not ask for.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use enclos_protocol::usage::{UsageTokens, UsageTotal};

use super::Hub;
use crate::bridge::store::{AGENT_USAGE_DAYS, HourRow, RuntimeHours};
use crate::engine::{Engine, Fact, UsageView};
use crate::model::audit::Actor;

/// How long a read serves usage windows before the next one reads again.
const FRESH: Duration = Duration::from_secs(120);

/// The last read, and when it was made.
#[derive(Default)]
pub(super) struct RuntimeUsage {
    last: Mutex<Option<(Instant, Arc<RuntimeHours>)>>,
}

impl RuntimeUsage {
    /// The last read while it is fresh; otherwise a new one, made by
    /// `read`, while the lock keeps a second caller waiting for it rather
    /// than reading too. A read that fails gives the last one, if any.
    fn get(&self, read: impl FnOnce() -> Option<RuntimeHours>) -> Option<Arc<RuntimeHours>> {
        let mut last = self.last.lock().expect("not poisoned");
        if let Some((at, hours)) = &*last
            && at.elapsed() < FRESH
        {
            return Some(Arc::clone(hours));
        }
        match read() {
            Some(hours) => {
                let hours = Arc::new(hours);
                *last = Some((Instant::now(), Arc::clone(&hours)));
                Some(hours)
            }
            None => last.as_ref().map(|(_, hours)| Arc::clone(hours)),
        }
    }
}

/// What a usage view holds of each agent whose records list hours, by
/// hour, model and model provider. An agent the runtime has no records of
/// is read too, and used nothing; one whose records could not be read, or
/// whose reader lists no hours, is left out, and its plugin's reports
/// count for it.
pub(super) fn runtime_hours(view: &UsageView) -> RuntimeHours {
    let mut agents = BTreeSet::new();
    let mut hours = Vec::new();
    for sandbox in &view.sandboxes {
        let Fact::Known(listed) = &sandbox.agents else {
            continue;
        };
        for a in listed {
            let name = format!("{}/{}", sandbox.name, a.agent);
            match &a.usage {
                Fact::Known(records) => {
                    let Some(rows) = &records.hours else {
                        continue;
                    };
                    for h in rows {
                        let t = h.tokens;
                        hours.push(HourRow {
                            agent: name.clone(),
                            hour: h.at.div_euclid(3600),
                            model: h.model.clone().unwrap_or_default(),
                            model_provider: h.model_provider.clone().unwrap_or_default(),
                            counts: UsageTotal {
                                calls: h.calls.unwrap_or(0),
                                tokens: UsageTokens {
                                    input: t.input,
                                    output: t.output,
                                    cache_read: t.cache_read,
                                    cache_write: t.cache_write,
                                    reasoning: t.reasoning,
                                },
                            },
                        });
                    }
                }
                Fact::Absent => {}
                Fact::CannotTell(_) | Fact::NotProvided => continue,
            }
            agents.insert(name);
        }
    }
    RuntimeHours { agents, hours }
}

impl Hub {
    /// What the runtimes of the running sandboxes recorded over the
    /// longest window a device asks for, read as `by`, or the last read
    /// while it is fresh: none when enclos's state cannot be read.
    pub(super) fn runtime_hours(&self, by: &Actor) -> Option<Arc<RuntimeHours>> {
        self.runtime_usage.get(|| {
            let since = crate::bridge::store::now() - AGENT_USAGE_DAYS * 86_400;
            let since = crate::model::Timestamp::from_second(since).ok()?;
            let engine = Engine::open(self.layout.clone(), crate::state::Wait::Background);
            match engine.usage(by, None, since) {
                Ok(view) => Some(runtime_hours(&view)),
                Err(e) => {
                    eprintln!("enclos app: the runtimes' usage could not be read: {e}");
                    None
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::{AgentRecords, AgentUsage, HourUsage, PricesRead, SandboxUsage, Tokens};

    fn view(agents: Vec<AgentUsage>) -> UsageView {
        UsageView {
            since: crate::model::Timestamp::UNIX_EPOCH,
            sandboxes: vec![
                SandboxUsage {
                    name: "lab".parse().unwrap(),
                    runtime: Some("Hermes"),
                    agents: Fact::Known(agents),
                    total: None,
                },
                SandboxUsage {
                    name: "off".parse().unwrap(),
                    runtime: Some("Hermes"),
                    agents: Fact::CannotTell("not running".into()),
                    total: None,
                },
            ],
            total: Default::default(),
            prices: PricesRead {
                override_file: "prices.toml".into(),
                override_read: crate::pricing::OverrideRead::Absent,
            },
        }
    }

    fn known(agent: &str, hours: Option<Vec<HourUsage>>) -> AgentUsage {
        AgentUsage {
            agent: agent.into(),
            usage: Fact::Known(AgentRecords {
                models: Vec::new(),
                top: Vec::new(),
                hours,
            }),
        }
    }

    #[test]
    fn agents_whose_records_list_hours_or_that_have_none_are_read_and_the_others_left_to_plugins() {
        let hour = HourUsage {
            at: 7200,
            model: Some("gpt".into()),
            model_provider: None,
            calls: Some(3),
            tokens: Tokens {
                input: Some(10),
                ..Tokens::default()
            },
        };
        let read = runtime_hours(&view(vec![
            known("engineer", Some(vec![hour])),
            // A reader that lists no hours (OpenClaw's).
            known("other", None),
            AgentUsage {
                agent: "new".into(),
                usage: Fact::Absent,
            },
            AgentUsage {
                agent: "broken".into(),
                usage: Fact::CannotTell("state.db: locked".into()),
            },
        ]));
        assert_eq!(
            read.agents.iter().map(String::as_str).collect::<Vec<_>>(),
            ["lab/engineer", "lab/new"]
        );
        assert_eq!(read.hours.len(), 1);
        let row = &read.hours[0];
        assert_eq!((row.agent.as_str(), row.hour), ("lab/engineer", 2));
        assert_eq!(
            (row.model.as_str(), row.model_provider.as_str()),
            ("gpt", "")
        );
        assert_eq!(row.counts.calls, 3);
        assert_eq!(row.counts.tokens.input, Some(10));
    }

    #[test]
    fn a_fresh_read_serves_again_and_a_failed_one_gives_the_last() {
        let usage = RuntimeUsage::default();
        let mut reads = 0;
        let first = usage.get(|| {
            reads += 1;
            Some(RuntimeHours::default())
        });
        assert!(first.is_some());
        let again = usage.get(|| {
            reads += 1;
            None
        });
        assert!(again.is_some());
        assert_eq!(reads, 1);
        // Stale: read again; failed, the last is given.
        *usage.last.lock().unwrap() = Some((
            Instant::now() - FRESH - Duration::from_secs(1),
            Arc::new(RuntimeHours::default()),
        ));
        assert!(usage.get(|| None).is_some());
        assert!(RuntimeUsage::default().get(|| None).is_none());
    }
}
