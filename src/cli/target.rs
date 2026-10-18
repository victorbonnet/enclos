//! `sandbox` or `sandbox/agent`, as commands that act on either take it.

use std::str::FromStr;

use enclos::model::sandbox::SandboxName;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub sandbox: SandboxName,
    pub agent: Option<String>,
}

impl FromStr for Target {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (sandbox, agent) = match s.split_once('/') {
            Some((sandbox, agent)) if !agent.is_empty() => (sandbox, Some(agent.to_owned())),
            Some(_) => {
                return Err(format!(
                    "`{s}`: name an agent after the /, such as home/main"
                ));
            }
            None => (s, None),
        };
        Ok(Target {
            sandbox: sandbox.parse().map_err(|e| format!("{e}"))?,
            agent,
        })
    }
}
