//! `sandbox` or `sandbox/profile`, as commands that act on either take it.

use std::str::FromStr;

use enclos::model::sandbox::SandboxName;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub sandbox: SandboxName,
    pub profile: Option<String>,
}

impl FromStr for Target {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (sandbox, profile) = match s.split_once('/') {
            Some((sandbox, profile)) if !profile.is_empty() => (sandbox, Some(profile.to_owned())),
            Some(_) => {
                return Err(format!(
                    "`{s}`: name a profile after the /, such as home/main"
                ));
            }
            None => (s, None),
        };
        Ok(Target {
            sandbox: sandbox.parse().map_err(|e| format!("{e}"))?,
            profile,
        })
    }
}
