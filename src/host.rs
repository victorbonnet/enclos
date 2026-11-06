//! What `enclos doctor` finds on the host beyond whether a backend runs
//! (design §10): each thing a backend, the service manager or the secret
//! store depends on, what was found and what to do about it. Each seam
//! gives its own: a backend through `Backend::host_checks`, the service
//! manager through `ServiceManager::host_checks`, the secret stores through
//! `Stores::host_checks`.

/// One thing looked at on the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostCheck {
    /// What was looked at, as a heading: `bubblewrap`, `Landlock`.
    pub what: String,
    /// What was found.
    pub found: String,
    pub verdict: Verdict,
    /// What to do about it, when anything.
    pub fix: Option<String>,
}

/// What a [`HostCheck`] found means for enclos.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// As enclos needs it.
    Fine,
    /// Said for what follows from it: nothing enclos needs is missing.
    Note,
    /// A degraded control: one the backend runs without here (design §5,
    /// Degraded controls on Linux), with what is not enforced and the risk.
    Degraded { not_enforced: String, risk: String },
    /// Keeps the backend from running.
    Blocks,
}

impl HostCheck {
    pub fn fine(what: &str, found: impl Into<String>) -> HostCheck {
        HostCheck::new(what, found, Verdict::Fine, None)
    }

    pub fn note(what: &str, found: impl Into<String>, fix: Option<String>) -> HostCheck {
        HostCheck::new(what, found, Verdict::Note, fix)
    }

    pub fn blocks(what: &str, found: impl Into<String>, fix: Option<String>) -> HostCheck {
        HostCheck::new(what, found, Verdict::Blocks, fix)
    }

    pub fn new(
        what: &str,
        found: impl Into<String>,
        verdict: Verdict,
        fix: Option<String>,
    ) -> HostCheck {
        HostCheck {
            what: what.to_owned(),
            found: found.into(),
            verdict,
            fix,
        }
    }

    pub fn blocks_backend(&self) -> bool {
        self.verdict == Verdict::Blocks
    }

    /// What was found and what to do, in one sentence: a refusal's reason.
    pub fn reason(&self) -> String {
        match &self.fix {
            Some(fix) => format!("{}: {fix}", self.found),
            None => self.found.clone(),
        }
    }
}
