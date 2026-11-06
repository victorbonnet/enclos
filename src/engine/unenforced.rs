//! A field the host does not enforce, run not enforced only once accepted
//! (ADR 0038). The backend says which fields of a policy its host does not
//! enforce; a sandbox runs with one only when the user accepted it at that
//! value, with `--accept-unenforced`, which is recorded with the sandbox and
//! in an audit entry of its own, so later stores and starts need none until
//! the value changes. A policy's checks and every start ask here.

use super::Engine;
use crate::error::{Error, Result};
use crate::model::audit::{Actor, Intent, Outcome};
use crate::model::now;
use crate::model::policy::Policy;
use crate::model::sandbox::{BackendKind, SandboxName};
use crate::model::unenforced::{Acceptance, NotEnforcedHere, UnenforcedField};
use crate::policy::{PolicyError, Problem};
use crate::state::StateLock;

/// The audit entry an acceptance is recorded under.
const ACCEPT_COMMAND: &str = "accept-unenforced";

impl Engine {
    /// The same engine, accepting that `fields` run not enforced where this
    /// host does not enforce them, as this command's `--accept-unenforced`
    /// says.
    pub fn accepting_unenforced(mut self, fields: Vec<UnenforcedField>) -> Engine {
        self.accepting = fields;
        self
    }

    /// What `policy` sets that backend `kind` does not enforce on this host;
    /// none when this build has no such backend, which no command then
    /// starts.
    fn not_enforced_here(&self, kind: BackendKind, policy: &Policy) -> Vec<NotEnforcedHere> {
        self.backends
            .iter()
            .find(|b| b.kind() == kind)
            .map(|b| b.not_enforced_here(policy))
            .unwrap_or_default()
    }

    /// What sandbox `name`, on backend `kind`, would run with not enforced
    /// under `policy`, each accepted: by an acceptance kept with the
    /// sandbox at the same value, or by this command's
    /// `--accept-unenforced`. One with neither is refused, saying to run
    /// `command` with the flag, or, with none, the command refused.
    pub(super) fn accepted_gaps(
        &self,
        name: &SandboxName,
        kind: BackendKind,
        policy: &Policy,
        command: Option<&str>,
    ) -> Result<Vec<NotEnforcedHere>> {
        let gaps = self.not_enforced_here(kind, policy);
        if gaps.is_empty() {
            return Ok(gaps);
        }
        // A sandbox being created has no record, and no acceptance.
        let kept = match self.state.get(name)? {
            Some(_) => self.state.acceptances(name)?,
            None => Vec::new(),
        };
        let refused: Vec<Problem> = gaps
            .iter()
            .filter(|gap| {
                !self.accepting.contains(&gap.field) && !kept.iter().any(|a| a.covers(gap))
            })
            .map(|gap| Problem::Refused(gap.refusal(command)))
            .collect();
        if !refused.is_empty() {
            return Err(Error::Policy(PolicyError::Invalid { problems: refused }));
        }
        Ok(gaps)
    }

    /// Records each acceptance this command gives (`--accept-unenforced`)
    /// for what `policy` runs with not enforced in sandbox `name`, `at`
    /// naming the policy it is for, such as `policy v4`. Each is kept with
    /// the sandbox and gets an audit entry of its own, naming the sandbox,
    /// the field, its value, that policy and why the host does not enforce
    /// it. One already kept at the same value is left as it is. Returns
    /// what runs not enforced.
    pub(super) fn record_acceptances(
        &self,
        lock: &StateLock,
        by: &Actor,
        name: &SandboxName,
        policy: &Policy,
        at: &str,
    ) -> Result<Vec<NotEnforcedHere>> {
        let kind = self.record(name)?.backend;
        let gaps = self.accepted_gaps(name, kind, policy, None)?;
        let kept = self.state.acceptances(name)?;
        for gap in &gaps {
            if kept.iter().any(|a| a.covers(gap)) {
                continue;
            }
            let ticket = self.audit.begin(
                lock,
                Intent {
                    by: by.clone(),
                    command: ACCEPT_COMMAND.to_owned(),
                    target: Some(name.to_string()),
                },
            )?;
            let accepted = Acceptance {
                field: gap.field,
                value: gap.value.clone(),
                why: gap.why.clone(),
                at: now(),
            };
            let outcome = match self.state.accept_unenforced(lock, name, &accepted) {
                Ok(()) => Outcome::ok(format!(
                    "{} = {} runs not applied in sandbox {name}, {at}: {}",
                    gap.field.policy_path(),
                    gap.value,
                    gap.why
                )),
                Err(e) => {
                    let message = e.to_string();
                    let _ = self.audit.finish(ticket, Outcome::failed(message));
                    return Err(e.into());
                }
            };
            self.audit.finish(ticket, outcome)?;
        }
        Ok(gaps)
    }
}

/// How a command's audit entry names the fields it runs with not enforced,
/// after what it did: nothing when there are none.
pub(super) fn not_enforced_note(gaps: &[NotEnforcedHere]) -> String {
    if gaps.is_empty() {
        return String::new();
    }
    let fields: Vec<String> = gaps
        .iter()
        .map(|g| format!("{} (accepted)", g.field.policy_path()))
        .collect();
    format!("; not enforced on this host: {}", fields.join(", "))
}
