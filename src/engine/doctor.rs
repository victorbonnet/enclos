//! `enclos doctor` (design §10): whether this host can run each backend,
//! and which sandboxes' policies enclos now compiles differently from the
//! file their last session ran under. Compiled policies are kept per
//! snapshot and enclos version, so an upgrade that changes enclos's own
//! rules recompiles at the next session start, without asking (ADR 0018);
//! this is where that change is shown.

use std::collections::BTreeSet;
use std::io::ErrorKind;
use std::path::PathBuf;

use super::Engine;
use crate::backend::{Capabilities, Probe};
use crate::error::Result;
use crate::layout::LayoutError;
use crate::model::sandbox::{BackendKind, SandboxName, SandboxRecord};
use crate::state::StateError;

/// What `enclos doctor` found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Doctor {
    /// Every backend this build has, in order of preference.
    pub backends: Vec<BackendCheck>,
    /// Every sandbox; none before `enclos init`.
    pub sandboxes: Option<Vec<SandboxCheck>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendCheck {
    pub kind: BackendKind,
    /// Whether it ran a program here.
    pub runs: Probe,
    pub capabilities: Capabilities,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxCheck {
    pub name: SandboxName,
    pub backend: BackendKind,
    pub compiled: CompiledCheck,
}

/// How the policy a sandbox's last session ran under compiles now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompiledCheck {
    /// No session of it has run under a compiled policy.
    NeverRun,
    /// Policy version `version` compiles as it did for its last session.
    Same { version: u32 },
    /// Policy version `version` compiles differently now: enclos's own
    /// rules changed, as an upgrade changes them. Its next session runs
    /// under `now`; `open` sessions still run under `ran`.
    Changed {
        version: u32,
        ran: PathBuf,
        now: PathBuf,
        /// The lines that changed; none when `ran` is no longer there.
        lines: Option<LineChanges>,
        open: usize,
    },
    /// It cannot be compiled here now: its next session cannot start.
    Fails { error: String },
}

/// Lines of a compiled policy, in their order, found in one text and not
/// in the other.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LineChanges {
    pub added: Vec<String>,
    pub removed: Vec<String>,
}

impl Doctor {
    /// Whether something keeps enclos from working here: no backend runs,
    /// or a sandbox's backend does not, or its policy does not compile.
    pub fn has_problems(&self) -> bool {
        let runs = |kind: BackendKind| {
            self.backends
                .iter()
                .any(|b| b.kind == kind && b.runs == Probe::Available)
        };
        !self.backends.iter().any(|b| b.runs == Probe::Available)
            || self
                .sandboxes
                .iter()
                .flatten()
                .any(|s| !runs(s.backend) || matches!(s.compiled, CompiledCheck::Fails { .. }))
    }
}

impl Engine {
    /// Looks at the host's backends and every sandbox's compiled policy.
    /// Changes nothing, but starts a program in each backend.
    pub fn doctor(&self) -> Result<Doctor> {
        let backends = self
            .backends
            .iter()
            .map(|b| BackendCheck {
                kind: b.kind(),
                runs: b.try_run(),
                capabilities: b.capabilities(),
            })
            .collect();
        let records = match self.state.list() {
            Ok(records) => records,
            Err(StateError::NotInitialized { .. }) => {
                return Ok(Doctor {
                    backends,
                    sandboxes: None,
                });
            }
            Err(e) => return Err(e.into()),
        };
        let sandboxes = records
            .iter()
            .map(|record| {
                Ok(SandboxCheck {
                    name: record.name.clone(),
                    backend: record.backend,
                    compiled: self.compiled_check(record)?,
                })
            })
            .collect::<Result<_>>()?;
        Ok(Doctor {
            backends,
            sandboxes: Some(sandboxes),
        })
    }

    /// The policy version the sandbox's last session ran under, compiled
    /// again, compared with the file it ran under. The same version, not
    /// the active one: a policy changed since is `policy diff`'s, not this.
    fn compiled_check(&self, record: &SandboxRecord) -> Result<CompiledCheck> {
        let name = &record.name;
        let sessions = self.state.sessions(name, false)?;
        let Some((last, ran)) = sessions
            .iter()
            .filter_map(|s| s.compiled.as_ref().map(|c| (s, PathBuf::from(c))))
            .max_by_key(|(s, _)| s.id.0)
        else {
            return Ok(CompiledCheck::NeverRun);
        };
        let Some((_, snapshot)) = self.state.policy_version(name, last.version)? else {
            return Ok(CompiledCheck::Fails {
                error: format!(
                    "policy version {} of its last session is not recorded",
                    last.version
                ),
            });
        };
        let (now, text) = match self.compiled_for(name, &snapshot.policy, record.proxy_port) {
            Ok(compiled) => compiled,
            Err(error) => {
                return Ok(CompiledCheck::Fails {
                    error: error.to_string(),
                });
            }
        };
        let before = match std::fs::read_to_string(&ran) {
            Ok(before) => Some(before),
            Err(e) if e.kind() == ErrorKind::NotFound => None,
            Err(source) => {
                return Err(LayoutError::Io {
                    path: ran.clone(),
                    source,
                }
                .into());
            }
        };
        // Compared by content where the file is still there: its name is
        // its digest, but its folder moves with the enclos folder.
        let same = match &before {
            Some(before) => *before == text,
            None => ran.file_name() == now.file_name(),
        };
        if same {
            return Ok(CompiledCheck::Same {
                version: last.version,
            });
        }
        let open = sessions
            .iter()
            .filter(|s| s.ended_at.is_none() && s.compiled.as_deref() == last.compiled.as_deref())
            .count();
        Ok(CompiledCheck::Changed {
            version: last.version,
            lines: before.map(|before| line_changes(&before, &text)),
            ran,
            now,
            open,
        })
    }
}

fn line_changes(before: &str, after: &str) -> LineChanges {
    let old: BTreeSet<&str> = before.lines().collect();
    let new: BTreeSet<&str> = after.lines().collect();
    LineChanges {
        added: after
            .lines()
            .filter(|l| !old.contains(l))
            .map(str::to_owned)
            .collect(),
        removed: before
            .lines()
            .filter(|l| !new.contains(l))
            .map(str::to_owned)
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn line_changes_keep_their_order() {
        let changes = line_changes("a\nb\nc\n", "a\nx\nc\ny\n");
        assert_eq!(changes.added, ["x", "y"]);
        assert_eq!(changes.removed, ["b"]);
        let none = line_changes("a\n", "a\n");
        assert!(none.added.is_empty() && none.removed.is_empty());
    }
}
