//! `enclos doctor` (design §10): whether this host can run each backend,
//! whether each sandbox's next session can start, and which files its
//! sessions ran under its policy now compiles differently from. Compiled
//! policies are kept by their content, so an upgrade that changes enclos's
//! own rules writes a new file at the next session start, without asking
//! (ADR 0018); this is where that change is shown.

use std::collections::BTreeSet;
use std::io::ErrorKind;
use std::path::PathBuf;

use super::Engine;
use super::session::marked_in;
use crate::backend::{Capabilities, Probe};
use crate::error::{Error, Result};
use crate::layout::LayoutError;
use crate::lifecycle::members::is_gone;
use crate::lifecycle::process::{Proc, PsError, processes};
use crate::model::sandbox::{BackendKind, SandboxName, SandboxRecord};
use crate::policy::sha256_hex;
use crate::state::StateError;

/// What `enclos doctor` found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Doctor {
    /// Every backend this build has, in order of preference.
    pub backends: Vec<BackendCheck>,
    pub sandboxes: Sandboxes,
}

/// The sandboxes, as far as enclos's records could be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Sandboxes {
    /// Before `enclos init`: there are none.
    NotInitialized,
    /// enclos's records could not be read, and why.
    Unreadable {
        error: String,
    },
    Listed(Vec<SandboxCheck>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendCheck {
    pub kind: BackendKind,
    /// Whether it is on this host, as checked before every session.
    pub found: Probe,
    /// Whether a program ran in it; asked only once it was found.
    pub runs: Option<Probe>,
    pub capabilities: Capabilities,
}

impl BackendCheck {
    pub fn runs_here(&self) -> bool {
        self.runs == Some(Probe::Available)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxCheck {
    pub name: SandboxName,
    pub backend: BackendKind,
    /// Whether its backend runs a program here. When it does not, nothing
    /// is compiled for it.
    pub backend_runs: bool,
    /// Whether its active policy compiles, as its next session compiles it.
    pub next: NextSession,
    /// The policy version its last session ran under, if one ran under a
    /// compiled policy.
    pub last_version: Option<u32>,
    /// Each file its last or a running session ran under that its policy
    /// version compiles differently from now.
    pub drift: Vec<Drift>,
    /// What enclos could not look at for it: what is above may then be
    /// incomplete.
    pub unreadable: Vec<String>,
}

/// Whether a sandbox's next session can compile its policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NextSession {
    /// Its active policy version compiles to `file`.
    Compiles { version: u32, file: PathBuf },
    /// It does not, so its next session cannot start.
    Fails { error: String },
    /// Not compiled: its backend does not run here.
    NotChecked,
    /// Not compiled: enclos could not look, as its `unreadable` says.
    Unknown,
}

/// A file a session ran under that its policy version compiles differently
/// from now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Drift {
    Changed(CompiledChange),
    /// The version no longer compiles at all; its next session is the
    /// active version's, checked apart.
    NoLongerCompiles {
        version: u32,
        ran: PathBuf,
        error: String,
    },
}

/// Policy version `version` compiled now, against the file `ran` a session
/// ran under. A different text is enclos's own rules changed, as an upgrade
/// changes them, or a path the policy names now resolving elsewhere.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledChange {
    pub version: u32,
    pub ran: PathBuf,
    /// The file `version` compiles to now.
    pub now: PathBuf,
    /// `ran` no longer holds the text its name, a digest, was made from: it
    /// was changed after it was written. Said whether or not it now matches
    /// what `version` compiles to.
    pub edited: bool,
    /// The lines removed and added, in order; none when `ran` is gone.
    pub lines: Option<Vec<LineChange>>,
    /// Running sessions under `ran`: they keep its rules until restarted.
    pub running: usize,
}

/// A line of a compiled policy, removed from the earlier text or added in
/// the new one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LineChange {
    Removed(String),
    Added(String),
}

impl Doctor {
    /// Whether something keeps enclos from working here: no backend runs,
    /// enclos's records cannot be read, or a sandbox's backend does not
    /// run, its next session cannot compile its policy, or enclos could not
    /// look at all of it. A drift is reported, not a problem.
    pub fn has_problems(&self) -> bool {
        let sandbox = |s: &SandboxCheck| {
            !s.backend_runs
                || matches!(s.next, NextSession::Fails { .. })
                || !s.unreadable.is_empty()
        };
        !self.backends.iter().any(BackendCheck::runs_here)
            || match &self.sandboxes {
                Sandboxes::NotInitialized => false,
                Sandboxes::Unreadable { .. } => true,
                Sandboxes::Listed(sandboxes) => sandboxes.iter().any(sandbox),
            }
    }
}

impl Engine {
    /// Looks at the host's backends and every sandbox. Changes nothing, but
    /// starts a program in each backend found here. What it cannot read is
    /// in the report, not an error, so that the rest is still shown.
    pub fn doctor(&self) -> Doctor {
        let backends: Vec<BackendCheck> = self
            .backends
            .iter()
            .map(|b| {
                let found = b.probe();
                let runs = (found == Probe::Available).then(|| b.try_run());
                BackendCheck {
                    kind: b.kind(),
                    found,
                    runs,
                    capabilities: b.capabilities(),
                }
            })
            .collect();
        let sandboxes = match self.state.list() {
            Err(StateError::NotInitialized { .. }) => Sandboxes::NotInitialized,
            Err(e) => Sandboxes::Unreadable {
                error: e.to_string(),
            },
            Ok(records) => {
                // Processes listed once, to tell running sessions from gone
                // ones.
                let procs = processes();
                Sandboxes::Listed(
                    records
                        .iter()
                        .map(|record| {
                            let runs = backends
                                .iter()
                                .any(|b| b.kind == record.backend && b.runs_here());
                            self.sandbox_check(record, runs, procs.as_deref())
                        })
                        .collect(),
                )
            }
        };
        Doctor {
            backends,
            sandboxes,
        }
    }

    fn sandbox_check(
        &self,
        record: &SandboxRecord,
        backend_runs: bool,
        procs: std::result::Result<&[Proc], &PsError>,
    ) -> SandboxCheck {
        let mut check = SandboxCheck {
            name: record.name.clone(),
            backend: record.backend,
            backend_runs,
            next: match backend_runs {
                true => NextSession::Unknown,
                false => NextSession::NotChecked,
            },
            last_version: None,
            drift: Vec::new(),
            unreadable: Vec::new(),
        };
        if let Err(error) = self.doctor_look_at(record, procs, &mut check) {
            check.unreadable.push(error.to_string());
        }
        check
    }

    fn doctor_look_at(
        &self,
        record: &SandboxRecord,
        procs: std::result::Result<&[Proc], &PsError>,
        check: &mut SandboxCheck,
    ) -> Result<()> {
        let name = &record.name;
        let sessions = self.state.sessions(name, false)?;
        let last = sessions
            .iter()
            .filter(|s| s.compiled.is_some())
            .max_by_key(|s| s.id.0);
        check.last_version = last.map(|s| s.version);
        if !check.backend_runs {
            return Ok(());
        }
        check.next = match self.compiled_file(name, record.proxy_port) {
            Ok((file, _)) => NextSession::Compiles {
                version: self.policy(name)?.version.version,
                file,
            },
            Err(error) if is_compile_failure(&error) => NextSession::Fails {
                error: error.to_string(),
            },
            Err(error) => return Err(error),
        };

        // The files to compare: the last session's, and those of sessions
        // still running, each with the version it was compiled from.
        // A session that cannot be told gone counts as running: its file
        // is still compared.
        let held = match procs {
            Ok(_) => match self.held(name) {
                Ok(held) => Some(held),
                Err(e) => {
                    check
                        .unreadable
                        .push(format!("cannot tell which of its sessions run: {e}"));
                    None
                }
            },
            Err(e) => {
                check
                    .unreadable
                    .push(format!("cannot tell which of its sessions run: {e}"));
                None
            }
        };
        let mut running: Vec<(u32, String)> = Vec::new();
        for session in sessions.iter().filter(|s| s.ended_at.is_none()) {
            let Some(compiled) = &session.compiled else {
                continue;
            };
            let gone = match (procs, &held) {
                (Ok(procs), Some(held)) => {
                    let mut marked = session.clone();
                    marked.tracked = marked_in(session, &session.tracked, procs, held);
                    is_gone(procs, &marked)
                }
                _ => false,
            };
            if !gone {
                running.push((session.version, compiled.clone()));
            }
        }
        let mut files: BTreeSet<(u32, String)> = running.iter().cloned().collect();
        if let Some(last) = last
            && let Some(compiled) = &last.compiled
        {
            files.insert((last.version, compiled.clone()));
        }
        for (version, ran) in files {
            let count = running
                .iter()
                .filter(|(v, r)| *v == version && *r == ran)
                .count();
            if let Some(drift) = self.drift(record, version, PathBuf::from(ran), count, check)? {
                check.drift.push(drift);
            }
        }
        Ok(())
    }

    /// Policy version `version` compiled again, against the file `ran` a
    /// session ran under: none when they match.
    fn drift(
        &self,
        record: &SandboxRecord,
        version: u32,
        ran: PathBuf,
        running: usize,
        check: &mut SandboxCheck,
    ) -> Result<Option<Drift>> {
        let name = &record.name;
        let Some((_, snapshot)) = self.state.policy_version(name, version)? else {
            check.unreadable.push(format!(
                "policy version {version}, which a session ran under, is not recorded: `enclos state check {name}` looks at its records"
            ));
            return Ok(None);
        };
        let (now, text) = match self.compiled_for(name, &snapshot.policy, record.proxy_port) {
            Ok(compiled) => compiled,
            Err(error) if is_compile_failure(&error) => {
                return Ok(Some(Drift::NoLongerCompiles {
                    version,
                    ran,
                    error: error.to_string(),
                }));
            }
            Err(error) => return Err(error),
        };
        let before = match std::fs::read(&ran) {
            Ok(bytes) => Some(String::from_utf8_lossy(&bytes).into_owned()),
            Err(e) if e.kind() == ErrorKind::NotFound => None,
            Err(source) => {
                check.unreadable.push(
                    LayoutError::Io {
                        path: ran.clone(),
                        source,
                    }
                    .to_string(),
                );
                return Ok(None);
            }
        };
        // A compiled file is named after the digest of what was written:
        // one whose content is not its name's was changed since.
        let edited = before.as_ref().is_some_and(|before| {
            let digest = sha256_hex(before.as_bytes());
            ran.file_stem().and_then(|s| s.to_str()) != Some(&digest[..16])
        });
        // By content while the file is there; else by its name.
        let same = match &before {
            Some(before) => *before == text,
            None => ran.file_name() == now.file_name(),
        };
        if same && !edited {
            return Ok(None);
        }
        Ok(Some(Drift::Changed(CompiledChange {
            version,
            edited,
            lines: before.map(|before| line_changes(&before, &text)),
            ran,
            now,
            running,
        })))
    }
}

/// Whether `error` says the policy cannot be compiled, rather than that
/// enclos could not look.
fn is_compile_failure(error: &Error) -> bool {
    matches!(
        error,
        Error::Compile(_)
            | Error::HomeNotAFolder { .. }
            | Error::ActivePolicyInvalid { .. }
            | Error::NoPolicy { .. }
    )
}

/// The lines removed from `before` and added in `after`, in order: a line
/// moved is removed where it was and added where it is, since in a Seatbelt
/// policy the last rule that matches wins.
fn line_changes(before: &str, after: &str) -> Vec<LineChange> {
    let old: Vec<&str> = before.lines().collect();
    let new: Vec<&str> = after.lines().collect();
    // The longest common subsequence of what follows each position.
    let mut common = vec![vec![0u32; new.len() + 1]; old.len() + 1];
    for i in (0..old.len()).rev() {
        for j in (0..new.len()).rev() {
            common[i][j] = match old[i] == new[j] {
                true => common[i + 1][j + 1] + 1,
                false => common[i + 1][j].max(common[i][j + 1]),
            };
        }
    }
    let (mut i, mut j) = (0, 0);
    let mut changes = Vec::new();
    while i < old.len() || j < new.len() {
        if i < old.len() && j < new.len() && old[i] == new[j] {
            i += 1;
            j += 1;
        } else if j < new.len() && (i == old.len() || common[i][j + 1] > common[i + 1][j]) {
            changes.push(LineChange::Added(new[j].to_owned()));
            j += 1;
        } else {
            changes.push(LineChange::Removed(old[i].to_owned()));
            i += 1;
        }
    }
    changes
}

#[cfg(test)]
mod tests {
    use super::LineChange::{Added, Removed};
    use super::*;

    #[test]
    fn line_changes_keep_their_order() {
        assert_eq!(
            line_changes("a\nb\nc\n", "a\nx\nc\ny\n"),
            [Removed("b".into()), Added("x".into()), Added("y".into())]
        );
        assert!(line_changes("a\n", "a\n").is_empty());
    }

    /// The same lines in another order are a change: in Seatbelt the last
    /// rule that matches wins.
    #[test]
    fn a_line_moved_is_removed_and_added() {
        assert_eq!(
            line_changes("allow\ndeny\n", "deny\nallow\n"),
            [Removed("allow".into()), Added("allow".into())]
        );
    }
}
