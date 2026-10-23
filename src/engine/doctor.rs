//! `enclos doctor` (design §10): whether this host can run each backend,
//! whether each sandbox's next session can compile its policy (not whether
//! `sandbox-exec` then accepts what it compiles to), and which files its
//! sessions ran under its policy now compiles differently from. Compiled
//! policies are kept by their content, so an upgrade that changes what
//! enclos adds when it compiles a policy writes a new file at the next
//! session start, without asking (ADR 0018); this is where that change is
//! shown.

use std::cell::OnceCell;
use std::collections::BTreeSet;
use std::io::ErrorKind;
use std::path::PathBuf;

use super::Engine;
use super::compile::compiled_stem;
use super::session::marked_in;
use crate::backend::{Capabilities, Probe};
use crate::error::Error;
use crate::layout::LayoutError;
use crate::lifecycle::members::is_gone;
use crate::lifecycle::process::{Proc, PsError, processes};
use crate::model::sandbox::{BackendKind, SandboxName, SandboxRecord};
use crate::model::session::SessionRecord;
use crate::state::StateError;

/// What `enclos doctor` found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Doctor {
    /// Every backend this build has.
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
    pub state: BackendState,
    pub capabilities: Capabilities,
}

/// Whether a backend is on this host, as checked before every session, and
/// then whether a program ran in it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackendState {
    NotFound {
        reason: String,
    },
    /// On this host, and it refused to run a program.
    Refuses {
        reason: String,
    },
    Runs,
}

impl BackendCheck {
    pub fn runs_here(&self) -> bool {
        self.state == BackendState::Runs
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxCheck {
    pub name: SandboxName,
    pub backend: BackendKind,
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

impl SandboxCheck {
    /// Whether its backend runs a program here. When it does not, nothing
    /// is compiled for it.
    pub fn backend_runs(&self) -> bool {
        self.next != NextSession::NotChecked
    }
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
    /// Not compiled: enclos could not read or compile its active policy,
    /// for another reason than the policy itself, as `why` says.
    Unknown { why: String },
}

/// A file a session ran under, `ran`, that its policy version `version`
/// compiles differently from now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Drift {
    pub version: u32,
    pub ran: PathBuf,
    pub running: Running,
    pub kind: DriftKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DriftKind {
    /// It compiles to `now`, which is not what `ran` holds: what enclos adds
    /// when it compiles a policy changed, as an upgrade changes it, or a
    /// path the policy names resolves elsewhere now.
    Changed { now: PathBuf, ran_file: RanFile },
    /// It no longer compiles, or no longer passes enclos's write checks;
    /// the next session is the active version's, checked apart.
    NoLongerCompiles { error: String },
}

/// The file a session ran under, as found now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RanFile {
    /// No longer there to compare: the version compiles to a file of
    /// another name.
    Gone,
    There {
        /// It no longer holds the text its name, a digest, was made from:
        /// it was changed after it was written. Said whether or not it now
        /// matches what the version compiles to.
        edited: bool,
        lines: Lines,
    },
}

/// What changed between the file a session ran under and the text of now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Lines {
    /// The lines removed and added, in order.
    Changed(Vec<LineChange>),
    /// One of the two has more than [`MAX_LINES`] lines: not compared line
    /// by line.
    TooLong,
}

/// A line of a compiled policy, removed from the earlier text or added in
/// the new one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LineChange {
    Removed(String),
    Added(String),
}

/// The sessions still running under a file: they keep it until restarted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Running {
    pub count: usize,
    /// enclos could not tell which of the sandbox's sessions run, so
    /// `count` holds every session recorded open under the file, some of
    /// which may have ended.
    pub unsure: bool,
}

/// The longest text compared line by line: comparing takes memory as the
/// product of the two lengths, and a file in `compiled/` can hold anything.
pub const MAX_LINES: usize = 2000;

impl Doctor {
    /// Whether something keeps enclos from working here: no backend runs,
    /// enclos's records cannot be read, or a sandbox's backend does not
    /// run, its next session cannot compile its policy, or enclos could not
    /// look at all of it. A compiled policy that changed is reported, not a
    /// problem.
    pub fn has_problems(&self) -> bool {
        let sandbox = |s: &SandboxCheck| {
            !s.backend_runs()
                || matches!(
                    s.next,
                    NextSession::Fails { .. } | NextSession::Unknown { .. }
                )
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

/// The host's processes, listed once for every sandbox, and only once one
/// has a session recorded open.
type Procs = OnceCell<std::result::Result<Vec<Proc>, PsError>>;

impl Engine {
    /// Looks at the host's backends and every sandbox. Changes nothing, but
    /// starts a program in each backend found here. What it cannot read is
    /// in the report, not an error, so that the rest is still shown.
    pub fn doctor(&self) -> Doctor {
        let backends: Vec<BackendCheck> = self
            .backends
            .iter()
            .map(|b| BackendCheck {
                kind: b.kind(),
                state: match b.probe() {
                    Probe::Unavailable { reason } => BackendState::NotFound { reason },
                    Probe::Available => match b.try_run() {
                        Probe::Unavailable { reason } => BackendState::Refuses { reason },
                        Probe::Available => BackendState::Runs,
                    },
                },
                capabilities: b.capabilities(),
            })
            .collect();
        let sandboxes = match self.state.list() {
            Err(StateError::NotInitialized { .. }) => Sandboxes::NotInitialized,
            Err(e) => Sandboxes::Unreadable {
                error: e.to_string(),
            },
            Ok(records) => {
                let procs = Procs::new();
                Sandboxes::Listed(
                    records
                        .iter()
                        .map(|record| {
                            let runs = backends
                                .iter()
                                .any(|b| b.kind == record.backend && b.runs_here());
                            self.sandbox_check(record, runs, &procs)
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

    /// One sandbox, each step's failure said with what it was looking at,
    /// and the others still made.
    fn sandbox_check(
        &self,
        record: &SandboxRecord,
        backend_runs: bool,
        procs: &Procs,
    ) -> SandboxCheck {
        let name = &record.name;
        let mut check = SandboxCheck {
            name: name.clone(),
            backend: record.backend,
            // First, and whatever else cannot be read: it needs only the
            // active policy.
            next: match backend_runs {
                true => self.next_session(record),
                false => NextSession::NotChecked,
            },
            last_version: None,
            drift: Vec::new(),
            unreadable: Vec::new(),
        };
        let sessions = match self.state.sessions(name, false) {
            Ok(sessions) => sessions,
            Err(e) => {
                check
                    .unreadable
                    .push(format!("cannot read its sessions: {e}"));
                return check;
            }
        };
        let last = sessions
            .iter()
            .filter(|s| s.compiled.is_some())
            .max_by_key(|s| s.id.0);
        check.last_version = last.map(|s| s.version);
        if !backend_runs {
            return check;
        }

        // The files to compare: the last session's, and those of sessions
        // still running, each with the version it was compiled from.
        let open: Vec<&SessionRecord> = sessions
            .iter()
            .filter(|s| s.ended_at.is_none() && s.compiled.is_some())
            .collect();
        let mut running: Vec<(u32, &str)> = Vec::new();
        let mut unsure = false;
        if !open.is_empty() {
            // A session that cannot be told gone counts as running: its
            // file is still compared, and its count said to be unsure.
            let listed = procs.get_or_init(processes).as_deref();
            let held = match listed {
                Ok(_) => self.held(name).map_err(|e| e.to_string()),
                Err(e) => Err(e.to_string()),
            };
            if let Err(e) = &held {
                check
                    .unreadable
                    .push(format!("cannot tell which of its sessions run: {e}"));
                unsure = true;
            }
            for session in open {
                let gone = match (listed, &held) {
                    (Ok(procs), Ok(held)) => {
                        let mut marked = session.clone();
                        marked.tracked = marked_in(session, &session.tracked, procs, held);
                        is_gone(procs, &marked)
                    }
                    _ => false,
                };
                if !gone && let Some(compiled) = &session.compiled {
                    running.push((session.version, compiled));
                }
            }
        }
        let mut files: BTreeSet<(u32, &str)> = running.iter().copied().collect();
        if let Some(last) = last
            && let Some(compiled) = &last.compiled
        {
            files.insert((last.version, compiled));
        }
        for (version, ran) in files {
            let running = Running {
                count: running.iter().filter(|f| **f == (version, ran)).count(),
                unsure,
            };
            match self.drift(record, version, PathBuf::from(ran), running) {
                Ok(Some(drift)) => check.drift.push(drift),
                Ok(None) => {}
                Err(e) => check.unreadable.push(format!(
                    "policy v{version}, which a session ran under ({ran}), was not compared: {e}"
                )),
            }
        }
        check
    }

    /// Whether the sandbox's next session can compile its active policy,
    /// read once, so that the version said is the one compiled.
    fn next_session(&self, record: &SandboxRecord) -> NextSession {
        let name = &record.name;
        let view = match self.policy(name) {
            Ok(view) => view,
            // No active policy: no session can start.
            Err(error) if is_compile_failure(&error) => {
                return NextSession::Fails {
                    error: error.to_string(),
                };
            }
            Err(e) => {
                return NextSession::Unknown {
                    why: format!("cannot read its active policy: {e}"),
                };
            }
        };
        match self.compiled_for(name, &view.snapshot.policy, record.proxy_port) {
            Ok((file, _)) => NextSession::Compiles {
                version: view.version.version,
                file,
            },
            Err(error) if is_compile_failure(&error) => NextSession::Fails {
                error: error.to_string(),
            },
            Err(e) => NextSession::Unknown {
                why: format!("cannot compile its active policy: {e}"),
            },
        }
    }

    /// Policy version `version` compiled again, against the file `ran` a
    /// session ran under: none when they match. A compile that fails, or
    /// write paths that no longer pass their checks, are a version that no
    /// longer compiles; a home gone is not compared, and its next session
    /// says it apart.
    fn drift(
        &self,
        record: &SandboxRecord,
        version: u32,
        ran: PathBuf,
        running: Running,
    ) -> std::result::Result<Option<Drift>, String> {
        let name = &record.name;
        let snapshot = self.state.policy_version(name, version);
        let Some((_, snapshot)) = snapshot.map_err(|e| e.to_string())? else {
            return Err(format!(
                "it is not recorded: `enclos state check {name}` looks at its records"
            ));
        };
        let no_longer = |error: String| Drift {
            version,
            ran: ran.clone(),
            running,
            kind: DriftKind::NoLongerCompiles { error },
        };
        let (now, text) = match self.compiled_for(name, &snapshot.policy, record.proxy_port) {
            Ok(compiled) => compiled,
            Err(error @ Error::Compile(_)) => return Ok(Some(no_longer(error.to_string()))),
            // Said of this version, not of the active policy the error
            // names.
            Err(Error::ActivePolicyInvalid { source, .. }) => {
                return Ok(Some(no_longer(format!(
                    "its write paths no longer pass enclos's checks: {source}"
                ))));
            }
            Err(error) => return Err(error.to_string()),
        };
        let ran_file = match std::fs::read(&ran) {
            // By its name once the file is gone.
            Err(e) if e.kind() == ErrorKind::NotFound => {
                if ran.file_name() == now.file_name() {
                    return Ok(None);
                }
                RanFile::Gone
            }
            Err(source) => {
                return Err(LayoutError::Io {
                    path: ran.clone(),
                    source,
                }
                .to_string());
            }
            Ok(bytes) => {
                // A compiled file is named after the digest of what was
                // written: one whose content is not its name's was changed
                // since.
                let edited = ran.file_stem().and_then(|s| s.to_str())
                    != Some(compiled_stem(&bytes).as_str());
                if bytes == text.as_bytes() && !edited {
                    return Ok(None);
                }
                RanFile::There {
                    edited,
                    lines: lines_between(&String::from_utf8_lossy(&bytes), &text),
                }
            }
        };
        Ok(Some(Drift {
            version,
            ran,
            running,
            kind: DriftKind::Changed { now, ran_file },
        }))
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
fn lines_between(before: &str, after: &str) -> Lines {
    let old: Vec<&str> = before.lines().collect();
    let new: Vec<&str> = after.lines().collect();
    if old.len().max(new.len()) > MAX_LINES {
        return Lines::TooLong;
    }
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
    Lines::Changed(changes)
}

#[cfg(test)]
mod tests {
    use super::LineChange::{Added, Removed};
    use super::*;

    #[test]
    fn line_changes_keep_their_order() {
        assert_eq!(
            lines_between("a\nb\nc\n", "a\nx\nc\ny\n"),
            Lines::Changed(vec![
                Removed("b".into()),
                Added("x".into()),
                Added("y".into())
            ])
        );
        assert_eq!(lines_between("a\n", "a\n"), Lines::Changed(vec![]));
    }

    /// The same lines in another order are a change: in Seatbelt the last
    /// rule that matches wins.
    #[test]
    fn a_line_moved_is_removed_and_added() {
        assert_eq!(
            lines_between("allow\ndeny\n", "deny\nallow\n"),
            Lines::Changed(vec![Removed("allow".into()), Added("allow".into())])
        );
    }

    /// A text past the cap is not compared line by line, whichever side.
    #[test]
    fn a_text_too_long_is_not_compared_line_by_line() {
        let long = "x\n".repeat(MAX_LINES + 1);
        assert_eq!(lines_between(&long, "x\n"), Lines::TooLong);
        assert_eq!(lines_between("x\n", &long), Lines::TooLong);
        let most = "x\n".repeat(MAX_LINES);
        assert!(matches!(lines_between(&most, "y\n"), Lines::Changed(_)));
    }
}
