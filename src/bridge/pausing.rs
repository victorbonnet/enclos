//! Bridge seam for host-wide and per-sandbox pause/resume. Every operation
//! goes through the engine's own `pause_sandboxes`, `resume_sandboxes`, and
//! `pause_state_snapshot` so the CLI and bridge derive the exact same state.

use std::collections::HashMap;

use enclos_protocol::device::{
    PauseOutcome as WirePauseOutcome, PauseSandboxOutcome, PauseSandboxState, PauseWhy, ToDevice,
};
use enclos_protocol::plugin::ErrorCode;

use crate::engine::pause_state::{HostPauseRead, HostPauseWord, NotPausedWhy};
use crate::engine::{
    Engine, PauseOutcome as EnginePauseOutcome, PauseReport, PauseScope,
    ResumeOutcome as EngineResumeOutcome, ResumeReport,
};
use crate::error::Error;
use crate::layout::Layout;
use crate::model::audit::Actor;
use crate::model::sandbox::{SandboxName, SandboxState};

/// Maximum number of sandbox names accepted in a subset `pause`/`resume`
/// request (keeps `pause.result` well inside one device frame).
pub const MAX_PAUSE_SANDBOXES: usize = 64;

/// One sandbox's derived pause state, ready for `pause.state`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PauseStateRow {
    pub sandbox: String,
    pub paused: bool,
    pub covered: bool,
    pub state: String,
    pub why: Option<PauseWhy>,
}

/// The host's presented pause state from the engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PauseStateView {
    pub paused: bool,
    pub partly: bool,
    pub since: Option<String>,
    pub by: Option<String>,
    pub revision: u64,
    pub sandboxes: Vec<PauseStateRow>,
}

impl PauseStateView {
    /// Converts this host state into a `pause.state` message.
    ///
    /// The host's person sees every sandbox of the host; another person sees
    /// the host-level facts and only the rows of sandboxes the pause covers,
    /// so a shared person never learns how many other sandboxes the host has.
    pub fn to_device_message(&self, is_host_person: bool) -> ToDevice {
        let sandboxes = self
            .sandboxes
            .iter()
            .filter(|row| is_host_person || row.covered)
            .map(|row| PauseSandboxState {
                sandbox: row.sandbox.clone(),
                paused: row.paused,
                state: row.state.clone(),
                why: row.why,
            })
            .collect();
        ToDevice::PauseState {
            paused: self.paused,
            partly: self.partly,
            waiting: None,
            since: self.since.clone(),
            by: self.by.clone(),
            revision: self.revision,
            sandboxes,
        }
    }
}

/// Result of a `pause` or `resume` operation on the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PauseActionResult {
    pub paused: bool,
    pub partly: bool,
    pub revision: u64,
    /// Per-sandbox outcomes in the order requested when `sandboxes` was
    /// provided; ignored (omitted on the wire) for the host switch.
    pub outcomes: Vec<PauseSandboxOutcome>,
}

/// Errors that prevented a pause/resume operation from starting or reading state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PauseError {
    NotFound(String),
    Conflict(String),
    OperationFailed(String),
    Internal(String),
}

impl PauseError {
    pub fn code(&self) -> ErrorCode {
        match self {
            PauseError::NotFound(_) => ErrorCode::NotFound,
            PauseError::Conflict(_) => ErrorCode::Conflict,
            PauseError::OperationFailed(_) => ErrorCode::OperationFailed,
            PauseError::Internal(_) => ErrorCode::Internal,
        }
    }

    pub fn message(&self) -> &str {
        match self {
            PauseError::NotFound(m)
            | PauseError::Conflict(m)
            | PauseError::OperationFailed(m)
            | PauseError::Internal(m) => m,
        }
    }
}

/// Bridge-to-engine seam for host pause state and actions.
pub trait Pausing: Send + Sync {
    fn state(&self) -> Result<PauseStateView, PauseError>;

    fn pause(
        &self,
        by: &Actor,
        scope: PauseScope,
        expected_revision: Option<u64>,
    ) -> Result<PauseActionResult, PauseError>;

    fn resume(
        &self,
        by: &Actor,
        scope: PauseScope,
        expected_revision: Option<u64>,
    ) -> Result<PauseActionResult, PauseError>;
}

/// Formats `host_pause.by_user` for `pause.state.by`: strips the audit
/// suffix `" (device ..., request ...)"` or `" (device ...)"` so paired
/// devices (including other persons') see only the person's name/login,
/// while the audit log keeps the full actor string.
fn display_pause_by(user: &str) -> String {
    match user.split_once(" (device ") {
        Some((person, _)) => person.to_owned(),
        None => user.to_owned(),
    }
}

fn dedup_names(names: &[SandboxName]) -> Vec<SandboxName> {
    let mut seen = Vec::with_capacity(names.len());
    for name in names {
        if !seen.contains(name) {
            seen.push(name.clone());
        }
    }
    seen
}

/// Validates and parses an optional `sandboxes` wire field into a `PauseScope`.
///
/// Enforces:
/// - absent → `PauseScope::All`
/// - present → non-empty, at most [`MAX_PAUSE_SANDBOXES`] names, each a valid
///   [`SandboxName`], deduplicated in first-occurrence order.
pub fn parse_scope(sandboxes: Option<Vec<String>>) -> Result<PauseScope, String> {
    let Some(names) = sandboxes else {
        return Ok(PauseScope::All);
    };
    if names.is_empty() {
        return Err("sandboxes must not be empty".to_owned());
    }
    if names.len() > MAX_PAUSE_SANDBOXES {
        return Err(format!(
            "sandboxes may name at most {MAX_PAUSE_SANDBOXES} sandboxes"
        ));
    }
    let mut parsed = Vec::with_capacity(names.len());
    for raw in names {
        let name = raw
            .parse::<SandboxName>()
            .map_err(|e| format!("invalid sandbox name `{raw}`: {e}"))?;
        if !parsed.contains(&name) {
            parsed.push(name);
        }
    }
    Ok(PauseScope::Names(parsed))
}

/// Real host-binary implementation backed by [`Engine`].
pub struct HostPausing {
    layout: Layout,
}

impl HostPausing {
    pub fn new(layout: Layout) -> Self {
        Self { layout }
    }

    fn engine(&self) -> Engine {
        Engine::open(self.layout.clone(), crate::state::Wait::Command)
    }
}

fn map_why(why: NotPausedWhy) -> PauseWhy {
    match why {
        NotPausedWhy::NotCovered => PauseWhy::NotCovered,
        NotPausedWhy::Released => PauseWhy::Released,
        NotPausedWhy::NothingToPause => PauseWhy::NothingToPause,
        NotPausedWhy::WouldNotStop => PauseWhy::WouldNotStop,
        NotPausedWhy::WouldNotStart => PauseWhy::WouldNotStart,
    }
}

fn map_pause_outcome(outcome: EnginePauseOutcome) -> WirePauseOutcome {
    match outcome {
        EnginePauseOutcome::Paused => WirePauseOutcome::Paused,
        EnginePauseOutcome::NothingToPause => WirePauseOutcome::NothingToPause,
        EnginePauseOutcome::WouldNotStop => WirePauseOutcome::WouldNotStop,
    }
}

fn map_resume_outcome(outcome: EngineResumeOutcome) -> WirePauseOutcome {
    match outcome {
        EngineResumeOutcome::Resumed => WirePauseOutcome::Resumed,
        EngineResumeOutcome::NothingToResume => WirePauseOutcome::NothingToResume,
        EngineResumeOutcome::LeftAsItWas => WirePauseOutcome::LeftAsItWas,
        EngineResumeOutcome::WouldNotStart => WirePauseOutcome::WouldNotStart,
    }
}

fn map_error(err: Error) -> PauseError {
    match err {
        Error::NoSuchSandbox { name } => {
            PauseError::NotFound(format!("no sandbox named `{name}` on this host"))
        }
        Error::PauseConflict { expected, found } => PauseError::Conflict(format!(
            "pause state changed since revision {expected} (now {found})"
        )),
        Error::State(_) | Error::Audit(_) => PauseError::Internal(err.to_string()),
        other => PauseError::OperationFailed(other.to_string()),
    }
}

impl Pausing for HostPausing {
    fn state(&self) -> Result<PauseStateView, PauseError> {
        let snapshot = self.engine().pause_state_snapshot().map_err(map_error)?;
        let sandboxes = snapshot
            .sandboxes
            .into_iter()
            .map(|entry| PauseStateRow {
                sandbox: entry.sandbox.to_string(),
                paused: entry.view.paused,
                covered: entry.view.covered,
                state: match entry.state {
                    SandboxState::Created => "created",
                    SandboxState::Running => "running",
                    SandboxState::Stopped => "stopped",
                    SandboxState::Failed { .. } => "failed",
                }
                .to_owned(),
                why: entry.view.why.map(map_why),
            })
            .collect();
        Ok(PauseStateView {
            paused: snapshot.host.word == HostPauseWord::Paused,
            partly: snapshot.host.word == HostPauseWord::PartlyPaused,
            since: snapshot.host.since.map(|t| t.to_string()),
            by: snapshot.host.by.map(|a| display_pause_by(&a.user)),
            revision: snapshot.host.revision,
            sandboxes,
        })
    }

    fn pause(
        &self,
        by: &Actor,
        scope: PauseScope,
        expected_revision: Option<u64>,
    ) -> Result<PauseActionResult, PauseError> {
        let named = match &scope {
            PauseScope::All => None,
            PauseScope::Names(names) => Some(dedup_names(names)),
        };
        let report = self
            .engine()
            .pause_sandboxes(by, scope, expected_revision)
            .map_err(map_error)?;
        Ok(pause_report_to_action_result(named.as_deref(), report))
    }

    fn resume(
        &self,
        by: &Actor,
        scope: PauseScope,
        expected_revision: Option<u64>,
    ) -> Result<PauseActionResult, PauseError> {
        let named = match &scope {
            PauseScope::All => None,
            PauseScope::Names(names) => Some(dedup_names(names)),
        };
        let report = self
            .engine()
            .resume_sandboxes(by, scope, expected_revision)
            .map_err(map_error)?;
        Ok(resume_report_to_action_result(named.as_deref(), report))
    }
}

pub(crate) fn pause_report_to_action_result(
    named: Option<&[SandboxName]>,
    report: PauseReport,
) -> PauseActionResult {
    let outcomes = match named {
        None => Vec::new(),
        Some(names) => {
            let by_name: HashMap<&str, WirePauseOutcome> = report
                .sandboxes
                .iter()
                .map(|r| (r.sandbox.as_str(), map_pause_outcome(r.outcome)))
                .collect();
            names
                .iter()
                .map(|n| PauseSandboxOutcome {
                    sandbox: n.to_string(),
                    outcome: by_name
                        .get(n.as_str())
                        .copied()
                        .unwrap_or(WirePauseOutcome::NothingToPause),
                })
                .collect()
        }
    };
    let (paused, partly, revision) = map_host_pause_read(&report.host, "pause");
    PauseActionResult {
        paused,
        partly,
        revision,
        outcomes,
    }
}

pub(crate) fn resume_report_to_action_result(
    named: Option<&[SandboxName]>,
    report: ResumeReport,
) -> PauseActionResult {
    let outcomes = match named {
        None => Vec::new(),
        Some(names) => {
            let by_name: HashMap<&str, WirePauseOutcome> = report
                .sandboxes
                .iter()
                .map(|r| (r.sandbox.as_str(), map_resume_outcome(r.outcome)))
                .collect();
            names
                .iter()
                .map(|n| PauseSandboxOutcome {
                    sandbox: n.to_string(),
                    outcome: by_name
                        .get(n.as_str())
                        .copied()
                        .unwrap_or(WirePauseOutcome::NothingToResume),
                })
                .collect()
        }
    };
    let (paused, partly, revision) = map_host_pause_read(&report.host, "resume");
    PauseActionResult {
        paused,
        partly,
        revision,
        outcomes,
    }
}

fn map_host_pause_read(host: &HostPauseRead, op: &str) -> (bool, bool, u64) {
    match host {
        HostPauseRead::Readable(h) => (
            h.word == HostPauseWord::Paused,
            h.word == HostPauseWord::PartlyPaused,
            h.revision,
        ),
        HostPauseRead::Unreadable(why) => {
            eprintln!("enclos app: pause state unreadable after {op}: {why}");
            (false, true, 0)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_pause_by_strips_device_and_request_ids() {
        assert_eq!(
            display_pause_by("owner@example.org (device d1, request p-1)"),
            "owner@example.org"
        );
        assert_eq!(
            display_pause_by("owner@example.org (device d1)"),
            "owner@example.org"
        );
        assert_eq!(display_pause_by("victor"), "victor");
    }

    #[test]
    fn parse_scope_deduplicates_preserving_first_occurrence_order() {
        let scope = parse_scope(Some(vec!["home".into(), "lab".into(), "home".into()])).unwrap();
        assert_eq!(
            scope,
            PauseScope::Names(vec!["home".parse().unwrap(), "lab".parse().unwrap()])
        );
    }

    #[test]
    fn pause_and_resume_reports_map_unreadable_host_to_partly_paused_rev_zero() {
        use crate::engine::{SandboxPauseResult, SandboxResumeResult};

        let lab: SandboxName = "lab".parse().unwrap();
        let pause_report = PauseReport {
            sandboxes: vec![SandboxPauseResult {
                sandbox: lab.clone(),
                outcome: EnginePauseOutcome::Paused,
                services: vec!["enclos.lab.gateway".into()],
                agents: Vec::new(),
                error: None,
            }],
            host: HostPauseRead::Unreadable("corrupt host_pause".into()),
        };
        let pause_res =
            pause_report_to_action_result(Some(std::slice::from_ref(&lab)), pause_report);
        assert!(!pause_res.paused);
        assert!(pause_res.partly);
        assert_eq!(pause_res.revision, 0);
        assert_eq!(
            pause_res.outcomes,
            vec![PauseSandboxOutcome {
                sandbox: "lab".into(),
                outcome: WirePauseOutcome::Paused,
            }]
        );

        let resume_report = ResumeReport {
            no_record: false,
            sandboxes: vec![SandboxResumeResult {
                sandbox: lab.clone(),
                outcome: EngineResumeOutcome::Resumed,
                services: vec!["enclos.lab.gateway".into()],
                agents: Vec::new(),
                error: None,
            }],
            host: HostPauseRead::Unreadable("corrupt sandbox_pauses".into()),
        };
        let resume_res = resume_report_to_action_result(Some(&[lab]), resume_report);
        assert!(!resume_res.paused);
        assert!(resume_res.partly);
        assert_eq!(resume_res.revision, 0);
        assert_eq!(
            resume_res.outcomes,
            vec![PauseSandboxOutcome {
                sandbox: "lab".into(),
                outcome: WirePauseOutcome::Resumed,
            }]
        );
    }
}
