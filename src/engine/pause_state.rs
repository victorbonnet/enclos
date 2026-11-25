//! Pure derivation of per-sandbox and host pause state from `host_pause`,
//! `sandbox_pauses`, each sandbox's recorded lifecycle state, and whether any
//! runtime service is currently installed.
//!
//! Used by both the CLI (`status`, `sandbox list`, `sandbox show`,
//! `sandbox pause`/`resume`) and the app bridge.

use serde::Serialize;

use crate::model::Timestamp;
use crate::model::audit::Actor;
use crate::model::pause::{HostPauseRecord, SandboxPauseRecord};
use crate::model::sandbox::{SandboxName, SandboxState};

/// Why a sandbox is not paused. Present in JSON and text views whenever
/// `paused` is `false`; one of five fixed words.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NotPausedWhy {
    /// A member whose resume was asked and succeeded (or left it as it was).
    Released,
    /// A member whose resume was asked (`released` set) but its runtime
    /// services are not installed again while its state is still `Running`.
    WouldNotStart,
    /// Covered by the pause, with runtime services still installed.
    WouldNotStop,
    /// Covered by the pause, with nothing to pause (already stopped, created,
    /// failed, or no runtime services installed).
    NothingToPause,
    /// Not covered by a pause in force (either no pause in force, or a subset
    /// pause that does not name this sandbox).
    NotCovered,
}

impl NotPausedWhy {
    pub fn as_str(self) -> &'static str {
        match self {
            NotPausedWhy::Released => "released",
            NotPausedWhy::WouldNotStart => "would_not_start",
            NotPausedWhy::WouldNotStop => "would_not_stop",
            NotPausedWhy::NothingToPause => "nothing_to_pause",
            NotPausedWhy::NotCovered => "not_covered",
        }
    }

    /// Plain-words explanation for text output while a pause record is in force.
    pub fn plain(self) -> &'static str {
        match self {
            NotPausedWhy::Released => "resumed",
            NotPausedWhy::WouldNotStart => "resume did not start its runtime services",
            NotPausedWhy::WouldNotStop => "runtime services would not stop",
            NotPausedWhy::NothingToPause => "nothing to pause",
            NotPausedWhy::NotCovered => "you left it running",
        }
    }
}

/// Inputs for deriving one sandbox's pause facts.
#[derive(Debug, Clone, Copy)]
pub struct SandboxPauseInput<'a> {
    pub name: &'a SandboxName,
    pub state: &'a SandboxState,
    /// Whether any runtime service of this sandbox is currently installed.
    pub has_runtime_services: bool,
    pub row: Option<&'a SandboxPauseRecord>,
}

/// Derived pause facts for one sandbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SandboxPauseView {
    /// Whether this sandbox has a `sandbox_pauses` row.
    pub member: bool,
    /// Member with non-empty `labels`, `released` set, state `Running`, and
    /// no runtime service installed (a resume that did not take).
    pub owed: bool,
    /// Reached by the pause in force (only meaningful while a host record exists).
    pub covered: bool,
    /// Presented as `paused`: member ∧ `released` NULL ∧ `labels` non-empty ∧
    /// state `Running` ∧ no runtime service installed.
    pub paused: bool,
    /// State is `Running` and not paused.
    pub runs: bool,
    /// Present iff `!paused`.
    pub why: Option<NotPausedWhy>,
}

/// Derives pause facts for a single sandbox given the optional `host_pause` record.
pub fn derive_sandbox(
    host: Option<&HostPauseRecord>,
    input: SandboxPauseInput<'_>,
) -> SandboxPauseView {
    let is_running = matches!(input.state, SandboxState::Running);
    let Some(host) = host else {
        return SandboxPauseView {
            member: false,
            owed: false,
            covered: false,
            paused: false,
            runs: is_running,
            why: Some(NotPausedWhy::NotCovered),
        };
    };

    match input.row {
        Some(row) => {
            let member = true;
            let has_labels = !row.labels.is_empty();
            let owed =
                has_labels && row.released.is_some() && is_running && !input.has_runtime_services;
            let covered = row.released.is_none() || owed;
            let paused =
                row.released.is_none() && has_labels && is_running && !input.has_runtime_services;
            let runs = is_running && !paused;
            let why = if paused {
                None
            } else if row.released.is_some() {
                if owed {
                    Some(NotPausedWhy::WouldNotStart)
                } else {
                    Some(NotPausedWhy::Released)
                }
            } else if has_labels && input.has_runtime_services {
                Some(NotPausedWhy::WouldNotStop)
            } else {
                Some(NotPausedWhy::NothingToPause)
            };
            SandboxPauseView {
                member,
                owed,
                covered,
                paused,
                runs,
                why,
            }
        }
        None => {
            let covered = host.pause_all;
            let why = if host.pause_all {
                if input.has_runtime_services {
                    NotPausedWhy::WouldNotStop
                } else {
                    NotPausedWhy::NothingToPause
                }
            } else {
                NotPausedWhy::NotCovered
            };
            SandboxPauseView {
                member: false,
                owed: false,
                covered,
                paused: false,
                runs: is_running,
                why: Some(why),
            }
        }
    }
}

/// The host-level pause word.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HostPauseWord {
    Running,
    Paused,
    PartlyPaused,
}

impl HostPauseWord {
    pub fn display(self) -> &'static str {
        match self {
            HostPauseWord::Running => "Running",
            HostPauseWord::Paused => "Paused",
            HostPauseWord::PartlyPaused => "Partly paused",
        }
    }
}

/// Derived host-level pause state across all sandboxes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostPauseView {
    pub word: HostPauseWord,
    /// `0` when no record is in force.
    pub revision: u64,
    pub since: Option<Timestamp>,
    pub by: Option<Actor>,
    pub pause_all: bool,
    /// Sandboxes that currently run (state `Running` and not paused).
    pub runs: Vec<SandboxName>,
    /// Covered sandboxes whose resume did not take.
    pub owed: Vec<SandboxName>,
    /// `true` when `pause_all` is in force over a host where nothing runs and
    /// nothing is paused (every sandbox is already stopped).
    pub nothing_to_pause_all: bool,
}

impl HostPauseView {
    /// Human-readable one-line summary when a pause record is in force; `None`
    /// when no record is in force (`Running`).
    pub fn summary_line(&self) -> Option<String> {
        if self.word == HostPauseWord::Running {
            return None;
        }
        if self.nothing_to_pause_all {
            return Some("Paused · nothing to pause: every sandbox is already stopped".to_owned());
        }
        match self.word {
            HostPauseWord::Running => None,
            HostPauseWord::Paused => Some("Paused".to_owned()),
            HostPauseWord::PartlyPaused => {
                let mut parts = Vec::new();
                if !self.runs.is_empty() {
                    let names: Vec<&str> = self.runs.iter().map(SandboxName::as_str).collect();
                    parts.push(format!("running: {}", names.join(", ")));
                }
                if !self.owed.is_empty() {
                    let names: Vec<&str> = self.owed.iter().map(SandboxName::as_str).collect();
                    parts.push(format!("would not start: {}", names.join(", ")));
                }
                if parts.is_empty() {
                    Some("Partly paused".to_owned())
                } else {
                    Some(format!("Partly paused ({})", parts.join("; ")))
                }
            }
        }
    }
}

/// Host pause state as read for display (`status`, `sandbox list`, `sandbox show`).
/// Distinguishes a readable state from an unreadable record/rows so callers
/// never guess `Running` over an unreadable record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostPauseRead {
    Readable(HostPauseView),
    Unreadable(String),
}

impl HostPauseRead {
    /// Whether a host pause record is in force (readable and not `Running`).
    pub fn in_force(&self) -> bool {
        matches!(self, HostPauseRead::Readable(v) if v.word != HostPauseWord::Running)
    }

    /// One-line summary to display: `None` when readable and `Running` (no
    /// record in force); otherwise the host pause line or unreadable notice.
    pub fn summary_line(&self) -> Option<String> {
        match self {
            HostPauseRead::Readable(v) => v.summary_line(),
            HostPauseRead::Unreadable(why) => Some(format!("pause state unreadable: {why}")),
        }
    }
}

impl Serialize for HostPauseRead {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        #[derive(Serialize)]
        struct ActorRef<'a> {
            user: &'a str,
            host: &'a str,
        }
        match self {
            HostPauseRead::Readable(v) => {
                let mut map = s.serialize_map(Some(7))?;
                map.serialize_entry("state", &v.word)?;
                map.serialize_entry("revision", &v.revision)?;
                map.serialize_entry("since", &v.since)?;
                let by = v.by.as_ref().map(|a| ActorRef {
                    user: &a.user,
                    host: &a.host,
                });
                map.serialize_entry("by", &by)?;
                map.serialize_entry("pause_all", &v.pause_all)?;
                let runs: Vec<&str> = v.runs.iter().map(SandboxName::as_str).collect();
                let owed: Vec<&str> = v.owed.iter().map(SandboxName::as_str).collect();
                map.serialize_entry("runs", &runs)?;
                map.serialize_entry("owed", &owed)?;
                map.end()
            }
            HostPauseRead::Unreadable(error) => {
                let mut map = s.serialize_map(Some(2))?;
                map.serialize_entry("state", "unreadable")?;
                map.serialize_entry("error", error)?;
                map.end()
            }
        }
    }
}

/// Derives the host-level pause state from the optional `host_pause` record and
/// every sandbox's inputs.
pub fn derive_host(
    host: Option<&HostPauseRecord>,
    sandboxes: &[SandboxPauseInput<'_>],
) -> HostPauseView {
    let Some(host) = host else {
        let runs = sandboxes
            .iter()
            .filter(|s| matches!(s.state, SandboxState::Running))
            .map(|s| s.name.clone())
            .collect();
        return HostPauseView {
            word: HostPauseWord::Running,
            revision: 0,
            since: None,
            by: None,
            pause_all: false,
            runs,
            owed: Vec::new(),
            nothing_to_pause_all: false,
        };
    };

    let mut runs = Vec::new();
    let mut owed = Vec::new();
    let mut paused_any = false;
    for input in sandboxes {
        let derived = derive_sandbox(Some(host), *input);
        if derived.paused {
            paused_any = true;
        }
        if derived.runs {
            runs.push(input.name.clone());
        }
        if derived.owed {
            owed.push(input.name.clone());
        }
    }

    let word = if runs.is_empty() && owed.is_empty() {
        HostPauseWord::Paused
    } else {
        HostPauseWord::PartlyPaused
    };
    let nothing_to_pause_all = word == HostPauseWord::Paused && host.pause_all && !paused_any;

    HostPauseView {
        word,
        revision: host.revision,
        since: Some(host.at),
        by: Some(host.by.clone()),
        pause_all: host.pause_all,
        runs,
        owed,
        nothing_to_pause_all,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::now;

    fn actor() -> Actor {
        Actor {
            user: "alice".into(),
            host: "mac".into(),
        }
    }

    fn sb(name: &str) -> SandboxName {
        name.parse().unwrap()
    }

    fn host_rec(pause_all: bool, revision: u64) -> HostPauseRecord {
        HostPauseRecord {
            revision,
            pause_all,
            by: actor(),
            at: now(),
        }
    }

    fn row(
        name: &str,
        labels: &[&str],
        kept: &[&str],
        released: Option<Timestamp>,
    ) -> SandboxPauseRecord {
        SandboxPauseRecord {
            sandbox: sb(name),
            labels: labels.iter().map(|s| (*s).to_owned()).collect(),
            kept: kept.iter().map(|s| (*s).to_owned()).collect(),
            released,
            at: now(),
            by: actor(),
        }
    }

    #[test]
    fn no_record_means_running_and_not_covered() {
        let a = sb("alpha");
        let b = sb("beta");
        let inputs = [
            SandboxPauseInput {
                name: &a,
                state: &SandboxState::Running,
                has_runtime_services: true,
                row: None,
            },
            SandboxPauseInput {
                name: &b,
                state: &SandboxState::Stopped,
                has_runtime_services: false,
                row: None,
            },
        ];
        let da = derive_sandbox(None, inputs[0]);
        assert!(!da.member && !da.covered && !da.paused && !da.owed && da.runs);
        assert_eq!(da.why, Some(NotPausedWhy::NotCovered));

        let host = derive_host(None, &inputs);
        assert_eq!(host.word, HostPauseWord::Running);
        assert_eq!(host.revision, 0);
        assert_eq!(host.runs, vec![a]);
        assert!(host.owed.is_empty());
        assert_eq!(host.summary_line(), None);
    }

    #[test]
    fn paused_member_and_all_paused_host() {
        let h = host_rec(true, 100);
        let a = sb("alpha");
        let ra = row(
            "alpha",
            &["enclos.alpha.gateway"],
            &["enclos.alpha.proxy"],
            None,
        );
        let input = SandboxPauseInput {
            name: &a,
            state: &SandboxState::Running,
            has_runtime_services: false,
            row: Some(&ra),
        };
        let d = derive_sandbox(Some(&h), input);
        assert!(d.member && d.covered && d.paused && !d.owed && !d.runs);
        assert_eq!(d.why, None);

        let host = derive_host(Some(&h), &[input]);
        assert_eq!(host.word, HostPauseWord::Paused);
        assert!(!host.nothing_to_pause_all);
        assert_eq!(host.summary_line().as_deref(), Some("Paused"));
    }

    #[test]
    fn pause_all_over_stopped_sandboxes_says_nothing_to_pause() {
        let h = host_rec(true, 100);
        let a = sb("alpha");
        let ra = row("alpha", &[], &[], None);
        let input = SandboxPauseInput {
            name: &a,
            state: &SandboxState::Stopped,
            has_runtime_services: false,
            row: Some(&ra),
        };
        let d = derive_sandbox(Some(&h), input);
        assert!(d.member && d.covered && !d.paused && !d.owed && !d.runs);
        assert_eq!(d.why, Some(NotPausedWhy::NothingToPause));

        let host = derive_host(Some(&h), &[input]);
        assert_eq!(host.word, HostPauseWord::Paused);
        assert!(host.nothing_to_pause_all);
        assert_eq!(
            host.summary_line().as_deref(),
            Some("Paused · nothing to pause: every sandbox is already stopped")
        );
    }

    #[test]
    fn never_paused_while_anything_runs_and_names_runners() {
        let h = host_rec(false, 200);
        let a = sb("alpha");
        let b = sb("beta");
        let ra = row("alpha", &["enclos.alpha.gateway"], &[], None);
        let inputs = [
            SandboxPauseInput {
                name: &a,
                state: &SandboxState::Running,
                has_runtime_services: false,
                row: Some(&ra),
            },
            SandboxPauseInput {
                name: &b,
                state: &SandboxState::Running,
                has_runtime_services: true,
                row: None,
            },
        ];
        let db = derive_sandbox(Some(&h), inputs[1]);
        assert!(!db.member && !db.covered && !db.paused && db.runs);
        assert_eq!(db.why, Some(NotPausedWhy::NotCovered));

        let host = derive_host(Some(&h), &inputs);
        assert_eq!(host.word, HostPauseWord::PartlyPaused);
        assert_eq!(host.runs, vec![b]);
        assert!(host.owed.is_empty());
        assert_eq!(
            host.summary_line().as_deref(),
            Some("Partly paused (running: beta)")
        );
    }

    #[test]
    fn owed_member_stays_covered_and_host_is_partly_paused() {
        let h = host_rec(true, 300);
        let a = sb("alpha");
        let ra = row("alpha", &["enclos.alpha.gateway"], &[], Some(now()));
        let input = SandboxPauseInput {
            name: &a,
            state: &SandboxState::Running,
            has_runtime_services: false,
            row: Some(&ra),
        };
        let d = derive_sandbox(Some(&h), input);
        assert!(d.member && d.owed && d.covered && !d.paused && d.runs);
        assert_eq!(d.why, Some(NotPausedWhy::WouldNotStart));

        let host = derive_host(Some(&h), &[input]);
        assert_eq!(host.word, HostPauseWord::PartlyPaused);
        assert_eq!(host.runs, vec![a.clone()]);
        assert_eq!(host.owed, vec![a]);
    }

    #[test]
    fn released_member_with_services_back_is_released_not_covered() {
        let h = host_rec(true, 301);
        let a = sb("alpha");
        let ra = row("alpha", &["enclos.alpha.gateway"], &[], Some(now()));
        let input = SandboxPauseInput {
            name: &a,
            state: &SandboxState::Running,
            has_runtime_services: true,
            row: Some(&ra),
        };
        let d = derive_sandbox(Some(&h), input);
        assert!(d.member && !d.owed && !d.covered && !d.paused && d.runs);
        assert_eq!(d.why, Some(NotPausedWhy::Released));
    }

    #[test]
    fn would_not_stop_and_new_sandbox_under_pause_all() {
        let h = host_rec(true, 400);
        let a = sb("alpha");
        let b = sb("beta");
        let c = sb("gamma");
        let ra = row("alpha", &["enclos.alpha.gateway"], &[], None);
        let da = derive_sandbox(
            Some(&h),
            SandboxPauseInput {
                name: &a,
                state: &SandboxState::Running,
                has_runtime_services: true,
                row: Some(&ra),
            },
        );
        assert!(da.covered && !da.paused && da.runs);
        assert_eq!(da.why, Some(NotPausedWhy::WouldNotStop));

        // Created while pause_all = 1, no row, no services: covered, nothing_to_pause.
        let db = derive_sandbox(
            Some(&h),
            SandboxPauseInput {
                name: &b,
                state: &SandboxState::Created,
                has_runtime_services: false,
                row: None,
            },
        );
        assert!(!db.member && db.covered && !db.paused && !db.runs);
        assert_eq!(db.why, Some(NotPausedWhy::NothingToPause));

        // No row under pause_all = 1, but somehow has services: covered, would_not_stop.
        let dc = derive_sandbox(
            Some(&h),
            SandboxPauseInput {
                name: &c,
                state: &SandboxState::Running,
                has_runtime_services: true,
                row: None,
            },
        );
        assert!(!dc.member && dc.covered && !dc.paused && dc.runs);
        assert_eq!(dc.why, Some(NotPausedWhy::WouldNotStop));
    }

    #[test]
    fn stopped_while_paused_becomes_not_paused_nothing_to_pause() {
        let h = host_rec(true, 500);
        let a = sb("alpha");
        let ra = row("alpha", &["enclos.alpha.gateway"], &[], None);
        let d = derive_sandbox(
            Some(&h),
            SandboxPauseInput {
                name: &a,
                state: &SandboxState::Stopped,
                has_runtime_services: false,
                row: Some(&ra),
            },
        );
        assert!(d.member && d.covered && !d.paused && !d.owed && !d.runs);
        assert_eq!(d.why, Some(NotPausedWhy::NothingToPause));
    }
}
