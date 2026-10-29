//! `enclos doctor`: what keeps enclos from working on this host, and which
//! compiled policies enclos now writes differently (design §10).

use enclos::backend::Enforcement;
use enclos::engine::{
    BackendCheck, BackendState, Doctor, Drift, DriftKind, Engine, LineChange, Lines, MAX_LINES,
    NextSession, RanFile, SandboxCheck, Sandboxes,
};
use enclos::error::{Result, exit};

pub fn run(engine: &Engine) -> Result<u8> {
    let doctor = engine.doctor();
    let code = match doctor.has_problems() {
        true => exit::ERROR,
        false => exit::OK,
    };
    match super::output::json() {
        true => super::output::emit(&super::output::with_error(json(&doctor), code, || {
            "doctor found something that keeps enclos or a sandbox from running here, or could not look at all of it: see the report".to_owned()
        })),
        false => print!("{}", shown(&doctor)),
    }
    Ok(code)
}

/// The report as JSON.
fn json(doctor: &Doctor) -> serde_json::Value {
    use serde_json::json;
    let enforced = |e: &Enforcement| match e {
        Enforcement::Enforced => json!({"enforced": "yes"}),
        Enforcement::Partial { note } => json!({"enforced": "partly", "note": note}),
        Enforcement::Unsupported => json!({"enforced": "no"}),
    };
    let backends: Vec<_> = doctor
        .backends
        .iter()
        .map(|b| {
            let c = &b.capabilities;
            json!({
                "kind": b.kind.to_string(),
                "state": match &b.state {
                    BackendState::NotFound { .. } => "not_found",
                    BackendState::Refuses { .. } => "refuses",
                    BackendState::Runs => "runs",
                },
                "reason": match &b.state {
                    BackendState::NotFound { reason } | BackendState::Refuses { reason } => {
                        Some(reason)
                    }
                    BackendState::Runs => None,
                },
                "capabilities": {
                    "files": enforced(&c.fs),
                    "network": enforced(&c.network),
                    "programs": enforced(&c.exec),
                    "limits": enforced(&c.resources),
                    "members": enforced(&c.members),
                },
            })
        })
        .collect();
    let sandbox = |s: &SandboxCheck| {
        let next = match &s.next {
            NextSession::Compiles { version, file } => json!({
                "state": "compiles",
                "version": version,
                "file": super::output::path(file),
            }),
            NextSession::Fails { error } => json!({"state": "fails", "error": error}),
            NextSession::NotChecked => json!({"state": "not_checked"}),
            NextSession::Unknown { why } => json!({"state": "unknown", "why": why}),
        };
        let drift: Vec<_> = s
            .drift
            .iter()
            .map(|d| {
                let mut found = match &d.kind {
                    DriftKind::NoLongerCompiles { error } => json!({
                        "kind": "no_longer_compiles",
                        "error": error,
                    }),
                    DriftKind::Changed { now, ran_file } => {
                        let (edited, lines) = match ran_file {
                            RanFile::Gone => (false, None),
                            RanFile::There { edited, lines } => (*edited, Some(lines)),
                        };
                        json!({
                            "kind": if edited { "edited" } else { "changed" },
                            "now": super::output::path(now),
                            "lines": match lines {
                                Some(Lines::Changed(lines)) => Some(lines.iter().map(|l| match l {
                                    LineChange::Removed(l) => json!({"removed": l}),
                                    LineChange::Added(l) => json!({"added": l}),
                                }).collect::<Vec<_>>()),
                                Some(Lines::TooLong) | None => None,
                            },
                            "lines_not_shown": match lines {
                                Some(Lines::Changed(_)) => None,
                                Some(Lines::TooLong) => Some("too_long"),
                                None => Some("file_gone"),
                            },
                        })
                    }
                };
                found["version"] = json!(d.version);
                found["ran"] = json!(super::output::path(&d.ran));
                found["running_sessions"] = json!(d.running.count);
                found["running_unsure"] = json!(d.running.unsure);
                found
            })
            .collect();
        json!({
            "name": s.name.to_string(),
            "backend": s.backend.to_string(),
            "backend_runs": s.backend_runs(),
            "next_session": next,
            "last_version": s.last_version,
            "drift": drift,
            "unreadable": s.unreadable,
        })
    };
    let sandboxes = match &doctor.sandboxes {
        Sandboxes::NotInitialized => json!({"initialized": false, "sandboxes": []}),
        Sandboxes::Unreadable { error } => {
            json!({"initialized": true, "unreadable": error, "sandboxes": []})
        }
        Sandboxes::Listed(list) => json!({
            "initialized": true,
            "sandboxes": list.iter().map(sandbox).collect::<Vec<_>>(),
        }),
    };
    json!({
        "problems": doctor.has_problems(),
        "backends": backends,
        "records": sandboxes,
    })
}

/// The report as text, one line per fact.
pub fn shown(doctor: &Doctor) -> String {
    let mut out = String::from("Backends\n");
    for b in &doctor.backends {
        out += &backend(b);
    }
    out += "\nSandboxes\n";
    match &doctor.sandboxes {
        Sandboxes::NotInitialized => {
            out += "  none: enclos is not initialized; `enclos init` sets it up\n";
        }
        Sandboxes::Unreadable { error } => {
            out += &format!("  enclos cannot read its records: {error}\n");
        }
        Sandboxes::Listed(sandboxes) if sandboxes.is_empty() => out += "  none\n",
        Sandboxes::Listed(sandboxes) => {
            for s in sandboxes {
                out += &sandbox(s);
            }
        }
    }
    out
}

fn backend(b: &BackendCheck) -> String {
    let state = match &b.state {
        BackendState::NotFound { reason } => format!("not on this host: {reason}"),
        BackendState::Refuses { reason } => {
            format!("on this host, and it refused to run a program: {reason}")
        }
        BackendState::Runs => "runs here".to_owned(),
    };
    let c = &b.capabilities;
    format!(
        "  {}: {state}\n    files {}; network {}; programs {}; limits {}; members {}\n",
        b.kind,
        enforced(&c.fs),
        enforced(&c.network),
        enforced(&c.exec),
        enforced(&c.resources),
        enforced(&c.members)
    )
}

fn sandbox(s: &SandboxCheck) -> String {
    let name = &s.name;
    let mut out = String::new();
    match &s.next {
        NextSession::NotChecked => {
            out += &format!(
                "  {name}: its backend {} does not run here, so no session of it can start\n",
                s.backend
            );
        }
        NextSession::Unknown { why } => {
            out += &format!(
                "  {name}: enclos could not tell whether its active policy compiles: {why}\n"
            );
        }
        NextSession::Fails { error } => {
            out += &format!(
                "  {name}: its active policy cannot be compiled, so its next session cannot start: {error}\n"
            );
        }
        NextSession::Compiles { version, .. } => {
            out += &format!("  {name}: its next session compiles policy v{version}\n");
        }
    }
    // Only once everything was looked at: else not everything was compared,
    // so no match can be claimed.
    if s.backend_runs() && s.unreadable.is_empty() {
        match (s.last_version, s.drift.is_empty()) {
            (None, _) => out += "    no session has run under a compiled policy yet\n",
            (Some(v), true) => {
                out += &format!("    policy v{v} compiles as it did for its last session\n");
            }
            (Some(_), false) => {}
        }
    }
    for drift in &s.drift {
        out += &drift_lines(name.as_str(), drift);
    }
    for what in &s.unreadable {
        out += &format!("    enclos could not look: {what}\n");
    }
    out
}

fn drift_lines(name: &str, drift: &Drift) -> String {
    let mut out = String::new();
    let (version, ran) = (drift.version, drift.ran.display());
    match &drift.kind {
        DriftKind::NoLongerCompiles { error } => {
            out += &format!(
                "    policy v{version}, which a session ran under ({ran}), no longer compiles: {error}\n"
            );
        }
        DriftKind::Changed { now, ran_file } => {
            if let RanFile::There { edited: true, .. } = ran_file {
                out += &format!(
                    "    {ran} no longer holds what policy v{version} compiled to: it was changed after it was written\n"
                );
                if drift.ran.file_name() != now.file_name() {
                    out += &format!(
                        "      policy v{version} also compiles to another file now: {}\n",
                        now.display()
                    );
                }
            } else {
                out += &format!(
                    "    policy v{version} compiles differently from the file a session ran under: what enclos adds when it compiles a policy changed, as an upgrade changes it, or a path the policy names resolves elsewhere now\n      ran under: {ran}\n      compiles now to: {}\n",
                    now.display()
                );
            }
            match ran_file {
                RanFile::Gone => {
                    out += "      the file it ran under is no longer there to compare\n";
                }
                RanFile::There {
                    lines: Lines::Changed(lines),
                    ..
                } => {
                    for line in lines {
                        out += &match line {
                            LineChange::Removed(l) => format!("      - {l}\n"),
                            LineChange::Added(l) => format!("      + {l}\n"),
                        };
                    }
                }
                RanFile::There {
                    lines: Lines::TooLong,
                    ..
                } => {
                    out +=
                        &format!("      more than {MAX_LINES} lines: not compared line by line\n");
                }
            }
        }
    }
    match (drift.running.count, drift.running.unsure) {
        (0, _) => {}
        (n, false) => {
            out += &format!(
                "      {n} running session(s) keep that compiled policy until restarted (`enclos sandbox restart {name}`)\n"
            );
        }
        (n, true) => {
            out += &format!(
                "      {n} session(s) recorded open may still run under it: enclos could not tell which run\n"
            );
        }
    }
    out
}

fn enforced(e: &Enforcement) -> String {
    match e {
        Enforcement::Enforced => "enforced".to_owned(),
        Enforcement::Partial { note } => format!("partly ({note})"),
        Enforcement::Unsupported => "not enforced".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use enclos::backend::{Capabilities, Enforcement};
    use enclos::engine::Running;
    use enclos::model::sandbox::BackendKind;
    use std::path::PathBuf;

    fn doctor(check: SandboxCheck) -> Doctor {
        Doctor {
            backends: vec![BackendCheck {
                kind: BackendKind::Seatbelt,
                state: BackendState::Runs,
                capabilities: Capabilities {
                    fs: Enforcement::Enforced,
                    network: Enforcement::Enforced,
                    exec: Enforcement::Unsupported,
                    resources: Enforcement::Unsupported,
                    members: Enforcement::Enforced,
                },
            }],
            sandboxes: Sandboxes::Listed(vec![check]),
        }
    }

    fn compiles() -> SandboxCheck {
        SandboxCheck {
            name: "home".parse().unwrap(),
            backend: BackendKind::Seatbelt,
            next: NextSession::Compiles {
                version: 2,
                file: PathBuf::from("/c/now.sb"),
            },
            last_version: Some(2),
            drift: Vec::new(),
            unreadable: Vec::new(),
        }
    }

    fn change(ran_file: RanFile, running: Running) -> Drift {
        Drift {
            version: 2,
            ran: PathBuf::from("/c/ran.sb"),
            running,
            kind: DriftKind::Changed {
                now: PathBuf::from("/c/now.sb"),
                ran_file,
            },
        }
    }

    /// What doctor could not look at is said, and nothing it did not
    /// compare is said to match.
    #[test]
    fn what_could_not_be_looked_at_is_not_said_to_match() {
        let shown = shown(&doctor(SandboxCheck {
            next: NextSession::Unknown {
                why: "cannot read its active policy: the database is busy".into(),
            },
            last_version: Some(99),
            unreadable: vec![
                "policy version 99, which a session ran under, is not recorded".into(),
            ],
            ..compiles()
        }));
        assert!(
            shown.contains("home: enclos could not tell whether its active policy compiles: cannot read its active policy: the database is busy"),
            "{shown}"
        );
        assert!(!shown.contains("does not run here"), "{shown}");
        assert!(!shown.contains("compiles as it did"), "{shown}");
        assert!(
            shown.contains("enclos could not look: policy version 99"),
            "{shown}"
        );
    }

    /// A drift names both files, its lines in order, and the sessions
    /// that keep the earlier file.
    #[test]
    fn a_drift_names_both_files_its_lines_and_who_keeps_it() {
        let shown = shown(&doctor(SandboxCheck {
            drift: vec![change(
                RanFile::There {
                    edited: false,
                    lines: Lines::Changed(vec![
                        LineChange::Removed("(old)".into()),
                        LineChange::Added("(new)".into()),
                    ]),
                },
                Running {
                    count: 2,
                    unsure: false,
                },
            )],
            ..compiles()
        }));
        let expected = "    policy v2 compiles differently from the file a session ran under";
        assert!(shown.contains(expected), "{shown}");
        assert!(shown.contains("      ran under: /c/ran.sb\n"), "{shown}");
        assert!(
            shown.contains("      compiles now to: /c/now.sb\n"),
            "{shown}"
        );
        assert!(shown.contains("      - (old)\n      + (new)\n"), "{shown}");
        assert!(
            shown.contains("2 running session(s) keep that compiled policy until restarted (`enclos sandbox restart home`)"),
            "{shown}"
        );
        assert!(!shown.contains("compiles as it did"), "{shown}");
    }

    /// An edited file that also compiles differently now names the file of
    /// now as well; a count enclos could not check is not said as a fact.
    #[test]
    fn an_edited_file_names_the_file_of_now_and_an_unsure_count_says_so() {
        let shown = shown(&doctor(SandboxCheck {
            drift: vec![change(
                RanFile::There {
                    edited: true,
                    lines: Lines::TooLong,
                },
                Running {
                    count: 1,
                    unsure: true,
                },
            )],
            unreadable: vec!["cannot tell which of its sessions run: ps failed".into()],
            ..compiles()
        }));
        assert!(shown.contains("/c/ran.sb no longer holds what policy v2 compiled to: it was changed after it was written"), "{shown}");
        assert!(
            shown.contains("policy v2 also compiles to another file now: /c/now.sb"),
            "{shown}"
        );
        assert!(shown.contains("not compared line by line"), "{shown}");
        assert!(
            shown.contains(
                "1 session(s) recorded open may still run under it: enclos could not tell which run"
            ),
            "{shown}"
        );
        assert!(!shown.contains("keep that compiled policy"), "{shown}");
    }

    #[test]
    fn a_file_no_longer_there_and_a_version_that_no_longer_compiles_are_said() {
        let shown = shown(&doctor(SandboxCheck {
            drift: vec![
                change(RanFile::Gone, Running::default()),
                Drift {
                    version: 1,
                    ran: PathBuf::from("/c/one.sb"),
                    running: Running {
                        count: 1,
                        unsure: false,
                    },
                    kind: DriftKind::NoLongerCompiles {
                        error: "bad rule".into(),
                    },
                },
            ],
            ..compiles()
        }));
        assert!(
            shown.contains("the file it ran under is no longer there to compare"),
            "{shown}"
        );
        assert!(
            shown.contains("policy v1, which a session ran under (/c/one.sb), no longer compiles: bad rule\n      1 running session(s) keep that compiled policy"),
            "{shown}"
        );
    }

    /// A sandbox whose backend does not run here is never said to compile
    /// as it did: nothing of it was compiled.
    #[test]
    fn a_sandbox_whose_backend_does_not_run_is_not_said_to_match() {
        let shown = shown(&doctor(SandboxCheck {
            next: NextSession::NotChecked,
            last_version: Some(2),
            ..compiles()
        }));
        assert!(shown.contains("does not run here"), "{shown}");
        assert!(!shown.contains("compiles as it did"), "{shown}");
    }
}
