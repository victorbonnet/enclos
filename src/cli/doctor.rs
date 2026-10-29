//! `enclos doctor`: what keeps enclos from working on this host, which
//! compiled policies enclos now writes differently, and secrets in a
//! runtime's settings (design §10).

use enclos::backend::Enforcement;
use enclos::engine::{
    BackendCheck, BackendState, Doctor, Drift, DriftKind, Engine, Held, LineChange, Lines,
    MAX_LINES, NextSession, RanFile, SandboxCheck, Sandboxes, SettingsFinding,
};
use enclos::error::{Result, exit};

pub fn run(engine: &Engine) -> Result<u8> {
    use enclos::backend::seatbelt::{BASELINE_VAR, Baseline};
    if Baseline::from_env() == Ok(Baseline::AllowDefault) {
        super::output::note(&format!(
            "doctor compiles on the (allow default) comparison baseline, as {BASELINE_VAR} asks: what it compares below is against that baseline, not (deny default), which services and release builds always use"
        ));
    }
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
                    BackendState::Unavailable { .. } => "unavailable",
                    BackendState::Refuses { .. } => "refuses",
                    BackendState::Runs => "runs",
                },
                "reason": match &b.state {
                    BackendState::Unavailable { reason } | BackendState::Refuses { reason } => {
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
                        let (edited, on_allow_default, lines) = match ran_file {
                            RanFile::Gone => (false, false, None),
                            RanFile::There { written, lines } => {
                                (written.edited(), written.on_allow_default(), Some(lines))
                            }
                        };
                        json!({
                            "kind": if edited { "edited" } else { "changed" },
                            "ran_on_allow_default": on_allow_default,
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
        let settings: Vec<_> = s
            .settings
            .iter()
            .map(|f| match f {
                SettingsFinding::Plain {
                    file,
                    line,
                    held: Held::Variable(variable),
                    granted,
                } => json!({
                    "kind": "plain",
                    "file": file.to_string(),
                    "line": line,
                    "variable": variable,
                    "granted": granted,
                }),
                SettingsFinding::Plain {
                    file,
                    line,
                    held: Held::Key(key),
                    ..
                } => json!({
                    "kind": "plain",
                    "file": file.to_string(),
                    "line": line,
                    "key": key,
                }),
                SettingsFinding::NotGranted {
                    file,
                    line,
                    variable,
                } => json!({
                    "kind": "not_granted",
                    "file": file.to_string(),
                    "line": line,
                    "variable": variable,
                }),
            })
            .collect();
        json!({
            "name": s.name.to_string(),
            "backend": s.backend.to_string(),
            "backend_runs": s.backend_runs(),
            "next_session": next,
            "last_version": s.last_version,
            "drift": drift,
            "settings": settings,
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
        BackendState::Unavailable { reason } => format!("not usable here: {reason}"),
        BackendState::Refuses { reason } => {
            format!("on this host, and it refused to run a program: {reason}")
        }
        BackendState::Runs => "runs here".to_owned(),
    };
    let c = &b.capabilities;
    let mut out = format!("  {}: {state}\n", b.kind);
    // Not a claim about this host when the backend is not on it.
    if let BackendState::Unavailable { .. } = b.state {
        out += "    where it runs, it would enforce:\n";
    }
    for (what, e) in [
        ("files", &c.fs),
        ("network", &c.network),
        ("programs", &c.exec),
        ("limits", &c.resources),
        ("members", &c.members),
    ] {
        out += &format!("    {what:<10}{}\n", hanging(&enforced(e), 14));
    }
    out
}

/// `text` wrapped at word boundaries to fit [`WIDTH`] columns once
/// `indent` columns in, its later lines indented by `indent`, so a long
/// note stays in its column rather than running back to the margin.
fn hanging(text: &str, indent: usize) -> String {
    let room = WIDTH.saturating_sub(indent).max(20);
    let mut lines: Vec<String> = Vec::new();
    for word in text.split(' ') {
        match lines.last_mut() {
            Some(line) if line.len() + 1 + word.len() <= room => {
                line.push(' ');
                line.push_str(word);
            }
            _ => lines.push(word.to_owned()),
        }
    }
    lines.join(&format!("\n{}", " ".repeat(indent)))
}

/// The columns doctor's text fits in: a terminal's usual width.
const WIDTH: usize = 80;

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
    for finding in &s.settings {
        out += &settings_line(name.as_str(), finding);
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
            if let RanFile::There { written, .. } = ran_file
                && written.on_allow_default()
            {
                out += &format!(
                    "    {ran} is on the (allow default) comparison baseline (ADR 0006), which only a debug build compiles\n"
                );
            }
            if let RanFile::There { written, .. } = ran_file
                && written.edited()
            {
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
    // A restart helps only a version that still compiles: one that does
    // not would stop the sandbox and then not start it again.
    let compiles = matches!(drift.kind, DriftKind::Changed { .. });
    match (drift.running.count, drift.running.unsure) {
        (0, _) => {}
        (n, false) if compiles => {
            out += &format!(
                "      {n} running session(s) keep that compiled policy until restarted (`enclos sandbox restart {name}`)\n"
            );
        }
        (n, false) => {
            out += &format!(
                "      {n} running session(s) keep that compiled policy; fix what keeps it from compiling (above) before `enclos sandbox restart {name}`, which would not start it again\n"
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

/// A secret found in the runtime's settings, and what to do about it. Only
/// names: doctor never prints a value.
fn settings_line(name: &str, finding: &SettingsFinding) -> String {
    let store = format!("store it with `enclos secret set {name}/<secret>`");
    let grant = format!("grant it with `enclos policy edit {name}`");
    match finding {
        SettingsFinding::Plain {
            file,
            line,
            held: Held::Variable(variable),
            granted: true,
        } => format!(
            "    {file}, line {line}, holds {variable} in plain text, which the policy already grants as a secret: remove the line\n"
        ),
        SettingsFinding::Plain {
            file,
            line,
            held: Held::Variable(variable),
            granted: false,
        } => format!(
            "    {file}, line {line}, holds {variable} in plain text, where any process of the sandbox reads it: {store}, {grant} as {variable}, then remove the line\n"
        ),
        SettingsFinding::Plain {
            file,
            line,
            held: Held::Key(key),
            ..
        } => format!(
            "    {file}, line {line}, holds `{key}` in plain text, where any process of the sandbox reads it: {store}, {grant} as a variable, then set `{key}` to `${{VARIABLE}}` with the runtime's own command\n"
        ),
        SettingsFinding::NotGranted {
            file,
            line,
            variable,
        } => format!(
            "    {file}, line {line}, refers to ${{{variable}}}, which the policy does not grant, so nothing enclos gives the sandbox sets it: {store}, then {grant} as {variable}\n"
        ),
    }
}

fn enforced(e: &Enforcement) -> String {
    match e {
        Enforcement::Enforced => "enforced".to_owned(),
        Enforcement::Partial { note } => format!("partly: {note}"),
        Enforcement::Unsupported => "not enforced".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use enclos::backend::seatbelt::Baseline;
    use enclos::backend::{Capabilities, Enforcement};
    use enclos::engine::{Running, Written};
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
            settings: Vec::new(),
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

    /// Each capability is a line of its own, its value in one column, and a
    /// long note wraps within that column, never back to the margin.
    #[test]
    fn each_capability_is_a_line_and_a_long_note_keeps_its_column() {
        let mut d = doctor(compiles());
        d.backends[0].capabilities.members = Enforcement::Partial {
            note: "markers its processes hold, the parent chain and process groups (ADR 0030); one that closes its marker and leaves its group and parent is not found".into(),
        };
        let shown = shown(&d);
        assert!(
            shown.contains("  seatbelt: runs here\n    files     enforced\n    network   enforced\n    programs  not enforced\n"),
            "{shown}"
        );
        let members: Vec<&str> = shown
            .lines()
            .skip_while(|l| !l.starts_with("    members   partly: markers"))
            .take_while(|l| !l.is_empty() && !l.starts_with("Sandboxes"))
            .collect();
        assert!(members.len() > 1, "{shown}");
        for line in &members {
            assert!(line.len() <= WIDTH, "{line:?}");
        }
        for line in &members[1..] {
            assert!(line.starts_with(&" ".repeat(14)), "{line:?}");
        }
    }

    /// A backend not on this host says what it would enforce, not what it
    /// enforces here.
    #[test]
    fn a_backend_not_here_says_what_it_would_enforce() {
        let mut d = doctor(compiles());
        d.backends[0].state = BackendState::Unavailable {
            reason: "not on this host".into(),
        };
        let shown = shown(&d);
        assert!(
            shown.contains("not usable here: not on this host\n    where it runs, it would enforce:\n    files     enforced\n"),
            "{shown}"
        );
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
                    written: Written::AsWritten {
                        baseline: Some(Baseline::DenyDefault),
                    },
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

    /// A file on the `(allow default)` comparison baseline is said to be,
    /// in text and in JSON.
    #[test]
    fn a_file_on_the_comparison_baseline_is_said_so() {
        let doctor = doctor(SandboxCheck {
            drift: vec![change(
                RanFile::There {
                    written: Written::AsWritten {
                        baseline: Some(Baseline::AllowDefault),
                    },
                    lines: Lines::TooLong,
                },
                Running::default(),
            )],
            ..compiles()
        });
        let shown = shown(&doctor);
        assert!(
            shown.contains("/c/ran.sb is on the (allow default) comparison baseline (ADR 0006)"),
            "{shown}"
        );
        let json = json(&doctor);
        assert_eq!(
            json["records"]["sandboxes"][0]["drift"][0]["ran_on_allow_default"], true,
            "{json}"
        );
    }

    /// An edited file that also compiles differently now names the file of
    /// now as well; a count enclos could not check is not said as a fact.
    #[test]
    fn an_edited_file_names_the_file_of_now_and_an_unsure_count_says_so() {
        let shown = shown(&doctor(SandboxCheck {
            drift: vec![change(
                RanFile::There {
                    written: Written::Edited,
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
        // No restart is suggested for a version that would not start again.
        assert!(
            shown.contains("fix what keeps it from compiling"),
            "{shown}"
        );
        assert_eq!(shown.matches("until restarted").count(), 0, "{shown}");
    }

    /// Each secret found in the runtime's settings is a line naming the file,
    /// the line and what to do, in text and in JSON.
    #[test]
    fn secrets_in_the_runtimes_settings_are_said_by_name() {
        use enclos::runtime::HomePath;
        let env = HomePath::new(".hermes/.env").unwrap();
        let config = HomePath::new(".hermes/config.yaml").unwrap();
        let doctor = doctor(SandboxCheck {
            settings: vec![
                SettingsFinding::Plain {
                    file: env.clone(),
                    line: 3,
                    held: Held::Variable("OPENROUTER_API_KEY".into()),
                    granted: false,
                },
                SettingsFinding::Plain {
                    file: env,
                    line: 4,
                    held: Held::Variable("TELEGRAM_BOT_TOKEN".into()),
                    granted: true,
                },
                SettingsFinding::Plain {
                    file: config.clone(),
                    line: 7,
                    held: Held::Key("token".into()),
                    granted: false,
                },
                SettingsFinding::NotGranted {
                    file: config,
                    line: 9,
                    variable: "SLACK_BOT_TOKEN".into(),
                },
            ],
            ..compiles()
        });
        let shown = shown(&doctor);
        for expected in [
            "    ~/.hermes/.env, line 3, holds OPENROUTER_API_KEY in plain text, where any process of the sandbox reads it: store it with `enclos secret set home/<secret>`, grant it with `enclos policy edit home` as OPENROUTER_API_KEY, then remove the line\n",
            "    ~/.hermes/.env, line 4, holds TELEGRAM_BOT_TOKEN in plain text, which the policy already grants as a secret: remove the line\n",
            "    ~/.hermes/config.yaml, line 7, holds `token` in plain text",
            "then set `token` to `${VARIABLE}` with the runtime's own command\n",
            "    ~/.hermes/config.yaml, line 9, refers to ${SLACK_BOT_TOKEN}, which the policy does not grant",
        ] {
            assert!(shown.contains(expected), "{expected}\n{shown}");
        }
        // A secret found is reported, not a problem.
        assert!(!doctor.has_problems());
        let json = json(&doctor);
        let settings = &json["records"]["sandboxes"][0]["settings"];
        assert_eq!(settings[0]["kind"], "plain", "{json}");
        assert_eq!(settings[0]["file"], "~/.hermes/.env", "{json}");
        assert_eq!(settings[0]["variable"], "OPENROUTER_API_KEY", "{json}");
        assert_eq!(settings[1]["granted"], true, "{json}");
        assert_eq!(settings[2]["key"], "token", "{json}");
        assert_eq!(settings[3]["kind"], "not_granted", "{json}");
        assert_eq!(json["problems"], false, "{json}");
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
