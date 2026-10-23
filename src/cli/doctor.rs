//! `enclos doctor`: what keeps enclos from working on this host, and which
//! compiled policies enclos now writes differently (design §10).

use enclos::backend::{Enforcement, Probe};
use enclos::engine::{
    BackendCheck, Doctor, Drift, Engine, LineChange, NextSession, SandboxCheck, Sandboxes,
};
use enclos::error::{Result, exit};

pub fn run(engine: &Engine) -> Result<u8> {
    let doctor = engine.doctor();
    print!("{}", shown(&doctor));
    Ok(if doctor.has_problems() {
        exit::ERROR
    } else {
        exit::OK
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
    let state = match (&b.found, &b.runs) {
        (Probe::Unavailable { reason }, _) => format!("not on this host: {reason}"),
        (Probe::Available, Some(Probe::Available)) => "runs here".to_owned(),
        (Probe::Available, Some(Probe::Unavailable { reason })) => {
            format!("on this host, and it refused to run a program: {reason}")
        }
        (Probe::Available, None) => "on this host; not tried".to_owned(),
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
        NextSession::Unknown => {
            out += &format!("  {name}: enclos could not tell whether its next session can start\n");
        }
        NextSession::Fails { error, .. } => {
            out += &format!(
                "  {name}: its active policy cannot be compiled, so its next session cannot start: {error}\n"
            );
        }
        NextSession::Compiles { version, .. } => {
            out += &format!("  {name}: its next session compiles policy v{version}\n");
        }
    }
    // Only once everything was looked at: else nothing was compared.
    if s.backend_runs && s.unreadable.is_empty() {
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
    match drift {
        Drift::NoLongerCompiles {
            version,
            ran,
            error,
        } => {
            out += &format!(
                "    policy v{version}, which a session ran under ({}), no longer compiles: {error}\n",
                ran.display()
            );
        }
        Drift::Changed(c) if c.edited => {
            out += &format!(
                "    {} no longer holds what policy v{} compiled to: it was changed after it was written\n",
                c.ran.display(),
                c.version
            );
        }
        Drift::Changed(c) => {
            out += &format!(
                "    policy v{} compiles differently from the file a session ran under: enclos's own rules changed, as an upgrade changes them, or a path the policy names resolves elsewhere now\n      ran under: {}\n      compiles now to: {}\n",
                c.version,
                c.ran.display(),
                c.now.display()
            );
        }
    }
    if let Drift::Changed(c) = drift {
        match &c.lines {
            Some(lines) => {
                for line in lines {
                    out += &match line {
                        LineChange::Removed(l) => format!("      - {l}\n"),
                        LineChange::Added(l) => format!("      + {l}\n"),
                    };
                }
            }
            None => out += "      the file it ran under is no longer there to compare\n",
        }
        if c.running > 0 {
            out += &format!(
                "      {} running session(s) keep its rules until restarted (`enclos sandbox restart {name}`)\n",
                c.running
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
    use enclos::model::sandbox::BackendKind;

    fn doctor(check: SandboxCheck) -> Doctor {
        Doctor {
            backends: vec![BackendCheck {
                kind: BackendKind::Seatbelt,
                found: Probe::Available,
                runs: Some(Probe::Available),
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

    /// What doctor could not look at is said, and nothing it did not
    /// compare is said to match.
    #[test]
    fn what_could_not_be_looked_at_is_not_said_to_match() {
        let shown = shown(&doctor(SandboxCheck {
            name: "home".parse().unwrap(),
            backend: BackendKind::Seatbelt,
            backend_runs: true,
            next: NextSession::Unknown,
            last_version: Some(99),
            drift: Vec::new(),
            unreadable: vec![
                "policy version 99, which a session ran under, is not recorded".into(),
            ],
        }));
        assert!(
            shown.contains("home: enclos could not tell whether its next session can start"),
            "{shown}"
        );
        assert!(!shown.contains("does not run here"), "{shown}");
        assert!(!shown.contains("compiles as it did"), "{shown}");
        assert!(
            shown.contains("enclos could not look: policy version 99"),
            "{shown}"
        );
    }
}
