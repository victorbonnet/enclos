//! `enclos doctor`: what keeps enclos from working on this host, and which
//! compiled policies enclos now writes differently (design §10).

use enclos::backend::{Enforcement, Probe};
use enclos::engine::{CompiledCheck, Doctor, Engine};
use enclos::error::{Result, exit};

pub fn run(engine: &Engine) -> Result<u8> {
    let doctor = engine.doctor()?;
    print(&doctor);
    Ok(if doctor.has_problems() {
        exit::ERROR
    } else {
        exit::OK
    })
}

fn print(doctor: &Doctor) {
    println!("Backends");
    for b in &doctor.backends {
        match &b.runs {
            Probe::Available => println!("  {}: runs here", b.kind),
            Probe::Unavailable { reason } => println!("  {}: cannot run here: {reason}", b.kind),
        }
        let c = &b.capabilities;
        println!(
            "    files {}; network {}; programs {}; limits {}; members {}",
            enforced(&c.fs),
            enforced(&c.network),
            enforced(&c.exec),
            enforced(&c.resources),
            enforced(&c.members)
        );
    }
    println!();
    println!("Sandboxes");
    let Some(sandboxes) = &doctor.sandboxes else {
        println!("  none: enclos is not initialized; `enclos init` sets it up");
        return;
    };
    if sandboxes.is_empty() {
        println!("  none");
    }
    for s in sandboxes {
        let backend_runs = doctor
            .backends
            .iter()
            .any(|b| b.kind == s.backend && b.runs == Probe::Available);
        if !backend_runs {
            println!(
                "  {}: its backend {} cannot run here, so no session of it can start",
                s.name, s.backend
            );
        }
        match &s.compiled {
            CompiledCheck::NeverRun => println!(
                "  {}: no session has run yet, so there is no compiled policy to compare",
                s.name
            ),
            CompiledCheck::Same { version } => println!(
                "  {}: policy v{version} compiles as it did for its last session",
                s.name
            ),
            CompiledCheck::Fails { error } => println!(
                "  {}: its policy cannot be compiled, so its next session cannot start: {error}",
                s.name
            ),
            CompiledCheck::Changed {
                version,
                ran,
                now,
                lines,
                open,
            } => {
                println!(
                    "  {}: policy v{version} compiles differently from the file its last session ran under: enclos's own rules changed, as an upgrade changes them",
                    s.name
                );
                println!("    ran under: {}", ran.display());
                println!("    next session: {}", now.display());
                match lines {
                    Some(lines) => {
                        for l in &lines.removed {
                            println!("    - {l}");
                        }
                        for l in &lines.added {
                            println!("    + {l}");
                        }
                    }
                    None => println!("    the file it ran under is no longer there to compare"),
                }
                if *open > 0 {
                    println!(
                        "    {open} open session(s) keep the earlier rules until restarted (`enclos sandbox restart {}`)",
                        s.name
                    );
                }
            }
        }
    }
}

fn enforced(e: &Enforcement) -> String {
    match e {
        Enforcement::Enforced => "enforced".to_owned(),
        Enforcement::Partial { note } => format!("partly ({note})"),
        Enforcement::Unsupported => "not enforced".to_owned(),
    }
}
