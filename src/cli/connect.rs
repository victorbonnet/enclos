//! `enclos connect`: a shell, or a command, inside a sandbox, in this
//! terminal; and `enclos exec`: one command, for a script or another
//! program.

use std::ffi::OsString;

/// Writes a line to stderr, where enclos's own messages go so that a
/// command's output stays clean. A stderr closed already (`2>&1 | head`)
/// never turns the command's exit code into a panic's.
macro_rules! say {
    ($($arg:tt)*) => {{
        use std::io::Write as _;
        let _ = writeln!(std::io::stderr(), $($arg)*);
    }};
}

use super::output::note;

use clap::Args;

use enclos::engine::Engine;
use enclos::engine::{Left, ServiceWait, SessionEnd};
use enclos::error::{Result, exit};
use enclos::model::audit::Actor;
use enclos::model::plan::{Confirm, Planned};
use enclos::model::sandbox::SandboxName;

#[derive(Args)]
pub struct ConnectArgs {
    sandbox: SandboxName,
    /// A command to run instead of a shell, after `--`, such as the
    /// runtime's own: `enclos connect lab -- hermes -p scout`.
    #[arg(last = true)]
    command: Vec<OsString>,
}

#[derive(Args)]
pub struct ExecArgs {
    sandbox: SandboxName,
    /// The command to run, after `--`: `enclos exec lab -- hermes -p scout chat -q "hello"`.
    #[arg(last = true, required = true)]
    command: Vec<OsString>,
}

pub fn run(engine: &Engine, by: &Actor, confirm: Confirm, args: ConnectArgs) -> Result<u8> {
    start_service_first(engine, by, &args.sandbox, confirm)?;
    let end = match engine.connect(by, &args.sandbox, args.command, confirm)? {
        // Nothing runs on a dry run: with --json, its plan is the document.
        Planned::DryRun(plan) if super::output::json() => {
            super::output::emit(&super::output::plan(&plan));
            return Ok(exit::OK);
        }
        Planned::DryRun(plan) => {
            plan.changes.iter().for_each(|c| println!("Would {c}."));
            return Ok(exit::OK);
        }
        Planned::Done(end) => end,
    };
    finish(engine, &args.sandbox, &end)
}

/// `enclos exec`: one command in the sandbox; enclos exits with the
/// command's code, or 125 when it fails itself.
pub fn exec(engine: &Engine, by: &Actor, confirm: Confirm, args: ExecArgs) -> Result<u8> {
    start_service_first(engine, by, &args.sandbox, confirm)?;
    let end = match engine.exec(by, &args.sandbox, args.command, confirm)? {
        // Nothing runs on a dry run: with --json, its plan is the document.
        Planned::DryRun(plan) if super::output::json() => {
            super::output::emit(&super::output::plan(&plan));
            return Ok(exit::OK);
        }
        Planned::DryRun(plan) => {
            plan.changes.iter().for_each(|c| println!("Would {c}."));
            return Ok(exit::OK);
        }
        Planned::Done(end) => end,
    };
    finish(engine, &args.sandbox, &end)
}

/// The runtime's own clients need its service, and a session reaches it
/// only on the port it holds when the session starts (ADR 0028), so it is
/// started first. On stderr, so a command's output stays clean.
fn start_service_first(
    engine: &Engine,
    by: &Actor,
    sandbox: &SandboxName,
    confirm: Confirm,
) -> Result<()> {
    if confirm == Confirm::DryRun {
        return Ok(());
    }
    let mut say = |what: String| note(&what);
    if let Some(ServiceWait {
        service,
        late: Some(why),
        ..
    }) = engine.start_listener_service(by, sandbox, &mut say)?
    {
        note(&format!(
            "starting the session while the {service} is not listening ({why}); its log: `enclos logs {sandbox}`."
        ));
    }
    Ok(())
}

/// Reports the session's end and the sandbox's agent changes, and returns
/// the command's exit code.
fn finish(engine: &Engine, sandbox: &SandboxName, end: &SessionEnd) -> Result<u8> {
    report_end(sandbox, end);
    // Agents made or deleted in the session with the runtime's own commands.
    // On stderr, so a command's output stays clean; the session's exit code
    // stays the command's.
    match super::agent::check_notes(engine, sandbox, false) {
        Ok(notes) => notes.iter().for_each(|n| note(n)),
        Err(e) => note(&format!("could not check the sandbox's agents: {e}")),
    }
    Ok(u8::try_from(end.exit).unwrap_or(1))
}

/// Tells the user what a session's end left behind: notes, the signal that
/// ended the command, and processes still running; with --json, as one
/// `{"session": …}` line on stderr.
pub fn report_end(sandbox: &SandboxName, end: &SessionEnd) {
    if super::output::json() {
        say!(
            "{}",
            super::output::line(&serde_json::json!({ "session": super::output::session(end) }))
        );
        return;
    }
    let shown = format!("sandbox {sandbox}");
    for note in &end.notes {
        say!("enclos: session {} in {shown}: {note}", end.session);
    }
    if let Some(signal) = end.signal {
        say!("enclos: the command was ended by signal {signal}");
    }
    let stays_open = format!(
        "Session {} stays open until `enclos sandbox stop {}` finds them gone",
        end.session, sandbox
    );
    match &end.left {
        Left::Nothing => {}
        Left::Running(left) => {
            let pids: Vec<String> = left
                .iter()
                .map(|m| format!("{} ({})", m.pid, m.command))
                .collect();
            say!(
                "enclos: the command exited, but it left {} processes running in {shown}: {}. {stays_open}; `enclos sandbox show {}` lists them.",
                left.len(),
                pids.join(", "),
                sandbox
            );
        }
        Left::Unknown(why) => {
            say!(
                "enclos: the command exited, but enclos could not look at what it left running in {shown}: {why}. {stays_open}."
            );
        }
    }
}
