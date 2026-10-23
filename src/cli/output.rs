//! How a command prints (design §10): readable text in a terminal, JSON when
//! its output is piped or with `--json`, errors and refusals included. A
//! command that runs a program whose output is its own (`connect`, `exec`,
//! `logs`, and what launchd starts) is never JSON because it is piped: only
//! `--json` makes enclos's own words in it JSON, on stderr.

use std::fs::File;
use std::io::{IsTerminal, Write};
use std::os::fd::AsFd;
use std::path::Path;
use std::sync::{Mutex, OnceLock};

use serde_json::{Value, json};

use enclos::error::{Error, exit};
use enclos::model::audit::{AuditEntry, AuditResult};
use enclos::model::plan::Plan;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Text,
    Json,
}

static FORMAT: OnceLock<Format> = OnceLock::new();

/// Where the JSON document goes: the stdout enclos was given, kept while
/// its descriptor 1 points at stderr.
static DOCUMENT: OnceLock<Mutex<File>> = OnceLock::new();

/// Decides the format once, for the whole command: `--json` or `--text` as
/// asked, else JSON when stdout is not a terminal and `piped_is_json`.
pub fn choose(json: bool, text: bool, piped_is_json: bool) -> Format {
    let format = match (json, text) {
        (true, _) => Format::Json,
        (false, true) => Format::Text,
        (false, false) if piped_is_json && !std::io::stdout().is_terminal() => Format::Json,
        (false, false) => Format::Text,
    };
    let _ = FORMAT.set(format);
    format
}

/// In JSON, keeps the stdout enclos was given for its document alone, and
/// points descriptor 1 at stderr: what a runtime's command that enclos runs
/// prints, such as an installer's progress, goes there, not into the
/// document. Left as it is when that cannot be done.
pub fn keep_stdout_for_the_document() {
    let kept = rustix::io::dup(std::io::stdout().as_fd()).and_then(|kept| {
        rustix::stdio::dup2_stdout(std::io::stderr().as_fd())?;
        Ok(kept)
    });
    if let Ok(kept) = kept {
        let _ = DOCUMENT.set(Mutex::new(File::from(kept)));
    }
}

/// Whether this command prints JSON.
pub fn json() -> bool {
    FORMAT.get() == Some(&Format::Json)
}

/// Prints `value` as the command's one JSON document.
pub fn emit(value: &Value) {
    let text = serde_json::to_string_pretty(value).expect("a JSON value serializes");
    match DOCUMENT.get() {
        Some(document) => {
            let mut document = document.lock().unwrap_or_else(|e| e.into_inner());
            let _ = writeln!(document, "{text}");
        }
        None => println!("{text}"),
    }
}

/// A dry run's plan: what it would create and change.
pub fn plan(plan: &Plan) -> Value {
    json!({
        "dry_run": true,
        "create": plan.create.iter().map(|p| path(p)).collect::<Vec<_>>(),
        "changes": plan.changes,
    })
}

/// A path as text, any byte that is not UTF-8 replaced.
pub fn path(p: &Path) -> Value {
    Value::String(p.to_string_lossy().into_owned())
}

/// An error as JSON: its message, what kind of failure its exit code says,
/// and the code.
pub fn error(err: &Error, code: u8) -> Value {
    json!({
        "error": {
            "message": err.to_string(),
            "kind": kind(code),
            "exit_code": code,
        }
    })
}

/// A failure given only as text, as for a usage error.
pub fn error_text(message: &str, code: u8) -> Value {
    json!({
        "error": {
            "message": message,
            "kind": kind(code),
            "exit_code": code,
        }
    })
}

fn kind(code: u8) -> &'static str {
    match code {
        exit::REFUSED => "refused",
        exit::NEEDS_CONFIRMATION => "needs_confirmation",
        _ => "error",
    }
}

/// An audit entry: when, who, what, and how it ended, if it did.
pub fn audit_entry(entry: &AuditEntry) -> Value {
    json!({
        "line": entry.seq,
        "at": entry.at.to_string(),
        "by": {"user": entry.intent.by.user, "host": entry.intent.by.host},
        "command": entry.intent.command,
        "target": entry.intent.target,
        "finished": entry.finished.as_ref().map(|f| json!({
            "at": f.at.to_string(),
            "result": match f.outcome.result {
                AuditResult::Ok => "ok",
                AuditResult::Failed => "failed",
            },
            "message": f.outcome.message,
        })),
    })
}
