//! How a command prints (design §10): readable text in a terminal, JSON when
//! its output is piped or with `--json`, errors and refusals included. A
//! command that runs a program whose output is its own (`connect`, `exec`,
//! `logs`, and what launchd starts) is never JSON because it is piped. With
//! `--json`, its dry run's plan is JSON on stdout, and enclos's own words in
//! it, its failure and its notes, are JSON on stderr.

use std::fs::File;
use std::io::{IsTerminal, Write};
use std::os::fd::AsFd;
use std::path::Path;
use std::sync::{Mutex, OnceLock};

use serde_json::{Value, json};

use enclos::engine::{Left, SessionEnd};
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

/// Why the document could not be written, if it could not.
static WRITE_FAILED: OnceLock<std::io::Error> = OnceLock::new();

/// Decides the format once, for the whole command: `--json` or `--text` as
/// asked, else JSON when stdout is not a terminal and `piped_is_json`.
pub fn choose(json: bool, text: bool, piped_is_json: bool) -> Format {
    let format = match (json, text) {
        (true, _) => Format::Json,
        (false, true) => Format::Text,
        (false, false) if piped_is_json && !std::io::stdout().is_terminal() => Format::Json,
        (false, false) => Format::Text,
    };
    *FORMAT.get_or_init(|| format)
}

/// In JSON, keeps the stdout enclos was given for its document alone, and
/// points descriptor 1 at stderr: what any program enclos starts prints,
/// such as an installer's progress or an editor, goes there, and so does a
/// `println!` of enclos's own. The copy kept is closed on exec, so no
/// program enclos starts holds it. When that cannot be done, it says so and
/// the document stays on descriptor 1, with whatever else is printed there.
pub fn keep_stdout_for_the_document() {
    let kept = rustix::io::fcntl_dupfd_cloexec(std::io::stdout(), 3).and_then(|kept| {
        rustix::stdio::dup2_stdout(std::io::stderr().as_fd())?;
        Ok(kept)
    });
    match kept {
        Ok(kept) => {
            let _ = DOCUMENT.set(Mutex::new(File::from(kept)));
        }
        Err(e) => eprintln!(
            "enclos: cannot keep stdout for the JSON document alone ({e}): what programs enclos runs print may go into it"
        ),
    }
}

/// Whether this command prints JSON.
pub fn json() -> bool {
    FORMAT.get() == Some(&Format::Json)
}

/// Prints `value` as the command's one JSON document. A failure to write it
/// is kept, for [`write_failure`] to report as the command ends.
pub fn emit(value: &Value) {
    let text = for_terminal(&serde_json::to_string_pretty(value).expect("a JSON value serializes"));
    let written = match DOCUMENT.get() {
        Some(document) => {
            let mut document = document.lock().unwrap_or_else(|e| e.into_inner());
            writeln!(document, "{text}").and_then(|()| document.flush())
        }
        None => {
            let mut out = std::io::stdout().lock();
            writeln!(out, "{text}").and_then(|()| out.flush())
        }
    };
    if let Err(e) = written {
        let _ = WRITE_FAILED.set(e);
    }
}

/// `value` compact, on one line, for stderr: a note or a failure of a
/// command whose stdout is its program's.
pub fn line(value: &Value) -> String {
    for_terminal(&serde_json::to_string(value).expect("a JSON value serializes"))
}

/// Why the document could not be written, if it could not.
pub fn write_failure() -> Option<&'static std::io::Error> {
    WRITE_FAILED.get()
}

/// JSON text with what could still drive a terminal or hide text escaped
/// as `\uXXXX`: DEL, the C1 controls, the bidirectional controls, the
/// zero-width characters and the line and paragraph separators. JSON
/// escapes only the C0 controls itself, and a sandbox writes some of what a
/// document holds, such as its log lines and its processes' commands. Such
/// characters only ever appear inside strings, so this changes no value.
pub fn for_terminal(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '\u{7f}'..='\u{9f}'
            | '\u{61c}'
            | '\u{200b}'..='\u{200f}'
            | '\u{2028}'..='\u{202e}'
            | '\u{2060}'..='\u{2069}'
            | '\u{feff}' => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
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

/// An error as JSON: its message, what kind of failure it is, and the exit
/// code the command gives, which for `exec` is 125 whatever the kind.
pub fn error(err: &Error, code: u8) -> Value {
    json!({
        "error": {
            "message": err.to_string(),
            "kind": kind(err.exit_code()),
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

/// `result` with an `error` beside it when `code` is not 0, saying in
/// `message` what the text says: a command that fails with a result to
/// show still has an `error` a script can look for.
pub fn with_error(mut result: Value, code: u8, message: impl FnOnce() -> String) -> Value {
    if code != exit::OK {
        result["error"] = error_text(&message(), code)["error"].clone();
    }
    result
}

fn kind(code: u8) -> &'static str {
    match code {
        exit::REFUSED => "refused",
        exit::NEEDS_CONFIRMATION => "needs_confirmation",
        _ => "error",
    }
}

/// How a session ended, as `report_end` says it: its exit status, the
/// signal that ended it, its notes, and what it left running.
pub fn session(end: &SessionEnd) -> Value {
    let left = match &end.left {
        Left::Nothing => json!({"state": "nothing"}),
        Left::Running(members) => json!({
            "state": "running",
            "members": members.iter().map(|m| json!({
                "pid": m.pid,
                "command": m.command,
            })).collect::<Vec<_>>(),
        }),
        Left::Unknown(why) => json!({"state": "unknown", "why": why}),
    };
    json!({
        "id": end.session.0,
        "exit": end.exit,
        "signal": end.signal,
        "notes": end.notes,
        "left": left,
        "restarting": end.restarting,
    })
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn what_could_drive_a_terminal_is_escaped_and_the_value_kept() {
        let value = json!({"line": "a\u{7f}b\u{9b}2J\u{202e}c\u{200b}d\u{2028}é"});
        let text = for_terminal(&serde_json::to_string(&value).unwrap());
        assert_eq!(
            text,
            "{\"line\":\"a\\u007fb\\u009b2J\\u202ec\\u200bd\\u2028é\"}"
        );
        assert_eq!(serde_json::from_str::<Value>(&text).unwrap(), value);
    }

    #[test]
    fn a_result_that_failed_carries_an_error() {
        let failed = with_error(json!({"stopped": false}), 1, || "it did not stop".into());
        assert_eq!(failed["error"]["message"], "it did not stop");
        assert_eq!(failed["error"]["exit_code"], 1);
        assert_eq!(failed["stopped"], false);
        let fine = with_error(json!({"stopped": true}), 0, || unreachable!());
        assert!(fine.get("error").is_none());
    }
}
