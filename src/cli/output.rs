//! How a command prints (design §10): readable text in a terminal, JSON when
//! its output is piped or with `--json`, errors and refusals included. A
//! command whose stdout is a program's or the services' ([`RUNS_A_PROGRAM`])
//! is never JSON because it is piped. With `--json`, its dry run's plan is
//! JSON on stdout, `logs` writes its lines as JSON Lines there, and enclos's
//! own words, its failure and its notes, are JSON on stderr.

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

/// How a command prints, decided once for it by [`decide`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Output {
    Text,
    /// One JSON document, on the stdout enclos was given.
    Document,
    /// The command's stdout is a program's: enclos's own words are JSON
    /// lines on stderr, and only a dry run's plan, or `logs`' lines, are
    /// JSON on stdout.
    OnStderr,
}

/// The commands, by their word, whose stdout is not enclos's to fill with a
/// document: the program's they run (`connect`, `exec`, the hidden
/// `launch`), the services' logs (`logs`), or a service's own log (the
/// hidden `proxy`).
pub const RUNS_A_PROGRAM: [&str; 5] = ["connect", "exec", "logs", "launch", "proxy"];

static OUTPUT: OnceLock<Output> = OnceLock::new();

/// What became of the command's JSON document. A command emits one: a
/// second is a bug, which a debug build panics on and a release refuses,
/// failing the command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Sent {
    /// None was emitted.
    Nothing,
    Written,
    /// It could not be written, and why; `unsent` is what it said of a
    /// failure, to be said on stderr instead, or it is lost.
    WriteFailed {
        why: String,
        unsent: Option<String>,
    },
    /// A second was refused. `first_failed` is why the first could not be
    /// written, if it could not; `unsent` what the documents said of a
    /// failure.
    SecondRefused {
        first_failed: Option<String>,
        unsent: Option<String>,
    },
}

static SENT: Mutex<Sent> = Mutex::new(Sent::Nothing);

/// Where the JSON document goes: the stdout enclos was given, kept while
/// its descriptor 1 points at stderr.
static DOCUMENT: OnceLock<Mutex<File>> = OnceLock::new();

/// How `command`, by its word, prints: JSON with `--json`, which wins over
/// `--text`; else text with `--text` or in a terminal, and JSON when piped,
/// but for the commands in [`RUNS_A_PROGRAM`], which print JSON only with
/// `--json`, and then mostly on stderr (see [`Output::OnStderr`]). The same for a parsed command and for a
/// usage error, which is told as the command would print.
pub fn decide(command: &str, json: bool, text: bool, stdout_is_terminal: bool) -> Output {
    let runs = RUNS_A_PROGRAM.contains(&command);
    match (runs, json, text || stdout_is_terminal) {
        (true, true, _) => Output::OnStderr,
        (true, false, _) => Output::Text,
        (false, true, _) | (false, false, false) => Output::Document,
        (false, false, true) => Output::Text,
    }
}

/// [`decide`] for this process, with its stdout as it is now: called once,
/// before anything is printed. A document's stdout is then kept for it
/// ([`keep_stdout_for_the_document`]).
pub fn choose(command: &str, json: bool, text: bool) -> Output {
    let output = decide(command, json, text, std::io::stdout().is_terminal());
    let chosen = *OUTPUT.get_or_init(|| output);
    debug_assert_eq!(chosen, output, "the output is chosen once");
    if chosen == Output::Document {
        keep_stdout_for_the_document();
    }
    chosen
}

/// How this command prints: text until [`choose`] says otherwise.
pub fn output() -> Output {
    OUTPUT.get().copied().unwrap_or(Output::Text)
}

/// For [`Output::Document`]: makes [`emit`] write to a close-on-exec copy
/// of the stdout enclos was given, and points descriptor 1 at stderr, so
/// that what any program enclos starts prints, such as an installer's
/// progress or an editor, goes there, and so does a `println!` of enclos's
/// own; no program enclos starts holds the copy. When that cannot be done,
/// it says so, and the document stays on descriptor 1, with whatever else is
/// printed there. (A stdout that was closed is `/dev/null` by then: Rust
/// reopens it so before `main`, so a document there is lost unsaid, as with
/// `>/dev/null`.)
fn keep_stdout_for_the_document() {
    let kept = rustix::io::fcntl_dupfd_cloexec(std::io::stdout(), 3).and_then(|kept| {
        rustix::stdio::dup2_stdout(std::io::stderr().as_fd())?;
        Ok(kept)
    });
    match kept {
        Ok(kept) => {
            let _ = DOCUMENT.set(Mutex::new(File::from(kept)));
        }
        Err(e) => note(&format!(
            "cannot keep stdout for the JSON document alone ({e}): what programs enclos runs print may go into it"
        )),
    }
}

/// Whether this command prints JSON, as a document or on stderr.
pub fn json() -> bool {
    output() != Output::Text
}

/// Prints `value` as the command's one JSON document. What became of it is
/// kept, for [`sent`] to report as the command ends.
pub fn emit(value: &Value) {
    let mut sent = SENT.lock().unwrap_or_else(|e| e.into_inner());
    let failure = || value["error"]["message"].as_str().map(str::to_owned);
    *sent = match std::mem::replace(&mut *sent, Sent::Nothing) {
        Sent::Nothing => match write_document(value) {
            Ok(()) => Sent::Written,
            Err(e) => Sent::WriteFailed {
                why: e.to_string(),
                unsent: failure(),
            },
        },
        // Two documents back to back are no JSON a reader takes.
        Sent::Written => Sent::SecondRefused {
            first_failed: None,
            unsent: failure(),
        },
        Sent::WriteFailed { why, unsent } => Sent::SecondRefused {
            first_failed: Some(why),
            unsent: unsent.or_else(failure),
        },
        refused @ Sent::SecondRefused { .. } => refused,
    };
    let refused = matches!(*sent, Sent::SecondRefused { .. });
    drop(sent);
    debug_assert!(!refused, "a command writes one JSON document");
}

fn write_document(value: &Value) -> std::io::Result<()> {
    let text = document_text(value);
    match DOCUMENT.get() {
        Some(document) => {
            let mut document = document.lock().unwrap_or_else(|e| e.into_inner());
            writeln!(document, "{text}").and_then(|()| document.flush())
        }
        None => {
            let mut out = std::io::stdout().lock();
            writeln!(out, "{text}").and_then(|()| out.flush())
        }
    }
}

/// What became of the command's document so far.
pub fn sent() -> Sent {
    SENT.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

/// Emits `result`, with an `error` beside it when `code` is not 0 (see
/// [`with_error`]), and returns `code`: the document's code and the
/// command's are then the same by construction.
pub fn conclude(result: Value, code: u8, message: impl FnOnce() -> String) -> u8 {
    emit(&with_error(result, code, message));
    code
}

/// The shape of what enclos prints as JSON: raised when a field a reader
/// may rely on changes or goes, so a script can tell one shape from the
/// next. A field added keeps it.
pub const SCHEMA_VERSION: u32 = 1;

/// `value`, an object as everything enclos prints as JSON is, with its
/// `schema_version`. Anything else is a bug, which a debug build panics on;
/// a release prints it as it is.
fn versioned(value: &Value) -> std::borrow::Cow<'_, Value> {
    match value {
        Value::Object(fields) => {
            let mut fields = fields.clone();
            fields.insert("schema_version".into(), SCHEMA_VERSION.into());
            std::borrow::Cow::Owned(Value::Object(fields))
        }
        _ => {
            debug_assert!(false, "enclos prints JSON objects only: {value}");
            std::borrow::Cow::Borrowed(value)
        }
    }
}

/// `value` as a document's text: with its `schema_version`, indented, and
/// escaped by [`for_terminal`].
pub fn document_text(value: &Value) -> String {
    for_terminal(&serde_json::to_string_pretty(&versioned(value)).expect("a JSON value serializes"))
}

/// A dry run's plan, as this command prints it: its document in JSON, else
/// a `Would …` line for each change.
pub fn show_plan(planned: &Plan) {
    match json() {
        true => emit(&plan(planned)),
        false => planned.changes.iter().for_each(|c| println!("Would {c}.")),
    }
}

/// `value` compact, on one line, with its `schema_version` and escaped as a
/// document is: one line of JSON Lines, such as a note, a session's end or
/// a failure on stderr, or a `logs` line on stdout.
pub fn line(value: &Value) -> String {
    for_terminal(&serde_json::to_string(&versioned(value)).expect("a JSON value serializes"))
}

/// JSON text with these characters escaped as `\uXXXX`, a character past
/// U+FFFF as its two UTF-16 halves: DEL and the C1 controls, which can drive
/// a terminal; the bidirectional controls, which reorder what is shown; and
/// characters that show nothing: zero-width ones, the line and paragraph
/// separators, the soft hyphen, the combining grapheme joiner, the
/// Mongolian vowel separator, the word joiner and invisible operators, the
/// variation selectors, the interlinear annotation characters and the tag
/// characters. JSON escapes only the C0 controls itself, and a sandbox
/// writes some of what a document holds, such as its services' logs and
/// its processes' commands. Such characters only ever appear inside strings,
/// so this changes no value.
pub fn for_terminal(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '\u{7f}'..='\u{9f}'
            | '\u{ad}'
            | '\u{34f}'
            | '\u{61c}'
            | '\u{180e}'
            | '\u{200b}'..='\u{200f}'
            | '\u{2028}'..='\u{202e}'
            | '\u{2060}'..='\u{206f}'
            | '\u{fe00}'..='\u{fe0f}'
            | '\u{feff}'
            | '\u{fff9}'..='\u{fffb}'
            | '\u{e0000}'..='\u{e007f}'
            | '\u{e0100}'..='\u{e01ef}' => {
                for unit in c.encode_utf16(&mut [0; 2]) {
                    out.push_str(&format!("\\u{unit:04x}"));
                }
            }
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

/// The command's error as JSON: its message, its kind, from the error
/// itself, and `code`, which for `exec` is 125 whatever the kind.
pub fn error(err: &Error, code: u8) -> Value {
    json!({"error": error_body(&err.to_string(), kind(err.exit_code()), code)})
}

/// A failure given only as text, as for a usage error.
pub fn error_text(message: &str, code: u8) -> Value {
    json!({"error": error_body(message, kind(code), code)})
}

fn error_body(message: &str, kind: &str, code: u8) -> Value {
    json!({"message": message, "kind": kind, "exit_code": code})
}

/// `result` with an `error` beside it when `code` is not 0, its `message` a
/// line saying why the command fails: a command that fails with a result to
/// show still has an `error` a script can look for.
pub fn with_error(mut result: Value, code: u8, message: impl FnOnce() -> String) -> Value {
    debug_assert!(
        result.is_object() && result.get("error").is_none(),
        "a result is an object with no error of its own: {result}"
    );
    if code != exit::OK {
        result["error"] = error_body(&message(), kind(code), code);
    }
    result
}

/// `result` with `err` beside it as its `error`, and the code it gives: a
/// part of a command that failed, such as one sandbox's in `sandboxes`,
/// kept with what it did.
pub fn with_failure(mut result: Value, err: &Error) -> (u8, Value) {
    debug_assert!(
        result.is_object() && result.get("error").is_none(),
        "a result is an object with no error of its own: {result}"
    );
    let code = err.exit_code();
    result["error"] = error_body(&err.to_string(), kind(code), code);
    (code, result)
}

/// Who did something, as an audit entry records them.
pub fn actor(by: &enclos::model::audit::Actor) -> Value {
    json!({"user": by.user, "host": by.host})
}

/// A process: its pid and its command as `ps` lists it.
pub fn member(pid: u32, command: &str) -> Value {
    json!({"pid": pid, "command": command})
}

/// A note of enclos's own, on stderr: `enclos: …` in text, one
/// `{"note": …}` line in JSON. A stderr closed already never makes it fail.
pub fn note(what: &str) {
    let shown = match json() {
        true => line(&json!({ "note": what })),
        false => format!("enclos: {what}"),
    };
    let _ = writeln!(std::io::stderr(), "{shown}");
}

fn kind(code: u8) -> &'static str {
    match code {
        exit::REFUSED => "refused",
        exit::NEEDS_CONFIRMATION => "needs_confirmation",
        _ => "error",
    }
}

/// How a session ended, as `report_end` says it: its id, its exit status,
/// the signal that ended it, its notes, what it left running, and whether
/// it restarts.
pub fn session(end: &SessionEnd) -> Value {
    let left = match &end.left {
        Left::Nothing => json!({"state": "nothing"}),
        Left::Running(members) => json!({
            "state": "running",
            "members": members.iter().map(|m| member(m.pid, &m.command)).collect::<Vec<_>>(),
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
        "by": actor(&entry.intent.by),
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

    /// Each end of each range is escaped, a character past U+FFFF as its
    /// two halves, and every value reads back as it was, a backslash before
    /// one included; some characters just outside the ranges are kept.
    #[test]
    fn every_listed_character_is_escaped_and_reads_back() {
        let escaped = [
            '\u{7f}',
            '\u{9f}',
            '\u{ad}',
            '\u{34f}',
            '\u{61c}',
            '\u{180e}',
            '\u{200b}',
            '\u{200f}',
            '\u{2028}',
            '\u{202e}',
            '\u{2060}',
            '\u{206f}',
            '\u{fe00}',
            '\u{fe0f}',
            '\u{feff}',
            '\u{fff9}',
            '\u{fffb}',
            '\u{e0000}',
            '\u{e007f}',
            '\u{e0100}',
            '\u{e01ef}',
        ];
        for c in escaped {
            let value = json!({"s": format!("\\{c}1")});
            let text = for_terminal(&serde_json::to_string(&value).unwrap());
            assert!(!text.contains(c), "{c:?} in {text}");
            assert_eq!(
                serde_json::from_str::<Value>(&text).unwrap(),
                value,
                "{c:?}"
            );
        }
        assert_eq!(
            for_terminal("\u{e0041}"),
            "\\udb40\\udc41",
            "a tag character is its two halves"
        );
        for kept in [
            '~',
            '\u{a0}',
            '\u{2027}',
            '\u{2070}',
            '\u{fe10}',
            '\u{e0080}',
        ] {
            assert_eq!(
                for_terminal(&kept.to_string()),
                kept.to_string(),
                "{kept:?}"
            );
        }
    }

    /// Every combination of the flags and the terminal, for a command that
    /// prints its own result and for one that runs a program.
    #[test]
    fn the_output_is_decided_by_the_flags_the_terminal_and_the_command() {
        for (json, text, terminal) in (0..8).map(|i| (i & 1 != 0, i & 2 != 0, i & 4 != 0)) {
            let own = match (json, text, terminal) {
                (true, _, _) => Output::Document,
                (false, false, false) => Output::Document,
                _ => Output::Text,
            };
            assert_eq!(
                decide("status", json, text, terminal),
                own,
                "{json} {text} {terminal}"
            );
            for runs in RUNS_A_PROGRAM {
                let theirs = match json {
                    true => Output::OnStderr,
                    false => Output::Text,
                };
                assert_eq!(
                    decide(runs, json, text, terminal),
                    theirs,
                    "{runs} {json} {text}"
                );
            }
        }
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

    /// A document's text escapes what a sandbox may write, through the
    /// same path `emit` writes.
    #[test]
    fn a_documents_text_is_escaped() {
        let value = json!({"command": "a\u{9b}2Jb\u{202e}c"});
        let text = document_text(&value);
        assert!(
            !text.contains('\u{9b}') && !text.contains('\u{202e}'),
            "{text}"
        );
        let mut versioned = value;
        versioned["schema_version"] = SCHEMA_VERSION.into();
        assert_eq!(serde_json::from_str::<Value>(&text).unwrap(), versioned);
    }

    /// A document and each line of JSON Lines say their shape.
    #[test]
    fn what_enclos_prints_as_json_carries_its_schema_version() {
        let value = json!({"sandboxes": []});
        for text in [document_text(&value), line(&value)] {
            let read: Value = serde_json::from_str(&text).unwrap();
            assert_eq!(read["schema_version"], SCHEMA_VERSION, "{text}");
            assert_eq!(read["sandboxes"], json!([]), "{text}");
        }
    }
}
