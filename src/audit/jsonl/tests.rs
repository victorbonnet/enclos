use std::os::unix::fs::PermissionsExt;

use tempfile::TempDir;

use super::*;
use crate::model::audit::{Actor, AuditResult, BreakKind};

fn log() -> (TempDir, JsonlAuditLog) {
    let dir = tempfile::tempdir().unwrap();
    let log = JsonlAuditLog::new(dir.path().join("audit.jsonl"));
    (dir, log)
}

fn intent(command: &str) -> Intent {
    Intent {
        by: Actor {
            user: "alice".into(),
            host: "mac".into(),
        },
        command: command.into(),
        target: Some("home".into()),
    }
}

/// Runs `n` commands, each opened and closed.
fn run(log: &JsonlAuditLog, n: usize) {
    let lock = StateLock::for_tests();
    for i in 0..n {
        let ticket = log.begin(&lock, intent(&format!("cmd{i}"))).unwrap();
        log.finish(ticket, Outcome::ok(format!("did {i}"))).unwrap();
    }
}

fn lines(log: &JsonlAuditLog) -> Vec<String> {
    std::fs::read_to_string(&log.path)
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect()
}

fn write_lines(log: &JsonlAuditLog, lines: &[String]) {
    std::fs::write(&log.path, lines.join("\n") + "\n").unwrap();
}

#[test]
fn begin_and_finish_make_one_finished_entry() {
    let (_dir, log) = log();
    let lock = StateLock::for_tests();
    let ticket = log.begin(&lock, intent("init")).unwrap();
    assert_eq!(ticket.entry(), 1);
    log.finish(ticket, Outcome::failed("disk full")).unwrap();

    let entries = log.entries(&AuditFilter::default()).unwrap();
    assert_eq!(entries.len(), 1);
    let entry = &entries[0];
    assert_eq!((entry.seq, entry.intent.clone()), (1, intent("init")));
    let finished = entry.finished.as_ref().unwrap();
    assert_eq!(finished.outcome.result, AuditResult::Failed);
    assert_eq!(finished.outcome.message, "disk full");
    assert!(finished.at >= entry.at);

    let mode = std::fs::metadata(&log.path).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
}

#[test]
fn entries_filter_by_time() {
    let (_dir, log) = log();
    run(&log, 2);
    let all = log.entries(&AuditFilter::default()).unwrap();
    assert_eq!(all.len(), 2);
    let since = |at| AuditFilter { since: Some(at) };
    assert_eq!(log.entries(&since(all[0].at)).unwrap().len(), 2);
    let later = all[1]
        .at
        .checked_add(jiff::SignedDuration::from_secs(1))
        .unwrap();
    assert!(log.entries(&since(later)).unwrap().is_empty());
}

#[test]
fn reading_a_missing_log_says_to_run_init() {
    let (_dir, log) = log();
    let err = log.entries(&AuditFilter::default()).unwrap_err();
    assert!(matches!(err, AuditError::NotFound { .. }));
    assert!(err.to_string().contains("enclos init"));
    assert!(matches!(log.verify(), Err(AuditError::NotFound { .. })));
}

#[test]
fn a_clean_log_verifies() {
    let (_dir, log) = log();
    run(&log, 3);
    let report = log.verify().unwrap();
    assert!(report.intact(), "{:?}", report.broken);
    assert_eq!((report.lines, report.entries), (6, 3));
    assert!(report.unfinished.is_empty());
}

#[test]
fn verify_finds_an_edited_line() {
    let (_dir, log) = log();
    run(&log, 3);
    let mut lines = lines(&log);
    lines[2] = lines[2].replace("alice", "bob");
    write_lines(&log, &lines);
    let broken = log.verify().unwrap().broken.unwrap();
    assert_eq!((broken.line, broken.problem), (3, BreakKind::Edited));
}

#[test]
fn verify_finds_an_edited_last_line() {
    let (_dir, log) = log();
    run(&log, 2);
    let mut lines = lines(&log);
    lines[3] = lines[3].replace("\"ok\"", "\"failed\"");
    write_lines(&log, &lines);
    let broken = log.verify().unwrap().broken.unwrap();
    assert_eq!((broken.line, broken.problem), (4, BreakKind::Edited));
}

#[test]
fn verify_finds_a_deleted_line() {
    let (_dir, log) = log();
    run(&log, 3);
    let mut lines = lines(&log);
    lines.remove(2);
    write_lines(&log, &lines);
    let broken = log.verify().unwrap().broken.unwrap();
    assert_eq!((broken.line, broken.problem), (3, BreakKind::OutOfOrder));
}

#[test]
fn verify_finds_reordered_lines() {
    let (_dir, log) = log();
    run(&log, 3);
    let mut lines = lines(&log);
    lines.swap(2, 4);
    write_lines(&log, &lines);
    let broken = log.verify().unwrap().broken.unwrap();
    assert_eq!((broken.line, broken.problem), (3, BreakKind::OutOfOrder));
}

#[test]
fn verify_reports_an_unfinished_entry() {
    let (_dir, log) = log();
    run(&log, 1);
    let lock = StateLock::for_tests();
    // A command that never finishes, as after a crash.
    let ticket = log.begin(&lock, intent("crashed")).unwrap();
    drop(ticket);
    run(&log, 1);
    let report = log.verify().unwrap();
    assert!(report.intact());
    assert_eq!(report.unfinished.len(), 1);
    assert_eq!(report.unfinished[0].intent.command, "crashed");
    assert_eq!(report.unfinished[0].seq, 3);
}

#[test]
fn an_incomplete_last_line_is_reported_and_blocks_writes() {
    let (_dir, log) = log();
    run(&log, 1);
    let mut content = std::fs::read_to_string(&log.path).unwrap();
    content.push_str("{\"schema_version\":1,\"seq\":3");
    std::fs::write(&log.path, content).unwrap();
    let broken = log.verify().unwrap().broken.unwrap();
    assert_eq!(broken.line, 3);
    assert!(matches!(broken.problem, BreakKind::Unreadable { .. }));
    let lock = StateLock::for_tests();
    let err = log.begin(&lock, intent("next")).unwrap_err();
    assert!(matches!(err, AuditError::Damaged { .. }), "{err}");
}

#[test]
fn appends_continue_the_chain_across_long_lines() {
    let (_dir, log) = log();
    let lock = StateLock::for_tests();
    let long = "x".repeat(3 * TAIL_CHUNK as usize);
    let ticket = log.begin(&lock, intent(&long)).unwrap();
    log.finish(ticket, Outcome::ok(long.clone())).unwrap();
    run(&log, 1);
    assert!(log.verify().unwrap().intact());
    assert_eq!(log.entries(&AuditFilter::default()).unwrap().len(), 2);
}
