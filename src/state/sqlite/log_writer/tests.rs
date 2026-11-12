use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

use rusqlite::Connection;

use super::NetLogWriter;
use crate::model::net::{NetEvent, Verdict};
use crate::model::now;
use crate::model::sandbox::SandboxName;
use crate::model::session::{ProcessRef, SessionId, SessionKind, SessionRecord};
use crate::state::sqlite::SqliteStateStore;
use crate::state::sqlite::tests::{record, store};
use crate::state::{NetLogStore, StateStore};

fn event(host: &str) -> NetEvent {
    NetEvent {
        at: now(),
        sandbox: "home".parse().unwrap(),
        host: host.into(),
        port: 443,
        method: "CONNECT".into(),
        address: None,
        verdict: Verdict::Allowed,
        reason: None,
        bytes_up: 0,
        bytes_down: 0,
        duration_ms: 0,
        name_seen: None,
    }
}

fn session(sandbox: &SandboxName) -> SessionRecord {
    SessionRecord {
        id: SessionId(0),
        sandbox: sandbox.clone(),
        kind: SessionKind::Interactive,
        service: None,
        version: 1,
        snapshot: crate::model::policy::SnapshotId("x".into()),
        compiled: None,
        root: ProcessRef {
            pid: 10,
            started: "Thu Oct 8 09:31:10 2026".into(),
        },
        pgid: None,
        cgroup: None,
        tracked: Vec::new(),
        started_at: "2026-10-08T09:31:10Z".parse().unwrap(),
        ended_at: None,
    }
}

fn writer_of(store: &SqliteStateStore) -> Arc<NetLogWriter> {
    Arc::new(NetLogWriter::start(SqliteStateStore::new(
        &store.db,
        &store.lock_file,
        crate::state::Wait::Command,
    )))
}

#[test]
fn connections_logged_from_many_threads_are_each_recorded_and_finished() {
    let (_dir, store) = store();
    let lock = store.lock().unwrap();
    store.migrate(&lock).unwrap();
    store.put(&lock, &record("home")).unwrap();
    let log = writer_of(&store);
    let threads: Vec<_> = (0..8)
        .map(|t| {
            let log = Arc::clone(&log);
            std::thread::spawn(move || {
                for i in 0..20 {
                    let mut e = event(&format!("{t}-{i}.example.com"));
                    let row = log.record(&e).unwrap();
                    e.bytes_down = 1000 + i;
                    log.finish(row, &e).unwrap();
                }
            })
        })
        .collect();
    for t in threads {
        t.join().unwrap();
    }
    let events = log.events(&"home".parse().unwrap(), None).unwrap();
    assert_eq!(events.len(), 160);
    assert!(events.iter().all(|e| e.bytes_down >= 1000), "each finished");
}

#[test]
fn a_write_to_a_database_that_is_not_there_says_so() {
    let (_dir, store) = store();
    let err = writer_of(&store)
        .record(&event("a.example.com"))
        .unwrap_err();
    assert!(err.to_string().contains("enclos init"), "{err}");
}

/// Makes each transaction that logs a connection take tens of milliseconds
/// holding the write lock, as on a loaded SD card: the first row a
/// connection writes makes it generate random bytes, and each transaction
/// opens its own connection.
fn slow_disk(db: &std::path::Path) {
    Connection::open(db)
        .unwrap()
        .execute_batch(
            "CREATE TRIGGER slow_disk AFTER INSERT ON net_events WHEN total_changes() = 0
             BEGIN SELECT length(randomblob(4000000)); END;",
        )
        .unwrap();
}

/// Opens a connection every `every` until told to stop, each logged as it
/// opens and as it closes from a thread of its own, as the proxy does; once
/// stopped, returns how many log writes failed.
fn burst(log: Arc<NetLogWriter>, every: Duration) -> (Arc<AtomicBool>, JoinHandle<usize>) {
    let stop = Arc::new(AtomicBool::new(false));
    let stopped = Arc::clone(&stop);
    let opening = std::thread::spawn(move || {
        let mut connections = Vec::new();
        while !stopped.load(Ordering::Relaxed) {
            let log = Arc::clone(&log);
            connections.push(std::thread::spawn(move || {
                let e = event("files.pythonhosted.org");
                log.record(&e).and_then(|row| log.finish(row, &e)).is_err()
            }));
            std::thread::sleep(every);
        }
        connections
            .into_iter()
            .map(JoinHandle::join)
            .filter(|failed| !matches!(failed, Ok(false)))
            .count()
    });
    (stop, opening)
}

/// Through an install's burst of connections on a slow disk, a session's
/// record of its members must get its turn, and so must each of the proxy's
/// own writes. With a transaction per row, both wait past their 10 seconds.
#[test]
fn a_member_record_gets_its_turn_while_a_proxy_logs_a_burst_of_connections() {
    let (_dir, store) = store();
    let lock = store.lock().unwrap();
    store.migrate(&lock).unwrap();
    store.put(&lock, &record("home")).unwrap();
    let name: SandboxName = "home".parse().unwrap();
    let id = store.put_session(&lock, &session(&name)).unwrap();
    slow_disk(&store.db);

    let (stop, opening) = burst(writer_of(&store), Duration::from_millis(10));
    let recorded = (0..5).try_for_each(|pid| {
        std::thread::sleep(Duration::from_millis(200));
        let members = [ProcessRef {
            pid,
            started: "Thu Oct 8 09:31:11 2026".into(),
        }];
        store.track(&lock, id, &members)
    });
    stop.store(true, Ordering::Relaxed);
    let failed = opening.join().unwrap();
    recorded.unwrap();
    assert_eq!(failed, 0, "log writes failed");
}

#[test]
fn tagged_connections_keep_provenance_through_the_existing_batched_writer() {
    use crate::model::net::Reason;
    let (_dir, store) = store();
    let lock = store.lock().unwrap();
    store.migrate(&lock).unwrap();
    store.put(&lock, &record("home")).unwrap();
    let log = writer_of(&store);
    let sandbox: SandboxName = "home".parse().unwrap();
    let registered = "a".repeat(64);
    let forged = "b".repeat(64);
    log.begin_probe(&sandbox, &registered).unwrap();
    let threads: Vec<_> = (0..8)
        .map(|thread| {
            let log = Arc::clone(&log);
            let registered = registered.clone();
            let forged = forged.clone();
            std::thread::spawn(move || {
                for index in 0..20 {
                    let mut connection = event("10.0.0.1");
                    connection.verdict = Verdict::Denied;
                    connection.reason = Some(Reason::PrivateAddress);
                    let tag = if (thread + index) % 2 == 0 {
                        &registered
                    } else {
                        &forged
                    };
                    let row = log.record_probe(&connection, Some(tag)).unwrap();
                    connection.bytes_down = 1000 + index;
                    log.finish(row, &connection).unwrap();
                }
            })
        })
        .collect();
    for thread in threads {
        thread.join().unwrap();
    }
    assert_eq!(log.events(&sandbox, None).unwrap().len(), 160);
    assert_eq!(log.denied(&sandbox).unwrap()[0].count, 160);
    assert_eq!(log.denied_for_approval(&sandbox).unwrap()[0].count, 80);
    assert!(
        log.events(&sandbox, None)
            .unwrap()
            .iter()
            .all(|event| event.bytes_down >= 1000)
    );
    log.end_probe(&registered).unwrap();
    let mut connection = event("10.0.0.1");
    connection.verdict = Verdict::Denied;
    connection.reason = Some(Reason::PrivateAddress);
    log.record_probe(&connection, Some(&registered)).unwrap();
    assert_eq!(
        log.denied_for_approval(&sandbox).unwrap()[0].count,
        81,
        "closing the host run makes later tagged traffic ordinary"
    );
    let version: u32 = Connection::open(&store.db)
        .unwrap()
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap();
    assert_eq!(
        version, 12,
        "diagnostic metadata does not change the Pi's released schema"
    );
}

#[test]
fn a_failed_batch_rolls_back_both_log_rows_and_their_diagnostic_provenance() {
    use super::Write;
    use crate::model::net::Reason;
    let (dir, store) = store();
    let lock = store.lock().unwrap();
    store.migrate(&lock).unwrap();
    store.put(&lock, &record("home")).unwrap();
    let sandbox: SandboxName = "home".parse().unwrap();
    let tag = "a".repeat(64);
    store.begin_probe(&sandbox, &tag).unwrap();
    Connection::open(&store.db).unwrap().execute_batch("CREATE TRIGGER reject_batch BEFORE INSERT ON net_events WHEN NEW.host='fail.example.com' BEGIN SELECT RAISE(ABORT,'batch refused'); END;").unwrap();
    let mut connection = event("10.0.0.1");
    connection.verdict = Verdict::Denied;
    connection.reason = Some(Reason::PrivateAddress);
    let tagged = Write::Record(connection.clone(), Some(tag));
    let failing = Write::Record(event("fail.example.com"), None);
    assert!(store.write_log(&[&tagged, &failing]).is_err());
    assert!(store.events(&sandbox, None).unwrap().is_empty());
    let marked: i64 = Connection::open(dir.path().join("probe-sources.db"))
        .unwrap()
        .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))
        .unwrap();
    assert_eq!(marked, 0, "no provenance survives without its log row");
    writer_of(&store).record(&connection).unwrap();
    assert_eq!(
        store.denied_for_approval(&sandbox).unwrap()[0].count,
        1,
        "a later real connection is never hidden by rolled-back metadata"
    );
}
