use std::os::unix::fs::PermissionsExt;

use tempfile::TempDir;

use super::*;
use crate::model::sandbox::BackendKind;

fn store() -> (TempDir, SqliteStateStore) {
    let dir = tempfile::tempdir().unwrap();
    let store = SqliteStateStore::new(dir.path().join("state.db"), dir.path().join("state.lock"));
    (dir, store)
}

fn record(name: &str) -> SandboxRecord {
    SandboxRecord {
        name: name.parse().unwrap(),
        backend: BackendKind::Seatbelt,
        template: "assistant".parse().unwrap(),
        proxy_port: 41000,
        runtime: None,
        state: SandboxState::Created,
        created_at: "2026-01-02T03:04:05.678Z".parse().unwrap(),
    }
}

#[test]
fn migrate_creates_the_database_once() {
    let (_dir, store) = store();
    let lock = store.lock().unwrap();
    let first = store.migrate(&lock).unwrap();
    assert_eq!(
        first,
        Migration {
            from: 0,
            to: schema::current()
        }
    );
    assert!(first.changed());
    let second = store.migrate(&lock).unwrap();
    assert!(!second.changed());
    let mode = std::fs::metadata(&store.db).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
}

#[test]
fn reads_before_init_say_to_run_init() {
    let (_dir, store) = store();
    let err = store.list().unwrap_err();
    assert!(matches!(err, StateError::NotInitialized { .. }), "{err}");
    assert!(err.to_string().contains("enclos init"));
}

#[test]
fn lock_fails_when_the_folder_is_missing() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("missing");
    let store = SqliteStateStore::new(missing.join("state.db"), missing.join("state.lock"));
    assert!(matches!(
        store.lock(),
        Err(StateError::NotInitialized { .. })
    ));
}

#[test]
fn put_get_list_remove() {
    let (_dir, store) = store();
    let lock = store.lock().unwrap();
    store.migrate(&lock).unwrap();

    store.put(&lock, &record("lab")).unwrap();
    store.put(&lock, &record("home")).unwrap();
    let names: Vec<_> = store.list().unwrap().into_iter().map(|r| r.name).collect();
    assert_eq!(names, ["home".parse().unwrap(), "lab".parse().unwrap()]);

    let mut failed = record("home");
    failed.state = SandboxState::Failed {
        reason: "proxy did not start".into(),
    };
    store.put(&lock, &failed).unwrap();
    assert_eq!(store.get(&failed.name).unwrap(), Some(failed.clone()));

    store.remove(&lock, &failed.name).unwrap();
    assert_eq!(store.get(&failed.name).unwrap(), None);
    assert_eq!(store.list().unwrap().len(), 1);
}

#[test]
fn rejects_an_outdated_schema() {
    let (_dir, store) = store();
    Connection::open(&store.db).unwrap();
    assert!(matches!(
        store.list(),
        Err(StateError::OutdatedSchema { found: 0, .. })
    ));
}

#[test]
fn rejects_a_newer_schema() {
    let (_dir, store) = store();
    let conn = Connection::open(&store.db).unwrap();
    conn.pragma_update(None, "user_version", schema::current() + 1)
        .unwrap();
    assert!(matches!(store.list(), Err(StateError::NewerSchema { .. })));
    let lock = store.lock().unwrap();
    assert!(matches!(
        store.migrate(&lock),
        Err(StateError::NewerSchema { .. })
    ));
}

#[test]
fn rejects_a_schema_its_migrations_do_not_make() {
    let (_dir, store) = store();
    let lock = store.lock().unwrap();
    store.migrate(&lock).unwrap();
    // An unreleased build that named a column differently, at the same version.
    let conn = Connection::open(&store.db).unwrap();
    conn.execute_batch("ALTER TABLE sandboxes RENAME COLUMN backend TO kind")
        .unwrap();
    assert!(matches!(
        store.list(),
        Err(StateError::UnknownSchema { .. })
    ));
    assert!(matches!(
        store.migrate(&lock),
        Err(StateError::UnknownSchema { .. })
    ));
}

#[test]
fn reports_a_corrupt_record() {
    let (_dir, store) = store();
    let lock = store.lock().unwrap();
    store.migrate(&lock).unwrap();
    let conn = Connection::open(&store.db).unwrap();
    conn.execute(
        "INSERT INTO sandboxes (name, backend, state, failed_reason, created_at)
         VALUES ('home', 'docker', 'created', NULL, 'x')",
        [],
    )
    .unwrap();
    assert!(matches!(store.list(), Err(StateError::Corrupt { .. })));
}

#[test]
fn the_lock_is_exclusive_until_dropped() {
    let (_dir, store) = store();
    let lock = store.lock().unwrap();
    let other = File::options().write(true).open(&store.lock_file).unwrap();
    assert!(matches!(other.try_lock(), Err(TryLockError::WouldBlock)));
    drop(lock);
    assert!(other.try_lock().is_ok());
}

#[test]
fn policy_versions_append_and_identical_snapshots_are_stored_once() {
    use crate::model::audit::Actor;
    let (_dir, store) = store();
    let lock = store.lock().unwrap();
    store.migrate(&lock).unwrap();
    let name: SandboxName = "home".parse().unwrap();
    store.put(&lock, &record("home")).unwrap();
    let by = Actor {
        user: "alice".into(),
        host: "mac".into(),
    };
    let snap = crate::policy::resolve("extends = \"assistant\"\n", None).unwrap();

    let v1 = store.save_policy(&lock, &name, &snap, &by, None).unwrap();
    let v2 = store
        .save_policy(&lock, &name, &snap, &by, Some(1))
        .unwrap();
    assert_eq!((v1.version, v2.version, v2.restores), (1, 2, Some(1)));

    let (active, stored) = store.active_policy(&name).unwrap().unwrap();
    assert_eq!(active, v2);
    assert_eq!(stored, snap);
    assert_eq!(store.policy_history(&name).unwrap(), [v1, v2]);

    // Removing the sandbox removes its history.
    store.remove(&lock, &name).unwrap();
    assert!(store.policy_history(&name).unwrap().is_empty());
}

#[test]
fn a_new_sandbox_and_its_first_policy_are_recorded_together_or_not_at_all() {
    use crate::model::audit::Actor;
    let (_dir, store) = store();
    let lock = store.lock().unwrap();
    store.migrate(&lock).unwrap();
    let name: SandboxName = "home".parse().unwrap();
    let by = Actor {
        user: "alice".into(),
        host: "mac".into(),
    };
    let snap = crate::policy::resolve("extends = \"assistant\"\n", None).unwrap();

    // The policy version is written after the record: failing it must take
    // the record back too.
    let conn = Connection::open(&store.db).unwrap();
    conn.execute_batch(
        "CREATE TRIGGER fail_policy BEFORE INSERT ON policy_versions
         BEGIN SELECT RAISE(ABORT, 'injected failure'); END;",
    )
    .unwrap();
    let err = store
        .create_sandbox(&lock, &record("home"), &snap, &by)
        .unwrap_err();
    assert!(err.to_string().contains("injected failure"), "{err}");
    assert_eq!(store.get(&name).unwrap(), None);
    assert!(store.policy_history(&name).unwrap().is_empty());

    conn.execute_batch("DROP TRIGGER fail_policy").unwrap();
    let v1 = store
        .create_sandbox(&lock, &record("home"), &snap, &by)
        .unwrap();
    assert_eq!((v1.version, &v1.by, v1.restores), (1, &by, None));
    assert_eq!(store.get(&name).unwrap(), Some(record("home")));
    assert_eq!(
        store.active_policy(&name).unwrap().unwrap(),
        (v1.clone(), snap.clone())
    );

    // A name already recorded is an error, and changes nothing.
    let mut other = record("home");
    other.proxy_port = 41001;
    store.create_sandbox(&lock, &other, &snap, &by).unwrap_err();
    assert_eq!(store.get(&name).unwrap(), Some(record("home")));
    assert_eq!(store.policy_history(&name).unwrap(), [v1]);
}

#[test]
fn the_network_log_filters_by_time_and_groups_denials() {
    use crate::model::net::{NetEvent, Reason, Verdict};
    use crate::state::NetLogStore;
    let (_dir, store) = store();
    let lock = store.lock().unwrap();
    store.migrate(&lock).unwrap();
    store.put(&lock, &record("home")).unwrap();
    let name: SandboxName = "home".parse().unwrap();
    let event = |at: &str, host: &str, verdict, reason| NetEvent {
        at: at.parse().unwrap(),
        sandbox: name.clone(),
        host: host.into(),
        port: 443,
        method: "CONNECT".into(),
        address: None,
        verdict,
        reason,
        bytes_up: 1,
        bytes_down: 2,
        duration_ms: 3,
    };
    // Whole seconds and milliseconds mixed: the order must still be by time.
    for e in [
        event(
            "2026-01-01T10:00:05Z",
            "api.example.com",
            Verdict::Allowed,
            None,
        ),
        event(
            "2026-01-01T10:00:05.500Z",
            "evil.example.com",
            Verdict::Denied,
            Some(Reason::NotAllowed),
        ),
        event(
            "2026-01-01T10:00:06Z",
            "evil.example.com",
            Verdict::Denied,
            Some(Reason::NotAllowed),
        ),
    ] {
        store.record(&e).unwrap();
    }
    // A tunnel opened first and closed last: listed by when it opened, with
    // the bytes it moved and why it closed, once it closed.
    let long = event(
        "2026-01-01T10:00:04Z",
        "long.example.com",
        Verdict::Allowed,
        None,
    );
    let row = store.record(&long).unwrap();
    store
        .finish(
            row,
            &NetEvent {
                bytes_down: 5_000_000,
                reason: Some(Reason::Idle),
                ..long
            },
        )
        .unwrap();
    let all = store.events(&name, None).unwrap();
    assert_eq!(all.len(), 4);
    assert_eq!(
        (all[0].host.as_str(), all[0].bytes_down, all[0].reason),
        ("long.example.com", 5_000_000, Some(Reason::Idle))
    );
    assert_eq!(
        store.last_event(&name).unwrap(),
        Some("2026-01-01T10:00:06Z".parse().unwrap())
    );
    // Another sandbox's later events are its own; one without any has none.
    store.put(&lock, &record("other")).unwrap();
    let other: SandboxName = "other".parse().unwrap();
    assert_eq!(store.last_event(&other).unwrap(), None);
    store
        .record(&NetEvent {
            sandbox: other.clone(),
            ..event(
                "2026-01-02T00:00:00Z",
                "x.example.com",
                Verdict::Allowed,
                None,
            )
        })
        .unwrap();
    assert_eq!(
        store.last_event(&name).unwrap(),
        Some("2026-01-01T10:00:06Z".parse().unwrap())
    );
    let since = "2026-01-01T10:00:05.200Z".parse().unwrap();
    assert_eq!(store.events(&name, Some(since)).unwrap().len(), 2);

    let denied = store.denied(&name).unwrap();
    assert_eq!(denied.len(), 1);
    assert_eq!(
        (denied[0].host.as_str(), denied[0].count),
        ("evil.example.com", 2)
    );
    assert_eq!(denied[0].first, "2026-01-01T10:00:05.500Z".parse().unwrap());
}

#[test]
fn sessions_keep_their_members_until_they_end() {
    use crate::model::session::{ProcessRef, SessionKind, SessionRecord};
    let (_dir, store) = store();
    let lock = store.lock().unwrap();
    store.migrate(&lock).unwrap();
    let name: SandboxName = "home".parse().unwrap();
    store.put(&lock, &record("home")).unwrap();
    let at = |pid: u32| ProcessRef {
        pid,
        started: format!("Thu Oct 8 09:31:{pid} 2026"),
    };
    let mut session = SessionRecord {
        id: SessionId(0),
        sandbox: name.clone(),
        kind: SessionKind::Interactive,
        version: 1,
        snapshot: crate::model::policy::SnapshotId("x".into()),
        compiled: Some("/Users/alice/.enclos/sandboxes/home/compiled/a.sb".into()),
        root: at(10),
        pgid: None,
        tracked: vec![at(11)],
        started_at: "2026-10-08T09:31:10Z".parse().unwrap(),
        ended_at: None,
    };
    session.id = store.put_session(&lock, &session).unwrap();
    assert_eq!(store.sessions(&name, true).unwrap(), [session.clone()]);

    // Tracking replaces what was recorded.
    store.track(&lock, session.id, &[at(12), at(13)]).unwrap();
    session.tracked = vec![at(12), at(13)];
    assert_eq!(store.sessions(&name, true).unwrap(), [session.clone()]);

    // Once ended, it is no longer running, and tracking no longer changes it.
    store.end_session(&lock, session.id).unwrap();
    assert!(store.sessions(&name, true).unwrap().is_empty());
    store.track(&lock, session.id, &[]).unwrap();
    let ended = store.sessions(&name, false).unwrap();
    assert_eq!(ended[0].tracked, session.tracked);
    assert!(ended[0].ended_at.is_some());

    // Removing the sandbox removes its sessions.
    store.remove(&lock, &name).unwrap();
    assert!(store.sessions(&name, false).unwrap().is_empty());
}

#[test]
fn reports_corrupt_session_members() {
    let (_dir, store) = store();
    let lock = store.lock().unwrap();
    store.migrate(&lock).unwrap();
    store.put(&lock, &record("home")).unwrap();
    let conn = Connection::open(&store.db).unwrap();
    conn.execute(
        "INSERT INTO sessions (sandbox, kind, version, snapshot, root_pid, root_start, tracked,
             started_at)
         VALUES ('home', 'interactive', 1, 'x', 10, 't', '[[1]]', '2026-10-08T09:31:10Z')",
        [],
    )
    .unwrap();
    let name: SandboxName = "home".parse().unwrap();
    assert!(matches!(
        store.sessions(&name, true),
        Err(StateError::Corrupt { .. })
    ));
}

#[test]
fn agents_are_recorded_once_each_and_go_with_their_sandbox() {
    use crate::model::agent::AgentRecord;
    use crate::model::runtime::RuntimeKind;
    let (_dir, store) = store();
    let lock = store.lock().unwrap();
    store.migrate(&lock).unwrap();
    let name: SandboxName = "home".parse().unwrap();
    let mut sandbox = record("home");
    sandbox.runtime = Some(RuntimeKind::Hermes);
    store.put(&lock, &sandbox).unwrap();
    assert_eq!(
        store.get(&name).unwrap().unwrap().runtime,
        Some(RuntimeKind::Hermes)
    );
    let agent = |n: &str| AgentRecord {
        name: n.parse().unwrap(),
        created_at: "2026-10-08T09:31:10Z".parse().unwrap(),
    };
    store.insert_agent(&lock, &name, &agent("zed")).unwrap();
    store.insert_agent(&lock, &name, &agent("main")).unwrap();
    let names: Vec<String> = store
        .agents(&name)
        .unwrap()
        .iter()
        .map(|a| a.name.to_string())
        .collect();
    assert_eq!(names, ["main", "zed"]);
    // A second record of the same agent is an error, not a duplicate.
    assert!(store.insert_agent(&lock, &name, &agent("main")).is_err());
    assert_eq!(store.agents(&name).unwrap().len(), 2);
    store
        .remove_agent(&lock, &name, &"zed".parse().unwrap())
        .unwrap();
    assert_eq!(store.agents(&name).unwrap().len(), 1);
    // Removing the sandbox removes its agents.
    store.remove(&lock, &name).unwrap();
    assert!(store.agents(&name).unwrap().is_empty());
    store.put(&lock, &record("home")).unwrap();
    assert!(store.agents(&name).unwrap().is_empty());
}

#[test]
fn reports_a_corrupt_agent_or_runtime() {
    let (_dir, store) = store();
    let lock = store.lock().unwrap();
    store.migrate(&lock).unwrap();
    store.put(&lock, &record("home")).unwrap();
    let name: SandboxName = "home".parse().unwrap();
    let conn = Connection::open(&store.db).unwrap();
    conn.execute(
        "INSERT INTO agents (sandbox, name, created_at) VALUES ('home', 'Bad Name', 'x')",
        [],
    )
    .unwrap();
    assert!(matches!(
        store.agents(&name),
        Err(StateError::Corrupt { .. })
    ));
    conn.execute(
        "UPDATE sandboxes SET runtime = 'claude' WHERE name = 'home'",
        [],
    )
    .unwrap();
    assert!(matches!(store.get(&name), Err(StateError::Corrupt { .. })));
}
