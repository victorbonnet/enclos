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
