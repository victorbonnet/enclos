//! The state database schema, one migration per version.
//!
//! The schema version is SQLite's `user_version`: the number of migrations
//! applied. Never edit a released migration; append a new one.

/// Migration `i` takes the schema from version `i` to version `i + 1`.
pub const MIGRATIONS: &[&str] = &[
    // 1: sandbox records
    "CREATE TABLE sandboxes (
        name          TEXT PRIMARY KEY,
        backend       TEXT NOT NULL,
        state         TEXT NOT NULL,
        failed_reason TEXT,
        created_at    TEXT NOT NULL
    ) STRICT;",
    // 2: policy snapshots, insert-only, and each sandbox's append-only
    // history of policy versions (ADR 0018)
    "CREATE TABLE policy_snapshots (
        id     TEXT PRIMARY KEY,
        inputs TEXT NOT NULL,
        policy TEXT NOT NULL
    ) STRICT;
    CREATE TABLE policy_versions (
        sandbox  TEXT NOT NULL REFERENCES sandboxes (name) ON DELETE CASCADE,
        version  INTEGER NOT NULL,
        snapshot TEXT NOT NULL REFERENCES policy_snapshots (id),
        by_user  TEXT NOT NULL,
        by_host  TEXT NOT NULL,
        at       TEXT NOT NULL,
        restores INTEGER,
        PRIMARY KEY (sandbox, version)
    ) STRICT;
    ALTER TABLE sandboxes ADD COLUMN active_version INTEGER;",
    // 3: the network log, one row per connection the proxy handled
    "CREATE TABLE net_events (
        id          INTEGER PRIMARY KEY,
        at          TEXT NOT NULL,
        sandbox     TEXT NOT NULL REFERENCES sandboxes (name) ON DELETE CASCADE,
        agent     TEXT,
        host        TEXT NOT NULL,
        port        INTEGER NOT NULL,
        method      TEXT NOT NULL,
        address     TEXT,
        verdict     TEXT NOT NULL,
        reason      TEXT,
        bytes_up    INTEGER NOT NULL,
        bytes_down  INTEGER NOT NULL,
        duration_ms INTEGER NOT NULL
    ) STRICT;
    CREATE INDEX net_events_by_sandbox ON net_events (sandbox, at);",
];

/// The schema version this enclos reads and writes.
pub fn current() -> u32 {
    MIGRATIONS.len() as u32
}
