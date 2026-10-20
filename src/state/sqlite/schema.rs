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
    // 4: each sandbox's template and proxy port, and sessions
    "ALTER TABLE sandboxes ADD COLUMN template TEXT NOT NULL DEFAULT 'assistant';
    ALTER TABLE sandboxes ADD COLUMN proxy_port INTEGER NOT NULL DEFAULT 0;
    CREATE TABLE sessions (
        id          INTEGER PRIMARY KEY,
        sandbox     TEXT NOT NULL REFERENCES sandboxes (name) ON DELETE CASCADE,
        kind        TEXT NOT NULL,
        version     INTEGER NOT NULL,
        snapshot    TEXT NOT NULL,
        compiled    TEXT,
        root_pid    INTEGER NOT NULL,
        root_start  TEXT NOT NULL,
        pgid        INTEGER,
        tracked     TEXT NOT NULL DEFAULT '[]',
        started_at  TEXT NOT NULL,
        ended_at    TEXT
    ) STRICT;
    CREATE INDEX sessions_running ON sessions (sandbox, ended_at);",
];

/// The schema version this enclos reads and writes.
pub fn current() -> u32 {
    MIGRATIONS.len() as u32
}
