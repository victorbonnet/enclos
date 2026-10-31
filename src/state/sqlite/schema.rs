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
        ended_at    TEXT,
        service     TEXT CHECK ((kind = 'service') = (service IS NOT NULL))
    ) STRICT;
    CREATE INDEX sessions_running ON sessions (sandbox, ended_at);",
    // 5: the runtime installed in each sandbox, and its agents
    "ALTER TABLE sandboxes ADD COLUMN runtime TEXT;
    CREATE TABLE agents (
        sandbox    TEXT NOT NULL REFERENCES sandboxes (name) ON DELETE CASCADE,
        name       TEXT NOT NULL,
        created_at TEXT NOT NULL,
        PRIMARY KEY (sandbox, name)
    ) STRICT;",
    // 6: the `policy.toml` each snapshot was resolved from, and each
    // sandbox's pending policy (design §7)
    "ALTER TABLE policy_snapshots ADD COLUMN overrides TEXT NOT NULL DEFAULT '';
    CREATE TABLE pending_policies (
        sandbox  TEXT PRIMARY KEY REFERENCES sandboxes (name) ON DELETE CASCADE,
        snapshot TEXT NOT NULL REFERENCES policy_snapshots (id),
        by_user  TEXT NOT NULL,
        by_host  TEXT NOT NULL,
        at       TEXT NOT NULL
    ) STRICT;",
    // 7: the version a pending rollback restores (design §7)
    "ALTER TABLE pending_policies ADD COLUMN restores INTEGER;",
    // 8: the secrets each sandbox has; their values are only in the secret
    // store (ADR 0022)
    "CREATE TABLE secrets (
        sandbox    TEXT NOT NULL REFERENCES sandboxes (name) ON DELETE CASCADE,
        name       TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        PRIMARY KEY (sandbox, name)
    ) STRICT;",
    // 9: what a tunnel's first bytes said about the server it asks for
    // (design §6, server name check)
    "ALTER TABLE net_events ADD COLUMN name_seen TEXT;
    ALTER TABLE net_events ADD COLUMN server_name TEXT;",
    // 10: the cgroup of each session's scope, on Linux (design §8)
    "ALTER TABLE sessions ADD COLUMN cgroup TEXT;",
];

/// The schema version this enclos reads and writes.
pub fn current() -> u32 {
    MIGRATIONS.len() as u32
}
