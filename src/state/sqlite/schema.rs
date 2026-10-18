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
];

/// The schema version this enclos reads and writes.
pub fn current() -> u32 {
    MIGRATIONS.len() as u32
}
