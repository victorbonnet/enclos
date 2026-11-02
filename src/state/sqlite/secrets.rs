//! Which secrets each sandbox has, in `state.db`. Their values are only in
//! the secret store (ADR 0022).

use rusqlite::{Connection, params};

use super::policy::ReadError;
use crate::model::Timestamp;
use crate::model::sandbox::SandboxName;
use crate::model::secret::{SecretRecord, SecretRef, StoreName};

/// Records `secret` as set at `at`, in `store` when it is new: a secret stays
/// in the store it first went to. True when it is new.
pub fn put(
    conn: &Connection,
    secret: &SecretRef,
    store: StoreName,
    at: Timestamp,
) -> rusqlite::Result<bool> {
    let existed = conn.execute(
        "UPDATE secrets SET updated_at = ?3 WHERE sandbox = ?1 AND name = ?2",
        params![
            secret.sandbox.as_str(),
            secret.name.as_str(),
            at.to_string()
        ],
    )? > 0;
    if !existed {
        conn.execute(
            "INSERT INTO secrets (sandbox, name, created_at, updated_at, store) VALUES (?1, ?2, ?3, ?3, ?4)",
            params![
                secret.sandbox.as_str(),
                secret.name.as_str(),
                at.to_string(),
                store.as_str()
            ],
        )?;
    }
    Ok(!existed)
}

/// Forgets `secret`; false when it was not recorded.
pub fn remove(conn: &Connection, secret: &SecretRef) -> rusqlite::Result<bool> {
    Ok(conn.execute(
        "DELETE FROM secrets WHERE sandbox = ?1 AND name = ?2",
        params![secret.sandbox.as_str(), secret.name.as_str()],
    )? > 0)
}

pub fn list(conn: &Connection, sandbox: &SandboxName) -> Result<Vec<SecretRecord>, ReadError> {
    let mut stmt = conn.prepare(
        "SELECT name, created_at, updated_at, store FROM secrets WHERE sandbox = ?1 ORDER BY name",
    )?;
    let mut rows = stmt.query(params![sandbox.as_str()])?;
    let mut secrets = Vec::new();
    while let Some(row) = rows.next()? {
        let (name, created, updated, store): (String, String, String, String) =
            (row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?);
        let time = |at: &str| {
            at.parse()
                .map_err(|e| ReadError::Corrupt(format!("secret time `{at}`: {e}")))
        };
        secrets.push(SecretRecord {
            secret: SecretRef {
                sandbox: sandbox.clone(),
                name: name
                    .parse()
                    .map_err(|e| ReadError::Corrupt(format!("{e}")))?,
            },
            store: store.parse().map_err(ReadError::Corrupt)?,
            created_at: time(&created)?,
            updated_at: time(&updated)?,
        });
    }
    Ok(secrets)
}
