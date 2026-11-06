//! The fields each sandbox runs with not enforced on this host, as the user
//! accepted them (ADR 0038), in `state.db`.

use rusqlite::{Connection, params};

use super::policy::ReadError;
use crate::model::sandbox::SandboxName;
use crate::model::unenforced::Acceptance;

/// Records `accepted` for `sandbox`, in place of an earlier acceptance of
/// the same field.
pub fn put(
    conn: &Connection,
    sandbox: &SandboxName,
    accepted: &Acceptance,
) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO unenforced_acceptances (sandbox, field, value, why, at) VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT (sandbox, field) DO UPDATE SET value = ?3, why = ?4, at = ?5",
        params![
            sandbox.as_str(),
            accepted.field.as_str(),
            accepted.value,
            accepted.why,
            accepted.at.to_string()
        ],
    )?;
    Ok(())
}

pub fn list(conn: &Connection, sandbox: &SandboxName) -> Result<Vec<Acceptance>, ReadError> {
    let mut stmt = conn.prepare(
        "SELECT field, value, why, at FROM unenforced_acceptances WHERE sandbox = ?1 ORDER BY field",
    )?;
    let mut rows = stmt.query(params![sandbox.as_str()])?;
    let mut accepted = Vec::new();
    while let Some(row) = rows.next()? {
        let (field, value, why, at): (String, String, String, String) =
            (row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?);
        accepted.push(Acceptance {
            field: field
                .parse()
                .map_err(|e| ReadError::Corrupt(format!("{e}")))?,
            value,
            why,
            at: at
                .parse()
                .map_err(|e| ReadError::Corrupt(format!("acceptance time `{at}`: {e}")))?,
        });
    }
    Ok(accepted)
}
