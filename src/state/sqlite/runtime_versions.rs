//! The version each sandbox's runtime last reported, for a runtime whose
//! home holds none enclos reads (ADR 0074, proposed), in `state.db`.

use rusqlite::{Connection, OptionalExtension, params};

use super::policy::ReadError;
use crate::model::Timestamp;
use crate::model::runtime::{RuntimeKind, RuntimeVersion};
use crate::model::sandbox::SandboxName;

/// Records `version` as what `runtime` in `sandbox` reported at `at`, in
/// place of what it reported before.
pub fn put(
    conn: &Connection,
    sandbox: &SandboxName,
    runtime: RuntimeKind,
    version: &RuntimeVersion,
    at: Timestamp,
) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO runtime_versions (sandbox, runtime, version, at) VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT (sandbox) DO UPDATE SET runtime = ?2, version = ?3, at = ?4",
        params![
            sandbox.as_str(),
            runtime.as_str(),
            version.as_str(),
            at.to_string()
        ],
    )?;
    Ok(())
}

pub fn get(
    conn: &Connection,
    sandbox: &SandboxName,
) -> Result<Option<(RuntimeKind, RuntimeVersion)>, ReadError> {
    let row: Option<(String, String)> = conn
        .query_row(
            "SELECT runtime, version FROM runtime_versions WHERE sandbox = ?1",
            params![sandbox.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let Some((runtime, version)) = row else {
        return Ok(None);
    };
    let runtime = runtime
        .parse()
        .map_err(|e| ReadError::Corrupt(format!("{e}")))?;
    let version = RuntimeVersion::new(&version)
        .ok_or_else(|| ReadError::Corrupt(format!("runtime version `{version}`")))?;
    Ok(Some((runtime, version)))
}
