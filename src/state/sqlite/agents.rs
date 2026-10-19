//! A sandbox's agents in `state.db`.

use rusqlite::{Connection, params};

use super::policy::ReadError;
use crate::model::agent::{AgentName, AgentRecord};
use crate::model::sandbox::SandboxName;

pub fn put(conn: &Connection, sandbox: &SandboxName, p: &AgentRecord) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO agents (sandbox, name, created_at) VALUES (?1, ?2, ?3)",
        params![sandbox.as_str(), p.name.as_str(), p.created_at.to_string()],
    )?;
    Ok(())
}

pub fn remove(conn: &Connection, sandbox: &SandboxName, name: &AgentName) -> rusqlite::Result<()> {
    conn.execute(
        "DELETE FROM agents WHERE sandbox = ?1 AND name = ?2",
        params![sandbox.as_str(), name.as_str()],
    )?;
    Ok(())
}

pub fn list(conn: &Connection, sandbox: &SandboxName) -> Result<Vec<AgentRecord>, ReadError> {
    let mut stmt =
        conn.prepare("SELECT name, created_at FROM agents WHERE sandbox = ?1 ORDER BY name")?;
    let mut rows = stmt.query(params![sandbox.as_str()])?;
    let mut agents = Vec::new();
    while let Some(row) = rows.next()? {
        let name: String = row.get(0)?;
        let at: String = row.get(1)?;
        agents.push(AgentRecord {
            name: name
                .parse()
                .map_err(|e| ReadError::Corrupt(format!("{e}")))?,
            created_at: at
                .parse()
                .map_err(|e| ReadError::Corrupt(format!("agent time `{at}`: {e}")))?,
        });
    }
    Ok(agents)
}
