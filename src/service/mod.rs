//! Background services (design §4, ADR 0002): a sandbox's proxy and its
//! runtime's gateway, run by the operating system's service manager while the
//! user is logged in. There is no enclos daemon.

#[cfg(test)]
pub mod fake;
pub mod launchd;

use std::ffi::OsString;
use std::path::PathBuf;

/// One service, as enclos defines it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceUnit {
    /// Unique on the host, such as `enclos.home.proxy`.
    pub label: String,
    pub program: PathBuf,
    pub args: Vec<OsString>,
    /// Where its standard output and error go.
    pub log: PathBuf,
    /// Variables it runs with; secrets never go here (ADR 0011).
    pub env: Vec<(String, String)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceStatus {
    Running {
        pid: u32,
    },
    /// Loaded but not running now (between restarts, or exited).
    Loaded,
    NotLoaded,
}

#[derive(Debug, thiserror::Error)]
#[error("{what}")]
pub struct ServiceError {
    pub what: String,
}

/// The host's service manager: launchd on macOS, systemd later.
pub trait ServiceManager {
    /// Installs the unit so it starts now and again at each login.
    fn start(&self, unit: &ServiceUnit) -> Result<(), ServiceError>;
    /// Stops the unit and removes it, so it does not start at login.
    fn stop(&self, label: &str) -> Result<(), ServiceError>;
    fn status(&self, label: &str) -> ServiceStatus;
}
