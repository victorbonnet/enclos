//! Background services (design §4, ADR 0002): a sandbox's proxy and its
//! runtime's gateway, run by the operating system's service manager while the
//! user is logged in. There is no enclos daemon.

#[cfg(test)]
pub mod fake;
#[cfg(target_os = "macos")]
pub mod launchd;

use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// One service, as enclos defines it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceUnit {
    /// Unique on the host, such as `enclos.1f2e3d4c.home.proxy`.
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
    /// The labels installed and not removed yet that start with `prefix`,
    /// whether or not they run.
    fn installed(&self, prefix: &str) -> Result<Vec<String>, ServiceError>;
}

/// This host's service manager: launchd on macOS. Other systems have none
/// yet, and refuse to start services.
#[cfg(target_os = "macos")]
pub fn host(user_home: &Path) -> Box<dyn ServiceManager> {
    Box::new(launchd::Launchd {
        agents_dir: user_home.join("Library/LaunchAgents"),
    })
}

/// This host's service manager: launchd on macOS. Other systems have none
/// yet, and refuse to start services.
#[cfg(not(target_os = "macos"))]
pub fn host(_user_home: &Path) -> Box<dyn ServiceManager> {
    Box::new(Unsupported {
        why: "enclos runs background services only on macOS for now",
    })
}

/// A service manager that refuses every start and has nothing installed:
/// on a system enclos has none for, and in an engine built without one, so
/// tests never reach the host's.
pub struct Unsupported {
    pub why: &'static str,
}

impl ServiceManager for Unsupported {
    fn start(&self, unit: &ServiceUnit) -> Result<(), ServiceError> {
        Err(ServiceError {
            what: format!("cannot start {}: {}", unit.label, self.why),
        })
    }

    fn stop(&self, _label: &str) -> Result<(), ServiceError> {
        Ok(())
    }

    fn status(&self, _label: &str) -> ServiceStatus {
        ServiceStatus::NotLoaded
    }

    fn installed(&self, _prefix: &str) -> Result<Vec<String>, ServiceError> {
        Ok(Vec::new())
    }
}
