//! Background services (design §4, ADRs 0002, 0021): a sandbox's proxy and
//! the services its runtime declares, run by the operating system's service
//! manager while the user is logged in. There is no enclos daemon.

#[cfg(test)]
pub mod fake;
#[cfg(target_os = "macos")]
pub mod launchd;
pub mod systemd;

use std::ffi::OsString;
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// A service's name for the service manager, unique on the host:
/// `enclos.<install>.<sandbox>.<service>`, such as
/// `enclos.1f2e3d4c.home.proxy`. Lowercase letters, digits, dots and
/// hyphens only, so a label is safe as a file name and as a word on a
/// command line; the engine builds them, and a manager parses what it
/// finds installed.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ServiceLabel(String);

/// What every label starts with.
pub const LABEL_PREFIX: &str = "enclos.";

impl ServiceLabel {
    /// `text` as a label, when it is one.
    pub fn parse(text: &str) -> Option<ServiceLabel> {
        let safe = text
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-');
        (safe && text.starts_with(LABEL_PREFIX) && text.len() > LABEL_PREFIX.len())
            .then(|| ServiceLabel(text.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The service's part, after the last dot: `proxy`, or the runtime's
    /// name for it.
    pub fn service(&self) -> &str {
        self.0.rsplit('.').next().unwrap_or_default()
    }
}

impl fmt::Display for ServiceLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(&self.0)
    }
}

/// One service, as enclos defines it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceUnit {
    pub label: ServiceLabel,
    pub program: PathBuf,
    pub args: Vec<OsString>,
    /// Where its standard output and error go.
    pub log: PathBuf,
    /// Variables it runs with; secrets never go here (ADR 0022).
    pub env: Vec<(String, String)>,
    /// How long the manager waits, after telling the program to end, before
    /// it kills it: the program may be stopping what it runs.
    pub stop_timeout: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceStatus {
    Running {
        pid: u32,
    },
    /// Installed but not running now (between restarts, or exited).
    Loaded,
    /// The manager says it has no such service.
    NotLoaded,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{what}")]
pub struct ServiceError {
    pub what: String,
}

/// The host's service manager: launchd on macOS, systemd later. What the
/// engine relies on, for every implementation:
///
/// - `start` installs a unit so it runs now and again at each login, and
///   replaces a unit of the same label already installed. The manager
///   restarts the program after a non-zero exit or a signal, never after
///   exit 0, with a throttle between restarts: a proxy or a runtime that
///   stops serving exits with an error to be started again.
/// - `stop` tells the program to end, waits for it up to the unit's
///   `stop_timeout`, then kills it, and removes the unit; a label that is
///   not installed is not an error.
/// - `installed` lists what `start` installed and `stop` has not removed,
///   running or not.
pub trait ServiceManager {
    /// Whether this manager can install units now; the reason when not.
    fn available(&self) -> Result<(), ServiceError>;
    /// Installs the unit so it starts now and again at each login.
    fn start(&self, unit: &ServiceUnit) -> Result<(), ServiceError>;
    /// Stops the unit and removes it, so it does not start at login.
    fn stop(&self, label: &ServiceLabel) -> Result<(), ServiceError>;
    /// Whether the unit is installed and runs; an error when the manager
    /// cannot be asked, which is not the same as not loaded.
    fn status(&self, label: &ServiceLabel) -> Result<ServiceStatus, ServiceError>;
    /// The labels installed and not removed yet that start with `prefix`,
    /// whether or not they run.
    fn installed(&self, prefix: &str) -> Result<Vec<ServiceLabel>, ServiceError>;
}

/// This host's service manager: launchd on macOS. Other systems have none
/// yet, and refuse to start services.
#[cfg(target_os = "macos")]
pub fn host(user_home: &Path) -> Box<dyn ServiceManager> {
    Box::new(launchd::Launchd::for_user(user_home))
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
    pub(crate) why: &'static str,
}

impl ServiceManager for Unsupported {
    fn available(&self) -> Result<(), ServiceError> {
        Err(ServiceError {
            what: self.why.to_owned(),
        })
    }

    fn start(&self, unit: &ServiceUnit) -> Result<(), ServiceError> {
        Err(ServiceError {
            what: format!("cannot start {}: {}", unit.label, self.why),
        })
    }

    fn stop(&self, _label: &ServiceLabel) -> Result<(), ServiceError> {
        Ok(())
    }

    fn status(&self, _label: &ServiceLabel) -> Result<ServiceStatus, ServiceError> {
        Ok(ServiceStatus::NotLoaded)
    }

    fn installed(&self, _prefix: &str) -> Result<Vec<ServiceLabel>, ServiceError> {
        Ok(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn this_system_has_no_service_manager_yet() {
        let host = host(Path::new("/home/alice"));
        let err = host.available().unwrap_err();
        assert!(err.what.contains("only on macOS"), "{err}");
        assert!(host.installed(LABEL_PREFIX).unwrap().is_empty());
    }

    #[test]
    fn a_label_is_a_safe_word_under_the_enclos_prefix() {
        let label = ServiceLabel::parse("enclos.1f2e3d4c.home.proxy").unwrap();
        assert_eq!(label.service(), "proxy");
        assert_eq!(label.to_string(), "enclos.1f2e3d4c.home.proxy");
        for bad in [
            "",
            "enclos.",
            "com.example.other",
            "enclos.1f2e3d4c.home/proxy",
            "enclos.1f2e3d4c.Home.proxy",
            "enclos.1f2e3d4c.home.proxy ",
        ] {
            assert!(ServiceLabel::parse(bad).is_none(), "{bad:?}");
        }
    }
}
