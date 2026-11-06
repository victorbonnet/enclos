//! Whether bubblewrap can run on this host (ADR 0009): Linux, bubblewrap
//! 0.9.0 or later, user namespaces, systemd 254 or later, and bubblewrap
//! starting a program. Landlock is not required (ADR 0037): where it is
//! missing or older, the backend runs and declares the weaker controls,
//! which `degraded` reports.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::backend::Probe;
use crate::host::HostCheck;
use crate::lifecycle::bounded::{LIMIT, output_within};
use crate::lifecycle::cgroup::Systemd;

/// The oldest bubblewrap enclos runs: Ubuntu 24.04's, the oldest any
/// supported target packages, and the oldest CI runs the backend's
/// arguments under (design §5, Linux hosts).
pub const BWRAP_NEEDED: Version = Version(0, 9, 0);

/// A bubblewrap version, as `bwrap --version` prints it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version(pub u32, pub u32, pub u32);

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.0, self.1, self.2)
    }
}

/// The version in what `bwrap --version` printed: `bubblewrap 0.9.0`.
fn parse_version(text: &str) -> Option<Version> {
    let mut words = text.lines().next()?.split_whitespace();
    if words.next()? != "bubblewrap" {
        return None;
    }
    let mut parts = words.next()?.split('.').map(|p| p.parse::<u32>().ok());
    Some(Version(
        parts.next()??,
        parts.next()??,
        parts.next().unwrap_or(Some(0))?,
    ))
}

/// The host as the probe reads it.
pub(super) struct OnHost {
    pub linux: bool,
    pub bwrap: PathBuf,
    pub systemd_run: PathBuf,
    /// `/proc/sys`, where the kernel says whether user namespaces may be made.
    pub proc_sys: PathBuf,
}

impl OnHost {
    pub fn new(bwrap: &Path, systemd_run: &Path) -> OnHost {
        OnHost {
            linux: cfg!(target_os = "linux"),
            bwrap: bwrap.to_owned(),
            systemd_run: systemd_run.to_owned(),
            proc_sys: PathBuf::from("/proc/sys"),
        }
    }

    fn setting(&self, name: &str) -> Option<String> {
        std::fs::read_to_string(self.proc_sys.join(name))
            .ok()
            .map(|v| v.trim().to_owned())
    }
}

/// What the probe found: its answer, and each check it made on the way.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Probed {
    pub probe: Probe,
    /// Up to the first that keeps bubblewrap from running. systemd's is not
    /// among them: `doctor` shows it apart, as every Linux session needs it.
    pub checks: Vec<HostCheck>,
}

/// Each check in turn; the first that fails says what was found and what to
/// do, and the checks after it are not made.
pub(super) fn probe(host: &OnHost) -> Probed {
    let refused = |checks, reason: String| Probed {
        probe: Probe::Unavailable { reason },
        checks,
    };
    let mut checks = Vec::new();
    if !host.linux {
        return refused(checks, "bubblewrap runs only on Linux".to_owned());
    }
    for check in [installed, user_namespaces] {
        let check = check(host);
        let reason = check.blocks_backend().then(|| check.reason());
        checks.push(check);
        if let Some(reason) = reason {
            return refused(checks, reason);
        }
    }
    if let Some(refusal) = Systemd::at(&host.systemd_run).refusal() {
        return refused(checks, refusal);
    }
    let started = starts(host);
    let probe = match started.blocks_backend() {
        true => Probe::Unavailable {
            reason: started.reason(),
        },
        false => Probe::Available,
    };
    checks.push(started);
    Probed { probe, checks }
}

/// bubblewrap at its path, at [`BWRAP_NEEDED`] or later.
fn installed(host: &OnHost) -> HostCheck {
    const WHAT: &str = "bubblewrap";
    let bwrap = host.bwrap.display();
    if !host.bwrap.exists() {
        return HostCheck::blocks(
            WHAT,
            format!("{bwrap} is missing"),
            Some("install the bubblewrap package (`sudo apt install bubblewrap` on Debian and Ubuntu)".to_owned()),
        );
    }
    let out = output_within(
        Command::new(&host.bwrap)
            .arg("--version")
            .env_clear()
            .stdin(Stdio::null()),
        LIMIT,
    );
    let version = match out {
        Ok(out) => {
            let said = String::from_utf8_lossy(&out.stdout);
            match parse_version(&said).filter(|_| out.status.success()) {
                Some(version) => Ok(version),
                None => Err(format!(
                    "`{bwrap} --version` ended with {} and printed `{}`",
                    out.status,
                    said.trim()
                )),
            }
        }
        Err(e) => Err(format!("cannot run {bwrap}: {e}")),
    };
    let upgrade = || {
        Some(format!(
            "install bubblewrap {BWRAP_NEEDED} or later from the host's packages: Ubuntu 24.04 has 0.9.0, Debian 13 0.12.0"
        ))
    };
    match version {
        Ok(version) if version >= BWRAP_NEEDED => HostCheck::fine(
            WHAT,
            format!("{bwrap} is bubblewrap {version}: enclos needs {BWRAP_NEEDED} or later"),
        ),
        Ok(version) => HostCheck::blocks(
            WHAT,
            format!("{bwrap} is bubblewrap {version}, and enclos needs {BWRAP_NEEDED} or later"),
            upgrade(),
        ),
        Err(why) => HostCheck::blocks(
            WHAT,
            format!(
                "enclos needs bubblewrap {BWRAP_NEEDED} or later, and cannot tell which {bwrap} is: {why}"
            ),
            upgrade(),
        ),
    }
}

/// Whether the kernel lets this user make the user namespace bubblewrap
/// makes for each session. AppArmor's restriction is only said here: what
/// it refuses shows when bubblewrap starts.
fn user_namespaces(host: &OnHost) -> HostCheck {
    const WHAT: &str = "user namespaces";
    if host.setting("user/max_user_namespaces").as_deref() == Some("0") {
        return HostCheck::blocks(
            WHAT,
            "this kernel allows no user namespace (user.max_user_namespaces = 0), which bubblewrap makes for each session",
            Some("set user.max_user_namespaces above 0 in a file of /etc/sysctl.d, then run `sudo sysctl --system`".to_owned()),
        );
    }
    if host.setting("kernel/unprivileged_userns_clone").as_deref() == Some("0") {
        return HostCheck::blocks(
            WHAT,
            "this kernel allows no user namespace to a user (kernel.unprivileged_userns_clone = 0), which bubblewrap makes for each session",
            Some("set kernel.unprivileged_userns_clone to 1 in a file of /etc/sysctl.d, then run `sudo sysctl --system`".to_owned()),
        );
    }
    let found = match apparmor_restricts(host) {
        true => {
            "allowed to a program whose AppArmor profile allows `userns` (kernel.apparmor_restrict_unprivileged_userns = 1)"
        }
        false => "allowed",
    };
    HostCheck::fine(WHAT, found)
}

/// Whether AppArmor lets only a program with a profile that allows it make
/// a user namespace, as on Ubuntu 24.04 (design §5).
fn apparmor_restricts(host: &OnHost) -> bool {
    host.setting("kernel/apparmor_restrict_unprivileged_userns")
        .as_deref()
        == Some("1")
}

/// Whether bubblewrap starts a program with the root bound read-only and
/// nothing else: the least a session needs, a user namespace included.
fn starts(host: &OnHost) -> HostCheck {
    const WHAT: &str = "bubblewrap starts a program";
    let out = output_within(
        Command::new(&host.bwrap)
            .args(["--ro-bind", "/", "/", "true"])
            .env_clear()
            .stdin(Stdio::null()),
        LIMIT,
    );
    let said = match out {
        Ok(out) if out.status.success() => {
            return HostCheck::fine(WHAT, "it does, with `--ro-bind / / true`");
        }
        Ok(out) => format!(
            "{} ({})",
            String::from_utf8_lossy(&out.stderr).trim(),
            out.status
        ),
        Err(e) => e.to_string(),
    };
    let bwrap = host.bwrap.display();
    let found = format!("{bwrap} could not start a program: {said}");
    match apparmor_restricts(host) {
        true => HostCheck::blocks(
            WHAT,
            format!(
                "{found}. AppArmor restricts user namespaces here (kernel.apparmor_restrict_unprivileged_userns = 1)"
            ),
            Some(format!(
                "give {bwrap} a profile that allows `userns`, as docs/getting-started.md shows"
            )),
        ),
        false => HostCheck::blocks(WHAT, found, None),
    }
}

/// The kernel's Landlock ABI, up to the one the rules need, if it has
/// Landlock. Asks only what the kernel supports: nothing is restricted.
#[cfg(target_os = "linux")]
pub(super) fn landlock_abi() -> Option<u32> {
    super::inside::landlock_abi()
}

#[cfg(not(target_os = "linux"))]
pub(super) fn landlock_abi() -> Option<u32> {
    None
}

#[cfg(test)]
mod tests;
