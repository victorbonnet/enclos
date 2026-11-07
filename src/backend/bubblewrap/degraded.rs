//! The degraded controls of the bubblewrap backend (design §5, Degraded
//! controls on Linux; ADRs 0037 and 0038): Landlock and the cgroup
//! controllers a limit needs. Where the host lacks one, the backend runs
//! without it, and `doctor` says what is not enforced, the risk and the fix.
//! Everything is read from files under the roots given, so tests give a
//! host of their own.

use std::path::PathBuf;

use super::proposed::LANDLOCK_ABI_NEEDED;
use crate::host::{HostCheck, Verdict};

/// The kernel version that brings the ABI the rules need (landlock(7)).
const LANDLOCK_ABI_NEEDED_LINUX: &str = "6.12";

/// The rights and scopes each Landlock ABI adds that the rules use, after
/// ABI 1's (landlock(7)).
const LANDLOCK_ADDS: [(u32, &str); 4] = [
    (
        2,
        "renaming and linking a file into another folder (REFER, ABI 2)",
    ),
    (3, "truncating a file (TRUNCATE, ABI 3)"),
    (5, "`ioctl` on devices (IOCTL_DEV, ABI 5)"),
    (
        6,
        "the scopes that keep abstract Unix sockets and signals within the sandbox (ABI 6)",
    ),
];

/// The host as these checks read it.
pub(super) struct Kernel {
    /// The kernel's Landlock ABI, up to the one the rules need, if it has
    /// Landlock.
    pub landlock_abi: Option<u32>,
    /// `/proc`.
    pub proc: PathBuf,
    /// `/sys`.
    pub sys: PathBuf,
    /// `/boot`, where Debian and Ubuntu keep each kernel's build
    /// configuration, and Raspberry Pi OS its boot options.
    pub boot: PathBuf,
    /// The user whose systemd manager runs the sessions.
    pub uid: u32,
}

impl Kernel {
    pub fn host() -> Kernel {
        Kernel {
            landlock_abi: super::probe::landlock_abi(),
            proc: "/proc".into(),
            sys: "/sys".into(),
            boot: "/boot".into(),
            uid: rustix::process::getuid().as_raw(),
        }
    }

    fn read(&self, path: &PathBuf) -> Result<String, String> {
        std::fs::read_to_string(path).map_err(|e| format!("cannot read {}: {e}", path.display()))
    }

    /// Whether the kernel's command line turns controller `name` off at
    /// boot (`cgroup_disable=`): the kernel has it, but it is not in use.
    fn turned_off_at_boot(&self, name: &str) -> bool {
        let cmdline = std::fs::read_to_string(self.proc.join("cmdline")).unwrap_or_default();
        cmdline
            .split_whitespace()
            .filter_map(|o| o.strip_prefix("cgroup_disable="))
            .any(|list| list.split(',').any(|c| c == name))
    }

    /// The active LSMs, as the kernel lists them.
    fn lsms(&self) -> Result<Vec<String>, String> {
        let text = self.read(&self.sys.join("kernel/security/lsm"))?;
        Ok(text
            .trim()
            .split(',')
            .filter(|l| !l.is_empty())
            .map(str::to_owned)
            .collect())
    }

    /// Whether this kernel is built with Landlock, from its build
    /// configuration in `/boot`; `None` when that cannot be read.
    fn landlock_built(&self) -> Option<bool> {
        let release = std::fs::read_to_string(self.proc.join("sys/kernel/osrelease")).ok()?;
        let config = self.boot.join(format!("config-{}", release.trim()));
        let config = std::fs::read_to_string(config).ok()?;
        Some(
            config
                .lines()
                .any(|l| l.trim() == "CONFIG_SECURITY_LANDLOCK=y"),
        )
    }
}

/// Each degraded control this host has, and each control it holds.
pub(super) fn checks(kernel: &Kernel) -> Vec<HostCheck> {
    let mut checks = vec![landlock(kernel)];
    checks.extend(["memory", "cpu"].map(|c| controller(kernel, c)));
    checks
}

fn landlock(kernel: &Kernel) -> HostCheck {
    const WHAT: &str = "Landlock";
    let degraded = |found: String, not_enforced: String, risk: &str, fix: Option<String>| {
        HostCheck::new(
            WHAT,
            found,
            Verdict::Degraded {
                not_enforced,
                risk: risk.to_owned(),
            },
            fix,
        )
    };
    match kernel.landlock_abi {
        Some(abi) if abi >= LANDLOCK_ABI_NEEDED => HostCheck::fine(
            WHAT,
            format!("ABI {LANDLOCK_ABI_NEEDED} or later, every right the rules need"),
        ),
        Some(abi) => {
            let lacks: Vec<&str> = LANDLOCK_ADDS
                .iter()
                .filter(|(added, _)| *added > abi)
                .map(|(_, right)| *right)
                .collect();
            degraded(
                format!(
                    "ABI {abi}, older than the {LANDLOCK_ABI_NEEDED} the rules need: what it has applies, as a layer over the mounts"
                ),
                format!(
                    "{}; whether execute rules apply on ABI {abi} is open (design §15)",
                    lacks.join("; ")
                ),
                "what those rights would hold rests on the mounts alone, and no mount holds device `ioctl`s or the scopes",
                Some(format!(
                    "a kernel whose Landlock has ABI {LANDLOCK_ABI_NEEDED}: Linux {LANDLOCK_ABI_NEEDED_LINUX} or later"
                )),
            )
        }
        None => {
            let (found, fix) = landlock_missing(kernel);
            degraded(
                found,
                "Landlock's execute rules, so an `[exec]` section; the second layer on writes; the separation of a sandbox's sessions' abstract sockets".to_owned(),
                "any program the sandbox can read can run, including one it downloaded or wrote into its home or a workspace; a path mounted writable by mistake has no second check",
                fix,
            )
        }
    }
}

/// What is known of a kernel that gives no Landlock ABI, and the fix: a
/// boot option where it is built, another kernel where it is not.
fn landlock_missing(kernel: &Kernel) -> (String, Option<String>) {
    let lsms = kernel.lsms();
    let rebuild = "a kernel built with CONFIG_SECURITY_LANDLOCK=y: no boot option turns it on in this one; Raspberry Pi OS's kernels are all built without it, so there it takes a kernel you build";
    let boot_option = |lsms: &[String]| {
        let mut wanted = vec!["landlock"];
        wanted.extend(
            lsms.iter()
                .map(String::as_str)
                .filter(|l| *l != "capability" && *l != "landlock"),
        );
        format!(
            "add `landlock` to the kernel's `lsm=` boot option, keeping the modules active now (`lsm={}`), then reboot",
            wanted.join(",")
        )
    };
    match (lsms, kernel.landlock_built()) {
        (Ok(lsms), _) if lsms.iter().any(|l| l == "landlock") => (
            format!(
                "in the active LSMs ({}), but the kernel answers no Landlock ABI",
                lsms.join(",")
            ),
            None,
        ),
        (_, Some(false)) => (
            "not in this kernel: it is built without CONFIG_SECURITY_LANDLOCK".to_owned(),
            Some(rebuild.to_owned()),
        ),
        (Ok(lsms), Some(true)) => (
            format!(
                "built into this kernel, but not active: the active LSMs are {}",
                lsms.join(",")
            ),
            Some(boot_option(&lsms)),
        ),
        (Ok(lsms), None) => (
            format!(
                "not active: the active LSMs are {}, and whether the kernel is built with it cannot be told, as its build configuration is not in {}",
                lsms.join(","),
                kernel.boot.display()
            ),
            Some(format!(
                "where it is built, {}; else {rebuild}",
                boot_option(&lsms)
            )),
        ),
        (Err(why), _) => (
            format!(
                "none: the kernel answers no Landlock ABI, and the active LSMs are unknown: {why}"
            ),
            Some(rebuild.to_owned()),
        ),
    }
}

/// Why this host does not hold a `memory` limit for this user, or none when
/// it does (ADR 0038): the memory controller as [`checks`] finds it, where
/// anything but delegated to the user's manager, a controller that cannot
/// be read included, counts as not held.
pub(super) fn memory_not_held(kernel: &Kernel) -> Option<String> {
    let check = controller(kernel, "memory");
    match check.verdict {
        Verdict::Fine => None,
        _ => Some(format!("memory controller: {}", check.found)),
    }
}

/// Whether `name`, the controller a limit of that name needs, is in the
/// kernel and delegated to the user's systemd manager, where a session's
/// scope sits.
fn controller(kernel: &Kernel, name: &str) -> HostCheck {
    let what = format!("{name} controller");
    let cgroups = kernel.sys.join("fs/cgroup");
    let root = cgroups.join("cgroup.controllers");
    let uid = kernel.uid;
    let manager = cgroups
        .join(format!("user.slice/user-{uid}.slice/user@{uid}.service"))
        .join("cgroup.controllers");
    let has = |text: &str| text.split_whitespace().any(|c| c == name);
    let degraded = |found: String, fix: String| {
        HostCheck::new(
            &what,
            found,
            Verdict::Degraded {
                not_enforced: format!("a `{name}` limit"),
                risk: match name {
                    "memory" => {
                        "no memory cap: a runaway agent can exhaust the host's RAM".to_owned()
                    }
                    _ => format!("no `{name}` cap: a busy agent can take all of it"),
                },
            },
            Some(fix),
        )
    };
    let in_root = match kernel.read(&root) {
        Ok(text) => text,
        Err(why) => return HostCheck::note(&what, format!("cannot tell: {why}"), None),
    };
    if !has(&in_root) {
        let turned_off = kernel.turned_off_at_boot(name);
        let found = match turned_off {
            true => format!(
                "turned off at boot: the kernel's command line ({}) has `cgroup_disable={name}`, so {} lists `{}`",
                kernel.proc.join("cmdline").display(),
                root.display(),
                in_root.trim()
            ),
            false => format!(
                "not in the kernel: {} lists `{}`",
                root.display(),
                in_root.trim()
            ),
        };
        return degraded(found, controller_back(kernel, name, turned_off));
    }
    match kernel.read(&manager) {
        Ok(text) if has(&text) => HostCheck::fine(&what, "delegated to your systemd manager"),
        Ok(text) => degraded(
            format!(
                "not delegated to your systemd manager: {} lists `{}`",
                manager.display(),
                text.trim()
            ),
            "where `systemctl cat user@.service` shows a `Delegate=` without it, a drop-in, /etc/systemd/system/user@.service.d/delegate.conf, holding `[Service]` and `Delegate=pids memory cpu`, then `sudo systemctl daemon-reload` and a reboot".to_owned(),
        ),
        Err(why) => HostCheck::note(
            &what,
            format!("in the kernel; whether it is delegated to your systemd manager cannot be told: {why}"),
            None,
        ),
    }
}

/// How to bring back controller `name`, missing from the root cgroup:
/// `turned_off` when the kernel's command line turned it off at boot.
fn controller_back(kernel: &Kernel, name: &str, turned_off: bool) -> String {
    let firmware = kernel.boot.join("firmware/cmdline.txt");
    match (turned_off, firmware.exists()) {
        // Raspberry Pi OS: the firmware passes it, and its kernels read
        // `cgroup_enable=` after the firmware's options.
        (true, true) => format!(
            "add ` cgroup_enable={name}` to the end of the single line in {}, reboot, and check that `{name}` is in /sys/fs/cgroup/cgroup.controllers",
            firmware.display()
        ),
        (true, false) => format!(
            "remove `cgroup_disable={name}` from the boot loader's kernel command line, then reboot"
        ),
        (false, _) => format!("a kernel with the {name} controller"),
    }
}

#[cfg(test)]
mod tests;
