//! Whether bubblewrap can run on this host (ADR 0009): Linux, bubblewrap,
//! user namespaces, systemd 254 or later, and bubblewrap starting a program.
//! Landlock is not required (ADR 0037, proposed): where it is missing or
//! older, the backend runs and declares the weaker controls.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::backend::Probe;
use crate::lifecycle::bounded::{LIMIT, output_within};
use crate::lifecycle::cgroup::Systemd;

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

fn unavailable(reason: String) -> Probe {
    Probe::Unavailable { reason }
}

/// Each check in turn; the first that fails says what was found and what to
/// do.
pub(super) fn probe(host: &OnHost) -> Probe {
    if !host.linux {
        return unavailable("bubblewrap runs only on Linux".to_owned());
    }
    if !host.bwrap.exists() {
        return unavailable(format!(
            "{} is missing: install the bubblewrap package (`sudo apt install bubblewrap` on Debian and Ubuntu)",
            host.bwrap.display()
        ));
    }
    if host.setting("user/max_user_namespaces").as_deref() == Some("0") {
        return unavailable(
            "this kernel allows no user namespace (user.max_user_namespaces = 0), which bubblewrap makes for each session: set it above 0".to_owned(),
        );
    }
    if host.setting("kernel/unprivileged_userns_clone").as_deref() == Some("0") {
        return unavailable(
            "this kernel allows no user namespace to a user (kernel.unprivileged_userns_clone = 0), which bubblewrap makes for each session: set it to 1".to_owned(),
        );
    }
    if let Some(refusal) = Systemd::at(&host.systemd_run).refusal() {
        return unavailable(refusal);
    }
    starts(host)
}

/// Whether bubblewrap starts a program with the root bound read-only and
/// nothing else: the least a session needs, a user namespace included.
fn starts(host: &OnHost) -> Probe {
    let out = output_within(
        Command::new(&host.bwrap)
            .args(["--ro-bind", "/", "/", "true"])
            .env_clear()
            .stdin(Stdio::null()),
        LIMIT,
    );
    let said = match out {
        Ok(out) if out.status.success() => return Probe::Available,
        Ok(out) => format!(
            "{} ({})",
            String::from_utf8_lossy(&out.stderr).trim(),
            out.status
        ),
        Err(e) => e.to_string(),
    };
    let mut reason = format!("{} could not start a program: {said}", host.bwrap.display());
    // Ubuntu 24.04's AppArmor, with no rule for bubblewrap (design §5).
    if host
        .setting("kernel/apparmor_restrict_unprivileged_userns")
        .as_deref()
        == Some("1")
    {
        reason += &format!(
            ". AppArmor restricts user namespaces here (kernel.apparmor_restrict_unprivileged_userns = 1): give {} a profile that allows `userns`, as docs/getting-started.md shows",
            host.bwrap.display()
        );
    }
    unavailable(reason)
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
mod tests {
    use super::*;

    /// A host with stand-ins for both programs, each a script printing
    /// `said` and exiting with `code`, and `/proc/sys` holding `settings`.
    struct Stand {
        dir: tempfile::TempDir,
    }

    impl Stand {
        fn new() -> Stand {
            let stand = Stand {
                dir: tempfile::tempdir().unwrap(),
            };
            stand.systemd(257);
            stand.bwrap("", 0);
            stand
        }

        fn script(&self, name: &str, body: &str) {
            crate::test_scripts::write_script(&self.dir.path().join(name), body);
        }

        fn systemd(&self, version: u32) {
            self.script(
                "systemd-run",
                &format!("echo 'systemd {version} ({version}.1-1)'"),
            );
        }

        fn bwrap(&self, said: &str, code: u8) {
            self.script("bwrap", &format!("echo '{said}' >&2\nexit {code}"));
        }

        fn setting(&self, name: &str, value: &str) {
            let path = self.dir.path().join("sys").join(name);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, format!("{value}\n")).unwrap();
        }

        fn host(&self) -> OnHost {
            OnHost {
                linux: true,
                bwrap: self.dir.path().join("bwrap"),
                systemd_run: self.dir.path().join("systemd-run"),
                proc_sys: self.dir.path().join("sys"),
            }
        }
    }

    fn reason(probe: Probe) -> String {
        match probe {
            Probe::Unavailable { reason } => reason,
            Probe::Available => panic!("available"),
        }
    }

    #[test]
    fn a_linux_host_whose_bubblewrap_starts_a_program_can_run_it() {
        assert_eq!(probe(&Stand::new().host()), Probe::Available);
    }

    #[test]
    fn another_system_cannot() {
        let mut host = Stand::new().host();
        host.linux = false;
        assert!(reason(probe(&host)).contains("only on Linux"));
    }

    #[test]
    fn a_missing_bubblewrap_says_which_package_to_install() {
        let stand = Stand::new();
        std::fs::remove_file(stand.dir.path().join("bwrap")).unwrap();
        let why = reason(probe(&stand.host()));
        assert!(why.contains("is missing"), "{why}");
        assert!(why.contains("apt install bubblewrap"), "{why}");
    }

    #[test]
    fn a_kernel_without_user_namespaces_is_named() {
        let stand = Stand::new();
        stand.setting("user/max_user_namespaces", "0");
        let why = reason(probe(&stand.host()));
        assert!(why.contains("user.max_user_namespaces = 0"), "{why}");
        let stand = Stand::new();
        stand.setting("kernel/unprivileged_userns_clone", "0");
        let why = reason(probe(&stand.host()));
        assert!(why.contains("unprivileged_userns_clone = 0"), "{why}");
        stand.setting("kernel/unprivileged_userns_clone", "1");
        assert_eq!(probe(&stand.host()), Probe::Available);
    }

    /// What was found, what is needed and what to do (issue #102, M3-15).
    #[test]
    fn systemd_older_than_254_is_refused_with_what_was_found_and_what_to_do() {
        let stand = Stand::new();
        stand.systemd(252);
        let why = reason(probe(&stand.host()));
        assert!(why.contains("systemd 254 or later"), "{why}");
        assert!(why.contains("this host has 252"), "{why}");
        assert!(why.contains("Debian 13 or Ubuntu 24.04"), "{why}");
        stand.systemd(254);
        assert_eq!(probe(&stand.host()), Probe::Available);
    }

    #[test]
    fn a_systemd_whose_version_cannot_be_read_is_refused() {
        let stand = Stand::new();
        stand.script("systemd-run", "echo nonsense");
        let why = reason(probe(&stand.host()));
        assert!(why.contains("cannot tell which this host has"), "{why}");
    }

    #[test]
    fn a_bubblewrap_that_cannot_start_a_program_says_what_it_said() {
        let stand = Stand::new();
        stand.bwrap("bwrap: setting up uid map: Permission denied", 1);
        let why = reason(probe(&stand.host()));
        assert!(why.contains("could not start a program"), "{why}");
        assert!(why.contains("setting up uid map"), "{why}");
        assert!(!why.contains("AppArmor"), "{why}");
    }

    /// Ubuntu 24.04 as installed (design §5, Linux hosts).
    #[test]
    fn apparmors_restriction_is_named_when_it_is_on() {
        let stand = Stand::new();
        stand.bwrap("bwrap: setting up uid map: Permission denied", 1);
        stand.setting("kernel/apparmor_restrict_unprivileged_userns", "1");
        let why = reason(probe(&stand.host()));
        assert!(
            why.contains("kernel.apparmor_restrict_unprivileged_userns = 1"),
            "{why}"
        );
        assert!(why.contains("getting-started"), "{why}");
    }

    /// The probe runs bubblewrap with the root bound read-only, and nothing
    /// of this process's environment.
    #[test]
    fn the_probe_starts_bubblewrap_with_the_root_alone_and_no_variables() {
        let stand = Stand::new();
        let seen = stand.dir.path().join("seen");
        stand.script(
            "bwrap",
            &format!(
                "printf '%s\\n' \"$@\" > '{}'; env >> '{}'",
                seen.display(),
                seen.display()
            ),
        );
        assert_eq!(probe(&stand.host()), Probe::Available);
        let said = std::fs::read_to_string(&seen).unwrap();
        let args: Vec<&str> = said.lines().take(4).collect();
        assert_eq!(args, ["--ro-bind", "/", "/", "true"]);
        assert!(!said.contains("HOME="), "{said}");
    }
}
