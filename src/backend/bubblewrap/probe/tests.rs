use super::*;
use crate::host::Verdict;

/// A host with stand-ins for both programs, and `/proc/sys` holding
/// `settings`. Its bubblewrap prints `version` for `--version`, and
/// otherwise prints `said` and exits with `code`.
struct Stand {
    dir: tempfile::TempDir,
}

impl Stand {
    fn new() -> Stand {
        let stand = Stand {
            dir: tempfile::tempdir().unwrap(),
        };
        stand.systemd(257);
        stand.bwrap("bubblewrap 0.12.0", "", 0);
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

    fn bwrap(&self, version: &str, said: &str, code: u8) {
        self.script(
            "bwrap",
            &format!(
                "[ \"$1\" = --version ] && {{ echo '{version}'; exit 0; }}\necho '{said}' >&2\nexit {code}"
            ),
        );
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

fn reason(probed: Probed) -> String {
    match probed.probe {
        Probe::Unavailable { reason } => reason,
        Probe::Available => panic!("available"),
    }
}

#[test]
fn a_linux_host_whose_bubblewrap_starts_a_program_can_run_it() {
    let probed = probe(&Stand::new().host());
    assert_eq!(probed.probe, Probe::Available);
    let checks: Vec<(&str, &Verdict)> = probed
        .checks
        .iter()
        .map(|c| (c.what.as_str(), &c.verdict))
        .collect();
    assert_eq!(
        checks,
        [
            ("bubblewrap", &Verdict::Fine),
            ("user namespaces", &Verdict::Fine),
            ("bubblewrap starts a program", &Verdict::Fine),
        ]
    );
    assert!(
        probed.checks[0]
            .found
            .ends_with("is bubblewrap 0.12.0: enclos needs 0.9.0 or later"),
        "{probed:?}"
    );
}

#[test]
fn another_system_cannot() {
    let mut host = Stand::new().host();
    host.linux = false;
    let probed = probe(&host);
    assert!(probed.checks.is_empty());
    assert!(reason(probed).contains("only on Linux"));
}

#[test]
fn a_missing_bubblewrap_says_which_package_to_install() {
    let stand = Stand::new();
    std::fs::remove_file(stand.dir.path().join("bwrap")).unwrap();
    let probed = probe(&stand.host());
    assert_eq!(
        probed.checks.len(),
        1,
        "no check after the first that fails"
    );
    assert_eq!(probed.checks[0].verdict, Verdict::Blocks);
    let why = reason(probed);
    assert!(why.contains("is missing"), "{why}");
    assert!(why.contains("apt install bubblewrap"), "{why}");
}

/// Debian 12's 0.8.0 is older than any supported target's.
#[test]
fn a_bubblewrap_older_than_the_oldest_accepted_is_refused_with_what_to_install() {
    let stand = Stand::new();
    stand.bwrap("bubblewrap 0.8.0", "", 0);
    let why = reason(probe(&stand.host()));
    assert!(
        why.contains("is bubblewrap 0.8.0, and enclos needs 0.9.0 or later"),
        "{why}"
    );
    assert!(why.contains("Ubuntu 24.04 has 0.9.0"), "{why}");
    stand.bwrap("bubblewrap 0.9.0", "", 0);
    assert_eq!(probe(&stand.host()).probe, Probe::Available);
    stand.bwrap("bubblewrap 0.10", "", 0);
    assert_eq!(probe(&stand.host()).probe, Probe::Available);
}

#[test]
fn a_bubblewrap_whose_version_cannot_be_read_is_refused() {
    let stand = Stand::new();
    stand.bwrap("bwrap, of some build", "", 0);
    let why = reason(probe(&stand.host()));
    assert!(why.contains("cannot tell which"), "{why}");
    assert!(why.contains("bwrap, of some build"), "{why}");
}

#[test]
fn versions_read_as_bubblewrap_prints_them() {
    assert_eq!(
        parse_version("bubblewrap 0.11.1\n"),
        Some(Version(0, 11, 1))
    );
    assert_eq!(parse_version("bubblewrap 0.10"), Some(Version(0, 10, 0)));
    assert_eq!(parse_version("bwrap 0.11.1"), None);
    assert_eq!(parse_version("bubblewrap 0.x.1"), None);
    assert_eq!(parse_version(""), None);
    assert!(Version(0, 10, 0) > Version(0, 9, 0));
}

#[test]
fn a_kernel_without_user_namespaces_is_named() {
    let stand = Stand::new();
    stand.setting("user/max_user_namespaces", "0");
    let why = reason(probe(&stand.host()));
    assert!(why.contains("user.max_user_namespaces = 0"), "{why}");
    assert!(why.contains("/etc/sysctl.d"), "{why}");
    let stand = Stand::new();
    stand.setting("kernel/unprivileged_userns_clone", "0");
    let why = reason(probe(&stand.host()));
    assert!(why.contains("unprivileged_userns_clone = 0"), "{why}");
    stand.setting("kernel/unprivileged_userns_clone", "1");
    assert_eq!(probe(&stand.host()).probe, Probe::Available);
}

/// The refusal says what was found, what is needed and what to do.
#[test]
fn systemd_older_than_254_is_refused_with_what_was_found_and_what_to_do() {
    let stand = Stand::new();
    stand.systemd(252);
    let probed = probe(&stand.host());
    assert_eq!(probed.checks.len(), 2, "bubblewrap is not started");
    let why = reason(probed);
    assert!(why.contains("systemd 254 or later"), "{why}");
    assert!(why.contains("this host has 252"), "{why}");
    assert!(why.contains("Debian 13 or Ubuntu 24.04"), "{why}");
    stand.systemd(254);
    assert_eq!(probe(&stand.host()).probe, Probe::Available);
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
    stand.bwrap(
        "bubblewrap 0.9.0",
        "bwrap: setting up uid map: Permission denied",
        1,
    );
    let probed = probe(&stand.host());
    assert_eq!(probed.checks[2].verdict, Verdict::Blocks);
    assert_eq!(probed.checks[2].fix, None);
    let why = reason(probed);
    assert!(why.contains("could not start a program"), "{why}");
    assert!(why.contains("setting up uid map"), "{why}");
    assert!(!why.contains("AppArmor"), "{why}");
}

/// Ubuntu 24.04 as installed (design §5, Linux hosts): said of user
/// namespaces, and named with its fix when bubblewrap cannot start.
#[test]
fn apparmors_restriction_is_named_when_it_is_on() {
    let stand = Stand::new();
    stand.setting("kernel/apparmor_restrict_unprivileged_userns", "1");
    let probed = probe(&stand.host());
    assert_eq!(probed.probe, Probe::Available);
    assert!(
        probed.checks[1]
            .found
            .contains("AppArmor profile allows `userns`")
    );
    stand.bwrap(
        "bubblewrap 0.9.0",
        "bwrap: setting up uid map: Permission denied",
        1,
    );
    let probed = probe(&stand.host());
    let fix = probed.checks[2].fix.clone().unwrap();
    assert!(fix.contains("getting-started"), "{fix}");
    let why = reason(probed);
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
            "[ \"$1\" = --version ] && {{ echo 'bubblewrap 0.9.0'; exit 0; }}\nprintf '%s\\n' \"$@\" > '{}'; env >> '{}'",
            seen.display(),
            seen.display()
        ),
    );
    assert_eq!(probe(&stand.host()).probe, Probe::Available);
    let said = std::fs::read_to_string(&seen).unwrap();
    let args: Vec<&str> = said.lines().take(4).collect();
    assert_eq!(args, ["--ro-bind", "/", "/", "true"]);
    assert!(!said.contains("HOME="), "{said}");
}
