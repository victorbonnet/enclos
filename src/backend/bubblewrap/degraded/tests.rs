use super::*;

/// A host's `/proc`, `/sys` and `/boot`, made of fixtures in a folder of
/// the test's own, for user 1000.
struct Fixture {
    dir: tempfile::TempDir,
    landlock_abi: Option<u32>,
}

const MANAGER: &str =
    "sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/cgroup.controllers";

impl Fixture {
    fn new(landlock_abi: Option<u32>) -> Fixture {
        let fixture = Fixture {
            dir: tempfile::tempdir().unwrap(),
            landlock_abi,
        };
        fixture.file("proc/sys/kernel/osrelease", "6.18.50+rpt-rpi-2712\n");
        fixture
    }

    /// GitHub's Ubuntu 24.04 runners, as the host survey measured them.
    fn ubuntu() -> Fixture {
        let fixture = Fixture::new(Some(8));
        fixture.file(
            "sys/kernel/security/lsm",
            "lockdown,capability,landlock,yama,apparmor,ima,evm",
        );
        fixture.file(
            "sys/fs/cgroup/cgroup.controllers",
            "cpuset cpu io memory hugetlb pids rdma misc\n",
        );
        fixture.file(MANAGER, "cpuset cpu io memory pids\n");
        fixture
    }

    /// 64-bit Raspberry Pi OS (Debian 13, kernel 6.18), as the host survey
    /// measured it: no Landlock built, and the firmware turning the memory
    /// controller off.
    fn raspberry_pi_os() -> Fixture {
        let fixture = Fixture::new(None);
        fixture.file("sys/kernel/security/lsm", "capability");
        fixture.file(
            "boot/config-6.18.50+rpt-rpi-2712",
            "CONFIG_SECURITY=y\n# CONFIG_SECURITY_LANDLOCK is not set\n",
        );
        fixture.file("sys/fs/cgroup/cgroup.controllers", "cpuset cpu io pids\n");
        fixture.file(MANAGER, "cpu pids\n");
        fixture.file(
            "proc/cmdline",
            "coherent_pool=1M 8250.nr_uarts=1 cgroup_disable=memory numa_policy=interleave console=tty1 root=PARTUUID=1-02 rootwait\n",
        );
        fixture.file(
            "boot/firmware/cmdline.txt",
            "console=tty1 root=PARTUUID=1-02 rootwait\n",
        );
        fixture
    }

    fn file(&self, path: &str, text: &str) {
        let path = self.dir.path().join(path);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }

    fn remove(&self, path: &str) {
        std::fs::remove_file(self.dir.path().join(path)).unwrap();
    }

    fn kernel(&self) -> Kernel {
        Kernel {
            landlock_abi: self.landlock_abi,
            proc: self.dir.path().join("proc"),
            sys: self.dir.path().join("sys"),
            boot: self.dir.path().join("boot"),
            uid: 1000,
        }
    }

    fn check(&self, what: &str) -> HostCheck {
        checks(&self.kernel())
            .into_iter()
            .find(|c| c.what == what)
            .unwrap()
    }
}

fn not_enforced(check: &HostCheck) -> &str {
    match &check.verdict {
        Verdict::Degraded { not_enforced, .. } => not_enforced,
        other => panic!("{other:?}: {check:?}"),
    }
}

fn fix(check: &HostCheck) -> &str {
    check.fix.as_deref().unwrap()
}

#[test]
fn a_host_with_every_control_says_each_is_held() {
    let checks = checks(&Fixture::ubuntu().kernel());
    let whats: Vec<&str> = checks.iter().map(|c| c.what.as_str()).collect();
    assert_eq!(whats, ["Landlock", "memory controller", "cpu controller"]);
    assert!(
        checks.iter().all(|c| c.verdict == Verdict::Fine),
        "{checks:?}"
    );
    assert_eq!(checks[0].found, "ABI 8: the rules need 6");
    assert_eq!(checks[1].found, "delegated to your systemd manager");
}

/// Raspberry Pi OS's kernel: no boot option turns it on.
#[test]
fn landlock_not_built_says_what_is_not_enforced_and_that_it_takes_another_kernel() {
    let check = Fixture::raspberry_pi_os().check("Landlock");
    assert!(
        check
            .found
            .contains("built without CONFIG_SECURITY_LANDLOCK"),
        "{check:?}"
    );
    assert!(
        not_enforced(&check).contains("`[exec]` section"),
        "{check:?}"
    );
    match &check.verdict {
        Verdict::Degraded { risk, .. } => {
            assert!(
                risk.contains("any program the sandbox can read can run"),
                "{risk}"
            )
        }
        other => panic!("{other:?}"),
    }
    assert!(
        fix(&check).contains("CONFIG_SECURITY_LANDLOCK=y"),
        "{check:?}"
    );
    assert!(!fix(&check).contains("lsm="), "{check:?}");
}

/// Built, but left out of the active list: the boot option keeps the
/// modules active now, and puts Landlock first, as the kernel's
/// documentation writes it.
#[test]
fn landlock_built_but_not_active_gives_the_boot_option_with_the_modules_kept() {
    let fixture = Fixture::new(None);
    fixture.file(
        "sys/kernel/security/lsm",
        "capability,lockdown,yama,apparmor",
    );
    fixture.file(
        "boot/config-6.18.50+rpt-rpi-2712",
        "CONFIG_SECURITY_LANDLOCK=y\nCONFIG_LSM=\"lockdown,yama,apparmor\"\n",
    );
    let check = fixture.check("Landlock");
    assert!(
        check
            .found
            .contains("built into this kernel, but not active"),
        "{check:?}"
    );
    assert!(
        fix(&check).contains("`lsm=landlock,lockdown,yama,apparmor`"),
        "{check:?}"
    );
}

/// With no build configuration to read, both fixes are given.
#[test]
fn landlock_missing_on_a_kernel_of_unknown_build_gives_both_fixes() {
    let fixture = Fixture::new(None);
    fixture.file("sys/kernel/security/lsm", "capability,yama");
    let check = fixture.check("Landlock");
    assert!(check.found.contains("cannot be told"), "{check:?}");
    assert!(fix(&check).contains("`lsm=landlock,yama`"), "{check:?}");
    assert!(
        fix(&check).contains("CONFIG_SECURITY_LANDLOCK=y"),
        "{check:?}"
    );
    fixture.remove("sys/kernel/security/lsm");
    let check = fixture.check("Landlock");
    assert!(check.found.contains("cannot read"), "{check:?}");
    assert!(
        fix(&check).contains("CONFIG_SECURITY_LANDLOCK=y"),
        "{check:?}"
    );
}

/// An older ABI names what it lacks, and the kernel that brings the ABI
/// the rules need.
#[test]
fn an_older_landlock_abi_names_what_it_lacks_and_the_kernel_that_brings_it() {
    let check = Fixture::new(Some(4)).check("Landlock");
    assert!(
        check.found.starts_with("ABI 4, older than the 6"),
        "{check:?}"
    );
    let lacks = not_enforced(&check);
    assert!(lacks.contains("IOCTL_DEV"), "{lacks}");
    assert!(lacks.contains("abstract Unix sockets"), "{lacks}");
    assert!(!lacks.contains("TRUNCATE"), "{lacks}");
    assert!(lacks.contains("open (design §15)"), "{lacks}");
    assert_eq!(
        fix(&check),
        "a kernel whose Landlock has ABI 6: Linux 6.12 or later"
    );
    let check = Fixture::new(Some(5)).check("Landlock");
    assert!(!not_enforced(&check).contains("IOCTL_DEV"), "{check:?}");
}

/// Raspberry Pi OS: the firmware passes `cgroup_disable=memory`, and
/// `cmdline.txt` takes the option that turns it back on.
#[test]
fn the_memory_controller_turned_off_by_the_firmware_says_what_to_add_to_cmdline_txt() {
    let fixture = Fixture::raspberry_pi_os();
    let check = fixture.check("memory controller");
    assert!(check.found.contains("not in the kernel"), "{check:?}");
    assert!(check.found.contains("`cpuset cpu io pids`"), "{check:?}");
    assert_eq!(not_enforced(&check), "a `memory` limit");
    assert!(fix(&check).contains("` cgroup_enable=memory`"), "{check:?}");
    assert!(fix(&check).contains("firmware/cmdline.txt"), "{check:?}");
    // The `cpu` controller the Raspberry Pi delegates.
    assert_eq!(fixture.check("cpu controller").verdict, Verdict::Fine);
    // Elsewhere, the option is the boot loader's to remove.
    fixture.remove("boot/firmware/cmdline.txt");
    let check = fixture.check("memory controller");
    assert!(
        fix(&check).contains("remove `cgroup_disable=memory`"),
        "{check:?}"
    );
}

#[test]
fn a_controller_not_delegated_gives_the_drop_in() {
    let fixture = Fixture::ubuntu();
    fixture.file(MANAGER, "cpu pids\n");
    let check = fixture.check("memory controller");
    assert!(check.found.contains("not delegated"), "{check:?}");
    assert!(check.found.contains("`cpu pids`"), "{check:?}");
    assert!(
        fix(&check).contains("Delegate=pids memory cpu"),
        "{check:?}"
    );
    assert_eq!(fixture.check("cpu controller").verdict, Verdict::Fine);
}

/// No user manager to read, or no unified hierarchy: said, not guessed.
#[test]
fn a_hierarchy_that_cannot_be_read_is_said_so() {
    let fixture = Fixture::ubuntu();
    fixture.remove(MANAGER);
    let check = fixture.check("memory controller");
    assert_eq!(check.verdict, Verdict::Note);
    assert!(check.found.contains("cannot be told"), "{check:?}");
    fixture.remove("sys/fs/cgroup/cgroup.controllers");
    let check = fixture.check("cpu controller");
    assert_eq!(check.verdict, Verdict::Note);
    assert!(check.found.contains("cannot read"), "{check:?}");
}
