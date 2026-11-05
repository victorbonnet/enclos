//! The seccomp filter bubblewrap's sandbox runs under: the same for every
//! policy, so it takes no input.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::compile::strings;

/// Refused with `EPERM`: design §14's list, then the kernel module, reboot
/// and swap calls, and io_uring, whose operations seccomp does not see.
/// The same on every architecture: the program that applies the filter
/// skips a name its own lacks.
const SECCOMP_DENY: &[&str] = &[
    "keyctl",
    "add_key",
    "request_key",
    "bpf",
    "perf_event_open",
    "userfaultfd",
    "mount",
    "umount2",
    "pivot_root",
    "move_mount",
    "open_tree",
    "fsopen",
    "fsconfig",
    "fsmount",
    "fspick",
    "mount_setattr",
    "setns",
    "kexec_load",
    "kexec_file_load",
    "init_module",
    "finit_module",
    "delete_module",
    "reboot",
    "swapon",
    "swapoff",
    "acct",
    "quotactl",
    "quotactl_fd",
    "ioperm",
    "iopl",
    "open_by_handle_at",
    "uselib",
    "io_uring_setup",
    "io_uring_enter",
    "io_uring_register",
];

/// `ioctl` requests refused, compared on their low 32 bits as the kernel does.
const SECCOMP_IOCTL: &[(&str, u64)] = &[("TIOCLINUX", 0x541C), ("TIOCSTI", 0x5412)];

/// Namespace flags refused in `unshare` and `clone`.
const CLONE_NEW: &[(&str, u64)] = &[
    ("CLONE_NEWCGROUP", 0x0200_0000),
    ("CLONE_NEWIPC", 0x0800_0000),
    ("CLONE_NEWNET", 0x4000_0000),
    ("CLONE_NEWNS", 0x0002_0000),
    ("CLONE_NEWPID", 0x2000_0000),
    ("CLONE_NEWTIME", 0x0000_0080),
    ("CLONE_NEWUSER", 0x1000_0000),
    ("CLONE_NEWUTS", 0x0400_0000),
];

/// `clone3` holds its flags in memory seccomp cannot read: `ENOSYS` makes
/// the C library fall back to `clone`.
const SECCOMP_ENOSYS: &[&str] = &["clone3"];

/// The only families `socket` may open. `--unshare-net` holds these, and may
/// not hold others: `AF_VSOCK` reaches a host's hypervisor past the proxy, and
/// `AF_ALG` and the like are kernel surface nothing here uses. What is listed
/// is what ADR 0004's "no network except a Unix socket" leaves, with loopback
/// and netlink, which C libraries and Chromium ask for.
const SOCKET_FAMILIES: &[(&str, u64)] = &[
    ("AF_INET", 2),
    ("AF_INET6", 10),
    ("AF_NETLINK", 16),
    ("AF_UNIX", 1),
];

/// What the filter refuses; anything else is allowed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeccompFilter {
    /// What a refused call returns.
    pub errno: String,
    /// The calls refused.
    pub deny: Vec<String>,
    /// The `ioctl` requests refused, by name.
    pub ioctl: BTreeMap<String, u64>,
    /// The namespace flags refused in `unshare` and `clone`.
    pub clone_flags: BTreeMap<String, u64>,
    /// The calls that return `ENOSYS`, so the C library falls back.
    pub enosys: Vec<String>,
    /// The families `socket` may open; any other is refused with `errno`.
    pub socket_families: BTreeMap<String, u64>,
}

/// The filter every compiled sandbox holds.
pub(super) fn filter() -> SeccompFilter {
    SeccompFilter {
        errno: "EPERM".to_owned(),
        deny: strings(SECCOMP_DENY),
        ioctl: named(SECCOMP_IOCTL),
        clone_flags: named(CLONE_NEW),
        enosys: strings(SECCOMP_ENOSYS),
        socket_families: named(SOCKET_FAMILIES),
    }
}

fn named(values: &[(&str, u64)]) -> BTreeMap<String, u64> {
    values.iter().map(|(n, v)| ((*n).to_owned(), *v)).collect()
}
