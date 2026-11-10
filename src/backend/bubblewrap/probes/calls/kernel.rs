//! Calls the kernel answers past the sandbox where nothing refuses them: a
//! socket family, the terminal, another process, namespaces and mounts.

use std::path::Path;

use super::{End, UNPREPARED, answered, call};
use crate::probes::{OwnReading, Probe, sh_quote};

/// Refused by the seccomp filter, which answers `EPERM` before the kernel
/// looks at the call's arguments.
pub(super) const FILTERED: OwnReading = OwnReading {
    label: "refused by the filter: EPERM",
    read: |succeeded, output| answered(&["EPERM"], &[], "", succeeded, output),
    when_control_fails: Some(
        "outside the sandbox, the call did not get as far as the sandbox refuses it",
    ),
};

/// Opens an `AF_VSOCK` socket, which no network namespace holds: refused by
/// the filter. Outside, the kernel opens one, or says it has no such family.
pub(crate) fn vsock() -> Probe {
    call(
        "vsock",
        "open an AF_VSOCK socket, which reaches past the network namespace".to_owned(),
        |end| {
            format!(
                "my $w = word(socket(my $s, 40, SOCK_STREAM, 0)); {}",
                end.perl()
            )
        },
        &[],
        FILTERED,
        &["ok", "EAFNOSUPPORT"],
    )
}

/// Pushes a character into the input of a terminal the program opens and
/// makes its own, as a session would type into the terminal it runs in:
/// refused by the filter. Outside, the kernel takes it, or refuses it
/// itself where `dev.tty.legacy_tiocsti` is off (`EIO`). perl's `ioctl`
/// may write to its last argument, so each is a variable.
pub(crate) fn tiocsti() -> Probe {
    let code = |end: End| {
        format!(
            r#"use POSIX ();
open(my $m, "+<", "/dev/ptmx") or do {UNPREPARED};
my $unlock = pack("i", 0); ioctl($m, 0x40045431, $unlock) or do {UNPREPARED};
my $n = pack("i", 0); ioctl($m, 0x80045430, $n) or do {UNPREPARED};
my $pid = fork(); defined($pid) or do {UNPREPARED};
if ($pid == 0) {{ POSIX::setsid(); open(my $t, "+<", "/dev/pts/" . unpack("i", $n)) or do {UNPREPARED};
my $typed = "x"; my $w = word(ioctl($t, 0x5412, $typed)); {} }}
waitpid($pid, 0); exit($? >> 8);"#,
            end.perl()
        )
    };
    call(
        "terminals",
        "type into its terminal (TIOCSTI)".to_owned(),
        code,
        &[],
        FILTERED,
        &["ok", "EIO"],
    )
}

/// The system calls perl has no function for, by number on this
/// architecture.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Numbers {
    pub(super) ptrace: u32,
    pub(super) unshare: u32,
    pub(super) mount: u32,
}

impl Numbers {
    /// This host's, if enclos knows its architecture's.
    pub(crate) fn here() -> Option<Numbers> {
        match std::env::consts::ARCH {
            "x86_64" => Some(Numbers {
                ptrace: 101,
                unshare: 272,
                mount: 165,
            }),
            "aarch64" => Some(Numbers {
                ptrace: 117,
                unshare: 97,
                mount: 40,
            }),
            _ => None,
        }
    }

    /// Attaches to process `pid` with `PTRACE_SEIZE`, which stops nothing,
    /// and is undone as the program exits. A process outside the session's
    /// PID namespace is not there (`ESRCH`); outside, the kernel finds it,
    /// and attaches or refuses (`EPERM`, as Yama does to a process that is
    /// not a child).
    pub(crate) fn ptrace(self, pid: u32) -> Probe {
        call(
            "ptrace",
            "attach to a process outside the sandbox".to_owned(),
            |end| {
                format!(
                    "my $w = word(syscall({}, 0x4206, $ARGV[0] + 0, 0, 0) == 0); {}",
                    self.ptrace,
                    end.perl()
                )
            },
            &[pid.to_string()],
            OUT_OF_SIGHT,
            &["ok", "EPERM"],
        )
    }

    /// Makes a user namespace: refused by the filter (`EPERM`), or by
    /// bubblewrap's `--disable-userns` without it (`ENOSPC`).
    pub(crate) fn user_namespace(self) -> Probe {
        call(
            "user namespace",
            "make a user namespace".to_owned(),
            |end| {
                format!(
                    "my $w = word(syscall({}, 0x10000000) == 0); {}",
                    self.unshare,
                    end.perl()
                )
            },
            &[],
            NO_NAMESPACE,
            &["ok"],
        )
    }

    /// Mounts a tmpfs on `missing`, a path that is nowhere: the filter
    /// refuses the call before the kernel looks the path up, which it does
    /// first outside (`ENOENT`), before it asks for a capability. perl's
    /// `syscall` takes no constant string, so each is a variable.
    pub(crate) fn mount(self, missing: &Path) -> Probe {
        call(
            "mounts",
            "mount a filesystem".to_owned(),
            |end| {
                format!(
                    r#"my ($source, $at, $kind) = ("none", $ARGV[0], "tmpfs");
my $w = word(syscall({}, $source, $at, $kind, 0, 0) == 0); {}"#,
                    self.mount,
                    end.perl()
                )
            },
            &[sh_quote(missing)],
            FILTERED,
            &["ENOENT"],
        )
    }
}

/// A process the session's PID namespace does not hold.
const OUT_OF_SIGHT: OwnReading = OwnReading {
    label: "not there: ESRCH",
    read: |succeeded, output| answered(&["ESRCH"], &[], "", succeeded, output),
    when_control_fails: Some("outside the sandbox, ptrace did not find the process either"),
};

const NO_NAMESPACE: OwnReading = OwnReading {
    label: "refused: EPERM or ENOSPC",
    read: |succeeded, output| answered(&["EPERM", "ENOSPC"], &[], "", succeeded, output),
    when_control_fails: Some("outside the sandbox, this user may not make one either"),
};
