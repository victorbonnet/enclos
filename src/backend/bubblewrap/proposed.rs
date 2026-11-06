//! What the backend rests on that depends on the host or is still open: the
//! dependences compiling has on ADRs 0037 to 0039 and 0041, accepted, and on
//! design §15. The module's name dates from when those ADRs were proposed.

use serde::{Deserialize, Serialize};

use crate::backend::{Capabilities, Enforcement};
use crate::model::policy::Policy;
use crate::model::unenforced::{NotEnforcedHere, UnenforcedField};

/// The namespaces bubblewrap makes for each session, a service's included,
/// inside the namespace holder's user and network namespaces, which the
/// session joined first (ADR 0039): a user namespace nested in the holder's,
/// and PID and IPC namespaces of its own, but no network namespace, as the
/// sandbox's is shared. No user namespace is made inside
/// (`--disable-userns`). `--as-pid-1`: without it bubblewrap's own reaper is
/// PID 1, with no filter and no Landlock, which a member on a host with
/// neither Landlock nor Yama could attach to; so what bubblewrap runs
/// confines itself, stays PID 1 and reaps.
pub(super) const NAMESPACES: &[&str] = &[
    "--unshare-user",
    "--disable-userns",
    "--unshare-pid",
    "--as-pid-1",
    "--unshare-ipc",
    "--unshare-uts",
    "--unshare-cgroup-try",
];

/// ADR 0037: the Landlock ABI the compiled rules need in full: `IOCTL_DEV`
/// comes with 5, the scopes with 6.
pub const LANDLOCK_ABI_NEEDED: u32 = 6;

/// What a session got of Landlock on its kernel (ADR 0037).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Landlock {
    /// Every compiled rule.
    Full,
    /// The rights and scopes this ABI has, as a layer over the mounts; those
    /// it lacks are not held.
    Older { abi: u32 },
    /// None: the session runs without it, on the mounts alone.
    Missing,
}

impl Landlock {
    /// What a kernel with this ABI gives, if it has Landlock.
    pub fn on(abi: Option<u32>) -> Self {
        match abi {
            None => Self::Missing,
            Some(abi) if abi < LANDLOCK_ABI_NEEDED => Self::Older { abi },
            Some(_) => Self::Full,
        }
    }

    /// The line a session prints when it holds less than was compiled.
    pub fn notice(self) -> Option<String> {
        match self {
            Self::Full => None,
            Self::Older { abi } => Some(format!(
                "enclos: this kernel's Landlock has ABI {abi}, and the rules need {LANDLOCK_ABI_NEEDED}: applied what it has; the rights and scopes it lacks are not held"
            )),
            Self::Missing => Some(
                "enclos: this kernel has no Landlock: writes are held by the mounts alone, and any program that is mounted can run"
                    .to_owned(),
            ),
        }
    }
}

/// What the backend's capabilities depend on, found on the host (ADR 0037,
/// ADR 0038).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Host {
    /// The kernel's Landlock ABI, if it has Landlock.
    pub landlock_abi: Option<u32>,
    /// Why the host's cgroups do not hold a `memory` limit, if they do not.
    pub memory_not_held: Option<String>,
}

/// What the backend enforces on `host` (design §5's table). Files where the
/// kernel has Landlock with the ABI the rules need, and members everywhere,
/// read enforced: bubblewrap's escape probes read READY on GitHub's Ubuntu
/// runners and on a Raspberry Pi without Landlock, and `enclos policy test`
/// shows what holds on the host it runs on. Landlock missing or too old
/// leaves the file and program rows degraded (ADR 0037); an older ABI's
/// rights still apply. `listen = false` is not held (ADR 0041). `memory` is
/// not applied on a host whose cgroups do not hold it (ADR 0038).
pub fn capabilities(host: &Host) -> Capabilities {
    let partial = |note: &str| Enforcement::Partial {
        note: note.to_owned(),
    };
    let (fs, exec) = match host.landlock_abi {
        Some(abi) if abi >= LANDLOCK_ABI_NEEDED => (
            Enforcement::Enforced,
            "programs that are mounted, and Landlock's execute rules",
        ),
        Some(_) => (
            partial(
                "the mounts, and what this ABI has of Landlock, which `enclos policy test` probes; the rights it lacks are not held",
            ),
            "programs that are mounted; execute rules on an older ABI are open",
        ),
        None => (
            partial(
                "writes held by the mounts alone, with no second layer, which `enclos policy test` probes",
            ),
            "any program that is mounted: no Landlock execute rules",
        ),
    };
    Capabilities {
        fs,
        network: partial("through the proxy; `listen = false` is not held"),
        exec: partial(exec),
        resources: partial(&match &host.memory_not_held {
            None => "open_files on each process; memory and cpu on the sandbox's slice, its sessions and services together; cpu_seconds and file_size refused; not yet shown by the escape probes".to_owned(),
            Some(why) => format!(
                "open_files on each process; cpu on the sandbox's slice, its sessions and services together; memory not applied on this host, as {why}; cpu_seconds and file_size refused; not yet shown by the escape probes"
            ),
        }),
        members: Enforcement::Enforced,
    }
}

/// The fields of `policy` that `host` does not enforce, which a sandbox runs
/// with only once accepted (ADR 0038).
pub fn not_enforced_here(policy: &Policy, host: &Host) -> Vec<NotEnforcedHere> {
    match (&policy.resources.memory, &host.memory_not_held) {
        (Some(value), Some(why)) => vec![NotEnforcedHere {
            field: UnenforcedField::Memory,
            value: value.clone(),
            why: why.clone(),
        }],
        _ => Vec::new(),
    }
}

/// A policy field the compiled sandbox does not hold, and on which hosts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Unenforced {
    pub field: String,
    pub when: String,
    pub why: String,
}

/// The field `listen = false` sets, which no bubblewrap host holds.
pub(super) const LISTEN: &str = "network.listen";

/// The fields of `policy` that are not held, listed in the compiled output
/// (ADR 0038) for what stores and starts a sandbox to accept or refuse. An
/// `[exec]` section joins them once a policy can hold one (ADR 0037).
pub(super) fn unenforced(policy: &Policy) -> Vec<Unenforced> {
    let mut fields = Vec::new();
    // Declared, not refused (ADR 0041): the sandbox's network namespace
    // limits who is reached, not whether the sandbox listens.
    if !policy.net.listen {
        fields.push(Unenforced {
            field: LISTEN.to_owned(),
            when: "every host".to_owned(),
            why: "nothing refuses bind or listen in the sandbox's network namespace, which its sessions share".to_owned(),
        });
    }
    // ADR 0038.
    if policy.resources.memory.is_some() {
        fields.push(Unenforced {
            field: "resources.memory".to_owned(),
            when: "a host whose memory controller is missing or not delegated".to_owned(),
            why: "the sandbox's slice holds this limit, and needs that controller".to_owned(),
        });
    }
    fields
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A host with this Landlock ABI, whose cgroups hold `memory`.
    fn host(landlock_abi: Option<u32>) -> Host {
        Host {
            landlock_abi,
            memory_not_held: None,
        }
    }

    fn partial_note(area: &Enforcement) -> &str {
        match area {
            Enforcement::Partial { note } => note,
            other => panic!("{other:?}"),
        }
    }

    /// CLAUDE.md: what reads as enforced is what the escape probes showed:
    /// files with Landlock as the rules need it, and members on every host.
    /// Files where Landlock is missing or older stay partial and name the
    /// probes that show them on a host, and the rows no probe tries do too.
    #[test]
    fn what_the_escape_probes_show_reads_as_enforced_and_no_more() {
        let full = capabilities(&host(Some(LANDLOCK_ABI_NEEDED)));
        assert_eq!(full.fs, Enforcement::Enforced);
        for landlock_abi in [None, Some(1), Some(LANDLOCK_ABI_NEEDED - 1)] {
            let degraded = capabilities(&host(landlock_abi));
            assert!(
                partial_note(&degraded.fs).contains("`enclos policy test` probes"),
                "{landlock_abi:?}"
            );
        }
        for landlock_abi in [None, Some(LANDLOCK_ABI_NEEDED)] {
            let declared = capabilities(&host(landlock_abi));
            assert_eq!(declared.members, Enforcement::Enforced, "{landlock_abi:?}");
            assert!(matches!(declared.network, Enforcement::Partial { .. }));
            assert!(matches!(declared.exec, Enforcement::Partial { .. }));
            assert!(matches!(declared.resources, Enforcement::Partial { .. }));
        }
    }

    #[test]
    fn a_session_is_told_when_it_holds_less_than_was_compiled() {
        assert_eq!(Landlock::on(Some(LANDLOCK_ABI_NEEDED)), Landlock::Full);
        assert_eq!(Landlock::Full.notice(), None);
        let older = Landlock::on(Some(4));
        assert_eq!(older, Landlock::Older { abi: 4 });
        let said = older.notice().unwrap();
        assert!(said.contains("ABI 4"), "{said}");
        // No mount holds `IOCTL_DEV` or the scopes.
        assert!(said.contains("are not held"), "{said}");
        assert!(!said.contains("mounts"), "{said}");
        let missing = Landlock::on(None).notice().unwrap();
        assert!(missing.contains("mounts alone"), "{missing}");
    }

    #[test]
    fn landlock_missing_or_too_old_declares_the_weaker_controls() {
        let full = capabilities(&host(Some(LANDLOCK_ABI_NEEDED)));
        assert!(partial_note(&full.exec).contains("Landlock's execute rules"));
        let none = capabilities(&host(None));
        assert!(partial_note(&none.fs).contains("mounts alone"));
        assert!(partial_note(&none.fs).contains("no second layer"));
        assert!(partial_note(&none.exec).contains("no Landlock"));
    }

    /// What an older ABI has still applies, so "no second layer" would be
    /// false there; whether that takes in execute rules is open (design §15).
    #[test]
    fn an_older_landlock_abi_is_not_declared_as_no_landlock() {
        for landlock_abi in [Some(1), Some(LANDLOCK_ABI_NEEDED - 1)] {
            let older = capabilities(&host(landlock_abi));
            assert!(partial_note(&older.fs).contains("what this ABI has"));
            assert!(!partial_note(&older.fs).contains("no second layer"));
            assert!(partial_note(&older.exec).contains("older ABI"));
            assert!(!partial_note(&older.exec).contains("no Landlock"));
        }
    }

    #[test]
    fn the_limits_are_declared_with_memory_where_the_host_holds_it() {
        let held = capabilities(&host(None));
        let note = partial_note(&held.resources);
        assert!(
            note.contains("memory and cpu on the sandbox's slice"),
            "{note}"
        );
        assert!(
            note.contains("not yet shown by the escape probes"),
            "{note}"
        );
        let pi = Host {
            memory_not_held: Some("this host's kernel has no memory controller".to_owned()),
            ..host(None)
        };
        let declared = capabilities(&pi);
        let note = partial_note(&declared.resources);
        assert!(note.contains("memory not applied on this host"), "{note}");
        assert!(note.contains("no memory controller"), "{note}");
    }

    #[test]
    fn memory_is_not_enforced_only_where_set_and_the_host_does_not_hold_it() {
        let pi = Host {
            memory_not_held: Some("no memory controller".to_owned()),
            ..host(None)
        };
        let mut policy = Policy::default();
        assert!(not_enforced_here(&policy, &pi).is_empty());
        policy.resources.memory = Some("1G".to_owned());
        assert!(not_enforced_here(&policy, &host(None)).is_empty());
        let gaps = not_enforced_here(&policy, &pi);
        assert_eq!(gaps.len(), 1);
        assert_eq!(gaps[0].field, UnenforcedField::Memory);
        assert_eq!(gaps[0].value, "1G");
        assert_eq!(gaps[0].why, "no memory controller");
    }

    #[test]
    fn a_field_nothing_holds_is_listed() {
        let fields = |policy: &Policy| -> Vec<String> {
            unenforced(policy).into_iter().map(|u| u.field).collect()
        };
        let mut policy = Policy::default();
        assert_eq!(fields(&policy), ["network.listen"]);
        policy.net.listen = true;
        assert!(fields(&policy).is_empty());
        policy.resources.memory = Some("512M".to_owned());
        assert_eq!(fields(&policy), ["resources.memory"]);
    }
}
