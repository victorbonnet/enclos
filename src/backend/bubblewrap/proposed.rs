//! What the backend rests on that is still proposed: each dependence on
//! ADRs 0037 to 0040 is here, so that a change to one of them changes this
//! file alone.

use serde::{Deserialize, Serialize};

use crate::backend::{Capabilities, Enforcement};
use crate::model::policy::Policy;

/// ADR 0039: every session its own namespaces, a service's included. No
/// user namespace is made inside (`--disable-userns`). `--as-pid-1`: without
/// it bubblewrap's own reaper is PID 1, with no filter and no Landlock, and a
/// member on a host with neither Landlock nor Yama could attach to it and run
/// what the filter refuses. So what bubblewrap runs must confine itself, then
/// stay as PID 1, fork the command and reap (M3-14).
pub(super) const NAMESPACES: &[&str] = &[
    "--unshare-user",
    "--disable-userns",
    "--unshare-pid",
    "--as-pid-1",
    "--unshare-net",
    "--unshare-ipc",
    "--unshare-uts",
    "--unshare-cgroup-try",
];

/// ADR 0037: the Landlock ABI the compiled rules need in full: `IOCTL_DEV`
/// comes with 5, the scopes with 6.
pub const LANDLOCK_ABI_NEEDED: u32 = 6;

/// What the backend's capabilities depend on, found on the host (ADR 0037).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Host {
    /// The kernel's Landlock ABI, if it has Landlock.
    pub landlock_abi: Option<u32>,
}

/// What the backend is built to enforce on `host` (design §5's table): a
/// declaration, which the escape probes have yet to show, so nothing reads
/// as enforced before M3-17 passes. Landlock missing or too old weakens the
/// file and program rows (ADR 0037): M3-14 applies what an older ABI has.
/// `listen = false` is not held (ADR 0040). Limits are M3-18's, the memory
/// controller included (ADR 0038).
pub fn capabilities(host: &Host) -> Capabilities {
    let (fs, exec) = match host.landlock_abi {
        Some(abi) if abi >= LANDLOCK_ABI_NEEDED => (
            "the mounts and Landlock, unproven until M3-17",
            "programs that are mounted, and Landlock's execute rules",
        ),
        Some(_) => (
            "the mounts, and what this ABI has of Landlock, unproven until M3-17",
            "programs that are mounted; execute rules on an older ABI are open",
        ),
        None => (
            "writes held by the mounts alone, with no second layer, unproven until M3-17",
            "any program that is mounted: no Landlock execute rules",
        ),
    };
    let partial = |note: &str| Enforcement::Partial {
        note: note.to_owned(),
    };
    Capabilities {
        fs: partial(fs),
        network: partial("through the proxy; `listen = false` is not held"),
        exec: partial(exec),
        resources: Enforcement::Unsupported,
        members: partial("a session's cgroup, unproven until M3-17"),
    }
}

/// A policy field the compiled sandbox does not hold, and on which hosts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Unenforced {
    pub field: String,
    pub when: String,
    pub why: String,
}

/// The fields of `policy` that are not held, listed in the compiled output
/// (ADR 0038) for what stores and starts a sandbox to accept or refuse. An
/// `[exec]` section joins them once a policy can hold one (ADR 0037).
pub(super) fn unenforced(policy: &Policy) -> Vec<Unenforced> {
    let mut fields = Vec::new();
    // ADR 0040: bind and listen stay open, and a network namespace of its
    // own limits who is reached, not whether the sandbox listens.
    if !policy.net.listen {
        fields.push(Unenforced {
            field: "network.listen".to_owned(),
            when: "every host".to_owned(),
            why: "nothing refuses bind or listen in a session's own network namespace".to_owned(),
        });
    }
    // ADR 0038.
    if policy.resources.memory.is_some() {
        fields.push(Unenforced {
            field: "resources.memory".to_owned(),
            when: "a host whose memory controller is missing or not delegated".to_owned(),
            why: "a session's cgroup holds this limit, and needs that controller".to_owned(),
        });
    }
    fields
}

#[cfg(test)]
mod tests {
    use super::*;

    fn partial_note(area: &Enforcement) -> &str {
        match area {
            Enforcement::Partial { note } => note,
            other => panic!("{other:?}"),
        }
    }

    /// CLAUDE.md: nothing reads as enforced before a probe shows it.
    #[test]
    fn no_area_reads_as_enforced_before_the_escape_probes_pass() {
        for landlock_abi in [
            None,
            Some(1),
            Some(LANDLOCK_ABI_NEEDED - 1),
            Some(LANDLOCK_ABI_NEEDED),
        ] {
            let declared = capabilities(&Host { landlock_abi });
            assert!(
                partial_note(&declared.fs).contains("M3-17"),
                "{landlock_abi:?}"
            );
            assert!(
                partial_note(&declared.members).contains("M3-17"),
                "{landlock_abi:?}"
            );
        }
    }

    #[test]
    fn landlock_missing_or_too_old_declares_the_weaker_controls() {
        let full = capabilities(&Host {
            landlock_abi: Some(LANDLOCK_ABI_NEEDED),
        });
        assert!(partial_note(&full.exec).contains("Landlock's execute rules"));
        let none = capabilities(&Host { landlock_abi: None });
        assert!(partial_note(&none.fs).contains("mounts alone"));
        assert!(partial_note(&none.fs).contains("no second layer"));
        assert!(partial_note(&none.exec).contains("no Landlock"));
    }

    /// M3-14 applies what an older ABI has, so "no second layer" would be
    /// false there; whether that takes in execute rules is open (design §15).
    #[test]
    fn an_older_landlock_abi_is_not_declared_as_no_landlock() {
        for landlock_abi in [Some(1), Some(LANDLOCK_ABI_NEEDED - 1)] {
            let older = capabilities(&Host { landlock_abi });
            assert!(partial_note(&older.fs).contains("what this ABI has"));
            assert!(!partial_note(&older.fs).contains("no second layer"));
            assert!(partial_note(&older.exec).contains("older ABI"));
            assert!(!partial_note(&older.exec).contains("no Landlock"));
        }
    }

    #[test]
    fn no_limit_is_declared_before_the_backend_sets_one() {
        let declared = capabilities(&Host { landlock_abi: None });
        assert_eq!(declared.resources, Enforcement::Unsupported);
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
