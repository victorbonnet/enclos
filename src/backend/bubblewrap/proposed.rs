//! What the backend rests on that is still proposed: each dependence on
//! ADRs 0037 to 0040 is here, so that a change to one of them changes this
//! file alone.

use serde::{Deserialize, Serialize};

use crate::backend::{Capabilities, Enforcement};
use crate::model::policy::Policy;

/// ADR 0039: every session its own namespaces, a service's included. No
/// user namespace is made inside (`--disable-userns`).
pub(super) const NAMESPACES: &[&str] = &[
    "--unshare-user",
    "--disable-userns",
    "--unshare-pid",
    "--unshare-net",
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
                "enclos: this kernel's Landlock has ABI {abi}, and the rules need {LANDLOCK_ABI_NEEDED}: applied what it has, and the mounts hold the rest"
            )),
            Self::Missing => Some(
                "enclos: this kernel has no Landlock: writes are held by the mounts alone, and any program that is mounted can run"
                    .to_owned(),
            ),
        }
    }
}

/// What the backend's capabilities depend on, found on the host (ADR 0037).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Host {
    /// The kernel's Landlock ABI, if it has Landlock.
    pub landlock_abi: Option<u32>,
}

/// What the backend is built to enforce on `host` (design §5's table): a
/// declaration, which the escape probes have yet to show (M3-17). Landlock
/// missing or too old weakens the file and program rows (ADR 0037). `listen
/// = false` is not held (ADR 0040). Limits are M3-18's, the memory controller
/// included (ADR 0038).
pub fn capabilities(host: &Host) -> Capabilities {
    let full_landlock = host
        .landlock_abi
        .is_some_and(|abi| abi >= LANDLOCK_ABI_NEEDED);
    let (fs, exec) = match full_landlock {
        true => (
            Enforcement::Enforced,
            Enforcement::Partial {
                note: "programs that are mounted, and Landlock's execute rules".to_owned(),
            },
        ),
        false => (
            Enforcement::Partial {
                note: "writes held by the mounts alone, with no second layer".to_owned(),
            },
            Enforcement::Partial {
                note: "any program that is mounted: no Landlock execute rules".to_owned(),
            },
        ),
    };
    Capabilities {
        fs,
        network: Enforcement::Partial {
            note: "through the proxy; `listen = false` is not held".to_owned(),
        },
        exec,
        resources: Enforcement::Unsupported,
        members: Enforcement::Enforced,
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

    #[test]
    fn a_session_is_told_when_it_holds_less_than_was_compiled() {
        assert_eq!(Landlock::on(Some(LANDLOCK_ABI_NEEDED)), Landlock::Full);
        assert_eq!(Landlock::Full.notice(), None);
        let older = Landlock::on(Some(4));
        assert_eq!(older, Landlock::Older { abi: 4 });
        assert!(older.notice().unwrap().contains("ABI 4"));
        let missing = Landlock::on(None).notice().unwrap();
        assert!(missing.contains("mounts alone"), "{missing}");
    }

    #[test]
    fn landlock_missing_or_too_old_declares_the_weaker_controls() {
        let full = capabilities(&Host {
            landlock_abi: Some(LANDLOCK_ABI_NEEDED),
        });
        assert_eq!(full.fs, Enforcement::Enforced);
        assert!(partial_note(&full.exec).contains("Landlock's execute rules"));
        for landlock_abi in [None, Some(LANDLOCK_ABI_NEEDED - 1)] {
            let degraded = capabilities(&Host { landlock_abi });
            assert!(partial_note(&degraded.fs).contains("mounts alone"));
            assert!(partial_note(&degraded.exec).contains("no Landlock"));
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
