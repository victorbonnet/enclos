//! The compiled Landlock rules as the crate's rights, and applying them.
//! Where the kernel has none or an older ABI, the crate's best effort leaves
//! out what it lacks and [`outcome`] says what was held (ADR 0037).

use std::io;

use landlock::{
    ABI, Access, AccessFs, BitFlags, CompatLevel, Compatible, LandlockStatus, PathBeneath, PathFd,
    Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetStatus, Scope,
};

use super::InsideError;
use crate::backend::bubblewrap::compile::LandlockRules;
use crate::backend::bubblewrap::proposed::{LANDLOCK_ABI_NEEDED, Landlock};

/// The ABI of [`LANDLOCK_ABI_NEEDED`], the rights the rules are written for.
const NEEDED: ABI = ABI::V6;

/// One path and what is granted beneath it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Grant {
    pub path: String,
    pub access: BitFlags<AccessFs>,
}

fn read() -> BitFlags<AccessFs> {
    AccessFs::ReadFile | AccessFs::ReadDir
}

fn write() -> BitFlags<AccessFs> {
    AccessFs::WriteFile
        | AccessFs::RemoveDir
        | AccessFs::RemoveFile
        | AccessFs::MakeDir
        | AccessFs::MakeReg
        | AccessFs::MakeSock
        | AccessFs::MakeFifo
        | AccessFs::MakeSym
        | AccessFs::Refer
        | AccessFs::Truncate
}

/// Each compiled list with its rights, as `prototype/m3/inside.py` gives them.
pub(super) fn grants(rules: &LandlockRules) -> Vec<Grant> {
    let lists = [
        (&rules.read, read()),
        (&rules.execute, read() | AccessFs::Execute),
        (&rules.write, read() | write()),
        (
            &rules.devices,
            read() | AccessFs::WriteFile | AccessFs::Truncate | AccessFs::IoctlDev,
        ),
        (
            &rules.proc_write,
            read() | AccessFs::WriteFile | AccessFs::Truncate,
        ),
    ];
    lists
        .into_iter()
        .flat_map(|(paths, access)| {
            paths.iter().map(move |path| Grant {
                path: path.clone(),
                access,
            })
        })
        .collect()
}

pub(super) fn scopes(rules: &LandlockRules) -> Result<BitFlags<Scope>, InsideError> {
    rules
        .scoped
        .iter()
        .try_fold(BitFlags::empty(), |scopes, name| match name.as_str() {
            "abstract_unix_socket" => Ok(scopes | Scope::AbstractUnixSocket),
            "signal" => Ok(scopes | Scope::Signal),
            other => Err(InsideError::Scope(other.to_owned())),
        })
}

/// What a rule on something that is not a folder may hold: the kernel
/// refuses a folder's rights on a file.
fn for_kind(access: BitFlags<AccessFs>, is_folder: bool) -> BitFlags<AccessFs> {
    match is_folder {
        true => access,
        false => access & AccessFs::from_file(NEEDED),
    }
}

/// The kernel's ABI, by its own answer: the crate caps what it reports at
/// the ABIs it knows, and tells a newer one apart.
fn kernel_abi(status: LandlockStatus) -> Option<u32> {
    match status {
        LandlockStatus::NotEnabled | LandlockStatus::NotImplemented => None,
        LandlockStatus::Available {
            effective_abi,
            kernel_abi,
        } => Some(kernel_abi.unwrap_or(effective_abi as i32).unsigned_abs()),
    }
}

/// What was held, from what the kernel answered. A kernel with every right
/// that held less is refused: it is no case ADR 0037 runs without.
pub(super) fn outcome(
    kernel: LandlockStatus,
    ruleset: RulesetStatus,
) -> Result<Landlock, InsideError> {
    let landlock = Landlock::on(kernel_abi(kernel));
    match (landlock, ruleset) {
        (Landlock::Full, RulesetStatus::FullyEnforced)
        | (Landlock::Older { .. } | Landlock::Missing, _) => Ok(landlock),
        (Landlock::Full, other) => Err(InsideError::Landlock(format!(
            "the kernel has ABI {LANDLOCK_ABI_NEEDED} or newer, and the rules came out {other:?}"
        ))),
    }
}

/// Restricts this thread and what it starts, for good. A path that is not
/// there has no rule, as `/lib32` on arm64.
pub(super) fn apply(grants: &[Grant], scopes: BitFlags<Scope>) -> Result<Landlock, InsideError> {
    let failed = |e: &dyn std::fmt::Display| InsideError::Landlock(e.to_string());
    let mut ruleset = Ruleset::default()
        .set_compatibility(CompatLevel::BestEffort)
        .handle_access(AccessFs::from_all(NEEDED))
        .map_err(|e| failed(&e))?
        .scope(scopes)
        .map_err(|e| failed(&e))?
        .create()
        .map_err(|e| failed(&e))?;
    for grant in grants {
        let is_folder = match std::fs::metadata(&grant.path) {
            Ok(found) => found.is_dir(),
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(failed(&format!("{}: {e}", grant.path))),
        };
        let path = PathFd::new(&grant.path).map_err(|e| failed(&e))?;
        ruleset = ruleset
            .add_rule(PathBeneath::new(path, for_kind(grant.access, is_folder)))
            .map_err(|e| failed(&e))?;
    }
    let status = ruleset.restrict_self().map_err(|e| failed(&e))?;
    outcome(status.landlock, status.ruleset)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn compiled() -> LandlockRules {
        let words = |list: &[&str]| list.iter().map(|w| (*w).to_owned()).collect();
        LandlockRules {
            read: words(&["/"]),
            execute: words(&["/usr", "/home/alice"]),
            write: words(&["/home/alice", "/tmp"]),
            devices: words(&["/dev"]),
            proc_write: words(&["/proc"]),
            scoped: words(&["abstract_unix_socket", "signal"]),
        }
    }

    fn access_of(path: &str) -> Vec<BitFlags<AccessFs>> {
        grants(&compiled())
            .into_iter()
            .filter(|g| g.path == path)
            .map(|g| g.access)
            .collect()
    }

    /// `prototype/m3/inside.py`'s numbers, shown on Landlock's ABI 8.
    #[test]
    fn each_list_has_the_prototypes_rights() {
        assert_eq!(access_of("/")[0].bits(), 0b1100);
        assert_eq!(access_of("/usr")[0].bits(), 0b1101);
        assert_eq!(access_of("/tmp")[0].bits(), 0x77BE);
        assert_eq!(access_of("/dev")[0].bits(), 0xC00E);
        assert_eq!(access_of("/proc")[0].bits(), 0x400E);
    }

    #[test]
    fn the_home_runs_and_writes_a_temporary_place_only_writes() {
        let home = access_of("/home/alice");
        assert_eq!(home.len(), 2);
        assert!(home[0].contains(AccessFs::Execute));
        assert!(home[1].contains(AccessFs::MakeReg));
        assert!(!access_of("/tmp")[0].contains(AccessFs::Execute));
    }

    #[test]
    fn nothing_a_rule_grants_is_outside_what_is_handled() {
        for grant in grants(&compiled()) {
            assert!(
                AccessFs::from_all(NEEDED).contains(grant.access),
                "{grant:?}"
            );
        }
    }

    #[test]
    fn every_right_of_the_needed_abi_is_handled() {
        assert_eq!(AccessFs::from_all(NEEDED).bits(), 0xFFFF);
    }

    #[test]
    fn a_rule_on_a_file_keeps_a_files_rights_only() {
        let access = read() | write();
        let kept = for_kind(access, false);
        assert!(kept.contains(AccessFs::WriteFile | AccessFs::ReadFile));
        assert!(!kept.contains(AccessFs::ReadDir));
        assert!(!kept.contains(AccessFs::MakeReg));
        assert_eq!(for_kind(access, true), access);
    }

    #[test]
    fn the_scopes_are_read_by_name_and_another_is_refused() {
        assert_eq!(
            scopes(&compiled()).unwrap(),
            Scope::AbstractUnixSocket | Scope::Signal
        );
        let mut rules = compiled();
        rules.scoped.push("thirds".to_owned());
        assert!(scopes(&rules).unwrap_err().to_string().contains("thirds"));
    }

    fn available(abi: ABI) -> LandlockStatus {
        LandlockStatus::Available {
            effective_abi: abi,
            kernel_abi: None,
        }
    }

    #[test]
    fn a_kernel_without_landlock_runs_on_the_mounts_alone() {
        for kernel in [LandlockStatus::NotImplemented, LandlockStatus::NotEnabled] {
            assert_eq!(
                outcome(kernel, RulesetStatus::NotEnforced).unwrap(),
                Landlock::Missing
            );
        }
    }

    #[test]
    fn an_older_abi_applies_what_it_has_and_says_so() {
        let older = outcome(available(ABI::V4), RulesetStatus::PartiallyEnforced).unwrap();
        assert_eq!(older, Landlock::Older { abi: 4 });
    }

    #[test]
    fn the_abi_needed_or_newer_holds_every_rule() {
        for kernel in [
            available(ABI::V6),
            available(ABI::V9),
            LandlockStatus::Available {
                effective_abi: ABI::V9,
                kernel_abi: Some(12),
            },
        ] {
            assert_eq!(
                outcome(kernel, RulesetStatus::FullyEnforced).unwrap(),
                Landlock::Full
            );
        }
    }

    #[test]
    fn a_kernel_with_every_right_that_held_less_is_refused() {
        let held_less = outcome(available(ABI::V8), RulesetStatus::PartiallyEnforced);
        assert!(
            matches!(held_less, Err(InsideError::Landlock(_))),
            "{held_less:?}"
        );
    }

    #[test]
    fn the_needed_abi_is_the_one_the_declared_capabilities_use() {
        assert_eq!(NEEDED as u32, LANDLOCK_ABI_NEEDED);
    }
}
