//! Checking a resolved policy before it is stored (design §5, §7).
//!
//! A policy may not grant writes to enclos's own folders except the sandbox's
//! own home, including through a broad path or a symlink, may not drop the
//! built-in read-deny entries, and its network entries must be ones the proxy
//! can enforce. Each of these is a refusal (exit 2); an entry that does not
//! parse is malformed (exit 1).

use std::path::PathBuf;

use super::file::PolicyFile;
use super::paths::{PathContext, is_within, real_path};
use super::{PolicyError, Problem};
use crate::model::policy::Policy;
use crate::net::addr::{AddrClass, classify};
use crate::net::host::{AllowEntry, HostPattern, canonical_private};

/// What a policy is checked against.
#[derive(Debug, Clone)]
pub struct ValidationContext {
    pub paths: PathContext,
    /// The enclos data and config folders.
    pub protected: Vec<PathBuf>,
}

pub fn validate(policy: &Policy, ctx: &ValidationContext) -> Result<(), PolicyError> {
    let mut problems = Vec::new();
    check_writes(policy, ctx, &mut problems);
    for entry in &policy.fs.read_deny {
        match ctx.paths.expand(entry) {
            Ok(path) => {
                check_writable_in_a_profile("read_deny", entry, &real_path(&path), &mut problems)
            }
            Err(e) => problems.push(Problem::Malformed(format!("filesystem.read_deny: {e}"))),
        }
    }
    check_default_denies(policy, &mut problems);
    check_network(policy, &mut problems);
    if problems.is_empty() {
        Ok(())
    } else {
        Err(PolicyError::Invalid { problems })
    }
}

fn check_writes(policy: &Policy, ctx: &ValidationContext, problems: &mut Vec<Problem>) {
    let own_home = real_path(&ctx.paths.sandbox_home);
    let protected: Vec<PathBuf> = ctx.protected.iter().map(|p| real_path(p)).collect();
    for entry in &policy.fs.write {
        let path = match ctx.paths.expand(entry) {
            Ok(path) => real_path(&path),
            Err(e) => {
                problems.push(Problem::Malformed(format!("filesystem.write: {e}")));
                continue;
            }
        };
        check_writable_in_a_profile("write", entry, &path, problems);
        for root in &protected {
            let contains_root = is_within(root, &path);
            let inside_root = is_within(&path, root) && !is_within(&path, &own_home);
            if contains_root || inside_root {
                problems.push(Problem::Refused(format!(
                    "filesystem.write: `{entry}` ({}) would let the sandbox write enclos's own files in {}; only the sandbox's home is writable there",
                    path.display(),
                    root.display()
                )));
            }
        }
    }
}

/// A path the compiled policy can hold as is: a double quote or a backslash
/// would change a Seatbelt rule, so the compiler refuses them, and a policy
/// that holds one could never start its sandbox. The backend cannot enforce
/// such a path, so it is refused (ADR 0009).
fn check_writable_in_a_profile(
    list: &str,
    entry: &str,
    path: &std::path::Path,
    problems: &mut Vec<Problem>,
) {
    match path.to_str() {
        Some(text) if !text.contains(['"', '\\']) => {}
        Some(text) => problems.push(Problem::Refused(format!(
            "filesystem.{list}: `{entry}` ({text}) holds a double quote or a backslash, which enclos cannot put in a sandbox profile"
        ))),
        None => problems.push(Problem::Refused(format!(
            "filesystem.{list}: `{entry}` ({}) is not valid UTF-8",
            path.display()
        ))),
    }
}

/// A layer that writes `read_deny = [...]` replaces the list below it; it may
/// not leave out what the built-in defaults hide (design §5).
fn check_default_denies(policy: &Policy, problems: &mut Vec<Problem>) {
    let mut defaults = Policy::default();
    PolicyFile::parse("built-in defaults", super::DEFAULTS)
        .expect("the built-in defaults parse")
        .apply(&mut defaults);
    let dropped: Vec<&str> = defaults
        .fs
        .read_deny
        .iter()
        .filter(|entry| !policy.fs.read_deny.contains(entry))
        .map(String::as_str)
        .collect();
    if !dropped.is_empty() {
        problems.push(Problem::Refused(format!(
            "filesystem.read_deny leaves out paths enclos always hides: {}; add your own with read_deny_add instead",
            dropped.join(", ")
        )));
    }
}

fn check_network(policy: &Policy, problems: &mut Vec<Problem>) {
    let mut allowed = Vec::new();
    for entry in &policy.net.allow {
        match AllowEntry::parse(entry) {
            Ok(parsed) => allowed.push(parsed),
            Err(e) => problems.push(Problem::entry(format!("network.allow: `{entry}`"), e)),
        }
    }
    let mut private = Vec::new();
    for entry in &policy.net.private {
        let host = match canonical_private(entry) {
            Ok(host) => host,
            Err(e) => {
                problems.push(Problem::entry(format!("network.private: `{entry}`"), e));
                continue;
            }
        };
        // An opt-in that unlocks nothing: a mistake in how the policy is
        // written, not a grant enclos refuses.
        if !allowed.iter().any(|a| a.host_text() == host) {
            problems.push(Problem::Malformed(format!(
                "network.private: `{entry}` must also be in network.allow; the opt-in only unlocks private addresses for allowed hosts"
            )));
        }
        private.push(host);
    }
    for entry in &allowed {
        if let HostPattern::Ip(ip) = entry.host
            && classify(ip) == AddrClass::Private
            && !private.contains(&ip.to_string())
        {
            problems.push(Problem::Refused(format!(
                "network.allow: {ip} is a private address; add it to network.private as well to opt in"
            )));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixture {
        _dir: tempfile::TempDir,
        ctx: ValidationContext,
    }

    fn fixture() -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().canonicalize().unwrap();
        let enclos = base.join("alice/.enclos");
        let sandbox_home = enclos.join("sandboxes/home/home");
        std::fs::create_dir_all(&sandbox_home).unwrap();
        std::fs::create_dir_all(base.join("alice/work")).unwrap();
        let ctx = ValidationContext {
            paths: PathContext {
                user_home: base.join("alice"),
                sandbox_home,
            },
            protected: vec![enclos],
        };
        Fixture { _dir: dir, ctx }
    }

    fn policy(write: &[&str], allow: &[&str], private: &[&str]) -> Policy {
        let mut p = Policy::default();
        PolicyFile::parse("built-in defaults", crate::policy::DEFAULTS)
            .unwrap()
            .apply(&mut p);
        p.fs.write = write.iter().map(|s| s.to_string()).collect();
        p.net.allow = allow.iter().map(|s| s.to_string()).collect();
        p.net.private = private.iter().map(|s| s.to_string()).collect();
        p
    }

    fn checked(p: &Policy, f: &Fixture) -> Vec<Problem> {
        match validate(p, &f.ctx) {
            Ok(()) => Vec::new(),
            Err(PolicyError::Invalid { problems }) => problems,
            Err(e) => panic!("{e}"),
        }
    }

    fn problems(p: &Policy, f: &Fixture) -> Vec<String> {
        checked(p, f).iter().map(Problem::to_string).collect()
    }

    #[test]
    fn the_sandbox_home_and_a_workspace_are_writable() {
        let f = fixture();
        assert!(problems(&policy(&["{home}", "{tmp}", "~/work"], &[], &[]), &f).is_empty());
    }

    #[test]
    fn what_a_policy_grants_or_reaches_is_refused_and_what_does_not_parse_is_malformed() {
        let f = fixture();
        let mut dropped = policy(&[], &[], &[]);
        dropped.fs.read_deny.retain(|e| e != "~/.ssh");
        for (case, p) in [
            ("loopback", policy(&[], &["127.0.0.1"], &[])),
            ("link-local", policy(&[], &["169.254.169.254"], &[])),
            ("localhost", policy(&[], &["localhost"], &[])),
            ("private without opt-in", policy(&[], &["10.0.0.5"], &[])),
            ("public suffix", policy(&[], &["*.co.uk"], &[])),
            ("enclos's own files", policy(&["~/.enclos"], &[], &[])),
            ("not enforceable", policy(&["~/work/a\\b"], &[], &[])),
            ("default deny dropped", dropped),
        ] {
            let found = checked(&p, &f);
            assert_eq!(found.len(), 1, "{case}: {found:?}");
            assert!(found[0].is_refused(), "{case}: {found:?}");
            let err = validate(&p, &f.ctx).unwrap_err();
            assert!(err.is_refused(), "{case}: {err}");
            assert!(err.to_string().starts_with("refused by policy:"), "{err}");
        }
        for (case, p) in [
            ("bad destination", policy(&[], &["exa mple.com"], &[])),
            ("bad port", policy(&[], &["example.com:0"], &[])),
            ("relative path", policy(&["work"], &[], &[])),
            ("opt-in for nothing", policy(&[], &[], &["printer.lan"])),
        ] {
            let found = checked(&p, &f);
            assert_eq!(found.len(), 1, "{case}: {found:?}");
            assert!(!found[0].is_refused(), "{case}: {found:?}");
            assert!(!validate(&p, &f.ctx).unwrap_err().is_refused(), "{case}");
        }
        // One malformed entry makes the whole list an error: what it means is
        // not known until it is fixed.
        let mixed = policy(&[], &["127.0.0.1", "exa mple.com"], &[]);
        let err = validate(&mixed, &f.ctx).unwrap_err();
        assert!(!err.is_refused(), "{err}");
        assert!(
            err.to_string().starts_with("the policy is not valid:"),
            "{err}"
        );
    }

    #[test]
    fn writes_to_enclos_files_are_refused_however_written() {
        let f = fixture();
        std::os::unix::fs::symlink(
            f.ctx.protected[0].clone(),
            f.ctx.paths.user_home.join("work/link"),
        )
        .unwrap();
        // A link to a sandbox folder that does not exist yet.
        std::os::unix::fs::symlink(
            f.ctx.protected[0].join("sandboxes/later"),
            f.ctx.paths.user_home.join("work/dangling"),
        )
        .unwrap();
        for entry in [
            "~",
            "~/.enclos",
            "~/.enclos/state.db",
            "~/.enclos/sandboxes/other",
            "~/work/link",
            "~/work/dangling",
            "~/work/dangling/inner",
            "~/work/../.enclos",
            "/",
        ] {
            let found = problems(&policy(&[entry], &[], &[]), &f);
            assert_eq!(found.len(), 1, "{entry}: {found:?}");
            assert!(
                found[0].contains("enclos's own files"),
                "{entry}: {found:?}"
            );
        }
    }

    #[test]
    fn paths_a_sandbox_profile_cannot_hold_are_refused_when_stored() {
        let f = fixture();
        let found = problems(&policy(&["~/work/\"Q3\" report"], &[], &[]), &f);
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].contains("double quote"), "{found:?}");
        let mut p = policy(&[], &[], &[]);
        p.fs.read_deny.push("~/back\\slash".into());
        let found = problems(&p, &f);
        assert!(found[0].starts_with("filesystem.read_deny"), "{found:?}");
    }

    #[test]
    fn network_entries_are_checked_and_private_needs_its_opt_in() {
        let f = fixture();
        assert!(
            problems(
                &policy(&[], &["api.openai.com", "printer.lan"], &["printer.lan"]),
                &f
            )
            .is_empty()
        );
        assert_eq!(problems(&policy(&[], &["*.com"], &[]), &f).len(), 1);
        assert_eq!(
            problems(&policy(&[], &["a.example.com"], &["printer.lan"]), &f).len(),
            1
        );
        assert_eq!(problems(&policy(&[], &["192.168.1.5"], &[]), &f).len(), 1);
        assert!(problems(&policy(&[], &["192.168.1.5"], &["192.168.1.5"]), &f).is_empty());
    }

    #[test]
    fn a_policy_may_add_to_the_built_in_read_denies_but_not_drop_them() {
        let f = fixture();
        let mut p = policy(&[], &[], &[]);
        p.fs.read_deny.push("~/dev/work".into());
        assert!(problems(&p, &f).is_empty());
        p.fs.read_deny.retain(|e| e != "~/.ssh");
        let found = problems(&p, &f);
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].contains("~/.ssh"), "{found:?}");
    }
}
