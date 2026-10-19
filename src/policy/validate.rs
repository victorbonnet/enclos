//! Checking a resolved policy before it is stored (design §5, §7).
//!
//! A policy may not grant writes to enclos's own folders except the sandbox's
//! own home, including through a broad path or a symlink, may not drop the
//! built-in read-deny entries, and its network entries must be ones the proxy
//! can enforce.

use std::path::PathBuf;

use super::PolicyError;
use super::file::PolicyFile;
use super::paths::{PathContext, is_within, real_path};
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
            Err(e) => problems.push(format!("filesystem.read_deny: {e}")),
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

fn check_writes(policy: &Policy, ctx: &ValidationContext, problems: &mut Vec<String>) {
    let own_home = real_path(&ctx.paths.sandbox_home);
    let protected: Vec<PathBuf> = ctx.protected.iter().map(|p| real_path(p)).collect();
    for entry in &policy.fs.write {
        let path = match ctx.paths.expand(entry) {
            Ok(path) => real_path(&path),
            Err(e) => {
                problems.push(format!("filesystem.write: {e}"));
                continue;
            }
        };
        check_writable_in_a_profile("write", entry, &path, problems);
        for root in &protected {
            let contains_root = is_within(root, &path);
            let inside_root = is_within(&path, root) && !is_within(&path, &own_home);
            if contains_root || inside_root {
                problems.push(format!(
                    "filesystem.write: `{entry}` ({}) would let the sandbox write enclos's own files in {}; only the sandbox's home is writable there",
                    path.display(),
                    root.display()
                ));
            }
        }
    }
}

/// A path the compiled policy can hold as is: a double quote or a backslash
/// would change a Seatbelt rule, so the compiler refuses them, and a policy
/// that holds one could never start its sandbox.
fn check_writable_in_a_profile(
    list: &str,
    entry: &str,
    path: &std::path::Path,
    problems: &mut Vec<String>,
) {
    match path.to_str() {
        Some(text) if !text.contains(['"', '\\']) => {}
        Some(text) => problems.push(format!(
            "filesystem.{list}: `{entry}` ({text}) holds a double quote or a backslash, which enclos cannot put in a sandbox profile"
        )),
        None => problems.push(format!(
            "filesystem.{list}: `{entry}` ({}) is not valid UTF-8",
            path.display()
        )),
    }
}

/// A layer that writes `read_deny = [...]` replaces the list below it; it may
/// not leave out what the built-in defaults hide (design §5).
fn check_default_denies(policy: &Policy, problems: &mut Vec<String>) {
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
        problems.push(format!(
            "filesystem.read_deny leaves out paths enclos always hides: {}; add your own with read_deny_add instead",
            dropped.join(", ")
        ));
    }
}

fn check_network(policy: &Policy, problems: &mut Vec<String>) {
    let mut allowed = Vec::new();
    for entry in &policy.net.allow {
        match AllowEntry::parse(entry) {
            Ok(parsed) => allowed.push(parsed),
            Err(e) => problems.push(format!("network.allow: `{entry}`: {e}")),
        }
    }
    let mut private = Vec::new();
    for entry in &policy.net.private {
        let host = match canonical_private(entry) {
            Ok(host) => host,
            Err(e) => {
                problems.push(format!("network.private: `{entry}`: {e}"));
                continue;
            }
        };
        if !allowed.iter().any(|a| a.host_text() == host) {
            problems.push(format!(
                "network.private: `{entry}` must also be in network.allow; the opt-in only unlocks private addresses for allowed hosts"
            ));
        }
        private.push(host);
    }
    for entry in &allowed {
        if let HostPattern::Ip(ip) = entry.host
            && classify(ip) == AddrClass::Private
            && !private.contains(&ip.to_string())
        {
            problems.push(format!(
                "network.allow: {ip} is a private address; add it to network.private as well to opt in"
            ));
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

    fn problems(p: &Policy, f: &Fixture) -> Vec<String> {
        match validate(p, &f.ctx) {
            Ok(()) => Vec::new(),
            Err(PolicyError::Invalid { problems }) => problems,
            Err(e) => panic!("{e}"),
        }
    }

    #[test]
    fn the_sandbox_home_and_a_workspace_are_writable() {
        let f = fixture();
        assert!(problems(&policy(&["{home}", "{tmp}", "~/work"], &[], &[]), &f).is_empty());
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
