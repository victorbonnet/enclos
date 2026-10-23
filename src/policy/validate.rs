//! Checking a resolved policy before it is stored (design §5, §7).
//!
//! Refused: a write to enclos's own folders except the sandbox's own home,
//! also through a broad path or a symlink; a workspace inside the home or
//! inside another workspace, or one reached through a symlink the sandbox
//! can change; a dropped built-in read-deny entry; a path the compiled
//! policy cannot hold; a destination the proxy never lets a sandbox reach.
//! Malformed: a path or destination that does not parse, or a
//! `network.private` opt-in for a host not in `network.allow`. A policy
//! exits 2 only when every problem is a refusal (design §10).

use std::path::{Path, PathBuf};

use super::file::PolicyFile;
use super::paths::{PathContext, is_within, links_on_the_way, real_path};
use super::{PolicyError, Problem};
use crate::model::policy::Policy;
use crate::model::sandbox::{BackendKind, SandboxName};
use crate::model::secret::{is_variable_name, reserved_variable};
use crate::net::addr::{AddrClass, classify};
use crate::net::host::{AllowEntry, HostPattern, canonical_private, listed_host};

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
            Ok(path) => check_holdable_in_a_compiled_policy(
                "read_deny",
                entry,
                &real_path(&path),
                &mut problems,
            ),
            Err(e) => problems.push(Problem::Malformed(format!("filesystem.read_deny: {e}"))),
        }
    }
    check_default_denies(policy, &mut problems);
    check_network(policy, &mut problems);
    invalid_if_any(problems)
}

/// Checks the secrets a policy grants `sandbox` (ADR 0022): each is set as
/// a variable a shell reads and enclos neither sets nor passes on itself,
/// and is one of that sandbox's own, since secrets are granted per sandbox.
/// Whether each is stored is the engine's to check, as the store holds the
/// values.
pub fn validate_secrets(policy: &Policy, sandbox: &SandboxName) -> Result<(), PolicyError> {
    let mut problems = Vec::new();
    for (variable, grant) in &policy.secrets {
        if !is_variable_name(variable) {
            problems.push(Problem::Malformed(format!(
                "secrets.env: `{variable}` is not a variable name: use letters, digits and `_`, not starting with a digit"
            )));
        } else if reserved_variable(variable) {
            problems.push(Problem::Refused(format!(
                "secrets.env: `{variable}` is a variable enclos sets or passes on itself, or that changes how the sandbox runs; name the secret's variable otherwise"
            )));
        }
        if grant.0.sandbox != *sandbox {
            problems.push(Problem::Refused(format!(
                "secrets.env.{variable}: `{grant}` is a secret of sandbox {}; a sandbox is granted only its own (ADR 0022)",
                grant.0.sandbox
            )));
        }
    }
    invalid_if_any(problems)
}

/// Checks the limits a policy sets against what `backend` enforces (ADR
/// 0009): one it cannot enforce is refused, never stored and ignored.
/// Seatbelt holds a process to two of the limits macOS keeps for each
/// process, open files and CPU time; macOS refuses a memory limit, and does
/// not hold appends to a file size limit.
pub fn validate_resources(policy: &Policy, backend: BackendKind) -> Result<(), PolicyError> {
    let r = &policy.resources;
    let mut problems = Vec::new();
    for (name, value) in [
        ("open_files", r.open_files),
        ("file_size", r.file_size.map(|s| s.0)),
        ("cpu_seconds", r.cpu_seconds),
    ] {
        if value == Some(0) {
            problems.push(Problem::Malformed(format!(
                "resources.{name}: 0 would leave the sandbox unusable; set at least 1, or leave it out"
            )));
        }
    }
    // A value past these is no limit macOS keeps (its "infinity" among
    // them, which `ulimit` reads as `unlimited`), or one it refuses to set,
    // which would stop every session; too few files and `sandbox-exec`
    // cannot open its profile.
    for (name, value, least, most) in [
        ("open_files", r.open_files, 16, 1 << 20),
        ("cpu_seconds", r.cpu_seconds, 1, 10 * 365 * 24 * 3600),
        ("file_size", r.file_size.map(|s| s.0), 1024, 1 << 50),
    ] {
        if let Some(value) = value
            && value != 0
            && !(least..=most).contains(&value)
        {
            problems.push(Problem::Malformed(format!(
                "resources.{name} = {value}: set it from {least} to {most}"
            )));
        }
    }
    // `ulimit -f` counts in KiB: a size of no whole KiB could only be cut,
    // and one under 1K would become `ulimit -f 0`, stopping every write.
    if r.file_size
        .is_some_and(|s| s.0 != 0 && !s.0.is_multiple_of(1024))
    {
        problems.push(Problem::Malformed(format!(
            "resources.file_size = {}: write a whole number of KiB, such as `512K` or `1G`",
            r.file_size.expect("set")
        )));
    }
    match backend {
        BackendKind::Seatbelt => {
            if let Some(size) = r.file_size {
                problems.push(Problem::Refused(format!(
                    "resources.file_size = {size}: the Seatbelt backend cannot hold a file to a size, since macOS checks the limit against the start of a file opened to append, so each new process may append past it (shown on macOS 26.5.2); leave it out"
                )));
            }
            if let Some(memory) = &r.memory {
                problems.push(Problem::Refused(format!(
                    "resources.memory = {memory}: the Seatbelt backend cannot enforce a memory limit, since macOS refuses to set one on a process (shown on macOS 26.5.2); leave it out. Linux's backend is designed to hold one"
                )));
            }
            if let Some(cpu) = &r.cpu {
                problems.push(Problem::Refused(format!(
                    "resources.cpu = {cpu}: the Seatbelt backend cannot hold a sandbox to a share of the CPU, for which enclos has no means on macOS; `cpu_seconds` limits each process's CPU time instead"
                )));
            }
        }
        // No other backend is built yet: none enforces a limit.
        other if !r.is_unset() => problems.push(Problem::Refused(format!(
            "resources: the {other} backend enforces no limit yet; leave [resources] out"
        ))),
        _ => {}
    }
    invalid_if_any(problems)
}

/// The write checks of [`validate`] alone, on the paths as they are now: run
/// again each time a stored policy is compiled, since a symlink on the way
/// to a workspace may have changed since the policy was stored. The other
/// checks are not repeated there: the active policy is used as stored
/// (ADR 0018).
pub fn validate_writes(policy: &Policy, ctx: &ValidationContext) -> Result<(), PolicyError> {
    let mut problems = Vec::new();
    check_writes(policy, ctx, &mut problems);
    invalid_if_any(problems)
}

fn invalid_if_any(problems: Vec<Problem>) -> Result<(), PolicyError> {
    if problems.is_empty() {
        Ok(())
    } else {
        Err(PolicyError::Invalid { problems })
    }
}

fn check_writes(policy: &Policy, ctx: &ValidationContext, problems: &mut Vec<Problem>) {
    let own_home = real_path(&ctx.paths.sandbox_home);
    let protected: Vec<PathBuf> = ctx.protected.iter().map(|p| real_path(p)).collect();
    let mut granted = Vec::new();
    for entry in &policy.fs.write {
        let expanded = match ctx.paths.expand(entry) {
            Ok(path) => path,
            Err(e) => {
                problems.push(Problem::Malformed(format!("filesystem.write: {e}")));
                continue;
            }
        };
        let path = real_path(&expanded);
        check_holdable_in_a_compiled_policy("write", entry, &path, problems);
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
        granted.push(Granted {
            entry,
            expanded,
            path,
        });
    }
    check_nesting(&granted, &own_home, problems);
    check_links(&granted, &own_home, problems);
}

/// A write entry, as written, expanded, and resolved.
struct Granted<'a> {
    entry: &'a str,
    expanded: PathBuf,
    path: PathBuf,
}

/// The folder the sandbox writes that holds `path`, as a problem names it:
/// its home, or a granted folder other than those `skip` leaves out.
fn writable_folder_holding(
    path: &Path,
    own_home: &Path,
    granted: &[Granted],
    skip: impl Fn(&Granted) -> bool,
) -> Option<String> {
    match is_within(path, own_home) {
        true => Some("the sandbox home".to_owned()),
        false => granted
            .iter()
            .find(|g| !skip(g) && is_within(path, &g.path))
            .map(|g| format!("`{}` ({})", g.entry, g.path.display())),
    }
}

/// A workspace is a folder of its own: never inside the sandbox home, which
/// the sandbox always writes, nor inside another workspace. The compiled
/// policy keeps only each granted folder's own path in place (design §5),
/// so a workspace inside another writable folder would not be kept there.
fn check_nesting(granted: &[Granted], own_home: &Path, problems: &mut Vec<Problem>) {
    for g in granted.iter().filter(|g| g.path != own_home) {
        let outer = writable_folder_holding(&g.path, own_home, granted, |o| o.path == g.path);
        if let Some(outer) = outer {
            problems.push(Problem::Refused(format!(
                "filesystem.write: `{}` ({}) is inside {outer}, which the sandbox can already write; a workspace must be a folder of its own, so list only the outer one",
                g.entry,
                g.path.display()
            )));
        }
    }
}

/// A symlink on the way to a granted folder must sit where the sandbox
/// cannot write: one inside its home or a granted folder, the sandbox could
/// point elsewhere, and the next compile would follow it there.
fn check_links(granted: &[Granted], own_home: &Path, problems: &mut Vec<Problem>) {
    for g in granted {
        for link in links_on_the_way(&g.expanded) {
            let at = real_path(link.parent().unwrap_or(&link));
            if let Some(outer) = writable_folder_holding(&at, own_home, granted, |_| false) {
                problems.push(Problem::Refused(format!(
                    "filesystem.write: `{}` ({}) goes through a link at {} inside {outer}, which the sandbox can change; grant the folder it points to directly",
                    g.entry,
                    g.path.display(),
                    link.display()
                )));
                break;
            }
        }
    }
}

/// A path the compiled policy can hold as is: a double quote or a backslash
/// would change a Seatbelt rule, so the compiler refuses them, and a policy
/// that holds one could never start its sandbox. The backend cannot enforce
/// such a path, so it is refused (ADR 0009).
fn check_holdable_in_a_compiled_policy(
    list: &str,
    entry: &str,
    path: &std::path::Path,
    problems: &mut Vec<Problem>,
) {
    match path.to_str() {
        Some(text) if !text.contains(['"', '\\']) => {}
        Some(text) => problems.push(Problem::Refused(format!(
            "filesystem.{list}: `{entry}` ({text}) holds a double quote or a backslash, which enclos cannot put in a compiled policy; rename it or pick another path"
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
    // Every host the list names, refused ones too: opting in a refused
    // address is not a second problem.
    let listed: Vec<String> = policy
        .net
        .allow
        .iter()
        .filter_map(|e| listed_host(e))
        .collect();
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
        if !listed.contains(&host) {
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

    #[test]
    fn a_limit_seatbelt_cannot_enforce_is_refused() {
        let mut policy = Policy::default();
        policy.resources.open_files = Some(256);
        policy.resources.cpu_seconds = Some(3600);
        assert!(validate_resources(&policy, BackendKind::Seatbelt).is_ok());
        // macOS does not hold appends to a file size: refused.
        policy.resources.file_size = Some("1G".parse().unwrap());
        let err = validate_resources(&policy, BackendKind::Seatbelt).unwrap_err();
        assert!(
            err.is_refused() && err.to_string().contains("append"),
            "{err}"
        );
        policy.resources.file_size = None;
        policy.resources.open_files = Some(0);
        let zero = validate_resources(&policy, BackendKind::Seatbelt).unwrap_err();
        assert!(!zero.is_refused(), "{zero}");
        policy.resources.open_files = None;
        // Sizes are whole KiB: `ulimit -f` takes nothing smaller.
        for bytes in [1500, 512] {
            policy.resources.file_size = Some(crate::model::policy::ByteSize(bytes));
            let err = validate_resources(&policy, BackendKind::Seatbelt).unwrap_err();
            assert!(err.to_string().contains("whole number of KiB"), "{err}");
        }
        policy.resources.file_size = None;
        // Bounds: too few files to start, a value macOS reads as no limit,
        // a size it refuses to set.
        let bounded = |r: crate::model::policy::Resources| {
            let p = Policy {
                resources: r,
                ..Default::default()
            };
            validate_resources(&p, BackendKind::Seatbelt)
        };
        let files = |n| crate::model::policy::Resources {
            open_files: Some(n),
            ..Default::default()
        };
        assert!(bounded(files(15)).is_err());
        assert!(bounded(files(16)).is_ok());
        assert!(bounded(files(i64::MAX as u64)).is_err());
        let cpu = crate::model::policy::Resources {
            cpu_seconds: Some(i64::MAX as u64),
            ..Default::default()
        };
        assert!(bounded(cpu).is_err());
        let zero = crate::model::policy::Resources {
            cpu_seconds: Some(0),
            ..Default::default()
        };
        assert!(bounded(zero).is_err());
        // A backend not built yet enforces none, and refuses any.
        let mut some = Policy::default();
        some.resources.open_files = Some(256);
        assert!(
            validate_resources(&some, BackendKind::Bubblewrap)
                .unwrap_err()
                .is_refused()
        );
        assert!(validate_resources(&Policy::default(), BackendKind::Bubblewrap).is_ok());
        for (memory, cpu) in [(Some("2G"), None), (None, Some("2.0"))] {
            policy.resources.memory = memory.map(str::to_owned);
            policy.resources.cpu = cpu.map(str::to_owned);
            let err = validate_resources(&policy, BackendKind::Seatbelt).unwrap_err();
            assert!(err.is_refused(), "{err}");
            assert!(err.to_string().contains("Seatbelt"), "{err}");
        }
    }

    #[test]
    fn a_sandbox_is_granted_only_its_own_secrets_as_plain_variables() {
        let home: SandboxName = "home".parse().unwrap();
        let grant = |pairs: &[(&str, &str)]| {
            let mut policy = Policy::default();
            for (k, v) in pairs {
                policy.secrets.insert((*k).into(), v.parse().unwrap());
            }
            validate_secrets(&policy, &home)
        };
        assert!(grant(&[("TELEGRAM_BOT_TOKEN", "secret:home/telegram")]).is_ok());
        let other = grant(&[("TOKEN", "secret:lab/telegram")]).unwrap_err();
        assert!(other.is_refused(), "{other}");
        assert!(other.to_string().contains("sandbox lab"), "{other}");
        let reserved = grant(&[("HOME", "secret:home/xy")]).unwrap_err();
        assert!(reserved.is_refused(), "{reserved}");
        let malformed = grant(&[("1X", "secret:home/xy")]).unwrap_err();
        assert!(!malformed.is_refused(), "{malformed}");
    }

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
        assert!(problems(&policy(&["{home}", "~/work"], &[], &[]), &f).is_empty());
        // The same folder twice is still one workspace.
        assert!(problems(&policy(&["~/work", "~/work/"], &[], &[]), &f).is_empty());
    }

    #[test]
    fn a_workspace_inside_the_home_or_another_workspace_is_refused() {
        let f = fixture();
        let home = f.ctx.paths.sandbox_home.clone();
        let work = f.ctx.paths.user_home.join("work");
        std::fs::create_dir_all(home.join("projects")).unwrap();
        // Reached through a link that sits outside both.
        std::os::unix::fs::symlink(&work, f.ctx.paths.user_home.join("work-link")).unwrap();
        for (entries, outer) in [
            (&["{home}", "{tmp}"][..], "the sandbox home"),
            (&["{home}/projects"], "the sandbox home"),
            (&["~/work", "~/work/sub"], "`~/work`"),
            (&["~/work/sub", "~/work"], "`~/work`"),
            (&["~/work", "~/work-link/sub"], "`~/work`"),
        ] {
            let found = problems(&policy(entries, &[], &[]), &f);
            assert_eq!(found.len(), 1, "{entries:?}: {found:?}");
            assert!(
                found[0].contains(&format!("is inside {outer}")),
                "{entries:?}: {found:?}"
            );
        }
        let found = problems(&policy(&["~/work", "~/work/sub"], &[], &[]), &f);
        assert!(
            found[0].starts_with("filesystem.write: `~/work/sub`"),
            "{found:?}"
        );
        assert!(validate_writes(&policy(&["~/work/sub", "~/work"], &[], &[]), &f.ctx).is_err());
        assert!(validate_writes(&policy(&["{home}", "~/work"], &[], &[]), &f.ctx).is_ok());
    }

    #[test]
    fn a_workspace_reached_through_a_link_the_sandbox_can_change_is_refused() {
        let f = fixture();
        let user = f.ctx.paths.user_home.clone();
        let home = f.ctx.paths.sandbox_home.clone();
        let link = |target: &Path, at: &Path| std::os::unix::fs::symlink(target, at).unwrap();
        std::fs::create_dir(user.join("docs")).unwrap();
        // Links in folders the sandbox writes: its home, and `~/work`.
        link(&user.join("docs"), &home.join("out"));
        link(&user.join("not-yet"), &home.join("dangling"));
        link(&user.join("docs"), &user.join("work/out"));
        // A link the sandbox cannot change, on the way to one it can.
        link(&user.join("work/out"), &user.join("via-work"));
        for (entries, at) in [
            (&["{home}", "{home}/out"][..], "the sandbox home"),
            (&["{home}/out"], "the sandbox home"),
            (&["{home}/dangling"], "the sandbox home"),
            (&["~/work", "~/work/out"], "`~/work`"),
            (&["~/work/out", "~/work"], "`~/work`"),
            (&["~/work", "~/via-work"], "`~/work`"),
        ] {
            let found = problems(&policy(entries, &[], &[]), &f);
            assert!(
                found
                    .iter()
                    .any(|p| p.contains("through a link") && p.contains(&format!("inside {at}"))),
                "{entries:?}: {found:?}"
            );
            assert!(validate_writes(&policy(entries, &[], &[]), &f.ctx).is_err());
        }
        // A link outside every folder the sandbox writes is the user's own.
        link(&user.join("docs"), &user.join("docs-link"));
        assert!(problems(&policy(&["{home}", "~/work", "~/docs-link"], &[], &[]), &f).is_empty());
        // `~/work/out` is not granted, so the sandbox cannot change it.
        assert!(problems(&policy(&["{home}", "~/via-work"], &[], &[]), &f).is_empty());
    }

    #[test]
    fn what_a_policy_grants_or_reaches_is_refused_and_what_does_not_parse_is_malformed() {
        let f = fixture();
        let mut dropped = policy(&[], &[], &[]);
        dropped.fs.read_deny.retain(|e| e != "~/.ssh");
        let mut quoted_deny = policy(&[], &[], &[]);
        quoted_deny.fs.read_deny.push("~/a\"b".into());
        for (case, p) in [
            ("loopback", policy(&[], &["127.0.0.1"], &[])),
            ("link-local", policy(&[], &["169.254.169.254"], &[])),
            ("localhost", policy(&[], &["localhost"], &[])),
            ("private without opt-in", policy(&[], &["10.0.0.5"], &[])),
            ("public suffix", policy(&[], &["*.co.uk"], &[])),
            ("enclos's own files", policy(&["~/.enclos"], &[], &[])),
            ("not enforceable", policy(&["~/work/a\\b"], &[], &[])),
            (
                "refused opt-in",
                policy(&[], &["api.example.com"], &["localhost"]),
            ),
            // The opt-in names an entry that is in allow but refused: only
            // the refusal is a problem.
            (
                "loopback opted in",
                policy(&[], &["127.0.0.1"], &["127.0.0.1"]),
            ),
            (
                "link-local opted in",
                policy(&[], &["169.254.169.254"], &["169.254.169.254"]),
            ),
            (
                "IPv6 loopback opted in",
                policy(&[], &["[::1]:8443"], &["::1"]),
            ),
            ("not enforceable deny", quoted_deny),
            ("default deny dropped", dropped),
        ] {
            let found = checked(&p, &f);
            assert_eq!(found.len(), 1, "{case}: {found:?}");
            assert!(found[0].is_refused(), "{case}: {found:?}");
            let err = validate(&p, &f.ctx).unwrap_err();
            assert!(err.is_refused(), "{case}: {err}");
            assert!(
                err.to_string().starts_with("refused by policy:"),
                "{case}: {err}"
            );
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
        // Both spellings of a local service are refused, as allowed and as
        // opted in.
        let local = policy(&[], &["localhost"], &["localhost"]);
        assert!(validate(&local, &f.ctx).unwrap_err().is_refused());
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
    fn paths_a_compiled_policy_cannot_hold_are_refused_when_stored() {
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
