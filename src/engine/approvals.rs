//! An approval changes only the scope the phone saw, under the state lock.
use super::pending::{Change, Recorded};
use super::{Engine, PolicyApplied};
use crate::error::{Error, Result};
use crate::model::{audit::Actor, plan::Confirm, sandbox::SandboxName};
use crate::net::host::{AllowEntry, HostPattern};
use crate::policy::sha256_hex;
use enclos_protocol::approval::{Access, AccessKind};
use toml_edit::{Array, DocumentMut, Item, Table};

/// `access` as the policy would hold it, so two spellings of one scope are
/// one request: a destination normalized, a path with its symlinks
/// resolved. One that does not parse stays as it is; planning refuses it.
pub fn normalized(access: &Access) -> Access {
    let mut access = access.clone();
    match access.kind {
        AccessKind::Network => {
            if let Ok(entry) = AllowEntry::parse(&access.target) {
                access.target = entry.to_string();
            } else if let Ok((host, port)) = crate::net::host::split_port(access.target.trim())
                && let Ok(ip) = host.parse::<std::net::IpAddr>()
                && matches!(
                    crate::net::addr::classify(ip),
                    crate::net::addr::AddrClass::Blocked(_)
                )
            {
                // Such a destination stays unavailable. Keep the proxy's explicit-port
                // spelling so its refusal and an explicit request have one identity.
                access.target = crate::model::net::destination(&ip.to_string(), port);
            }
        }
        AccessKind::Write => {
            let path = std::path::Path::new(&access.target);
            if path.is_absolute() {
                access.target = crate::policy::paths::real_path(path).display().to_string();
            }
        }
        AccessKind::Read => {}
    }
    access
}

pub struct AccessPlan {
    pub revision: String,
    pub change: String,
    /// The exact entry written to the policy: a normalized destination, or
    /// a writable path with its symlinks resolved.
    pub scope: String,
    pub restart: bool,
    before: String,
    after: String,
}
fn refused(what: impl Into<String>) -> Error {
    Error::Session { what: what.into() }
}

/// Local names an outside party cannot register, so cannot point at the
/// host's network later (DNS rebinding): the only names whose private
/// addresses an agent may ask for from the phone (ADR 0046).
const LOCAL_NAME_SUFFIXES: &[&str] = &[".local", ".home.arpa", ".internal", ".lan"];

/// Folders under the user's home that hold code or settings the host runs
/// outside any sandbox: macOS's `Library` (launch agents, editor and IDE
/// settings), apps, and the usual personal `bin` folders.
const HOME_RUN_FOLDERS: &[&str] = &["Library", "Applications", "bin", "go/bin"];

/// Whether `a` is, or is inside, `b`. On macOS without case: its usual file
/// system does not tell `~/library` from `~/Library`, and a folder that does
/// not exist yet keeps the case the agent wrote.
fn within(a: &std::path::Path, b: &std::path::Path) -> bool {
    if cfg!(target_os = "macos") {
        let lower =
            |p: &std::path::Path| std::path::PathBuf::from(p.to_string_lossy().to_lowercase());
        lower(a).starts_with(lower(b))
    } else {
        a.starts_with(b)
    }
}

/// Why a writable path an agent asks for lets the agent run code on the
/// host, if it does: the path is, holds or is inside a place the host reads
/// settings or programs from (ADR 0046). The preview leads with it, so this
/// grant does not read like an ordinary project folder's. Approval does not
/// refuse it: the host's person decides, as in the policy editor. `target`
/// and `home` are real paths; `path` is the host's `PATH`.
pub(crate) fn write_risk(
    target: &std::path::Path,
    home: &std::path::Path,
    path: &[std::path::PathBuf],
) -> Option<String> {
    use std::path::{Component, Path};
    let runs = "what an agent writes there can run as you, outside the sandbox";
    if let Ok(rest) = target.strip_prefix(home) {
        if rest.components().any(|c| match c {
            Component::Normal(part) => part.to_string_lossy().starts_with('.'),
            _ => false,
        }) {
            return Some(format!(
                "{} is or is inside a hidden file or folder, where shell startup files and git, editor and tool settings live: {runs}.",
                target.display()
            ));
        }
        // Both ways: a grant on `~/go` covers `~/go/bin`.
        if let Some(folder) = HOME_RUN_FOLDERS
            .iter()
            .find(|f| within(rest, Path::new(f)) || within(Path::new(f), rest))
        {
            return Some(format!(
                "{} is, holds or is inside ~/{folder}, which holds programs or settings the host runs: {runs}.",
                target.display()
            ));
        }
    }
    if let Some(folder) = path
        .iter()
        .find(|p| p.is_absolute() && (within(target, p) || within(p, target)))
    {
        return Some(format!(
            "{} is, holds or is inside {}, a folder on the host's PATH: an agent could replace programs the host runs, outside the sandbox.",
            target.display(),
            folder.display()
        ));
    }
    None
}

/// The host's `PATH`, each folder as a real path.
fn host_path() -> Vec<std::path::PathBuf> {
    std::env::var_os("PATH")
        .map(|p| {
            std::env::split_paths(&p)
                .filter(|p| p.is_absolute())
                .map(|p| crate::policy::paths::real_path(&p))
                .collect()
        })
        .unwrap_or_default()
}

impl Engine {
    pub fn deny_access(&self, by: &Actor, name: &SandboxName, id: &str) -> Result<()> {
        self.write(
            by,
            "app approval deny",
            Some(format!("{name} {id}")),
            |_: &()| "denied; policy unchanged".into(),
            |_| Ok(()),
        )
    }

    pub fn access_plan(&self, name: &SandboxName, access: &Access) -> Result<AccessPlan> {
        let view = self.policy(name)?;
        if view.pending.is_some() {
            return Err(refused(
                "A policy change is pending. Apply or discard it on the host first.",
            ));
        }
        let before = self.layout.read_policy(name.as_str())?;
        let current = self.checked_policy(name, &before)?;
        if current.policy != view.snapshot.policy {
            return Err(refused(
                "The policy file has unapplied edits. Review them on the host first.",
            ));
        }
        if access.target.len() > 4096 || enclos_protocol::visible::has_hidden(&access.target, false)
        {
            return Err(refused(
                "The requested target is too long or contains hidden characters.",
            ));
        }
        let mut doc = before
            .parse::<DocumentMut>()
            .map_err(|e| refused(e.to_string()))?;
        let mut expected = current.policy.clone();
        let scope;
        let change = match access.kind {
            AccessKind::Network => {
                let entry =
                    AllowEntry::parse(&access.target).map_err(|e| refused(e.to_string()))?;
                if matches!(entry.host, HostPattern::Subdomains(_)) {
                    return Err(refused("Name one destination, without a wildcard."));
                }
                let target = entry.to_string();
                let local_name = match &entry.host {
                    HostPattern::Exact(host) => {
                        Some(LOCAL_NAME_SUFFIXES.iter().any(|s| host.ends_with(s)))
                    }
                    _ => None,
                };
                if access.private && local_name == Some(false) {
                    return Err(refused(format!(
                        "From the phone, private addresses can be approved for an IP address or a local name ({}). {} is a public name its owner could point at your network later; add it in the app's policy editor or with `enclos policy edit` on the host if you mean it.",
                        LOCAL_NAME_SUFFIXES.join(", "),
                        entry.host_text()
                    )));
                }
                scope = target.clone();
                if !expected.net.allow.contains(&target) {
                    add(&mut doc, "network", "allow_add", &target)?;
                }
                if !expected.net.allow.contains(&target) {
                    expected.net.allow.push(target.clone());
                }
                if access.private {
                    if !expected.net.private.contains(&entry.host_text()) {
                        add(&mut doc, "network", "private_add", &entry.host_text())?;
                    }
                    if !expected.net.private.contains(&entry.host_text()) {
                        expected.net.private.push(entry.host_text());
                    }
                }
                format!(
                    "Allow {target}{} for every agent in {name}. Future connections are allowed without another approval.",
                    match (access.private, local_name) {
                        (false, _) => String::new(),
                        (true, Some(true)) => format!(
                            ", opting {} into private addresses, whatever it resolves to on your network, on every port the policy already allows",
                            entry.host_text()
                        ),
                        (true, _) => ", opting this host into private addresses on every port the policy already allows".to_owned(),
                    }
                )
            }
            AccessKind::Write => {
                let path = std::path::Path::new(&access.target);
                if !path.is_absolute()
                    || path.parent().is_none()
                    || access.target.split('/').any(|p| p == "." || p == "..")
                    || path.components().any(|c| {
                        matches!(
                            c,
                            std::path::Component::ParentDir | std::path::Component::CurDir
                        )
                    })
                {
                    return Err(refused(
                        "Name one absolute path, without .. or a filesystem root.",
                    ));
                }
                if access.private {
                    return Err(refused("Private addresses apply only to network access."));
                }
                // Store the resolved destination: changing a symlink after approval cannot
                // redirect the persistent grant to another host folder.
                let real = crate::policy::paths::real_path(path);
                // The host's person reviews the grant, as in the app's policy
                // editor, and the shared validator below holds the protected
                // paths and backend restrictions. One narrowing is the
                // agent's alone: the home folder, or a folder holding it,
                // would let it change everything there in one approval, and
                // only enclos's own folders inside it would otherwise stop it.
                let home = crate::policy::paths::real_path(self.layout.user_home());
                if within(&home, &real) {
                    return Err(refused(format!(
                        "{} is your home folder or holds it, so approving it would let every agent change everything in your home folder. Only a folder inside it can be approved here.",
                        real.display()
                    )));
                }
                let risk = write_risk(&real, &home, &host_path());
                let target = real.display().to_string();
                scope = target.clone();
                if !expected.fs.write.contains(&target) {
                    add(&mut doc, "filesystem", "write_add", &target)?;
                    expected.fs.write.push(target.clone());
                }
                format!(
                    "{}Allow every agent in {name} to create, change or delete files at {target} and everything beneath it, hidden files and folders included (such as .git, .envrc or .vscode), which tools on the host may read and run outside the sandbox. A running sandbox restarts to apply it. Future writes in this scope need no further approval.",
                    risk.map(|r| format!("Warning: {r} ")).unwrap_or_default()
                )
            }
            AccessKind::Read => {
                return Err(refused(
                    "Read denials protect sensitive paths. This request cannot remove them; review the policy on the host.",
                ));
            }
        };
        let after = doc.to_string();
        let snapshot = self.checked_policy(name, &after)?;
        // Resolution must add exactly this scope, with no implicit template or adapter changes.
        for list in [
            &mut expected.fs.write,
            &mut expected.net.allow,
            &mut expected.net.private,
        ] {
            list.sort();
            list.dedup();
        }
        if snapshot.policy != expected {
            return Err(refused(
                "This request would change more than the scope shown. Review the policy on the host.",
            ));
        }
        let restart = !snapshot.policy.same_at_launch(&view.snapshot.policy)
            && !self.sessions_under_rules(name)?.is_empty();
        let revision = sha256_hex(
            format!(
                "{}:{}:{}:{restart}",
                view.snapshot.id,
                sha256_hex(before.as_bytes()),
                snapshot.id
            )
            .as_bytes(),
        );
        Ok(AccessPlan {
            revision,
            change,
            scope,
            restart,
            before,
            after,
        })
    }

    pub fn approve_access(
        &self,
        by: &Actor,
        name: &SandboxName,
        access: &Access,
        revision: &str,
    ) -> Result<PolicyApplied> {
        // What the policy received, which the person saw: the agent's own
        // spelling may differ (a symlink, a host's case or port)
        let written = std::cell::RefCell::new(String::new());
        let recorded = self.write(
            by,
            "app approval",
            Some(format!("{name} {:?} {}", access.kind, access.target)),
            |_: &Recorded| {
                format!(
                    "approved the requested policy scope: {}{}",
                    written.borrow(),
                    if access.private {
                        ", private addresses"
                    } else {
                        ""
                    }
                )
            },
            |lock| {
                let plan = self.access_plan(name, access)?;
                *written.borrow_mut() = plan.scope.clone();
                if plan.revision != revision {
                    return Err(refused(
                        "The policy changed. Review the refreshed request before approving.",
                    ));
                }
                let snapshot = self.checked_policy(name, &plan.after)?;
                // The plan was made under the same lock as this write.
                debug_assert_eq!(self.layout.read_policy(name.as_str())?, plan.before);
                self.propose(lock, by, name, Change::edit(&plan.after, &snapshot))
            },
        )?;
        self.restart_if_asked(by, name, Confirm::Yes, recorded)
    }

    /// A fresh description, not an independent grant: the active snapshot
    /// remains authority. It goes into every model turn, so it names the
    /// grants but only counts the read denials, a long list of host paths.
    pub fn access_context(&self, name: &SandboxName) -> Result<String> {
        let view = self.policy(name)?;
        let p = view.snapshot.policy;
        Ok(format!(
            "Enclos sandbox {name}, active policy {}. All agents share these grants. Network mode: {:?}; allowed destinations: {}; private destinations: {}. Writable paths: {}. Sensitive paths ({} of them: credentials, keys, histories, browser data) cannot be read, and no request can change that. These are current grants, not permission to bypass a refusal. If blocked, use enclos_request_access; do not retry until the person approves. Approved access persists, so do not ask again within its scope.",
            view.snapshot.id,
            p.net.mode,
            p.net.allow.join(", "),
            p.net.private.join(", "),
            p.fs.write.join(", "),
            p.fs.read_deny.len()
        ))
    }
}
fn add(doc: &mut DocumentMut, section: &str, key: &str, value: &str) -> Result<()> {
    if doc.get(section).is_none() {
        doc[section] = Item::Table(Table::new());
    }
    if doc[section].get(key).is_none() {
        doc[section][key] = toml_edit::value(Array::new());
    }
    let list = doc[section][key]
        .as_array_mut()
        .ok_or_else(|| refused("The policy list is not an array."))?;
    if !list.iter().any(|v| v.as_str() == Some(value)) {
        list.push(value);
    }
    Ok(())
}
