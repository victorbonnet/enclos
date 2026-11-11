//! An approval changes only the scope the phone saw, under the state lock.
use super::pending::{Change, Recorded};
use super::{Engine, PolicyApplied};
use crate::error::{Error, Result};
use crate::model::{audit::Actor, plan::Confirm, sandbox::SandboxName};
use crate::net::host::{AllowEntry, HostPattern};
use crate::policy::sha256_hex;
use enclos_protocol::approval::{Access, AccessKind};
use toml_edit::{Array, DocumentMut, Item, Table};

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
const HOME_REFUSED: &[&str] = &["Library", "Applications", "bin", "go/bin"];

/// Why an agent-proposed write scope cannot be approved from the phone, if
/// it cannot (ADR 0046). `target` and `home` are real paths; `path` is the
/// host's `PATH`. The host's own `enclos policy edit` is not narrowed: there
/// the person writes the path, here the agent does.
pub(crate) fn phone_write_refusal(
    target: &std::path::Path,
    home: &std::path::Path,
    path: &[std::path::PathBuf],
) -> Option<String> {
    use std::path::{Component, Path};
    let on_host = "; grant it on the host with `enclos policy edit` if you mean it";
    let below = |root: &Path, depth: usize| {
        target
            .strip_prefix(root)
            .ok()
            .filter(|rest| rest.components().count() >= depth)
            .map(Path::to_owned)
    };
    // A folder inside the home, or on an external volume: never the system's.
    let Some(rest) = below(home, 1)
        .or_else(|| below(Path::new("/Volumes"), 2))
        .or_else(|| below(Path::new("/mnt"), 2))
        .or_else(|| below(Path::new("/media"), 3))
    else {
        return Some(format!(
            "{} is outside your home folder and external volumes{on_host}",
            target.display()
        ));
    };
    if rest.components().any(|c| match c {
        Component::Normal(part) => part.to_string_lossy().starts_with('.'),
        _ => false,
    }) {
        return Some(format!(
            "{} is or is inside a hidden file or folder, where shell startup files, git, editor and tool settings live and run outside the sandbox{on_host}",
            target.display()
        ));
    }
    if target.starts_with(home)
        && let Some(folder) = HOME_REFUSED.iter().find(|f| rest.starts_with(f))
    {
        return Some(format!(
            "{} is inside ~/{folder}, which holds programs or settings the host runs outside the sandbox{on_host}",
            target.display()
        ));
    }
    if let Some(folder) = path
        .iter()
        .find(|p| p.is_absolute() && (target.starts_with(p) || p.starts_with(target)))
    {
        return Some(format!(
            "{} is, holds or is inside {}, a folder on the host's PATH, whose programs run outside the sandbox{on_host}",
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
                        "From the phone, private addresses can be approved for an IP address or a local name ({}). {} is a public name its owner could point at your network later; grant it on the host with `enclos policy edit` if you mean it.",
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
                let home = crate::policy::paths::real_path(self.layout.user_home());
                if let Some(why) = phone_write_refusal(&real, &home, &host_path()) {
                    return Err(refused(format!("{why}.")));
                }
                let target = real.display().to_string();
                scope = target.clone();
                if !expected.fs.write.contains(&target) {
                    add(&mut doc, "filesystem", "write_add", &target)?;
                    expected.fs.write.push(target.clone());
                }
                format!(
                    "Allow every agent in {name} to write {target} and everything beneath it. A running sandbox restarts to apply it. Future writes in this scope need no further approval."
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
        let recorded = self.write(
            by,
            "app approval",
            Some(format!("{name} {:?} {}", access.kind, access.target)),
            |_: &Recorded| "approved the requested policy scope".to_owned(),
            |lock| {
                let plan = self.access_plan(name, access)?;
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
