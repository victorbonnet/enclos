//! What one launch's masks depend on, read from the host: whether a
//! workspace leads to a place the sandbox has its own of, where each mask
//! goes ([`super::masks`]), whether a link lies between a grant and a mask
//! in it, what each path is now, and the home's folders on the way to a
//! hidden path.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};

use super::masks::{
    Grants, Masks, agents_socket, at_a_workspaces_name, home_sockets, in_grants_as_written,
    refuse_workspace_reaching_an_entry, resolved_entries, unmovable, where_links_lead,
};
use super::paths;
use crate::backend::WrapError;
use crate::backend::bubblewrap::compile::{CompiledSandbox, OWN_PLACES};
use crate::policy::paths::{is_within, real_path};

/// What a mask covers, as the host holds it at launch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::backend::bubblewrap) enum Kind {
    Folder,
    /// A file, a socket or anything else that is not a folder.
    Other,
    Missing,
}

impl Kind {
    /// What `path` is, not following a link at its end: a link there is the
    /// sandbox's to have made, and is masked as itself.
    fn of(path: &Path) -> Result<Kind, WrapError> {
        match std::fs::symlink_metadata(path) {
            Ok(meta) if meta.is_dir() => Ok(Kind::Folder),
            Ok(_) => Ok(Kind::Other),
            Err(e) if gone(&e) => Ok(Kind::Missing),
            Err(e) => Err(unreadable(path, &e)),
        }
    }
}

/// One entry of a folder the home's mask rebuilds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::backend::bubblewrap) struct Entry {
    pub name: OsString,
    /// Where it points, for a link, which is made again as a link.
    pub link: Option<PathBuf>,
}

/// What the masks of one launch depend on, read from the host.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(in crate::backend::bubblewrap) struct Host {
    /// Each folder from the user's home down that holds a hidden path, with
    /// what it holds. A folder that went away lists nothing.
    pub entries: BTreeMap<PathBuf, Vec<Entry>>,
    /// The paths the home's folders leave out.
    pub hidden: BTreeSet<PathBuf>,
    /// The masks after the `/` bind, outside the home.
    pub elsewhere: Vec<(PathBuf, Kind)>,
    /// The folders inside a grant that hold a mask, bound on themselves.
    pub unmovable: Vec<PathBuf>,
    /// The masks inside a grant, after its bind, at the path the grant is
    /// written by.
    pub in_grants: Vec<(PathBuf, Kind)>,
    /// The host's listening sockets under the user's home that the home's
    /// mask would show, each masked after it.
    pub sockets: Vec<PathBuf>,
}

fn gone(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
    )
}

fn unreadable(path: &Path, e: &io::Error) -> WrapError {
    WrapError(format!(
        "cannot look at {}, so what it holds cannot be hidden: {e}",
        path.display()
    ))
}

/// Refuses a link between `grant` and `entry`, which lies inside it: the
/// sandbox writes every folder there, so it could have made the link, and
/// bubblewrap would follow it as it places the mask. `entry` itself may be
/// one: it is masked as itself.
pub(super) fn no_link_between(grant: &Path, entry: &Path) -> Result<(), WrapError> {
    let Ok(rest) = entry.strip_prefix(grant) else {
        return Ok(());
    };
    let mut folder = grant.to_path_buf();
    let mut parts: Vec<_> = rest.components().collect();
    parts.pop();
    for part in parts {
        folder.push(part);
        match std::fs::symlink_metadata(&folder) {
            Ok(meta) if meta.file_type().is_symlink() => {
                return Err(WrapError(format!(
                    "{} is a link between {} and the deny entry {}: the session is refused, since the mask would follow it; replace the link with a folder",
                    folder.display(),
                    grant.display(),
                    entry.display()
                )));
            }
            Ok(_) => {}
            Err(e) if gone(&e) => return Ok(()),
            Err(e) => return Err(unreadable(&folder, &e)),
        }
    }
    Ok(())
}

/// Refuses a workspace that is, holds or lies inside a place the sandbox
/// has its own of, as written or where a link leads now, whether or not it
/// is there yet: its bind comes after the sandbox's own mounts, and follows
/// a link at the workspace's name inside the sandbox, so the host's would
/// replace the sandbox's (`~/alias -> ../../run`).
fn refuse_workspace_on_an_own_place(compiled: &CompiledSandbox) -> Result<(), WrapError> {
    for written in paths(&compiled.bubblewrap.grant_masks.workspaces) {
        let real = real_path(&written);
        let Some(place) = OWN_PLACES
            .undone_by(&written)
            .or_else(|| OWN_PLACES.undone_by(&real))
        else {
            continue;
        };
        let through = match real == written {
            true => String::new(),
            false => format!(", which leads to {},", real.display()),
        };
        return Err(WrapError(format!(
            "workspace {}{through} would bring back the host's {place}, which the sandbox has its own of: the session is refused; point the link elsewhere, or grant another folder",
            written.display()
        )));
    }
    Ok(())
}

/// The folders between `grant` and `entry` that are there, parents first.
pub(super) fn holders(grant: &Path, entry: &Path) -> Vec<PathBuf> {
    let Ok(rest) = entry.strip_prefix(grant) else {
        return Vec::new();
    };
    let mut parts: Vec<_> = rest.components().collect();
    parts.pop();
    let mut folder = grant.to_path_buf();
    let mut found = Vec::new();
    for part in parts {
        folder.push(part);
        if !folder.is_dir() {
            break;
        }
        found.push(folder.clone());
    }
    found
}

/// Each path with what the host holds there now.
fn with_kinds(mut found: Vec<PathBuf>) -> Result<Vec<(PathBuf, Kind)>, WrapError> {
    found.sort();
    found.dedup();
    found
        .into_iter()
        .map(|path| Kind::of(&path).map(|kind| (path, kind)))
        .collect()
}

/// What this launch's masks depend on, in the order design §5 gives:
/// workspaces that reach a place the sandbox has its own of or a deny entry
/// refused, the masks inside the grants, where links lead, the agent's
/// socket, the home's listening sockets, the folders that cannot move, then
/// the home's folders listed. `ssh_auth_sock` is the socket the host's
/// `SSH_AUTH_SOCK` names, and `sockets` the files the host's listening
/// sockets are bound to now.
pub(in crate::backend::bubblewrap) fn read_host(
    compiled: &CompiledSandbox,
    sandbox_home: &Path,
    ssh_auth_sock: Option<&Path>,
    sockets: &[PathBuf],
) -> Result<Host, WrapError> {
    refuse_workspace_on_an_own_place(compiled)?;
    let root_masks = &compiled.bubblewrap.root_masks;
    let grants = Grants::read(compiled, sandbox_home);
    let entries = resolved_entries(compiled);
    refuse_workspace_reaching_an_entry(&entries, &grants)?;

    // An entry outside the home that is itself a link is masked where it
    // leads alone: bubblewrap's mount would follow it there anyway, and the
    // sandbox cannot change it.
    let mut masks = Masks {
        in_grants: Vec::new(),
        hidden: paths(&root_masks.denied).collect(),
        elsewhere: paths(&root_masks.denied_elsewhere)
            .filter(|e| !std::fs::symlink_metadata(e).is_ok_and(|m| m.file_type().is_symlink()))
            .collect(),
    };
    in_grants_as_written(compiled, &grants, &mut masks)?;
    at_a_workspaces_name(&entries, &grants, &mut masks)?;
    where_links_lead(&entries, &grants, &mut masks)?;
    if let Some(socket) = ssh_auth_sock.filter(|s| s.is_absolute()) {
        agents_socket(socket, &grants, &mut masks)?;
    }

    // One that went away since the table was read gets no mask, which
    // bubblewrap would otherwise make as a file.
    let home_sockets = with_kinds(home_sockets(sockets, &grants, &masks.hidden))?
        .into_iter()
        .filter(|(_, kind)| *kind == Kind::Other)
        .map(|(socket, _)| socket)
        .collect();
    let mut host = Host {
        unmovable: unmovable(
            &compiled.bubblewrap.grant_masks.unmovable,
            &masks.in_grants,
            &grants,
        ),
        in_grants: with_kinds(masks.in_grants)?,
        elsewhere: with_kinds(masks.elsewhere)?,
        sockets: home_sockets,
        ..Host::default()
    };
    let roots: Vec<PathBuf> = grants.present.into_iter().map(|(_, real)| real).collect();
    walk(&grants.home, &masks.hidden, &roots, &mut host.entries)?;
    host.hidden = masks.hidden;
    Ok(host)
}

/// Lists `folder` and each folder below it on the way to a hidden path. A
/// workspace is not listed, whichever name reaches it: its bind replaces it.
fn walk(
    folder: &Path,
    hidden: &BTreeSet<PathBuf>,
    workspaces: &[PathBuf],
    entries: &mut BTreeMap<PathBuf, Vec<Entry>>,
) -> Result<(), WrapError> {
    if workspaces
        .iter()
        .any(|root| is_within(&real_path(folder), root))
    {
        return Ok(());
    }
    let listing = match std::fs::read_dir(folder) {
        Ok(listing) => listing,
        Err(e) if gone(&e) => return Ok(()),
        Err(e) => return Err(unreadable(folder, &e)),
    };
    let mut found = Vec::new();
    let mut below = Vec::new();
    for item in listing {
        let item = item.map_err(|e| unreadable(folder, &e))?;
        let path = item.path();
        let link = match item.file_type() {
            Ok(kind) if kind.is_symlink() => {
                Some(std::fs::read_link(&path).map_err(|e| unreadable(&path, &e))?)
            }
            Ok(_) => None,
            Err(e) => return Err(unreadable(&path, &e)),
        };
        let holds_hidden = hidden.iter().any(|d| is_within(d, &path) && *d != path);
        if link.is_none() && holds_hidden && path.is_dir() {
            below.push(path);
        }
        found.push(Entry {
            name: item.file_name(),
            link,
        });
    }
    found.sort_by(|a, b| a.name.cmp(&b.name));
    entries.insert(folder.to_path_buf(), found);
    for path in below {
        walk(&path, hidden, workspaces, entries)?;
    }
    Ok(())
}
