//! Where each mask of a launch goes: inside a grant after its bind, in the
//! home's mask, after the `/` bind, or nowhere, under what the sandbox has
//! its own of. Links are resolved here, as the host holds them now.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use super::host::{holders, no_link_between};
use super::paths;
use crate::backend::WrapError;
use crate::backend::bubblewrap::compile::{CompiledSandbox, OWN_MOUNTS, OWN_TMPFS};
use crate::policy::paths::{is_within, real_path};

/// The places a mask can go, as this launch finds them: the home and the
/// sandbox home as written and as they really are, and each workspace.
pub(super) struct Grants<'a> {
    pub(super) home: PathBuf,
    real_home: PathBuf,
    sandbox_home: &'a Path,
    real_sandbox_home: PathBuf,
    /// Every workspace, as written.
    workspaces: Vec<PathBuf>,
    /// Each workspace that is there, as written and where it really is: one
    /// reached through a link the user made is bound where it leads.
    pub(super) present: Vec<(PathBuf, PathBuf)>,
}

impl<'a> Grants<'a> {
    pub(super) fn read(compiled: &CompiledSandbox, sandbox_home: &'a Path) -> Grants<'a> {
        let home = PathBuf::from(&compiled.bubblewrap.root_masks.home);
        let workspaces: Vec<PathBuf> = paths(&compiled.bubblewrap.grant_masks.workspaces).collect();
        let present = workspaces
            .iter()
            .filter(|w| w.is_dir())
            .map(|w| (w.clone(), real_path(w)))
            .collect();
        Grants {
            real_home: real_path(&home),
            home,
            sandbox_home,
            real_sandbox_home: real_path(sandbox_home),
            workspaces,
            present,
        }
    }
}

/// Where a mask for a path, as it really is, goes.
#[derive(Debug, PartialEq, Eq)]
enum Place {
    /// At the home or above it, which no mask can hide.
    HoldsTheHome,
    /// Inside `grant`, at `at`, after the grant's bind.
    InGrant { grant: PathBuf, at: PathBuf },
    /// Under the home, left out of the home's mask.
    InHome(PathBuf),
    /// Under a place the sandbox has its own of, never the host's.
    SandboxOwn,
    /// Anywhere else, masked after the `/` bind.
    Elsewhere(PathBuf),
}

/// Where the mask for `real` goes. A grant comes before the home that may
/// hold it, and each is named as the sandbox reaches it.
fn place(real: &Path, grants: &Grants<'_>) -> Place {
    let under =
        |root: &Path, written: &Path| real.strip_prefix(root).ok().map(|rest| written.join(rest));
    if is_within(&grants.real_home, real) {
        return Place::HoldsTheHome;
    }
    for (written, real_workspace) in &grants.present {
        if let Some(at) = under(real_workspace, written) {
            return Place::InGrant {
                grant: written.clone(),
                at,
            };
        }
    }
    if let Some(at) = under(&grants.real_sandbox_home, grants.sandbox_home) {
        return Place::InGrant {
            grant: grants.sandbox_home.to_path_buf(),
            at,
        };
    }
    if let Some(at) = under(&grants.real_home, &grants.home) {
        return Place::InHome(at);
    }
    match sandbox_own(real) {
        true => Place::SandboxOwn,
        false => Place::Elsewhere(real.to_path_buf()),
    }
}

/// Whether `path` lies under a place the sandbox has its own of.
fn sandbox_own(path: &Path) -> bool {
    OWN_TMPFS
        .iter()
        .chain(OWN_MOUNTS)
        .any(|own| is_within(path, Path::new(own)))
}

/// The masks of one launch, before the host says what each path is.
#[derive(Default)]
pub(super) struct Masks {
    pub(super) in_grants: Vec<PathBuf>,
    pub(super) hidden: BTreeSet<PathBuf>,
    pub(super) elsewhere: Vec<PathBuf>,
}

impl Masks {
    /// Adds the mask `place` names, or refuses it as `refused` says.
    fn put(&mut self, place: Place, refused: impl FnOnce() -> WrapError) -> Result<(), WrapError> {
        match place {
            Place::HoldsTheHome => return Err(refused()),
            Place::InGrant { grant, at } => {
                no_link_between(&grant, &at)?;
                self.in_grants.push(at);
            }
            Place::InHome(at) => {
                self.hidden.insert(at);
            }
            Place::SandboxOwn => {}
            Place::Elsewhere(at) => self.elsewhere.push(at),
        }
        Ok(())
    }
}

/// Every deny entry the compiled file lists, as written and where it really
/// is now.
pub(super) fn resolved_entries(compiled: &CompiledSandbox) -> Vec<(PathBuf, PathBuf)> {
    let root_masks = &compiled.bubblewrap.root_masks;
    let grant_masks = &compiled.bubblewrap.grant_masks;
    paths(&root_masks.denied)
        .chain(paths(&root_masks.denied_elsewhere))
        .chain(paths(&grant_masks.in_workspace))
        .chain(paths(&grant_masks.in_sandbox_home))
        .map(|entry| {
            let real = real_path(&entry);
            (entry, real)
        })
        .collect()
}

/// Refuses a workspace whose real path is a deny entry's or lies inside one.
pub(super) fn refuse_workspace_reaching_an_entry(
    entries: &[(PathBuf, PathBuf)],
    grants: &Grants<'_>,
) -> Result<(), WrapError> {
    for (entry, real) in entries {
        if let Some((written, _)) = grants.present.iter().find(|(_, w)| is_within(w, real)) {
            return Err(WrapError(format!(
                "workspace {} is at or inside {}, which the deny list hides, through a link: write the folder it means, outside the deny list",
                written.display(),
                entry.display()
            )));
        }
    }
    Ok(())
}

/// The entries compile placed inside a grant, as written: the sandbox
/// home's, then each of a workspace that is there. A workspace that is
/// missing gets no mask: bubblewrap binds none.
pub(super) fn in_grants_as_written(
    compiled: &CompiledSandbox,
    grants: &Grants<'_>,
    masks: &mut Masks,
) -> Result<(), WrapError> {
    let grant_masks = &compiled.bubblewrap.grant_masks;
    for entry in paths(&grant_masks.in_sandbox_home) {
        no_link_between(grants.sandbox_home, &entry)?;
        masks.in_grants.push(entry);
    }
    for entry in paths(&grant_masks.in_workspace) {
        let Some(workspace) = grants.workspaces.iter().find(|w| is_within(&entry, w)) else {
            continue;
        };
        if !grants.present.iter().any(|(w, _)| w == workspace) {
            continue;
        }
        no_link_between(workspace, &entry)?;
        masks.in_grants.push(entry);
    }
    Ok(())
}

/// An entry whose real path a workspace holds, through a link the user
/// made, is masked at the workspace's own name for it (`~/cargo` ->
/// `~/.cargo`).
pub(super) fn at_a_workspaces_name(
    entries: &[(PathBuf, PathBuf)],
    grants: &Grants<'_>,
    masks: &mut Masks,
) -> Result<(), WrapError> {
    for (entry, real) in entries {
        for (written, real_workspace) in &grants.present {
            if is_within(entry, written) {
                continue;
            }
            let Ok(rest) = real.strip_prefix(real_workspace) else {
                continue;
            };
            let at = written.join(rest);
            no_link_between(written, &at)?;
            masks.in_grants.push(at);
        }
    }
    Ok(())
}

/// Where an entry leads through a link is masked too, wherever it is, as
/// Seatbelt denies the resolved path (design §15): hiding the name alone
/// leaves what it leads to in the broad read (`~/.ssh -> dotfiles/ssh`).
/// One a workspace holds was masked at the workspace's name for it.
pub(super) fn where_links_lead(
    entries: &[(PathBuf, PathBuf)],
    grants: &Grants<'_>,
    masks: &mut Masks,
) -> Result<(), WrapError> {
    for (entry, real) in entries {
        if real == entry || grants.present.iter().any(|(_, w)| is_within(real, w)) {
            continue;
        }
        masks.put(place(real, grants), || {
            WrapError(format!(
                "deny entry {} leads to {}, which is the home {} or holds it, so it cannot be hidden: point the link elsewhere or take the entry off the deny list",
                entry.display(),
                real.display(),
                grants.home.display()
            ))
        })?;
    }
    Ok(())
}

/// The socket the host's `SSH_AUTH_SOCK` names, masked wherever it really
/// is. One named under the sandbox's own places is hidden there already,
/// whatever link leads elsewhere on the host (`/tmp` on macOS).
pub(super) fn agents_socket(
    socket: &Path,
    grants: &Grants<'_>,
    masks: &mut Masks,
) -> Result<(), WrapError> {
    let place = match place(&real_path(socket), grants) {
        Place::Elsewhere(_) if sandbox_own(socket) => Place::SandboxOwn,
        place => place,
    };
    masks.put(place, || {
        WrapError(format!(
            "SSH_AUTH_SOCK names {}, which is the home {} or holds it, so it cannot be hidden: unset it, or name the agent's socket",
            socket.display(),
            grants.home.display()
        ))
    })
}

/// Of the host's listening sockets, those the home's mask would show the
/// sandbox, each at the path the sandbox reaches it by: under the user's
/// home, but not inside the sandbox's own home or a workspace, which are
/// its own, nor inside a path the home's mask leaves out already. No deny
/// entry names them, and a read-only mount does not stop a connection.
pub(super) fn home_sockets(
    sockets: &[PathBuf],
    grants: &Grants<'_>,
    hidden: &BTreeSet<PathBuf>,
) -> Vec<PathBuf> {
    sockets
        .iter()
        .filter(|socket| socket.is_absolute())
        .filter_map(|socket| match place(&real_path(socket), grants) {
            Place::InHome(at) if !hidden.iter().any(|h| is_within(&at, h)) => Some(at),
            _ => None,
        })
        .collect()
}

/// The folders bound on themselves so the sandbox cannot move them: those
/// compile listed that are there, and each between a grant and a mask in it.
pub(super) fn unmovable(
    listed: &[String],
    in_grants: &[PathBuf],
    grants: &Grants<'_>,
) -> Vec<PathBuf> {
    let mut unmovable: Vec<PathBuf> = paths(listed).filter(|f| f.is_dir()).collect();
    for at in in_grants {
        let grant = std::iter::once(grants.sandbox_home)
            .chain(grants.workspaces.iter().map(PathBuf::as_path))
            .find(|g| is_within(at, g) && at != g);
        if let Some(grant) = grant {
            unmovable.extend(holders(grant, at));
        }
    }
    unmovable.sort();
    unmovable.dedup();
    unmovable
}
