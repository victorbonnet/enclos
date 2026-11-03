//! Where each workspace and deny entry may go: the workspaces refused, and
//! each deny entry placed for its mask, dropped as hidden already, or
//! refused.

use std::path::{Path, PathBuf};

use super::{CompileError, refused};
use crate::backend::SandboxContext;
use crate::policy::paths::{FsPaths, is_within};

/// The sandbox's own, empty places. They hide the host's sockets there
/// (`/run/user/<uid>`, the system bus, systemd-resolved, Docker,
/// `/tmp/.X11-unix`), so a deny entry under one needs no mask.
pub(in crate::backend::bubblewrap) const OWN_TMPFS: &[&str] =
    &["/tmp", "/var/tmp", "/run", "/dev/shm"];

/// The sandbox's own too, and mounted after any mask, so a mask under one
/// would not last.
const OWN_MOUNTS: &[&str] = &["/dev", "/proc"];

/// What a later `--bind` must not uncover: a workspace may not be at or hold
/// one of these. `/var/run` is the host's `/run` through a link.
const MASKED_HOST_PATHS: &[&str] = &[
    "/tmp", "/var/tmp", "/run", "/var/run", "/dev/shm", "/dev", "/proc",
];

/// Whose every folder is the host's: a workspace may not lie inside one,
/// where `/tmp` and `/var/tmp` allow a folder of the host's for a project.
const NO_WORKSPACE_INSIDE: &[&str] = &["/run", "/var/run", "/dev", "/proc"];

/// Refuses a workspace that would undo a mask, that the deny list hides, or
/// that overlaps a protected root.
pub(super) fn check_workspace(
    workspace: &Path,
    deny: &[PathBuf],
    protected: &[PathBuf],
) -> Result<(), CompileError> {
    if undoes_a_masked_host_path(workspace) {
        return Err(refused(format!(
            "workspace {} would bring back the host's {}, which the sandbox has its own of",
            workspace.display(),
            MASKED_HOST_PATHS.join(", ")
        )));
    }
    if let Some(entry) = deny.iter().find(|d| is_within(workspace, d)) {
        return Err(refused(format!(
            "workspace {} is at or inside {}, which the deny list hides, so the sandbox could write nothing there",
            workspace.display(),
            entry.display()
        )));
    }
    if let Some(root) = protected
        .iter()
        .find(|p| is_within(p, workspace) || is_within(workspace, p))
    {
        return Err(refused(format!(
            "workspace {} overlaps {}, which no sandbox may write",
            workspace.display(),
            root.display()
        )));
    }
    Ok(())
}

/// `--bind` comes after the masks of the sandbox's own places, so a workspace
/// at, holding or inside one puts the host's folder and sockets back.
fn undoes_a_masked_host_path(workspace: &Path) -> bool {
    MASKED_HOST_PATHS
        .iter()
        .any(|p| is_within(Path::new(p), workspace))
        || NO_WORKSPACE_INSIDE
            .iter()
            .any(|p| is_within(workspace, Path::new(p)))
}

/// Of enclos's files, what is bound back into the sandbox, read-only and for
/// this sandbox alone. Connecting to a socket needs no write access to its
/// mount (ADR 0004). `secrets` is there only while the sandbox's services
/// run (ADR 0034, ADR 0036), and a session may start without it.
pub(super) struct BoundBack {
    pub(super) visible: PathBuf,
    pub(super) compiled: PathBuf,
    pub(super) secrets: PathBuf,
}

impl BoundBack {
    pub(super) fn of(ctx: &SandboxContext) -> BoundBack {
        BoundBack {
            visible: ctx
                .proxy_socket
                .parent()
                .unwrap_or(&ctx.proxy_socket)
                .to_owned(),
            compiled: ctx.dir.join("compiled"),
            secrets: ctx.secrets.clone(),
        }
    }

    fn holds(&self, entry: &Path) -> bool {
        [&self.visible, &self.compiled, &self.secrets]
            .iter()
            .any(|b| is_within(entry, b))
    }
}

/// What a deny entry is placed against.
pub(super) struct Around<'a> {
    pub(super) home: &'a Path,
    pub(super) user_home: &'a Path,
    pub(super) workspaces: &'a [PathBuf],
    pub(super) protected: &'a [PathBuf],
    pub(super) bound_back: &'a BoundBack,
}

/// Where each deny entry is masked.
#[derive(Debug, Default)]
pub(super) struct Placed {
    pub(super) denied: Vec<PathBuf>,
    pub(super) denied_elsewhere: Vec<PathBuf>,
    pub(super) in_sandbox_home: Vec<PathBuf>,
    pub(super) in_workspace: Vec<PathBuf>,
}

impl Placed {
    pub(super) fn sort(&mut self) {
        for list in [
            &mut self.denied,
            &mut self.denied_elsewhere,
            &mut self.in_sandbox_home,
            &mut self.in_workspace,
        ] {
            list.sort();
            list.dedup();
        }
    }
}

/// Places each deny entry where it is masked, drops one the sandbox hides
/// already, and refuses one that cannot be held.
pub(super) fn place_deny_entries(
    deny: Vec<PathBuf>,
    around: &Around,
) -> Result<Placed, CompileError> {
    let mut placed = Placed::default();
    for entry in deny {
        if is_within(&entry, around.home) {
            placed.in_sandbox_home.push(entry);
            continue;
        }
        // Before the arms that call an entry hidden: a workspace's bind
        // brings back what the tmpfs or a protected root hides.
        if around.workspaces.iter().any(|w| is_within(&entry, w)) {
            placed.in_workspace.push(entry);
            continue;
        }
        if around.bound_back.holds(&entry) {
            return Err(refused(format!(
                "deny entry {} cannot be held: enclos binds that folder into the sandbox",
                entry.display()
            )));
        }
        let hidden = OWN_TMPFS.iter().any(|t| is_within(&entry, Path::new(t)))
            || around.protected.iter().any(|root| is_within(&entry, root));
        if hidden {
            continue;
        }
        if is_within(&entry, around.user_home) && entry != around.user_home {
            placed.denied.push(entry);
        } else if is_within(around.user_home, &entry) {
            return Err(refused(format!(
                "deny entry {} cannot be held: it is the home {} or holds it",
                entry.display(),
                around.user_home.display()
            )));
        } else if OWN_MOUNTS.iter().any(|m| is_within(&entry, Path::new(m))) {
            return Err(refused(format!(
                "deny entry {} cannot be held: the sandbox mounts its own {}",
                entry.display(),
                OWN_MOUNTS.join(" and ")
            )));
        } else {
            placed.denied_elsewhere.push(entry);
        }
    }
    Ok(placed)
}

/// The folders between a grant and a mask in it. The home and workspaces
/// are mounts already, so they are left out.
pub(super) fn unmovable(home: &Path, workspaces: &[PathBuf], placed: &Placed) -> Vec<PathBuf> {
    FsPaths {
        home: home.to_owned(),
        writes: workspaces.to_vec(),
        read_deny: placed
            .in_sandbox_home
            .iter()
            .chain(&placed.in_workspace)
            .cloned()
            .collect(),
    }
    .unmovable()
    .into_iter()
    .filter(|folder| folder != home && !workspaces.contains(folder))
    .collect()
}
