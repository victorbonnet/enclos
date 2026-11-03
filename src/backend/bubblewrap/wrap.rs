//! Running a program under bubblewrap (M3-15): the compiled arguments, with
//! the masks that depend on the host made from what it holds at this launch
//! (design §5, What compiling for bubblewrap gives).
//!
//! [`read_host`] looks at the host; [`arguments`] only uses what it is
//! given, so the order of the masks is tested without a host to read.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

use super::compile::{CompiledSandbox, OWN_TMPFS};
use crate::backend::{Launch, SandboxContext, WrapError, environment, under_limits};
use crate::policy::paths::{is_within, real_path};

/// What a mask covers, as the host holds it at launch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Kind {
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
pub(super) struct Entry {
    pub name: OsString,
    /// Where it points, for a link, which is made again as a link.
    pub link: Option<PathBuf>,
}

/// What the masks of one launch depend on, read from the host.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct Host {
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

fn paths(texts: &[String]) -> impl Iterator<Item = PathBuf> + '_ {
    texts.iter().map(PathBuf::from)
}

/// Refuses a link between `grant` and `entry`, which lies inside it: the
/// sandbox writes every folder there, so it could have made the link, and
/// bubblewrap would follow it as it places the mask. `entry` itself may be
/// one: it is masked as itself.
fn no_link_between(grant: &Path, entry: &Path) -> Result<(), WrapError> {
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

/// The folders between `grant` and `entry` that are there, parents first.
fn holders(grant: &Path, entry: &Path) -> Vec<PathBuf> {
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

/// What this launch's masks depend on. `ssh_auth_sock` is the socket the
/// host's `SSH_AUTH_SOCK` names, masked wherever it is.
pub(super) fn read_host(
    compiled: &CompiledSandbox,
    sandbox_home: &Path,
    ssh_auth_sock: Option<&Path>,
) -> Result<Host, WrapError> {
    let root_masks = &compiled.bubblewrap.root_masks;
    let grant_masks = &compiled.bubblewrap.grant_masks;
    let home = PathBuf::from(&root_masks.home);
    let workspaces: Vec<PathBuf> = paths(&grant_masks.workspaces).collect();
    // Each workspace as written, and where it really is now: one reached
    // through a link the user made is bound where it leads.
    let present: Vec<(PathBuf, PathBuf)> = workspaces
        .iter()
        .filter(|w| w.is_dir())
        .map(|w| (w.clone(), real_path(w)))
        .collect();
    let every_entry: Vec<PathBuf> = paths(&root_masks.denied)
        .chain(paths(&root_masks.denied_elsewhere))
        .chain(paths(&grant_masks.in_workspace))
        .chain(paths(&grant_masks.in_sandbox_home))
        .collect();
    let mut host = Host::default();

    for entry in &every_entry {
        let real = real_path(entry);
        for (written, real_workspace) in &present {
            if is_within(real_workspace, &real) {
                return Err(WrapError(format!(
                    "workspace {} is at or inside {}, which the deny list hides, through a link: write the folder it means, outside the deny list",
                    written.display(),
                    entry.display()
                )));
            }
        }
    }

    // Inside a grant: the sandbox home, then each workspace that is there,
    // its entries as written first.
    let mut in_grants: Vec<PathBuf> = Vec::new();
    for entry in paths(&grant_masks.in_sandbox_home) {
        no_link_between(sandbox_home, &entry)?;
        in_grants.push(entry);
    }
    for entry in paths(&grant_masks.in_workspace) {
        let Some(workspace) = workspaces.iter().find(|w| is_within(&entry, w)) else {
            continue;
        };
        // No mask for a workspace that is missing: bubblewrap binds none.
        if !present.iter().any(|(w, _)| w == workspace) {
            continue;
        }
        no_link_between(workspace, &entry)?;
        in_grants.push(entry);
    }
    // An entry whose real path a workspace holds, through a link the user
    // made, is masked at the workspace's own name for it (`~/cargo` ->
    // `~/.cargo`).
    for entry in &every_entry {
        let real = real_path(entry);
        for (written, real_workspace) in &present {
            if is_within(entry, written) || !is_within(&real, real_workspace) {
                continue;
            }
            let Ok(rest) = real.strip_prefix(real_workspace) else {
                continue;
            };
            let at = written.join(rest);
            no_link_between(written, &at)?;
            in_grants.push(at);
        }
    }
    in_grants.sort();
    in_grants.dedup();

    let mut unmovable: Vec<PathBuf> = paths(&grant_masks.unmovable)
        .filter(|f| f.is_dir())
        .collect();
    for at in &in_grants {
        let grant = std::iter::once(sandbox_home)
            .chain(workspaces.iter().map(PathBuf::as_path))
            .find(|g| is_within(at, g) && at != g);
        if let Some(grant) = grant {
            unmovable.extend(holders(grant, at));
        }
    }
    unmovable.sort();
    unmovable.dedup();
    for at in in_grants {
        let kind = Kind::of(&at)?;
        host.in_grants.push((at, kind));
    }
    host.unmovable = unmovable;

    let mut hidden: BTreeSet<PathBuf> = paths(&root_masks.denied).collect();
    let mut elsewhere: Vec<PathBuf> = paths(&root_masks.denied_elsewhere).collect();
    if let Some(socket) = ssh_auth_sock.filter(|s| s.is_absolute()) {
        let socket = socket.to_path_buf();
        let own = OWN_TMPFS.iter().any(|t| is_within(&socket, Path::new(t)));
        let in_grant =
            is_within(&socket, sandbox_home) || workspaces.iter().any(|w| is_within(&socket, w));
        if in_grant {
            let kind = Kind::of(&socket)?;
            host.in_grants.push((socket, kind));
        } else if is_within(&socket, &home) && socket != home {
            hidden.insert(socket);
        } else if !own {
            elsewhere.push(socket);
        }
    }
    elsewhere.sort();
    elsewhere.dedup();
    for path in elsewhere {
        let kind = Kind::of(&path)?;
        host.elsewhere.push((path, kind));
    }

    let roots: Vec<PathBuf> = present.iter().map(|(_, real)| real.clone()).collect();
    walk(&home, &hidden, &roots, &mut host.entries)?;
    host.hidden = hidden;
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

/// What bubblewrap masks a path that is not a folder with: its own
/// `/dev/null`, which `--ro-bind` mounts without its device, so the path
/// opens to nothing and a socket there takes no connection.
const NOT_A_FOLDER: &str = "/dev/null";

/// bubblewrap's arguments for one launch, from [`read_host`]'s `host`, in the
/// order the compiled file names (design §5): the `/` bind, the masks of the
/// home and outside it, the compiled mounts, the unmovable folders, the masks
/// inside the grants, each folder made here sealed read-only, then the
/// options, whose place does not matter.
pub(super) fn arguments(compiled: &CompiledSandbox, host: &Host) -> Vec<OsString> {
    let mut args: Vec<OsString> = Vec::new();
    let mut made: Vec<PathBuf> = Vec::new();
    let push = |args: &mut Vec<OsString>, words: &[&std::ffi::OsStr]| {
        args.extend(words.iter().map(|w| w.to_os_string()));
    };
    let bubblewrap = &compiled.bubblewrap;
    args.extend(bubblewrap.root.iter().map(OsString::from));
    let home = PathBuf::from(&bubblewrap.root_masks.home);
    if host.entries.contains_key(&home) {
        hide(&home, host, &mut args, &mut made);
    }
    for (path, kind) in &host.elsewhere {
        match kind {
            Kind::Folder => {
                push(&mut args, &["--tmpfs".as_ref(), path.as_os_str()]);
                made.push(path.clone());
            }
            Kind::Other => push(
                &mut args,
                &[
                    "--ro-bind".as_ref(),
                    NOT_A_FOLDER.as_ref(),
                    path.as_os_str(),
                ],
            ),
            // Read-only to the sandbox, which cannot make it.
            Kind::Missing => {}
        }
    }
    args.extend(bubblewrap.mounts.iter().map(OsString::from));
    for folder in &host.unmovable {
        push(
            &mut args,
            &["--bind".as_ref(), folder.as_os_str(), folder.as_os_str()],
        );
    }
    for (path, kind) in &host.in_grants {
        match kind {
            // A missing one too: the sandbox writes there and could make it.
            Kind::Folder | Kind::Missing => {
                push(&mut args, &["--tmpfs".as_ref(), path.as_os_str()]);
                made.push(path.clone());
            }
            Kind::Other => push(
                &mut args,
                &[
                    "--ro-bind".as_ref(),
                    NOT_A_FOLDER.as_ref(),
                    path.as_os_str(),
                ],
            ),
        }
    }
    // Writable while bubblewrap made mount points in them.
    for folder in made {
        push(&mut args, &["--remount-ro".as_ref(), folder.as_os_str()]);
    }
    args.extend(bubblewrap.options.iter().map(OsString::from));
    args
}

/// An empty tmpfs on `folder`, with each entry that is neither hidden nor on
/// the way to a hidden path bound back read-only. `--ro-bind-try`: an entry
/// may go between the listing and bubblewrap's start.
fn hide(folder: &Path, host: &Host, args: &mut Vec<OsString>, made: &mut Vec<PathBuf>) {
    args.extend(["--tmpfs".into(), folder.as_os_str().to_owned()]);
    made.push(folder.to_path_buf());
    for entry in host.entries.get(folder).into_iter().flatten() {
        let path = folder.join(&entry.name);
        if host.hidden.contains(&path) {
            continue;
        }
        if let Some(link) = &entry.link {
            args.extend([
                "--symlink".into(),
                link.as_os_str().to_owned(),
                path.into_os_string(),
            ]);
        } else if host.entries.contains_key(&path) {
            hide(&path, host, args, made);
        } else {
            args.extend([
                "--ro-bind-try".into(),
                path.as_os_str().to_owned(),
                path.into_os_string(),
            ]);
        }
    }
}

/// Where enclos and bubblewrap are, for one launch.
pub(super) struct Programs<'a> {
    pub bwrap: &'a Path,
    /// This program, which bubblewrap runs first as `enclos inside`.
    pub enclos: &'a Path,
}

/// The command that runs `launch` under bubblewrap: `enclos inside` first,
/// in the sandbox's environment, which bubblewrap passes on as it is given.
/// It is set on bubblewrap's own process, never with `--setenv`, so no
/// secret is ever on a command line another process can read.
pub(super) fn command(
    programs: &Programs<'_>,
    compiled_path: &Path,
    compiled: &CompiledSandbox,
    host: &Host,
    ctx: &SandboxContext,
    launch: &Launch,
) -> Result<Command, WrapError> {
    let enclos = programs.enclos;
    let root_masks = &compiled.bubblewrap.root_masks;
    if let Some(hidden) = paths(&root_masks.denied)
        .chain(paths(&root_masks.denied_elsewhere))
        .find(|d| is_within(enclos, d))
    {
        return Err(WrapError(format!(
            "enclos runs from {}, inside {}, which the sandbox does not see: install it outside the deny list",
            enclos.display(),
            hidden.display()
        )));
    }
    let mut bwrap = Command::new(programs.bwrap);
    bwrap
        .args(arguments(compiled, host))
        .arg(enclos)
        .args(["inside", "--compiled"])
        .arg(compiled_path);
    bwrap.arg("--").arg(&launch.program).args(&launch.args);
    let mut command = under_limits(bwrap, &launch.limits);
    environment::apply(&mut command, ctx, launch);
    command.current_dir(&ctx.home);
    Ok(command)
}

#[cfg(test)]
mod tests;
