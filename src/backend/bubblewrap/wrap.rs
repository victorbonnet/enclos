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

use super::compile::{CompiledSandbox, OWN_MOUNTS, OWN_TMPFS};
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

/// The places a mask can go, as this launch finds them: the home and the
/// sandbox home as written and as they really are, and each workspace.
struct Grants<'a> {
    home: PathBuf,
    real_home: PathBuf,
    sandbox_home: &'a Path,
    real_sandbox_home: PathBuf,
    /// Every workspace, as written.
    workspaces: Vec<PathBuf>,
    /// Each workspace that is there, as written and where it really is: one
    /// reached through a link the user made is bound where it leads.
    present: Vec<(PathBuf, PathBuf)>,
}

impl<'a> Grants<'a> {
    fn read(compiled: &CompiledSandbox, sandbox_home: &'a Path) -> Grants<'a> {
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
struct Masks {
    in_grants: Vec<PathBuf>,
    hidden: BTreeSet<PathBuf>,
    elsewhere: Vec<PathBuf>,
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
fn resolved_entries(compiled: &CompiledSandbox) -> Vec<(PathBuf, PathBuf)> {
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
fn refuse_workspace_reaching_an_entry(
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
fn in_grants_as_written(
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
fn at_a_workspaces_name(
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
fn where_links_lead(
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
fn agents_socket(socket: &Path, grants: &Grants<'_>, masks: &mut Masks) -> Result<(), WrapError> {
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

/// The folders bound on themselves so the sandbox cannot move them: those
/// compile listed that are there, and each between a grant and a mask in it.
fn unmovable(listed: &[String], in_grants: &[PathBuf], grants: &Grants<'_>) -> Vec<PathBuf> {
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
/// workspaces that reach a deny entry refused, the masks inside the grants,
/// where links lead, the agent's socket, the folders that cannot move, then
/// the home's folders listed. `ssh_auth_sock` is the socket the host's
/// `SSH_AUTH_SOCK` names.
pub(super) fn read_host(
    compiled: &CompiledSandbox,
    sandbox_home: &Path,
    ssh_auth_sock: Option<&Path>,
) -> Result<Host, WrapError> {
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

    let mut host = Host {
        unmovable: unmovable(
            &compiled.bubblewrap.grant_masks.unmovable,
            &masks.in_grants,
            &grants,
        ),
        in_grants: with_kinds(masks.in_grants)?,
        elsewhere: with_kinds(masks.elsewhere)?,
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

/// What bubblewrap masks a path that is not a folder with: its own
/// `/dev/null`, which `--ro-bind` mounts without its device, so the path
/// opens to nothing and a socket there takes no connection.
const NOT_A_FOLDER: &str = "/dev/null";

/// bubblewrap's arguments for one launch, from [`read_host`]'s `host`, in the
/// order the compiled file names (design §5): the `/` bind, the masks of the
/// home and outside it, the compiled mounts, each staged file in `reads`
/// read-only at its own path, the unmovable folders, the masks inside the
/// grants, each folder made here and each the compiled file seals, read-only,
/// then the options, whose place does not matter.
pub(super) fn arguments(
    compiled: &CompiledSandbox,
    host: &Host,
    reads: &[PathBuf],
) -> Vec<OsString> {
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
    // The file itself, not its folder: what else is staged there, such as
    // another import's archive, stays out of sight.
    for file in reads {
        push(
            &mut args,
            &["--ro-bind".as_ref(), file.as_os_str(), file.as_os_str()],
        );
    }
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
    for folder in &bubblewrap.sealed {
        push(&mut args, &["--remount-ro".as_ref(), folder.as_ref()]);
    }
    args.extend(bubblewrap.options.iter().map(OsString::from));
    args
}

/// Refuses a staged file the sandbox would read that is not one of the
/// sandbox's `installers/` folder, where the host alone writes: a bind of
/// anything else would show the sandbox more than enclos staged for it.
pub(super) fn staged_only(installers: &Path, reads: &[PathBuf]) -> Result<(), WrapError> {
    for file in reads {
        let named = file.parent() == Some(installers)
            && matches!(
                file.components().next_back(),
                Some(std::path::Component::Normal(_))
            );
        if !named {
            return Err(WrapError(format!(
                "{} is not a file enclos stages in {}, so the sandbox is not shown it",
                file.display(),
                installers.display()
            )));
        }
    }
    Ok(())
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
    staged_only(&ctx.installers, &launch.reads)?;
    let mut bwrap = Command::new(programs.bwrap);
    bwrap
        .args(arguments(compiled, host, &launch.reads))
        .arg(enclos)
        .args(["inside", "--compiled"])
        .arg(compiled_path);
    if launch.in_terminal {
        bwrap.arg(super::INTERRUPTS_FLAG);
    }
    bwrap.arg("--").arg(&launch.program).args(&launch.args);
    let command = match launch.in_terminal {
        true => out_of_reach_of_interrupts(bwrap),
        false => bwrap,
    };
    let mut command = under_limits(command, &launch.limits);
    environment::apply(&mut command, ctx, launch);
    command.current_dir(&ctx.home);
    Ok(command)
}

/// `bwrap` with Ctrl-C and Ctrl-\ ignored, for a command's session, which
/// a terminal may run in, or `connect` passes the signals it catches to.
/// bubblewrap's outer process stays in the session's process group, which a
/// terminal's Ctrl-C reaches, and
/// handles only SIGCHLD: ended so, it would take the whole session with it
/// through `--die-with-parent`, a program that catches SIGINT included,
/// where `connect` waits for its program through Ctrl-C (design §8). An
/// ignored signal stays ignored through `exec`, so `enclos inside` hands
/// both back to the command ([`super::INTERRUPTS_FLAG`]). `/bin/sh` reads no
/// startup file when it runs a command, and none of the sandbox's
/// variables can name a function.
fn out_of_reach_of_interrupts(bwrap: Command) -> Command {
    let mut sh = Command::new("/bin/sh");
    sh.arg("-c")
        .arg("trap '' INT QUIT; exec \"$0\" \"$@\"")
        .arg(bwrap.get_program())
        .args(bwrap.get_args());
    sh
}

#[cfg(test)]
mod tests;
