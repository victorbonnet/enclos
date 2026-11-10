//! bubblewrap's arguments for one launch, from what [`super::host`] read:
//! nothing here looks at the host, so the order of the masks is tested
//! without one.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use super::host::{Host, Kind};
use crate::backend::bubblewrap::compile::CompiledSandbox;

/// What bubblewrap masks a path that is not a folder with: its own
/// `/dev/null`, which `--ro-bind` mounts without its device, so the path
/// opens to nothing and a socket there takes no connection.
const NOT_A_FOLDER: &str = "/dev/null";

/// bubblewrap's arguments for one launch, from [`read_host`]'s `host`, in the
/// order the compiled file names (design §5): the `/` bind, the masks of the
/// home and outside it, the home's listening sockets, the compiled mounts, each staged file in `reads`
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
    // Over what the home's mask binds back.
    for socket in &host.sockets {
        push(
            &mut args,
            &[
                "--ro-bind".as_ref(),
                NOT_A_FOLDER.as_ref(),
                socket.as_os_str(),
            ],
        );
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
