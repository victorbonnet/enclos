//! Compiling a policy for bubblewrap: its arguments, the Landlock rules and
//! the seccomp filter, as one JSON file.
//!
//! Pure: this reads no file, lists no folder and asks nothing of the host,
//! so paths are expanded and tidied as written, never resolved through a
//! link, and the output is the same on any system. What depends on the host
//! is left to `wrap`, at each launch: the masks of the user's home, rebuilt
//! from what it holds then, and a session's variables.

mod place;
#[cfg(test)]
mod tests;

use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::proposed::{self, Unenforced};
use super::seccomp::{self, SeccompFilter};
use crate::backend::{CompileError, Compiled, SandboxContext};
use crate::model::policy::Policy;
use crate::model::sandbox::BackendKind;
use crate::policy::paths::{PathContext, is_within};
use place::{Around, BoundBack, check_workspace, place_deny_entries, unmovable};
pub(super) use place::{OWN_MOUNTS, OWN_TMPFS};

/// Programs may run from these where Landlock applies, and from the
/// sandbox's home, where the runtime installs itself. A workspace may not,
/// unless it lies under one of these: Landlock's rights add up, so `/opt`
/// grants execute to `/opt/proj` as well.
const EXEC_SYSTEM: &[&str] = &[
    "/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32", "/opt", "/snap",
];

/// The ones of [`OWN_TMPFS`] the sandbox writes temporary files in.
const OWN_TEMPORARY: &[&str] = &["/tmp", "/var/tmp", "/dev/shm"];

/// What the file in `compiled/` holds. The relay to the proxy is not a
/// session's: the sandbox's namespace holder serves it (ADR 0039).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompiledSandbox {
    pub bubblewrap: Bubblewrap,
    pub landlock: LandlockRules,
    pub seccomp: SeccompFilter,
    pub unenforced: Vec<Unenforced>,
}

/// bubblewrap's arguments. `wrap` joins them in field order, with the staged
/// files a launch reads after `mounts`, then seals each folder it made and
/// each of `sealed` with `--remount-ro`: a mask comes after the bind of the
/// folder that holds it, and before anything is sealed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bubblewrap {
    /// `--ro-bind / /`: the host's files, read-only.
    pub root: Vec<String>,
    /// Masks over `root`, which `wrap` makes at each launch.
    pub root_masks: RootMasks,
    /// The sandbox's own places, the protected roots outside the user's
    /// home, the writable binds and what is bound read-only.
    pub mounts: Vec<String>,
    /// Masks inside what `mounts` binds writable, which a mask made before
    /// that bind would not survive.
    pub grant_masks: GrantMasks,
    /// The protected folders outside the user's home, each a tmpfs of its
    /// own in `mounts`: `wrap` seals them read-only once what it binds
    /// under them is there.
    pub sealed: Vec<String>,
    /// The namespaces, `--die-with-parent` and `--chdir`, whose place among
    /// the arguments does not matter. No `--clearenv`: `wrap` empties
    /// bubblewrap's own environment and sets the session's there, so no
    /// secret is on its command line.
    pub options: Vec<String>,
}

/// The masks over the host's files, made by `wrap` from what the host holds
/// at each launch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootMasks {
    /// The user's home, where `denied` lies.
    pub home: String,
    /// Deny entries in the user's home: each folder from `home` down that
    /// holds one becomes an empty tmpfs with its other entries bound back.
    pub denied: Vec<String>,
    /// Deny entries outside the user's home that nothing mounted covers: a
    /// tmpfs on a folder, `/dev/null` on a file, nothing on a missing path.
    pub denied_elsewhere: Vec<String>,
}

/// The masks inside the sandbox's home and the workspaces, each made
/// whether or not its path exists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantMasks {
    /// Folders that hold a mask, each bound on itself before the masks, so
    /// renaming or removing one gets `EBUSY`.
    pub unmovable: Vec<String>,
    /// Deny entries inside the sandbox's home.
    pub in_sandbox_home: Vec<String>,
    /// Deny entries inside a workspace.
    pub in_workspace: Vec<String>,
    /// The workspaces, as written: `wrap` resolves each at every launch, and
    /// masks a deny entry whose real path one holds at the workspace's own
    /// name for it.
    pub workspaces: Vec<String>,
}

/// Where each set of rights is granted, beneath each path. The rights of
/// rules over one path add up; all else is refused.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LandlockRules {
    /// Reading files and listing folders.
    pub read: Vec<String>,
    /// Reading, and running programs.
    pub execute: Vec<String>,
    /// Reading, and making, writing, renaming and removing files and folders.
    pub write: Vec<String>,
    /// Reading, writing and truncating files, and `ioctl` on devices.
    pub devices: Vec<String>,
    /// Reading and writing files, as a process does to set its own values.
    pub proc_write: Vec<String>,
    /// Landlock's scopes by name, not paths: what a session may not reach
    /// outside its own Landlock domain.
    pub scoped: Vec<String>,
}

pub fn compile(policy: &Policy, ctx: &SandboxContext) -> Result<Compiled, CompileError> {
    let text = serde_json::to_string_pretty(&compiled_sandbox(policy, ctx)?)
        .map_err(|e| refused(e.to_string()))?;
    Ok(Compiled {
        text: format!("{text}\n"),
        extension: "json",
    })
}

fn compiled_sandbox(
    policy: &Policy,
    ctx: &SandboxContext,
) -> Result<CompiledSandbox, CompileError> {
    let home = tidy(&ctx.home);
    let user_home = tidy(&ctx.user_home);
    let protected = protected_roots(ctx);
    let workspaces: Vec<PathBuf> = expand(&policy.fs.write, ctx)?
        .into_iter()
        .filter(|w| !is_within(w, &home))
        .collect();
    let deny = expand(&policy.fs.read_deny, ctx)?;
    for workspace in &workspaces {
        check_workspace(workspace, &deny, &protected)?;
    }
    // A protected root in the user's home is masked as a deny entry; one
    // elsewhere gets a tmpfs of its own, which `--ro-bind / /` would
    // otherwise show.
    let (in_user_home, elsewhere): (Vec<PathBuf>, Vec<PathBuf>) = protected
        .iter()
        .cloned()
        .partition(|root| is_within(root, &user_home) && *root != user_home);
    let bound_back = BoundBack::of(ctx);
    let around = Around {
        home: &home,
        user_home: &user_home,
        workspaces: &workspaces,
        protected: &protected,
        bound_back: &bound_back,
    };
    let mut placed = place_deny_entries(deny, &around)?;
    placed.denied.extend(in_user_home);
    placed.sort();
    let unmovable = unmovable(&home, &workspaces, &placed);

    Ok(CompiledSandbox {
        bubblewrap: Bubblewrap {
            root: strings(&["--ro-bind", "/", "/"]),
            root_masks: RootMasks {
                home: text(&user_home)?,
                denied: texts(&placed.denied)?,
                denied_elsewhere: texts(&placed.denied_elsewhere)?,
            },
            mounts: mounts(&home, &workspaces, &elsewhere, &bound_back)?,
            grant_masks: GrantMasks {
                unmovable: texts(&unmovable)?,
                in_sandbox_home: texts(&placed.in_sandbox_home)?,
                in_workspace: texts(&placed.in_workspace)?,
                workspaces: texts(&workspaces)?,
            },
            // Writable while bubblewrap makes mount points in them; nothing
            // may write there afterwards.
            sealed: texts(&elsewhere)?,
            options: options(&home)?,
        },
        landlock: landlock_rules(&home, &workspaces)?,
        seccomp: seccomp::filter(),
        unenforced: proposed::unenforced(policy),
    })
}

/// `entries` expanded and tidied as written; one holding `..` is refused.
fn expand(entries: &[String], ctx: &SandboxContext) -> Result<Vec<PathBuf>, CompileError> {
    let paths = PathContext {
        user_home: ctx.user_home.clone(),
        sandbox_home: ctx.home.clone(),
    };
    entries
        .iter()
        .map(|entry| {
            if Path::new(entry).components().any(|c| c == Component::ParentDir) {
                return Err(refused(format!(
                    "`{entry}` holds `..`, which a link can make name another path than the one checked: write the path it means"
                )));
            }
            paths.expand(entry).map(|p| tidy(&p)).map_err(refused)
        })
        .collect()
}

/// The protected roots, each also at its real path: `--ro-bind / /` shows
/// the real folder whatever its spelling is masked with.
fn protected_roots(ctx: &SandboxContext) -> Vec<PathBuf> {
    let mut protected: Vec<PathBuf> = ctx
        .protected
        .iter()
        .chain(&ctx.protected_real)
        .map(|p| tidy(p))
        .collect();
    protected.sort();
    protected.dedup();
    protected
}

/// The sandbox's own places, the protected roots outside the user's home,
/// the writable binds and what is bound back, each after what it lies in.
fn mounts(
    home: &Path,
    workspaces: &[PathBuf],
    elsewhere: &[PathBuf],
    bound_back: &BoundBack,
) -> Result<Vec<String>, CompileError> {
    let mut mounts = strings(&["--dev", "/dev", "--proc", "/proc"]);
    for place in OWN_TMPFS {
        mounts.extend(strings(&["--tmpfs", place]));
    }
    for root in elsewhere {
        mounts.extend(["--tmpfs".to_owned(), text(root)?]);
    }
    mounts.extend(["--bind".to_owned(), text(home)?, text(home)?]);
    // `-try`: a workspace not made yet does not stop the session, as on
    // Seatbelt, where `policy test` reports it as not run (design §5).
    for workspace in workspaces {
        mounts.extend(["--bind-try".to_owned(), text(workspace)?, text(workspace)?]);
    }
    let visible = text(&bound_back.visible)?;
    let compiled = text(&bound_back.compiled)?;
    let secrets = text(&bound_back.secrets)?;
    mounts.extend(strings(&["--ro-bind", &visible, &visible]));
    mounts.extend(strings(&["--ro-bind", &compiled, &compiled]));
    mounts.extend(strings(&["--ro-bind-try", &secrets, &secrets]));
    Ok(mounts)
}

fn options(home: &Path) -> Result<Vec<String>, CompileError> {
    let mut options = strings(proposed::NAMESPACES);
    // No `--clearenv`: `wrap` empties bubblewrap's own environment and sets
    // the session's there, so no secret is on its command line.
    options.extend(strings(&["--die-with-parent"]));
    options.extend(["--chdir".to_owned(), text(home)?]);
    Ok(options)
}

fn landlock_rules(home: &Path, workspaces: &[PathBuf]) -> Result<LandlockRules, CompileError> {
    let mut execute = strings(EXEC_SYSTEM);
    execute.push(text(home)?);
    let mut write = vec![text(home)?];
    write.extend(texts(workspaces)?);
    write.extend(strings(OWN_TEMPORARY));
    Ok(LandlockRules {
        read: strings(&["/"]),
        execute,
        write,
        devices: strings(&["/dev"]),
        proc_write: strings(&["/proc"]),
        scoped: strings(&["abstract_unix_socket", "signal"]),
    })
}

/// `path` without `.` or a trailing `/`, as written: nothing is looked up.
fn tidy(path: &Path) -> PathBuf {
    path.components().collect()
}

fn text(path: &Path) -> Result<String, CompileError> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| refused(format!("{} is not valid UTF-8", path.display())))
}

fn texts(paths: &[PathBuf]) -> Result<Vec<String>, CompileError> {
    paths.iter().map(|p| text(p)).collect()
}

pub(super) fn strings(words: &[&str]) -> Vec<String> {
    words.iter().map(|w| (*w).to_owned()).collect()
}

fn refused(reason: String) -> CompileError {
    CompileError::Unsupported {
        backend: BackendKind::Bubblewrap,
        reason,
    }
}
