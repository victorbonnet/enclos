//! Compiling a policy for bubblewrap: its arguments, the Landlock rules and
//! the seccomp filter, as one JSON file (M3-13, `prototype/m3/compile.py`).
//!
//! Pure: this reads no file, lists no folder and asks nothing of the host,
//! so paths are expanded and tidied as written, never resolved through a
//! link, and the output is the same on any system. What depends on the host
//! is left to `wrap`, at each launch (M3-15): which entries the user's home
//! holds, each folder of [`HomeMask`] then rebuilt from them, and a session's
//! variables, which `environment` reads from the host.
//!
//! The deny list is not mounted. The arguments `wrap` runs are
//! `before_home_mask`, what it makes of [`HomeMask`]'s `denied` and
//! `denied_elsewhere`, `after_home_mask`, then its `--remount-ro` for each
//! folder it made.

use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::proposed::{self, Unenforced};
use crate::backend::{CompileError, Compiled, SandboxContext};
use crate::model::policy::Policy;
use crate::model::sandbox::BackendKind;
use crate::policy::paths::{PathContext, is_within};

/// Programs may run from these where Landlock applies, and from the
/// sandbox's home, where the runtime installs itself; workspaces may not.
const EXEC_SYSTEM: &[&str] = &[
    "/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32", "/opt", "/snap",
];

/// The sandbox's own, empty places. They hide the host's sockets there
/// (`/run/user/<uid>`, the system bus, systemd-resolved, Docker,
/// `/tmp/.X11-unix`), so a deny entry under one needs no mask.
const OWN_TMPFS: &[&str] = &["/tmp", "/var/tmp", "/run", "/dev/shm"];

/// The ones of [`OWN_TMPFS`] the sandbox writes temporary files in.
const OWN_TEMPORARY: &[&str] = &["/tmp", "/var/tmp", "/dev/shm"];

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

/// Refused with `EPERM`: design §14's list, then the kernel module, reboot
/// and swap calls, and io_uring, whose operations seccomp does not see.
/// The same on every architecture: the program that applies the filter
/// skips a name its own lacks (M3-14).
const SECCOMP_DENY: &[&str] = &[
    "keyctl",
    "add_key",
    "request_key",
    "bpf",
    "perf_event_open",
    "userfaultfd",
    "mount",
    "umount2",
    "pivot_root",
    "move_mount",
    "open_tree",
    "fsopen",
    "fsconfig",
    "fsmount",
    "fspick",
    "mount_setattr",
    "setns",
    "kexec_load",
    "kexec_file_load",
    "init_module",
    "finit_module",
    "delete_module",
    "reboot",
    "swapon",
    "swapoff",
    "acct",
    "quotactl",
    "quotactl_fd",
    "ioperm",
    "iopl",
    "open_by_handle_at",
    "uselib",
    "io_uring_setup",
    "io_uring_enter",
    "io_uring_register",
];

/// `ioctl` requests refused, compared on their low 32 bits as the kernel does.
const SECCOMP_IOCTL: &[(&str, u64)] = &[("TIOCLINUX", 0x541C), ("TIOCSTI", 0x5412)];

/// Namespace flags refused in `unshare` and `clone`.
const CLONE_NEW: &[(&str, u64)] = &[
    ("CLONE_NEWCGROUP", 0x0200_0000),
    ("CLONE_NEWIPC", 0x0800_0000),
    ("CLONE_NEWNET", 0x4000_0000),
    ("CLONE_NEWNS", 0x0002_0000),
    ("CLONE_NEWPID", 0x2000_0000),
    ("CLONE_NEWTIME", 0x0000_0080),
    ("CLONE_NEWUSER", 0x1000_0000),
    ("CLONE_NEWUTS", 0x0400_0000),
];

/// `clone3` holds its flags in memory seccomp cannot read: `ENOSYS` makes
/// the C library fall back to `clone`.
const SECCOMP_ENOSYS: &[&str] = &["clone3"];

/// The only families `socket` may open. `--unshare-net` holds these, and may
/// not hold others: `AF_VSOCK` reaches a host's hypervisor past the proxy, and
/// `AF_ALG` and the like are kernel surface nothing here uses. What is listed
/// is what ADR 0004's "no network except a Unix socket" leaves, with loopback
/// and netlink, which C libraries and Chromium ask for.
const SOCKET_FAMILIES: &[(&str, u64)] = &[
    ("AF_INET", 2),
    ("AF_INET6", 10),
    ("AF_NETLINK", 16),
    ("AF_UNIX", 1),
];

/// What the file in `compiled/` holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompiledSandbox {
    pub before_home_mask: Vec<String>,
    pub home_mask: HomeMask,
    pub after_home_mask: Vec<String>,
    pub landlock: LandlockRules,
    pub seccomp: SeccompFilter,
    pub relay: Relay,
    pub unenforced: Vec<Unenforced>,
}

/// The masks `wrap` makes at each launch from what the home holds then.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HomeMask {
    /// The user's home. Each folder from here down that holds a path of
    /// `denied` becomes an empty tmpfs with its other entries bound back
    /// read-only, so a denied path does not exist in the sandbox.
    pub home: String,
    pub denied: Vec<String>,
    /// Deny entries outside the user's home that nothing the sandbox mounts
    /// covers. `wrap` masks each after the `/` bind: a tmpfs on a folder,
    /// `/dev/null` on a file, nothing if it is missing, since this area is
    /// read-only to the sandbox and it cannot be made there.
    pub denied_elsewhere: Vec<String>,
    /// Deny entries inside the sandbox's home, which is bound writable:
    /// masked one by one after that bind.
    pub in_sandbox_home: Vec<String>,
    /// Deny entries inside a workspace, masked the same way after its bind.
    pub in_workspace: Vec<String>,
}

/// What each kind of access is granted beneath; all else is refused.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LandlockRules {
    pub read: Vec<String>,
    pub execute: Vec<String>,
    pub write: Vec<String>,
    pub devices: Vec<String>,
    pub proc_write: Vec<String>,
    pub scoped: Vec<String>,
}

/// What the filter refuses; anything else is allowed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeccompFilter {
    pub errno: String,
    pub deny: Vec<String>,
    pub ioctl: BTreeMap<String, u64>,
    pub clone_flags: BTreeMap<String, u64>,
    pub enosys: Vec<String>,
    /// The families `socket` may open; M3-14 refuses any other, with `errno`.
    pub socket_families: BTreeMap<String, u64>,
}

/// The relay to the sandbox's proxy, in a session's own network namespace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Relay {
    pub port: u16,
    pub socket: String,
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
    let paths = PathContext {
        user_home: ctx.user_home.clone(),
        sandbox_home: ctx.home.clone(),
    };
    let expand = |entries: &[String]| -> Result<Vec<PathBuf>, CompileError> {
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
    };
    let home = tidy(&ctx.home);
    let user_home = tidy(&ctx.user_home);
    // A root behind a link is two folders to hide: `--ro-bind / /` shows the
    // real one whatever its spelling is masked with.
    let mut protected: Vec<PathBuf> = ctx
        .protected
        .iter()
        .chain(&ctx.protected_real)
        .map(|p| tidy(p))
        .collect();
    protected.sort();
    protected.dedup();
    let workspaces: Vec<PathBuf> = expand(&policy.fs.write)?
        .into_iter()
        .filter(|w| !is_within(w, &home))
        .collect();
    let deny = expand(&policy.fs.read_deny)?;

    for workspace in &workspaces {
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
    }

    // A protected root in the user's home is masked as a deny entry; one
    // elsewhere gets a tmpfs of its own, which `--ro-bind / /` would
    // otherwise show. Everything of enclos's lies under one of them, so
    // only what is bound below is left: `members/`, other sandboxes and
    // the rest of `run/` stay out.
    let (in_user_home, elsewhere): (Vec<PathBuf>, Vec<PathBuf>) = protected
        .iter()
        .cloned()
        .partition(|root| is_within(root, &user_home) && *root != user_home);
    // Read-only, for this sandbox alone. Connecting to a socket needs no
    // write access to its mount (ADR 0004). `secrets/` is there only while
    // the sandbox's services run (ADR 0034, ADR 0036), and a session may
    // start without them.
    let visible = ctx.proxy_socket.parent().unwrap_or(&ctx.proxy_socket);
    let compiled = ctx.dir.join("compiled");
    let bound_back = [visible, compiled.as_path(), ctx.secrets.as_path()];
    let mut denied = in_user_home.clone();
    let mut denied_elsewhere = Vec::new();
    let mut in_sandbox_home = Vec::new();
    let mut in_workspace = Vec::new();
    for entry in deny {
        if is_within(&entry, &home) {
            in_sandbox_home.push(entry);
        // First of the rest: a workspace's bind undoes the arms below it.
        } else if workspaces.iter().any(|w| is_within(&entry, w)) {
            in_workspace.push(entry);
        } else if bound_back.iter().any(|b| is_within(&entry, b)) {
            return Err(refused(format!(
                "deny entry {} cannot be held: enclos binds that folder into the sandbox",
                entry.display()
            )));
        } else if OWN_TMPFS.iter().any(|t| is_within(&entry, Path::new(t)))
            || protected.iter().any(|root| is_within(&entry, root))
        {
            // Hidden already.
        } else if is_within(&entry, &user_home) && entry != user_home {
            denied.push(entry);
        } else if is_within(&user_home, &entry) {
            return Err(refused(format!(
                "deny entry {} cannot be held: it is the home {} or holds it",
                entry.display(),
                user_home.display()
            )));
        } else if OWN_MOUNTS.iter().any(|m| is_within(&entry, Path::new(m))) {
            return Err(refused(format!(
                "deny entry {} cannot be held: the sandbox mounts its own {}",
                entry.display(),
                OWN_MOUNTS.join(" and ")
            )));
        } else {
            denied_elsewhere.push(entry);
        }
    }
    denied.sort();
    denied.dedup();
    denied_elsewhere.sort();
    denied_elsewhere.dedup();
    in_sandbox_home.sort();
    in_sandbox_home.dedup();
    in_workspace.sort();
    in_workspace.dedup();

    let mut after = args(&["--dev", "/dev", "--proc", "/proc"]);
    for place in OWN_TMPFS {
        after.extend(args(&["--tmpfs", place]));
    }
    for root in &elsewhere {
        after.extend(["--tmpfs".to_owned(), text(root)?]);
    }
    after.extend(["--bind".to_owned(), text(&home)?, text(&home)?]);
    // `-try`: a workspace not made yet does not stop the session, as on
    // Seatbelt, where `policy test` reports it as not run (design §5).
    for workspace in &workspaces {
        after.extend(["--bind-try".to_owned(), text(workspace)?, text(workspace)?]);
    }
    let [visible, compiled, secrets] = bound_back.map(text);
    let (visible, compiled, secrets) = (visible?, compiled?, secrets?);
    after.extend(args(&["--ro-bind", &visible, &visible]));
    after.extend(args(&["--ro-bind", &compiled, &compiled]));
    after.extend(args(&["--ro-bind-try", &secrets, &secrets]));
    // Writable while bubblewrap made mount points in it; nothing may write
    // there afterwards.
    for root in &elsewhere {
        after.extend(["--remount-ro".to_owned(), text(root)?]);
    }
    after.extend(args(proposed::NAMESPACES));
    after.extend(args(&["--die-with-parent", "--clearenv"]));
    after.extend(["--chdir".to_owned(), text(&home)?]);

    let mut execute = strings(EXEC_SYSTEM);
    execute.push(text(&home)?);
    let mut write = texts(std::iter::once(&home).chain(&workspaces))?;
    write.extend(strings(OWN_TEMPORARY));

    Ok(CompiledSandbox {
        before_home_mask: args(&["--ro-bind", "/", "/"]),
        home_mask: HomeMask {
            home: text(&user_home)?,
            denied: texts(&denied)?,
            denied_elsewhere: texts(&denied_elsewhere)?,
            in_sandbox_home: texts(&in_sandbox_home)?,
            in_workspace: texts(&in_workspace)?,
        },
        after_home_mask: after,
        landlock: LandlockRules {
            read: strings(&["/"]),
            execute,
            write,
            devices: strings(&["/dev"]),
            proc_write: strings(&["/proc"]),
            scoped: strings(&["abstract_unix_socket", "signal"]),
        },
        seccomp: SeccompFilter {
            errno: "EPERM".to_owned(),
            deny: strings(SECCOMP_DENY),
            ioctl: named(SECCOMP_IOCTL),
            clone_flags: named(CLONE_NEW),
            enosys: strings(SECCOMP_ENOSYS),
            socket_families: named(SOCKET_FAMILIES),
        },
        relay: Relay {
            port: ctx.proxy_port,
            socket: text(&ctx.proxy_socket)?,
        },
        unenforced: proposed::unenforced(policy),
    })
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

/// `path` without `.` or a trailing `/`, as written: nothing is looked up.
fn tidy(path: &Path) -> PathBuf {
    path.components().collect()
}

fn text(path: &Path) -> Result<String, CompileError> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| refused(format!("{} is not valid UTF-8", path.display())))
}

fn texts<'a>(paths: impl IntoIterator<Item = &'a PathBuf>) -> Result<Vec<String>, CompileError> {
    paths.into_iter().map(|p| text(p)).collect()
}

fn args(words: &[&str]) -> Vec<String> {
    strings(words)
}

fn strings(words: &[&str]) -> Vec<String> {
    words.iter().map(|w| (*w).to_owned()).collect()
}

fn named(values: &[(&str, u64)]) -> BTreeMap<String, u64> {
    values.iter().map(|(n, v)| ((*n).to_owned(), *v)).collect()
}

fn refused(reason: String) -> CompileError {
    CompileError::Unsupported {
        backend: BackendKind::Bubblewrap,
        reason,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layout::{Layout, Os};
    use crate::model::policy::TemplateName;
    use crate::policy::paths::real_path;
    use crate::policy::{initial_overrides, resolve};

    const USER: &str = "/nonexistent-enclos-test/alice";

    /// `layout` as Linux protects it, whichever system runs the test.
    fn on_linux(layout: &Layout) -> SandboxContext {
        let mut ctx = SandboxContext::new(layout, &"home".parse().unwrap(), 41001);
        ctx.protected = layout.protected_on(Os::Linux);
        ctx.protected_real = ctx.protected.iter().map(|p| real_path(p)).collect();
        ctx
    }

    fn ctx() -> SandboxContext {
        on_linux(&Layout::at(format!("{USER}/.enclos")))
    }

    /// What every compile masks in the home of [`ctx`], and `also`.
    fn protected_and(also: &[&str]) -> Vec<String> {
        let mut denied: Vec<String> = [
            ".config/systemd/user",
            ".enclos",
            ".local/share/systemd/user",
        ]
        .iter()
        .chain(also)
        .map(|e| format!("{USER}/{e}"))
        .collect();
        denied.sort();
        denied
    }

    fn policy(write: &[&str], deny: &[&str]) -> Policy {
        let mut p = Policy::default();
        p.fs.write = write.iter().map(|e| (*e).to_owned()).collect();
        p.fs.read_deny = deny.iter().map(|e| (*e).to_owned()).collect();
        p
    }

    fn compiled(p: &Policy) -> CompiledSandbox {
        compiled_sandbox(p, &ctx()).unwrap()
    }

    /// The value after each `option` in `words`.
    fn after<'a>(words: &'a [String], option: &str) -> Vec<&'a str> {
        words
            .iter()
            .enumerate()
            .filter(|(_, w)| *w == option)
            .map(|(i, _)| words[i + 1].as_str())
            .collect()
    }

    fn refusal(p: &Policy) -> String {
        compiled_sandbox(p, &ctx()).unwrap_err().to_string()
    }

    /// Runs on every system against one file each, so a template's output
    /// that came to depend on the host fails on the others.
    #[test]
    fn each_template_compiles_to_its_snapshot() {
        for (template, expected) in [
            ("assistant", include_str!("assistant.snapshot")),
            ("minimal", include_str!("minimal.snapshot")),
        ] {
            let name: TemplateName = template.parse().unwrap();
            let snap = resolve(&initial_overrides("home", &name), None).unwrap();
            let text = compile(&snap.policy, &ctx()).unwrap().text;
            if std::env::var_os("ENCLOS_WRITE_SNAPSHOTS").is_some() {
                let file = Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join(format!("src/backend/bubblewrap/{template}.snapshot"));
                std::fs::write(file, &text).unwrap();
                continue;
            }
            assert_eq!(text, expected, "{template}");
            let read: CompiledSandbox = serde_json::from_str(&text).unwrap();
            assert_eq!(read, compiled(&snap.policy));
        }
    }

    #[test]
    fn a_denied_path_is_named_for_the_mask_and_never_bound() {
        let c = compiled(&policy(&["{home}"], &["~/.ssh", "~/.config/google-chrome"]));
        assert_eq!(c.home_mask.home, USER);
        assert_eq!(
            c.home_mask.denied,
            protected_and(&[".config/google-chrome", ".ssh"])
        );
        assert_eq!(c.before_home_mask, ["--ro-bind", "/", "/"]);
        assert!(!c.after_home_mask.iter().any(|a| a.contains("/.ssh")));
    }

    /// A session starts without a workspace not made yet, as on Seatbelt,
    /// and `policy test` reports it as not run (design §5). The sandbox's
    /// home is enclos's own, so a missing one stops the session.
    #[test]
    fn a_workspace_not_made_yet_does_not_stop_the_session() {
        let c = compiled(&policy(&["{home}", "~/proj"], &[]));
        let args = &c.after_home_mask;
        assert_eq!(
            after(args, "--bind"),
            [format!("{USER}/.enclos/sandboxes/home/home")]
        );
        assert_eq!(after(args, "--bind-try"), [format!("{USER}/proj")]);
    }

    /// `/run/user` is on the default deny list, and `--tmpfs /run` hides it.
    #[test]
    fn a_deny_entry_under_the_sandboxs_own_tmpfs_needs_no_mask() {
        let c = compiled(&policy(&["{home}"], &["/run/user", "/tmp/x"]));
        assert_eq!(c.home_mask.denied, protected_and(&[]));
        assert!(c.home_mask.denied_elsewhere.is_empty());
    }

    #[test]
    fn the_masked_host_paths_come_after_the_devices_whatever_the_policy() {
        let c = compiled(&Policy::default());
        assert_eq!(
            after(&c.after_home_mask, "--tmpfs"),
            ["/tmp", "/var/tmp", "/run", "/dev/shm"]
        );
        let at = |word: &str| c.after_home_mask.iter().position(|a| a == word).unwrap();
        assert!(at("--dev") < at("--tmpfs"));
        assert!(at("--tmpfs") < at("--bind"));
    }

    #[test]
    fn the_protected_paths_are_masked_whatever_the_policy_says() {
        let c = compiled(&policy(&[], &[]));
        assert_eq!(c.home_mask.denied, protected_and(&[]));
    }

    /// Outside the home no mask reaches them, so each gets its own tmpfs,
    /// sealed once what is bound in it is there.
    #[test]
    fn protected_folders_outside_the_home_are_hidden_and_sealed() {
        let layout = Layout::at("/srv/enclos").with_user_home(USER);
        let ctx = on_linux(&layout);
        let c = compiled_sandbox(&policy(&["{home}"], &[]), &ctx).unwrap();
        let args = &c.after_home_mask;
        assert_eq!(
            c.home_mask.denied,
            [
                format!("{USER}/.config/systemd/user"),
                format!("{USER}/.local/share/systemd/user")
            ]
        );
        assert!(after(args, "--tmpfs").contains(&"/srv/enclos"));
        assert_eq!(after(args, "--remount-ro"), ["/srv/enclos"]);
        let last_mount = args
            .iter()
            .rposition(|a| a.starts_with("--ro-bind") || a == "--bind")
            .unwrap();
        let sealed = args.iter().position(|a| a == "--remount-ro").unwrap();
        assert!(last_mount < sealed);
    }

    /// `--ro-bind / /` shows the real folder, so a mask on the spelled path
    /// alone leaves `secrets.json` and `state.db` readable behind a link.
    #[test]
    fn a_protected_root_behind_a_link_is_hidden_at_its_real_path_too() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().canonicalize().unwrap();
        let real = base.join("ssd/enclos");
        let user = base.join("user");
        std::fs::create_dir_all(&real).unwrap();
        std::fs::create_dir_all(&user).unwrap();
        std::os::unix::fs::symlink(&real, user.join("e")).unwrap();
        let layout = Layout::at(user.join("e")).with_user_home(&user);
        let ctx = on_linux(&layout);
        let real = real.to_str().unwrap();
        let c = compiled_sandbox(&policy(&["{home}"], &[]), &ctx).unwrap();
        let args = &c.after_home_mask;
        assert!(
            c.home_mask
                .denied
                .contains(&format!("{}/e", user.display()))
        );
        assert!(after(args, "--tmpfs").contains(&real), "{args:?}");
        assert!(after(args, "--remount-ro").contains(&real), "{args:?}");
        let hidden = args.iter().position(|a| a == real).unwrap();
        let bound = args.iter().position(|a| a == "--bind").unwrap();
        assert!(hidden < bound, "{args:?}");
    }

    /// The real path is another protected root for a workspace too.
    #[test]
    fn a_workspace_on_a_protected_roots_real_path_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().canonicalize().unwrap();
        let real = base.join("ssd/enclos");
        std::fs::create_dir_all(&real).unwrap();
        std::os::unix::fs::symlink(&real, base.join("e")).unwrap();
        let ctx = on_linux(&Layout::at(base.join("e")).with_user_home(&base));
        let inside = format!("{}/sandboxes", real.display());
        let err = compiled_sandbox(&policy(&[&inside], &[]), &ctx)
            .unwrap_err()
            .to_string();
        assert!(err.contains("overlaps"), "{err}");
    }

    #[test]
    fn the_sandbox_gets_its_own_folders_and_only_those() {
        let c = compiled(&policy(&["{home}", "~/proj"], &[]));
        let args = &c.after_home_mask;
        let sandbox = format!("{USER}/.enclos/sandboxes/home");
        assert_eq!(after(args, "--bind"), [format!("{sandbox}/home")]);
        assert_eq!(after(args, "--bind-try"), [format!("{USER}/proj")]);
        assert_eq!(
            after(args, "--ro-bind"),
            [
                format!("{USER}/.enclos/run/home/visible"),
                format!("{sandbox}/compiled")
            ]
        );
        assert_eq!(after(args, "--ro-bind-try"), [format!("{sandbox}/secrets")]);
        assert_eq!(
            c.relay.socket,
            format!("{USER}/.enclos/run/home/visible/proxy.sock")
        );
        assert_eq!(c.relay.port, 41001);
        let mounted = args.join(" ");
        assert!(!mounted.contains("members"), "{mounted}");
    }

    #[test]
    fn writes_go_to_the_home_workspaces_and_temporary_places_and_programs_not_to_workspaces() {
        let c = compiled(&policy(&["{home}", "~/proj"], &[]));
        let home = format!("{USER}/.enclos/sandboxes/home/home");
        let proj = format!("{USER}/proj");
        assert_eq!(
            c.landlock.write,
            [home.as_str(), &proj, "/tmp", "/var/tmp", "/dev/shm"]
        );
        assert!(c.landlock.execute.contains(&home));
        assert!(!c.landlock.execute.contains(&proj));
    }

    #[test]
    fn a_session_has_its_own_namespaces_an_empty_environment_and_no_user_namespace() {
        let c = compiled(&Policy::default());
        for option in [
            "--unshare-user",
            "--disable-userns",
            "--unshare-pid",
            "--unshare-net",
            "--unshare-ipc",
            "--clearenv",
            "--die-with-parent",
        ] {
            assert!(c.after_home_mask.iter().any(|a| a == option), "{option}");
        }
    }

    /// A network namespace may not hold vsock, so the filter does, for a
    /// host that is itself a VM: only these families may be opened.
    #[test]
    fn the_filter_allows_only_the_socket_families_a_session_uses() {
        let families = compiled(&Policy::default()).seccomp.socket_families;
        assert_eq!(
            families.into_iter().collect::<Vec<_>>(),
            [
                ("AF_INET".to_owned(), 2),
                ("AF_INET6".to_owned(), 10),
                ("AF_NETLINK".to_owned(), 16),
                ("AF_UNIX".to_owned(), 1)
            ]
        );
    }

    #[test]
    fn the_filter_refuses_the_listed_calls() {
        let s = compiled(&Policy::default()).seccomp;
        assert_eq!(s.deny.len(), 35);
        assert_eq!(s.ioctl["TIOCSTI"], 0x5412);
        assert_eq!(s.clone_flags["CLONE_NEWUSER"], 0x1000_0000);
        assert_eq!(s.clone_flags.len(), 8);
        assert_eq!(s.enosys, ["clone3"]);
    }

    /// A Mac's `/opt/secrets` and LXD's folder are held the same way:
    /// nothing else stops `connect` to a socket a read-only mount shows.
    #[test]
    fn a_deny_entry_outside_the_home_is_listed_for_a_mask() {
        let c = compiled(&policy(
            &["{home}"],
            &["/opt/secrets", "/var/snap/lxd", "/var/run/docker.sock"],
        ));
        assert_eq!(
            c.home_mask.denied_elsewhere,
            ["/opt/secrets", "/var/run/docker.sock", "/var/snap/lxd"]
        );
        assert_eq!(c.home_mask.denied, protected_and(&[]));
    }

    #[test]
    fn the_default_list_compiles_with_its_entries_outside_the_home_masked() {
        let name: TemplateName = "minimal".parse().unwrap();
        let snap = resolve(&initial_overrides("home", &name), None).unwrap();
        let c = compiled(&snap.policy);
        assert_eq!(
            c.home_mask.denied_elsewhere,
            ["/var/lib/incus", "/var/lib/lxd", "/var/snap/lxd"]
        );
    }

    /// The home, or what holds it, cannot be masked and still be the home;
    /// and `/dev` and `/proc` are the sandbox's own, mounted after any mask.
    #[test]
    fn a_deny_entry_that_cannot_be_held_is_refused() {
        for entry in [
            "~",
            "/nonexistent-enclos-test",
            "/",
            "/proc/sys",
            "/dev/sda",
        ] {
            let err = refusal(&policy(&["{home}"], &[entry]));
            assert!(err.contains("cannot be held"), "{entry}: {err}");
        }
    }

    #[test]
    fn a_workspace_at_or_inside_a_deny_entry_is_refused() {
        for workspace in ["~/dev/work", "~/dev/work/child"] {
            let err = refusal(&policy(&[workspace], &["~/dev/work"]));
            assert!(err.contains("deny list hides"), "{workspace}: {err}");
        }
    }

    /// The default list's Photos entry must not stop `~/Pictures` on Linux.
    #[test]
    fn a_deny_entry_inside_a_workspace_is_kept_for_a_mask_after_its_bind() {
        let entry = format!("{USER}/Pictures/Photos Library.photoslibrary");
        let c = compiled(&policy(
            &["~/Pictures"],
            &["~/Pictures/Photos Library.photoslibrary"],
        ));
        assert_eq!(c.home_mask.in_workspace, [entry.clone()]);
        assert_eq!(c.home_mask.denied, protected_and(&[]));
        assert!(!c.after_home_mask.contains(&entry));
    }

    /// Before the arms for what is hidden already: the workspace's bind
    /// brings back what the tmpfs or a protected root would have hidden.
    #[test]
    fn a_deny_entry_inside_a_workspace_under_the_sandboxs_own_tmpfs_is_masked() {
        let c = compiled(&policy(&["/tmp/proj"], &["/tmp/proj/.env"]));
        assert_eq!(c.home_mask.in_workspace, ["/tmp/proj/.env"]);
    }

    /// `~/.cargo` granted: the login the host trusts must not be writable,
    /// whether or not it exists yet, and nothing here looks.
    #[test]
    fn a_deny_entry_inside_a_workspace_is_listed_whether_or_not_it_exists() {
        let c = compiled(&policy(
            &["~/.cargo", "/nonexistent-enclos-test/proj"],
            &[
                "~/.cargo/credentials.toml",
                "/nonexistent-enclos-test/proj/.env",
            ],
        ));
        assert_eq!(
            c.home_mask.in_workspace,
            [
                "/nonexistent-enclos-test/alice/.cargo/credentials.toml",
                "/nonexistent-enclos-test/proj/.env"
            ]
        );
    }

    /// `--tmpfs /tmp` then `--bind /tmp /tmp` would bring back the host's
    /// X11 and agent sockets; `/var/run` the host's `/run`.
    #[test]
    fn a_workspace_that_would_undo_a_masked_host_path_is_refused() {
        for workspace in [
            "/",
            "/tmp",
            "/var",
            "/var/tmp",
            "/run",
            "/var/run",
            "/dev",
            "/dev/shm",
            "/proc",
            "/run/user",
            "/run/user/1000",
            "/var/run/docker",
            "/dev/shm/x",
            "/dev/pts",
            "/proc/self",
        ] {
            let err = refusal(&policy(&[workspace], &[]));
            assert!(err.contains("host's"), "{workspace}: {err}");
        }
    }

    #[test]
    fn a_workspace_in_a_temporary_place_is_allowed() {
        for workspace in ["/tmp/proj", "/var/tmp/proj"] {
            let c = compiled(&policy(&[workspace], &[]));
            assert!(c.landlock.write.contains(&workspace.to_owned()));
        }
    }

    #[test]
    fn a_workspace_that_overlaps_a_protected_path_is_refused() {
        for workspace in ["~/.enclos", "~/.enclos/run"] {
            let err = refusal(&policy(&[workspace], &[]));
            assert!(err.contains("overlaps"), "{workspace}: {err}");
        }
    }

    /// The home is bound writable after the masks, so its entries are named
    /// apart, for masks that come after that bind.
    #[test]
    fn a_deny_entry_in_the_sandbox_home_is_kept_for_its_own_mask() {
        let c = compiled(&policy(&["{home}"], &["{home}/private"]));
        assert_eq!(
            c.home_mask.in_sandbox_home,
            [format!("{USER}/.enclos/sandboxes/home/home/private")]
        );
    }

    #[test]
    fn an_entry_that_holds_the_home_leaves_it_bound() {
        let c = compiled(&policy(&["{home}"], &["~/.enclos/sandboxes"]));
        assert_eq!(c.home_mask.denied, protected_and(&[]));
        assert!(after(&c.after_home_mask, "--bind")[0].ends_with("/sandboxes/home/home"));
    }

    /// These folders are bound back after a protected root is hidden, so
    /// such an entry would be dropped as hidden and silently not held.
    #[test]
    fn a_deny_entry_in_what_compile_binds_back_is_refused() {
        for entry in [
            "~/.enclos/sandboxes/home/secrets",
            "~/.enclos/sandboxes/home/secrets/bot.env",
            "~/.enclos/sandboxes/home/compiled",
            "~/.enclos/run/home/visible",
            "~/.enclos/run/home/visible/proxy.sock",
        ] {
            let err = refusal(&policy(&["{home}"], &[entry]));
            assert!(err.contains("cannot be held"), "{entry}: {err}");
        }
    }

    /// Other sandboxes' folders are not bound in: hidden is true of them.
    #[test]
    fn a_deny_entry_under_a_protected_root_and_not_bound_back_stays_hidden() {
        let c = compiled(&policy(&["{home}"], &["~/.enclos/sandboxes/other/secrets"]));
        assert_eq!(c.home_mask.denied, protected_and(&[]));
    }

    /// Nothing of the host reaches the output: a link stays as written, and
    /// neither what a home holds nor a new entry in it changes anything.
    #[test]
    fn compiling_looks_at_nothing_on_the_host() {
        let dir = tempfile::tempdir().unwrap();
        let user = dir.path().canonicalize().unwrap();
        let layout = Layout::at(user.join(".enclos")).with_user_home(&user);
        let ctx = SandboxContext::new(&layout, &"home".parse().unwrap(), 41001);
        std::fs::create_dir(user.join("real")).unwrap();
        std::os::unix::fs::symlink(user.join("real"), user.join("link")).unwrap();
        let p = policy(&["{home}", "~/link"], &["~/.ssh"]);
        let first = compile(&p, &ctx).unwrap().text;
        assert!(
            first.contains(&format!("{}/link", user.display())),
            "{first}"
        );
        assert!(!first.contains("/real"), "{first}");
        std::fs::write(user.join("new-entry"), "").unwrap();
        assert_eq!(compile(&p, &ctx).unwrap().text, first);
    }

    /// With `~/l -> /data/x/y`, `validate` reads `~/l/../secret` as
    /// `/data/x/secret`: taking `..` on the text would mask `~/secret`.
    #[test]
    fn an_entry_holding_dot_dot_is_refused() {
        for (write, deny) in [
            (vec!["{home}"], vec!["~/l/../secret"]),
            (vec!["{home}", "~/l/../work"], vec![]),
            (vec!["{home}"], vec!["{home}/../x"]),
        ] {
            let err = refusal(&policy(&write, &deny));
            assert!(err.contains("`..`"), "{write:?} {deny:?}: {err}");
        }
    }

    #[test]
    fn tidying_a_path_only_reads_its_text() {
        assert_eq!(tidy(Path::new("/a/./b/c/")), Path::new("/a/b/c"));
        assert_eq!(tidy(Path::new("/a/../b")), Path::new("/a/../b"));
    }

    #[test]
    fn a_path_that_is_not_text_is_refused() {
        use std::os::unix::ffi::OsStrExt;
        let name = std::ffi::OsStr::from_bytes(b"/a/\xff");
        let err = text(Path::new(name)).unwrap_err().to_string();
        assert!(err.contains("not valid UTF-8"), "{err}");
    }
}
