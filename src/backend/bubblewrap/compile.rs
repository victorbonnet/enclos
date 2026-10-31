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
//! `before_home_mask`, what it makes of [`HomeMask`], `after_home_mask`,
//! then its `--remount-ro` for each folder it made.

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
    /// Deny entries inside the sandbox's home, which is bound writable:
    /// masked one by one after that bind.
    pub in_sandbox_home: Vec<String>,
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
            .map(|e| paths.expand(e).map(|p| tidy(&p)).map_err(refused))
            .collect()
    };
    let home = tidy(&ctx.home);
    let user_home = tidy(&ctx.user_home);
    let protected: Vec<PathBuf> = ctx.protected.iter().map(|p| tidy(p)).collect();
    let workspaces: Vec<PathBuf> = expand(&policy.fs.write)?
        .into_iter()
        .filter(|w| !is_within(w, &home))
        .collect();
    let deny = expand(&policy.fs.read_deny)?;

    for workspace in &workspaces {
        if let Some(hit) = deny
            .iter()
            .chain(&protected)
            .find(|d| is_within(d, workspace) || is_within(workspace, d))
        {
            return Err(refused(format!(
                "workspace {} overlaps {}: bubblewrap has no way to keep it out of a folder bound writable",
                workspace.display(),
                hit.display()
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
    let mut denied = in_user_home.clone();
    let mut in_sandbox_home = Vec::new();
    for entry in deny {
        if is_within(&entry, &home) {
            in_sandbox_home.push(entry);
        } else if OWN_TMPFS.iter().any(|t| is_within(&entry, Path::new(t)))
            || protected.iter().any(|root| is_within(&entry, root))
        {
            // Hidden already.
        } else if is_within(&entry, &user_home) && entry != user_home {
            denied.push(entry);
        } else {
            return Err(refused(format!(
                "deny entry {} is not inside the home {}, where a denied path can be left out",
                entry.display(),
                user_home.display()
            )));
        }
    }
    denied.sort();
    denied.dedup();
    in_sandbox_home.sort();
    in_sandbox_home.dedup();

    let mut after = args(&["--dev", "/dev", "--proc", "/proc"]);
    for place in OWN_TMPFS {
        after.extend(args(&["--tmpfs", place]));
    }
    for root in &elsewhere {
        after.extend(["--tmpfs".to_owned(), text(root)?]);
    }
    for writable in std::iter::once(&home).chain(&workspaces) {
        after.extend(["--bind".to_owned(), text(writable)?, text(writable)?]);
    }
    // Read-only, for this sandbox alone. Connecting to a socket needs no
    // write access to its mount (ADR 0004). `secrets/` is there only while
    // the sandbox's services run (ADR 0034, ADR 0036), and a session may
    // start without them.
    let visible = text(ctx.proxy_socket.parent().unwrap_or(&ctx.proxy_socket))?;
    let compiled = text(&ctx.dir.join("compiled"))?;
    let secrets = text(&ctx.secrets)?;
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
            in_sandbox_home: texts(&in_sandbox_home)?,
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
        },
        relay: Relay {
            port: ctx.proxy_port,
            socket: text(&ctx.proxy_socket)?,
        },
        unenforced: proposed::unenforced(policy),
    })
}

/// `path` without `.`, a trailing `/` or `..`, as written: nothing is
/// looked up, so `..` climbs the name before it, whatever that is.
fn tidy(path: &Path) -> PathBuf {
    let mut tidied = PathBuf::new();
    for component in path.components() {
        match component {
            Component::ParentDir => {
                tidied.pop();
            }
            Component::CurDir => {}
            other => tidied.push(other),
        }
    }
    tidied
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
    use crate::layout::Layout;
    use crate::model::policy::TemplateName;
    use crate::policy::{initial_overrides, resolve};

    const USER: &str = "/nonexistent-enclos-test/alice";

    fn ctx() -> SandboxContext {
        let layout = Layout::at(format!("{USER}/.enclos"));
        SandboxContext::new(&layout, &"home".parse().unwrap(), 41001)
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
            ("mcp-only", include_str!("mcp-only.snapshot")),
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
            [
                format!("{USER}/.config/google-chrome"),
                format!("{USER}/.enclos"),
                format!("{USER}/.ssh"),
            ]
        );
        assert_eq!(c.before_home_mask, ["--ro-bind", "/", "/"]);
        assert!(!c.after_home_mask.iter().any(|a| a.contains("/.ssh")));
    }

    /// `/run/user` is on the default deny list, and `--tmpfs /run` hides it.
    #[test]
    fn a_deny_entry_under_the_sandboxs_own_tmpfs_needs_no_mask() {
        let c = compiled(&policy(&["{home}"], &["/run/user", "/tmp/x"]));
        assert_eq!(c.home_mask.denied, [format!("{USER}/.enclos")]);
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
        assert_eq!(c.home_mask.denied, [format!("{USER}/.enclos")]);
    }

    /// Outside the home no mask reaches them, so each gets its own tmpfs,
    /// sealed once what is bound in it is there.
    #[test]
    fn protected_folders_outside_the_home_are_hidden_and_sealed() {
        let layout = Layout::at("/srv/enclos").with_user_home(USER);
        let ctx = SandboxContext::new(&layout, &"home".parse().unwrap(), 41001);
        let c = compiled_sandbox(&policy(&["{home}"], &[]), &ctx).unwrap();
        let args = &c.after_home_mask;
        assert!(c.home_mask.denied.is_empty());
        assert!(after(args, "--tmpfs").contains(&"/srv/enclos"));
        assert_eq!(after(args, "--remount-ro"), ["/srv/enclos"]);
        let last_mount = args
            .iter()
            .rposition(|a| a.starts_with("--ro-bind") || a == "--bind")
            .unwrap();
        let sealed = args.iter().position(|a| a == "--remount-ro").unwrap();
        assert!(last_mount < sealed);
    }

    #[test]
    fn the_sandbox_gets_its_own_folders_and_only_those() {
        let c = compiled(&policy(&["{home}", "~/proj"], &[]));
        let args = &c.after_home_mask;
        let sandbox = format!("{USER}/.enclos/sandboxes/home");
        assert_eq!(
            after(args, "--bind"),
            [format!("{sandbox}/home"), format!("{USER}/proj")]
        );
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

    #[test]
    fn the_filter_refuses_the_listed_calls() {
        let s = compiled(&Policy::default()).seccomp;
        assert_eq!(s.deny.len(), 35);
        assert_eq!(s.ioctl["TIOCSTI"], 0x5412);
        assert_eq!(s.clone_flags["CLONE_NEWUSER"], 0x1000_0000);
        assert_eq!(s.clone_flags.len(), 8);
        assert_eq!(s.enosys, ["clone3"]);
    }

    #[test]
    fn a_deny_entry_that_cannot_be_left_out_is_refused() {
        for entry in ["/etc/shadow", "~", "/nonexistent-enclos-test"] {
            let err = refusal(&policy(&["{home}"], &[entry]));
            assert!(err.contains("is not inside the home"), "{entry}: {err}");
        }
    }

    #[test]
    fn a_workspace_that_overlaps_a_deny_entry_is_refused() {
        for workspace in ["~/dev", "~/dev/work", "~/dev/work/child"] {
            let err = refusal(&policy(&[workspace], &["~/dev/work"]));
            assert!(err.contains("overlaps"), "{workspace}: {err}");
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
        assert_eq!(c.home_mask.denied, [format!("{USER}/.enclos")]);
        assert!(after(&c.after_home_mask, "--bind")[0].ends_with("/sandboxes/home/home"));
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

    #[test]
    fn tidying_a_path_only_reads_its_text() {
        assert_eq!(tidy(Path::new("/a/./b/../c/")), Path::new("/a/c"));
    }

    #[test]
    fn a_path_that_is_not_text_is_refused() {
        use std::os::unix::ffi::OsStrExt;
        let name = std::ffi::OsStr::from_bytes(b"/a/\xff");
        let err = text(Path::new(name)).unwrap_err().to_string();
        assert!(err.contains("not valid UTF-8"), "{err}");
    }
}
