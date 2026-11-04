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

/// The arguments compiled as they are, not made by `wrap` from a list.
fn fixed_arguments(c: &CompiledSandbox) -> impl Iterator<Item = &String> {
    let b = &c.bubblewrap;
    b.root.iter().chain(&b.mounts).chain(&b.options)
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

/// A real Linux layout with its data outside the home: two roots and
/// the unit folders, none spelled as [`Layout::at`] spells them.
fn resolved_linux() -> Layout {
    Layout::resolve(Os::Linux, |name| match name {
        "HOME" => Some(USER.into()),
        "XDG_DATA_HOME" => Some("/srv/alice-data".into()),
        "XDG_CONFIG_HOME" => Some(format!("{USER}/.config").into()),
        _ => None,
    })
    .unwrap()
}

fn resolved_linux_case() -> (Policy, SandboxContext) {
    let name: TemplateName = "minimal".parse().unwrap();
    let mut p = resolve(&initial_overrides("home", &name), None)
        .unwrap()
        .policy;
    p.fs.write.push("~/proj".to_owned());
    p.fs.read_deny.push("~/proj/config/.env".to_owned());
    p.fs.read_deny.push("/opt/secrets".to_owned());
    (p, on_linux(&resolved_linux()))
}

/// `Layout::at` has one root, so dropping any later one would pass the
/// template snapshots: this compares a real layout's whole output.
#[test]
fn a_resolved_linux_layout_compiles_to_its_snapshot() {
    let (p, ctx) = resolved_linux_case();
    let text = compile(&p, &ctx).unwrap().text;
    if std::env::var_os("ENCLOS_WRITE_SNAPSHOTS").is_some() {
        let file = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("src/backend/bubblewrap/resolved-linux.snapshot");
        std::fs::write(file, &text).unwrap();
        return;
    }
    assert_eq!(text, include_str!("../resolved-linux.snapshot"));
}

/// Every root of the layout, each folder of it, and before anything is
/// bound: a `--bind` first would be covered, or uncover the root.
#[test]
fn every_protected_root_is_hidden_before_the_first_bind() {
    let (p, ctx) = resolved_linux_case();
    assert_eq!(ctx.protected.len(), 4, "{:?}", ctx.protected);
    let c = compiled_sandbox(&p, &ctx).unwrap();
    let args = &c.bubblewrap.mounts;
    let first_bind = args.iter().position(|a| a.starts_with("--bind")).unwrap();
    for root in &ctx.protected {
        let root = root.to_str().unwrap();
        if root.starts_with(USER) {
            assert!(
                c.bubblewrap.root_masks.denied.contains(&root.to_owned()),
                "{root}"
            );
        } else {
            let at = args.iter().position(|a| a == root).unwrap();
            assert_eq!(args[at - 1], "--tmpfs", "{root}");
            assert!(at < first_bind, "{root}: {args:?}");
            assert!(c.bubblewrap.sealed.contains(&root.to_owned()), "{root}");
        }
    }
}

/// Runs on every system against one file each, so a template's output
/// that came to depend on the host fails on the others.
#[test]
fn each_template_compiles_to_its_snapshot() {
    for (template, expected) in [
        ("assistant", include_str!("../assistant.snapshot")),
        ("minimal", include_str!("../minimal.snapshot")),
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

/// `wrap` joins bubblewrap's arguments in the order the file holds them,
/// so the masks over what a mount binds must come after that mount.
#[test]
fn bubblewraps_arguments_are_held_in_the_order_wrap_joins_them() {
    let text = compile(&policy(&["{home}", "~/proj"], &["~/proj/.env"]), &ctx())
        .unwrap()
        .text;
    let at: Vec<usize> = [
        "bubblewrap",
        "root",
        "root_masks",
        "mounts",
        "grant_masks",
        "sealed",
        "options",
        "landlock",
    ]
    .iter()
    .map(|field| text.find(&format!("\"{field}\": ")).expect(field))
    .collect();
    assert!(at.is_sorted(), "{at:?}");
    let c = compiled(&policy(&["{home}", "~/proj"], &["~/proj/.env"]));
    let b = &c.bubblewrap;
    for option in proposed::NAMESPACES
        .iter()
        .chain(&["--die-with-parent", "--chdir"])
    {
        assert!(b.options.iter().any(|a| a == option), "{option}");
        assert!(!b.mounts.iter().any(|a| a == option), "{option}");
    }
    for mount in [
        "--dev",
        "--proc",
        "--tmpfs",
        "--bind",
        "--bind-try",
        "--ro-bind",
    ] {
        assert!(b.mounts.iter().any(|a| a == mount), "{mount}");
        assert!(!b.options.iter().any(|a| a == mount), "{mount}");
    }
    assert_eq!(b.grant_masks.in_workspace, [format!("{USER}/proj/.env")]);
}

#[test]
fn a_denied_path_is_named_for_the_mask_and_never_bound() {
    let c = compiled(&policy(&["{home}"], &["~/.ssh", "~/.config/google-chrome"]));
    assert_eq!(c.bubblewrap.root_masks.home, USER);
    assert_eq!(
        c.bubblewrap.root_masks.denied,
        protected_and(&[".config/google-chrome", ".ssh"])
    );
    assert_eq!(c.bubblewrap.root, ["--ro-bind", "/", "/"]);
    assert!(!fixed_arguments(&c).any(|a| a.contains("/.ssh")));
}

/// A session starts without a workspace not made yet, as on Seatbelt,
/// and `policy test` reports it as not run (design §5). The sandbox's
/// home is enclos's own, so a missing one stops the session.
#[test]
fn a_workspace_not_made_yet_does_not_stop_the_session() {
    let c = compiled(&policy(&["{home}", "~/proj"], &[]));
    let args = &c.bubblewrap.mounts;
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
    assert_eq!(c.bubblewrap.root_masks.denied, protected_and(&[]));
    assert!(c.bubblewrap.root_masks.denied_elsewhere.is_empty());
}

#[test]
fn the_masked_host_paths_come_after_the_devices_whatever_the_policy() {
    let c = compiled(&Policy::default());
    assert_eq!(
        after(&c.bubblewrap.mounts, "--tmpfs"),
        ["/tmp", "/var/tmp", "/run", "/dev/shm"]
    );
    let at = |word: &str| c.bubblewrap.mounts.iter().position(|a| a == word).unwrap();
    assert!(at("--dev") < at("--tmpfs"));
    assert!(at("--tmpfs") < at("--bind"));
}

#[test]
fn the_protected_paths_are_masked_whatever_the_policy_says() {
    let c = compiled(&policy(&[], &[]));
    assert_eq!(c.bubblewrap.root_masks.denied, protected_and(&[]));
}

/// Outside the home no mask reaches them, so each gets its own tmpfs,
/// sealed once what is bound in it is there.
#[test]
fn protected_folders_outside_the_home_are_hidden_and_sealed() {
    let layout = Layout::at("/srv/enclos").with_user_home(USER);
    let ctx = on_linux(&layout);
    let c = compiled_sandbox(&policy(&["{home}"], &[]), &ctx).unwrap();
    let args = &c.bubblewrap.mounts;
    assert_eq!(
        c.bubblewrap.root_masks.denied,
        [
            format!("{USER}/.config/systemd/user"),
            format!("{USER}/.local/share/systemd/user")
        ]
    );
    assert!(after(args, "--tmpfs").contains(&"/srv/enclos"));
    assert_eq!(c.bubblewrap.sealed, ["/srv/enclos"]);
    // `wrap` seals it last, after every bind of its own under it.
    assert!(after(args, "--remount-ro").is_empty(), "{args:?}");
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
    let args = &c.bubblewrap.mounts;
    assert!(
        c.bubblewrap
            .root_masks
            .denied
            .contains(&format!("{}/e", user.display()))
    );
    assert!(after(args, "--tmpfs").contains(&real), "{args:?}");
    assert!(
        c.bubblewrap.sealed.contains(&real.to_owned()),
        "{:?}",
        c.bubblewrap.sealed
    );
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
    let args = &c.bubblewrap.mounts;
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

/// Landlock's rights add up: the rule on `/opt` covers what lies under
/// it, so `/opt/proj` runs programs where `~/proj` does not.
#[test]
fn a_workspace_under_a_system_folder_is_not_kept_from_running_programs() {
    let c = compiled(&policy(&["{home}", "/opt/proj"], &[]));
    assert!(c.landlock.write.contains(&"/opt/proj".to_owned()));
    assert!(
        c.landlock
            .execute
            .iter()
            .any(|root| is_within(Path::new("/opt/proj"), Path::new(root)))
    );
}

#[test]
fn a_session_has_its_own_namespaces_and_no_user_namespace() {
    let c = compiled(&Policy::default());
    for option in [
        "--unshare-user",
        "--disable-userns",
        "--unshare-pid",
        "--as-pid-1",
        "--unshare-net",
        "--unshare-ipc",
        "--die-with-parent",
    ] {
        assert!(c.bubblewrap.options.iter().any(|a| a == option), "{option}");
    }
    // `wrap` empties the environment (`wrap::tests`), on the process,
    // where a secret is not on a command line.
    assert!(!c.bubblewrap.options.iter().any(|a| a == "--clearenv"));
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
        c.bubblewrap.root_masks.denied_elsewhere,
        ["/opt/secrets", "/var/run/docker.sock", "/var/snap/lxd"]
    );
    assert_eq!(c.bubblewrap.root_masks.denied, protected_and(&[]));
}

#[test]
fn the_default_list_compiles_with_its_entries_outside_the_home_masked() {
    let name: TemplateName = "minimal".parse().unwrap();
    let snap = resolve(&initial_overrides("home", &name), None).unwrap();
    let c = compiled(&snap.policy);
    assert_eq!(
        c.bubblewrap.root_masks.denied_elsewhere,
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
    assert_eq!(
        c.bubblewrap.grant_masks.in_workspace,
        std::slice::from_ref(&entry)
    );
    assert_eq!(c.bubblewrap.root_masks.denied, protected_and(&[]));
    assert!(!fixed_arguments(&c).any(|a| *a == entry));
}

/// Before the arms for what is hidden already: the workspace's bind
/// brings back what the tmpfs or a protected root would have hidden.
#[test]
fn a_deny_entry_inside_a_workspace_under_the_sandboxs_own_tmpfs_is_masked() {
    let c = compiled(&policy(&["/tmp/proj"], &["/tmp/proj/.env"]));
    assert_eq!(c.bubblewrap.grant_masks.in_workspace, ["/tmp/proj/.env"]);
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
        c.bubblewrap.grant_masks.in_workspace,
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
        c.bubblewrap.grant_masks.in_sandbox_home,
        [format!("{USER}/.enclos/sandboxes/home/home/private")]
    );
}

#[test]
fn an_entry_that_holds_the_home_leaves_it_bound() {
    let c = compiled(&policy(&["{home}"], &["~/.enclos/sandboxes"]));
    assert_eq!(c.bubblewrap.root_masks.denied, protected_and(&[]));
    assert!(after(&c.bubblewrap.mounts, "--bind")[0].ends_with("/sandboxes/home/home"));
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

/// A mask names a path, so each folder above it stays where it is:
/// sorted, so a folder's bind comes before those of what it holds.
#[test]
fn the_folders_that_hold_a_mask_are_listed_above_it() {
    let c = compiled(&policy(
        &["{home}", "~/proj"],
        &["~/proj/config/deep/.env", "{home}/a/key"],
    ));
    assert_eq!(
        c.bubblewrap.grant_masks.unmovable,
        [
            format!("{USER}/.enclos/sandboxes/home/home/a"),
            format!("{USER}/proj/config"),
            format!("{USER}/proj/config/deep"),
        ]
    );
}

/// A workspace and the home are mounts already, so bound once.
#[test]
fn a_folder_with_no_mask_below_it_is_not_listed() {
    let c = compiled(&policy(&["{home}", "~/proj"], &["~/proj/.env", "{home}/x"]));
    assert!(
        c.bubblewrap.grant_masks.unmovable.is_empty(),
        "{:?}",
        c.bubblewrap.grant_masks.unmovable
    );
}

/// Other sandboxes' folders are not bound in: hidden is true of them.
#[test]
fn a_deny_entry_under_a_protected_root_and_not_bound_back_stays_hidden() {
    let c = compiled(&policy(&["{home}"], &["~/.enclos/sandboxes/other/secrets"]));
    assert_eq!(c.bubblewrap.root_masks.denied, protected_and(&[]));
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

/// Each step stands on its own: placing deny entries needs no policy, and
/// each entry lands in one list, is dropped as hidden, or is refused.
#[test]
fn each_deny_entry_is_placed_once_by_its_own_step() {
    let ctx = ctx();
    let home = tidy(&ctx.home);
    let user_home = tidy(&ctx.user_home);
    let workspaces = vec![PathBuf::from(format!("{USER}/proj"))];
    let protected = protected_roots(&ctx);
    let bound_back = place::BoundBack::of(&ctx);
    let around = place::Around {
        home: &home,
        user_home: &user_home,
        workspaces: &workspaces,
        protected: &protected,
        bound_back: &bound_back,
    };
    let entry = |e: &str| PathBuf::from(e);
    let mut placed = place::place_deny_entries(
        vec![
            home.join("key"),
            entry(&format!("{USER}/proj/.env")),
            entry(&format!("{USER}/.ssh")),
            entry("/opt/secrets"),
            entry("/run/user"),
            entry(&format!("{USER}/.enclos/sandboxes/other")),
        ],
        &around,
    )
    .unwrap();
    placed.sort();
    assert_eq!(placed.in_sandbox_home, [home.join("key")]);
    assert_eq!(placed.in_workspace, [entry(&format!("{USER}/proj/.env"))]);
    assert_eq!(placed.denied, [entry(&format!("{USER}/.ssh"))]);
    assert_eq!(placed.denied_elsewhere, [entry("/opt/secrets")]);
    let err = place::place_deny_entries(vec![entry("/proc/sys")], &around)
        .unwrap_err()
        .to_string();
    assert!(err.contains("cannot be held"), "{err}");
    assert!(place::check_workspace(&entry("/tmp"), &[], &protected).is_err());
    assert_eq!(seccomp::filter(), compiled(&Policy::default()).seccomp);
}
