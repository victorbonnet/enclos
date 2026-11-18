//! The masks of the home, outside it and inside the grants, and their order.

use super::*;

#[test]
fn a_denied_path_in_the_home_is_left_out_of_its_folders_and_the_rest_bound_back() {
    let home = Home::new();
    home.file(".ssh/id_ed25519");
    home.file(".config/gh/hosts.yml");
    home.file(".config/kept.toml");
    home.file("notes.txt");
    symlink("notes.txt", home.at("link")).unwrap();
    let c = compiled(
        &home,
        Lists {
            denied: vec![home.at(".ssh"), home.at(".config/gh")],
            ..Lists::default()
        },
    );
    let host = read(&home, &c, None).unwrap();
    let args = strings(&arguments(&c, &host, &[]));
    let user = text(&home.user());
    let config = text(&home.at(".config"));
    // Each folder on the way to a denied path becomes a tmpfs.
    position(&args, &["--tmpfs", &user]);
    position(&args, &["--tmpfs", &config]);
    let kept = text(&home.at("notes.txt"));
    position(&args, &["--ro-bind-try", &kept, &kept]);
    let kept = text(&home.at(".config/kept.toml"));
    position(&args, &["--ro-bind-try", &kept, &kept]);
    position(&args, &["--symlink", "notes.txt", &text(&home.at("link"))]);
    for denied in [".ssh", ".config/gh", ".enclos"] {
        let denied = text(&home.at(denied));
        assert!(!args.contains(&denied), "{denied}: {args:?}");
    }
    // Read-only once bubblewrap has made its mount points, after the
    // compiled mounts; only the options, whose place does not matter, follow.
    let sealed = position(&args, &["--remount-ro", &user]);
    assert!(sealed > position(&args, &["--bind", &text(&home.sandbox_home())]));
    assert!(sealed < position(&args, &["--die-with-parent"]));
    position(&args, &["--remount-ro", &config]);
}

#[test]
fn a_home_reached_by_symlink_is_rebuilt_at_its_target_with_its_deny_masks() {
    let home = Home::new();
    let actual = home.user();
    let alias = actual.with_file_name("via-link");
    symlink(&actual, &alias).unwrap();
    let denied = home.folder(".private");
    let visible = home.file("visible");
    let mut c = compiled(&home, Lists::default());
    c.bubblewrap.root_masks.home = text(&alias);
    c.bubblewrap.root_masks.denied =
        vec![text(&alias.join(".private")), text(&alias.join(".enclos"))];

    let host = read(&home, &c, None).unwrap();
    let args = strings(&arguments(&c, &host, &[]));
    assert!(host.hidden.contains(&denied));
    let tmpfs = ["--tmpfs", actual.to_str().unwrap()];
    assert_eq!(args.windows(2).filter(|words| *words == tmpfs).count(), 1);
    position(&args, &["--remount-ro", &text(&actual)]);
    position(&args, &["--symlink", &text(&actual), &text(&alias)]);
    position(&args, &["--ro-bind-try", &text(&visible), &text(&visible)]);
    assert!(!args.contains(&text(&denied)), "{args:?}");
}

#[test]
fn the_root_view_builds_and_seals_each_home_ancestor_once() {
    use crate::backend::bubblewrap::wrap::host::Entry;

    let home = Home::new();
    let mut c = compiled(&home, Lists::default());
    c.bubblewrap.root_masks.home = "/home/alice".to_owned();
    let mut host = Host::default();
    host.entries.insert(
        PathBuf::from("/"),
        vec![
            Entry {
                name: "home".into(),
                link: None,
            },
            Entry {
                name: "usr".into(),
                link: None,
            },
        ],
    );
    host.entries.insert(
        PathBuf::from("/home"),
        vec![Entry {
            name: "alice".into(),
            link: None,
        }],
    );
    host.entries.insert(
        PathBuf::from("/home/alice"),
        vec![Entry {
            name: "keep".into(),
            link: None,
        }],
    );
    let args = strings(&arguments(&c, &host, &[]));
    let mut expected: Vec<String> = [
        "--tmpfs",
        "/",
        "--tmpfs",
        "/home",
        "--tmpfs",
        "/home/alice",
        "--ro-bind-try",
        "/home/alice/keep",
        "/home/alice/keep",
        "--ro-bind-try",
        "/usr",
        "/usr",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    expected.extend(c.bubblewrap.mounts.iter().cloned());
    expected.extend(
        [
            "--remount-ro",
            "/",
            "--remount-ro",
            "/home",
            "--remount-ro",
            "/home/alice",
        ]
        .into_iter()
        .map(str::to_owned),
    );
    for dir in &c.bubblewrap.sealed {
        expected.extend(["--remount-ro".to_owned(), dir.clone()]);
    }
    expected.extend(c.bubblewrap.options.iter().cloned());
    assert_eq!(args, expected);
}

#[test]
fn a_deny_entry_elsewhere_is_masked_by_its_kind_after_the_root() {
    let home = Home::new();
    let outside = tempfile::tempdir().unwrap();
    let folder = outside.path().join("lxd");
    std::fs::create_dir(&folder).unwrap();
    let file = outside.path().join("token");
    std::fs::write(&file, "x").unwrap();
    let missing = outside.path().join("missing");
    let c = compiled(
        &home,
        Lists {
            elsewhere: vec![folder.clone(), file.clone(), missing.clone()],
            ..Lists::default()
        },
    );
    let host = read(&home, &c, None).unwrap();
    let args = strings(&arguments(&c, &host, &[]));
    let rest = position(&args, &["--bind", &text(&home.sandbox_home())]);
    assert!(position(&args, &["--tmpfs", &text(&folder)]) < rest);
    assert!(position(&args, &["--ro-bind", "/dev/null", &text(&file)]) < rest);
    assert!(!args.contains(&text(&missing)), "{args:?}");
    position(&args, &["--remount-ro", &text(&folder)]);
}

/// Inside a workspace, after its bind, which would uncover a mask made
/// before it; a missing entry gets a folder, so the sandbox cannot make it.
#[test]
fn a_deny_entry_in_a_workspace_is_masked_after_its_bind_whether_or_not_it_is_there() {
    let home = Home::new();
    let workspace = home.folder("proj");
    let env = home.file("proj/config/.env");
    let keys = home.folder("proj/keys");
    let missing = home.at("proj/.netrc");
    let c = compiled(
        &home,
        Lists {
            in_workspace: vec![env.clone(), keys.clone(), missing.clone()],
            workspaces: vec![workspace.clone()],
            unmovable: vec![home.at("proj/config")],
            ..Lists::default()
        },
    );
    let host = read(&home, &c, None).unwrap();
    let args = strings(&arguments(&c, &host, &[]));
    let bound = position(&args, &["--bind-try", &text(&workspace)]);
    let config = text(&home.at("proj/config"));
    let unmovable = position(&args, &["--bind", &config, &config]);
    let file = position(&args, &["--ro-bind", "/dev/null", &text(&env)]);
    let folder = position(&args, &["--tmpfs", &text(&keys)]);
    let made = position(&args, &["--tmpfs", &text(&missing)]);
    assert!(bound < unmovable, "{args:?}");
    assert!(
        unmovable < file && unmovable < folder && unmovable < made,
        "{args:?}"
    );
    let sealed = position(&args, &["--remount-ro", &text(&keys)]);
    assert!(sealed > made);
    position(&args, &["--remount-ro", &text(&missing)]);
}

#[test]
fn a_deny_entry_in_the_sandbox_home_is_masked_after_its_bind() {
    let home = Home::new();
    let entry = home.sandbox_home().join(".ssh");
    let c = compiled(
        &home,
        Lists {
            in_sandbox_home: vec![entry.clone()],
            ..Lists::default()
        },
    );
    let host = read(&home, &c, None).unwrap();
    let args = strings(&arguments(&c, &host, &[]));
    let bound = position(&args, &["--bind", &text(&home.sandbox_home())]);
    assert!(position(&args, &["--tmpfs", &text(&entry)]) > bound);
}

/// bubblewrap binds none, so there is nothing to mask, and a mount point
/// there would fail the session.
#[test]
fn a_workspace_not_made_yet_gets_no_mask() {
    let home = Home::new();
    let workspace = home.at("later");
    let entry = home.at("later/.env");
    let c = compiled(
        &home,
        Lists {
            in_workspace: vec![entry.clone()],
            workspaces: vec![workspace],
            ..Lists::default()
        },
    );
    let host = read(&home, &c, None).unwrap();
    assert!(host.in_grants.is_empty(), "{host:?}");
    assert!(!strings(&arguments(&c, &host, &[])).contains(&text(&entry)));
}
