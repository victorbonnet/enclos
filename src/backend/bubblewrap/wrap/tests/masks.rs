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
fn the_home_is_masked_after_the_root_and_before_the_compiled_rest() {
    let home = Home::new();
    let c = compiled(&home, Lists::default());
    let host = read(&home, &c, None).unwrap();
    let args = strings(&arguments(&c, &host, &[]));
    let user = text(&home.user());
    assert_eq!(&args[..3], ["--ro-bind", "/", "/"]);
    assert_eq!(&args[3..5], ["--tmpfs", user.as_str()]);
    let home_bind = position(&args, &["--bind", &text(&home.sandbox_home())]);
    assert!(home_bind > position(&args, &["--tmpfs", &user]));
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
