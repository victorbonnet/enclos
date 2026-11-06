//! Links resolved at launch, the agent's socket, and what refuses a session.

use super::*;

/// `~/cargo -> ~/.cargo` with `write = ["~/cargo"]`: the bind reaches the
/// real folder, so the entry is masked at the workspace's name for it
/// (design §14).
#[test]
fn a_workspace_through_a_link_has_the_entry_it_reaches_masked_at_its_own_name() {
    let home = Home::new();
    home.file(".cargo/credentials.toml");
    home.file(".cargo/config.toml");
    symlink(home.at(".cargo"), home.at("cargo")).unwrap();
    let credentials = home.at(".cargo/credentials.toml");
    let c = compiled(
        &home,
        Lists {
            denied: vec![credentials],
            workspaces: vec![home.at("cargo")],
            ..Lists::default()
        },
    );
    let host = read(&home, &c, None).unwrap();
    let args = strings(&arguments(&c, &host, &[]));
    let through = text(&home.at("cargo/credentials.toml"));
    let mask = position(&args, &["--ro-bind", "/dev/null", &through]);
    assert!(mask > position(&args, &["--bind-try", &text(&home.at("cargo"))]));
    // The real folder is the workspace's: its bind replaces it, so it is
    // not listed for the home's mask.
    assert!(!host.entries.contains_key(&home.at(".cargo")), "{host:?}");
}

/// `~/.ssh -> dotfiles/ssh`, as GNU stow sets a home up: the entry as
/// written and the folder it leads to are both out of sight, as Seatbelt
/// denies the resolved path (design §15), and so is the folder when a
/// workspace holds it.
#[test]
fn a_deny_entry_that_is_a_link_has_the_folder_it_leads_to_masked_too() {
    let home = Home::new();
    home.file("dotfiles/ssh/id_ed25519");
    home.file("dotfiles/vimrc");
    symlink("dotfiles/ssh", home.at(".ssh")).unwrap();
    let ssh = text(&home.at(".ssh"));
    let target = text(&home.at("dotfiles/ssh"));
    let key = text(&home.at("dotfiles/ssh/id_ed25519"));

    // Given the home's broad read.
    let c = compiled(
        &home,
        Lists {
            denied: vec![home.at(".ssh")],
            ..Lists::default()
        },
    );
    let host = read(&home, &c, None).unwrap();
    let args = strings(&arguments(&c, &host, &[]));
    assert!(!args.contains(&ssh), "{args:?}");
    position(&args, &["--tmpfs", &text(&home.at("dotfiles"))]);
    let kept = text(&home.at("dotfiles/vimrc"));
    position(&args, &["--ro-bind-try", &kept, &kept]);
    for hidden in [&target, &key] {
        assert!(!args.contains(hidden), "{hidden}: {args:?}");
    }

    // Given a workspace that holds the folder.
    let dotfiles = home.at("dotfiles");
    let c = compiled(
        &home,
        Lists {
            denied: vec![home.at(".ssh")],
            workspaces: vec![dotfiles.clone()],
            ..Lists::default()
        },
    );
    let host = read(&home, &c, None).unwrap();
    let args = strings(&arguments(&c, &host, &[]));
    assert!(!args.contains(&ssh), "{args:?}");
    let bound = position(&args, &["--bind-try", &text(&dotfiles)]);
    assert!(position(&args, &["--tmpfs", &target]) > bound, "{args:?}");
}

/// `~/.config -> ../data` with the deny entry `~/.config/google-chrome`:
/// the link is made again in the home's mask, so the folder it reaches,
/// outside the home, is masked where it is.
#[test]
fn a_deny_entry_reached_through_a_linked_folder_is_masked_where_it_leads() {
    let home = Home::outside_tmp();
    let data = home.dir.path().join("data");
    std::fs::create_dir_all(data.join("google-chrome/Default")).unwrap();
    std::fs::write(data.join("google-chrome/Default/Cookies"), "x").unwrap();
    symlink("../data", home.at(".config")).unwrap();
    let entry = home.at(".config/google-chrome");
    let c = compiled(
        &home,
        Lists {
            denied: vec![entry.clone()],
            ..Lists::default()
        },
    );
    let host = read(&home, &c, None).unwrap();
    let args = strings(&arguments(&c, &host, &[]));
    let config = text(&home.at(".config"));
    position(&args, &["--symlink", "../data", &config]);
    let resolved = text(&real_path(&data.join("google-chrome")));
    let rest = position(&args, &["--bind", &text(&home.sandbox_home())]);
    assert!(position(&args, &["--tmpfs", &resolved]) < rest, "{args:?}");
    position(&args, &["--remount-ro", &resolved]);
    assert!(!args.contains(&text(&entry)), "{args:?}");
}

/// A link that leads to the home, or above it, cannot be masked where it
/// leads without hiding the home.
#[test]
fn a_deny_entry_that_leads_to_the_home_refuses_the_session() {
    let home = Home::new();
    symlink(".", home.at(".ssh")).unwrap();
    let c = compiled(
        &home,
        Lists {
            denied: vec![home.at(".ssh")],
            ..Lists::default()
        },
    );
    let why = read(&home, &c, None).unwrap_err().to_string();
    assert!(why.contains("is the home"), "{why}");
}

#[test]
fn a_workspace_that_reaches_a_deny_entry_through_a_link_is_refused() {
    let home = Home::new();
    home.file(".ssh/id_ed25519");
    symlink(home.at(".ssh"), home.at("keys")).unwrap();
    let c = compiled(
        &home,
        Lists {
            denied: vec![home.at(".ssh")],
            workspaces: vec![home.at("keys")],
            ..Lists::default()
        },
    );
    let why = read(&home, &c, None).unwrap_err().to_string();
    assert!(why.contains("which the deny list hides"), "{why}");
}

/// The sandbox writes every folder of its workspace, so it could make one a
/// link, and the mask would follow it.
#[test]
fn a_link_between_a_workspace_and_its_deny_entry_refuses_the_session() {
    let home = Home::new();
    let workspace = home.folder("proj");
    let elsewhere = home.folder("elsewhere");
    symlink(&elsewhere, home.at("proj/config")).unwrap();
    let c = compiled(
        &home,
        Lists {
            in_workspace: vec![home.at("proj/config/.env")],
            workspaces: vec![workspace],
            ..Lists::default()
        },
    );
    let why = read(&home, &c, None).unwrap_err().to_string();
    assert!(why.contains("is a link between"), "{why}");
    assert!(why.contains("proj/config"), "{why}");
}

#[test]
fn a_link_between_the_sandbox_home_and_its_deny_entry_refuses_the_session() {
    let home = Home::new();
    let elsewhere = home.folder("elsewhere");
    symlink(&elsewhere, home.sandbox_home().join(".config")).unwrap();
    let c = compiled(
        &home,
        Lists {
            in_sandbox_home: vec![home.sandbox_home().join(".config/gh")],
            ..Lists::default()
        },
    );
    let why = read(&home, &c, None).unwrap_err().to_string();
    assert!(why.contains("is a link between"), "{why}");
}

#[test]
fn the_agents_socket_is_masked_wherever_the_host_puts_it() {
    let home = Home::new();
    let in_home = home.file(".agent/agent.sock");
    // Outside `/tmp`, where every temporary folder is.
    let elsewhere = PathBuf::from("/nonexistent-enclos-test/agent.sock");
    let c = compiled(&home, Lists::default());

    let host = read(&home, &c, Some(&in_home)).unwrap();
    assert!(host.hidden.contains(&in_home), "{host:?}");
    let args = strings(&arguments(&c, &host, &[]));
    position(&args, &["--tmpfs", &text(&home.at(".agent"))]);
    assert!(!args.contains(&text(&in_home)), "{args:?}");

    // Masked as any deny entry elsewhere is, by its kind.
    let host = read(&home, &c, Some(&elsewhere)).unwrap();
    assert_eq!(host.elsewhere, [(elsewhere, Kind::Missing)]);

    // The sandbox's own `/tmp` hides one there already.
    let host = read(&home, &c, Some(Path::new("/tmp/ssh-x/agent.1"))).unwrap();
    assert!(host.elsewhere.is_empty(), "{host:?}");
}

/// The agent's socket is placed as the place a linked deny entry leads to
/// is: in a grant, the folders that hold it cannot be moved; under the
/// sandbox's own `/dev`, nothing is masked, as a mask there would not last;
/// the home itself cannot be hidden, so the session is refused.
#[test]
fn the_agents_socket_is_placed_as_where_a_deny_entry_leads() {
    let home = Home::new();
    let c = compiled(&home, Lists::default());
    let in_sandbox_home = home.file(".enclos/sandboxes/lab/home/.agent/agent.sock");

    let host = read(&home, &c, Some(&in_sandbox_home)).unwrap();
    assert_eq!(host.in_grants, [(in_sandbox_home.clone(), Kind::Other)]);
    assert_eq!(host.unmovable, [home.sandbox_home().join(".agent")]);

    let host = read(&home, &c, Some(Path::new("/dev/enclos-test/agent.sock"))).unwrap();
    assert!(host.elsewhere.is_empty(), "{host:?}");

    let why = read(&home, &c, Some(&home.user())).unwrap_err().to_string();
    assert!(why.contains("SSH_AUTH_SOCK"), "{why}");
}

#[test]
fn a_folder_that_cannot_be_listed_refuses_the_session() {
    let home = Home::new();
    let config = home.folder(".config");
    home.file(".config/gh/hosts.yml");
    std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o000)).unwrap();
    let c = compiled(
        &home,
        Lists {
            denied: vec![home.at(".config/gh")],
            ..Lists::default()
        },
    );
    let got = read(&home, &c, None);
    std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o755)).unwrap();
    // Root reads it all the same.
    if rustix::process::geteuid().is_root() {
        return;
    }
    let why = got.unwrap_err().to_string();
    assert!(why.contains("cannot look at"), "{why}");
}
