use super::policy::with_sandbox;
use super::*;
use enclos_protocol::approval::{Access, AccessKind};
fn network(target: &str) -> Access {
    Access {
        kind: AccessKind::Network,
        target: target.into(),
        private: false,
    }
}
fn write(target: impl AsRef<std::path::Path>) -> Access {
    Access {
        kind: AccessKind::Write,
        target: target.as_ref().display().to_string(),
        private: false,
    }
}

#[test]
fn access_approval_refuses_absolute_paths_that_run_code_outside_the_sandbox() {
    let (dir, e, name) = with_sandbox();
    // The fixture's home is the temporary folder: these are absolute paths in it.
    let home = dir.path();
    std::fs::create_dir_all(home.join("project/.git/hooks")).unwrap();
    for target in [
        home.join(".zshrc"),
        home.join(".bashrc"),
        home.join(".gitconfig"),
        home.join(".config/git"),
        home.join(".local/bin"),
        home.join(".ssh"),
        home.join(".vscode/extensions"),
        home.join("Library/Application Support/Code/User"),
        home.join("Library/LaunchAgents"),
        home.join("bin"),
        home.join("go/bin"),
        // Holds ~/go/bin, which a service's PATH does not name.
        home.join("go"),
        home.join("project/.git/hooks"),
        // enclos's own files, inside the home too: refused by validation.
        dir.path().join("enclos"),
        dir.path().join("enclos/sandboxes"),
        std::path::PathBuf::from("/opt/homebrew/bin"),
        std::path::PathBuf::from("/usr/local/bin"),
        std::path::PathBuf::from("/etc"),
        std::path::PathBuf::from("/Volumes/Disk"),
    ] {
        assert!(
            e.access_plan(&name, &write(&target)).is_err(),
            "{}",
            target.display()
        );
    }
    assert!(e.access_plan(&name, &write(home.join("project"))).is_ok());
    assert_eq!(e.policy(&name).unwrap().version.version, 1);
}

#[test]
fn access_approval_write_narrowing_holds_path_folders_and_external_volumes() {
    use crate::engine::approvals::phone_write_refusal;
    use std::path::{Path, PathBuf};
    let home = Path::new("/Users/alice");
    let path = [
        PathBuf::from("/Users/alice/tools/bin"),
        PathBuf::from("/usr/bin"),
    ];
    for refused in [
        "/Users/alice/tools/bin",
        "/Users/alice/tools/bin/new",
        // Holds a PATH folder: its programs could be replaced.
        "/Users/alice/tools",
        "/Users/alice",
        // Holds a refused home folder, whether or not it is on PATH.
        "/Users/alice/go",
        "/Users/alice/Library/LaunchAgents",
        "/Users/alice/bin/tool",
        "/Users/other/work",
        "/Volumes/Disk",
        "/Volumes/Disk/.Trashes",
        "/mnt/disk",
        "/media/me/disk",
    ] {
        assert!(
            phone_write_refusal(Path::new(refused), home, &path).is_some(),
            "{refused}"
        );
    }
    for allowed in [
        "/Users/alice/work",
        "/Users/alice/Documents/report",
        "/Volumes/Disk/projects",
        "/mnt/disk/projects",
        "/media/me/disk/projects",
    ] {
        assert_eq!(phone_write_refusal(Path::new(allowed), home, &path), None);
    }
    // A folder that does not exist yet keeps the agent's case; macOS's
    // usual file system does not tell it from the refused one.
    if cfg!(target_os = "macos") {
        for refused in [
            "/Users/alice/library/LaunchAgents",
            "/Users/alice/GO",
            "/Users/alice/Tools/Bin",
        ] {
            assert!(
                phone_write_refusal(Path::new(refused), home, &path).is_some(),
                "{refused}"
            );
        }
    }
}

#[test]
fn access_approval_private_names_are_local_only() {
    let (_dir, e, name) = with_sandbox();
    let mut a = network("nas.example.com:8443");
    a.private = true;
    let refused = e.access_plan(&name, &a).err().unwrap().to_string();
    assert!(refused.contains("local name"), "{refused}");
    a.target = "nas.local:8443".into();
    let plan = e.access_plan(&name, &a).unwrap();
    assert!(
        plan.change
            .contains("whatever it resolves to on your network"),
        "{}",
        plan.change
    );
    e.approve_access(&alice(), &name, &a, &plan.revision)
        .unwrap();
    assert_eq!(
        e.policy(&name).unwrap().snapshot.policy.net.private,
        ["nas.local"]
    );
}

#[test]
fn access_approval_shows_the_scope_it_writes() {
    let (dir, e, name) = with_sandbox();
    let plan = e
        .access_plan(&name, &network("API.Example.com:443"))
        .unwrap();
    assert_eq!(plan.scope, "api.example.com");
    let real = dir.path().join("real");
    std::fs::create_dir(&real).unwrap();
    std::os::unix::fs::symlink(&real, dir.path().join("alias")).unwrap();
    let plan = e
        .access_plan(&name, &write(dir.path().join("alias")))
        .unwrap();
    assert_eq!(
        plan.scope,
        crate::policy::paths::real_path(&real).display().to_string()
    );
    // The narrowing refuses a hidden folder as the target, not the hidden
    // entries beneath an approved one: the preview says so.
    assert!(
        plan.change.contains("hidden files and folders included"),
        "{}",
        plan.change
    );
}

#[test]
fn access_context_counts_read_denials_without_listing_host_paths() {
    let (_dir, e, name) = with_sandbox();
    let text = e.access_context(&name).unwrap();
    assert!(!text.contains(".ssh"), "{text}");
    assert!(text.contains("cannot be read"), "{text}");
}

#[test]
fn access_approval_adds_only_the_reviewed_scope_and_updates_knowledge() {
    let (_dir, e, name) = with_sandbox();
    let a = network("api.example.com:8443");
    let before = e.policy(&name).unwrap().snapshot.policy;
    let plan = e.access_plan(&name, &a).unwrap();
    assert!(!plan.restart);
    assert!(plan.change.contains("every agent"));
    assert!(
        e.policy(&name)
            .unwrap()
            .snapshot
            .policy
            .net
            .allow
            .is_empty()
    );
    e.approve_access(&alice(), &name, &a, &plan.revision)
        .unwrap();
    let mut expected = before;
    expected.net.allow.push("api.example.com:8443".into());
    assert_eq!(e.policy(&name).unwrap().snapshot.policy, expected);
    assert!(
        e.access_context(&name)
            .unwrap()
            .contains("api.example.com:8443")
    );
    let last = e.audit(None).unwrap().last().unwrap().clone();
    assert_eq!(last.intent.command, "app approval");
    // The scope written, not only the agent's spelling of it
    assert!(
        last.finished
            .unwrap()
            .outcome
            .message
            .contains("api.example.com:8443")
    );
    assert!(e.verify_audit().unwrap().intact());
}

#[test]
fn two_spellings_of_one_destination_are_one_scope() {
    assert_eq!(
        crate::engine::normalized(&network("API.Example.com:8443")),
        crate::engine::normalized(&network("api.example.com:8443"))
    );
}
#[test]
fn access_approval_stale_policy_does_not_apply_the_old_decision() {
    let (_dir, e, name) = with_sandbox();
    let a = network("api.example.com");
    let plan = e.access_plan(&name, &a).unwrap();
    done(
        e.policy_allow(&alice(), &name, "other.example.com", Confirm::Yes)
            .unwrap(),
    );
    assert!(
        e.approve_access(&alice(), &name, &a, &plan.revision)
            .is_err()
    );
    assert!(!e.allows(&name, "api.example.com").unwrap());
}
#[test]
fn access_approval_never_applies_unrelated_edits_or_pending_changes() {
    let (dir, e, name) = with_sandbox();
    let a = network("api.example.com");
    let file = e.policy(&name).unwrap().file;
    let before = std::fs::read_to_string(&file).unwrap();
    std::fs::write(
        &file,
        before.replace(
            "write_add = []",
            &format!("write_add = [\"{}\"]", dir.path().join("work").display()),
        ),
    )
    .unwrap();
    assert!(e.access_plan(&name, &a).is_err());
    assert!(!e.allows(&name, "api.example.com").unwrap());
}
#[test]
fn access_approval_rejects_wildcards_loopback_sensitive_paths_and_root() {
    let (_dir, e, name) = with_sandbox();
    for target in ["*.example.com", "127.0.0.1", "169.254.169.254"] {
        assert!(e.access_plan(&name, &network(target)).is_err(), "{target}");
    }
    for target in ["/", "relative", "/tmp/../etc", "/tmp/./a", "~/.ssh"] {
        let a = Access {
            kind: AccessKind::Write,
            target: target.into(),
            private: false,
        };
        assert!(e.access_plan(&name, &a).is_err(), "{target}");
    }
    let a = Access {
        kind: AccessKind::Read,
        target: "~/.ssh".into(),
        private: false,
    };
    assert!(e.access_plan(&name, &a).is_err());
    assert_eq!(e.policy(&name).unwrap().version.version, 1);
}
#[test]
fn access_approval_private_opt_in_is_for_the_host_and_shown_as_such() {
    let (_dir, e, name) = with_sandbox();
    let mut a = network("192.168.1.5:8443");
    assert!(e.access_plan(&name, &a).is_err());
    a.private = true;
    let plan = e.access_plan(&name, &a).unwrap();
    assert!(plan.change.contains("every port the policy already allows"));
    e.approve_access(&alice(), &name, &a, &plan.revision)
        .unwrap();
    assert_eq!(
        e.policy(&name).unwrap().snapshot.policy.net.private,
        ["192.168.1.5"]
    );
}
#[test]
fn access_approval_write_grant_works_without_a_running_session() {
    let (dir, e, name) = with_sandbox();
    let a = Access {
        kind: AccessKind::Write,
        target: dir.path().join("work").display().to_string(),
        private: false,
    };
    let plan = e.access_plan(&name, &a).unwrap();
    assert!(!plan.restart);
    e.approve_access(&alice(), &name, &a, &plan.revision)
        .unwrap();
    assert!(
        e.policy(&name).unwrap().snapshot.policy.fs.write.contains(
            &crate::policy::paths::real_path(std::path::Path::new(&a.target))
                .display()
                .to_string()
        )
    );
}
#[test]
fn access_denial_is_audited_without_changing_policy() {
    let (_dir, e, name) = with_sandbox();
    let before = e.policy(&name).unwrap().snapshot;
    e.deny_access(&alice(), &name, "request-1").unwrap();
    assert_eq!(e.policy(&name).unwrap().snapshot, before);
    assert_eq!(
        e.audit(None).unwrap().last().unwrap().intent.command,
        "app approval deny"
    );
}

#[test]
fn access_approval_a_retargeted_symlink_invalidates_the_preview() {
    let (dir, e, name) = with_sandbox();
    let first = dir.path().join("first");
    let second = dir.path().join("second");
    std::fs::create_dir(&first).unwrap();
    std::fs::create_dir(&second).unwrap();
    let link = dir.path().join("work");
    std::os::unix::fs::symlink(&first, &link).unwrap();
    let a = Access {
        kind: AccessKind::Write,
        target: link.display().to_string(),
        private: false,
    };
    let plan = e.access_plan(&name, &a).unwrap();
    assert!(plan.change.contains("first"));
    std::fs::remove_file(&link).unwrap();
    std::os::unix::fs::symlink(&second, &link).unwrap();
    assert!(
        e.approve_access(&alice(), &name, &a, &plan.revision)
            .is_err()
    );
    let fresh = e.access_plan(&name, &a).unwrap();
    assert!(fresh.change.contains("second"));
    e.approve_access(&alice(), &name, &a, &fresh.revision)
        .unwrap();
    let granted = crate::policy::paths::real_path(&second)
        .display()
        .to_string();
    assert!(
        e.policy(&name)
            .unwrap()
            .snapshot
            .policy
            .fs
            .write
            .contains(&granted)
    );
}
