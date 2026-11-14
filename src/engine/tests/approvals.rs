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
fn access_approval_can_grant_the_hosts_gradle_cache_after_review() {
    let (dir, e, name) = with_sandbox();
    let target = dir.path().join(".gradle");
    std::fs::create_dir(&target).unwrap();
    let a = write(&target);
    let before = e.policy(&name).unwrap().snapshot.policy;
    let state = e.mobile_policy(&name).unwrap();
    // The owner can already add this path in the app's policy editor.
    let edit = enclos_protocol::policy::PolicyChange {
        field: "write".into(),
        before: None,
        after: Some(a.target.clone()),
    };
    e.mobile_policy_preview(&name, &state.base, &edit).unwrap();

    let plan = e.access_plan(&name, &a).unwrap();
    let resolved = crate::policy::paths::real_path(&target)
        .display()
        .to_string();
    assert_eq!(plan.scope, resolved);
    // Gradle runs init scripts from it on the host: the preview leads with that.
    assert!(
        plan.change.starts_with("Warning:") && plan.change.contains("hidden"),
        "{}",
        plan.change
    );
    assert!(plan.change.contains("every agent"));
    assert!(plan.change.contains("outside the sandbox"));
    assert!(plan.change.contains("Future writes"));
    assert_eq!(e.policy(&name).unwrap().snapshot.policy, before);

    e.approve_access(&alice(), &name, &a, &plan.revision)
        .unwrap();
    let mut expected = before;
    expected.fs.write.push(resolved);
    expected.fs.write.sort();
    assert_eq!(e.policy(&name).unwrap().snapshot.policy, expected);
    assert!(e.verify_audit().unwrap().intact());
}

#[test]
fn access_approval_write_paths_use_the_same_validation_as_the_policy_editor() {
    let (dir, e, name) = with_sandbox();
    let outside = tempfile::tempdir().unwrap();
    let home = dir.path();
    std::fs::create_dir_all(home.join("project/.git/hooks")).unwrap();
    let state = e.mobile_policy(&name).unwrap();
    let mut library = home.join("Library/LaunchAgents");
    if cfg!(target_os = "macos") {
        // Not there yet, so it keeps the agent's case; macOS's usual file
        // system does not tell it from `Library`.
        library = home.join("library/LaunchAgents");
    }
    // Places the host runs programs or settings from, then ordinary folders.
    let risky = [
        home.join(".zshrc"),
        home.join(".gitconfig"),
        home.join(".config/git"),
        home.join(".local/bin"),
        home.join(".vscode/extensions"),
        home.join("Library/Application Support/Code/User"),
        library,
        home.join("bin"),
        home.join("go/bin"),
        // Holds ~/go/bin.
        home.join("go"),
        home.join("project/.git/hooks"),
    ];
    let ordinary = [
        home.join("project"),
        // A grant is not restricted to the host user's home or external volumes.
        outside.path().join("tools/bin"),
    ];
    for (target, warned) in risky
        .iter()
        .map(|t| (t, true))
        .chain(ordinary.iter().map(|t| (t, false)))
    {
        let a = write(target);
        let edit = enclos_protocol::policy::PolicyChange {
            field: "write".into(),
            before: None,
            after: Some(a.target.clone()),
        };
        e.mobile_policy_preview(&name, &state.base, &edit)
            .unwrap_or_else(|err| panic!("policy editor {}: {err}", target.display()));
        let plan = e
            .access_plan(&name, &a)
            .unwrap_or_else(|err| panic!("approval {}: {err}", target.display()));
        assert_eq!(
            plan.change.starts_with("Warning:"),
            warned,
            "{}: {}",
            target.display(),
            plan.change
        );
    }
    // Preparing the previews grants nothing.
    assert_eq!(e.policy(&name).unwrap().version.version, 1);
}

#[test]
fn access_approval_still_refuses_sensitive_and_enclos_paths_including_symlinks() {
    let (dir, e, name) = with_sandbox();
    let home = dir.path();
    let sensitive = home.join(".ssh");
    std::fs::create_dir(&sensitive).unwrap();
    let alias = home.join("ssh-alias");
    std::os::unix::fs::symlink(&sensitive, &alias).unwrap();
    let state = e.mobile_policy(&name).unwrap();
    for target in [
        sensitive,
        home.join(".config/gh"),
        home.join(".config/systemd/user"),
        dir.path().join("enclos"),
        dir.path().join("enclos/sandboxes"),
        alias,
    ] {
        assert!(
            e.access_plan(&name, &write(&target)).is_err(),
            "approval {}",
            target.display()
        );
        // The policy editor refuses them too: the two surfaces share these limits.
        let edit = enclos_protocol::policy::PolicyChange {
            field: "write".into(),
            before: None,
            after: Some(target.display().to_string()),
        };
        assert!(
            e.mobile_policy_preview(&name, &state.base, &edit).is_err(),
            "policy editor {}",
            target.display()
        );
    }
    assert_eq!(e.policy(&name).unwrap().version.version, 1);
}

#[test]
fn access_approval_refuses_the_home_folder_and_the_folders_holding_it() {
    // enclos's folder outside the home, so nothing of enclos's own inside
    // it refuses a grant over the whole home.
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("users/alice");
    std::fs::create_dir_all(home.join("project")).unwrap();
    let e = engine_on(
        vec![Box::new(FakeBackend::available(BackendKind::Seatbelt))],
        Layout::at(dir.path().join("srv/enclos")).with_user_home(&home),
    );
    let name = super::policy::home_sandbox(&e);
    for target in [home.clone(), dir.path().join("users")] {
        let err = e
            .access_plan(&name, &write(&target))
            .err()
            .unwrap_or_else(|| panic!("{} was approvable", target.display()));
        assert!(err.to_string().contains("home folder"), "{err}");
    }
    assert!(e.access_plan(&name, &write(home.join("project"))).is_ok());
    assert_eq!(e.policy(&name).unwrap().version.version, 1);
}

#[test]
fn access_approval_warns_of_folders_on_the_hosts_path() {
    use crate::engine::approvals::write_risk;
    use std::path::{Path, PathBuf};
    let home = Path::new("/Users/alice");
    let path = [
        PathBuf::from("/opt/homebrew/bin"),
        PathBuf::from("/Users/alice/tools/bin"),
    ];
    for warned in [
        "/opt/homebrew/bin",
        "/opt/homebrew/bin/new",
        // Holds a PATH folder: its programs could be replaced.
        "/opt/homebrew",
        "/Users/alice/tools",
    ] {
        let why = write_risk(Path::new(warned), home, &path)
            .unwrap_or_else(|| panic!("{warned} has no warning"));
        assert!(why.contains("PATH"), "{why}");
    }
    for plain in ["/Users/alice/work", "/Volumes/Disk/projects", "/srv/data"] {
        assert_eq!(write_risk(Path::new(plain), home, &path), None, "{plain}");
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
    // The reviewed scope includes hidden entries beneath the granted folder.
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
