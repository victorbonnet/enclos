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
    assert_eq!(
        e.audit(None).unwrap().last().unwrap().intent.command,
        "app approval"
    );
    assert!(e.verify_audit().unwrap().intact());
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
fn an_approval_revision_cannot_apply_to_a_recreated_same_name_sandbox() {
    let (_dir, engine, name) = with_sandbox();
    let access = network("api.example.com");
    let old = engine.access_plan(&name, &access).unwrap();
    let original_policy = engine.policy(&name).unwrap().snapshot.id;
    let old_second = engine.sandbox_created_at(&name).unwrap().as_second();
    done(
        engine
            .remove_sandbox(&alice(), &name, false, Confirm::Yes)
            .unwrap(),
    );
    done(
        engine
            .create_sandbox(
                &alice(),
                SandboxSpec {
                    name: name.clone(),
                    backend: BackendKind::Seatbelt,
                    template: "assistant".parse().unwrap(),
                },
                Confirm::Yes,
            )
            .unwrap(),
    );
    let lock = engine.state.lock().unwrap();
    let mut record = engine.state.get(&name).unwrap().unwrap();
    record.created_at = crate::model::Timestamp::from_second(old_second + 2).unwrap();
    engine.state.put(&lock, &record).unwrap();
    drop(lock);
    assert_eq!(engine.policy(&name).unwrap().snapshot.id, original_policy);
    assert!(
        engine
            .approve_access(&alice(), &name, &access, &old.revision)
            .is_err()
    );
    assert!(
        engine
            .policy(&name)
            .unwrap()
            .snapshot
            .policy
            .net
            .allow
            .is_empty()
    );
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
