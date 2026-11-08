use super::policy::with_sandbox;
use super::*;
use enclos_protocol::policy::PolicyChange;
fn edit(field: &str, before: Option<&str>, after: Option<&str>) -> PolicyChange {
    PolicyChange {
        field: field.into(),
        before: before.map(str::to_owned),
        after: after.map(str::to_owned),
    }
}
fn save(e: &Engine, name: &crate::model::sandbox::SandboxName, change: &PolicyChange) {
    let state = e.mobile_policy(name).unwrap();
    let p = e.mobile_policy_preview(name, &state.base, change).unwrap();
    e.mobile_policy_apply(&alice(), name, &state.base, &p.revision, change)
        .unwrap();
}
#[test]
fn mobile_policy_removes_an_accepted_grant_without_touching_other_fields() {
    let (_dir, e, name) = with_sandbox();
    let a = enclos_protocol::approval::Access {
        kind: enclos_protocol::approval::AccessKind::Network,
        target: "api.example.com:8443".into(),
        private: false,
    };
    let p = e.access_plan(&name, &a).unwrap();
    e.approve_access(&alice(), &name, &a, &p.revision).unwrap();
    let mut expected = e.policy(&name).unwrap().snapshot.policy;
    expected.net.allow.clear();
    save(
        &e,
        &name,
        &edit("allow", Some("api.example.com:8443"), None),
    );
    assert_eq!(e.policy(&name).unwrap().snapshot.policy, expected);
    assert!(!e.access_context(&name).unwrap().contains("api.example.com"));
    assert!(e.verify_audit().unwrap().intact());
}
#[test]
fn mobile_policy_edits_inherited_defaults_only_for_this_sandbox() {
    let (_dir, e, name) = with_sandbox();
    save(&e, &name, &edit("mode", Some("public"), Some("allowlist")));
    assert_eq!(
        e.policy(&name).unwrap().snapshot.policy.net.mode,
        crate::model::policy::NetMode::Allowlist
    );
    assert!(
        crate::policy::resolve(
            &crate::policy::initial_overrides("other", &"assistant".parse().unwrap()),
            None
        )
        .unwrap()
        .policy
        .net
        .mode
            == crate::model::policy::NetMode::Public
    );
}
#[test]
fn mobile_policy_rejects_stale_previews_and_edited_requests() {
    let (_dir, e, name) = with_sandbox();
    let state = e.mobile_policy(&name).unwrap();
    let change = edit("allow", None, Some("one.example.com"));
    let p = e
        .mobile_policy_preview(&name, &state.base, &change)
        .unwrap();
    assert!(
        e.mobile_policy_apply(
            &alice(),
            &name,
            &state.base,
            &p.revision,
            &edit("allow", None, Some("two.example.com"))
        )
        .is_err()
    );
    done(
        e.policy_allow(&alice(), &name, "other.example.com", Confirm::Yes)
            .unwrap(),
    );
    assert!(
        e.mobile_policy_apply(&alice(), &name, &state.base, &p.revision, &change)
            .is_err()
    );
    assert!(!e.allows(&name, "one.example.com").unwrap());
}
#[test]
fn mobile_policy_cannot_drop_protected_defaults_or_edit_secret_grants() {
    let (_dir, e, name) = with_sandbox();
    let state = e.mobile_policy(&name).unwrap();
    for c in [
        edit("read_deny", Some("~/.ssh"), None),
        edit("secrets", None, Some("TOKEN=secret")),
        edit("allow", None, Some("127.0.0.1")),
        edit("mode", Some("public"), Some("anything")),
    ] {
        assert!(
            e.mobile_policy_preview(&name, &state.base, &c).is_err(),
            "{c:?}"
        );
    }
}
#[test]
fn mobile_policy_remove_private_destination_cleans_up_its_opt_in() {
    let (_dir, e, name) = with_sandbox();
    let a = enclos_protocol::approval::Access {
        kind: enclos_protocol::approval::AccessKind::Network,
        target: "10.0.0.1:8443".into(),
        private: true,
    };
    let p = e.access_plan(&name, &a).unwrap();
    e.approve_access(&alice(), &name, &a, &p.revision).unwrap();
    save(&e, &name, &edit("allow", Some("10.0.0.1:8443"), None));
    assert!(
        e.policy(&name)
            .unwrap()
            .snapshot
            .policy
            .net
            .private
            .is_empty()
    );
}
#[test]
fn mobile_policy_writes_are_resolved_and_cannot_apply_unreviewed_file_edits() {
    let (dir, e, name) = with_sandbox();
    let target = dir.path().join("work");
    std::fs::create_dir(&target).unwrap();
    let text = target.display().to_string();
    save(&e, &name, &edit("write", None, Some(&text)));
    let state = e.mobile_policy(&name).unwrap();
    let file = e.policy(&name).unwrap().file;
    let before = std::fs::read_to_string(&file).unwrap();
    std::fs::write(file, format!("{before}\n# another editor\n")).unwrap();
    assert!(
        e.mobile_policy_preview(&name, &state.base, &edit("write", Some(&text), None))
            .is_err()
    );
}
#[test]
fn mobile_policy_restart_requirement_is_reviewed_and_pending_edits_block_new_changes() {
    use super::sandbox::{Sleeping, put, session_of};
    let (dir, e, name) = with_sandbox();
    let state = e.mobile_policy(&name).unwrap();
    let work = dir.path().join("work").display().to_string();
    let change = edit("write", None, Some(&work));
    let p = e
        .mobile_policy_preview(&name, &state.base, &change)
        .unwrap();
    assert!(!p.restart);
    let sleeping = Sleeping::new();
    let mut session = session_of(&e, &name, sleeping.process());
    session.compiled = Some("/compiled/rules.sb".into());
    let _id = put(&e, &session);
    assert!(
        e.mobile_policy_apply(&alice(), &name, &state.base, &p.revision, &change)
            .is_err()
    );
    assert!(
        e.mobile_policy_preview(&name, &state.base, &change)
            .unwrap()
            .restart
    );
    let before = e.layout.read_policy(name.as_str()).unwrap();
    let after = before.replace("write_add = []", &format!("write_add = [\"{work}\"]"));
    done(
        e.policy_edit(&alice(), &name, &before, &after, Confirm::Ask)
            .unwrap(),
    );
    assert!(!e.mobile_policy(&name).unwrap().editable);
}
