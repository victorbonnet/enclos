//! Compiling a sandbox's active policy into the sandbox's folder.

use super::policy::with_sandbox_on;
use super::sandbox::{with_backends, without_backend};
use super::*;
use crate::lifecycle::marker::spawn_unmarked;
use crate::probes::OwnProbes as _;

#[test]
fn the_active_policy_compiles_once_into_the_sandbox_folder() {
    let (_dir, engine, name) = with_sandbox_on(FakeBackend::available(BackendKind::Seatbelt));
    let file = engine.compile_policy(&name, 41001).unwrap();
    assert!(file.starts_with(engine.layout.sandbox_dir("home").join("compiled")));
    assert!(
        std::fs::read_to_string(&file)
            .unwrap()
            .contains("write {home}")
    );
    assert_eq!(engine.compile_policy(&name, 41001).unwrap(), file);
    // A new grant is a new compiled policy.
    done(
        engine
            .policy_allow(&alice(), &name, "api.example.com", Confirm::Yes)
            .unwrap(),
    );
    assert_ne!(engine.compile_policy(&name, 41001).unwrap(), file);
}

#[test]
fn the_compiled_text_is_shown_without_being_written() {
    let (_dir, engine, name) = with_sandbox_on(FakeBackend::available(BackendKind::Seatbelt));
    let text = engine.compiled_text(&name).unwrap();
    assert!(text.contains("write {home}"), "{text}");
    let compiled = engine.layout.sandbox_dir("home").join("compiled");
    assert!(!compiled.exists());
}

#[test]
fn a_cut_off_compiled_policy_is_never_reused() {
    let (_dir, engine, name) = with_sandbox_on(FakeBackend::available(BackendKind::Seatbelt));
    let file = engine.compile_policy(&name, 41001).unwrap();
    let full = std::fs::read_to_string(&file).unwrap();

    // What an interrupted write would have left: a valid start, no end.
    std::fs::write(&file, &full[..full.len() / 2]).unwrap();
    assert_eq!(engine.compile_policy(&name, 41001).unwrap(), file);
    assert_eq!(std::fs::read_to_string(&file).unwrap(), full);

    // A write that fails, here because a folder stands where the file
    // goes (which fails for root too), leaves nothing of the policy, and
    // the retry succeeds.
    std::fs::remove_file(&file).unwrap();
    std::fs::create_dir_all(file.join("in-the-way")).unwrap();
    assert!(engine.compile_policy(&name, 41001).is_err());
    assert!(file.is_dir());
    std::fs::remove_dir_all(&file).unwrap();
    let compiled = file.parent().unwrap();
    assert_eq!(engine.compile_policy(&name, 41001).unwrap(), file);
    assert_eq!(std::fs::read_to_string(&file).unwrap(), full);
    assert_eq!(std::fs::read_dir(compiled).unwrap().count(), 1);
}

#[test]
fn a_backend_this_host_cannot_run_is_refused_and_nothing_is_left() {
    let backend = FakeBackend::unavailable(BackendKind::Seatbelt, "not macOS");
    let (_dir, engine) = engine_with(vec![Box::new(backend)]);
    done(engine.init(&alice(), Confirm::Yes).unwrap());
    let spec = crate::engine::SandboxSpec {
        name: "home".parse().unwrap(),
        backend: BackendKind::Seatbelt,
        template: "assistant".parse().unwrap(),
    };
    let err = engine
        .create_sandbox(&alice(), spec, Confirm::Yes)
        .unwrap_err();
    assert!(matches!(err, Error::BackendUnavailable { .. }), "{err}");
    assert_eq!(err.exit_code(), 2);
    assert!(engine.list_sandboxes().unwrap().is_empty());
}

/// Puts the sandbox home aside, as the host can, and lets `replace` put
/// something else at its path.
fn replace_home(engine: &Engine, replace: impl FnOnce(&std::path::Path)) {
    let home = engine.layout.sandbox_home("home");
    std::fs::rename(&home, home.with_file_name("home-aside")).unwrap();
    replace(&home);
}

#[test]
fn a_home_that_is_not_a_real_folder_is_never_compiled() {
    let outside = std::path::PathBuf::from("/nonexistent-enclos-outside");
    let link_out = |home: &std::path::Path| std::os::unix::fs::symlink(&outside, home).unwrap();
    let a_file = |home: &std::path::Path| std::fs::write(home, "x").unwrap();
    let nothing = |_: &std::path::Path| {};
    for (replace, expected) in [
        (
            &link_out as &dyn Fn(&std::path::Path),
            HomeFound::Link {
                to: outside.clone(),
            },
        ),
        (&a_file, HomeFound::NotAFolder),
        (&nothing, HomeFound::Missing),
    ] {
        let (_dir, engine, name) = with_sandbox_on(FakeBackend::available(BackendKind::Seatbelt));
        engine.compile_policy(&name, 41001).unwrap();
        replace_home(&engine, replace);
        let err = engine.compile_policy(&name, 41001).unwrap_err();
        assert!(
            matches!(&err, Error::HomeNotAFolder { found, .. } if *found == expected),
            "{expected}: {err}"
        );
        assert!(err.to_string().contains("enclos sandbox rm home"), "{err}");
        assert_eq!(err.exit_code(), 1);
        // `show` and `status` say so: nothing new starts there.
        let shown = engine.show_sandbox(&name).unwrap().policy_refused;
        assert!(shown.is_some_and(|why| why.contains(&expected.to_string())));
    }
    let (_dir, engine, name) = with_sandbox_on(FakeBackend::available(BackendKind::Seatbelt));
    assert_eq!(engine.show_sandbox(&name).unwrap().policy_refused, None);
    replace_home(&engine, link_out);
    let status = engine.status(Some(&name)).unwrap();
    let refused = status.sandboxes[0].policy_refused.as_deref().unwrap();
    assert!(
        refused.contains("a symbolic link to /nonexistent"),
        "{refused}"
    );
}

/// Grants writes to `entries` by hand-editing `policy.toml`, applied by
/// the next `policy allow`.
fn grant_writes(engine: &Engine, name: &SandboxName, entries: &str) {
    let file = engine.layout.policy_file(name.as_str());
    let text = std::fs::read_to_string(&file)
        .unwrap()
        .replace("write_add = []", &format!("write_add = [{entries}]"));
    std::fs::write(&file, text).unwrap();
    done(
        engine
            .policy_allow(&alice(), name, "api.example.com", Confirm::Yes)
            .unwrap(),
    );
}

#[test]
fn policy_test_probes_each_workspace_once_and_names_one_not_made_yet() {
    let (dir, engine, name) = with_sandbox_on(FakeBackend::available(BackendKind::Seatbelt));
    let user = dir.path().canonicalize().unwrap();
    for d in ["a", "b"] {
        std::fs::create_dir(user.join(d)).unwrap();
    }
    grant_writes(&engine, &name, r#""~/a", "~/b", "~/a/", "~/later""#);
    let ctx = engine.sandbox_context(&name, 41001);
    let inputs = engine
        .probe_inputs(&name, &ctx, None, None, Default::default())
        .unwrap();
    let home = ctx.home.canonicalize().unwrap();
    assert_eq!(inputs.home, home);
    assert_eq!(
        inputs.workspaces,
        [user.join("a"), user.join("b"), user.join("later")]
    );
    let own = crate::backend::seatbelt::probes::SeatbeltProbes::on(
        crate::backend::seatbelt::Baseline::DenyDefault,
    );
    let names: Vec<String> = crate::probes::probes(&inputs, &own)
        .into_iter()
        .filter(|p| p.route == "writable folders")
        .map(|p| p.name)
        .collect();
    let rename = |p: &std::path::Path| format!("rename {}", p.display());
    assert_eq!(
        names,
        [
            "remove the sandbox home".to_owned(),
            rename(&home),
            rename(&user.join("a")),
            rename(&user.join("b")),
        ]
    );
    let missing = own.folders_not_run(&inputs);
    assert_eq!(missing.len(), 1);
    assert_eq!(missing[0].name, rename(&user.join("later")));
    assert!(
        matches!(&missing[0].outcome, crate::probes::Outcome::NotRun(why) if why.contains("create it on the host"))
    );
    // A backend with no such probe has none to call not run, which would
    // fail its test.
    let fake = FakeBackend::available(BackendKind::Seatbelt)
        .own_probes(None)
        .unwrap();
    assert!(fake.folders_not_run(&inputs).is_empty());
}

/// A dry run asks nothing of the host, so a backend this host cannot run
/// still counts its probes; one not in this build has none to count.
#[test]
fn a_policy_test_dry_run_counts_on_an_unavailable_backend_and_needs_it_in_the_build() {
    let (_dir, engine, name) = with_sandbox_on(FakeBackend::available(BackendKind::Seatbelt));
    let unavailable = without_backend(&engine);
    let Planned::DryRun(plan) = unavailable
        .policy_test(&alice(), &name, false, Confirm::DryRun)
        .unwrap()
    else {
        panic!("a dry run plans");
    };
    assert!(
        plan.changes
            .iter()
            .any(|c| c.starts_with("run ") && c.contains(" escape probes in sandbox home ")),
        "{:?}",
        plan.changes
    );
    let not_in_this_build = with_backends(&engine, Vec::new());
    let err = not_in_this_build
        .policy_test(&alice(), &name, false, Confirm::DryRun)
        .unwrap_err();
    assert!(
        matches!(&err, Error::BackendUnavailable { reason, .. } if reason.contains("does not include it")),
        "{err}"
    );
}

/// A backend with no probes of its own runs the shared set through its
/// `wrap`: the fake holds nothing back, so a write and a signal get out
/// and read open, on what the host sees.
#[test]
fn a_fake_backend_s_probes_run_through_the_shared_set() {
    use crate::backend::{Launch, LaunchLimits};
    use crate::probes::{Outcome, probes};
    let (_dir, engine, name) = with_sandbox_on(FakeBackend::available(BackendKind::Seatbelt));
    let backend = engine.backend_of(&name).unwrap();
    let own = backend.own_probes(Some("fake policy for home\n")).unwrap();
    assert_eq!(own.notes().baseline_key, None);
    assert_eq!(own.notes().comparison, None);
    // This test's own child, the signal probe's target.
    let mut target = spawn_unmarked(std::process::Command::new("/bin/sleep").arg("60")).unwrap();
    let ctx = engine.sandbox_context(&name, 41001);
    let inputs = engine
        .probe_inputs(
            &name,
            &ctx,
            Some(target.id()),
            None,
            LaunchLimits::default(),
        )
        .unwrap();
    let list = probes(&inputs, own.as_ref());
    assert!(own.host_services(&inputs).is_empty());
    for route in ["writes", "signals"] {
        let probe = list.iter().find(|p| p.route == route).unwrap();
        let got = crate::engine::probe::run_probe(
            probe,
            |script| {
                let launch = Launch {
                    program: "/bin/sh".into(),
                    args: vec!["-c".into(), script.into()],
                    env: Vec::new(),
                    in_terminal: false,
                    service_port: None,
                    dashboard_socket: false,
                    limits: LaunchLimits::default(),
                    reads: Vec::new(),
                };
                backend
                    .wrap(std::path::Path::new("unused"), &ctx, &launch)
                    .unwrap()
                    .stdin(std::process::Stdio::null())
                    .output()
            },
            &mut target,
        );
        assert!(matches!(got, Outcome::Open(_)), "{route}: {got:?}");
    }
    let _ = target.kill();
    let _ = target.wait();
}

#[test]
fn the_write_rules_are_checked_again_as_the_paths_are_when_compiled() {
    let (dir, engine, name) = with_sandbox_on(FakeBackend::available(BackendKind::Seatbelt));
    let work = dir.path().join("work");
    std::fs::create_dir(&work).unwrap();
    grant_writes(&engine, &name, "\"~/work\"");
    assert!(
        engine
            .policy(&name)
            .unwrap()
            .snapshot
            .policy
            .fs
            .write
            .contains(&"~/work".into())
    );
    engine.compile_policy(&name, 41001).unwrap();

    // The host points the workspace at enclos's own folder afterwards.
    std::fs::remove_dir(&work).unwrap();
    std::os::unix::fs::symlink(engine.layout.data(), &work).unwrap();
    let err = engine.compile_policy(&name, 41001).unwrap_err();
    assert!(matches!(err, Error::ActivePolicyInvalid { .. }), "{err}");
    assert!(err.to_string().contains("enclos's own files"), "{err}");
    assert_eq!(err.exit_code(), 1);

    // Or through a link in the sandbox home, which the sandbox can
    // point anywhere before the next compile.
    std::fs::remove_file(&work).unwrap();
    let in_home = engine.layout.sandbox_home("home").join("out");
    std::os::unix::fs::symlink(dir.path(), &in_home).unwrap();
    std::os::unix::fs::symlink(&in_home, &work).unwrap();
    let err = engine.compile_policy(&name, 41001).unwrap_err();
    assert!(matches!(err, Error::ActivePolicyInvalid { .. }), "{err}");
    assert!(err.to_string().contains("through a link"), "{err}");
}

/// The backend's own places, checked when a policy is stored and each time
/// it is compiled, through a link as it is then: a workspace that led to a
/// folder of the user's may lead to `/dev` by the next session.
#[test]
fn a_workspace_that_leads_to_the_backends_own_place_is_refused_when_stored_and_compiled() {
    use crate::policy::own_places::{OwnPlace, OwnPlaces, links};
    let dev = OwnPlaces(&[OwnPlace {
        path: "/dev",
        holds_workspaces: false,
    }]);
    let (dir, engine, name) =
        with_sandbox_on(FakeBackend::available(BackendKind::Seatbelt).with_own_places(dev));
    let user = dir.path().canonicalize().unwrap();
    std::fs::create_dir(user.join("work")).unwrap();
    let alias = user.join("alias");
    std::os::unix::fs::symlink("work", &alias).unwrap();
    grant_writes(&engine, &name, "\"~/alias\"");
    engine.compile_policy(&name, 41001).unwrap();

    std::fs::remove_file(&alias).unwrap();
    std::os::unix::fs::symlink(links::relative(&user, "/dev"), &alias).unwrap();
    let err = engine.compile_policy(&name, 41001).unwrap_err();
    assert!(matches!(err, Error::ActivePolicyInvalid { .. }), "{err}");
    assert!(err.to_string().contains("host's /dev"), "{err}");

    // Stored again, as any change to the policy stores it.
    let err = engine
        .policy_allow(&alice(), &name, "api.example.org", Confirm::Yes)
        .unwrap_err();
    assert!(err.to_string().contains("host's /dev"), "{err}");
    assert_eq!(err.exit_code(), 2);
}

/// With macOS's own Seatbelt: the sandbox cannot put a link in place of
/// its home, and when the host does, the policy is not compiled.
#[cfg(target_os = "macos")]
#[test]
fn a_sandbox_cannot_swap_its_home_and_a_swapped_home_is_never_compiled() {
    use crate::backend::Launch;
    use crate::backend::seatbelt::Seatbelt;

    let (dir, engine) = engine_with(vec![Box::new(Seatbelt::default())]);
    done(engine.init(&alice(), Confirm::Yes).unwrap());
    let name: SandboxName = "home".parse().unwrap();
    let spec = crate::engine::SandboxSpec {
        name: name.clone(),
        backend: BackendKind::Seatbelt,
        template: "assistant".parse().unwrap(),
    };
    done(engine.create_sandbox(&alice(), spec, Confirm::Yes).unwrap());
    let compiled = engine.compile_policy(&name, 41001).unwrap();
    let home = engine.layout.sandbox_home("home");
    let outside = dir.path().canonicalize().unwrap();
    let swap = format!(
        "/bin/rmdir \"$HOME/tmp\"; /bin/rmdir \"$HOME\" && /bin/ln -s '{}' \"$HOME\"",
        outside.display()
    );
    let launch = Launch {
        program: "/bin/sh".into(),
        args: vec!["-c".into(), swap.into()],
        env: Vec::new(),
        in_terminal: false,
        service_port: None,
        dashboard_socket: false,
        limits: Default::default(),
        reads: Vec::new(),
    };
    let ctx = engine.sandbox_context(&name, 41001);
    let out = Seatbelt::default()
        .wrap(&compiled, &ctx, &launch)
        .unwrap()
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success());
    assert!(stderr.contains("Operation not permitted"), "{stderr}");
    let meta = home.symlink_metadata().unwrap();
    assert!(meta.is_dir() && !meta.file_type().is_symlink());

    replace_home(&engine, |home| {
        std::os::unix::fs::symlink(&outside, home).unwrap();
    });
    let err = engine.compile_policy(&name, 41001).unwrap_err();
    assert!(
        matches!(&err, Error::HomeNotAFolder { found: HomeFound::Link { to }, .. } if *to == outside),
        "{err}"
    );
}

/// An engine whose data folder is reached through a link, with one sandbox
/// on `kind`.
fn behind_a_link_on(kind: BackendKind) -> (TempDir, Engine, SandboxName, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path().canonicalize().unwrap();
    std::fs::create_dir(base.join("real")).unwrap();
    std::os::unix::fs::symlink(base.join("real"), base.join("e")).unwrap();
    let layout = Layout::at(base.join("e"));
    let state = SqliteStateStore::new(
        layout.state_db(),
        layout.state_lock(),
        crate::state::Wait::Command,
    );
    let audit = JsonlAuditLog::new(layout.audit_log());
    let backend = FakeBackend::available(kind);
    let engine = Engine::new(
        layout,
        Box::new(state),
        Box::new(audit),
        vec![Box::new(backend)],
    );
    done(engine.init(&alice(), Confirm::Yes).unwrap());
    let name: SandboxName = "home".parse().unwrap();
    let spec = crate::engine::SandboxSpec {
        name: name.clone(),
        backend: kind,
        template: "assistant".parse().unwrap(),
    };
    done(engine.create_sandbox(&alice(), spec, Confirm::Yes).unwrap());
    (dir, engine, name, base.join("real"))
}

/// The backend kind decides, not the host's system: under one bind of `/`
/// the real folder shows, so a bubblewrap sandbox's probes read it too.
#[test]
fn a_protected_file_behind_a_link_is_probed_at_its_real_path_for_bubblewrap_alone() {
    for (kind, probed) in [
        (BackendKind::Bubblewrap, true),
        (BackendKind::Seatbelt, false),
    ] {
        let (_dir, engine, name, real) = behind_a_link_on(kind);
        let ctx = engine.sandbox_context(&name, 41001);
        let inputs = engine
            .probe_inputs(&name, &ctx, None, None, Default::default())
            .unwrap();
        let hidden = engine.layout.hidden_files();
        assert_eq!(&inputs.hidden_files[..hidden.len()], hidden, "{kind:?}");
        assert!(
            inputs.hidden_files.contains(&real.join("state.db")) == probed,
            "{kind:?}"
        );
        assert!(
            inputs.hidden_files.contains(&real.join("run")) == probed,
            "{kind:?}"
        );
    }
}

/// An `autonomous` sandbox (ADR 0058), as the engine builds what its probes
/// and compiler start from: enclos's program by every path that leads to
/// it, the whole filesystem granted, every port open, and what the policy
/// opens said in the report.
#[test]
fn an_autonomous_sandbox_keeps_enclos_program_by_every_path_and_opens_every_port() {
    let (dir, engine) = engine_with(vec![Box::new(FakeBackend::available(
        BackendKind::Seatbelt,
    ))]);
    let base = dir.path().canonicalize().unwrap();
    for d in ["bin", "cellar"] {
        std::fs::create_dir(base.join(d)).unwrap();
    }
    std::fs::write(base.join("cellar/enclos"), "p").unwrap();
    std::os::unix::fs::symlink(base.join("cellar/enclos"), base.join("bin/enclos")).unwrap();
    let engine = engine.with_exe(base.join("bin/enclos"));
    done(engine.init(&alice(), Confirm::Yes).unwrap());
    let name: SandboxName = "keeper".parse().unwrap();
    let spec = crate::engine::SandboxSpec {
        name: name.clone(),
        backend: BackendKind::Seatbelt,
        template: "autonomous".parse().unwrap(),
    };
    done(engine.create_sandbox(&alice(), spec, Confirm::Yes).unwrap());
    let ctx = engine.sandbox_context(&name, 41001);
    assert_eq!(ctx.program, Some(vec![base.join("bin/enclos")]));
    let inputs = engine
        .probe_inputs(&name, &ctx, None, None, Default::default())
        .unwrap();
    assert_eq!(
        inputs.program,
        [base.join("bin/enclos"), base.join("cellar/enclos")]
    );
    assert!(inputs.writes.contains(&std::path::PathBuf::from("/")));
    assert!(inputs.every_port);
    assert!(inputs.unmovable.contains(&base.join("bin")));
    assert!(inputs.unmovable.contains(&base.join("cellar")));
    assert!(!inputs.unmovable.contains(&std::path::PathBuf::from("/")));
    assert_eq!(crate::probes::open_by_policy(&inputs).len(), 2);
}

/// On bubblewrap, which cannot keep a path unchanged inside a folder the
/// sandbox writes yet, an `autonomous` sandbox is refused and nothing is
/// left, and so is a workspace holding enclos's program (ADR 0058).
#[test]
fn bubblewrap_refuses_the_whole_filesystem_and_a_workspace_holding_enclos_program() {
    let (dir, engine) = engine_with(vec![Box::new(FakeBackend::available(
        BackendKind::Bubblewrap,
    ))]);
    let base = dir.path().canonicalize().unwrap();
    std::fs::create_dir(base.join("bin")).unwrap();
    std::fs::write(base.join("bin/enclos"), "p").unwrap();
    let engine = engine.with_exe(base.join("bin/enclos"));
    done(engine.init(&alice(), Confirm::Yes).unwrap());
    let spec = |name: &str, template: &str| crate::engine::SandboxSpec {
        name: name.parse().unwrap(),
        backend: BackendKind::Bubblewrap,
        template: template.parse().unwrap(),
    };
    let err = engine
        .create_sandbox(&alice(), spec("keeper", "autonomous"), Confirm::Yes)
        .unwrap_err();
    assert!(
        err.to_string()
            .contains("not built on the bubblewrap backend"),
        "{err}"
    );
    assert!(!engine.layout.sandbox_dir("keeper").exists());

    done(
        engine
            .create_sandbox(&alice(), spec("lab", "assistant"), Confirm::Yes)
            .unwrap(),
    );
    let name: SandboxName = "lab".parse().unwrap();
    let file = engine.layout.policy_file("lab");
    let text = std::fs::read_to_string(&file)
        .unwrap()
        .replace("write_add = []", "write_add = [\"~/bin\"]");
    std::fs::write(&file, text).unwrap();
    let err = engine
        .policy_allow(&alice(), &name, "api.example.com", Confirm::Yes)
        .unwrap_err();
    assert!(
        err.to_string().contains("holds enclos's own program"),
        "{err}"
    );
}
