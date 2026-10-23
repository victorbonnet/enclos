//! `enclos doctor` (design §10): whether the host runs each backend, whether
//! each sandbox's next session can compile its policy, and which files its
//! sessions ran under its policy now compiles differently from (ADR 0018).

use std::path::PathBuf;

use super::policy::with_sandbox;
use super::sandbox::{Sleeping, gone_process, put, session_of};
use super::*;
use crate::engine::{
    BackendState, Doctor, DriftKind, LineChange, Lines, NextSession, RanFile, Running,
    SandboxCheck, Sandboxes,
};
use crate::model::sandbox::SandboxName;
use crate::model::session::SessionRecord;

fn check_of(doctor: &Doctor, name: &SandboxName) -> SandboxCheck {
    let Sandboxes::Listed(sandboxes) = &doctor.sandboxes else {
        panic!("{doctor:?}");
    };
    sandboxes.iter().find(|s| s.name == *name).unwrap().clone()
}

fn port(engine: &Engine, name: &SandboxName) -> u16 {
    engine.state.get(name).unwrap().unwrap().proxy_port
}

/// The file the active policy compiles to, written as a session start
/// writes it.
fn compiled_now(engine: &Engine, name: &SandboxName) -> PathBuf {
    engine.compile_policy(name, port(engine, name)).unwrap()
}

/// A file this sandbox's policy compiled to under an earlier enclos, named
/// by its own digest: what it compiles to now, and a line this enclos no
/// longer writes.
fn compiled_earlier(engine: &Engine, name: &SandboxName) -> PathBuf {
    let (now, text) = engine.compiled_file(name, port(engine, name)).unwrap();
    let earlier_text = format!("{text}a rule enclos dropped\n");
    let digest = crate::policy::sha256_hex(earlier_text.as_bytes());
    let earlier = now.with_file_name(format!("{}.fake", &digest[..16]));
    std::fs::create_dir_all(earlier.parent().unwrap()).unwrap();
    std::fs::write(&earlier, earlier_text).unwrap();
    earlier
}

/// A session of `name` that ran under `file`.
fn ran_under(
    engine: &Engine,
    name: &SandboxName,
    root: crate::model::session::ProcessRef,
    file: &std::path::Path,
) -> SessionRecord {
    let mut session = session_of(engine, name, root);
    session.compiled = Some(file.display().to_string());
    put(engine, &session);
    session
}

fn ended(engine: &Engine, name: &SandboxName) {
    let lock = engine.state.lock().unwrap();
    let ids: Vec<_> = engine
        .state
        .sessions(name, true)
        .unwrap()
        .iter()
        .map(|s| s.id)
        .collect();
    let record = engine.state.get(name).unwrap().unwrap();
    engine.state.end_sessions(&lock, &ids, &record).unwrap();
}

/// A change found, flattened for the tests: `lines` is none once the file
/// it ran under is gone.
#[derive(Debug)]
struct Change {
    version: u32,
    ran: PathBuf,
    now: PathBuf,
    edited: bool,
    lines: Option<Lines>,
    running: Running,
}

fn changed(check: &SandboxCheck) -> Vec<Change> {
    check
        .drift
        .iter()
        .filter_map(|d| match &d.kind {
            DriftKind::Changed { now, ran_file } => Some(Change {
                version: d.version,
                ran: d.ran.clone(),
                now: now.clone(),
                edited: matches!(ran_file, RanFile::There { edited: true, .. }),
                lines: match ran_file {
                    RanFile::Gone => None,
                    RanFile::There { lines, .. } => Some(lines.clone()),
                },
                running: d.running,
            }),
            DriftKind::NoLongerCompiles { .. } => None,
        })
        .collect()
}

/// The versions said to no longer compile, with why.
fn no_longer_compiles(check: &SandboxCheck) -> Vec<(u32, String)> {
    check
        .drift
        .iter()
        .filter_map(|d| match &d.kind {
            DriftKind::NoLongerCompiles { error } => Some((d.version, error.clone())),
            DriftKind::Changed { .. } => None,
        })
        .collect()
}

/// `policy edit` of sandbox `home` adding `path` to what it writes.
fn grant_write(engine: &Engine, path: &std::path::Path) {
    let before = engine.layout.read_policy("home").unwrap();
    let after = match before.contains("write_add = []") {
        true => before.replace(
            "write_add = []",
            &format!("write_add = [\"{}\"]", path.display()),
        ),
        false => before.replace(
            "write_add = [",
            &format!("write_add = [\"{}\", ", path.display()),
        ),
    };
    engine
        .policy_edit(
            &alice(),
            &"home".parse().unwrap(),
            &before,
            &after,
            Confirm::Yes,
        )
        .unwrap();
}

/// `policy edit` of sandbox `home` putting back what it was created with.
fn ungrant_writes(engine: &Engine, created: &str) {
    let before = engine.layout.read_policy("home").unwrap();
    engine
        .policy_edit(
            &alice(),
            &"home".parse().unwrap(),
            &before,
            created,
            Confirm::Yes,
        )
        .unwrap();
}

#[test]
fn before_init_the_backends_are_still_checked() {
    let (_dir, engine) = engine_with(vec![Box::new(FakeBackend::available(
        BackendKind::Seatbelt,
    ))]);
    let doctor = engine.doctor();
    assert_eq!(doctor.backends[0].state, BackendState::Runs);
    assert!(doctor.backends[0].runs_here());
    assert_eq!(doctor.sandboxes, Sandboxes::NotInitialized);
    assert!(!doctor.has_problems());
}

#[test]
fn a_backend_not_on_this_host_is_not_tried() {
    let (_dir, engine) = engine_with(vec![Box::new(FakeBackend::unavailable(
        BackendKind::Seatbelt,
        "not on this host",
    ))]);
    let doctor = engine.doctor();
    assert_eq!(
        doctor.backends[0].state,
        BackendState::NotFound {
            reason: "not on this host".into()
        }
    );
    assert!(doctor.has_problems());
}

/// A backend that is there and refuses to run a program, as Seatbelt does
/// in a process already in a sandbox whose policy has a deny rule, runs no
/// sandbox: nothing is compiled for its sandboxes, and that is said once.
#[test]
fn a_backend_that_refuses_to_run_is_a_problem_and_nothing_is_compiled() {
    let (_dir, engine, name) = super::policy::with_sandbox_on(FakeBackend::refuses_to_run(
        BackendKind::Seatbelt,
        "sandbox_apply: Operation not permitted",
    ));
    let doctor = engine.doctor();
    assert_eq!(
        doctor.backends[0].state,
        BackendState::Refuses {
            reason: "sandbox_apply: Operation not permitted".into()
        }
    );
    let check = check_of(&doctor, &name);
    assert!(!check.backend_runs());
    assert_eq!(check.next, NextSession::NotChecked);
    assert!(check.unreadable.is_empty(), "{check:?}");
    assert!(doctor.has_problems());
}

#[test]
fn a_sandbox_with_no_session_yet_is_checked_for_its_next_one() {
    let (_dir, engine, name) = with_sandbox();
    let doctor = engine.doctor();
    let check = check_of(&doctor, &name);
    assert!(
        matches!(check.next, NextSession::Compiles { version: 1, .. }),
        "{check:?}"
    );
    assert_eq!(check.last_version, None);
    assert!(check.drift.is_empty());
    assert!(!doctor.has_problems());
}

/// Its next session compiles the active policy, whatever its last one ran:
/// a home gone stops it, though no session ran yet.
#[test]
fn a_next_session_that_cannot_compile_its_policy_is_a_problem() {
    let (_dir, engine, name) = with_sandbox();
    std::fs::remove_dir_all(engine.layout.sandbox_home(name.as_str())).unwrap();
    let doctor = engine.doctor();
    let NextSession::Fails { error } = check_of(&doctor, &name).next else {
        panic!("{doctor:?}");
    };
    assert!(error.contains("home"), "{error}");
    assert!(doctor.has_problems());
}

#[test]
fn a_policy_that_compiles_as_it_did_has_no_drift() {
    let (_dir, engine, name) = with_sandbox();
    let file = compiled_now(&engine, &name);
    ran_under(&engine, &name, gone_process(), &file);
    let check = check_of(&engine.doctor(), &name);
    assert_eq!(check.last_version, Some(1));
    assert!(check.drift.is_empty(), "{check:?}");
}

/// The same version compiled to another file than a session ran under: the
/// lines are shown, with the sessions that still run under it.
#[test]
fn a_policy_enclos_now_compiles_differently_is_shown_with_its_lines() {
    let (_dir, engine, name) = with_sandbox();
    let earlier = compiled_earlier(&engine, &name);
    let sleeping = Sleeping::new();
    ran_under(&engine, &name, sleeping.process(), &earlier);
    let doctor = engine.doctor();
    let check = check_of(&doctor, &name);
    let [change] = changed(&check).try_into().unwrap();
    assert_eq!(change.version, 1);
    assert_eq!(change.ran, earlier);
    assert_eq!(
        change.now,
        engine.compiled_file(&name, port(&engine, &name)).unwrap().0
    );
    assert!(!change.edited);
    assert_eq!(
        change.lines,
        Some(Lines::Changed(vec![LineChange::Removed(
            "a rule enclos dropped".into()
        )]))
    );
    assert_eq!(
        change.running,
        Running {
            count: 1,
            unsure: false
        }
    );
    // A drift is shown, not a problem.
    assert!(!doctor.has_problems());

    // Once the file it ran under is gone, the change is still named.
    drop(sleeping);
    std::fs::remove_file(&earlier).unwrap();
    let [change] = changed(&check_of(&engine.doctor(), &name))
        .try_into()
        .unwrap();
    assert_eq!(change.lines, None);
    assert_eq!(change.running, Running::default());
}

/// A file whose name, its digest, no longer matches what it holds was
/// changed after it was written: that is said, not an upgrade.
#[test]
fn a_compiled_file_changed_after_it_was_written_is_named_as_such() {
    let (_dir, engine, name) = with_sandbox();
    let file = compiled_now(&engine, &name);
    ran_under(&engine, &name, gone_process(), &file);
    let text = std::fs::read_to_string(&file).unwrap();
    std::fs::write(&file, format!("{text}(allow default)\n")).unwrap();
    let [change] = changed(&check_of(&engine.doctor(), &name))
        .try_into()
        .unwrap();
    assert!(change.edited);
    assert_eq!(
        change.lines,
        Some(Lines::Changed(vec![LineChange::Removed(
            "(allow default)".into()
        )]))
    );
}

/// The version compared is the session's, not the active one: a change
/// applied since is `policy diff`'s, not a drift.
#[test]
fn a_session_on_an_earlier_version_is_compared_with_that_version() {
    let (dir, engine, name) = with_sandbox();
    let file = compiled_now(&engine, &name);
    ran_under(&engine, &name, gone_process(), &file);
    ended(&engine, &name);
    let work = dir.path().join("work");
    std::fs::create_dir_all(&work).unwrap();
    let before = engine.layout.read_policy("home").unwrap();
    let after = match before.contains("write_add = []") {
        true => before.replace(
            "write_add = []",
            &format!("write_add = [\"{}\"]", work.display()),
        ),
        false => before.replace(
            "write_add = [",
            &format!("write_add = [\"{}\", ", work.display()),
        ),
    };
    engine
        .policy_edit(&alice(), &name, &before, &after, Confirm::Yes)
        .unwrap();
    let check = check_of(&engine.doctor(), &name);
    assert!(
        matches!(check.next, NextSession::Compiles { version: 2, .. }),
        "{check:?}"
    );
    assert_eq!(check.last_version, Some(1));
    assert!(check.drift.is_empty(), "{check:?}");
}

/// A session still running under an earlier file is shown though a later
/// session ran under the file of now.
#[test]
fn a_running_session_under_an_earlier_file_is_shown_after_a_later_one() {
    let (_dir, engine, name) = with_sandbox();
    let earlier = compiled_earlier(&engine, &name);
    let sleeping = Sleeping::new();
    ran_under(&engine, &name, sleeping.process(), &earlier);
    let file = compiled_now(&engine, &name);
    ran_under(&engine, &name, gone_process(), &file);
    let [change] = changed(&check_of(&engine.doctor(), &name))
        .try_into()
        .unwrap();
    assert_eq!(change.ran, earlier);
    assert_eq!(change.running.count, 1);

    // A gone session keeps no compiled policy: once nothing of it runs,
    // the later session is the one compared.
    drop(sleeping);
    assert!(check_of(&engine.doctor(), &name).drift.is_empty());
}

/// A version a session ran under that is not recorded is said, with what
/// was looked at, and the other files are still compared.
#[test]
fn a_session_whose_policy_version_is_not_recorded_is_a_problem() {
    let (_dir, engine, name) = with_sandbox();
    let earlier = compiled_earlier(&engine, &name);
    let sleeping = Sleeping::new();
    ran_under(&engine, &name, sleeping.process(), &earlier);
    let file = compiled_now(&engine, &name);
    let mut session = session_of(&engine, &name, gone_process());
    session.version = 99;
    session.compiled = Some(file.display().to_string());
    put(&engine, &session);
    let doctor = engine.doctor();
    let check = check_of(&doctor, &name);
    let not_compared = format!(
        "policy v99, which a session ran under ({}), was not compared: it is not recorded",
        file.display()
    );
    assert!(
        check
            .unreadable
            .iter()
            .any(|u| u.starts_with(&not_compared)),
        "{check:?}"
    );
    let [change] = changed(&check).try_into().unwrap();
    assert_eq!(change.ran, earlier);
    assert!(matches!(check.next, NextSession::Compiles { .. }));
    assert!(doctor.has_problems());
}

/// Records that cannot be read are said, and the backends still checked.
#[test]
fn records_that_cannot_be_read_are_a_problem() {
    let (_dir, engine, _name) = with_sandbox();
    std::fs::write(engine.layout.state_db(), "not a database").unwrap();
    let doctor = engine.doctor();
    assert!(
        matches!(doctor.sandboxes, Sandboxes::Unreadable { .. }),
        "{doctor:?}"
    );
    assert!(doctor.backends[0].runs_here());
    assert!(doctor.has_problems());
}

/// A home gone is the next session's to say: an earlier version is then
/// not compared, rather than said to no longer compile.
#[test]
fn a_home_gone_is_not_an_earlier_version_that_no_longer_compiles() {
    let (_dir, engine, name) = with_sandbox();
    let file = compiled_now(&engine, &name);
    ran_under(&engine, &name, gone_process(), &file);
    std::fs::remove_dir_all(engine.layout.sandbox_home(name.as_str())).unwrap();
    let check = check_of(&engine.doctor(), &name);
    assert!(matches!(check.next, NextSession::Fails { .. }), "{check:?}");
    assert!(check.drift.is_empty(), "{check:?}");
    assert!(
        check
            .unreadable
            .iter()
            .any(|u| u.starts_with("policy v1, which a session ran under")
                && u.contains("was not compared")),
        "{check:?}"
    );
}

/// When enclos cannot tell which sessions run, each one recorded open
/// counts, and the count is said to be unsure; with none open, nothing
/// needed that answer.
#[test]
fn sessions_enclos_cannot_tell_are_counted_as_unsure() {
    let (_dir, engine, name) = with_sandbox();
    // A marker folder that cannot be looked at: a link to itself.
    let markers = engine.layout.sandbox_dir(name.as_str()).join("members");
    let _ = std::fs::remove_dir_all(&markers);
    std::os::unix::fs::symlink(&markers, &markers).unwrap();
    let file = compiled_now(&engine, &name);
    ran_under(&engine, &name, gone_process(), &file);
    ended(&engine, &name);
    let check = check_of(&engine.doctor(), &name);
    assert!(check.unreadable.is_empty(), "{check:?}");

    let earlier = compiled_earlier(&engine, &name);
    ran_under(&engine, &name, gone_process(), &earlier);
    let doctor = engine.doctor();
    let check = check_of(&doctor, &name);
    assert!(
        check
            .unreadable
            .iter()
            .any(|u| u.starts_with("cannot tell which of its sessions run")),
        "{check:?}"
    );
    let [change] = changed(&check).try_into().unwrap();
    assert_eq!(change.ran, earlier);
    assert_eq!(
        change.running,
        Running {
            count: 1,
            unsure: true
        }
    );
    assert!(doctor.has_problems());
}

#[test]
fn a_sandbox_whose_backend_cannot_run_here_is_a_problem() {
    let (_dir, engine, name) = with_sandbox();
    let lock = engine.state.lock().unwrap();
    let mut record = engine.state.get(&name).unwrap().unwrap();
    record.backend = BackendKind::Bubblewrap;
    engine.state.put(&lock, &record).unwrap();
    drop(lock);
    let doctor = engine.doctor();
    let check = check_of(&doctor, &name);
    assert!(!check.backend_runs());
    assert_eq!(check.next, NextSession::NotChecked);
    assert!(doctor.has_problems());
}

/// An earlier file edited after it was written is named as such, though
/// the policy also compiles to another file now.
#[test]
fn an_earlier_file_changed_after_it_was_written_is_named_as_such() {
    let (_dir, engine, name) = with_sandbox();
    let earlier = compiled_earlier(&engine, &name);
    ran_under(&engine, &name, gone_process(), &earlier);
    let text = std::fs::read_to_string(&earlier).unwrap();
    std::fs::write(&earlier, format!("{text}(allow default)\n")).unwrap();
    let [change] = changed(&check_of(&engine.doctor(), &name))
        .try_into()
        .unwrap();
    assert!(change.edited, "{change:?}");
    assert_ne!(change.now, change.ran);
}

/// A version a session ran under that no longer compiles is named as such,
/// and while it is the active one, its next session cannot start.
#[test]
fn a_version_that_no_longer_compiles_is_named_and_stops_the_next_session() {
    let (dir, engine, name) = with_sandbox();
    let created = engine.layout.read_policy("home").unwrap();
    let path = dir.path().join(crate::backend::fake::UNCOMPILABLE);
    std::fs::create_dir_all(&path).unwrap();
    grant_write(&engine, &path);
    let ran = engine
        .layout
        .sandbox_dir("home")
        .join("compiled/0000000000000000.fake");
    let mut session = session_of(&engine, &name, gone_process());
    session.version = 2;
    session.compiled = Some(ran.display().to_string());
    put(&engine, &session);
    let doctor = engine.doctor();
    let check = check_of(&doctor, &name);
    let NextSession::Fails { error } = &check.next else {
        panic!("{check:?}");
    };
    assert!(error.contains("cannot compile a write to"), "{error}");
    assert!(doctor.has_problems());
    let [(version, why)] = no_longer_compiles(&check).try_into().unwrap();
    assert_eq!(version, 2);
    assert!(why.contains("cannot compile a write to"), "{why}");
    assert!(check.unreadable.is_empty(), "{check:?}");

    // Once a later version is active, only the earlier one is named.
    ungrant_writes(&engine, &created);
    let check = check_of(&engine.doctor(), &name);
    assert!(
        matches!(check.next, NextSession::Compiles { version: 3, .. }),
        "{check:?}"
    );
    assert_eq!(no_longer_compiles(&check).len(), 1, "{check:?}");
}

/// A write path that now leads into enclos's own files stops the next
/// session, and an earlier version with it is said to no longer pass the
/// checks, not to be the active policy.
#[test]
fn write_paths_that_no_longer_pass_their_checks_are_named() {
    let (dir, engine, name) = with_sandbox();
    let created = engine.layout.read_policy("home").unwrap();
    let work = dir.path().join("work");
    std::fs::create_dir_all(&work).unwrap();
    grant_write(&engine, &work);
    let file = compiled_now(&engine, &name);
    let mut session = session_of(&engine, &name, gone_process());
    session.version = 2;
    session.compiled = Some(file.display().to_string());
    put(&engine, &session);
    std::fs::remove_dir(&work).unwrap();
    std::os::unix::fs::symlink(engine.layout.sandbox_dir("home"), &work).unwrap();
    let doctor = engine.doctor();
    let check = check_of(&doctor, &name);
    assert!(matches!(check.next, NextSession::Fails { .. }), "{check:?}");
    assert!(check.unreadable.is_empty(), "{check:?}");
    assert!(doctor.has_problems());

    ungrant_writes(&engine, &created);
    let check = check_of(&engine.doctor(), &name);
    assert!(
        matches!(check.next, NextSession::Compiles { version: 3, .. }),
        "{check:?}"
    );
    let [(version, why)] = no_longer_compiles(&check).try_into().unwrap();
    assert_eq!(version, 2);
    assert!(why.starts_with("its write paths no longer pass"), "{why}");
    assert!(!why.contains("active policy"), "{why}");
}

/// A sandbox with no active policy cannot start a session: that is said,
/// not that enclos could not tell.
#[test]
fn a_sandbox_with_no_active_policy_cannot_start() {
    let (_dir, engine, name) = with_sandbox();
    rusqlite::Connection::open(engine.layout.state_db())
        .unwrap()
        .execute(
            "UPDATE sandboxes SET active_version = NULL WHERE name = 'home'",
            [],
        )
        .unwrap();
    let doctor = engine.doctor();
    let check = check_of(&doctor, &name);
    assert!(matches!(check.next, NextSession::Fails { .. }), "{check:?}");
    assert!(doctor.has_problems());
}

/// Its sessions that cannot be read do not keep the next session from
/// being checked.
#[test]
fn unreadable_sessions_do_not_hide_the_next_session() {
    let (_dir, engine, name) = with_sandbox();
    rusqlite::Connection::open(engine.layout.state_db())
        .unwrap()
        .execute(
            "INSERT INTO sessions (sandbox, kind, version, snapshot, root_pid, root_start, started_at)
             VALUES ('home', 'bogus', 1, 'x', 1, 'x', 'x')",
            [],
        )
        .unwrap();
    let check = check_of(&engine.doctor(), &name);
    assert!(
        check
            .unreadable
            .iter()
            .any(|u| u.starts_with("cannot read its sessions")),
        "{check:?}"
    );
    assert!(
        matches!(check.next, NextSession::Compiles { version: 1, .. }),
        "{check:?}"
    );
}

/// Doctor writes nothing: no folder before `init`, and after, no compiled
/// file, audit entry or record, even with a drift to report.
#[test]
fn doctor_changes_nothing() {
    let (_dir, engine) = engine_with(vec![Box::new(FakeBackend::available(
        BackendKind::Seatbelt,
    ))]);
    engine.doctor();
    assert!(!engine.layout.data().exists());

    let (_dir, engine, name) = with_sandbox();
    let earlier = compiled_earlier(&engine, &name);
    ran_under(&engine, &name, gone_process(), &earlier);
    let compiled = engine.layout.sandbox_dir("home").join("compiled");
    let listing = || {
        let mut names: Vec<_> = std::fs::read_dir(&compiled)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        names.sort();
        names
    };
    let audit = engine.layout.data().join("audit.jsonl");
    let (files, log, db) = (
        listing(),
        std::fs::read(&audit).unwrap(),
        std::fs::read(engine.layout.state_db()).unwrap(),
    );
    for _ in 0..2 {
        assert!(!check_of(&engine.doctor(), &name).drift.is_empty());
    }
    assert_eq!(listing(), files);
    assert_eq!(std::fs::read(&audit).unwrap(), log);
    assert_eq!(std::fs::read(engine.layout.state_db()).unwrap(), db);
}

/// A file a session ran under that is on the `(allow default)` comparison
/// baseline, as enclos wrote it, is said to be; an edited one is not.
#[test]
fn a_file_on_the_allow_default_baseline_is_said_so() {
    let (_dir, engine, name) = with_sandbox();
    let (now, _) = engine.compiled_file(&name, port(&engine, &name)).unwrap();
    let text = ";; enclos compiled policy for home\n(version 1)\n(allow default)\n";
    let digest = crate::policy::sha256_hex(text.as_bytes());
    let ran = now.with_file_name(format!("{}.sb", &digest[..16]));
    std::fs::create_dir_all(ran.parent().unwrap()).unwrap();
    std::fs::write(&ran, text).unwrap();
    ran_under(&engine, &name, gone_process(), &ran);
    let flag = |engine: &Engine| {
        let check = check_of(&engine.doctor(), &name);
        let [drift] = check.drift.as_slice() else {
            panic!("{check:?}");
        };
        match &drift.kind {
            DriftKind::Changed {
                ran_file:
                    RanFile::There {
                        on_allow_default,
                        edited,
                        ..
                    },
                ..
            } => (*on_allow_default, *edited),
            other => panic!("{other:?}"),
        }
    };
    assert_eq!(flag(&engine), (true, false));
    std::fs::write(&ran, format!("{text}(edited)\n")).unwrap();
    assert_eq!(flag(&engine), (false, true));
}
