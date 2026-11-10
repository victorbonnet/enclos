//! A workspace that leads to a place the sandbox has its own of refuses the
//! session at each launch, whatever `validate` and compile saw: the link
//! is read as the host holds it now.

use super::*;
use crate::policy::own_places::links;

/// Why a launch with `workspace` is refused.
fn refused(home: &Home, workspace: &Path) -> String {
    let c = compiled(
        home,
        Lists {
            workspaces: vec![workspace.to_owned()],
            ..Lists::default()
        },
    );
    read(home, &c, None).unwrap_err().to_string()
}

/// `~/alias -> ../../run`: bubblewrap would follow the link as it binds
/// the workspace, after the sandbox's own `/run`. An absolute link is
/// refused the same.
#[test]
fn a_workspace_that_leads_to_one_through_a_link_refuses_the_session() {
    let home = Home::new();
    for (i, (target, place)) in links::targets().into_iter().enumerate() {
        for alias in links::both(&home.user(), &format!("alias-{i}"), target) {
            let why = refused(&home, &alias);
            let named = format!("workspace {}, which leads to ", alias.display());
            assert!(why.starts_with(&named), "{why}");
            assert!(
                why.contains(&format!("would bring back the host's {place},")),
                "{why}"
            );
            assert!(why.contains("the session is refused"), "{why}");
        }
    }
}

/// The link is read at each launch: one that led to a folder of the user's
/// when the policy was checked may lead to `/proc` now, or to a place not
/// made yet under `/run`.
#[test]
fn a_link_changed_since_the_policy_was_checked_refuses_the_session() {
    let home = Home::new();
    home.folder("proj");
    let alias = home.at("alias");
    symlink("proj", &alias).unwrap();
    let c = compiled(
        &home,
        Lists {
            workspaces: vec![alias.clone()],
            ..Lists::default()
        },
    );
    read(&home, &c, None).unwrap();
    for target in ["/proc", "/run/enclos-test-not-made"] {
        std::fs::remove_file(&alias).unwrap();
        symlink(links::relative(&home.user(), target), &alias).unwrap();
        let why = read(&home, &c, None).unwrap_err().to_string();
        assert!(why.contains(&format!("which leads to {target},")), "{why}");
    }
}

/// Compile refuses it first; a compiled file that lists one all the same
/// is refused at launch too.
#[test]
fn a_workspace_written_at_one_refuses_the_session() {
    let home = Home::new();
    let why = refused(&home, Path::new("/run/user/1000"));
    assert!(
        why.starts_with("workspace /run/user/1000 would bring back the host's /run,"),
        "{why}"
    );
}
