//! A workspace that would put the host's back over a place bubblewrap gives
//! each session of its own: refused as written, and where a link the user
//! made outside the grants leads, relative or absolute.

use super::*;
use crate::backend::Backend;
use crate::backend::bubblewrap::Bubblewrap;
use crate::policy::own_places::links;

/// A fixture checked against bubblewrap's own places.
fn on_bubblewrap() -> Fixture {
    let mut f = fixture();
    f.ctx.own_places = Bubblewrap::on_host().own_places();
    f
}

/// The refusal of `entry` for bringing back the host's `place`, alone of
/// its kind, and the same refusal each time the policy is compiled.
fn assert_refused(entry: &str, place: &str, f: &Fixture) {
    let p = policy(&["{home}", entry], &[], &[]);
    let found = checked(&p, f);
    let said = format!("would bring back the host's {place},");
    let refusals: Vec<&Problem> = found
        .iter()
        .filter(|p| p.to_string().contains("would bring back"))
        .collect();
    assert_eq!(refusals.len(), 1, "{entry}: {found:?}");
    assert!(refusals[0].is_refused(), "{entry}: {found:?}");
    let text = refusals[0].to_string();
    assert!(
        text.starts_with(&format!("filesystem.write: `{entry}` (")) && text.contains(&said),
        "{entry}: {text}"
    );
    let again = validate_writes(&p, &f.ctx).unwrap_err().to_string();
    assert!(again.contains(&said), "{entry}: {again}");
}

#[test]
fn a_workspace_at_holding_or_inside_one_is_refused_as_written() {
    let f = on_bubblewrap();
    for (entry, place) in [
        ("/run", "/run"),
        ("/run/user/1000", "/run"),
        ("/var/run", "/var/run"),
        ("/tmp", "/tmp"),
        ("/var/tmp", "/var/tmp"),
        ("/dev/shm", "/dev/shm"),
        ("/dev/shm/x", "/dev/shm"),
        ("/dev", "/dev"),
        ("/proc/self", "/proc"),
        ("/var", "/var/tmp"),
    ] {
        assert_refused(entry, place, &f);
    }
    // A folder of the host's for a project, its bind alone.
    for entry in ["/tmp/proj", "/var/tmp/proj"] {
        let found = problems(&policy(&["{home}", entry], &[], &[]), &f);
        assert!(found.is_empty(), "{entry}: {found:?}");
    }
}

/// `~/alias -> ../../run`: bubblewrap would follow the link as it binds the
/// workspace, after the sandbox's own `/run`.
#[test]
fn a_workspace_that_leads_to_one_through_a_link_is_refused() {
    let f = on_bubblewrap();
    let user = f.ctx.paths.user_home.clone();
    for (i, (target, place)) in links::targets().into_iter().enumerate() {
        for alias in links::both(&user, &format!("alias-{i}"), target) {
            let name = alias.file_name().unwrap().to_str().unwrap();
            assert_refused(&format!("~/{name}"), place, &f);
        }
    }
    // A link to a folder beside them is the user's own.
    std::fs::create_dir(user.join("docs")).unwrap();
    std::os::unix::fs::symlink("docs", user.join("docs-alias")).unwrap();
    let found = problems(&policy(&["{home}", "~/docs-alias"], &[], &[]), &f);
    assert!(found.is_empty(), "{found:?}");
}

/// The places are the backend's: on one whose sessions see the host's, the
/// same link is a workspace like any other.
#[test]
fn a_backend_with_no_own_places_takes_the_same_link() {
    let f = fixture();
    let [relative, absolute] = links::both(&f.ctx.paths.user_home, "alias", "/dev");
    for alias in [relative, absolute] {
        let name = alias.file_name().unwrap().to_str().unwrap();
        let found = problems(&policy(&["{home}", &format!("~/{name}")], &[], &[]), &f);
        assert!(found.is_empty(), "{name}: {found:?}");
    }
}
