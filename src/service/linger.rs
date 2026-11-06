//! Lingering: whether systemd keeps a user's manager, and so every
//! sandbox's services, running after the user's last logout (design §2,
//! §15). enclos never turns it on itself; `doctor` says whether it is on and
//! what follows from it.

use std::path::Path;
use std::process::Command;

use crate::host::HostCheck;
use crate::lifecycle::bounded::{LIMIT, output_within};

pub const LOGINCTL: &str = "/usr/bin/loginctl";

const WHAT: &str = "lingering";

/// What `loginctl` says of user `uid`'s lingering.
pub fn check(loginctl: &Path, uid: u32) -> HostCheck {
    let out = output_within(
        Command::new(loginctl).args([
            "show-user",
            &uid.to_string(),
            "--property=Linger",
            "--value",
        ]),
        LIMIT,
    );
    let said = match out {
        Ok(out) if out.status.success() => String::from_utf8_lossy(&out.stdout).trim().to_owned(),
        Ok(out) => {
            return cannot_tell(format!(
                "`loginctl show-user {uid}` ended with {}: {}",
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        Err(e) => return cannot_tell(format!("cannot run {}: {e}", loginctl.display())),
    };
    match said.as_str() {
        "yes" => HostCheck::fine(
            WHAT,
            "on: your systemd manager, and every sandbox's services with it, keep running after your last logout",
        ),
        "no" => HostCheck::note(
            WHAT,
            "off: systemd stops your manager at your last logout, and every sandbox's services with it, until you log in again",
            Some("to keep them running while you are logged out, `loginctl enable-linger`, which may ask for an administrator's password; enclos never turns it on itself".to_owned()),
        ),
        other => cannot_tell(format!("`loginctl show-user {uid}` printed `{other}`")),
    }
}

fn cannot_tell(why: String) -> HostCheck {
    HostCheck::note(WHAT, format!("cannot tell: {why}"), None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::Verdict;

    /// `check` against a stand-in for `loginctl` running `body`, which
    /// records its arguments in `args`.
    fn with(body: &str) -> (HostCheck, String) {
        let dir = tempfile::tempdir().unwrap();
        let loginctl = dir.path().join("loginctl");
        let args = dir.path().join("args");
        crate::test_scripts::write_script(
            &loginctl,
            &format!("echo \"$@\" > '{}'\n{body}", args.display()),
        );
        let check = check(&loginctl, 1000);
        (check, std::fs::read_to_string(args).unwrap())
    }

    #[test]
    fn lingering_on_is_said_with_what_follows() {
        let (check, args) = with("echo yes");
        assert_eq!(args.trim(), "show-user 1000 --property=Linger --value");
        assert_eq!(check.verdict, Verdict::Fine);
        assert!(
            check.found.contains("keep running after your last logout"),
            "{check:?}"
        );
    }

    /// Not a problem, and not turned on: said, with how to.
    #[test]
    fn lingering_off_is_a_note_with_how_to_turn_it_on() {
        let (check, _) = with("echo no");
        assert_eq!(check.verdict, Verdict::Note);
        assert!(
            check
                .found
                .contains("stops your manager at your last logout"),
            "{check:?}"
        );
        assert!(check.fix.unwrap().contains("loginctl enable-linger"));
    }

    #[test]
    fn what_loginctl_cannot_say_is_said_so() {
        let (check, _) = with("echo 'Failed to get user: No such user' >&2; exit 1");
        assert_eq!(check.verdict, Verdict::Note);
        assert!(check.found.starts_with("cannot tell"), "{check:?}");
        assert!(check.found.contains("No such user"), "{check:?}");
        let (check, _) = with("echo maybe");
        assert!(check.found.contains("printed `maybe`"), "{check:?}");
        let check = super::check(Path::new("/nowhere/loginctl"), 1000);
        assert!(
            check.found.contains("cannot run /nowhere/loginctl"),
            "{check:?}"
        );
    }
}
