//! A workspace the user reaches through a link made outside every grant,
//! leading to a place the sandbox has its own of, `/run` or `/proc`
//! (design §5): bubblewrap follows the link as it binds the workspace,
//! after the sandbox's own `/run` and `/proc`.

use std::os::unix::fs::{FileTypeExt, symlink};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use super::{Lab, home, on_a_runner, text};

/// What a link in the runner's home holds to reach `target` without a
/// leading `/`: `../../run` from `/home/runner`.
fn relative(target: &str) -> PathBuf {
    let up = home().canonicalize().unwrap().components().count() - 1;
    PathBuf::from("../".repeat(up)).join(target.trim_start_matches('/'))
}

/// Makes `link` point at `to`, in place of what it pointed at.
fn point(link: &Path, to: &Path) {
    let _ = std::fs::remove_file(link);
    symlink(to, link).unwrap();
}

/// `script` under bubblewrap alone, with a `/run` and a `/proc` of its own
/// and `workspace`, if any, bound after them as `wrap` binds one.
fn bubblewrap_alone(workspace: Option<&Path>, script: &str) -> Output {
    let mut bwrap = Command::new("/usr/bin/bwrap");
    bwrap.args([
        "--ro-bind",
        "/",
        "/",
        "--unshare-pid",
        "--proc",
        "/proc",
        "--tmpfs",
        "/run",
    ]);
    if let Some(workspace) = workspace {
        bwrap.arg("--bind-try").arg(workspace).arg(workspace);
    }
    bwrap.args(["/bin/sh", "-c", script]).output().unwrap()
}

impl Lab {
    /// Sets `lab`'s workspaces to `workspaces` in its `policy.toml`, then
    /// stores the file as `policy allow` does, and says what that said.
    fn grant(&self, workspaces: &[&Path]) -> Output {
        let file = self.root.path().join("sandboxes/lab/policy.toml");
        let listed: Vec<String> = workspaces
            .iter()
            .map(|w| format!("\"{}\"", w.display()))
            .collect();
        let edited: String = std::fs::read_to_string(&file)
            .unwrap()
            .lines()
            .map(|line| match line.starts_with("write_add = ") {
                true => format!("write_add = [{}]\n", listed.join(", ")),
                false => format!("{line}\n"),
            })
            .collect();
        std::fs::write(&file, edited).unwrap();
        self.command(&["policy", "allow", "lab", "example.com", "--yes"])
            .output()
            .unwrap()
    }
}

/// Refused when the policy is stored, relative link or absolute, and at
/// each launch when the link changed since; a link to a folder of the
/// user's is a workspace like any other, and the sandbox's `/run` and
/// `/proc` stay its own there. The control: bubblewrap alone, given such a
/// bind after its own `/run` or `/proc`, shows the host's.
#[test]
fn on_a_runner_a_workspace_that_leads_to_the_sandboxs_own_run_or_proc_is_refused() {
    if !on_a_runner() {
        return;
    }
    let lab = Lab::new();
    let runtime = std::env::var("XDG_RUNTIME_DIR").expect("the job sets XDG_RUNTIME_DIR");
    let bus = Path::new(&runtime).join("bus");
    let init = std::fs::read_to_string("/proc/1/comm").unwrap();
    let init = init.trim();
    // The host's own: its user's bus, and its PID 1.
    let found = std::fs::metadata(&bus).unwrap().file_type();
    assert!(found.is_socket(), "{}: {found:?}", bus.display());
    let look = format!("test -S '{}' && echo BUS; cat /proc/1/comm", bus.display());
    let alias = home().join("enclos-ci-alias");
    let work = home().join("enclos-ci-alias-work");
    std::fs::create_dir_all(&work).unwrap();

    let own = text(&bubblewrap_alone(None, &look).stdout);
    assert!(!own.contains("BUS") && !own.ends_with(init), "{own}");
    point(&alias, &relative("/run"));
    let out = bubblewrap_alone(Some(&alias), &look);
    assert!(text(&out.stdout).contains("BUS"), "{out:?}");
    point(&alias, &relative("/proc"));
    let out = bubblewrap_alone(Some(&alias), &look);
    assert!(text(&out.stdout).ends_with(init), "{init}: {out:?}");

    for (to, place) in [
        (relative("/run"), "/run"),
        (relative("/proc"), "/proc"),
        (PathBuf::from("/run"), "/run"),
    ] {
        point(&alias, &to);
        let out = lab.grant(&[&alias]);
        assert_eq!(out.status.code(), Some(2), "{to:?}: {out:?}");
        let said = format!("would bring back the host's {place},");
        assert!(text(&out.stderr).contains(&said), "{to:?}: {out:?}");
    }

    point(&alias, Path::new("enclos-ci-alias-work"));
    let out = lab.grant(&[&alias]);
    assert!(out.status.success(), "{out:?}");
    let written = alias.join("written");
    let out = lab.connect(&format!(
        "echo through > '{}' && echo WROTE; {look}",
        written.display()
    ));
    let said = text(&out.stdout);
    assert!(said.contains("WROTE"), "{out:?}");
    assert!(!said.contains("BUS") && !said.ends_with(init), "{out:?}");
    let through = std::fs::read_to_string(work.join("written")).unwrap();
    assert_eq!(through, "through\n");

    for (to, place) in [(relative("/run"), "/run"), (relative("/proc"), "/proc")] {
        point(&alias, &to);
        let out = lab.connect(&format!("echo RAN; {look}"));
        assert!(!out.status.success(), "{to:?}: {out:?}");
        assert!(!text(&out.stdout).contains("RAN"), "{to:?}: {out:?}");
        let said = format!("would bring back the host's {place},");
        assert!(text(&out.stderr).contains(&said), "{to:?}: {out:?}");
    }
    let _ = std::fs::remove_file(&alias);
    let _ = std::fs::remove_dir_all(&work);
}
