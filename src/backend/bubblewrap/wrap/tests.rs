use std::collections::BTreeMap;
use std::ffi::OsString;
use std::os::unix::fs::{PermissionsExt, symlink};

use super::host::Kind;
use super::*;
use crate::backend::bubblewrap::compile::{Bubblewrap, GrantMasks, RootMasks};
use crate::backend::{LaunchLimits, SandboxContext};
use crate::layout::Layout;
use crate::model::secret::SecretValue;
use crate::policy::paths::real_path;

/// A user's home in a folder of its own, with the sandbox's home inside it
/// as enclos keeps it.
struct Home {
    dir: tempfile::TempDir,
}

impl Home {
    fn new() -> Home {
        Home::in_folder(tempfile::tempdir().unwrap())
    }

    /// One outside `/tmp`, which the sandbox has its own of: what lies
    /// beside the home there is the host's, as in a real home.
    fn outside_tmp() -> Home {
        let target = Path::new(env!("CARGO_MANIFEST_DIR")).join("target");
        std::fs::create_dir_all(&target).unwrap();
        Home::in_folder(tempfile::tempdir_in(target).unwrap())
    }

    fn in_folder(dir: tempfile::TempDir) -> Home {
        let home = Home { dir };
        std::fs::create_dir_all(home.sandbox_home()).unwrap();
        home
    }

    fn user(&self) -> PathBuf {
        self.dir.path().join("alice")
    }

    fn at(&self, rest: &str) -> PathBuf {
        self.user().join(rest)
    }

    fn sandbox_home(&self) -> PathBuf {
        self.at(".enclos/sandboxes/lab/home")
    }

    fn folder(&self, rest: &str) -> PathBuf {
        let path = self.at(rest);
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    fn file(&self, rest: &str) -> PathBuf {
        let path = self.at(rest);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "x").unwrap();
        path
    }
}

fn text(path: &Path) -> String {
    path.to_str().unwrap().to_owned()
}

fn texts(paths: &[PathBuf]) -> Vec<String> {
    paths.iter().map(|p| text(p)).collect()
}

/// A compiled file for `home`, as compile lists it: `denied` in the home,
/// with the protected root, and the rest as given.
#[derive(Default)]
struct Lists {
    denied: Vec<PathBuf>,
    elsewhere: Vec<PathBuf>,
    in_sandbox_home: Vec<PathBuf>,
    in_workspace: Vec<PathBuf>,
    workspaces: Vec<PathBuf>,
    unmovable: Vec<PathBuf>,
    sealed: Vec<PathBuf>,
}

fn compiled(home: &Home, lists: Lists) -> CompiledSandbox {
    let mut denied = lists.denied;
    denied.push(home.at(".enclos"));
    denied.sort();
    let mut mounts = vec![
        "--bind".to_owned(),
        text(&home.sandbox_home()),
        text(&home.sandbox_home()),
    ];
    for w in &lists.workspaces {
        mounts.extend(["--bind-try".to_owned(), text(w), text(w)]);
    }
    CompiledSandbox {
        bubblewrap: Bubblewrap {
            root: vec!["--ro-bind".into(), "/".into(), "/".into()],
            root_masks: RootMasks {
                home: text(&home.user()),
                denied: texts(&denied),
                denied_elsewhere: texts(&lists.elsewhere),
            },
            mounts,
            grant_masks: GrantMasks {
                unmovable: texts(&lists.unmovable),
                in_sandbox_home: texts(&lists.in_sandbox_home),
                in_workspace: texts(&lists.in_workspace),
                workspaces: texts(&lists.workspaces),
            },
            sealed: texts(&lists.sealed),
            options: vec!["--die-with-parent".to_owned()],
        },
        landlock: serde_json::from_value(serde_json::json!({
            "read": [], "execute": [], "write": [], "devices": [], "proc_write": [], "scoped": []
        }))
        .unwrap(),
        seccomp: serde_json::from_value(serde_json::json!({
            "errno": "EPERM", "deny": [], "ioctl": {}, "clone_flags": {}, "enosys": [],
            "socket_families": {}
        }))
        .unwrap(),
        relay: serde_json::from_value(serde_json::json!({
            "port": 41001, "socket": "/x/proxy.sock", "log": "/tmp/enclos-relay.log"
        }))
        .unwrap(),
        unenforced: Vec::new(),
    }
}

fn read(home: &Home, c: &CompiledSandbox, ssh: Option<&Path>) -> Result<Host, WrapError> {
    read_host(c, &home.sandbox_home(), ssh)
}

fn strings(args: &[OsString]) -> Vec<String> {
    args.iter()
        .map(|a| a.to_str().unwrap().to_owned())
        .collect()
}

/// Where `words` start in `args`, in order.
fn position(args: &[String], words: &[&str]) -> usize {
    args.windows(words.len())
        .position(|w| w == words)
        .unwrap_or_else(|| panic!("{words:?} not in {args:?}"))
}

fn ctx(home: &Home) -> SandboxContext {
    let layout = Layout::at(home.at(".enclos"));
    let mut ctx = SandboxContext::new(&layout, &"lab".parse().unwrap(), 41001);
    ctx.home = home.sandbox_home();
    ctx
}

fn launch(env: Vec<(String, SecretValue)>) -> Launch {
    Launch {
        program: "/bin/sh".into(),
        args: vec!["-c".into(), "echo hi".into()],
        env,
        in_terminal: false,
        service_port: None,
        limits: LaunchLimits::default(),
        reads: Vec::new(),
    }
}

/// The files an install staged in the sandbox's `installers/` folder.
fn staged(home: &Home) -> Vec<PathBuf> {
    let installers = ctx(home).installers;
    vec![
        installers.join("home-0"),
        installers.join("hermes-install-0a1b.sh"),
    ]
}

mod command;
mod links;
mod masks;
mod staged;
