//! The compiled policy enforced by macOS itself: `/bin/sh` runs under
//! `sandbox-exec` in temporary folders, and the OS must refuse what the
//! policy denies. Only processes these tests start are ever signalled.

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use super::super::{Backend, Launch, SandboxContext};
use super::Seatbelt;
use crate::model::policy::Policy;

struct World {
    _dir: tempfile::TempDir,
    base: PathBuf,
    ctx: SandboxContext,
    compiled: PathBuf,
    allowed: TcpListener,
    other: TcpListener,
}

fn world() -> World {
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path().canonicalize().unwrap();
    let user = base.join("alice");
    let data = user.join(".enclos");
    let home = data.join("sandboxes/home/home");
    for d in [
        user.join(".ssh"),
        home.join("tmp"),
        data.join("sandboxes/other"),
        data.join("run"),
    ] {
        std::fs::create_dir_all(d).unwrap();
    }
    std::fs::write(user.join(".ssh/id_ed25519"), "secret").unwrap();
    std::fs::write(data.join("state.db"), "state").unwrap();
    std::fs::write(data.join("sandboxes/other/policy.toml"), "theirs").unwrap();
    std::fs::write(user.join("readable.txt"), "fine").unwrap();
    let allowed = TcpListener::bind("127.0.0.1:0").unwrap();
    let other = TcpListener::bind("127.0.0.1:0").unwrap();
    let ctx = SandboxContext {
        name: "home".parse().unwrap(),
        dir: data.join("sandboxes/home"),
        home,
        user_home: user.clone(),
        protected: vec![data.clone()],
        sandboxes: data.join("sandboxes"),
        data: data.clone(),
        config_file: data.join("config.toml"),
        proxy_port: allowed.local_addr().unwrap().port(),
    };
    let mut policy = Policy::default();
    policy.fs.write = vec!["{home}".into()];
    policy.fs.read_deny = vec!["~/.ssh".into()];
    let compiled = base.join("policy.sb");
    std::fs::write(&compiled, Seatbelt.compile(&policy, &ctx).unwrap().text).unwrap();
    World {
        _dir: dir,
        base,
        ctx,
        compiled,
        allowed,
        other,
    }
}

impl World {
    /// Runs a shell command in the sandbox; true when it exits 0.
    fn sh(&self, script: &str) -> bool {
        let launch = Launch {
            program: "/bin/sh".into(),
            args: vec!["-c".into(), script.into()],
            env: vec![],
        };
        let mut command: Command = Seatbelt.wrap(&self.compiled, &self.ctx, &launch);
        command.stdout(Stdio::null()).stderr(Stdio::null());
        command.status().unwrap().success()
    }

    fn path(&self, rel: &str) -> String {
        self.base.join(rel).display().to_string()
    }
}

#[test]
fn an_installer_can_create_folders_in_its_home_with_mkdir_p() {
    let w = world();
    // mkdir -p checks every parent, from the root down to the home.
    assert!(w.sh("/bin/mkdir -p \"$HOME/.hermes/hermes-agent/venv\""));
    assert!(w.ctx.home.join(".hermes/hermes-agent/venv").is_dir());
}

#[test]
fn the_sandbox_writes_only_in_its_home() {
    let w = world();
    assert!(w.sh("echo ok > \"$HOME/written\""));
    assert!(w.ctx.home.join("written").exists());
    assert!(!w.sh(&format!("echo no > '{}'", w.path("alice/outside"))));
    assert!(!Path::new(&w.path("alice/outside")).exists());
}

#[test]
fn sensitive_paths_and_enclos_files_are_unreadable_and_unwritable() {
    let w = world();
    assert!(w.sh(&format!("cat '{}'", w.path("alice/readable.txt"))));
    assert!(!w.sh(&format!("cat '{}'", w.path("alice/.ssh/id_ed25519"))));
    assert!(!w.sh(&format!("cat '{}'", w.path("alice/.enclos/state.db"))));
    assert!(!w.sh(&format!(
        "cat '{}'",
        w.path("alice/.enclos/sandboxes/other/policy.toml")
    )));
    assert!(!w.sh(&format!("echo x > '{}'", w.path("alice/.enclos/new"))));
    assert!(!w.sh(&format!(
        "echo x > '{}'",
        w.path("alice/.enclos/sandboxes/other/policy.toml")
    )));
}

#[test]
fn the_network_reaches_only_the_proxy_port() {
    let w = world();
    let port = |l: &TcpListener| l.local_addr().unwrap().port();
    assert!(w.sh(&format!(
        "/usr/bin/nc -z -w 3 127.0.0.1 {}",
        port(&w.allowed)
    )));
    assert!(!w.sh(&format!("/usr/bin/nc -z -w 3 127.0.0.1 {}", port(&w.other))));
}

#[test]
fn processes_outside_the_sandbox_cannot_be_signalled() {
    let w = world();
    // A process this test starts and records: the only one it may signal.
    let mut outside = Command::new("/bin/sleep").arg("30").spawn().unwrap();
    let refused = !w.sh(&format!("kill -TERM {}", outside.id()));
    let survived = outside.try_wait().unwrap().is_none();
    let _ = outside.kill();
    let _ = outside.wait();
    assert!(
        refused && survived,
        "the sandbox could signal a process outside it"
    );
}

#[test]
fn home_files_are_copied_from_inside_so_a_planted_link_reaches_nothing_outside() {
    use crate::engine::home_files_script;
    use crate::runtime::HomeFile;
    let w = world();
    // The sandbox planted a link where enclos puts its mktemp wrapper.
    let sentinel = w.base.join("alice/sentinel");
    std::fs::write(&sentinel, "host file").unwrap();
    std::fs::create_dir_all(w.ctx.home.join("bin")).unwrap();
    std::os::unix::fs::symlink(&sentinel, w.ctx.home.join("bin/mktemp")).unwrap();
    let staged = w.ctx.dir.join("installers/home-0");
    std::fs::create_dir_all(staged.parent().unwrap()).unwrap();
    std::fs::write(&staged, "wrapper").unwrap();
    let file = HomeFile {
        path: "bin/mktemp",
        contents: "wrapper",
        executable: true,
    };
    assert!(!w.sh(&home_files_script(&[(staged.clone(), &file)])));
    assert_eq!(std::fs::read_to_string(&sentinel).unwrap(), "host file");

    // Without the link, the same lines put the file in place.
    std::fs::remove_file(w.ctx.home.join("bin/mktemp")).unwrap();
    assert!(w.sh(&home_files_script(&[(staged, &file)])));
    assert_eq!(
        std::fs::read_to_string(w.ctx.home.join("bin/mktemp")).unwrap(),
        "wrapper"
    );
}
