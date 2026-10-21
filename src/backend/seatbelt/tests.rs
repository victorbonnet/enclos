//! The compiled policy enforced by macOS itself: `/bin/sh` runs under
//! `sandbox-exec` in temporary folders, and the OS must refuse what the
//! policy denies. Only processes these tests start are ever signalled.

use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use super::super::{Backend, Launch, SandboxContext};
use super::Seatbelt;
use crate::layout::Layout;
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
        user.join("work/secret"),
        home.join("private"),
        home.join("tmp"),
        data.join("sandboxes/other"),
        data.join("run"),
    ] {
        std::fs::create_dir_all(d).unwrap();
    }
    std::fs::write(user.join(".ssh/id_ed25519"), "secret").unwrap();
    std::fs::write(user.join("work/secret/key"), "secret").unwrap();
    std::fs::write(home.join("private/key"), "secret").unwrap();
    std::fs::write(data.join("state.db"), "state").unwrap();
    std::fs::write(data.join("sandboxes/other/policy.toml"), "theirs").unwrap();
    std::fs::write(user.join("readable.txt"), "fine").unwrap();
    let allowed = TcpListener::bind("127.0.0.1:0").unwrap();
    let other = TcpListener::bind("127.0.0.1:0").unwrap();
    let ctx = SandboxContext::new(
        &Layout::at(&data),
        &"home".parse().unwrap(),
        allowed.local_addr().unwrap().port(),
    );
    let mut policy = Policy::default();
    policy.fs.write = vec!["{home}".into(), "~/work".into()];
    policy.fs.read_deny = vec![
        "~/.ssh".into(),
        "~/work/secret".into(),
        "{home}/private".into(),
    ];
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

    /// Runs a shell command in the sandbox: whether it exited 0, and what
    /// it printed.
    fn out(&self, script: &str) -> (bool, String) {
        let launch = Launch {
            program: "/bin/sh".into(),
            args: vec!["-c".into(), script.into()],
            env: vec![],
        };
        let out = Seatbelt
            .wrap(&self.compiled, &self.ctx, &launch)
            .stderr(Stdio::null())
            .output()
            .unwrap();
        (
            out.status.success(),
            String::from_utf8_lossy(&out.stdout).trim().to_owned(),
        )
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
fn the_sandbox_reads_but_cannot_write_its_own_installers_folder() {
    // Where enclos copies an installer or an archive to import: the
    // sandbox reads it there and can neither change, replace nor add one.
    let w = world();
    let installers = w.ctx.dir.join("installers");
    std::fs::create_dir_all(&installers).unwrap();
    let copy = installers.join("agent-main.1.tar.gz");
    std::fs::write(&copy, "an export").unwrap();
    let copy = copy.display().to_string();
    let dir = installers.display().to_string();
    assert!(w.sh(&format!("cat '{copy}'")));
    assert!(!w.sh(&format!("echo x > '{copy}'")));
    assert!(!w.sh(&format!("rm '{copy}'")));
    assert!(!w.sh(&format!("echo x > '{dir}/new'")));
    assert!(!w.sh(&format!("ln -s /etc/hosts '{dir}/link'")));
    assert_eq!(std::fs::read_to_string(&copy).unwrap(), "an export");
    assert_eq!(std::fs::read_dir(&installers).unwrap().count(), 1);
    // Nor its own policy file.
    assert!(!w.sh(&format!(
        "echo x > '{}'",
        w.ctx.dir.join("policy.toml").display()
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
fn a_write_grant_never_opens_a_hidden_path() {
    let w = world();
    // ~/work is granted and ~/work/secret hidden: the hidden part wins.
    assert!(w.sh(&format!("echo ok > '{}'", w.path("alice/work/ok"))));
    assert!(!w.sh(&format!("cat '{}'", w.path("alice/work/secret/key"))));
    assert!(!w.sh(&format!("echo x > '{}'", w.path("alice/work/secret/new"))));
    assert!(!Path::new(&w.path("alice/work/secret/new")).exists());
    // So does a hidden path inside the home, which is readable and writable.
    assert!(!w.sh("cat \"$HOME/private/key\""));
    assert!(!w.sh("echo x > \"$HOME/private/new\""));
    assert!(w.sh("cat \"$HOME/written\" 2>/dev/null; echo ok > \"$HOME/written\""));
}

#[test]
fn the_sandbox_cannot_type_into_its_terminal() {
    let w = world();
    // `script` gives the sandboxed program a terminal of its own: TIOCSTI
    // (0x80017472) there never reaches the terminal running these tests.
    let try_tiocsti =
        r#"my $c = "x"; print ioctl(STDIN, 0x80017472, $c) ? "INJECTED\n" : "REFUSED\n""#;
    let out = Command::new("/usr/bin/script")
        .args(["-q", "/dev/null", "/usr/bin/sandbox-exec", "-f"])
        .arg(&w.compiled)
        .args(["/usr/bin/perl", "-e", try_tiocsti])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let out = String::from_utf8_lossy(&out.stdout);
    assert!(out.contains("REFUSED"), "{out}");
    assert!(!out.contains("INJECTED"), "{out}");
}

fn staged_wrapper(w: &World) -> (PathBuf, HomeFile) {
    let staged = w.ctx.dir.join("installers/home-0");
    std::fs::create_dir_all(staged.parent().unwrap()).unwrap();
    std::fs::write(&staged, "wrapper").unwrap();
    let file = HomeFile {
        path: "bin/mktemp",
        contents: "wrapper",
        executable: true,
    };
    (staged, file)
}

use crate::engine::home_files_script;
use crate::runtime::HomeFile;

#[test]
fn home_files_are_copied_from_inside_so_a_planted_link_reaches_nothing_outside() {
    let w = world();
    // The sandbox planted a link where enclos puts its mktemp wrapper. The
    // link goes, the wrapper takes its place, and the host file is untouched.
    let sentinel = w.base.join("alice/sentinel");
    std::fs::write(&sentinel, "host file").unwrap();
    std::fs::create_dir_all(w.ctx.home.join("bin")).unwrap();
    std::os::unix::fs::symlink(&sentinel, w.ctx.home.join("bin/mktemp")).unwrap();
    let (staged, file) = staged_wrapper(&w);
    assert!(w.sh(&home_files_script(&[(staged.clone(), &file)])));
    assert_eq!(std::fs::read_to_string(&sentinel).unwrap(), "host file");
    let target = w.ctx.home.join("bin/mktemp");
    assert!(target.symlink_metadata().unwrap().is_file());
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "wrapper");

    // A folder planted there goes the same way.
    std::fs::remove_file(&target).unwrap();
    std::fs::create_dir_all(target.join("inside")).unwrap();
    assert!(w.sh(&home_files_script(&[(staged, &file)])));
    assert!(target.is_file());
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "wrapper");
}

#[test]
fn a_home_folder_that_is_a_link_outside_gets_nothing() {
    let w = world();
    // `~/bin` itself leads outside the home: the copy is refused and the
    // host folder stays empty.
    let outside = w.base.join("alice/outside-bin");
    std::fs::create_dir_all(&outside).unwrap();
    std::os::unix::fs::symlink(&outside, w.ctx.home.join("bin")).unwrap();
    let (staged, file) = staged_wrapper(&w);
    assert!(!w.sh(&home_files_script(&[(staged, &file)])));
    assert_eq!(std::fs::read_dir(&outside).unwrap().count(), 0);
}

#[test]
fn a_hard_link_to_a_host_file_cannot_be_made_in_the_home() {
    let w = world();
    let readable = w.path("alice/readable.txt");
    assert!(!w.sh(&format!("/bin/ln '{readable}' \"$HOME/bin-link\"")));
    assert!(!w.ctx.home.join("bin-link").exists());
}

#[test]
fn the_mktemp_wrapper_puts_temp_files_under_the_sandbox_tmp() {
    let w = world();
    let bin = w.ctx.home.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let shim = bin.join("mktemp");
    std::fs::write(&shim, include_str!("../../runtime/hermes/mktemp")).unwrap();
    std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o700)).unwrap();
    let tmp = w.ctx.home.join("tmp").display().to_string();
    for (call, prefix) in [
        ("mktemp", "tmp."),
        ("mktemp -d", "tmp."),
        ("mktemp -t pfx", "pfx."),
        ("mktemp -d -t pfx", "pfx."),
        ("mktemp -q -t pfx", "pfx."),
    ] {
        let (ok, made) = w.out(call);
        assert!(ok, "{call}");
        let expected = format!("{tmp}/{prefix}");
        assert!(
            made.starts_with(&expected),
            "{call}: {made} not under {expected}"
        );
        assert!(Path::new(&made).exists(), "{call}: {made}");
    }
    // A template, or a long option, passes through unchanged.
    let (ok, made) = w.out("mktemp \"$HOME/tmp/mine.XXXXXX\"");
    assert!(ok && made.starts_with(&format!("{tmp}/mine.")), "{made}");
    assert!(!w.sh("mktemp --tmpdir=/nonexistent x.XXXX"));
    // -p counts only when TMPDIR is unset; TMPDIR wins otherwise.
    let alt = w.ctx.home.join("tmp/alt");
    std::fs::create_dir_all(&alt).unwrap();
    let (ok, made) = w.out(&format!("mktemp -p '{}' -t pfx", alt.display()));
    assert!(ok && made.starts_with(&format!("{tmp}/pfx.")), "{made}");
    let (ok, made) = w.out(&format!(
        "env -u TMPDIR mktemp -p '{}' -t pfx",
        alt.display()
    ));
    assert!(
        ok && made.starts_with(&format!("{}/pfx.", alt.display())),
        "{made}"
    );
}
