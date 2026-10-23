//! The compiled policy enforced by macOS itself: `/bin/sh` runs under
//! `sandbox-exec` in temporary folders, and the OS must refuse what the
//! policy denies. Only processes these tests start are ever signalled.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, TcpListener, UdpSocket};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use super::super::{Backend, Launch, SandboxContext};
use super::Seatbelt;
use crate::layout::Layout;
use crate::model::policy::Policy;
use crate::policy::file::PolicyFile;
use crate::policy::paths::{FsPaths, PathContext};
use crate::probes::{Outcome, ProbeInputs, Proof, Run, outcome, probes, sandboxed_script};

struct World {
    _dir: tempfile::TempDir,
    base: PathBuf,
    ctx: SandboxContext,
    compiled: PathBuf,
    /// The policy's paths, as the compiler and `policy test` see them.
    fs: FsPaths,
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
        user.join("empty"),
        user.join("projects"),
        user.join("work/project/private"),
        user.join("plain"),
        home.join("private"),
        home.join("tmp"),
        data.join("sandboxes/other"),
        data.join("run"),
    ] {
        std::fs::create_dir_all(d).unwrap();
    }
    std::fs::write(user.join(".ssh/id_ed25519"), "secret").unwrap();
    std::fs::write(user.join("work/secret/key"), "secret").unwrap();
    std::fs::write(user.join("work/project/private/key"), "secret").unwrap();
    std::fs::write(home.join("private/key"), "secret").unwrap();
    std::fs::write(data.join("state.db"), "state").unwrap();
    std::fs::write(data.join("sandboxes/other/policy.toml"), "theirs").unwrap();
    std::fs::write(user.join("readable.txt"), "fine").unwrap();
    // A workspace the user reaches through a link of their own.
    std::os::unix::fs::symlink(user.join("projects"), user.join("linked")).unwrap();
    // The proxy's port: one of enclos's proxy range, which the compiler
    // requires (ADR 0028).
    let allowed = (crate::model::sandbox::PORT_FIRST..=crate::model::sandbox::PORT_LAST)
        .find_map(|port| TcpListener::bind(("127.0.0.1", port)).ok())
        .unwrap();
    let other = TcpListener::bind("127.0.0.1:0").unwrap();
    let ctx = SandboxContext::new(
        &Layout::at(&data),
        &"home".parse().unwrap(),
        allowed.local_addr().unwrap().port(),
    );
    let mut policy = Policy::default();
    // `~/plain` holds nothing hidden: only being writable keeps it in place.
    policy.fs.write = vec![
        "{home}".into(),
        "~/work".into(),
        "~/empty".into(),
        "~/linked".into(),
        "~/later".into(),
        "~/plain".into(),
    ];
    policy.fs.read_deny = vec![
        "~/.ssh".into(),
        "~/work/secret".into(),
        "~/work/project/private".into(),
        "{home}/private".into(),
    ];
    let compiled = base.join("policy.sb");
    std::fs::write(&compiled, Seatbelt.compile(&policy, &ctx).unwrap().text).unwrap();
    let paths = PathContext {
        user_home: ctx.user_home.clone(),
        sandbox_home: ctx.home.clone(),
    };
    let fs = FsPaths::of(&policy.fs, &paths).unwrap();
    World {
        _dir: dir,
        base,
        ctx,
        compiled,
        fs,
        allowed,
        other,
    }
}

impl World {
    /// Runs a shell command in the sandbox; true when it exits 0.
    fn sh(&self, script: &str) -> bool {
        self.sh_with_service(script, None)
    }

    /// [`World::sh`], for a session given the port of its runtime's service.
    fn sh_with_service(&self, script: &str, service_port: Option<u16>) -> bool {
        let launch = Launch {
            program: "/bin/sh".into(),
            args: vec!["-c".into(), script.into()],
            env: vec![],
            in_terminal: false,
            service_port,
            limits: Default::default(),
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
            in_terminal: false,
            service_port: None,
            limits: Default::default(),
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

    /// Whether the policy refused the command: it failed with Seatbelt's
    /// `Operation not permitted`, not for another reason.
    fn refused(&self, script: &str) -> bool {
        let (ok, out) = self.out(&format!("{{ {script}; }} 2>&1"));
        !ok && out.contains("Operation not permitted")
    }

    fn path(&self, rel: &str) -> String {
        self.base.join(rel).display().to_string()
    }

    /// Compiles `policy` in place of the one [`world`] wrote.
    fn enforce(&self, policy: &Policy) {
        let text = Seatbelt.compile(policy, &self.ctx).unwrap().text;
        std::fs::write(&self.compiled, text).unwrap();
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

/// TCP to the proxy port on 127.0.0.1, and nothing else on either loopback.
/// What the rule opens at the proxy port on `[::1]` is not asserted: it was
/// checked by hand on macOS 26.5.2 only, and the proxy holds that address
/// too (`proxy::listen`).
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
    let other6 = TcpListener::bind((Ipv6Addr::LOCALHOST, 0)).unwrap();
    assert!(!w.sh(&format!("/usr/bin/nc -z -w 3 ::1 {}", port(&other6))));
}

/// Listening (ADR 0028). Without `listen`, no TCP bind at all. With it, any
/// port outside the proxy range, on both loopbacks and on every address, and
/// none in it, held by a proxy or not, whatever install reserved it: an IPv6
/// socket that also takes IPv4 (`[::]`) included. Outbound still reaches only
/// the proxy port. The `policy test` probes are closed in both cases, judged
/// as `policy test` judges them, and open without the deny rules.
#[test]
fn a_sandbox_that_listens_binds_any_port_but_the_proxy_ports() {
    let mut w = world();
    let bind = |addr: &str, port: u16| {
        let (family, sockaddr) = match addr.contains(':') {
            false => (
                "AF_INET",
                format!("sockaddr_in({port}, inet_aton(\"{addr}\"))"),
            ),
            true => (
                "AF_INET6",
                format!("pack_sockaddr_in6({port}, inet_pton(AF_INET6, \"{addr}\"))"),
            ),
        };
        format!(
            "/usr/bin/perl -MSocket=:all -e 'socket(my $s, {family}, SOCK_STREAM, 0) or die \"$!\\n\"; bind($s, {sockaddr}) or die \"$!\\n\"; listen($s, 1) or die \"$!\\n\"'"
        )
    };
    // Two ports of the proxy range, every install's: the world's proxy port,
    // held by a listener standing in for its proxy, and one nothing holds,
    // such as the port of a sandbox made after this policy was compiled.
    let proxy = w.ctx.proxy_port;
    let free = (crate::model::sandbox::PORT_FIRST..=crate::model::sandbox::PORT_LAST)
        .find_map(|port| TcpListener::bind(("127.0.0.1", port)).ok())
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let v6 = TcpListener::bind(("::1", 0)).is_ok();
    // Each probe as `policy test` runs it: the sandbox, then the control.
    let judged = |w: &World, listen: bool| -> Vec<(String, Outcome)> {
        crate::probes::listen_probes(listen, proxy)
            .into_iter()
            .filter(|p| v6 || !p.name.ends_with("[::1]"))
            .map(|p| {
                let launch = Launch {
                    program: "/bin/sh".into(),
                    args: vec!["-c".into(), sandboxed_script(&p).into()],
                    env: vec![],
                    in_terminal: false,
                    service_port: None,
                    limits: Default::default(),
                };
                let out = Seatbelt
                    .wrap(&w.compiled, &w.ctx, &launch)
                    .stdin(Stdio::null())
                    .output()
                    .unwrap();
                let Proof::Control { control, .. } = &p.proof else {
                    panic!("{} has no control", p.name);
                };
                let host = Command::new("/bin/sh")
                    .args(["-c", control.as_str()])
                    .output()
                    .unwrap();
                let text = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
                let got = outcome(
                    &p,
                    Run::read(out.status.success(), &text(&out.stdout), &text(&out.stderr)),
                    Ok(None),
                    Some((host.status.success(), &text(&host.stdout))),
                );
                (p.name, got)
            })
            .collect()
    };
    assert!(w.refused(&bind("127.0.0.1", 0)));
    if v6 {
        assert!(w.refused(&bind("::1", 0)));
    }
    for (name, got) in judged(&w, false) {
        assert_eq!(got, Outcome::Closed, "{name}");
    }

    let mut policy = Policy::default();
    policy.fs.write = vec!["{home}".into()];
    policy.net.listen = true;
    w.enforce(&policy);
    let mut addrs = vec!["127.0.0.1", "0.0.0.0"];
    if v6 {
        addrs.extend(["::1", "::"]);
    }
    for addr in addrs {
        assert!(w.sh(&bind(addr, 0)), "{addr}:0");
        // Seatbelt refuses before the port is found in use.
        assert!(w.refused(&bind(addr, proxy)), "{addr}:{proxy}, held");
        assert!(w.refused(&bind(addr, free)), "{addr}:{free}");
    }
    for (name, got) in judged(&w, true) {
        assert_eq!(got, Outcome::Closed, "{name}");
    }
    let other = w.other.local_addr().unwrap().port();
    assert!(!w.sh(&format!("/usr/bin/nc -z -w 3 127.0.0.1 {other}")));

    // The runtime's service, as a listener on the host's loopback here: a
    // session given its port reaches it on 127.0.0.1, and nothing else
    // there, not even `[::1]` at that port, where another sandbox that
    // listens could be; a session given none reaches neither.
    let service_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let service = service_listener.local_addr().unwrap().port();
    let squatter = TcpListener::bind(("::1", service));
    let nc = |host: &str, port: u16| format!("/usr/bin/nc -z -w 3 {host} {port}");
    assert!(w.sh_with_service(&nc("127.0.0.1", service), Some(service)));
    if squatter.is_ok() {
        assert!(!w.sh_with_service(&nc("::1", service), Some(service)));
    }
    assert!(!w.sh_with_service(&nc("127.0.0.1", other), Some(service)));
    assert!(!w.sh(&nc("127.0.0.1", service)));
    assert!(!w.sh(&nc("127.0.0.1", other)));

    // Without the deny rules, the probes read as open: the bind went
    // through. The proxy's stand-in is closed first, so the bind is not
    // refused for the port being in use instead.
    let text = std::fs::read_to_string(&w.compiled).unwrap();
    let without: String = text
        .lines()
        .filter(|l| !l.starts_with("(deny network-bind (local tcp"))
        .map(|l| format!("{l}\n"))
        .collect();
    w.compiled = w.base.join("without-the-deny.sb");
    std::fs::write(&w.compiled, without).unwrap();
    drop(std::mem::replace(
        &mut w.allowed,
        TcpListener::bind("127.0.0.1:0").unwrap(),
    ));
    for (name, got) in judged(&w, true) {
        assert!(matches!(got, Outcome::Open(_)), "{name}: {got:?}");
    }
}

/// The rule opens the proxy port to TCP only: a program holding that port
/// for UDP would get datagrams around the proxy, which holds TCP alone.
#[test]
fn no_datagram_reaches_the_proxy_port() {
    let w = world();
    let port = w.allowed.local_addr().unwrap().port();
    for loopback in [
        IpAddr::from(Ipv4Addr::LOCALHOST),
        Ipv6Addr::LOCALHOST.into(),
    ] {
        // A program on the proxy port, for UDP.
        let listener = UdpSocket::bind((loopback, port)).unwrap();
        listener
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        w.sh(&format!("echo x | /usr/bin/nc -u -w 1 {loopback} {port}"));
        let mut buf = [0; 16];
        assert!(
            listener.recv(&mut buf).is_err(),
            "a datagram reached {loopback}:{port}"
        );
    }
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

/// `renameatx_np(2)` with `RENAME_SWAP`, through perl: swaps two folders in
/// one call, so neither ends up named the way it was.
fn swap(a: &str, b: &str) -> String {
    format!(
        "/usr/bin/perl -e 'syscall(488, -2, $ARGV[0], -2, $ARGV[1], 2) == 0 or die \"$!\\n\"' '{a}' '{b}'"
    )
}

#[test]
fn a_folder_holding_a_hidden_path_cannot_be_moved_to_uncover_it() {
    let w = world();
    let project = w.path("alice/work/project");
    let moved = w.path("alice/work/moved");
    // Deny rules name paths: under its new name, the key would be readable.
    assert!(w.refused(&format!(
        "/bin/mv '{project}' '{moved}' && cat '{moved}/private/key'"
    )));
    assert!(Path::new(&project).join("private/key").exists());
    assert!(!Path::new(&moved).exists());
    std::fs::create_dir_all(&moved).unwrap();
    assert!(w.refused(&format!(
        "{} && cat '{moved}/private/key'",
        swap(&moved, &project)
    )));
    assert!(Path::new(&project).join("private/key").exists());
    // The same for the sandbox home, into a workspace.
    assert!(w.refused(&format!(
        "/bin/mv \"$HOME\" '{}'",
        w.path("alice/work/home")
    )));
    assert!(w.ctx.home.join("private/key").exists());
}

#[test]
fn a_workspace_cannot_be_moved_away() {
    let w = world();
    let work = w.path("alice/work");
    assert!(w.refused(&format!("/bin/mv '{work}' \"$HOME/stolen\"")));
    assert!(Path::new(&work).join("project/private/key").exists());
    assert!(!w.ctx.home.join("stolen").exists());
    std::fs::create_dir_all(w.ctx.home.join("empty")).unwrap();
    assert!(w.refused(&swap(
        &w.ctx.home.join("empty").display().to_string(),
        &work
    )));
    assert!(Path::new(&work).join("project/private/key").exists());
    // A workspace holding nothing hidden stays in place too, and the home
    // cannot be moved into it; what is inside it can still be removed.
    let plain = w.path("alice/plain");
    assert!(w.refused(&format!("/bin/mv '{plain}' \"$HOME/plain\"")));
    assert!(w.refused(&format!("/bin/mv \"$HOME\" '{plain}/home'")));
    assert!(w.refused(&swap(
        &w.ctx.home.join("empty").display().to_string(),
        &plain
    )));
    assert!(w.sh(&format!(
        "/usr/bin/touch '{plain}/file' && /bin/rm '{plain}/file'"
    )));
    assert!(w.refused(&format!("/bin/rmdir '{plain}'")));
    assert!(Path::new(&plain).is_dir());
    assert!(!w.ctx.home.join("plain").exists());
    assert!(w.ctx.home.join("private/key").exists());
}

/// `clonefileat(2)` through perl: copies a folder and everything under it
/// in one call.
fn clone(from: &str, to: &str) -> String {
    format!(
        "/usr/bin/perl -e 'syscall(462, -2, $ARGV[0], -2, $ARGV[1], 0) == 0 or die \"$!\\n\"' '{from}' '{to}'"
    )
}

#[test]
fn a_folder_holding_a_hidden_path_cannot_be_cloned_to_copy_it_out() {
    let w = world();
    let work = w.path("alice/work");
    for (from, to) in [
        (format!("{work}/project"), format!("{work}/copy")),
        (work.clone(), w.ctx.home.join("copy").display().to_string()),
        (
            w.ctx.home.display().to_string(),
            format!("{work}/home-copy"),
        ),
        (w.path("alice/plain"), format!("{work}/plain-copy")),
        // The denied folder itself, which its own denial covers.
        (
            format!("{work}/project/private"),
            format!("{work}/private-copy"),
        ),
    ] {
        assert!(w.refused(&clone(&from, &to)), "{from}");
        assert!(!Path::new(&to).exists(), "{to}");
    }
    // Files, and folders that hold nothing hidden, still clone.
    assert!(w.sh(&format!(
        "/bin/mkdir -p '{work}/project/src' && /usr/bin/touch '{work}/project/src/a'"
    )));
    assert!(w.sh(&clone(
        &format!("{work}/project/src"),
        &format!("{work}/src-copy")
    )));
    assert!(w.sh(&format!(
        "/bin/cp -c '{work}/project/src/a' '{work}/project/b'"
    )));
    assert!(Path::new(&work).join("src-copy/a").exists());
}

#[test]
fn folders_and_files_in_a_workspace_are_still_made_renamed_and_removed() {
    let w = world();
    let work = w.path("alice/work");
    for script in [
        format!("/bin/mkdir -p '{work}/new/deep/er'"),
        format!("/bin/mkdir -p '{work}/project/src/lib'"),
        format!("/usr/bin/touch '{work}/project/file' '{work}/top'"),
        format!("/bin/mv '{work}/project/file' '{work}/project/renamed'"),
        format!("/bin/rm '{work}/project/renamed'"),
        format!("/bin/mv '{work}/new' '{work}/newer'"),
        format!("/bin/rm -r '{work}/newer'"),
        format!("/bin/mv '{work}/project/src' '{work}/project/source'"),
        // Two folders that hold nothing hidden still swap.
        format!("/bin/mkdir '{work}/x' '{work}/y' && /usr/bin/touch '{work}/x/in-x'"),
        swap(&format!("{work}/x"), &format!("{work}/y")),
        "/bin/mkdir -p \"$HOME/a/b\" && /bin/mv \"$HOME/a\" \"$HOME/c\"".to_owned(),
        "/usr/bin/touch \"$HOME/c/f\" && /bin/cp -c \"$HOME/c/f\" \"$HOME/c/g\"".to_owned(),
        clone(
            &w.ctx.home.join("c").display().to_string(),
            &w.ctx.home.join("d").display().to_string(),
        ),
        "/bin/rm \"$HOME/c/f\" && /bin/rm -r \"$HOME/d\"".to_owned(),
    ] {
        assert!(w.sh(&script), "{script}");
    }
    assert!(Path::new(&work).join("project/source/lib").is_dir());
    assert!(Path::new(&work).join("top").exists());
    assert!(!Path::new(&work).join("newer").exists());
    assert!(Path::new(&work).join("y/in-x").exists());
    assert!(w.ctx.home.join("c/b").is_dir());
    assert!(w.ctx.home.join("c/g").exists());
    assert!(!w.ctx.home.join("c/f").exists());
    assert!(!w.ctx.home.join("d").exists());
}

/// The rename and clone probes of `policy test` for the world's policy, each
/// run under `compiled` and judged as `policy test` does.
fn folder_probes(w: &World, compiled: &Path) -> Vec<(String, Outcome)> {
    let user = w.base.join("alice");
    let inputs = ProbeInputs {
        user_home: user.clone(),
        data: user.join(".enclos"),
        config_file: user.join(".enclos/config.toml"),
        sandbox_dir: user.join(".enclos/sandboxes/home"),
        other_sandboxes: Vec::new(),
        writes: w.fs.writes.clone(),
        read_deny: w.fs.read_deny.clone(),
        home: w.fs.home.clone(),
        workspaces: w.fs.writes.clone(),
        unmovable: w.fs.unmovable(),
        host_sockets: Vec::new(),
        proxy_port: w.ctx.proxy_port,
        listen: false,
        other_terminal: None,
        target: None,
        tag: 7,
        keychain_item: Err("not probed here".into()),
        limits: Default::default(),
    };
    let output = |mut command: Command| {
        let out = command.stdin(Stdio::null()).output().unwrap();
        let text = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
        (out.status.success(), text(&out.stdout), text(&out.stderr))
    };
    probes(&inputs)
        .into_iter()
        .filter(|p| ["renames", "clones"].contains(&p.route))
        .map(|p| {
            let launch = Launch {
                program: "/bin/sh".into(),
                args: vec!["-c".into(), sandboxed_script(&p).into()],
                env: vec![],
                in_terminal: false,
                service_port: None,
                limits: Default::default(),
            };
            let (ok, stdout, stderr) = output(Seatbelt.wrap(compiled, &w.ctx, &launch));
            let Proof::Control { control, .. } = &p.proof else {
                panic!("{} has no control", p.name);
            };
            let mut host = Command::new("/bin/sh");
            host.args(["-c", control.as_str()]);
            let (control_ok, control_out, _) = output(host);
            let got = outcome(
                &p,
                Run::read(ok, &stdout, &stderr),
                Ok(None),
                Some((control_ok, &control_out)),
            );
            (p.name, got)
        })
        .collect()
}

/// The compiled policy at `compiled` without the two rules that keep
/// writable folders in place: the folders that cannot move (no unlink or
/// clone) and, last, the home and each workspace themselves (no unlink or
/// create). Each covers the home and the workspaces, so a probe of them
/// reads as open only once both are gone.
fn without_folder_rules(compiled: &Path) -> String {
    let text = std::fs::read_to_string(compiled).unwrap();
    let roots = text
        .find("\n;; ---- The home and each workspace themselves")
        .unwrap();
    let text = &text[..roots];
    let start = text.find("(deny file-write-unlink file-clone").unwrap();
    let end = start + text[start..].find("\n\n").unwrap();
    format!("{}{}\n", &text[..start], &text[end..])
}

#[test]
fn the_rename_and_clone_probes_are_closed_and_would_say_open_without_the_rule() {
    let w = world();
    let closed = folder_probes(&w, &w.compiled);
    // The home, the five workspaces, and the folder holding a hidden path in
    // one, each that is a folder here renamed and cloned.
    assert_eq!(w.fs.unmovable().len(), 7, "{:?}", w.fs.unmovable());
    let folders = w.fs.unmovable().iter().filter(|f| f.is_dir()).count();
    assert_eq!(closed.len(), 2 * folders, "{closed:?}");
    for (name, got) in &closed {
        assert_eq!(*got, Outcome::Closed, "{name}");
    }
    // The same policy without the rules that keep these folders in place.
    let without = w.base.join("without-unmovable.sb");
    std::fs::write(&without, without_folder_rules(&w.compiled)).unwrap();
    for (name, got) in folder_probes(&w, &without) {
        assert!(matches!(got, Outcome::Open(_)), "{name}: {got:?}");
    }
    // Nothing moved or was copied either way.
    assert!(w.base.join("alice/work/project/private/key").exists());
    assert!(w.ctx.home.join("private/key").exists());
    // `~/later` is a workspace not made yet, so it has nothing to keep.
    for folder in w.fs.unmovable().iter().filter(|f| !f.ends_with("later")) {
        assert!(folder.is_dir(), "{}", folder.display());
        assert!(
            !folder.join("enclos-probe-7").exists(),
            "{}",
            folder.display()
        );
    }
}

#[test]
fn the_home_and_each_workspace_stay_the_folders_the_policy_was_compiled_for() {
    let w = world();
    let home = w.ctx.home.display().to_string();
    let work = w.path("alice/work");
    let empty = w.path("alice/empty");
    let later = w.path("alice/later");
    let linked = w.path("alice/linked");
    let outside = w.path("alice");
    // The home and each workspace can be neither moved nor removed, so
    // nothing else can take their place.
    assert!(w.refused(&format!("/bin/mv '{home}' '{work}/home'")));
    assert!(w.refused(&format!("/bin/mv '{work}' \"$HOME/work\"")));
    assert!(w.refused(&format!(
        "/bin/rmdir '{empty}' && /bin/ln -s '{outside}' '{empty}'"
    )));
    // Nor swapped with a link in one step: renamex_np(RENAME_SWAP), through
    // its system call (renameatx_np, 488; AT_FDCWD is -2).
    let swap = |a: &str, b: &str| {
        format!(
            "/usr/bin/perl -e 'syscall(488, -2, $ARGV[0], -2, $ARGV[1], 2) == 0 or die \"$!\\n\"' '{a}' '{b}'"
        )
    };
    assert!(w.sh(&format!("/bin/ln -s '{outside}' \"$HOME/link\"")));
    assert!(w.refused(&swap(&format!("{home}/link"), &empty)));
    assert!(w.refused(&swap(&format!("{home}/link"), &home)));
    // A workspace not made yet cannot be made, as a link or a folder.
    assert!(w.refused(&format!("/bin/ln -s '{outside}' '{later}'")));
    assert!(w.refused(&format!("/bin/mkdir '{later}'")));
    for folder in [&home, &work, &empty] {
        let meta = Path::new(folder).symlink_metadata().unwrap();
        assert!(meta.is_dir() && !meta.file_type().is_symlink(), "{folder}");
    }
    assert!(Path::new(&later).symlink_metadata().is_err());
    // A link the user made outside every writable folder stays theirs:
    // the sandbox writes where it leads, and cannot point it elsewhere.
    assert!(w.refused(&format!("/bin/ln -sfn '{outside}' '{linked}'")));
    assert!(w.refused(&format!("/bin/rm '{linked}'")));
    assert_eq!(
        std::fs::read_link(&linked).unwrap(),
        w.base.join("alice/projects")
    );
    assert!(w.sh(&format!("echo x > '{linked}/f'")));
    // A link in the home is the sandbox's own to change, which is why
    // `validate` refuses a workspace reached through one.
    assert!(w.sh(&format!(
        "/bin/rm \"$HOME/link\" && /bin/ln -s '{work}' \"$HOME/link\""
    )));
    // Inside them, everything still goes: files, folders, links and moves.
    assert!(w.sh(&format!(
        "cd '{empty}' && echo x > f && mkdir d && mv d e && ln -s '{outside}' l && rm l f && rmdir e"
    )));
    assert!(w.sh("/bin/mkdir -p \"$HOME/a/b\" && /bin/mv \"$HOME/a\" \"$HOME/c\""));

    // The escape probes for these folders are closed under this policy.
    let inputs = crate::probes::ProbeInputs {
        user_home: w.base.join("alice"),
        data: w.base.join("alice/.enclos"),
        config_file: w.base.join("alice/.enclos/config.toml"),
        sandbox_dir: w.base.join("alice/.enclos/sandboxes/home"),
        other_sandboxes: Vec::new(),
        writes: Vec::new(),
        read_deny: Vec::new(),
        home: w.ctx.home.clone(),
        workspaces: vec![w.base.join("alice/work"), w.base.join("alice/empty")],
        unmovable: Vec::new(),
        host_sockets: Vec::new(),
        proxy_port: w.ctx.proxy_port,
        listen: false,
        other_terminal: None,
        target: None,
        tag: 7,
        keychain_item: Err("not probed here".into()),
        limits: Default::default(),
    };
    let folders: Vec<_> = crate::probes::probes(&inputs)
        .into_iter()
        .filter(|p| p.route == "writable folders")
        .collect();
    assert_eq!(folders.len(), 4);
    for probe in &folders {
        let (ok, out) = w.out(&probe.script);
        assert!(
            !ok && out.contains("Operation not permitted"),
            "{}: {out}",
            probe.name
        );
    }
    assert!(w.ctx.home.join("tmp").is_dir());

    // Without the rules, the probes read as open and still change nothing.
    let mut w = w;
    let without = without_folder_rules(&w.compiled);
    w.compiled = w.base.join("without-the-rule.sb");
    std::fs::write(&w.compiled, without).unwrap();
    for probe in &folders {
        let (ok, out) = w.out(&probe.script);
        assert!(
            ok && out.contains("the policy let it through"),
            "{}: {out}",
            probe.name
        );
    }
    for folder in [&home, &work, &empty] {
        let meta = Path::new(folder).symlink_metadata().unwrap();
        assert!(meta.is_dir() && !meta.file_type().is_symlink(), "{folder}");
    }
}

#[test]
fn the_home_stays_in_place_when_the_policy_leaves_it_out_of_its_writes() {
    let mut w = world();
    let mut policy = Policy::default();
    policy.fs.write = vec!["~/work".into()];
    w.compiled = w.base.join("no-home.sb");
    std::fs::write(&w.compiled, Seatbelt.compile(&policy, &w.ctx).unwrap().text).unwrap();
    let home = w.ctx.home.display().to_string();
    assert!(w.sh("echo x > \"$HOME/still-writable\""));
    let work = w.path("alice/work");
    // Into a workspace, which the sandbox writes: only the rule refuses it.
    assert!(w.refused(&format!("/bin/mv '{home}' '{work}/home'")));
    let meta = w.ctx.home.symlink_metadata().unwrap();
    assert!(meta.is_dir() && !meta.file_type().is_symlink());
}

/// Fake files at paths the built-in deny list names, relative to the user's
/// home. Together they cover each shape of entry: a file, a folder, a name
/// with spaces and a bundle.
const DENIED_FAKES: &[&str] = &[
    // File entries
    ".cargo/credentials.toml",
    ".cache/huggingface/token",
    ".zhistory",
    // Folder entries
    ".config/rclone/rclone.conf",
    ".local/share/atuin/history.db",
    ".password-store/bank.gpg",
    ".gemini/oauth_creds.json",
    ".local/share/opencode/auth.json",
    "Library/HTTPStorages/com.example.app/httpstorages.sqlite",
    "Library/Containers/com.apple.Safari/Data/Library/Cookies/Cookies.binarycookies",
    "Library/Group Containers/group.com.apple.notes/NoteStore.sqlite",
    // A name with spaces
    "Library/Application Support/Google/Chrome Beta/Default/Cookies",
    // A bundle
    "Pictures/Photos Library.photoslibrary/database/Photos.sqlite",
];

#[test]
fn the_built_in_deny_list_hides_the_users_files_but_not_the_same_names_in_the_home() {
    let w = world();
    let mut policy = Policy::default();
    PolicyFile::parse("built-in defaults", crate::policy::DEFAULTS)
        .unwrap()
        .apply(&mut policy);
    w.enforce(&policy);
    for rel in DENIED_FAKES {
        let host = w.base.join("alice").join(rel);
        std::fs::create_dir_all(host.parent().unwrap()).unwrap();
        std::fs::write(&host, "secret").unwrap();
        assert!(
            !w.sh(&format!("cat '{}'", host.display())),
            "{rel} was read"
        );
        // A file of the same name in the sandbox home is the sandbox's own:
        // `~` in the list is the user's home, not the sandbox home.
        let own = format!("\"$HOME/{rel}\"");
        assert!(
            w.sh(&format!(
                "/bin/mkdir -p \"$(dirname {own})\" && echo mine > {own} && cat {own}"
            )),
            "{rel} in the sandbox home"
        );
    }
    // Only the named file is hidden, not the folder holding it.
    std::fs::write(w.base.join("alice/.cargo/config.toml"), "fine").unwrap();
    assert!(w.sh(&format!("cat '{}'", w.path("alice/.cargo/config.toml"))));
    assert!(w.sh(&format!("/bin/ls '{}'", w.path("alice/.cache/huggingface"))));
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

    // On either baseline, each rule holds alone, and with neither the byte
    // goes in: the control (into `script`'s own terminal only).
    let run = |text: &str, name: &str| {
        let file = w.base.join(name);
        std::fs::write(&file, text).unwrap();
        let out = Command::new("/usr/bin/script")
            .args(["-q", "/dev/null", "/usr/bin/sandbox-exec", "-f"])
            .arg(&file)
            .args(["/usr/bin/perl", "-e", try_tiocsti])
            .stdin(Stdio::null())
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout).into_owned()
    };
    let text = std::fs::read_to_string(&w.compiled).unwrap();
    let ioctl_rule =
        "(deny file-ioctl (with message \"enclos:home\")\n  (ioctl-command TIOCSTI))\n";
    let hid_rule = "(deny hid-control (with message \"enclos:home\"))\n";
    assert!(
        text.contains(ioctl_rule) && text.contains(hid_rule),
        "{text}"
    );
    let neither = format!(
        "{}(allow hid-control)\n",
        text.replace(ioctl_rule, "").replace(hid_rule, "")
    );
    assert!(
        run(&neither, "neither.sb").contains("INJECTED"),
        "the control"
    );
    let ioctl_alone = format!("{}(allow hid-control)\n", text.replace(hid_rule, ""));
    assert!(run(&ioctl_alone, "ioctl-alone.sb").contains("REFUSED"));
    let allow_default = text.replace(
        "(deny default (with message \"enclos:home\"))\n",
        "(allow default)\n",
    );
    assert_ne!(allow_default, text);
    let allow_ioctl_alone = format!(
        "{}(allow hid-control)\n",
        allow_default.replace(hid_rule, "")
    );
    assert!(run(&allow_ioctl_alone, "allow-ioctl-alone.sb").contains("REFUSED"));
    let hid_alone = text.replace(ioctl_rule, "");
    assert!(run(&hid_alone, "hid-alone.sb").contains("REFUSED"));
    let allow_hid_alone = allow_default.replace(ioctl_rule, "");
    assert!(run(&allow_hid_alone, "allow-hid-alone.sb").contains("REFUSED"));
    let allow_neither = allow_default.replace(ioctl_rule, "").replace(hid_rule, "");
    assert!(
        run(&allow_neither, "allow-neither.sb").contains("INJECTED"),
        "the control under (allow default)"
    );
}

/// The sandbox still signals its own processes, as job control, timeouts
/// and Ctrl-C need: only those it starts itself. (`ps` cannot show the
/// rest: it is setuid, and Seatbelt runs no setuid program, whatever the
/// baseline.)
#[test]
fn the_sandbox_signals_its_own_processes() {
    let w = world();
    assert!(w.sh("/bin/sleep 30 & p=$!; /bin/kill $p; wait $p; [ $? -eq 143 ]"));
}

/// A pseudo-terminal this test opens, as a terminal app does for each tab:
/// its primary (master) side, kept open while the test runs, and its
/// device's name.
pub(super) fn terminal() -> (std::os::fd::OwnedFd, PathBuf) {
    use rustix::pty::{OpenptFlags, grantpt, openpt, ptsname, unlockpt};
    let main = openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY).unwrap();
    grantpt(&main).unwrap();
    unlockpt(&main).unwrap();
    let name = ptsname(&main, Vec::new()).unwrap();
    (main, PathBuf::from(name.into_string().unwrap()))
}

#[test]
fn the_sandbox_opens_no_terminal_but_its_own() {
    let w = world();
    let (_mine, mine) = terminal();
    let (_other, other) = terminal();
    // Opening it to read, then to write.
    let opens = |t: &Path| {
        let t = t.display();
        (format!(": < '{t}'"), format!(": >> '{t}'"))
    };
    let (read_mine, write_mine) = opens(&mine);
    let (read, write) = opens(&other);
    // Each works outside the sandbox.
    for script in [&read_mine, &write_mine, &read, &write] {
        let host = Command::new("/bin/sh").args(["-c", script]).status();
        assert!(host.unwrap().success(), "{script}");
    }
    let run = |terminal: Option<&Path>, script: &str| {
        let launch = Launch {
            program: "/bin/sh".into(),
            args: vec!["-c".into(), script.into()],
            env: vec![],
            in_terminal: false,
            service_port: None,
            limits: Default::default(),
        };
        super::wrap::wrap_in(&w.compiled, &w.ctx, &launch, terminal)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success()
    };
    // Without a terminal, as a service runs: no terminal opens by name.
    for script in [&read_mine, &write_mine, &read, &write] {
        assert!(!run(None, script), "{script}");
    }
    // A session in `mine` opens it by name, and still no other.
    assert!(run(Some(&mine), &read_mine));
    assert!(run(Some(&mine), &write_mine));
    assert!(!run(Some(&mine), &read));
    assert!(!run(Some(&mine), &write));
    // Only a terminal device opens by name: naming another file grants
    // nothing.
    let file = w.base.join("alice/readable.txt");
    let append = format!("echo x >> '{}'", file.display());
    assert!(!run(Some(&file), &append));
    assert!(run(None, "echo x > /dev/null && : < /dev/null"));
}

#[test]
fn the_sandbox_cannot_grant_itself_another_terminal() {
    let w = world();
    let (_other, other) = terminal();
    // Asks macOS for the pty extension for `other`, through JavaScript for
    // Automation (so enclos needs no code of its own for it), then opens it.
    let issue = "ObjC.bindFunction('sandbox_extension_issue_file', ['char *', ['char *', 'char *', 'int']]);
        ObjC.bindFunction('sandbox_extension_consume', ['long long', ['char *']]);
        function run(argv) {
            try { $.sandbox_extension_consume($.sandbox_extension_issue_file('com.apple.sandbox.pty', argv[0], 0)) } catch (e) {}
        }";
    let script = r#"/usr/bin/osascript -l JavaScript -e "$1" "$2" >/dev/null 2>&1; : < "$2""#;
    let run = |compiled: &Path| {
        let launch = Launch {
            program: "/bin/sh".into(),
            args: vec![
                "-c".into(),
                script.into(),
                "sh".into(),
                issue.into(),
                other.clone().into(),
            ],
            env: vec![],
            in_terminal: false,
            service_port: None,
            limits: Default::default(),
        };
        super::wrap::wrap_in(compiled, &w.ctx, &launch, None)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success()
    };
    // The control: from `(allow default)` and without the rule that refuses
    // it, the extension opens `other`, so the route exists and this test can
    // see it closed. `(deny default)` refuses it too, as Apple's own
    // `application.sb` does: the rule keeps it closed should the baseline
    // ever be `(allow default)` again (ADR 0006).
    let text = std::fs::read_to_string(&w.compiled).unwrap();
    let without: String = text
        .lines()
        .filter(|l| !l.starts_with("(deny file-issue-extension"))
        .map(|l| match l.starts_with("(deny default") {
            true => "(allow default)\n".to_owned(),
            false => format!("{l}\n"),
        })
        .collect();
    assert!(
        text.lines()
            .any(|l| l.starts_with("(deny file-issue-extension")),
        "no rule to remove"
    );
    let open = w.base.join("without-the-rule.sb");
    std::fs::write(&open, without).unwrap();
    assert!(run(&open), "the route is gone: nothing to test");
    assert!(!run(&w.compiled));
    // The rule alone closes it on the earlier baseline, and the baseline
    // alone closes it without the rule.
    let with_rule = text.replace(
        "(deny default (with message \"enclos:home\"))\n",
        "(allow default)\n",
    );
    let file = w.base.join("allow-default-with-the-rule.sb");
    std::fs::write(&file, with_rule).unwrap();
    assert!(
        !run(&file),
        "the rule does not close it under (allow default)"
    );
    let baseline_alone: String = text
        .lines()
        .filter(|l| !l.starts_with("(deny file-issue-extension"))
        .map(|l| format!("{l}\n"))
        .collect();
    let file = w.base.join("deny-default-without-the-rule.sb");
    std::fs::write(&file, &baseline_alone).unwrap();
    assert!(!run(&file), "(deny default) does not close it alone");
    // The control on that baseline: allowed to issue the extension, the
    // sandbox opens `other`, so what closes it there is the baseline.
    let issued = format!(
        "{baseline_alone}(allow file-issue-extension (extension-class \"{}\"))\n",
        "com.apple.sandbox.pty"
    );
    let file = w.base.join("deny-default-allowed-to-issue.sb");
    std::fs::write(&file, issued).unwrap();
    assert!(
        run(&file),
        "the route is gone under (deny default): nothing to test"
    );
}

#[test]
fn a_session_keeps_its_terminal_and_the_terminals_it_opens() {
    let w = world();
    // `script` gives the session a terminal of its own, named to the policy
    // as `wrap` names the one enclos runs in.
    let session = r#"exec /usr/bin/sandbox-exec -D "ENCLOS_TERMINAL=$(/usr/bin/tty)" -f "$0" /bin/sh -c "$1""#;
    let inside = [
        "echo via-tty > /dev/tty",
        "t=$(/usr/bin/tty) && : < \"$t\" && : >> \"$t\" && echo own-by-name",
        // A terminal the sandbox opens itself, as tmux or an agent's shell tool does.
        "/usr/bin/script -q /dev/null /bin/echo in-a-new-terminal",
    ]
    .join("; ");
    let out = Command::new("/usr/bin/script")
        .args(["-q", "/dev/null", "/bin/sh", "-c", session])
        .arg(&w.compiled)
        .arg(&inside)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let out = String::from_utf8_lossy(&out.stdout);
    for expected in ["via-tty", "own-by-name", "in-a-new-terminal"] {
        assert!(out.contains(expected), "{expected}: {out}");
    }
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
