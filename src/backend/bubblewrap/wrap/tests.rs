use std::os::unix::fs::{PermissionsExt, symlink};

use super::*;
use crate::backend::bubblewrap::compile::{Bubblewrap, GrantMasks, RootMasks};
use crate::backend::{LaunchLimits, SandboxContext};
use crate::layout::Layout;
use crate::model::secret::SecretValue;

/// A user's home in a folder of its own, with the sandbox's home inside it
/// as enclos keeps it.
struct Home {
    dir: tempfile::TempDir,
}

impl Home {
    fn new() -> Home {
        let home = Home {
            dir: tempfile::tempdir().unwrap(),
        };
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

#[test]
fn a_denied_path_in_the_home_is_left_out_of_its_folders_and_the_rest_bound_back() {
    let home = Home::new();
    home.file(".ssh/id_ed25519");
    home.file(".config/gh/hosts.yml");
    home.file(".config/kept.toml");
    home.file("notes.txt");
    symlink("notes.txt", home.at("link")).unwrap();
    let c = compiled(
        &home,
        Lists {
            denied: vec![home.at(".ssh"), home.at(".config/gh")],
            ..Lists::default()
        },
    );
    let host = read(&home, &c, None).unwrap();
    let args = strings(&arguments(&c, &host, &[]));
    let user = text(&home.user());
    let config = text(&home.at(".config"));
    // Each folder on the way to a denied path becomes a tmpfs.
    position(&args, &["--tmpfs", &user]);
    position(&args, &["--tmpfs", &config]);
    let kept = text(&home.at("notes.txt"));
    position(&args, &["--ro-bind-try", &kept, &kept]);
    let kept = text(&home.at(".config/kept.toml"));
    position(&args, &["--ro-bind-try", &kept, &kept]);
    position(&args, &["--symlink", "notes.txt", &text(&home.at("link"))]);
    for denied in [".ssh", ".config/gh", ".enclos"] {
        let denied = text(&home.at(denied));
        assert!(!args.contains(&denied), "{denied}: {args:?}");
    }
    // Read-only once bubblewrap has made its mount points, after the
    // compiled mounts; only the options, whose place does not matter, follow.
    let sealed = position(&args, &["--remount-ro", &user]);
    assert!(sealed > position(&args, &["--bind", &text(&home.sandbox_home())]));
    assert!(sealed < position(&args, &["--die-with-parent"]));
    position(&args, &["--remount-ro", &config]);
}

#[test]
fn the_home_is_masked_after_the_root_and_before_the_compiled_rest() {
    let home = Home::new();
    let c = compiled(&home, Lists::default());
    let host = read(&home, &c, None).unwrap();
    let args = strings(&arguments(&c, &host, &[]));
    let user = text(&home.user());
    assert_eq!(&args[..3], ["--ro-bind", "/", "/"]);
    assert_eq!(&args[3..5], ["--tmpfs", user.as_str()]);
    let home_bind = position(&args, &["--bind", &text(&home.sandbox_home())]);
    assert!(home_bind > position(&args, &["--tmpfs", &user]));
}

#[test]
fn a_deny_entry_elsewhere_is_masked_by_its_kind_after_the_root() {
    let home = Home::new();
    let outside = tempfile::tempdir().unwrap();
    let folder = outside.path().join("lxd");
    std::fs::create_dir(&folder).unwrap();
    let file = outside.path().join("token");
    std::fs::write(&file, "x").unwrap();
    let missing = outside.path().join("missing");
    let c = compiled(
        &home,
        Lists {
            elsewhere: vec![folder.clone(), file.clone(), missing.clone()],
            ..Lists::default()
        },
    );
    let host = read(&home, &c, None).unwrap();
    let args = strings(&arguments(&c, &host, &[]));
    let rest = position(&args, &["--bind", &text(&home.sandbox_home())]);
    assert!(position(&args, &["--tmpfs", &text(&folder)]) < rest);
    assert!(position(&args, &["--ro-bind", "/dev/null", &text(&file)]) < rest);
    assert!(!args.contains(&text(&missing)), "{args:?}");
    position(&args, &["--remount-ro", &text(&folder)]);
}

/// Inside a workspace, after its bind, which would uncover a mask made
/// before it; a missing entry gets a folder, so the sandbox cannot make it.
#[test]
fn a_deny_entry_in_a_workspace_is_masked_after_its_bind_whether_or_not_it_is_there() {
    let home = Home::new();
    let workspace = home.folder("proj");
    let env = home.file("proj/config/.env");
    let keys = home.folder("proj/keys");
    let missing = home.at("proj/.netrc");
    let c = compiled(
        &home,
        Lists {
            in_workspace: vec![env.clone(), keys.clone(), missing.clone()],
            workspaces: vec![workspace.clone()],
            unmovable: vec![home.at("proj/config")],
            ..Lists::default()
        },
    );
    let host = read(&home, &c, None).unwrap();
    let args = strings(&arguments(&c, &host, &[]));
    let bound = position(&args, &["--bind-try", &text(&workspace)]);
    let config = text(&home.at("proj/config"));
    let unmovable = position(&args, &["--bind", &config, &config]);
    let file = position(&args, &["--ro-bind", "/dev/null", &text(&env)]);
    let folder = position(&args, &["--tmpfs", &text(&keys)]);
    let made = position(&args, &["--tmpfs", &text(&missing)]);
    assert!(bound < unmovable, "{args:?}");
    assert!(
        unmovable < file && unmovable < folder && unmovable < made,
        "{args:?}"
    );
    let sealed = position(&args, &["--remount-ro", &text(&keys)]);
    assert!(sealed > made);
    position(&args, &["--remount-ro", &text(&missing)]);
}

#[test]
fn a_deny_entry_in_the_sandbox_home_is_masked_after_its_bind() {
    let home = Home::new();
    let entry = home.sandbox_home().join(".ssh");
    let c = compiled(
        &home,
        Lists {
            in_sandbox_home: vec![entry.clone()],
            ..Lists::default()
        },
    );
    let host = read(&home, &c, None).unwrap();
    let args = strings(&arguments(&c, &host, &[]));
    let bound = position(&args, &["--bind", &text(&home.sandbox_home())]);
    assert!(position(&args, &["--tmpfs", &text(&entry)]) > bound);
}

/// bubblewrap binds none, so there is nothing to mask, and a mount point
/// there would fail the session.
#[test]
fn a_workspace_not_made_yet_gets_no_mask() {
    let home = Home::new();
    let workspace = home.at("later");
    let entry = home.at("later/.env");
    let c = compiled(
        &home,
        Lists {
            in_workspace: vec![entry.clone()],
            workspaces: vec![workspace],
            ..Lists::default()
        },
    );
    let host = read(&home, &c, None).unwrap();
    assert!(host.in_grants.is_empty(), "{host:?}");
    assert!(!strings(&arguments(&c, &host, &[])).contains(&text(&entry)));
}

/// `~/cargo -> ~/.cargo` with `write = ["~/cargo"]`: the bind reaches the
/// real folder, so the entry is masked at the workspace's name for it
/// (design §14).
#[test]
fn a_workspace_through_a_link_has_the_entry_it_reaches_masked_at_its_own_name() {
    let home = Home::new();
    home.file(".cargo/credentials.toml");
    home.file(".cargo/config.toml");
    symlink(home.at(".cargo"), home.at("cargo")).unwrap();
    let credentials = home.at(".cargo/credentials.toml");
    let c = compiled(
        &home,
        Lists {
            denied: vec![credentials],
            workspaces: vec![home.at("cargo")],
            ..Lists::default()
        },
    );
    let host = read(&home, &c, None).unwrap();
    let args = strings(&arguments(&c, &host, &[]));
    let through = text(&home.at("cargo/credentials.toml"));
    let mask = position(&args, &["--ro-bind", "/dev/null", &through]);
    assert!(mask > position(&args, &["--bind-try", &text(&home.at("cargo"))]));
    // The real folder is the workspace's: its bind replaces it, so it is
    // not listed for the home's mask.
    assert!(!host.entries.contains_key(&home.at(".cargo")), "{host:?}");
}

#[test]
fn a_workspace_that_reaches_a_deny_entry_through_a_link_is_refused() {
    let home = Home::new();
    home.file(".ssh/id_ed25519");
    symlink(home.at(".ssh"), home.at("keys")).unwrap();
    let c = compiled(
        &home,
        Lists {
            denied: vec![home.at(".ssh")],
            workspaces: vec![home.at("keys")],
            ..Lists::default()
        },
    );
    let why = read(&home, &c, None).unwrap_err().to_string();
    assert!(why.contains("which the deny list hides"), "{why}");
}

/// The sandbox writes every folder of its workspace, so it could make one a
/// link, and the mask would follow it.
#[test]
fn a_link_between_a_workspace_and_its_deny_entry_refuses_the_session() {
    let home = Home::new();
    let workspace = home.folder("proj");
    let elsewhere = home.folder("elsewhere");
    symlink(&elsewhere, home.at("proj/config")).unwrap();
    let c = compiled(
        &home,
        Lists {
            in_workspace: vec![home.at("proj/config/.env")],
            workspaces: vec![workspace],
            ..Lists::default()
        },
    );
    let why = read(&home, &c, None).unwrap_err().to_string();
    assert!(why.contains("is a link between"), "{why}");
    assert!(why.contains("proj/config"), "{why}");
}

#[test]
fn a_link_between_the_sandbox_home_and_its_deny_entry_refuses_the_session() {
    let home = Home::new();
    let elsewhere = home.folder("elsewhere");
    symlink(&elsewhere, home.sandbox_home().join(".config")).unwrap();
    let c = compiled(
        &home,
        Lists {
            in_sandbox_home: vec![home.sandbox_home().join(".config/gh")],
            ..Lists::default()
        },
    );
    let why = read(&home, &c, None).unwrap_err().to_string();
    assert!(why.contains("is a link between"), "{why}");
}

#[test]
fn the_agents_socket_is_masked_wherever_the_host_puts_it() {
    let home = Home::new();
    let in_home = home.file(".agent/agent.sock");
    // Outside `/tmp`, where every temporary folder is.
    let elsewhere = PathBuf::from("/nonexistent-enclos-test/agent.sock");
    let c = compiled(&home, Lists::default());

    let host = read(&home, &c, Some(&in_home)).unwrap();
    assert!(host.hidden.contains(&in_home), "{host:?}");
    let args = strings(&arguments(&c, &host, &[]));
    position(&args, &["--tmpfs", &text(&home.at(".agent"))]);
    assert!(!args.contains(&text(&in_home)), "{args:?}");

    // Masked as any deny entry elsewhere is, by its kind.
    let host = read(&home, &c, Some(&elsewhere)).unwrap();
    assert_eq!(host.elsewhere, [(elsewhere, Kind::Missing)]);

    // The sandbox's own `/tmp` hides one there already.
    let host = read(&home, &c, Some(Path::new("/tmp/ssh-x/agent.1"))).unwrap();
    assert!(host.elsewhere.is_empty(), "{host:?}");
}

#[test]
fn a_folder_that_cannot_be_listed_refuses_the_session() {
    let home = Home::new();
    let config = home.folder(".config");
    home.file(".config/gh/hosts.yml");
    std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o000)).unwrap();
    let c = compiled(
        &home,
        Lists {
            denied: vec![home.at(".config/gh")],
            ..Lists::default()
        },
    );
    let got = read(&home, &c, None);
    std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o755)).unwrap();
    // Root reads it all the same.
    if rustix::process::geteuid().is_root() {
        return;
    }
    let why = got.unwrap_err().to_string();
    assert!(why.contains("cannot look at"), "{why}");
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

/// The data folder is hidden from the sandbox, so what an install reads
/// there is bound back, each file alone and read-only, after the binds the
/// compiled file makes and before anything is sealed.
#[test]
fn the_files_an_install_staged_are_bound_read_only_and_nothing_else_of_their_folder() {
    let home = Home::new();
    let c = compiled(&home, Lists::default());
    let host = read(&home, &c, None).unwrap();
    let reads = staged(&home);
    let args = strings(&arguments(&c, &host, &reads));
    let sandbox = text(&home.sandbox_home());
    let bound = position(&args, &["--bind", &sandbox, &sandbox]);
    let first_seal = args.iter().position(|a| a == "--remount-ro").unwrap();
    for file in &reads {
        let at = position(&args, &["--ro-bind", &text(file), &text(file)]);
        assert!(bound < at && at < first_seal, "{args:?}");
    }
    let installers = text(&ctx(&home).installers);
    let shown: Vec<&String> = args.iter().filter(|a| a.contains(&installers)).collect();
    assert_eq!(shown.len(), 2 * reads.len(), "{args:?}");
    assert!(!args.contains(&installers), "{args:?}");
}

/// A session that reads nothing staged sees none of the folder.
#[test]
fn a_session_that_reads_nothing_staged_is_shown_nothing_of_the_installers() {
    let home = Home::new();
    let c = compiled(&home, Lists::default());
    let host = read(&home, &c, None).unwrap();
    let programs = Programs {
        bwrap: Path::new("/usr/bin/bwrap"),
        enclos: Path::new("/usr/bin/enclos"),
    };
    let file = Path::new("/c/compiled/x.json");
    let command = command(&programs, file, &c, &host, &ctx(&home), &launch(Vec::new())).unwrap();
    let installers = text(&ctx(&home).installers);
    let args: Vec<_> = command.get_args().map(|a| a.to_str().unwrap()).collect();
    assert!(!args.iter().any(|a| a.contains(&installers)), "{args:?}");
}

/// A data folder outside the user's home is a tmpfs of its own: sealed
/// before the staged files are bound, bubblewrap could not make their
/// mount points in it.
#[test]
fn a_protected_folder_outside_the_home_is_sealed_after_the_staged_files() {
    let home = Home::new();
    let elsewhere = home.folder("srv/enclos");
    let c = compiled(
        &home,
        Lists {
            sealed: vec![elsewhere.clone()],
            ..Lists::default()
        },
    );
    let host = read(&home, &c, None).unwrap();
    let reads = staged(&home);
    let args = strings(&arguments(&c, &host, &reads));
    let sealed = position(&args, &["--remount-ro", &text(&elsewhere)]);
    for file in &reads {
        assert!(position(&args, &["--ro-bind", &text(file), &text(file)]) < sealed);
    }
    // Sealed last, with only the options, whose place does not matter, after.
    let options = c.bubblewrap.options.len();
    assert_eq!(args.len(), sealed + 2 + options, "sealed last: {args:?}");
}

/// Only a file of the sandbox's own `installers/` folder is bound: not the
/// folder, nothing below a folder in it, and nothing elsewhere.
#[test]
fn only_a_file_of_the_sandboxs_installers_folder_is_shown() {
    let installers = Path::new("/d/sandboxes/lab/installers");
    assert!(staged_only(installers, &[installers.join("home-0")]).is_ok());
    assert!(staged_only(installers, &[]).is_ok());
    for refused in [
        installers.to_path_buf(),
        installers.join("deep/home-0"),
        installers.join(".."),
        PathBuf::from("/d/sandboxes/other/installers/home-0"),
        PathBuf::from("/d/state.db"),
        PathBuf::from("home-0"),
    ] {
        let why = staged_only(installers, &[installers.join("home-0"), refused.clone()])
            .unwrap_err()
            .to_string();
        assert!(why.contains(&refused.display().to_string()), "{why}");
    }
}

/// A launch naming another file starts nothing.
#[test]
fn a_launch_reading_a_file_enclos_did_not_stage_is_refused() {
    let home = Home::new();
    let c = compiled(&home, Lists::default());
    let host = read(&home, &c, None).unwrap();
    let programs = Programs {
        bwrap: Path::new("/usr/bin/bwrap"),
        enclos: Path::new("/usr/bin/enclos"),
    };
    let mut launch = launch(Vec::new());
    launch.reads = vec![home.at(".enclos/state.db")];
    let file = Path::new("/c/compiled/x.json");
    let why = command(&programs, file, &c, &host, &ctx(&home), &launch)
        .unwrap_err()
        .to_string();
    assert!(why.contains("is not a file enclos stages"), "{why}");
}

/// bubblewrap runs `enclos inside` first, with the compiled file, then the
/// session's command as it was given.
#[test]
fn bubblewrap_runs_enclos_inside_then_the_command() {
    let home = Home::new();
    let c = compiled(&home, Lists::default());
    let host = read(&home, &c, None).unwrap();
    let programs = Programs {
        bwrap: Path::new("/usr/bin/bwrap"),
        enclos: Path::new("/usr/bin/enclos"),
    };
    let file = Path::new("/c/compiled/x.json");
    let command = command(&programs, file, &c, &host, &ctx(&home), &launch(Vec::new())).unwrap();
    assert_eq!(command.get_program(), "/usr/bin/bwrap");
    let args: Vec<_> = command.get_args().map(|a| a.to_str().unwrap()).collect();
    let at = args.iter().position(|a| *a == "/usr/bin/enclos").unwrap();
    assert_eq!(
        &args[at..],
        [
            "/usr/bin/enclos",
            "inside",
            "--compiled",
            "/c/compiled/x.json",
            "--",
            "/bin/sh",
            "-c",
            "echo hi"
        ]
    );
    assert_eq!(
        command.get_current_dir(),
        Some(home.sandbox_home().as_path())
    );
}

/// The environment is set on bubblewrap's own process, emptied first: a
/// secret given as `--setenv` would be on a command line every process of
/// the host reads.
#[test]
fn the_environment_is_emptied_and_no_secret_is_on_the_command_line() {
    let home = Home::new();
    let c = compiled(&home, Lists::default());
    let host = read(&home, &c, None).unwrap();
    let programs = Programs {
        bwrap: Path::new("/usr/bin/bwrap"),
        enclos: Path::new("/usr/bin/enclos"),
    };
    let secret = SecretValue::new("sk-in-the-environment".to_owned()).unwrap();
    let env = vec![("API_KEY".to_owned(), secret)];
    let ctx = ctx(&home);
    let launch = launch(env);
    let command = command(&programs, Path::new("/c.json"), &c, &host, &ctx, &launch).unwrap();
    assert!(
        !command
            .get_args()
            .any(|a| a.to_string_lossy().contains("sk-in-the-environment"))
    );
    assert!(!command.get_args().any(|a| a == "--setenv"));
    let set: BTreeMap<_, _> = command
        .get_envs()
        .map(|(k, v)| (k.to_str().unwrap().to_owned(), v.map(|v| v.to_owned())))
        .collect();
    assert_eq!(
        set["API_KEY"].as_deref(),
        Some(std::ffi::OsStr::new("sk-in-the-environment"))
    );
    assert_eq!(
        set["HOME"].as_deref(),
        Some(home.sandbox_home().as_os_str())
    );
    // Nothing of this process's own variables but those every backend keeps.
    let run = command.get_envs().count();
    let mut every_backend = Command::new("/usr/bin/true");
    environment::apply(&mut every_backend, &ctx, &launch);
    let expected = every_backend.get_envs().count();
    assert!(run <= expected, "{run} variables set, {expected} expected");
    // `env_clear` leaves no inherited variable: run it and look.
    let mut shown = Command::new("/usr/bin/env");
    shown.env_clear();
    for (k, v) in command.get_envs() {
        if let Some(v) = v {
            shown.env(k, v);
        }
    }
    let out = String::from_utf8(shown.output().unwrap().stdout).unwrap();
    assert!(!out.contains("CARGO_PKG_NAME"), "{out}");
}

#[test]
fn an_enclos_the_sandbox_does_not_see_refuses_the_session() {
    let home = Home::new();
    home.file(".hidden-tools/enclos");
    let c = compiled(
        &home,
        Lists {
            denied: vec![home.at(".hidden-tools")],
            ..Lists::default()
        },
    );
    let host = read(&home, &c, None).unwrap();
    let enclos = home.at(".hidden-tools/enclos");
    let programs = Programs {
        bwrap: Path::new("/usr/bin/bwrap"),
        enclos: &enclos,
    };
    let why = command(
        &programs,
        Path::new("/c.json"),
        &c,
        &host,
        &ctx(&home),
        &launch(Vec::new()),
    )
    .unwrap_err()
    .to_string();
    assert!(why.contains("does not see"), "{why}");
}

/// What `/proc/self/status` says the stand-in bubblewrap ignores, and the
/// arguments it was given, for a launch in a terminal or not.
#[cfg(target_os = "linux")]
fn as_bubblewrap_ran(in_terminal: bool) -> (u64, String) {
    let home = Home::new();
    let c = compiled(&home, Lists::default());
    let host = read(&home, &c, None).unwrap();
    let bwrap = home.dir.path().join("bwrap");
    crate::test_scripts::write_script(
        &bwrap,
        "grep '^SigIgn:' /proc/self/status | cut -f2; printf '%s\\n' \"$@\"",
    );
    let programs = Programs {
        bwrap: &bwrap,
        enclos: Path::new("/usr/bin/enclos"),
    };
    let mut launch = launch(Vec::new());
    launch.in_terminal = in_terminal;
    let out = command(
        &programs,
        Path::new("/c.json"),
        &c,
        &host,
        &ctx(&home),
        &launch,
    )
    .unwrap()
    .output()
    .unwrap();
    let said = String::from_utf8(out.stdout).unwrap();
    let (mask, args) = said.split_once('\n').unwrap();
    (
        u64::from_str_radix(mask.trim(), 16).unwrap(),
        args.to_owned(),
    )
}

/// SIGINT is signal 2 and SIGQUIT 3: bits 1 and 2 of the mask.
#[cfg(target_os = "linux")]
const INT_AND_QUIT: u64 = 0b110;

/// A terminal's Ctrl-C reaches bubblewrap's outer process, in the session's
/// group: it ignores it, and `enclos inside` is told to hand it back.
#[cfg(target_os = "linux")]
#[test]
fn in_a_terminal_bubblewrap_ignores_ctrl_c_and_the_command_gets_it_back() {
    let (ignored, args) = as_bubblewrap_ran(true);
    assert_eq!(ignored & INT_AND_QUIT, INT_AND_QUIT, "{ignored:x}");
    let args: Vec<&str> = args.lines().collect();
    let at = args.iter().position(|a| *a == "inside").unwrap();
    assert_eq!(
        &args[at..at + 5],
        [
            "inside",
            "--compiled",
            "/c.json",
            "--restore-interrupts",
            "--"
        ]
    );
}

/// A service or a probe has no terminal, and runs as it was started.
#[cfg(target_os = "linux")]
#[test]
fn without_a_terminal_nothing_is_ignored_or_handed_back() {
    let (ignored, args) = as_bubblewrap_ran(false);
    assert_eq!(ignored & INT_AND_QUIT, 0, "{ignored:x}");
    assert!(!args.contains("--restore-interrupts"), "{args}");
}
