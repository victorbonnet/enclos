//! The command `wrap` builds: what bubblewrap runs, the environment, and Ctrl-C.

use super::*;

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
