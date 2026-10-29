//! Running a program under `sandbox-exec` with the sandbox's environment.
//!
//! The environment starts empty: a user's shell often holds tokens
//! (`GITHUB_TOKEN`, API keys) that a sandboxed agent must not inherit. Only
//! harmless terminal, locale, time zone and user name variables come from
//! the host; `HOME`, `TMPDIR` and caches point into the sandbox home, `PATH`
//! searches the home's `bin` folders before the host's system ones, and every
//! common proxy variable points at the sandbox's proxy (design §5).

use std::ffi::{OsStr, OsString};
use std::os::fd::{AsFd, BorrowedFd};
use std::os::unix::ffi::OsStringExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use super::super::{Launch, Probe, SandboxContext};
use super::compile::{Baseline, SERVICE_PARAM, TERMINAL_PARAM};

pub const SANDBOX_EXEC: &str = "/usr/bin/sandbox-exec";

/// Host variables a sandbox keeps: how to draw, which language to speak,
/// the time zone and the user's name.
/// Every `LC_*` variable is kept too.
const PASSED_THROUGH: &[&str] = &[
    "TERM",
    "TERMINFO",
    "TERMINFO_DIRS",
    "COLORTERM",
    "LANG",
    "TZ",
    "USER",
    "LOGNAME",
];

/// Where ncurses looks for a terminal description when nothing says otherwise.
const SYSTEM_TERMINFO: &str = "/usr/share/terminfo";

/// The terminal type a sandbox gets when the host's has no description it
/// can find; terminals that bring their own (Ghostty's `xterm-ghostty`)
/// understand it.
const FALLBACK_TERM: &str = "xterm-256color";

/// Whether `sandbox-exec` runs `/usr/bin/true` under `baseline` alone, as
/// every session's compiled policy starts, with no variable of the user's,
/// within [`TRY_RUN_WAIT`]: on `(deny default)`, a macOS that rejects one of
/// its allowances, or needs one it lacks to start a program, is found here,
/// not at a session's start. Inside a sandbox whose policy denies a write,
/// as every enclos sandbox's does, macOS 26.5.2 refuses to apply this
/// policy, `sandbox_apply: Operation not permitted` (exit 71): a test runs
/// doctor so, on either baseline. Inside one whose policy only allows
/// everything, `(version 1)(allow default)` ran, exit 0 (by hand, macOS
/// 26.5.2); this policy on `(deny default)` there is not shown.
pub fn try_run(baseline: Baseline) -> Probe {
    let policy = format!("(version 1)\n{}", baseline.text("enclos:doctor"));
    let named = match baseline {
        Baseline::DenyDefault => "(deny default)",
        Baseline::AllowDefault => "(allow default)",
    };
    let started = Command::new(SANDBOX_EXEC)
        .args(["-p", &policy, "/usr/bin/true"])
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn();
    let mut child = match started {
        Ok(child) => child,
        Err(e) => {
            return Probe::Unavailable {
                reason: format!("cannot run {SANDBOX_EXEC}: {e}"),
            };
        }
    };
    // Read as it is written, so that a full pipe never holds it up.
    let stderr = child.stderr.take();
    let reader = std::thread::spawn(move || {
        let mut said = String::new();
        let read = stderr.map(|mut s| std::io::Read::read_to_string(&mut s, &mut said));
        (said, read)
    });
    let deadline = std::time::Instant::now() + TRY_RUN_WAIT;
    let status = loop {
        let failed = match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(20));
                continue;
            }
            Ok(None) => format!(
                "{SANDBOX_EXEC} did not finish /usr/bin/true within {} s",
                TRY_RUN_WAIT.as_secs()
            ),
            Err(e) => format!("cannot wait for {SANDBOX_EXEC}: {e}"),
        };
        // Its own child: stopped and reaped.
        let _ = child.kill();
        let _ = child.wait();
        return Probe::Unavailable { reason: failed };
    };
    if status.success() {
        return Probe::Available;
    }
    let (said, read) = reader.join().unwrap_or_else(|_| {
        (
            String::new(),
            Some(Err(std::io::Error::other("its reader failed"))),
        )
    });
    let mut said = said.trim().to_owned();
    if let Some(Err(e)) = read {
        said = format!("{said} (its stderr could not be read: {e})")
            .trim()
            .to_owned();
    }
    Probe::Unavailable {
        reason: match said.is_empty() {
            true => format!(
                "{SANDBOX_EXEC} could not run /usr/bin/true under the {named} baseline alone ({status})"
            ),
            false => format!(
                "{SANDBOX_EXEC} could not run /usr/bin/true under the {named} baseline alone ({status}): {said}"
            ),
        },
    }
}

/// How long [`try_run`] waits for `/usr/bin/true`, which takes milliseconds.
const TRY_RUN_WAIT: std::time::Duration = std::time::Duration::from_secs(10);

pub fn wrap(compiled: &Path, ctx: &SandboxContext, launch: &Launch) -> Command {
    let terminal = match launch.in_terminal {
        true => own_terminal(),
        false => None,
    };
    wrap_in(compiled, ctx, launch, terminal.as_deref())
}

/// [`wrap`], for a program in `terminal`, which the compiled policy then
/// lets the sandbox open by name. Without one, no terminal device opens by
/// name but those the sandbox opens itself.
pub(super) fn wrap_in(
    compiled: &Path,
    ctx: &SandboxContext,
    launch: &Launch,
    terminal: Option<&Path>,
) -> Command {
    let mut command = Command::new(SANDBOX_EXEC);
    if let Some(terminal) = terminal {
        let mut param = OsString::from(format!("{TERMINAL_PARAM}="));
        param.push(terminal);
        command.arg("-D").arg(param);
    }
    // A parameter, not a rule of its own, so every session of the sandbox
    // runs under the same compiled policy.
    if let Some(port) = launch.service_port {
        command
            .arg("-D")
            .arg(format!("{SERVICE_PARAM}=localhost:{port}"));
    }
    command
        .arg("-f")
        .arg(compiled)
        .arg(&launch.program)
        .args(&launch.args);
    let mut command = super::super::under_limits(command, &launch.limits);
    command.env_clear();
    // The secrets the policy grants first: what enclos sets or passes on
    // comes after them and so is never one of theirs, whatever the
    // validation of the policy let through.
    for (name, value) in &launch.env {
        command.env(name, value.expose());
    }
    for name in PASSED_THROUGH {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    for (name, value) in std::env::vars_os() {
        if name.to_str().is_some_and(|n| n.starts_with("LC_")) {
            command.env(name, value);
        }
    }
    if let Some(term) = std::env::var_os("TERM")
        && needs_fallback_term(
            &term,
            std::env::var_os("TERMINFO").is_some(),
            std::env::var_os("TERMINFO_DIRS").as_deref(),
        )
    {
        command.env("TERM", FALLBACK_TERM);
    }
    for (name, value) in environment(ctx) {
        command.env(name, value);
    }
    command.current_dir(&ctx.home);
    command
}

/// The terminal this process runs in, from its stdin, stdout and stderr.
fn own_terminal() -> Option<PathBuf> {
    let (stdin, stdout, stderr) = (std::io::stdin(), std::io::stdout(), std::io::stderr());
    terminal_of([stdin.as_fd(), stdout.as_fd(), stderr.as_fd()])
}

/// The terminal device of the first of `fds` that is one. A session's
/// program inherits these streams, so naming their terminal opens nothing
/// it does not already hold, and a program that reopens its terminal by
/// name (`tty`, `ttyname`) finds this one.
fn terminal_of(fds: [BorrowedFd<'_>; 3]) -> Option<PathBuf> {
    fds.into_iter()
        .filter(|fd| rustix::termios::isatty(fd))
        .filter_map(|fd| rustix::termios::ttyname(fd, Vec::new()).ok())
        .map(|name| PathBuf::from(OsString::from_vec(name.into_bytes())))
        .find(|path| is_terminal_device(path))
}

/// Whether `path` names a terminal device, `/dev/ttys` and digits: the only
/// ones the compiled policy can open by name (`compile::TERMINALS`, which
/// checks the name again).
fn is_terminal_device(path: &Path) -> bool {
    path.to_str()
        .and_then(|p| p.strip_prefix("/dev/ttys"))
        .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
}

/// Whether `term` has no description a sandboxed program would find: no
/// `TERMINFO` names one, and neither `TERMINFO_DIRS` nor the system's
/// folder holds it. ncurses files an entry under its first letter, or on
/// macOS under that letter's hex code.
fn needs_fallback_term(term: &OsStr, terminfo: bool, dirs: Option<&OsStr>) -> bool {
    let Some(name) = term.to_str().filter(|n| !n.is_empty()) else {
        return false;
    };
    if terminfo {
        return false;
    }
    let first = name.chars().next().unwrap_or_default();
    let mut folders = dirs
        .into_iter()
        .flat_map(std::env::split_paths)
        .filter(|d| !d.as_os_str().is_empty())
        .chain([PathBuf::from(SYSTEM_TERMINFO)]);
    !folders.any(|dir| {
        dir.join(first.to_string()).join(name).is_file()
            || dir
                .join(format!("{:x}", u32::from(first)))
                .join(name)
                .is_file()
    })
}

/// The variables every sandboxed program gets.
pub fn environment(ctx: &SandboxContext) -> Vec<(String, String)> {
    let home = ctx.home.display().to_string();
    let proxy = format!("http://127.0.0.1:{}", ctx.proxy_port);
    let mut path = vec![format!("{home}/.local/bin"), format!("{home}/bin")];
    // Host tools stay usable: reads are broad, and the network goes through the proxy.
    for dir in [
        "/opt/homebrew/bin",
        "/usr/local/bin",
        "/usr/bin",
        "/bin",
        "/usr/sbin",
        "/sbin",
    ] {
        if Path::new(dir).is_dir() {
            path.push(dir.to_owned());
        }
    }
    let mut env = vec![
        ("HOME", home.clone()),
        ("TMPDIR", format!("{home}/tmp/")),
        ("SHELL", "/bin/zsh".to_owned()),
        ("PATH", path.join(":")),
        ("XDG_CONFIG_HOME", format!("{home}/.config")),
        ("XDG_CACHE_HOME", format!("{home}/.cache")),
        ("XDG_DATA_HOME", format!("{home}/.local/share")),
        ("XDG_STATE_HOME", format!("{home}/.local/state")),
        ("UV_CACHE_DIR", format!("{home}/.cache/uv")),
        ("npm_config_cache", format!("{home}/.npm")),
        ("ENCLOS_SANDBOX", ctx.name.to_string()),
        // No browser opens from a sandbox: a program that would open one
        // (Python's `webbrowser`, gh) runs this instead, which prints
        // the URL and succeeds, rather than trying one browser after
        // another through Apple Events, which the policy refuses, each
        // refusal printing macOS's own errors.
        ("BROWSER", "/bin/echo".to_owned()),
    ];
    // curl reads only the lowercase forms; Node's fetch needs NODE_USE_ENV_PROXY.
    for name in [
        "HTTPS_PROXY",
        "HTTP_PROXY",
        "ALL_PROXY",
        "https_proxy",
        "http_proxy",
        "all_proxy",
    ] {
        env.push((name, proxy.clone()));
    }
    env.push(("NO_PROXY", String::new()));
    env.push(("no_proxy", String::new()));
    env.push(("NODE_USE_ENV_PROXY", "1".to_owned()));
    env.into_iter().map(|(k, v)| (k.to_owned(), v)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layout::Layout;
    use std::path::PathBuf;

    fn ctx() -> SandboxContext {
        let layout = Layout::at(PathBuf::from("/Users/alice/.enclos"));
        SandboxContext::new(&layout, &"home".parse().unwrap(), 41001)
    }

    #[test]
    fn the_environment_points_into_the_sandbox_and_at_its_proxy() {
        let env: std::collections::HashMap<_, _> = environment(&ctx()).into_iter().collect();
        assert_eq!(env["HOME"], "/Users/alice/.enclos/sandboxes/home/home");
        assert_eq!(env["https_proxy"], "http://127.0.0.1:41001");
        assert_eq!(env["HTTP_PROXY"], "http://127.0.0.1:41001");
        assert_eq!(env["NODE_USE_ENV_PROXY"], "1");
        assert_eq!(env["BROWSER"], "/bin/echo");
        assert!(env["PATH"].starts_with("/Users/alice/.enclos/sandboxes/home/home/.local/bin:"));
        assert!(env["PATH"].contains(":/usr/bin:/bin"));
    }

    /// Set before what enclos sets, a secret never replaces one of its
    /// variables, whatever the validation of a policy let through.
    #[test]
    fn a_secret_never_replaces_a_variable_enclos_sets() {
        let value = |v: &str| crate::model::secret::SecretValue::new(v.to_owned()).unwrap();
        let launch = Launch {
            program: "/bin/true".into(),
            args: Vec::new(),
            env: vec![
                ("HOME".to_owned(), value("/elsewhere")),
                ("TOKEN".to_owned(), value("t")),
            ],
            in_terminal: false,
            service_port: None,
            limits: Default::default(),
        };
        let command = wrap_in(Path::new("/c.sb"), &ctx(), &launch, None);
        let env: std::collections::HashMap<_, _> = command
            .get_envs()
            .filter_map(|(k, v)| Some((k.to_str()?.to_owned(), v?.to_str()?.to_owned())))
            .collect();
        assert_eq!(env["HOME"], "/Users/alice/.enclos/sandboxes/home/home");
        assert_eq!(env["TOKEN"], "t");
    }

    #[test]
    fn no_secret_is_given_as_a_variable_enclos_sets_or_passes_on() {
        let set = environment(&ctx()).into_iter().map(|(name, _)| name);
        for name in set.chain(PASSED_THROUGH.iter().map(|n| (*n).to_owned())) {
            assert!(
                crate::model::secret::reserved_variable(&name),
                "{name} is not reserved"
            );
        }
        assert!(crate::model::secret::reserved_variable("LC_CTYPE"));
    }

    #[test]
    fn an_undescribed_terminal_falls_back_to_xterm_256color() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("78")).unwrap();
        std::fs::write(dir.path().join("78/xterm-ghostty"), b"").unwrap();
        std::fs::create_dir_all(dir.path().join("k")).unwrap();
        std::fs::write(dir.path().join("k/kitty"), b"").unwrap();
        let ghostty = OsStr::new("xterm-ghostty");
        // Ghostty sets TERMINFO to its own folder: keep its TERM.
        assert!(!needs_fallback_term(ghostty, true, None));
        // Without it, nothing describes xterm-ghostty.
        assert!(needs_fallback_term(ghostty, false, None));
        // TERMINFO_DIRS may describe it, under a hex or a letter folder.
        let dirs = dir.path().as_os_str();
        assert!(!needs_fallback_term(ghostty, false, Some(dirs)));
        assert!(!needs_fallback_term(OsStr::new("kitty"), false, Some(dirs)));
        assert!(!needs_fallback_term(OsStr::new(""), false, None));
        #[cfg(target_os = "macos")]
        assert!(!needs_fallback_term(
            OsStr::new("xterm-256color"),
            false,
            None
        ));
    }

    #[test]
    fn the_host_environment_is_not_inherited() {
        let launch = Launch {
            program: "/bin/sh".into(),
            args: vec![],
            env: vec![],
            in_terminal: false,
            service_port: None,
            limits: Default::default(),
        };
        let command = wrap_in(Path::new("/x.sb"), &ctx(), &launch, None);
        let names: Vec<_> = command
            .get_envs()
            .map(|(k, _)| k.to_string_lossy().into_owned())
            .collect();
        assert!(
            !names
                .iter()
                .any(|n| n == "GITHUB_TOKEN" || n == "OPENAI_API_KEY" || n == "SSH_AUTH_SOCK"),
            "{names:?}"
        );
        let args: Vec<_> = command
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(args, ["-f", "/x.sb", "/bin/sh"]);
    }

    #[test]
    fn a_session_names_its_runtime_service_port_to_the_policy() {
        let mut launch = Launch {
            program: "/bin/sh".into(),
            args: vec![],
            env: vec![],
            in_terminal: false,
            service_port: Some(61374),
            limits: Default::default(),
        };
        let args = |launch: &Launch| -> Vec<String> {
            wrap_in(Path::new("/x.sb"), &ctx(), launch, None)
                .get_args()
                .map(|a| a.to_string_lossy().into_owned())
                .collect()
        };
        assert_eq!(
            args(&launch),
            [
                "-D",
                "ENCLOS_SERVICE=localhost:61374",
                "-f",
                "/x.sb",
                "/bin/sh"
            ]
        );
        launch.service_port = None;
        assert_eq!(args(&launch), ["-f", "/x.sb", "/bin/sh"]);
    }

    #[test]
    fn a_session_names_its_own_terminal_to_the_policy() {
        let launch = Launch {
            program: "/bin/sh".into(),
            args: vec![],
            env: vec![],
            in_terminal: false,
            service_port: None,
            limits: Default::default(),
        };
        let terminal = Path::new("/dev/ttys004");
        let command = wrap_in(Path::new("/x.sb"), &ctx(), &launch, Some(terminal));
        let args: Vec<_> = command
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            args,
            [
                "-D",
                "ENCLOS_TERMINAL=/dev/ttys004",
                "-f",
                "/x.sb",
                "/bin/sh"
            ]
        );
    }

    /// The device of a pseudo-terminal the test opened, as a stream a
    /// program might inherit; never the test's own terminal.
    #[cfg(target_os = "macos")]
    fn device(terminal: &Path) -> std::os::fd::OwnedFd {
        use rustix::fs::{Mode, OFlags, open};
        open(terminal, OFlags::RDWR | OFlags::NOCTTY, Mode::empty()).unwrap()
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn the_terminal_named_is_the_first_standard_stream_that_is_one() {
        use super::super::tests::terminal;
        let null = std::fs::File::open("/dev/null").unwrap();
        let (_first, first) = terminal();
        let (_second, second) = terminal();
        let (in_first, in_second) = (device(&first), device(&second));
        let (null, a, b) = (null.as_fd(), in_first.as_fd(), in_second.as_fd());
        assert_eq!(terminal_of([null, null, null]), None);
        assert_eq!(terminal_of([null, a, null]), Some(first.clone()));
        assert_eq!(terminal_of([null, null, b]), Some(second.clone()));
        assert_eq!(terminal_of([a, b, null]), Some(first));
        assert_eq!(terminal_of([b, a, a]), Some(second));
    }

    #[test]
    fn a_launch_outside_a_terminal_names_none_to_the_policy() {
        // Whatever terminal this test runs in, as `enclos launch` run by
        // hand would be.
        let launch = Launch {
            program: "/bin/sh".into(),
            args: vec![],
            env: vec![],
            in_terminal: false,
            service_port: None,
            limits: Default::default(),
        };
        let command = wrap(Path::new("/x.sb"), &ctx(), &launch);
        let args: Vec<_> = command
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(args, ["-f", "/x.sb", "/bin/sh"]);
    }

    #[test]
    fn only_terminal_devices_are_named_to_the_policy() {
        assert!(is_terminal_device(Path::new("/dev/ttys004")));
        for other in [
            "/dev/ttys",
            "/dev/ttys00a",
            "/dev/ttys004/../null",
            "/dev/console",
            "/dev/tty",
            "/Users/alice/ttys004",
        ] {
            assert!(!is_terminal_device(Path::new(other)), "{other}");
        }
    }
}
