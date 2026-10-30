//! The variables a session's programs run with, on every backend.
//!
//! The environment starts empty: a user's shell often holds tokens
//! (`GITHUB_TOKEN`, API keys) that a sandboxed agent must not inherit. Only
//! harmless terminal, locale, time zone and user name variables come from
//! the host; `HOME`, `TMPDIR` and caches point into the sandbox home, `PATH`
//! searches the home's `bin` folders before the host's system ones, and every
//! common proxy variable points at the sandbox's proxy (design §5).

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

use super::SandboxContext;

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

/// The terminal type a sandbox gets when the host's has no description it
/// can find; terminals that bring their own (Ghostty's `xterm-ghostty`)
/// understand it.
const FALLBACK_TERM: &str = "xterm-256color";

/// Where a host system keeps what a session needs from it.
#[derive(Debug, PartialEq, Eq)]
pub struct HostSystem {
    /// The shells a session may get, best first; the last is the one to
    /// name when none is found.
    shells: &'static [&'static str],
    /// What makes the shell ready for a person. A login shell on macOS. Not
    /// on Linux: `/etc/profile` sets `PATH` there on Debian and Ubuntu, which
    /// would drop the sandbox's own `bin` folders.
    shell_args: &'static [&'static str],
    /// Its folders of programs, in `PATH` order.
    folders: &'static [&'static str],
    /// Where ncurses looks for a terminal description when nothing says
    /// otherwise.
    terminfo: &'static [&'static str],
}

const MACOS: HostSystem = HostSystem {
    shells: &["/bin/zsh"],
    shell_args: &["-l"],
    folders: &[
        "/opt/homebrew/bin",
        "/usr/local/bin",
        "/usr/bin",
        "/bin",
        "/usr/sbin",
        "/sbin",
    ],
    terminfo: &["/usr/share/terminfo"],
};

const LINUX: HostSystem = HostSystem {
    shells: &["/bin/bash", "/bin/sh"],
    shell_args: &[],
    folders: &["/usr/local/bin", "/usr/bin", "/bin", "/usr/sbin", "/sbin"],
    terminfo: &["/etc/terminfo", "/lib/terminfo", "/usr/share/terminfo"],
};

impl HostSystem {
    /// The system this process runs on.
    fn current() -> &'static HostSystem {
        match cfg!(target_os = "macos") {
            true => &MACOS,
            false => &LINUX,
        }
    }

    fn shell(&self, present: &dyn Fn(&str) -> bool) -> &'static str {
        self.shells
            .iter()
            .copied()
            .find(|shell| present(shell))
            .or(self.shells.last().copied())
            .unwrap_or_default()
    }
}

fn on_host(path: &str) -> bool {
    Path::new(path).exists()
}

/// The command a session runs when it is given none.
pub fn shell_command() -> Vec<OsString> {
    let system = HostSystem::current();
    std::iter::once(system.shell(&on_host))
        .chain(system.shell_args.iter().copied())
        .map(OsString::from)
        .collect()
}

/// The host's variables a sandbox keeps.
pub fn from_host() -> Vec<(OsString, OsString)> {
    kept_from(HostSystem::current(), std::env::vars_os())
}

/// Of `vars`, those a sandbox keeps, with `TERM` replaced when `system` has
/// no description of it: a later entry wins.
fn kept_from(
    system: &HostSystem,
    vars: impl IntoIterator<Item = (OsString, OsString)>,
) -> Vec<(OsString, OsString)> {
    let mut kept: Vec<_> = vars
        .into_iter()
        .filter(|(name, _)| {
            PASSED_THROUGH.iter().any(|kept| name == kept)
                || name.to_str().is_some_and(|n| n.starts_with("LC_"))
        })
        .collect();
    let value = |wanted: &str| {
        kept.iter()
            .find(|(name, _)| name == wanted)
            .map(|(_, value)| value.as_os_str())
    };
    if let Some(term) = value("TERM")
        && needs_fallback_term(
            term,
            value("TERMINFO").is_some(),
            value("TERMINFO_DIRS"),
            system.terminfo,
        )
    {
        kept.push(("TERM".into(), FALLBACK_TERM.into()));
    }
    kept
}

/// Whether `term` has no description a sandboxed program would find: no
/// `TERMINFO` names one, and neither `TERMINFO_DIRS` nor the system's
/// folders hold it. ncurses files an entry under its first letter, or on
/// macOS under that letter's hex code.
fn needs_fallback_term(
    term: &OsStr,
    terminfo: bool,
    dirs: Option<&OsStr>,
    system: &[&str],
) -> bool {
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
        .chain(system.iter().map(PathBuf::from));
    !folders.any(|dir| {
        dir.join(first.to_string()).join(name).is_file()
            || dir
                .join(format!("{:x}", u32::from(first)))
                .join(name)
                .is_file()
    })
}

/// The variables every sandboxed program gets.
pub fn variables(ctx: &SandboxContext) -> Vec<(String, String)> {
    variables_on(HostSystem::current(), ctx, &on_host)
}

fn variables_on(
    system: &HostSystem,
    ctx: &SandboxContext,
    present: &dyn Fn(&str) -> bool,
) -> Vec<(String, String)> {
    let home = ctx.home.display().to_string();
    let proxy = format!("http://127.0.0.1:{}", ctx.proxy_port);
    let mut path = vec![format!("{home}/.local/bin"), format!("{home}/bin")];
    // Host tools stay usable: reads are broad, and the network goes through the proxy.
    for dir in system.folders.iter().filter(|dir| present(dir)) {
        path.push((*dir).to_owned());
    }
    let mut env = vec![
        ("HOME", home.clone()),
        ("TMPDIR", format!("{home}/tmp/")),
        ("SHELL", system.shell(present).to_owned()),
        ("PATH", path.join(":")),
        ("XDG_CONFIG_HOME", format!("{home}/.config")),
        ("XDG_CACHE_HOME", format!("{home}/.cache")),
        ("XDG_DATA_HOME", format!("{home}/.local/share")),
        ("XDG_STATE_HOME", format!("{home}/.local/state")),
        ("UV_CACHE_DIR", format!("{home}/.cache/uv")),
        ("npm_config_cache", format!("{home}/.npm")),
        ("ENCLOS_SANDBOX", ctx.name.to_string()),
        // No browser opens from a sandbox: print the URL instead of trying
        // each one, on macOS through Apple Events, which the policy refuses
        // noisily.
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
    use std::collections::HashMap;
    use std::process::Command;

    const HOME: &str = "/Users/alice/.enclos/sandboxes/home/home";

    fn ctx() -> SandboxContext {
        let layout = Layout::at(PathBuf::from("/Users/alice/.enclos"));
        SandboxContext::new(&layout, &"home".parse().unwrap(), 41001)
    }

    fn on(system: &HostSystem, present: &dyn Fn(&str) -> bool) -> HashMap<String, String> {
        variables_on(system, &ctx(), present).into_iter().collect()
    }

    fn all_present(_: &str) -> bool {
        true
    }

    fn kept(system: &HostSystem, vars: &[(&str, &str)]) -> HashMap<OsString, OsString> {
        let vars = vars.iter().map(|(k, v)| ((*k).into(), (*v).into()));
        kept_from(system, vars).into_iter().collect()
    }

    #[test]
    fn the_environment_points_into_the_sandbox_and_at_its_proxy() {
        for system in [&MACOS, &LINUX] {
            let env = on(system, &all_present);
            assert_eq!(env["HOME"], HOME);
            assert_eq!(env["TMPDIR"], format!("{HOME}/tmp/"));
            assert_eq!(env["https_proxy"], "http://127.0.0.1:41001");
            assert_eq!(env["HTTP_PROXY"], "http://127.0.0.1:41001");
            assert_eq!(env["NO_PROXY"], "");
            assert_eq!(env["NODE_USE_ENV_PROXY"], "1");
            assert_eq!(env["ENCLOS_SANDBOX"], "home");
        }
    }

    #[test]
    fn a_program_that_would_open_a_browser_prints_the_url_instead() {
        for system in [&MACOS, &LINUX] {
            assert_eq!(on(system, &all_present)["BROWSER"], "/bin/echo");
        }
    }

    #[test]
    fn macos_gives_zsh_and_homebrews_folder() {
        let env = on(&MACOS, &all_present);
        assert_eq!(env["SHELL"], "/bin/zsh");
        assert_eq!(
            env["PATH"],
            format!(
                "{HOME}/.local/bin:{HOME}/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
            )
        );
    }

    #[test]
    fn linux_gives_bash_and_its_own_folders() {
        let env = on(&LINUX, &all_present);
        assert_eq!(env["SHELL"], "/bin/bash");
        assert_eq!(
            env["PATH"],
            format!("{HOME}/.local/bin:{HOME}/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin")
        );
    }

    #[test]
    fn a_host_without_bash_gives_sh() {
        let env = on(&LINUX, &|path| path != "/bin/bash");
        assert_eq!(env["SHELL"], "/bin/sh");
    }

    #[test]
    fn a_folder_the_host_lacks_stays_off_the_path() {
        let env = on(&LINUX, &|path| path != "/usr/local/bin");
        assert_eq!(
            env["PATH"],
            format!("{HOME}/.local/bin:{HOME}/bin:/usr/bin:/bin:/usr/sbin:/sbin")
        );
    }

    /// The shell a session gets keeps the `PATH` it is given, so that a
    /// program in the home's `bin` folders is found: a login shell on Debian
    /// or Ubuntu loses it to `/etc/profile`. It only prints it, in an empty
    /// home.
    #[test]
    fn the_sessions_shell_keeps_the_sandboxs_path() {
        let home = tempfile::tempdir().unwrap();
        let shell = shell_command();
        let out = Command::new(&shell[0])
            .args(&shell[1..])
            .args(["-c", "printf %s \"$PATH\""])
            .env_clear()
            .env("HOME", home.path())
            .env("PATH", "/nonexistent/sandbox/bin:/usr/bin:/bin")
            .output()
            .unwrap();
        assert!(out.status.success(), "{out:?}");
        let path = String::from_utf8_lossy(&out.stdout);
        assert!(path.contains("/nonexistent/sandbox/bin"), "{path}");
    }

    #[test]
    fn only_harmless_host_variables_are_kept() {
        let vars = [
            ("LANG", "fr_FR.UTF-8"),
            ("LC_CTYPE", "UTF-8"),
            ("TZ", "Europe/Paris"),
            ("USER", "alice"),
            ("GITHUB_TOKEN", "t"),
            ("SSH_AUTH_SOCK", "/tmp/agent"),
            ("HOME", "/Users/alice"),
            ("SHELL", "/bin/fish"),
        ];
        let kept = kept(&LINUX, &vars);
        let mut names: Vec<_> = kept.keys().map(|n| n.to_str().unwrap()).collect();
        names.sort_unstable();
        assert_eq!(names, ["LANG", "LC_CTYPE", "TZ", "USER"]);
    }

    #[test]
    fn a_term_without_description_is_replaced_in_what_is_kept() {
        let kept = kept(&LINUX, &[("TERM", "enclos-no-such-terminal")]);
        assert_eq!(kept[OsStr::new("TERM")], "xterm-256color");
    }

    #[test]
    fn no_secret_is_given_as_a_variable_enclos_sets_or_passes_on() {
        let set = variables(&ctx()).into_iter().map(|(name, _)| name);
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
        let needs = |term, terminfo, dirs| needs_fallback_term(term, terminfo, dirs, &[]);
        // Ghostty sets TERMINFO to its own folder: keep its TERM.
        assert!(!needs(ghostty, true, None));
        // Without it, nothing describes xterm-ghostty.
        assert!(needs(ghostty, false, None));
        // TERMINFO_DIRS may describe it, under a hex or a letter folder.
        let dirs = dir.path().as_os_str();
        assert!(!needs(ghostty, false, Some(dirs)));
        assert!(!needs(OsStr::new("kitty"), false, Some(dirs)));
        assert!(!needs(OsStr::new(""), false, None));
    }

    /// Debian's `ncurses-base` files the common terminals in `/lib/terminfo`,
    /// and anything else in `/usr/share/terminfo`.
    #[test]
    fn each_system_names_where_its_ncurses_looks() {
        assert_eq!(MACOS.terminfo, ["/usr/share/terminfo"]);
        assert_eq!(
            LINUX.terminfo,
            ["/etc/terminfo", "/lib/terminfo", "/usr/share/terminfo"]
        );
    }

    #[test]
    fn a_system_folder_describes_a_terminal() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("k")).unwrap();
        std::fs::write(dir.path().join("k/kitty"), b"").unwrap();
        let folder = dir.path().to_str().unwrap();
        let system = ["/nonexistent", folder];
        assert!(!needs_fallback_term(
            OsStr::new("kitty"),
            false,
            None,
            &system
        ));
    }

    /// On the host itself, where every system has the usual terminal.
    #[cfg(target_os = "macos")]
    #[test]
    fn the_system_describes_xterm_256color() {
        assert!(!needs_fallback_term(
            OsStr::new("xterm-256color"),
            false,
            None,
            MACOS.terminfo
        ));
    }
}
