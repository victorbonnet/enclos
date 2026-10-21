//! Running a program under `sandbox-exec` with the sandbox's environment.
//!
//! The environment starts empty: a user's shell often holds tokens
//! (`GITHUB_TOKEN`, API keys) that a sandboxed agent must not inherit. Only
//! harmless terminal, locale, time zone and user name variables come from
//! the host; `HOME`, `TMPDIR` and caches point into the sandbox home, `PATH`
//! searches the home's `bin` folders before the host's system ones, and every
//! common proxy variable points at the sandbox's proxy (design §5).

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Command;

use super::super::{Launch, SandboxContext};

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

pub fn wrap(compiled: &Path, ctx: &SandboxContext, launch: &Launch) -> Command {
    let mut command = Command::new(SANDBOX_EXEC);
    command
        .arg("-f")
        .arg(compiled)
        .arg(&launch.program)
        .args(&launch.args);
    command.env_clear();
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
    for (name, value) in &launch.env {
        command.env(name, value);
    }
    command.current_dir(&ctx.home);
    command
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
        assert!(env["PATH"].starts_with("/Users/alice/.enclos/sandboxes/home/home/.local/bin:"));
        assert!(env["PATH"].contains(":/usr/bin:/bin"));
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
        };
        let command = wrap(Path::new("/x.sb"), &ctx(), &launch);
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
}
