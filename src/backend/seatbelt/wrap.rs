//! Running a program under `sandbox-exec` with the sandbox's environment.
//!
//! The environment starts empty: a user's shell often holds tokens
//! (`GITHUB_TOKEN`, API keys) that a sandboxed agent must not inherit. Only
//! harmless terminal and locale variables come from the host; `HOME`,
//! `TMPDIR`, caches and `PATH` point into the sandbox home, and every common
//! proxy variable points at the sandbox's proxy (design §5).

use std::path::Path;
use std::process::Command;

use super::super::{Launch, SandboxContext};

pub const SANDBOX_EXEC: &str = "/usr/bin/sandbox-exec";

/// Host variables a sandbox keeps: how to draw and which language to speak.
const PASSED_THROUGH: &[&str] = &[
    "TERM",
    "COLORTERM",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "TZ",
    "USER",
    "LOGNAME",
];

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
    for (name, value) in environment(ctx, launch.proxy_port) {
        command.env(name, value);
    }
    for (name, value) in &launch.env {
        command.env(name, value);
    }
    command.current_dir(&ctx.home);
    command
}

/// The variables every sandboxed program gets.
pub fn environment(ctx: &SandboxContext, proxy_port: u16) -> Vec<(String, String)> {
    let home = ctx.home.display().to_string();
    let proxy = format!("http://127.0.0.1:{proxy_port}");
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
    use std::path::PathBuf;

    fn ctx() -> SandboxContext {
        let data = PathBuf::from("/Users/alice/.enclos");
        SandboxContext {
            name: "home".parse().unwrap(),
            dir: data.join("sandboxes/home"),
            home: data.join("sandboxes/home/home"),
            user_home: "/Users/alice".into(),
            protected: vec![data.clone()],
            sandboxes: data.join("sandboxes"),
            data: data.clone(),
            config_file: data.join("config.toml"),
            proxy_ports: vec![41001],
        }
    }

    #[test]
    fn the_environment_points_into_the_sandbox_and_at_its_proxy() {
        let env: std::collections::HashMap<_, _> = environment(&ctx(), 41001).into_iter().collect();
        assert_eq!(env["HOME"], "/Users/alice/.enclos/sandboxes/home/home");
        assert_eq!(env["https_proxy"], "http://127.0.0.1:41001");
        assert_eq!(env["HTTP_PROXY"], "http://127.0.0.1:41001");
        assert_eq!(env["NODE_USE_ENV_PROXY"], "1");
        assert!(env["PATH"].starts_with("/Users/alice/.enclos/sandboxes/home/home/.local/bin:"));
        assert!(env["PATH"].contains(":/usr/bin:/bin"));
    }

    #[test]
    fn the_host_environment_is_not_inherited() {
        let launch = Launch {
            program: "/bin/sh".into(),
            args: vec![],
            proxy_port: 41001,
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
