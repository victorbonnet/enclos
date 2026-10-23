//! Backends: the isolation technologies sandboxes are built on (design §5).
//!
//! The trait holds what the commands built so far need; it grows toward the
//! full shape in design §9 (prepare, members, denials, ...) as the commands
//! that use it arrive.

#[cfg(test)]
pub mod fake;
pub mod seatbelt;

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::layout::Layout;
use crate::model::policy::Policy;
use crate::model::sandbox::{BackendKind, SandboxName};

/// Whether a backend can run on this host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Probe {
    Available,
    Unavailable { reason: String },
}

/// How well a backend enforces one area of the policy (ADR 0008).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Enforcement {
    Enforced,
    Partial { note: String },
    Unsupported,
}

/// What a backend enforces, per policy area.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capabilities {
    pub fs: Enforcement,
    pub network: Enforcement,
    pub exec: Enforcement,
    pub resources: Enforcement,
    /// Finding every process of a sandbox (ADR 0019).
    pub members: Enforcement,
}

/// Everything about a sandbox that compiling and wrapping need, with every
/// path already absolute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxContext {
    pub name: SandboxName,
    /// The sandbox's folder: its policy, compiled policies and home.
    pub dir: PathBuf,
    pub home: PathBuf,
    /// The user's own home, which `~` in policies means.
    pub user_home: PathBuf,
    /// The enclos data and config folders (ADR 0010).
    pub protected: Vec<PathBuf>,
    /// The folder holding every sandbox's folder.
    pub sandboxes: PathBuf,
    /// Files the sandbox may not read, each with every file whose name
    /// starts with it.
    pub hidden_files: Vec<PathBuf>,
    /// Folders the sandbox may not read.
    pub hidden_dirs: Vec<PathBuf>,
    /// The sandbox's proxy port, on 127.0.0.1 and [::1]: its only way out.
    pub proxy_port: u16,
}

impl SandboxContext {
    /// The sandbox `name` in `layout`, the one source of its paths.
    pub fn new(layout: &Layout, name: &SandboxName, proxy_port: u16) -> SandboxContext {
        SandboxContext {
            name: name.clone(),
            dir: layout.sandbox_dir(name.as_str()),
            home: layout.sandbox_home(name.as_str()),
            user_home: layout.user_home().to_owned(),
            protected: layout.protected(),
            sandboxes: layout.sandboxes_dir(),
            hidden_files: layout.hidden_files(),
            hidden_dirs: layout.hidden_dirs(),
            proxy_port,
        }
    }
}

/// A policy compiled for one backend, as the backend reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Compiled {
    pub text: String,
    /// The file extension it is stored under, such as `sb`.
    pub extension: &'static str,
}

/// A program to run inside a sandbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Launch {
    pub program: OsString,
    pub args: Vec<OsString>,
    /// The secrets its policy grants, by variable, set before the
    /// sandbox's own environment, which they never replace.
    pub env: Vec<(String, crate::model::secret::SecretValue)>,
    /// Whether the program runs in the terminal enclos runs in, as a
    /// session does: the backend then lets it open that terminal by name. A
    /// service or a probe never does, whatever terminal enclos runs in.
    pub in_terminal: bool,
    /// The port at 127.0.0.1 where the sandbox's own runtime service listens,
    /// which the program may then connect to besides the proxy (ADR 0028).
    /// Set for the sessions `run_in_sandbox` starts while the service
    /// listens; none for the service itself, a probe, a sandbox whose
    /// runtime has no such service, or one whose service does not listen.
    pub service_port: Option<u16>,
    /// The limits each of its processes runs under (design §7): those its
    /// policy sets, which the validation let through for this backend.
    pub limits: crate::model::policy::Resources,
}

/// `command` run under `limits`, which every process it starts inherits:
/// `/bin/bash` sets them with `ulimit`, hard and soft alike, so nothing in
/// the sandbox can raise them, then becomes the program; one it cannot set
/// stops the chain, so no program runs without its limits. Bash, not
/// `/bin/sh`, which macOS lets an administrator point at dash, whose
/// `ulimit -f` counts in another unit; in privileged mode (`-p`), as it
/// runs on the host with the sandbox's variables: it then reads no
/// `BASH_ENV` or `ENV` file, no `SHELLOPTS` and no function from them. As it
/// is when no limit is set.
pub fn under_limits(command: Command, limits: &crate::model::policy::Resources) -> Command {
    let mut set = Vec::new();
    if let Some(files) = limits.open_files {
        set.push(format!("ulimit -n {files}"));
    }
    // In KiB, the unit of bash's `ulimit -f` (shown on macOS 26.5.2): the
    // validation takes only whole KiB.
    if let Some(size) = limits.file_size {
        set.push(format!("ulimit -f {}", size.0 / 1024));
    }
    if let Some(seconds) = limits.cpu_seconds {
        set.push(format!("ulimit -t {seconds}"));
    }
    if set.is_empty() {
        return command;
    }
    set.push("exec \"$0\" \"$@\"".to_owned());
    let mut limited = Command::new("/bin/bash");
    limited
        .arg("-p")
        .arg("-c")
        .arg(set.join(" && "))
        .arg(command.get_program())
        .args(command.get_args());
    limited
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CompileError {
    #[error("cannot compile the policy for {backend}: {reason}")]
    Unsupported {
        backend: BackendKind,
        reason: String,
    },
}

/// One isolation technology. Prepares, wraps and finds members; never
/// supervises.
pub trait Backend {
    fn kind(&self) -> BackendKind;
    /// Checks, without side effects, whether this backend works on this host.
    fn probe(&self) -> Probe;
    /// Whether a program runs in the backend, asked once `probe` passed: a
    /// host can have it and still refuse it. Starts a process; only `enclos
    /// doctor` calls it.
    fn try_run(&self) -> Probe;
    fn capabilities(&self) -> Capabilities;
    /// Turns a policy into what the backend enforces. Pure.
    fn compile(&self, policy: &Policy, ctx: &SandboxContext) -> Result<Compiled, CompileError>;
    /// The command that runs `launch` inside the sandbox under `compiled`.
    fn wrap(&self, compiled: &Path, ctx: &SandboxContext, launch: &Launch) -> Command;
}

/// Every backend this build of enclos ships, in order of preference.
///
/// This is the one explicit list of implementations.
pub fn registered() -> Vec<Box<dyn Backend>> {
    vec![Box::new(seatbelt::Seatbelt)]
}

#[cfg(test)]
mod limits_tests {
    use super::*;

    #[test]
    fn limits_are_set_by_the_shell_that_becomes_the_program() {
        let plain = Command::new("/usr/bin/true");
        let none = under_limits(plain, &crate::model::policy::Resources::default());
        assert_eq!(none.get_program(), "/usr/bin/true");
        let mut program = Command::new("/usr/bin/sandbox-exec");
        program.args(["-f", "x.sb", "/bin/zsh"]);
        let limits = crate::model::policy::Resources {
            open_files: Some(256),
            file_size: Some("1M".parse().unwrap()),
            cpu_seconds: Some(60),
            ..Default::default()
        };
        let limited = under_limits(program, &limits);
        assert_eq!(limited.get_program(), "/bin/bash");
        let args: Vec<_> = limited.get_args().map(|a| a.to_str().unwrap()).collect();
        assert_eq!(
            args,
            [
                "-p",
                "-c",
                "ulimit -n 256 && ulimit -f 1024 && ulimit -t 60 && exec \"$0\" \"$@\"",
                "/usr/bin/sandbox-exec",
                "-f",
                "x.sb",
                "/bin/zsh"
            ]
        );
    }

    /// macOS refuses a file size past what it can hold; Linux takes any
    /// value, so the case does not arise there.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_limit_that_cannot_be_set_runs_no_program() {
        let mut echo = Command::new("/bin/echo");
        echo.arg("ran");
        let limits = crate::model::policy::Resources {
            file_size: Some(crate::model::policy::ByteSize(u64::MAX)),
            ..Default::default()
        };
        let out = under_limits(echo, &limits).output().unwrap();
        assert!(!out.status.success());
        assert!(!String::from_utf8_lossy(&out.stdout).contains("ran"));
    }

    #[test]
    fn the_shell_reads_no_startup_file_or_option_from_the_environment() {
        let dir = tempfile::tempdir().unwrap();
        let startup = dir.path().join("startup.sh");
        let touched = dir.path().join("touched");
        std::fs::write(&startup, format!("touch {}\n", touched.display())).unwrap();
        let mut echo = Command::new("/bin/echo");
        echo.arg("ran");
        let limits = crate::model::policy::Resources {
            open_files: Some(256),
            ..Default::default()
        };
        let mut limited = under_limits(echo, &limits);
        limited
            .env_clear()
            .env("BASH_ENV", &startup)
            .env("ENV", &startup)
            .env("SHELLOPTS", "xtrace");
        let out = limited.output().unwrap();
        assert!(out.status.success(), "{out:?}");
        assert_eq!(String::from_utf8_lossy(&out.stdout), "ran\n");
        assert!(!touched.exists(), "the shell ran a startup file");
        assert!(
            out.stderr.is_empty(),
            "xtrace: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    /// Each probe's script, run under the limit it checks, is closed (it
    /// fails); under one higher, open.
    #[test]
    fn a_probe_is_closed_under_its_limit_and_open_above_it() {
        let probe = |flag: &str, limit: u64, under: crate::model::policy::Resources| {
            let mut sh = Command::new("/bin/sh");
            sh.arg("-c").arg(format!(
                "test \"$(ulimit {flag})\" = unlimited || test \"$(ulimit {flag})\" -gt {limit}"
            ));
            under_limits(sh, &under).status().unwrap().success()
        };
        let files = |n| crate::model::policy::Resources {
            open_files: Some(n),
            ..Default::default()
        };
        assert!(!probe("-Hn", 64, files(64)), "closed at the limit");
        assert!(probe("-Hn", 63, files(64)), "open above it");
        let cpu = |n| crate::model::policy::Resources {
            cpu_seconds: Some(n),
            ..Default::default()
        };
        assert!(!probe("-Ht", 600, cpu(600)));
        assert!(probe("-Ht", 599, cpu(600)));
    }
}
