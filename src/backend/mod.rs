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
/// `/bin/bash` sets them with `ulimit`, hard and soft alike, so no process
/// in the sandbox without root can raise them, then becomes the program;
/// one it cannot set stops it with exit 125 and the field named, so no
/// program runs without its limits. Only the limits a backend enforces as
/// written are set: `open_files` (ADR 0033 refuses the others). In
/// privileged mode (`-p`), as it runs on the host with the sandbox's
/// variables: it then reads no `BASH_ENV` or `ENV` file, no `SHELLOPTS` and
/// no function from them. Only `command`'s program and arguments are kept:
/// set its environment and folder on the result. Returns `command`
/// unchanged when no limit is set.
pub fn under_limits(command: Command, limits: &crate::model::policy::Resources) -> Command {
    debug_assert!(
        command.get_envs().next().is_none() && command.get_current_dir().is_none(),
        "set the environment and folder after the limits"
    );
    // Every field named, so one added is decided on here.
    let crate::model::policy::Resources {
        open_files,
        file_size: _,
        cpu_seconds: _,
        memory: _,
        cpu: _,
    } = limits;
    let mut set = Vec::new();
    if let Some(files) = open_files {
        set.push(format!(
            "ulimit -n {files} || {{ echo \"enclos: cannot set resources.open_files = {files}\" >&2; exit 125; }}"
        ));
    }
    if set.is_empty() {
        return command;
    }
    set.push("exec \"$0\" \"$@\"".to_owned());
    let mut limited = Command::new("/bin/bash");
    limited
        .arg("-p")
        .arg("-c")
        .arg(set.join("; "))
        .arg(command.get_program())
        .args(command.get_args());
    limited
}

/// Why `limits` cannot be set where enclos runs, if they cannot: a limit
/// above the hard one enclos itself runs under, which no process without
/// root can raise, would stop every program with it.
pub fn unsettable(limits: &crate::model::policy::Resources) -> Option<String> {
    let files = limits.open_files?;
    let hard = rustix::process::getrlimit(rustix::process::Resource::Nofile).maximum;
    match hard {
        Some(hard) if files > hard => Some(format!(
            "resources.open_files = {files} is above the hard limit enclos runs under ({hard}): lower it in the policy, or raise the hard limit of the shell or service manager enclos runs from"
        )),
        _ => None,
    }
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

    fn files(n: u64) -> crate::model::policy::Resources {
        crate::model::policy::Resources {
            open_files: Some(n),
            ..Default::default()
        }
    }

    #[test]
    fn limits_are_set_by_the_shell_that_becomes_the_program() {
        let plain = Command::new("/usr/bin/true");
        let none = under_limits(plain, &crate::model::policy::Resources::default());
        assert_eq!(none.get_program(), "/usr/bin/true");
        let mut program = Command::new("/usr/bin/sandbox-exec");
        program.args(["-f", "x.sb", "/bin/zsh"]);
        // Only what a backend enforces is set; the others are refused
        // before a policy is stored.
        let limits = crate::model::policy::Resources {
            file_size: Some("1M".parse().unwrap()),
            cpu_seconds: Some(60),
            ..files(256)
        };
        let limited = under_limits(program, &limits);
        assert_eq!(limited.get_program(), "/bin/bash");
        let args: Vec<_> = limited.get_args().map(|a| a.to_str().unwrap()).collect();
        assert_eq!(
            args,
            [
                "-p",
                "-c",
                "ulimit -n 256 || { echo \"enclos: cannot set resources.open_files = 256\" >&2; exit 125; }; exec \"$0\" \"$@\"",
                "/usr/bin/sandbox-exec",
                "-f",
                "x.sb",
                "/bin/zsh"
            ]
        );
    }

    /// A limit above the hard one the shell runs under cannot be set: no
    /// program runs, and the field is named, with exit 125.
    #[test]
    fn a_limit_that_cannot_be_set_runs_no_program() {
        let mut echo = Command::new("/bin/echo");
        echo.arg("ran");
        let limited = under_limits(echo, &files(200));
        let out = Command::new("/bin/bash")
            .arg("-c")
            .arg("ulimit -n 100 && exec \"$0\" \"$@\"")
            .arg(limited.get_program())
            .args(limited.get_args())
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(125), "{out:?}");
        assert!(!String::from_utf8_lossy(&out.stdout).contains("ran"));
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("cannot set resources.open_files = 200"),
            "{out:?}"
        );
    }

    /// The shell reads nothing from the sandbox's variables: no startup
    /// file, no option, and no function, such as one named `ulimit` that
    /// would set no limit.
    #[test]
    fn the_shell_reads_no_startup_file_option_or_function_from_the_environment() {
        let dir = tempfile::tempdir().unwrap();
        let startup = dir.path().join("startup.sh");
        let touched = dir.path().join("touched");
        std::fs::write(&startup, format!("touch {}\n", touched.display())).unwrap();
        // Read by a shell that imports no function either: the limit the
        // wrapper set.
        let mut sh = Command::new("/bin/bash");
        sh.args(["-p", "-c", "ulimit -Hn"]);
        let mut limited = under_limits(sh, &files(256));
        limited
            .env_clear()
            .env("BASH_ENV", &startup)
            .env("ENV", &startup)
            .env("SHELLOPTS", "xtrace")
            .env("BASH_FUNC_ulimit%%", "() { :; }");
        let out = limited.output().unwrap();
        assert!(out.status.success(), "{out:?}");
        assert_eq!(String::from_utf8_lossy(&out.stdout), "256\n");
        assert!(!touched.exists(), "the shell ran a startup file");
        assert!(
            out.stderr.is_empty(),
            "xtrace: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    /// The probe's own script, run under the limit it checks, is closed (it
    /// fails); under one higher, open.
    #[test]
    fn a_probe_is_closed_under_its_limit_and_open_above_it() {
        let probe = |limit: u64, under: u64| {
            let mut sh = Command::new("/bin/sh");
            sh.arg("-c").arg(crate::probes::limit_script("-Hn", limit));
            under_limits(sh, &files(under)).status().unwrap().success()
        };
        assert!(!probe(64, 64), "closed at the limit");
        assert!(probe(63, 64), "open above it");
    }

    /// Why Seatbelt refuses `cpu_seconds` (ADR 0033): a process that
    /// ignores SIGXCPU runs on past its CPU time. This test's own child,
    /// ended by it.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_process_that_ignores_sigxcpu_runs_past_its_cpu_time() {
        let mut child = Command::new("/bin/bash")
            .args([
                "-p",
                "-c",
                "ulimit -t 1 && trap '' XCPU && exec /usr/bin/perl -e '1 while 1'",
            ])
            .spawn()
            .unwrap();
        std::thread::sleep(std::time::Duration::from_secs(3));
        let running = child.try_wait().unwrap().is_none();
        let _ = child.kill();
        let _ = child.wait();
        assert!(running, "a process ignoring SIGXCPU was held to 1 s of CPU");
    }
}
