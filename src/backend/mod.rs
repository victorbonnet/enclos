//! Backends: the isolation technologies sandboxes are built on (design §5).
//!
//! The trait holds what the commands built so far need; it grows toward the
//! full shape in design §9 (prepare, members, denials, ...) as the commands
//! that use it arrive.

pub mod bubblewrap;
pub mod environment;
#[cfg(test)]
pub mod fake;
pub mod seatbelt;

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::layout::Layout;
use crate::model::policy::Policy;
use crate::model::sandbox::{BackendKind, SandboxName};
use crate::probes::OwnProbes;

/// What a compiled policy does with an operation none of its rules names
/// (ADR 0006).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Baseline {
    /// `(deny default)`, then the reviewed allowances of `deny-default.sb`.
    #[default]
    DenyDefault,
    /// `(allow default)`, as before ADR 0006: only for comparing the two.
    AllowDefault,
}

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
    /// The folder of its secrets files, there while its services run (ADR
    /// 0034, ADR 0036).
    pub secrets: PathBuf,
    /// The socket its proxy listens on for a session with a network of its
    /// own.
    pub proxy_socket: PathBuf,
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
            secrets: layout.sandbox_secrets_dir(name.as_str()),
            proxy_socket: layout.proxy_socket(name.as_str()),
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
#[derive(Debug, PartialEq, Eq)]
pub struct Launch {
    pub program: OsString,
    pub args: Vec<OsString>,
    /// The secrets its policy grants, by variable, or, for a service whose
    /// runtime reads them from a file, the variable naming that file's
    /// folder (ADR 0034); set before the sandbox's own environment, which
    /// they never replace.
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
    /// The limits each of its processes runs under (design §7).
    pub limits: LaunchLimits,
}

/// The limits a program runs under, as a backend sets them: only those a
/// backend enforces as written, `open_files` for now (design §7, ADR 0033).
/// The engine makes them from a policy's `[resources]` once checked for the
/// sandbox's backend, so a limit nothing enforces never reaches a program.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LaunchLimits {
    open_files: Option<u64>,
}

impl LaunchLimits {
    /// The limits of `resources`, which the caller has checked for the
    /// backend: one set that no backend enforces is refused here too, in
    /// every build, never dropped, so a backend that comes to accept one
    /// must be given it here first.
    pub(crate) fn of_checked(
        resources: &crate::model::policy::Resources,
    ) -> Result<LaunchLimits, String> {
        // Every field named, so one added is decided on here.
        let crate::model::policy::Resources {
            open_files,
            file_size,
            cpu_seconds,
            memory,
            cpu,
        } = resources;
        if file_size.is_some() || cpu_seconds.is_some() || memory.is_some() || cpu.is_some() {
            return Err(format!(
                "a limit no backend enforces reached a launch: {resources:?}"
            ));
        }
        Ok(LaunchLimits {
            open_files: *open_files,
        })
    }

    /// The file descriptors a process may hold, if limited.
    pub fn open_files(&self) -> Option<u64> {
        self.open_files
    }
}

/// `command` run under `limits`, which every process it starts inherits:
/// `/bin/bash` sets them with `ulimit`, hard and soft alike, so no process
/// in the sandbox without root can raise them, then becomes the program;
/// one it cannot set stops it with exit 125 and the field named, so no
/// program runs without its limits. Only `open_files` is set: Seatbelt
/// refuses the others (ADR 0033), and no other backend is built. In
/// privileged mode (`-p`), as it runs on the host with the sandbox's
/// variables: it then reads no `BASH_ENV` or `ENV` file, no `SHELLOPTS` and
/// no function from them. Only `command`'s program and arguments are kept:
/// set its environment and folder on the result. Returns `command`
/// unchanged when no limit is set.
pub fn under_limits(command: Command, limits: &LaunchLimits) -> Command {
    debug_assert!(
        command.get_envs().next().is_none() && command.get_current_dir().is_none(),
        "set the environment and folder after the limits"
    );
    let mut set = Vec::new();
    if let Some(files) = limits.open_files {
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

/// Why `limits` cannot be set where enclos runs as written, if they
/// cannot: a limit above the hard one enclos itself runs under, which no
/// process without root can raise, would stop every program with it; one
/// above macOS's own ceiling on the files a process holds would be set, but
/// hold each process to that ceiling instead.
pub fn unsettable(limits: &LaunchLimits) -> Option<String> {
    let files = limits.open_files?;
    let hard = rustix::process::getrlimit(rustix::process::Resource::Nofile).maximum;
    if let Some(hard) = hard
        && files > hard
    {
        return Some(format!(
            "resources.open_files = {files} is above the hard limit enclos runs under ({hard}): lower it in the policy, or raise the hard limit of the shell or service manager enclos runs from"
        ));
    }
    if let Some(most) = max_files_per_process()
        && files > most
    {
        return Some(format!(
            "resources.open_files = {files} is above the {most} files macOS lets any process hold (kern.maxfilesperproc), so a process would be stopped there, not where the policy says: lower it to {most} or less"
        ));
    }
    None
}

/// macOS's ceiling on the files one process holds, `kern.maxfilesperproc`:
/// `ulimit` sets a limit above it and reads it back, but the kernel stops
/// every process at it. None elsewhere, or when it cannot be read; the
/// limit then holds no process to more than the policy says, only maybe to
/// fewer.
pub(crate) fn max_files_per_process() -> Option<u64> {
    if !cfg!(target_os = "macos") {
        return None;
    }
    let out = Command::new("/usr/sbin/sysctl")
        .args(["-n", "kern.maxfilesperproc"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8(out.stdout).ok()?.trim().parse().ok()
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
    /// Its own escape probes and how it refuses, for a sandbox compiled to
    /// `compiled`, or on a dry run, which compiles nothing, for none. Says
    /// why not when that text is not what it compiles.
    fn own_probes(&self, compiled: Option<&str>) -> Result<Box<dyn OwnProbes>, String>;
}

/// Every backend this build of enclos ships, in order of preference.
///
/// This is the one explicit list of implementations.
pub fn registered() -> Vec<Box<dyn Backend>> {
    vec![Box::new(seatbelt::Seatbelt::from_env())]
}

#[cfg(test)]
mod limits_tests {
    use super::*;

    /// Why `unsettable` refuses an `open_files` above `kern.maxfilesperproc`:
    /// `ulimit` sets it and reads it back, but no process opens more files
    /// than that.
    #[cfg(target_os = "macos")]
    #[test]
    fn no_process_opens_more_files_than_kern_maxfilesperproc() {
        let most = max_files_per_process().expect("kern.maxfilesperproc");
        let over = most + 10_000;
        let mut read = Command::new("/bin/sh");
        read.args(["-c", "ulimit -Hn"]);
        let out = under_limits(read, &files(over)).output().unwrap();
        if out.status.code() == Some(125) {
            // Under a hard limit below `over`, as unsettable says first;
            // the ceiling itself is not shown on this host.
            assert!(
                unsettable(&files(over))
                    .unwrap()
                    .contains("hard limit enclos runs under")
            );
            eprintln!(
                "skipped: this test's hard limit is below {over}, so kern.maxfilesperproc ({most}) was not shown to hold"
            );
            return;
        }
        assert_eq!(String::from_utf8(out.stdout).unwrap(), format!("{over}\n"));
        let mut perl = Command::new("/usr/bin/perl");
        perl.args([
            "-e",
            "my @f; my $n = 0; while (open(my $f, '<', '/dev/null')) { push @f, $f; $n++ } print $n",
        ]);
        let out = under_limits(perl, &files(over)).output().unwrap();
        let opened: u64 = String::from_utf8(out.stdout).unwrap().parse().unwrap();
        assert!(
            opened < most,
            "opened {opened} under {over}, with {most} the ceiling"
        );
        assert!(
            opened > most - 100,
            "opened {opened}, with {most} the ceiling"
        );
        let why = unsettable(&files(over)).unwrap();
        assert!(why.contains("kern.maxfilesperproc"), "{why}");
        assert_eq!(unsettable(&files(most)), None);
    }

    fn files(n: u64) -> LaunchLimits {
        LaunchLimits::of_checked(&crate::model::policy::Resources {
            open_files: Some(n),
            ..Default::default()
        })
        .unwrap()
    }

    #[test]
    fn limits_are_set_by_the_shell_that_becomes_the_program() {
        let plain = Command::new("/usr/bin/true");
        let none = under_limits(plain, &LaunchLimits::default());
        assert_eq!(none.get_program(), "/usr/bin/true");
        let mut program = Command::new("/usr/bin/sandbox-exec");
        program.args(["-f", "x.sb", "/bin/zsh"]);
        let limited = under_limits(program, &files(256));
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

    /// The probe reads closed only on a number no higher than the limit:
    /// no limit, or a value it cannot read, reads open, never closed. A
    /// shell function stands in for `ulimit`, so no real limit is needed.
    #[test]
    fn a_probe_reads_no_limit_or_an_unreadable_one_as_open() {
        let probe = |value: &str| {
            Command::new("/bin/sh")
                .arg("-c")
                .arg(format!(
                    "ulimit() {{ printf '%s\\n' \"$V\"; }}; {}",
                    crate::probes::limit_script("-Hn", 64)
                ))
                .env("V", value)
                .output()
                .unwrap()
        };
        for value in ["unlimited", "", "abc", "12x", "65"] {
            assert!(probe(value).status.success(), "{value:?} reads open");
        }
        for value in ["abc", ""] {
            let said = String::from_utf8(probe(value).stdout).unwrap();
            assert!(said.contains("unreadable limit"), "{value:?}: {said}");
        }
        for value in ["64", "16"] {
            assert!(!probe(value).status.success(), "{value:?} reads closed");
        }
    }

    /// macOS refuses a memory limit: `ulimit -v`, `-d` and `-m` fail.
    #[cfg(target_os = "macos")]
    #[test]
    fn macos_refuses_a_memory_limit() {
        for flag in ["-v", "-d", "-m"] {
            let out = Command::new("/bin/bash")
                .args(["-p", "-c", &format!("ulimit {flag} 100000")])
                .output()
                .unwrap();
            assert!(!out.status.success(), "ulimit {flag} was set");
        }
    }

    /// macOS checks a file size limit against where an appending write
    /// starts, from the start of the file each process opened: separate
    /// processes each appending under 1 KiB grow a file past it.
    #[cfg(target_os = "macos")]
    #[test]
    fn appends_of_separate_processes_grow_a_file_past_its_size_limit() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("f");
        let script = format!(
            "ulimit -f 1; for i in $(seq 50); do /bin/sh -c 'head -c 100 /dev/zero >> \"$1\"' sh '{}'; done",
            file.display()
        );
        let _ = Command::new("/bin/bash")
            .args(["-p", "-c", &script])
            .status()
            .unwrap();
        let size = std::fs::metadata(&file).unwrap().len();
        assert!(size > 1024, "{size} bytes, held to 1 KiB");
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
