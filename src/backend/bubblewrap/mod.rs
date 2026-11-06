//! The bubblewrap backend: Linux's sandbox (ADR 0004). It compiles a policy
//! to one file, `wrap` runs `enclos inside` under bubblewrap with the masks
//! the host holds at launch, and `enclos inside` applies the rest. Every
//! session joins the network namespace of the sandbox's namespace holder
//! first (ADR 0039).

pub mod compile;
mod degraded;
pub mod holder;
#[cfg(target_os = "linux")]
pub mod inside;
mod probe;
pub mod probes;
pub mod proposed;
pub mod seccomp;
mod wrap;

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

use super::{
    Backend, Capabilities, CompileError, Compiled, HeldNamespace, Launch, NamespaceHolder, Probe,
    SandboxContext, WrapError,
};
use crate::host::HostCheck;
use crate::model::policy::Policy;
use crate::model::sandbox::BackendKind;
use crate::probes::OwnProbes;

pub use compile::{CompiledSandbox, compile};
pub use proposed::{Host, capabilities};

/// What `wrap` passes `enclos inside` in a terminal's session, whose
/// bubblewrap outer process ignores Ctrl-C and Ctrl-\: hand them back to
/// the command.
pub const INTERRUPTS_FLAG: &str = "--restore-interrupts";

/// Where Debian's and Ubuntu's `bubblewrap` package installs it.
pub const BWRAP: &str = "/usr/bin/bwrap";

/// bubblewrap, as this host runs it.
pub struct Bubblewrap {
    bwrap: PathBuf,
    systemd_run: PathBuf,
    /// This program, which bubblewrap runs first as `enclos inside`.
    enclos: Option<PathBuf>,
    /// What [`Backend::probe`] found, once per process: it starts
    /// bubblewrap, and every command asks it.
    probed: OnceLock<probe::Probed>,
}

impl Bubblewrap {
    /// bubblewrap and systemd where the host's packages put them, and this
    /// program as it runs.
    pub fn on_host() -> Bubblewrap {
        Bubblewrap::at(
            Path::new(BWRAP),
            Path::new(crate::lifecycle::cgroup::SYSTEMD_RUN),
            std::env::current_exe().ok(),
        )
    }

    /// With the programs at these paths, as tests give stand-ins for them.
    pub fn at(bwrap: &Path, systemd_run: &Path, enclos: Option<PathBuf>) -> Bubblewrap {
        Bubblewrap {
            bwrap: bwrap.to_owned(),
            systemd_run: systemd_run.to_owned(),
            enclos,
            probed: OnceLock::new(),
        }
    }

    fn probed(&self) -> &probe::Probed {
        self.probed
            .get_or_init(|| probe::probe(&probe::OnHost::new(&self.bwrap, &self.systemd_run)))
    }
}

impl Backend for Bubblewrap {
    fn kind(&self) -> BackendKind {
        BackendKind::Bubblewrap
    }

    fn probe(&self) -> Probe {
        self.probed().probe.clone()
    }

    /// What `probe` found, which already started bubblewrap: nothing more
    /// is started here, so `doctor` changes nothing on the host either.
    fn try_run(&self) -> Probe {
        self.probe()
    }

    /// The probe's checks, up to the first that keeps bubblewrap from
    /// running, then the degraded controls, on Linux alone.
    fn host_checks(&self) -> Vec<HostCheck> {
        let mut checks = self.probed().checks.clone();
        if !checks.is_empty() {
            checks.extend(degraded::checks(&degraded::Kernel::host()));
        }
        checks
    }

    /// Declared for this host's Landlock (ADR 0037).
    fn capabilities(&self) -> Capabilities {
        capabilities(&Host {
            landlock_abi: probe::landlock_abi(),
        })
    }

    fn compile(&self, policy: &Policy, ctx: &SandboxContext) -> Result<Compiled, CompileError> {
        compile::compile(policy, ctx)
    }

    /// Reads the compiled file and the host as they are now: the masks of
    /// the user's home and of what a link reaches are this launch's.
    fn wrap(
        &self,
        compiled: &Path,
        ctx: &SandboxContext,
        launch: &Launch,
    ) -> Result<Command, WrapError> {
        let text = std::fs::read_to_string(compiled).map_err(|e| {
            WrapError(format!(
                "cannot read the compiled policy {}: {e}",
                compiled.display()
            ))
        })?;
        let parsed: CompiledSandbox = serde_json::from_str(&text).map_err(|e| {
            WrapError(format!(
                "the compiled policy {} does not read: {e}",
                compiled.display()
            ))
        })?;
        let enclos = self.enclos.as_deref().ok_or_else(|| {
            WrapError("cannot find the enclos program, which bubblewrap runs first".to_owned())
        })?;
        let ssh_auth_sock = std::env::var_os("SSH_AUTH_SOCK").map(PathBuf::from);
        let host = wrap::read_host(&parsed, &ctx.home, ssh_auth_sock.as_deref())?;
        let programs = wrap::Programs {
            bwrap: &self.bwrap,
            enclos,
        };
        wrap::command(&programs, compiled, &parsed, &host, ctx, launch)
    }

    /// `listen = false` is not held (design §15): every start says so.
    fn said_at_start(&self, policy: &Policy, ctx: &SandboxContext) -> Vec<String> {
        proposed::unenforced(policy)
            .into_iter()
            .filter(|u| u.field == proposed::LISTEN)
            .map(|u| {
                format!(
                    "sandbox {}: `listen = false` is not held on bubblewrap: {} (enclos doctor)",
                    ctx.name, u.why
                )
            })
            .collect()
    }

    /// The same probes for every compiled file, which must be one this
    /// backend wrote.
    fn own_probes(&self, compiled: Option<&str>) -> Result<Box<dyn OwnProbes>, String> {
        if let Some(text) = compiled {
            serde_json::from_str::<CompiledSandbox>(text)
                .map_err(|e| format!("is not a policy compiled for bubblewrap: {e}"))?;
        }
        Ok(Box::new(probes::BubblewrapProbes::default()))
    }

    /// Every session joins it (ADR 0039).
    fn namespace_holder(&self) -> Option<&dyn NamespaceHolder> {
        Some(self)
    }
}

impl NamespaceHolder for Bubblewrap {
    #[cfg(target_os = "linux")]
    fn command(&self, ctx: &SandboxContext) -> Result<Command, WrapError> {
        let enclos = self.enclos.as_deref().ok_or_else(|| {
            WrapError("cannot find the enclos program, which runs the namespace holder".to_owned())
        })?;
        holder::command(&self.bwrap, enclos, ctx)
    }

    #[cfg(target_os = "linux")]
    fn ask(&self, ctx: &SandboxContext) -> Result<HeldNamespace, String> {
        holder::ask(&ctx.holder_socket).map(|answer| HeldNamespace {
            pid: answer.pid,
            ephemeral: answer.ephemeral,
        })
    }

    #[cfg(not(target_os = "linux"))]
    fn command(&self, _ctx: &SandboxContext) -> Result<Command, WrapError> {
        Err(WrapError("the namespace holder runs on Linux".to_owned()))
    }

    #[cfg(not(target_os = "linux"))]
    fn ask(&self, _ctx: &SandboxContext) -> Result<HeldNamespace, String> {
        Err("the namespace holder runs on Linux".to_owned())
    }
}
