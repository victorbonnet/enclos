//! The bubblewrap backend: Linux's sandbox (ADR 0004). It compiles a policy
//! to one file, `wrap` runs `enclos inside` under bubblewrap with the masks
//! the host holds at launch, and `enclos inside` applies the rest.

pub mod compile;
#[cfg(target_os = "linux")]
pub mod inside;
mod probe;
pub mod proposed;
mod wrap;

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

use super::{
    Backend, Capabilities, CompileError, Compiled, Launch, Probe, SandboxContext, WrapError,
};
use crate::model::policy::Policy;
use crate::model::sandbox::BackendKind;
use crate::probes::OwnProbes;

pub use compile::{CompiledSandbox, compile};
pub use proposed::{Host, capabilities};

/// Where Debian's and Ubuntu's `bubblewrap` package installs it.
pub const BWRAP: &str = "/usr/bin/bwrap";

/// bubblewrap, as this host runs it.
pub struct Bubblewrap {
    bwrap: PathBuf,
    systemd_run: PathBuf,
    /// This program, which bubblewrap runs first as `enclos inside`.
    enclos: Option<PathBuf>,
    /// [`Backend::probe`]'s answer, found once per process: it starts
    /// bubblewrap, and every command asks it.
    probed: OnceLock<Probe>,
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
}

impl Backend for Bubblewrap {
    fn kind(&self) -> BackendKind {
        BackendKind::Bubblewrap
    }

    fn probe(&self) -> Probe {
        self.probed
            .get_or_init(|| probe::probe(&probe::OnHost::new(&self.bwrap, &self.systemd_run)))
            .clone()
    }

    /// What `probe` found, which already started bubblewrap: nothing more
    /// is started here, so `doctor` changes nothing on the host either.
    fn try_run(&self) -> Probe {
        self.probe()
    }

    /// Declared for this host's Landlock (ADR 0037, proposed).
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

    fn own_probes(&self, _compiled: Option<&str>) -> Result<Box<dyn OwnProbes>, String> {
        Err(
            "cannot be tested yet: the bubblewrap backend's escape probes are not in this build (milestone 3, M3-17)"
                .to_owned(),
        )
    }
}
