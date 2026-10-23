//! The Seatbelt backend: macOS's sandbox, through `sandbox-exec` (ADR 0005).
//! Policies compile on the `(deny default)` baseline (ADR 0006); the
//! `(allow default)` one milestone 1 used is kept only so tests can compare
//! the two baselines.

mod compile;
#[cfg(all(test, target_os = "macos"))]
mod tests;
mod wrap;

use std::path::Path;
use std::process::Command;

use super::{
    Backend, Capabilities, CompileError, Compiled, Enforcement, Launch, Probe, SandboxContext,
};
use crate::model::policy::Policy;
use crate::model::sandbox::BackendKind;

pub use compile::{BASELINE_VAR, Baseline, tag};
pub use wrap::environment;

/// Seatbelt, compiling on one baseline for the whole process.
pub struct Seatbelt {
    /// [`Baseline::from_env`], read once: every policy compiled in a
    /// process is on the same baseline, and a bad value fails each compile.
    baseline: Result<Baseline, String>,
}

impl Seatbelt {
    /// On the baseline [`BASELINE_VAR`] asks for.
    pub fn from_env() -> Seatbelt {
        Seatbelt {
            baseline: Baseline::from_env(),
        }
    }

    /// On `baseline`, whatever the environment says.
    pub fn on(baseline: Baseline) -> Seatbelt {
        Seatbelt {
            baseline: Ok(baseline),
        }
    }
}

impl Default for Seatbelt {
    fn default() -> Seatbelt {
        Seatbelt::on(Baseline::DenyDefault)
    }
}

/// Says once, on stderr, that a program runs on the comparison baseline.
fn say_allow_default(ctx: &SandboxContext) {
    static SAID: std::sync::Once = std::sync::Once::new();
    SAID.call_once(|| {
        eprintln!(
            "enclos: sandbox {} runs under a policy compiled from (allow default), as {BASELINE_VAR} asks: that baseline is only for comparing the two (ADR 0006)",
            ctx.name
        );
    });
}

impl Backend for Seatbelt {
    fn kind(&self) -> BackendKind {
        BackendKind::Seatbelt
    }

    fn probe(&self) -> Probe {
        if !cfg!(target_os = "macos") {
            return Probe::Unavailable {
                reason: "Seatbelt exists only on macOS".to_owned(),
            };
        }
        if !Path::new(wrap::SANDBOX_EXEC).exists() {
            return Probe::Unavailable {
                reason: format!("{} is missing", wrap::SANDBOX_EXEC),
            };
        }
        Probe::Available
    }

    fn try_run(&self) -> Probe {
        wrap::try_run()
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            fs: Enforcement::Enforced,
            network: Enforcement::Enforced,
            exec: Enforcement::Unsupported,
            resources: Enforcement::Partial {
                note: "per process: open files and CPU time; no memory, file size or CPU share"
                    .to_owned(),
            },
            members: Enforcement::Partial {
                note: "markers its processes hold, the parent chain and process groups (ADR 0030); one that closes its marker and leaves its group and parent is not found"
                    .to_owned(),
            },
        }
    }

    fn compile(&self, policy: &Policy, ctx: &SandboxContext) -> Result<Compiled, CompileError> {
        let baseline = self
            .baseline
            .clone()
            .map_err(|reason| CompileError::Unsupported {
                backend: BackendKind::Seatbelt,
                reason,
            })?;
        compile::compile(policy, ctx, baseline)
    }

    fn wrap(&self, compiled: &Path, ctx: &SandboxContext, launch: &Launch) -> Command {
        if self.baseline == Ok(Baseline::AllowDefault) {
            say_allow_default(ctx);
        }
        wrap::wrap(compiled, ctx, launch)
    }
}
