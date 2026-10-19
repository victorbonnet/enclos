//! The Seatbelt backend: macOS's sandbox, through `sandbox-exec` (ADR 0005).
//! Milestone 1 compiles on the `(allow default)` baseline; ADR 0006 decides
//! between it and `(deny default)` in milestone 2.

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

pub use compile::tag;

pub struct Seatbelt;

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

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            fs: Enforcement::Enforced,
            network: Enforcement::Enforced,
            exec: Enforcement::Unsupported,
            resources: Enforcement::Unsupported,
            members: Enforcement::Partial {
                note: "process groups, until the milestone 1 tracking issue settles the method"
                    .to_owned(),
            },
        }
    }

    fn compile(&self, policy: &Policy, ctx: &SandboxContext) -> Result<Compiled, CompileError> {
        compile::compile(policy, ctx)
    }

    fn wrap(&self, compiled: &Path, ctx: &SandboxContext, launch: &Launch) -> Command {
        wrap::wrap(compiled, ctx, launch)
    }
}
