//! A backend for tests: it reports whatever kind and probe it is given and
//! touches nothing on the host.

use std::path::Path;
use std::process::Command;

use super::{
    Backend, Capabilities, CompileError, Compiled, Enforcement, Launch, Probe, SandboxContext,
};
use crate::model::policy::Policy;
use crate::model::sandbox::BackendKind;

pub struct FakeBackend {
    kind: BackendKind,
    probe: Probe,
}

impl FakeBackend {
    /// A fake that stands in for `kind` and is available.
    pub fn available(kind: BackendKind) -> Self {
        FakeBackend {
            kind,
            probe: Probe::Available,
        }
    }

    /// A fake that stands in for `kind` and is unavailable for `reason`.
    pub fn unavailable(kind: BackendKind, reason: &str) -> Self {
        FakeBackend {
            kind,
            probe: Probe::Unavailable {
                reason: reason.to_owned(),
            },
        }
    }
}

impl Backend for FakeBackend {
    fn kind(&self) -> BackendKind {
        self.kind
    }

    fn probe(&self) -> Probe {
        self.probe.clone()
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            fs: Enforcement::Enforced,
            network: Enforcement::Enforced,
            exec: Enforcement::Unsupported,
            resources: Enforcement::Unsupported,
            members: Enforcement::Enforced,
        }
    }

    /// One line per grant, so tests can see what reached the backend.
    fn compile(&self, policy: &Policy, ctx: &SandboxContext) -> Result<Compiled, CompileError> {
        let mut text = format!("fake policy for {}\n", ctx.name);
        for w in &policy.fs.write {
            text.push_str(&format!("write {w}\n"));
        }
        for d in &policy.net.allow {
            text.push_str(&format!("allow {d}\n"));
        }
        Ok(Compiled {
            text,
            extension: "fake",
        })
    }

    /// Runs the program as it is, outside any sandbox.
    fn wrap(&self, _compiled: &Path, _ctx: &SandboxContext, launch: &Launch) -> Command {
        let mut command = Command::new(&launch.program);
        command.args(&launch.args);
        command
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_what_it_was_given() {
        let fake = FakeBackend::unavailable(BackendKind::Bubblewrap, "not Linux");
        assert_eq!(fake.kind(), BackendKind::Bubblewrap);
        assert_eq!(
            fake.probe(),
            Probe::Unavailable {
                reason: "not Linux".into()
            }
        );
        assert_eq!(
            FakeBackend::available(BackendKind::Seatbelt).probe(),
            Probe::Available
        );
    }
}
