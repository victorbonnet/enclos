//! A backend for tests: it reports whatever kind and probe it is given and
//! touches nothing on the host.

use std::path::Path;
use std::process::Command;

use super::{
    Backend, Capabilities, CompileError, Compiled, Enforcement, Launch, Probe, SandboxContext,
};
use crate::model::policy::Policy;
use crate::model::sandbox::BackendKind;

/// The variable that tells a program the fake runs whether it was launched
/// in enclos's terminal (`Launch::in_terminal`): `true` or `false`.
pub const IN_TERMINAL: &str = "ENCLOS_FAKE_IN_TERMINAL";

/// The variable that tells a program the fake runs which runtime service
/// port it was given (`Launch::service_port`, ADR 0028): the port, or `none`.
pub const SERVICE_PORT: &str = "ENCLOS_FAKE_SERVICE_PORT";

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

    /// Runs the program as it is, outside any sandbox, but with the
    /// sandbox's environment (its home, PATH and TMPDIR), so that a test's
    /// program never touches the developer's own home. It also gets
    /// [`IN_TERMINAL`], so a test sees whether the program was to run in
    /// enclos's terminal, and [`SERVICE_PORT`], the service port it was given.
    fn wrap(&self, _compiled: &Path, ctx: &SandboxContext, launch: &Launch) -> Command {
        let mut command = Command::new(&launch.program);
        command.args(&launch.args);
        let mut command = super::under_limits(command, &launch.limits);
        command.env_clear();
        for (name, value) in &launch.env {
            command.env(name, value.expose());
        }
        for (name, value) in super::seatbelt::environment(ctx) {
            command.env(name, value);
        }
        command.env(IN_TERMINAL, launch.in_terminal.to_string());
        command.env(
            SERVICE_PORT,
            launch
                .service_port
                .map_or_else(|| "none".to_owned(), |p| p.to_string()),
        );
        command.current_dir(&ctx.home);
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
