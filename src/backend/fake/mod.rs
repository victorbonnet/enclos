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

/// The name of a path the fake refuses to compile a write to.
pub const UNCOMPILABLE: &str = "uncompilable";

pub struct FakeBackend {
    kind: BackendKind,
    probe: Probe,
    /// What `try_run` answers.
    runs: Probe,
}

impl FakeBackend {
    /// A fake that stands in for `kind` and is available.
    pub fn available(kind: BackendKind) -> Self {
        FakeBackend {
            kind,
            probe: Probe::Available,
            runs: Probe::Available,
        }
    }

    /// A fake that stands in for `kind`, is there, and refuses to run a
    /// program for `reason`, as Seatbelt does in a process already in a
    /// sandbox whose policy has a deny rule (macOS 26.5.2).
    pub fn refuses_to_run(kind: BackendKind, reason: &str) -> Self {
        FakeBackend {
            kind,
            probe: Probe::Available,
            runs: Probe::Unavailable {
                reason: reason.to_owned(),
            },
        }
    }

    /// A fake that stands in for `kind` and is unavailable for `reason`.
    pub fn unavailable(kind: BackendKind, reason: &str) -> Self {
        FakeBackend {
            kind,
            probe: Probe::Unavailable {
                reason: reason.to_owned(),
            },
            runs: Probe::Unavailable {
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

    fn try_run(&self) -> Probe {
        self.runs.clone()
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

    /// One line per grant, so tests can see what reached the backend. A
    /// write to a path named [`UNCOMPILABLE`] is refused, as a backend
    /// refuses what it cannot hold.
    fn compile(&self, policy: &Policy, ctx: &SandboxContext) -> Result<Compiled, CompileError> {
        if let Some(w) = policy.fs.write.iter().find(|w| w.ends_with(UNCOMPILABLE)) {
            return Err(CompileError::Unsupported {
                backend: self.kind,
                reason: format!("the fake cannot compile a write to {w}"),
            });
        }
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
    /// variables every backend gives (its home, PATH and TMPDIR among them),
    /// so that a test's program never touches the developer's own home. It also gets
    /// [`IN_TERMINAL`], so a test sees whether the program was to run in
    /// enclos's terminal, and [`SERVICE_PORT`], the service port it was given.
    fn wrap(&self, _compiled: &Path, ctx: &SandboxContext, launch: &Launch) -> Command {
        let mut command = Command::new(&launch.program);
        command.args(&launch.args);
        let mut command = super::under_limits(command, &launch.limits);
        super::environment::apply(&mut command, ctx, launch);
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
    use crate::layout::Layout;
    use std::collections::HashMap;
    use std::ffi::OsString;
    use std::path::PathBuf;

    /// The host's kept variables included, so engine tests run a program
    /// with what a real session gets.
    #[test]
    fn a_program_gets_the_variables_every_backend_gives() {
        let layout = Layout::at(PathBuf::from("/home/alice/.enclos"));
        let ctx = SandboxContext::new(&layout, &"home".parse().unwrap(), 41001);
        let launch = Launch {
            program: "/usr/bin/true".into(),
            args: Vec::new(),
            env: Vec::new(),
            in_terminal: false,
            service_port: None,
            limits: Default::default(),
        };
        let envs = |command: &Command| -> HashMap<OsString, Option<OsString>> {
            command
                .get_envs()
                .map(|(k, v)| (k.to_owned(), v.map(ToOwned::to_owned)))
                .filter(|(k, _)| k != IN_TERMINAL && k != SERVICE_PORT)
                .collect()
        };
        let fake = FakeBackend::available(BackendKind::Seatbelt);
        let wrapped = fake.wrap(Path::new("/c.fake"), &ctx, &launch);
        let mut expected = Command::new("/usr/bin/true");
        crate::backend::environment::apply(&mut expected, &ctx, &launch);
        assert_eq!(envs(&wrapped), envs(&expected));
    }

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
