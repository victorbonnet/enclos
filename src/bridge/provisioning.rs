//! Provisioning for the host's person for the mobile app. Every
//! change goes through the same engine and audit log as its CLI command.

use std::io::Read;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use enclos_protocol::device::{RuntimeInfo, SandboxInfo};
use serde_json::Value;

use crate::engine::{Engine, SandboxSpec};
use crate::layout::Layout;
use crate::model::audit::Actor;
use crate::model::plan::{Confirm, Planned};
use crate::model::policy::TemplateName;
use crate::model::runtime::RuntimeKind;
use crate::model::sandbox::{SandboxName, SandboxState};

/// All inputs have been checked before a worker is started.
pub enum Operation {
    Create {
        name: SandboxName,
        template: TemplateName,
    },
    Install {
        name: SandboxName,
        runtime: RuntimeKind,
    },
}

impl Operation {
    pub fn create(sandbox: &str, template: &str) -> Result<Self, String> {
        // Only the built-in templates with explained mobile choices. Custom
        // templates may contain host paths the phone cannot review.
        if !matches!(template, "minimal" | "assistant") {
            return Err("choose the minimal or assistant template".to_owned());
        }
        Ok(Self::Create {
            name: sandbox.parse::<SandboxName>().map_err(|e| e.to_string())?,
            template: template
                .parse::<TemplateName>()
                .map_err(|e| e.to_string())?,
        })
    }

    pub fn install(sandbox: &str, runtime: &str) -> Result<Self, String> {
        Ok(Self::Install {
            name: sandbox.parse::<SandboxName>().map_err(|e| e.to_string())?,
            runtime: runtime.parse::<RuntimeKind>().map_err(|e| e.to_string())?,
        })
    }

    pub fn sandbox(&self) -> &str {
        match self {
            Self::Create { name, .. } | Self::Install { name, .. } => name.as_str(),
        }
    }

    pub fn verb(&self) -> &'static str {
        match self {
            Self::Create { .. } => "sandbox.create",
            Self::Install { .. } => "runtime.install",
        }
    }

    pub fn progress(&self) -> &'static str {
        match self {
            Self::Create { .. } => "Creating the sandbox and its policy…",
            Self::Install { .. } => {
                "Downloading and running the runtime's installer inside the sandbox. This can take several minutes…"
            }
        }
    }
}

#[derive(Debug)]
pub enum Completed {
    Created,
    Installed { runtime: String, login: String },
}

/// Data a worker needs to open its own engine and to run enclos. It
/// contains no connection, database or device keys.
pub struct Host {
    layout: Layout,
    executable: PathBuf,
}

impl Host {
    pub fn new(layout: Layout, executable: PathBuf) -> Self {
        Self { layout, executable }
    }

    pub fn sandboxes(&self) -> Result<Vec<SandboxInfo>, String> {
        sandbox_list(&Engine::open(
            self.layout.clone(),
            crate::state::Wait::Command,
        ))
    }

    pub fn runtimes(&self) -> Vec<RuntimeInfo> {
        RuntimeKind::ALL.into_iter().map(|kind| RuntimeInfo {
            runtime: kind.to_string(),
            name: kind.display_name().to_owned(),
            description: match kind {
                RuntimeKind::Hermes => "An agent runtime installed inside this sandbox. Login and app channel setup follow on the host.".to_owned(),
            },
        }).collect()
    }

    /// Runs `operation` for `by`, the authenticated person and device that
    /// asked for it, whom the audit log names.
    pub fn execute(&self, operation: &Operation, by: &Actor) -> Result<Completed, String> {
        match operation {
            Operation::Create { name, template } => {
                let engine = Engine::open(self.layout.clone(), crate::state::Wait::Command);
                create(&engine, by, name.clone(), template.clone())?;
                Ok(Completed::Created)
            }
            Operation::Install { name, runtime } => self.install(name, *runtime, by),
        }
    }

    fn install(
        &self,
        name: &SandboxName,
        runtime: RuntimeKind,
        by: &Actor,
    ) -> Result<Completed, String> {
        // A session installs signal handlers and inherits standard streams.
        // Give it a process of its own, no terminal and no stdin, instead of
        // changing the bridge process's signals or reading its terminal.
        // No --yes: an unrelated policy edit still needs review on the host.
        let mut child = Command::new(&self.executable)
            .args([
                "--json",
                "runtime",
                "install",
                runtime.as_str(),
                "--sandbox",
                name.as_str(),
                // Its audit entry names the person and device, not the
                // host's user who runs the bridge; joined by `=`, so a
                // value starting with `-` is not taken for an option
                &format!("--requested-by={}", by.user),
            ])
            .envs(self.layout.env())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            // A runtime installer can leave background members holding
            // stderr open. Discard it directly: waiting for a pipe's EOF
            // would then wait for those members too, after install ended.
            .stderr(Stdio::null())
            .process_group(0)
            .spawn()
            .map_err(|e| format!("cannot start the runtime installer: {e}"))?;
        let stdout = child.stdout.take().expect("piped stdout");
        // CLI document output reserves its original stdout with a close-on-exec
        // descriptor and redirects installer output to stderr (cli::output).
        // Drain that document concurrently, retaining only bounded output.
        // Installer output may contain secrets, so it is never sent to a
        // phone or added to the bridge's log.
        let output = std::thread::spawn(move || read_bounded(stdout, 65_536));
        let status = child
            .wait()
            .map_err(|e| format!("cannot wait for the installer: {e}"))?;
        let bytes = output
            .join()
            .map_err(|_| "cannot read the install result")??;
        let result: Value = serde_json::from_slice(&bytes)
            .map_err(|_| format!("the installer exited with {status} without a readable result; check the sandbox on the host"))?;
        if let Some(message) = result["error"]["message"].as_str() {
            return Err(message.to_owned());
        }
        if !status.success() || result["installed"].as_bool() != Some(true) {
            return Err("the runtime was not installed; check the sandbox on the host".to_owned());
        }
        if result["sandbox"].as_str() != Some(name.as_str())
            || result["runtime"].as_str() != Some(runtime.as_str())
            || result["login"].as_str().is_none_or(str::is_empty)
        {
            return Err("the installer returned an incomplete or mismatched result; check the sandbox on the host".to_owned());
        }
        Ok(Completed::Installed {
            runtime: runtime.to_string(),
            login: result["login"].as_str().unwrap_or_default().to_owned(),
        })
    }
}

fn read_bounded(mut stream: impl Read, limit: usize) -> Result<Vec<u8>, String> {
    let mut saved = Vec::new();
    let mut chunk = [0; 8192];
    loop {
        let n = stream.read(&mut chunk).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        let keep = n.min(limit.saturating_sub(saved.len()));
        saved.extend_from_slice(&chunk[..keep]);
    }
    Ok(saved)
}

fn sandbox_list(engine: &Engine) -> Result<Vec<SandboxInfo>, String> {
    engine
        .list_sandboxes()
        .map_err(|e| e.to_string())
        .map(|views| {
            views
                .into_iter()
                .map(|view| SandboxInfo {
                    sandbox: view.record.name.to_string(),
                    runtime: view.record.runtime.map(|kind| kind.to_string()),
                    state: match view.record.state {
                        SandboxState::Created => "created",
                        SandboxState::Running => "running",
                        SandboxState::Stopped => "stopped",
                        SandboxState::Failed { .. } => "failed",
                    }
                    .to_owned(),
                })
                .collect()
        })
}

/// Creates sandbox `name` with the backend `sandbox create` takes when it
/// names none: the configured default, else the first available.
fn create(
    engine: &Engine,
    actor: &Actor,
    name: SandboxName,
    template: TemplateName,
) -> Result<(), String> {
    let backend = engine.default_backend().map_err(|e| e.to_string())?;
    match engine
        .create_sandbox(
            actor,
            SandboxSpec {
                name,
                backend,
                template,
            },
            Confirm::Ask,
        )
        .map_err(|e| e.to_string())?
    {
        Planned::Done(_) => Ok(()),
        Planned::DryRun(_) => unreachable!("not a dry run"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::sandbox::BackendKind;
    use std::os::unix::fs::PermissionsExt;

    fn actor() -> Actor {
        Actor {
            user: "owner@example.org".into(),
            host: "mac".into(),
        }
    }

    fn device_actor() -> Actor {
        Actor {
            user: "owner@example.org (device phone-1)".into(),
            host: "mac".into(),
        }
    }

    fn fake_host(body: &str) -> (tempfile::TempDir, Host) {
        let dir = tempfile::tempdir().unwrap();
        let executable = dir.path().join("enclos");
        std::fs::write(&executable, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
        let host = Host::new(Layout::at(dir.path().join("data")), executable);
        (dir, host)
    }

    #[test]
    fn creates_and_lists_an_empty_sandbox_with_the_hosts_backend_and_audit() {
        use crate::audit::jsonl::JsonlAuditLog;
        use crate::backend::fake::FakeBackend;
        use crate::state::sqlite::SqliteStateStore;

        let dir = tempfile::tempdir().unwrap();
        let layout = Layout::at(dir.path().join("data"));
        let engine = Engine::new(
            layout.clone(),
            Box::new(SqliteStateStore::new(
                layout.state_db(),
                layout.state_lock(),
                crate::state::Wait::Command,
            )),
            Box::new(JsonlAuditLog::new(layout.audit_log())),
            vec![Box::new(FakeBackend::available(BackendKind::Seatbelt))],
        );
        engine.init(&actor(), Confirm::Yes).unwrap();
        assert!(sandbox_list(&engine).unwrap().is_empty());
        create(
            &engine,
            &actor(),
            "lab".parse().unwrap(),
            "minimal".parse().unwrap(),
        )
        .unwrap();
        assert_eq!(
            sandbox_list(&engine).unwrap(),
            vec![SandboxInfo {
                sandbox: "lab".into(),
                runtime: None,
                state: "created".into()
            }]
        );
        assert!(engine.app_agents().unwrap().is_empty());
        let view = engine.show_sandbox(&"lab".parse().unwrap()).unwrap();
        assert_eq!(view.record.backend, BackendKind::Seatbelt);
        assert_eq!(view.template.as_str(), "minimal");
        let entries = engine.audit(None).unwrap();
        let created = entries
            .iter()
            .find(|entry| entry.intent.command == "sandbox create")
            .unwrap();
        assert_eq!(created.intent.by, actor());
        assert_eq!(created.intent.target.as_deref(), Some("lab"));
        assert!(
            create(
                &engine,
                &actor(),
                "lab".parse().unwrap(),
                "minimal".parse().unwrap()
            )
            .unwrap_err()
            .contains("already exists")
        );
    }

    #[test]
    fn creates_with_the_backend_sandbox_create_takes_when_the_config_names_none() {
        use crate::audit::jsonl::JsonlAuditLog;
        use crate::backend::fake::FakeBackend;
        use crate::state::sqlite::SqliteStateStore;

        let dir = tempfile::tempdir().unwrap();
        let layout = Layout::at(dir.path().join("data"));
        let engine = Engine::new(
            layout.clone(),
            Box::new(SqliteStateStore::new(
                layout.state_db(),
                layout.state_lock(),
                crate::state::Wait::Command,
            )),
            Box::new(JsonlAuditLog::new(layout.audit_log())),
            vec![
                Box::new(FakeBackend::unavailable(BackendKind::Seatbelt, "not here")),
                Box::new(FakeBackend::available(BackendKind::Bubblewrap)),
            ],
        );
        engine.init(&actor(), Confirm::Yes).unwrap();
        // A config.toml that names no default backend, as `sandbox create`
        // reads one: the first backend available here
        let config = std::fs::read_to_string(layout.config_file()).unwrap();
        let without: String = config
            .lines()
            .filter(|line| !line.trim_start().starts_with("default_backend"))
            .map(|line| format!("{line}\n"))
            .collect();
        std::fs::write(layout.config_file(), without).unwrap();
        create(
            &engine,
            &actor(),
            "lab".parse().unwrap(),
            "minimal".parse().unwrap(),
        )
        .unwrap();
        let view = engine.show_sandbox(&"lab".parse().unwrap()).unwrap();
        assert_eq!(view.record.backend, BackendKind::Bubblewrap);
        // One that names something else than a backend is refused, as by
        // `sandbox create`
        std::fs::write(layout.config_file(), "default_backend = \"docker\"\n").unwrap();
        assert!(
            create(
                &engine,
                &actor(),
                "lab2".parse().unwrap(),
                "minimal".parse().unwrap()
            )
            .is_err()
        );
    }

    #[test]
    fn installs_in_a_child_with_exact_arguments_layout_no_input_and_no_yes() {
        let (_dir, host) = fake_host(
            r#"
test "$#" = 7 && test "$1" = --json && test "$2" = runtime && test "$3" = install && test "$4" = hermes && test "$5" = --sandbox && test "$6" = lab && test "$7" = "--requested-by=owner@example.org (device phone-1)" || exit 10
test -n "$ENCLOS_HOME" || exit 11
if read -r ignored; then exit 12; fi
printf '%s\n' '{"sandbox":"lab","runtime":"hermes","installed":true,"login":"enclos connect lab -- hermes setup"}'
"#,
        );
        let done = host
            .execute(
                &Operation::install("lab", "hermes").unwrap(),
                &device_actor(),
            )
            .unwrap();
        assert!(
            matches!(done, Completed::Installed { runtime, login } if runtime == "hermes" && login == "enclos connect lab -- hermes setup")
        );
    }

    #[test]
    fn child_failures_malformed_and_mismatched_results_are_not_successes() {
        for (body, expected) in [
            (
                r#"printf '%s\n' '{"error":{"message":"the policy needs host review"}}'; exit 1"#,
                "the policy needs host review",
            ),
            ("printf 'not json'; exit 1", "without a readable result"),
            (
                r#"printf '%s\n' '{"sandbox":"lab","runtime":"hermes","installed":true,"login":"setup"}'; exit 1"#,
                "not installed",
            ),
            (
                r#"printf '%s\n' '{"sandbox":"other","runtime":"hermes","installed":true,"login":"setup"}'"#,
                "mismatched result",
            ),
            (
                r#"printf '%s\n' '{"sandbox":"lab","runtime":"hermes","installed":true}'"#,
                "incomplete or mismatched result",
            ),
        ] {
            let (_dir, host) = fake_host(body);
            let why = host
                .execute(
                    &Operation::install("lab", "hermes").unwrap(),
                    &device_actor(),
                )
                .unwrap_err();
            assert!(why.contains(expected), "{why}");
        }
    }

    #[test]
    fn background_stderr_does_not_hold_install_completion_open() {
        let (_dir, host) = fake_host(
            r#"
sleep 5 >/dev/null &
printf '%s\n' '{"sandbox":"lab","runtime":"hermes","installed":true,"login":"enclos connect lab -- hermes setup"}'
"#,
        );
        let start = std::time::Instant::now();
        host.execute(
            &Operation::install("lab", "hermes").unwrap(),
            &device_actor(),
        )
        .unwrap();
        assert!(start.elapsed() < std::time::Duration::from_secs(3));
    }

    #[test]
    fn rejects_paths_options_unknown_runtimes_and_custom_templates() {
        for name in ["../home", "--yes", "Home", "a", "home;id"] {
            assert!(Operation::create(name, "minimal").is_err());
            assert!(Operation::install(name, "hermes").is_err());
        }
        assert!(Operation::create("home", "coding").is_err());
        assert!(Operation::install("home", "unknown").is_err());
        assert!(Operation::create("home", "minimal").is_ok());
        assert!(Operation::create("home", "assistant").is_ok());
    }

    #[test]
    fn output_is_drained_without_retaining_unbounded_installer_output() {
        let mut input = std::io::Cursor::new(vec![42; 100_000]);
        assert_eq!(read_bounded(&mut input, 16).unwrap(), vec![42; 16]);
        assert_eq!(input.position(), 100_000);
    }
}
