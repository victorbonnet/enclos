//! The host owner's small provisioning surface for the mobile app. Every
//! change goes through the same engine and audit log as its CLI command.

use std::io::Read;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use enclos_protocol::device::{RuntimeInfo, SandboxAgentInfo, SandboxInfo};
use serde_json::Value;

use crate::engine::{Engine, SandboxSpec};
use crate::layout::Layout;
use crate::model::agent::AgentName;
use crate::model::audit::Actor;
use crate::model::plan::{Confirm, Planned};
use crate::model::policy::TemplateName;
use crate::model::runtime::RuntimeKind;
use crate::model::sandbox::{BackendKind, SandboxName, SandboxState};

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
    AgentCreate {
        name: SandboxName,
        agent: AgentName,
    },
    AgentConnect {
        name: SandboxName,
        agent: AgentName,
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

    pub fn create_agent(sandbox: &str, agent: &str) -> Result<Self, String> {
        Ok(Self::AgentCreate {
            name: sandbox
                .parse::<SandboxName>()
                .map_err(|error| error.to_string())?,
            agent: agent
                .parse::<AgentName>()
                .map_err(|error| error.to_string())?,
        })
    }

    pub fn connect_agent(sandbox: &str, agent: &str) -> Result<Self, String> {
        Ok(Self::AgentConnect {
            name: sandbox
                .parse::<SandboxName>()
                .map_err(|error| error.to_string())?,
            agent: agent
                .parse::<AgentName>()
                .map_err(|error| error.to_string())?,
        })
    }

    pub fn sandbox(&self) -> &str {
        match self {
            Self::Create { name, .. }
            | Self::Install { name, .. }
            | Self::AgentCreate { name, .. }
            | Self::AgentConnect { name, .. } => name.as_str(),
        }
    }

    pub fn verb(&self) -> &'static str {
        match self {
            Self::Create { .. } => "sandbox.create",
            Self::Install { .. } => "runtime.install",
            Self::AgentCreate { .. } => "agent.create",
            Self::AgentConnect { .. } => "agent.connect",
        }
    }

    pub fn progress(&self) -> &'static str {
        match self {
            Self::Create { .. } => "Creating the sandbox and its policy…",
            Self::Install { .. } => {
                "Downloading and running the runtime's installer inside the sandbox. This can take several minutes…"
            }
            Self::AgentCreate { .. } => "Creating the agent inside its sandbox…",
            Self::AgentConnect { .. } => {
                "Connecting the agent to the app and restarting its sandbox…"
            }
        }
    }
}

#[derive(Debug)]
pub enum Completed {
    Created,
    Installed {
        runtime: String,
        login: String,
    },
    AgentCreated {
        agent: String,
        runtime: String,
        setup: String,
    },
    AgentConnected {
        agent: String,
        runtime: String,
    },
}

/// Data a worker needs to open its own engine and to identify its caller in
/// the audit log. It contains no connection, database or device keys.
pub struct Host {
    layout: Layout,
    actor: Actor,
    executable: PathBuf,
    owner: Option<String>,
}

impl Host {
    pub fn new(layout: Layout, actor: Actor, executable: PathBuf, owner: Option<String>) -> Self {
        Self {
            layout,
            actor,
            executable,
            owner: owner.filter(|p| !p.trim().is_empty()),
        }
    }

    /// Unknown ownership fails closed. A paired device alone does not make
    /// its person the host's user (sharing may pair other people).
    pub fn owner(&self) -> Option<&str> {
        self.owner.as_deref()
    }

    pub fn is_owner(&self, person: &str) -> bool {
        self.owner.as_deref() == Some(person)
    }

    pub fn sandboxes(&self) -> Result<Vec<SandboxInfo>, String> {
        sandbox_list(&Engine::open(self.layout.clone()))
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

    pub fn sandbox_agents(&self, sandbox: &str) -> Result<Vec<SandboxAgentInfo>, String> {
        let name = sandbox
            .parse::<SandboxName>()
            .map_err(|error| error.to_string())?;
        sandbox_agents(&Engine::open(self.layout.clone()), &name)
    }

    /// Refreshes from host state, so setting up a new sandbox's app channel
    /// never needs a bridge restart.
    pub fn agents(&self) -> Result<Vec<super::server::AgentEndpoint>, String> {
        let engine = Engine::open(self.layout.clone());
        let mut agents = Vec::new();
        for (sandbox, agent, runtime) in engine.app_agents().map_err(|e| e.to_string())? {
            if let Ok(endpoint) = engine.app_endpoint(&sandbox, &agent) {
                agents.push(super::server::AgentEndpoint {
                    name: format!("{sandbox}/{agent}"),
                    runtime,
                    socket: endpoint.socket,
                    token: endpoint.token.expose().to_owned(),
                });
            }
        }
        Ok(agents)
    }

    pub fn execute(&self, operation: &Operation, person: &str) -> Result<Completed, String> {
        if !self.is_owner(person) {
            return Err("only the host's user can manage sandboxes and agents".to_owned());
        }
        // The authenticated transport login identifies who requested the
        // change; the host is the one executing it.
        let actor = Actor {
            user: person.to_owned(),
            host: self.actor.host.clone(),
        };
        match operation {
            Operation::Create { name, template } => {
                let engine = Engine::open(self.layout.clone());
                create(
                    &engine,
                    &actor,
                    &self.layout,
                    name.clone(),
                    template.clone(),
                )?;
                Ok(Completed::Created)
            }
            Operation::Install { name, runtime } => self.install(name, *runtime),
            Operation::AgentCreate { name, agent } => self.agent_operation(name, agent, false),
            Operation::AgentConnect { name, agent } => self.agent_operation(name, agent, true),
        }
    }

    fn agent_operation(
        &self,
        name: &SandboxName,
        agent: &AgentName,
        connecting: bool,
    ) -> Result<Completed, String> {
        let target = format!("{name}/{agent}");
        let verb = if connecting { "connect" } else { "add" };
        let option = if connecting { "--restart" } else { "--new" };
        let result = self.command_result(
            &["--json", "agent", verb, &target, option],
            "agent operation",
        )?;
        if connecting {
            if result["sandbox"].as_str() != Some(name.as_str())
                || result["agent"].as_str() != Some(agent.as_str())
                || result["app_channel"].as_bool() != Some(true)
            {
                return Err("the app connection returned an incomplete or mismatched result; refresh the sandbox before trying again".to_owned());
            }
        } else if result["agent"].as_str() != Some(target.as_str())
            || result["how"].as_str() != Some("created")
        {
            return Err("the agent was not created as a new profile; refresh the sandbox before trying again".to_owned());
        }
        let runtime = result["runtime"]
            .as_str()
            .filter(|value| value.parse::<RuntimeKind>().is_ok())
            .ok_or_else(|| "the agent operation returned no known runtime".to_owned())?
            .to_owned();
        Ok(if connecting {
            Completed::AgentConnected {
                agent: agent.to_string(),
                runtime,
            }
        } else {
            Completed::AgentCreated {
                agent: agent.to_string(),
                runtime,
                setup: format!("enclos agent connect {target} --restart"),
            }
        })
    }

    fn command_result(&self, arguments: &[&str], label: &str) -> Result<Value, String> {
        let mut child = Command::new(&self.executable)
            .args(arguments)
            .envs(self.layout.env())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .process_group(0)
            .spawn()
            .map_err(|error| format!("cannot start the {label}: {error}"))?;
        let stdout = child.stdout.take().expect("piped stdout");
        let output = std::thread::spawn(move || read_bounded(stdout, 65_536));
        let status = child
            .wait()
            .map_err(|error| format!("cannot wait for the {label}: {error}"))?;
        let bytes = output
            .join()
            .map_err(|_| format!("cannot read the {label} result"))??;
        let result: Value = serde_json::from_slice(&bytes)
            .map_err(|_| format!("the {label} exited with {status} without a readable result; check the sandbox on the host"))?;
        if let Some(message) = result["error"]["message"].as_str() {
            return Err(message.to_owned());
        }
        if !status.success() {
            return Err(format!(
                "the {label} failed; refresh the sandbox and check it on the host"
            ));
        }
        Ok(result)
    }

    fn install(&self, name: &SandboxName, runtime: RuntimeKind) -> Result<Completed, String> {
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
        // Drain stdout concurrently, retaining only a bounded JSON document.
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

fn sandbox_agents(engine: &Engine, name: &SandboxName) -> Result<Vec<SandboxAgentInfo>, String> {
    use std::collections::BTreeSet;
    engine
        .require_sandbox(name)
        .map_err(|error| error.to_string())?;
    let Some(kind) = engine.runtime(name).map_err(|error| error.to_string())? else {
        return Ok(Vec::new());
    };
    let runtime = crate::runtime::adapter(kind);
    let found = runtime
        .agents_in(&engine.sandbox_home(name))
        .map_err(|why| format!("cannot read the runtime's agents in sandbox {name}: {why}"))?;
    let mut names = found
        .into_iter()
        .filter_map(|agent| agent.as_str().parse::<AgentName>().ok())
        .collect::<BTreeSet<_>>();
    if let Some(builtin) = runtime.builtin_agent() {
        names.insert(builtin.agent_name());
    }
    let configured = engine.app_agents().map_err(|error| error.to_string())?;
    Ok(names
        .into_iter()
        .map(|agent| SandboxAgentInfo {
            app_channel: configured
                .iter()
                .any(|(sandbox, candidate, _)| sandbox == name && candidate == agent.as_str()),
            agent: agent.to_string(),
            runtime: kind.to_string(),
        })
        .collect())
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

fn create(
    engine: &Engine,
    actor: &Actor,
    layout: &Layout,
    name: SandboxName,
    template: TemplateName,
) -> Result<(), String> {
    let text = layout.read_config().map_err(|e| e.to_string())?;
    let config: toml::Table = text.parse().map_err(|e: toml::de::Error| e.to_string())?;
    let backend = config
        .get("default_backend")
        .and_then(toml::Value::as_str)
        .ok_or_else(|| "the host has no default backend; run enclos init on the host".to_owned())?
        .parse::<BackendKind>()
        .map_err(|e| e.to_string())?;
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
    use std::os::unix::fs::PermissionsExt;

    fn actor() -> Actor {
        Actor {
            user: "owner@example.org".into(),
            host: "mac".into(),
        }
    }

    fn fake_host(body: &str) -> (tempfile::TempDir, Host) {
        let dir = tempfile::tempdir().unwrap();
        let executable = dir.path().join("enclos");
        std::fs::write(&executable, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
        let host = Host::new(
            Layout::at(dir.path().join("data")),
            actor(),
            executable,
            Some("owner@example.org".into()),
        );
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
            )),
            Box::new(JsonlAuditLog::new(layout.audit_log())),
            vec![Box::new(FakeBackend::available(BackendKind::Seatbelt))],
        );
        engine.init(&actor(), Confirm::Yes).unwrap();
        assert!(sandbox_list(&engine).unwrap().is_empty());
        create(
            &engine,
            &actor(),
            &layout,
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
        assert!(
            sandbox_agents(&engine, &"lab".parse().unwrap())
                .unwrap()
                .is_empty()
        );
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
                &layout,
                "lab".parse().unwrap(),
                "minimal".parse().unwrap()
            )
            .unwrap_err()
            .contains("already exists")
        );
        // Management inventory includes runtime profiles before chat setup,
        // including valid profiles the host has not explicitly tracked yet.
        use crate::state::StateStore;
        let state = SqliteStateStore::new(layout.state_db(), layout.state_lock());
        let name = "lab".parse().unwrap();
        let lock = state.lock().unwrap();
        let mut record = state.get(&name).unwrap().unwrap();
        record.runtime = Some(RuntimeKind::Hermes);
        state.put(&lock, &record).unwrap();
        drop(lock);
        let profiles = layout.sandbox_home("lab").join(".hermes/profiles");
        for profile in ["scout", "my_bot"] {
            std::fs::create_dir_all(profiles.join(profile)).unwrap();
            std::fs::write(profiles.join(profile).join("config.yaml"), "").unwrap();
        }
        let inventory = sandbox_agents(&engine, &name).unwrap();
        assert_eq!(
            inventory
                .iter()
                .map(|agent| agent.agent.as_str())
                .collect::<Vec<_>>(),
            ["default", "scout"]
        );
        assert!(
            inventory
                .iter()
                .all(|agent| agent.runtime == "hermes" && !agent.app_channel)
        );
    }

    #[test]
    fn installs_in_a_child_with_exact_arguments_layout_no_input_and_no_yes() {
        let (_dir, host) = fake_host(
            r#"
test "$#" = 6 && test "$1" = --json && test "$2" = runtime && test "$3" = install && test "$4" = hermes && test "$5" = --sandbox && test "$6" = lab || exit 10
test -n "$ENCLOS_HOME" || exit 11
if read -r ignored; then exit 12; fi
printf '%s\n' '{"sandbox":"lab","runtime":"hermes","installed":true,"login":"enclos connect lab -- hermes setup"}'
"#,
        );
        let done = host
            .execute(
                &Operation::install("lab", "hermes").unwrap(),
                "owner@example.org",
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
                    "owner@example.org",
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
            "owner@example.org",
        )
        .unwrap();
        assert!(start.elapsed() < std::time::Duration::from_secs(3));
    }

    #[test]
    fn ownership_is_explicit_and_exact() {
        let host = |owner| {
            Host::new(
                Layout::at("/unused"),
                Actor {
                    user: "local".into(),
                    host: "mac".into(),
                },
                PathBuf::from("/unused/enclos"),
                owner,
            )
        };
        assert!(!host(None).is_owner("owner@example.org"));
        assert!(!host(Some("".into())).is_owner(""));
        let host = host(Some("owner@example.org".into()));
        assert!(host.is_owner("owner@example.org"));
        assert!(!host.is_owner("shared@example.org"));
        let operation = Operation::install("home", "hermes").unwrap();
        assert!(
            host.execute(&operation, "shared@example.org")
                .unwrap_err()
                .contains("only the host's user")
        );
    }

    #[test]
    fn agent_children_have_exact_noninteractive_arguments_and_correlated_results() {
        for (operation, expected_args, result) in [
            (
                Operation::create_agent("lab", "scout").unwrap(),
                "--json agent add lab/scout --new",
                r#"{"agent":"lab/scout","runtime":"hermes","how":"created"}"#,
            ),
            (
                Operation::connect_agent("lab", "scout").unwrap(),
                "--json agent connect lab/scout --restart",
                r#"{"sandbox":"lab","agent":"scout","runtime":"hermes","app_channel":true}"#,
            ),
        ] {
            let body = format!(
                "test \"$*\" = '{expected_args}' || exit 10\nif read -r ignored; then exit 12; fi\nprintf '%s\\n' '{result}'\n"
            );
            let (_dir, host) = fake_host(&body);
            match host.execute(&operation, "owner@example.org").unwrap() {
                Completed::AgentCreated {
                    agent,
                    runtime,
                    setup,
                } => {
                    assert_eq!(agent, "scout");
                    assert_eq!(runtime, "hermes");
                    assert_eq!(setup, "enclos agent connect lab/scout --restart");
                }
                Completed::AgentConnected { agent, runtime } => {
                    assert_eq!(agent, "scout");
                    assert_eq!(runtime, "hermes");
                }
                _ => panic!("wrong completion"),
            }
        }
    }

    #[test]
    fn create_refuses_adoption_and_connect_refuses_wrong_or_failed_results() {
        for (connect, result) in [
            (
                false,
                r#"{"agent":"lab/scout","runtime":"hermes","how":"adopted"}"#,
            ),
            (
                true,
                r#"{"sandbox":"other","agent":"scout","runtime":"hermes","app_channel":true}"#,
            ),
            (
                true,
                r#"{"sandbox":"lab","agent":"scout","runtime":"hermes","app_channel":false}"#,
            ),
            (
                true,
                r#"{"error":{"message":"a different policy is pending"}}"#,
            ),
        ] {
            let (_dir, host) = fake_host(&format!("printf '%s\\n' '{result}'\n"));
            let operation = if connect {
                Operation::connect_agent("lab", "scout")
            } else {
                Operation::create_agent("lab", "scout")
            }
            .unwrap();
            assert!(host.execute(&operation, "owner@example.org").is_err());
        }
        for invalid in ["../profile", "--yes", "my_bot", "", "a;id"] {
            assert!(Operation::create_agent("lab", invalid).is_err());
            assert!(Operation::connect_agent("lab", invalid).is_err());
        }
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
