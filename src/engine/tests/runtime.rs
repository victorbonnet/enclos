//! A runtime in a sandbox: its install, agents, settings, channels and
//! secrets, and its service's launch and stop (design §8, §9).

mod cgroups;

use super::policy::with_sandbox_on;
use super::*;
use crate::lifecycle::marker::spawn_unmarked;
use crate::model::agent::{AgentName, AgentRecord};
use crate::model::runtime::RuntimeKind;
use crate::runtime::RuntimeAgentName;
use crate::runtime::{
    HomeFile, Installer, RuntimeAdapter, SandboxCommand, Unreadable, hermes::Hermes,
};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

#[test]
fn an_installed_runtime_adds_its_endpoints_as_a_new_policy_version() {
    let (_dir, engine, name) = with_sandbox_on(FakeBackend::available(BackendKind::Seatbelt));
    engine
        .write(
            &alice(),
            "test",
            None,
            |_| String::new(),
            |lock| {
                let mut record = engine.state.get(&name)?.unwrap();
                record.runtime = Some(RuntimeKind::Hermes);
                engine.state.put(lock, &record)?;
                let overrides = engine.layout.read_policy("home")?;
                engine
                    .checked_policy(&name, &overrides)
                    .and_then(|s| engine.store_policy(lock, &alice(), &name, &overrides, &s, None))
            },
        )
        .unwrap();
    let view = engine.policy(&name).unwrap();
    assert_eq!(view.version.version, 2);
    assert!(
        view.snapshot
            .policy
            .net
            .allow
            .contains(&"chatgpt.com".to_owned())
    );
    assert_eq!(
        view.snapshot.inputs.adapter.as_ref().unwrap().runtime,
        "hermes"
    );
    // The adapter adds destinations and nothing else.
    let first = engine.state.policy_history(&name).unwrap()[0].clone();
    assert_eq!(first.version, 1);
    assert_eq!(view.snapshot.policy.fs.write, ["{home}"]);
    assert!(
        view.snapshot
            .policy
            .fs
            .read_deny
            .iter()
            .any(|p| p == "~/.ssh")
    );
}

#[test]
fn saving_the_active_policy_again_adds_no_version() {
    let (_dir, engine, name) = with_sandbox_on(FakeBackend::available(BackendKind::Seatbelt));
    for _ in 0..2 {
        engine
            .write(
                &alice(),
                "test",
                None,
                |_| String::new(),
                |lock| {
                    let overrides = engine.layout.read_policy("home")?;
                    engine.checked_policy(&name, &overrides).and_then(|s| {
                        engine.store_policy(lock, &alice(), &name, &overrides, &s, None)
                    })
                },
            )
            .unwrap();
    }
    assert_eq!(engine.policy(&name).unwrap().version.version, 1);
    assert_eq!(engine.state.policy_history(&name).unwrap().len(), 1);
}

#[test]
fn agents_need_a_runtime_first() {
    let (_dir, engine, name) = with_sandbox_on(FakeBackend::available(BackendKind::Seatbelt));
    let err = engine.agents(&name).unwrap_err();
    assert!(err.to_string().contains("no runtime yet"), "{err}");
    assert!(
        err.to_string()
            .contains("enclos runtime install hermes --sandbox home"),
        "{err}"
    );
}

/// Hermes's adapter with an installer of the test's own: `url` is a
/// `file://` URL to it and `sha256` its hash, which the audit entry should
/// name.
pub(super) struct TestRuntime {
    url: String,
    pub(super) sha256: String,
}

impl TestRuntime {
    pub(super) fn new(dir: &Path, script: &str) -> TestRuntime {
        let installer = dir.join("install.sh");
        std::fs::write(&installer, script).unwrap();
        let digest = <sha2::Sha256 as sha2::Digest>::digest(script.as_bytes());
        let sha256 = digest.iter().map(|b| format!("{b:02x}")).collect();
        TestRuntime {
            url: format!("file://{}", installer.display()),
            sha256,
        }
    }
}

impl RuntimeAdapter for TestRuntime {
    fn kind(&self) -> RuntimeKind {
        RuntimeKind::Hermes
    }
    fn version(&self) -> &'static str {
        Hermes.version()
    }
    fn endpoints(&self) -> &'static str {
        Hermes.endpoints()
    }
    fn installer(&self) -> Installer {
        Installer {
            url: self.url.clone(),
            args: vec!["--non-interactive".into()],
        }
    }
    fn home_files(&self, backend: BackendKind) -> Vec<HomeFile> {
        Hermes.home_files(backend)
    }
    fn login(&self) -> String {
        Hermes.login()
    }
    fn create_agent(&self, name: &AgentName) -> SandboxCommand {
        Hermes.create_agent(name)
    }
    fn agent_files(&self, name: &AgentName) -> String {
        Hermes.agent_files(name)
    }
    fn talk(&self, agent: &AgentName) -> String {
        Hermes.talk(agent)
    }
    fn services(&self) -> Vec<crate::runtime::RuntimeService> {
        Hermes.services()
    }
    fn agents_in(&self, home: &Path) -> std::result::Result<Vec<RuntimeAgentName>, Unreadable> {
        Hermes.agents_in(home)
    }
}

/// An installer that puts a `hermes` stub on the sandbox's PATH, which
/// records its calls in the home and fails while `hermes-fails` exists.
/// While `identity-pending` exists, its delete answers as Hermes 0.23.0's
/// does when the profile's session and routing records are not purged:
/// the folder removed, exit 1, naming `purge-identity`, which then succeeds
/// unless `purge-fails` exists. While `gateway-runs` exists, as a running
/// gateway owns every profile, its delete stops halfway, as Hermes
/// 0.23.0's does: the profile marked deleted, its folder kept, exit 1.
/// Its create copies `default`'s `config.yaml`, when there is one, as
/// `--clone-from` does.
pub(super) const INSTALLS: &str = "#!/bin/sh
mkdir -p \"$HOME/.local/bin\"
cat > \"$HOME/.local/bin/hermes\" <<'STUB'
#!/bin/sh
printf '%s\\n' \"$*\" >> \"$HOME/hermes-calls\"
[ -f \"$HOME/hermes-fails\" ] && exit 3
[ -f \"$HOME/hermes-token-fails\" ] && [ \"$5\" = platforms.telegram.token ] && exit 3
[ -f \"$HOME/hermes-after-fails\" ] && [ \"$5\" = secrets.command.enabled ] && exit 3
if [ \"$1 $2 $4 $5\" = \"profile create --clone-from default\" ] && [ -f \"$HOME/.hermes/config.yaml\" ]; then
  mkdir -p \"$HOME/.hermes/profiles/$3\"
  cp \"$HOME/.hermes/config.yaml\" \"$HOME/.hermes/profiles/$3/config.yaml\"
fi
if [ \"$1 $2\" = \"profile delete\" ] && [ -f \"$HOME/gateway-runs\" ]; then
  mkdir -p \"$HOME/.hermes/profiles/.deleted\"
  echo deleted > \"$HOME/.hermes/profiles/.deleted/$3\"
  echo \"Error: Could not remove profile directory $HOME/.hermes/profiles/$3: a running gateway still owns this profile; retry the delete once it settles\" >&2
  exit 1
fi
if [ \"$1 $2\" = \"profile delete\" ] && [ -f \"$HOME/identity-pending\" ]; then
  rm -rf \"$HOME/.hermes/profiles/$3\"
  echo \"Error: Profile '$3' was deleted, but its session/routing identity settlement is still pending — run: hermes profile purge-identity $3\" >&2
  exit 1
fi
[ \"$1 $2\" = \"profile purge-identity\" ] && [ -f \"$HOME/purge-fails\" ] && exit 1
if [ \"$1 $2\" = \"profile delete\" ] && [ ! -f \"$HOME/hermes-keeps\" ]; then
  rm -rf \"$HOME/.hermes/profiles/$3\"
fi
[ \"$2\" = import ] && cat \"$3\" > \"$HOME/imported-$5\"
exit 0
STUB
chmod 700 \"$HOME/.local/bin/hermes\"
echo \"installed $*\" > \"$HOME/installed\"
";

/// The number of `SIGUSR1`, which differs between the two systems.
const USR1: i32 = if cfg!(target_os = "macos") { 30 } else { 10 };

/// Engine tests start real proxies on this host's ports: one at a time,
/// with every other test run of this user too.
static HOST_PORTS: crate::host_ports::HostPorts = crate::host_ports::HostPorts;

/// `ask` again while it is `None`, the lock busy, as a service's wait
/// loop asks again: another test's child, forked while this test held
/// the state lock, holds a copy of its descriptor until it execs, and so
/// the lock, a moment after this test dropped it.
fn answered<T>(mut ask: impl FnMut() -> Option<T>) -> Option<T> {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        let asked = ask();
        if asked.is_some() || std::time::Instant::now() > deadline {
            return asked;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// A sandbox whose proxy is a listener this test stands in (`nc`), so
/// that sessions can run through the fake backend; stopped when dropped,
/// so the listener never outlives the test.
struct Lab {
    _dir: TempDir,
    engine: Engine,
    name: SandboxName,
    home: PathBuf,
}

impl Lab {
    fn new() -> Lab {
        Lab::with_services(None)
    }

    /// A lab whose engine installs services through `services`.
    fn with_services(services: Option<Box<dyn crate::service::ServiceManager>>) -> Lab {
        Lab::build(services, None, None, &super::Root::usual())
    }

    /// A lab whose `launch` stops a session's members with `stop` once
    /// told to end.
    fn stopping_with(stop: crate::engine::StopMembers) -> Lab {
        Lab::build(None, Some(stop), None, &super::Root::usual())
    }

    /// A lab whose engine keeps secrets in `secrets`.
    fn with_secrets(secrets: Box<dyn crate::secrets::Stores>) -> Lab {
        Lab::build(None, None, Some(secrets), &super::Root::usual())
    }

    /// [`Lab::with_secrets`], enclos's folder at `root`.
    fn with_secrets_under(secrets: Box<dyn crate::secrets::Stores>, root: &super::Root) -> Lab {
        Lab::build(None, None, Some(secrets), root)
    }

    fn build(
        services: Option<Box<dyn crate::service::ServiceManager>>,
        stop: Option<crate::engine::StopMembers>,
        secrets: Option<Box<dyn crate::secrets::Stores>>,
        root: &super::Root,
    ) -> Lab {
        let (dir, engine, name) =
            super::policy::with_sandbox_under(FakeBackend::available(BackendKind::Seatbelt), root);
        let engine = match services {
            Some(services) => engine.with_services(services),
            None => engine,
        };
        let engine = match secrets {
            Some(secrets) => engine.with_secrets(secrets),
            None => engine,
        };
        let engine = match stop {
            Some(stop) => engine.with_stop_members(stop),
            None => engine,
        };
        let proxy = dir.path().join("proxy.sh");
        crate::test_scripts::write_script(
            &proxy,
            "echo \"fake proxy on port $5\" >&2\nexec /usr/bin/nc -lk 127.0.0.1 \"$5\"",
        );
        let home = engine.layout.sandbox_home("home");
        Lab {
            _dir: dir,
            engine: engine.with_exe(proxy),
            name,
            home,
        }
    }

    fn install(&self, script: &str, confirm: Confirm) -> Result<Planned<InstallEnd>> {
        let runtime = TestRuntime::new(self._dir.path(), script);
        self.engine
            .install_runtime_with(&alice(), &self.name, &runtime, confirm)
    }

    fn runtime(&self) -> Option<RuntimeKind> {
        self.engine.state.get(&self.name).unwrap().unwrap().runtime
    }

    fn allows(&self, host: &str) -> bool {
        self.engine
            .policy(&self.name)
            .unwrap()
            .snapshot
            .policy
            .net
            .allow
            .contains(&host.to_owned())
    }

    fn audit(&self) -> String {
        self.engine
            .audit(None)
            .unwrap()
            .iter()
            .map(|e| format!("{} {:?}", e.intent.command, e.finished))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// The summary of the last finished audit entry for `command`.
    fn summary(&self, command: &str) -> String {
        self.engine
            .audit(None)
            .unwrap()
            .into_iter()
            .rfind(|e| e.intent.command == command)
            .and_then(|e| e.finished)
            .map(|f| f.outcome.message)
            .unwrap_or_else(|| panic!("no finished {command} entry"))
    }
}

impl Drop for Lab {
    fn drop(&mut self) {
        let _ = self.engine.stop_sandbox(&alice(), &self.name, Confirm::Yes);
    }
}

#[test]
fn a_dry_run_of_an_install_says_what_it_would_change_and_changes_nothing() {
    let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
    let lab = Lab::new();
    let entries = lab.engine.audit(None).unwrap().len();
    let Planned::DryRun(plan) = lab.install(INSTALLS, Confirm::DryRun).unwrap() else {
        panic!("a dry run installed");
    };
    let plan = plan.changes.join("\n");
    assert!(
        plan.contains("allow the 14 destinations hermes needs"),
        "{plan}"
    );
    // Listening is what the adapter brings, like its destinations: named,
    // and not an "also" change that would ask first (ADR 0028).
    assert!(
        plan.contains("let sandbox home listen on TCP for hermes"),
        "{plan}"
    );
    assert!(!plan.contains("also "), "{plan}");
    assert!(
        plan.contains("download the hermes installer from file://"),
        "{plan}"
    );
    // A Seatbelt sandbox's host: the line a Mac has always shown.
    assert!(
        plan.contains(" on this Mac, as it is served now (ADR 0029)"),
        "{plan}"
    );
    assert!(plan.contains("start the proxy"), "{plan}");
    assert_eq!(lab.engine.audit(None).unwrap().len(), entries);
    assert_eq!(lab.runtime(), None);
    assert_eq!(lab.engine.policy(&lab.name).unwrap().version.version, 1);
    assert!(!lab.home.join("bin/mktemp").exists());
}

/// `policy.toml` keeping listening off wins over the adapter, and the
/// plan says Hermes's gateway then cannot start (ADR 0028).
#[test]
fn an_install_says_when_policy_toml_keeps_listening_off() {
    let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
    let lab = Lab::new();
    let toml = lab.engine.layout.read_policy("home").unwrap();
    let off = toml.replace("[network]", "[network]\nlisten = false");
    lab.engine.layout.write_policy("home", &off).unwrap();
    let Planned::DryRun(plan) = lab.install(INSTALLS, Confirm::DryRun).unwrap() else {
        panic!("a dry run installed");
    };
    let plan = plan.changes.join("\n");
    assert!(
        plan.contains("keep sandbox home from listening, as its policy.toml sets `listen = false`: hermes's service cannot start"),
        "{plan}"
    );
    assert!(!plan.contains("listen on TCP for hermes"), "{plan}");
    done(lab.install(INSTALLS, Confirm::Yes).unwrap());
    assert!(
        !lab.engine
            .policy(&lab.name)
            .unwrap()
            .snapshot
            .policy
            .net
            .listen
    );
}

#[test]
fn an_installer_not_served_over_https_is_not_downloaded() {
    let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
    let lab = Lab::new();
    let mut runtime = TestRuntime::new(lab._dir.path(), INSTALLS);
    // Nothing listens here, so a curl that tried would exit 7 (could
    // not connect); it exits 1, unsupported protocol, before trying.
    runtime.url = "http://127.0.0.1:9/install.sh".into();
    let err = lab
        .engine
        .install_runtime_with(&alice(), &lab.name, &runtime, Confirm::Yes)
        .unwrap_err();
    let text = err.to_string();
    assert!(
        text.contains(
            "could not download http://127.0.0.1:9/install.sh: it is not served over HTTPS"
        ) && text.contains("Update enclos"),
        "{text}"
    );
    assert_eq!(lab.runtime(), None);
    assert!(!lab.allows("chatgpt.com"));
    assert_eq!(lab.engine.policy(&lab.name).unwrap().version.version, 1);
    let installers = lab.engine.layout.sandbox_dir("home").join("installers");
    assert!(std::fs::read_dir(&installers).unwrap().all(|e| {
        !e.unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with("hermes-install")
    }));
    assert!(
        std::fs::read_dir(&installers)
            .unwrap()
            .all(|e| { !e.unwrap().file_name().to_string_lossy().ends_with(".part") })
    );
    assert!(!lab.audit().contains("runtime install"), "{}", lab.audit());
}

#[test]
fn any_installer_runs_and_the_audit_names_its_hash() {
    // Whatever version the runtime serves (ADR 0029): the entry names
    // what ran.
    let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
    let lab = Lab::new();
    let runtime = TestRuntime::new(lab._dir.path(), INSTALLS);
    let Planned::Done(end) = lab
        .engine
        .install_runtime_with(&alice(), &lab.name, &runtime, Confirm::Yes)
        .unwrap()
    else {
        panic!("a dry run");
    };
    assert!(end.installed, "{end:?}");
    let audit = lab.audit();
    assert!(
        audit.contains(&format!("installer sha256 {}", runtime.sha256)),
        "{audit}"
    );
    // At a path of its own hash, so an install running at the same time
    // with another version cannot replace what this one runs.
    let installers = lab.engine.layout.sandbox_dir("home").join("installers");
    let named = format!("hermes-install-{}.sh", runtime.sha256);
    assert_eq!(
        std::fs::read(installers.join(&named)).unwrap(),
        INSTALLS.as_bytes()
    );
    assert!(
        std::fs::read_dir(&installers)
            .unwrap()
            .all(|e| { !e.unwrap().file_name().to_string_lossy().ends_with(".part") })
    );
}

#[test]
fn an_installer_that_fails_leaves_the_sandbox_as_before() {
    let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
    let lab = Lab::new();
    let end = done(lab.install("#!/bin/sh\nexit 3\n", Confirm::Yes).unwrap());
    assert!(!end.installed);
    assert_eq!(end.recorded, None);
    assert_eq!(end.end.exit, 3);
    assert_eq!(lab.runtime(), None);
    assert!(!lab.allows("chatgpt.com"));
    // The destinations came and went: two versions, back to the first's content.
    let history = lab.engine.state.policy_history(&lab.name).unwrap();
    assert_eq!(history.len(), 3);
    assert_eq!(end.policy, 3);
    let audit = lab.audit();
    assert!(audit.contains("runtime install failed"), "{audit}");
    assert!(!audit.contains("runtime installed"), "{audit}");
    assert_eq!(
        lab.summary("runtime install failed"),
        "the installer exited with 3; policy v3 without hermes's destinations"
    );
    // The home file was put in place from inside the sandbox before.
    assert!(lab.home.join("bin/mktemp").is_file());
}

#[test]
fn a_reinstall_that_fails_keeps_the_runtime_and_its_destinations() {
    let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
    let lab = Lab::new();
    assert!(done(lab.install(INSTALLS, Confirm::Yes).unwrap()).installed);
    let before = lab.engine.policy(&lab.name).unwrap();
    assert_eq!(before.version.version, 2);

    let end = done(lab.install("#!/bin/sh\nexit 3\n", Confirm::Yes).unwrap());
    assert!(!end.installed);
    assert_eq!(end.recorded, Some(RuntimeKind::Hermes));
    assert_eq!(end.end.exit, 3);
    // The sandbox is as before the reinstall: the runtime still
    // recorded, and the same active policy, which allows its endpoints.
    assert_eq!(lab.runtime(), Some(RuntimeKind::Hermes));
    assert!(lab.allows("chatgpt.com"));
    assert!(lab.allows("github.com"));
    let after = lab.engine.policy(&lab.name).unwrap();
    assert_eq!(end.policy, 2);
    assert_eq!(after.version.version, 2);
    assert_eq!(after.snapshot.id, before.snapshot.id);
    assert_eq!(lab.engine.state.policy_history(&lab.name).unwrap().len(), 2);
    assert_eq!(
        lab.summary("runtime install failed"),
        "the installer exited with 3; hermes still recorded as installed, under policy v2"
    );
}

#[test]
fn a_proxy_a_session_started_writes_where_enclos_logs_reads() {
    let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
    let lab = Lab::new();
    done(lab.install("#!/bin/sh\nexit 3\n", Confirm::Yes).unwrap());
    let files = lab.engine.log_files(&lab.name).unwrap();
    assert_eq!(files.len(), 1, "{files:?}");
    let text = std::fs::read_to_string(&files[0]).unwrap();
    assert!(text.contains("fake proxy on port "), "{text}");
}

#[test]
fn an_install_records_the_runtime_once_its_installer_exits_0_and_agents_follow() {
    let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
    let lab = Lab::new();
    let end = done(lab.install(INSTALLS, Confirm::Yes).unwrap());
    assert!(end.installed);
    assert_eq!(end.policy, 2);
    assert_eq!(lab.runtime(), Some(RuntimeKind::Hermes));
    assert!(lab.allows("chatgpt.com") && lab.allows("github.com"));
    let installed = lab.engine.policy(&lab.name).unwrap().snapshot.policy;
    assert!(installed.net.listen, "the gateway may listen (ADR 0028)");
    assert_eq!(
        std::fs::read_to_string(lab.home.join("installed")).unwrap(),
        "installed --non-interactive\n"
    );
    let mode = std::fs::metadata(lab.home.join("bin/mktemp"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o700);
    assert!(lab.audit().contains("runtime installed"), "{}", lab.audit());

    // A second install of the same runtime is allowed, another refused.
    let main: AgentName = "main".parse().unwrap();
    let Planned::DryRun(plan) = lab
        .engine
        .add_agent(&alice(), &lab.name, main.clone(), Confirm::DryRun)
        .unwrap()
    else {
        panic!("a dry run added");
    };
    assert_eq!(
        plan.changes,
        [
            "run `hermes profile create main --clone-from default` in sandbox home under policy v2",
            "run `hermes -p main config set secrets.command.enabled false` in sandbox home under policy v2",
            "record agent home/main"
        ]
    );
    assert!(!lab.home.join("hermes-calls").exists());

    let added = done(
        lab.engine
            .add_agent(&alice(), &lab.name, main.clone(), Confirm::Yes)
            .unwrap(),
    );
    assert_eq!(added.agent.name, main);
    let Added::Created(end) = &added.how else {
        panic!("adopted: {added:?}");
    };
    assert_eq!(end.exit, 0);
    assert_eq!(
        std::fs::read_to_string(lab.home.join("hermes-calls")).unwrap(),
        "profile create main --clone-from default\n-p main config set secrets.command.enabled false\n"
    );
    assert_eq!(lab.engine.agents(&lab.name).unwrap().len(), 1);
    // Twice is refused before the runtime runs again.
    let err = lab
        .engine
        .add_agent(&alice(), &lab.name, main.clone(), Confirm::Yes)
        .unwrap_err();
    assert!(err.to_string().contains("already has agent main"), "{err}");
    assert_eq!(
        std::fs::read_to_string(lab.home.join("hermes-calls")).unwrap(),
        "profile create main --clone-from default\n-p main config set secrets.command.enabled false\n"
    );
    // A clone whose copied `secrets.command` cannot be turned off would
    // read the built-in agent's secrets: not recorded, and said how to
    // finish by hand (ADR 0036).
    std::fs::write(lab.home.join("hermes-after-fails"), "").unwrap();
    let err = lab
        .engine
        .add_agent(&alice(), &lab.name, "other".parse().unwrap(), Confirm::Yes)
        .unwrap_err();
    assert!(matches!(err, Error::FailedAfter { .. }), "{err}");
    assert!(
        err.to_string().contains(
            "enclos connect home -- hermes -p other config set secrets.command.enabled false"
        ),
        "{err}"
    );
    assert_eq!(lab.engine.agents(&lab.name).unwrap().len(), 1);
    std::fs::remove_file(lab.home.join("hermes-after-fails")).unwrap();
    std::fs::write(
        lab.home.join("hermes-calls"),
        "profile create main --clone-from default\n-p main config set secrets.command.enabled false\n",
    )
    .unwrap();
    // A name that is a command on the sandbox's PATH is refused.
    let err = lab
        .engine
        .add_agent(&alice(), &lab.name, "curl".parse().unwrap(), Confirm::Yes)
        .unwrap_err();
    assert!(
        err.to_string().contains("command on the sandbox's PATH"),
        "{err}"
    );
    let err = lab
        .engine
        .add_agent(&alice(), &lab.name, "hermes".parse().unwrap(), Confirm::Yes)
        .unwrap_err();
    assert!(err.to_string().contains(".local/bin/hermes"), "{err}");

    // The runtime failing leaves no record, and says how to recover.
    std::fs::write(lab.home.join("hermes-fails"), "").unwrap();
    let err = lab
        .engine
        .add_agent(&alice(), &lab.name, "other".parse().unwrap(), Confirm::Yes)
        .unwrap_err();
    let text = err.to_string();
    assert!(
        text.contains("exit 3") && text.contains("~/.hermes/profiles/other"),
        "{text}"
    );
    assert_eq!(lab.engine.agents(&lab.name).unwrap().len(), 1);

    // The stub made no profile folder: nothing for Hermes to delete.
    let Planned::DryRun(plan) = lab
        .engine
        .remove_agent(&alice(), &lab.name, &main, false, Confirm::DryRun)
        .unwrap()
    else {
        panic!("a dry run removed");
    };
    assert_eq!(
        plan.changes,
        ["remove the record of agent home/main, which Hermes no longer has"]
    );
    assert_eq!(lab.engine.agents(&lab.name).unwrap().len(), 1);
    let removed = done(
        lab.engine
            .remove_agent(&alice(), &lab.name, &main, false, Confirm::Yes)
            .unwrap(),
    );
    assert_eq!(
        removed,
        AgentRemoved::RecordOnly {
            kind: RuntimeKind::Hermes,
            files: "~/.hermes/profiles/main".into(),
            why: FilesKept::RuntimeLacksIt,
        }
    );
    assert!(lab.engine.agents(&lab.name).unwrap().is_empty());
    let err = lab
        .engine
        .remove_agent(&alice(), &lab.name, &main, false, Confirm::Yes)
        .unwrap_err();
    assert!(err.to_string().contains("has no agent `main`"), "{err}");
}

#[test]
fn removing_an_agent_runs_the_runtimes_delete_then_removes_the_record() {
    let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
    let lab = Lab::new();
    assert!(done(lab.install(INSTALLS, Confirm::Yes).unwrap()).installed);
    let profile = |a: &str| {
        let dir = lab.home.join(".hermes/profiles").join(a);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("config.yaml"), "").unwrap();
        dir
    };
    let calls = || std::fs::read_to_string(lab.home.join("hermes-calls")).unwrap();
    for a in ["main", "kept", "broken"] {
        profile(a);
        done(
            lab.engine
                .add_agent(&alice(), &lab.name, a.parse().unwrap(), Confirm::Yes)
                .unwrap(),
        );
    }
    let main: AgentName = "main".parse().unwrap();

    // It asks first, and the dry run says what would go.
    let err = lab
        .engine
        .remove_agent(&alice(), &lab.name, &main, false, Confirm::Ask)
        .unwrap_err();
    assert!(matches!(err, Error::NeedsConfirmation { .. }), "{err}");
    let Planned::DryRun(plan) = lab
        .engine
        .remove_agent(&alice(), &lab.name, &main, false, Confirm::DryRun)
        .unwrap()
    else {
        panic!("a dry run removed");
    };
    assert_eq!(
        plan.changes,
        ["delete agent home/main and its files, with Hermes's own command"]
    );

    let removed = done(
        lab.engine
            .remove_agent(&alice(), &lab.name, &main, false, Confirm::Yes)
            .unwrap(),
    );
    assert_eq!(
        removed,
        AgentRemoved::Deleted {
            kind: RuntimeKind::Hermes
        }
    );
    assert!(
        calls().ends_with("profile delete main --yes\n"),
        "{}",
        calls()
    );
    assert!(!lab.home.join(".hermes/profiles/main").exists());
    let names: Vec<String> = lab
        .engine
        .agents(&lab.name)
        .unwrap()
        .iter()
        .map(|a| a.name.to_string())
        .collect();
    assert_eq!(names, ["broken", "kept"]);
    let audit = lab.audit();
    assert!(audit.contains("agent rm run"), "{audit}");
    assert!(audit.contains("deleted"), "{audit}");

    // Hermes failing leaves the record, and says how it ended.
    std::fs::write(lab.home.join("hermes-fails"), "").unwrap();
    let err = lab
        .engine
        .remove_agent(
            &alice(),
            &lab.name,
            &"broken".parse().unwrap(),
            false,
            Confirm::Yes,
        )
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("exited with 3") && err.contains("its record stays"),
        "{err}"
    );
    std::fs::remove_file(lab.home.join("hermes-fails")).unwrap();

    // Hermes saying it deleted an agent it still lists leaves the record.
    std::fs::write(lab.home.join("hermes-keeps"), "").unwrap();
    let err = lab
        .engine
        .remove_agent(
            &alice(),
            &lab.name,
            &"kept".parse().unwrap(),
            false,
            Confirm::Yes,
        )
        .unwrap_err()
        .to_string();
    assert!(err.contains("still lists it"), "{err}");
    assert_eq!(lab.engine.agents(&lab.name).unwrap().len(), 2);
}

/// A sandbox with Hermes's stub installed and `agents` added, each with a
/// profile folder Hermes lists.
fn lab_with_profiles(lab: &Lab, agents: &[&str]) {
    assert!(done(lab.install(INSTALLS, Confirm::Yes).unwrap()).installed);
    for a in agents {
        let dir = lab.home.join(".hermes/profiles").join(a);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("config.yaml"), "").unwrap();
        done(
            lab.engine
                .add_agent(&alice(), &lab.name, a.parse().unwrap(), Confirm::Yes)
                .unwrap(),
        );
    }
}

#[test]
fn an_agent_added_before_the_login_chose_a_provider_is_said_to_have_none() {
    let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
    let lab = Lab::new();
    assert!(done(lab.install(INSTALLS, Confirm::Yes).unwrap()).installed);
    let settings = lab.home.join(".hermes/config.yaml");
    let add = |a: &str| {
        done(
            lab.engine
                .add_agent(&alice(), &lab.name, a.parse().unwrap(), Confirm::Yes)
                .unwrap(),
        )
    };
    // Before the login: Hermes's own settings, which the new agent copies.
    std::fs::create_dir_all(lab.home.join(".hermes")).unwrap();
    std::fs::write(&settings, "model:\n  default: ''\n  provider: auto\n").unwrap();
    let early = add("early");
    assert_eq!(
        early.choose_provider.as_deref(),
        Some("hermes -p early model")
    );
    // After it, the new agent starts on the provider it chose.
    std::fs::write(
        &settings,
        "model:\n  default: gpt-5.5\n  provider: openai-codex\n",
    )
    .unwrap();
    assert_eq!(add("late").choose_provider, None);
    assert_eq!(
        std::fs::read_to_string(lab.home.join(".hermes/profiles/late/config.yaml")).unwrap(),
        "model:\n  default: gpt-5.5\n  provider: openai-codex\n"
    );
}

#[test]
fn a_delete_runs_with_the_gateway_stopped_and_a_half_deleted_agent_is_deleted_again() {
    use crate::runtime::ServiceName;
    use crate::service::fake::FakeServices;

    let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
    let fake = std::rc::Rc::new(FakeServices::default());
    let lab = Lab::with_services(Some(Box::new(std::rc::Rc::clone(&fake))));
    lab_with_profiles(&lab, &["writer", "reader", "other"]);
    let calls = || std::fs::read_to_string(lab.home.join("hermes-calls")).unwrap();
    let rm = |a: &str| {
        lab.engine.remove_agent(
            &alice(),
            &lab.name,
            &a.parse().unwrap(),
            false,
            Confirm::Yes,
        )
    };
    let profile = |a: &str| lab.home.join(".hermes/profiles").join(a);
    // A gateway that runs owns every profile; the service manager stops
    // and starts it.
    let runs = lab.home.join("gateway-runs");
    std::fs::write(&runs, "").unwrap();

    // Without its service installed, enclos cannot stop it: Hermes's
    // delete stops halfway and the record stays, saying what is left.
    let err = rm("writer").unwrap_err().to_string();
    assert!(
        err.contains("exited with 1 and left its folder (~/.hermes/profiles/writer), which Hermes no longer lists; its record stays")
            && err.contains("`enclos agent rm home/writer` runs Hermes's delete again"),
        "{err}"
    );
    assert!(profile("writer").exists());
    assert_eq!(lab.engine.agents(&lab.name).unwrap().len(), 3);

    // Installed, as `sandbox start` leaves it, the gateway stops while
    // Hermes deletes, then is installed again.
    let gateway = lab
        .engine
        .label(&lab.name, Unit::Runtime(ServiceName::new("gateway")))
        .unwrap();
    fake.seed(gateway.as_str());
    let on = runs.clone();
    *fake.on_stop.borrow_mut() = Some(Box::new(move |l| {
        if l.service() == "gateway" {
            let _ = std::fs::remove_file(&on);
        }
    }));
    let on = runs.clone();
    *fake.on_start.borrow_mut() = Some(Box::new(move |l| {
        if l.service() == "gateway" {
            std::fs::write(&on, "").unwrap();
        }
    }));
    let Planned::DryRun(plan) = lab
        .engine
        .remove_agent(
            &alice(),
            &lab.name,
            &agent("reader"),
            false,
            Confirm::DryRun,
        )
        .unwrap()
    else {
        panic!("a dry run removed");
    };
    assert_eq!(
        plan.changes,
        [
            format!("stop service {gateway}"),
            "delete agent home/reader and its files, with Hermes's own command".to_owned(),
            format!("install service {gateway} again"),
        ]
    );
    let err = lab
        .engine
        .remove_agent(&alice(), &lab.name, &agent("reader"), false, Confirm::Ask)
        .unwrap_err();
    assert!(
        err.to_string().contains(
            "deleting agent home/reader and its files, its service gateway stopped meanwhile"
        ),
        "{err}"
    );
    // The half-deleted agent first: Hermes's delete runs again and
    // finishes it.
    for a in ["writer", "reader"] {
        assert_eq!(
            done(rm(a).unwrap()),
            AgentRemoved::Deleted {
                kind: RuntimeKind::Hermes
            }
        );
        assert!(!profile(a).exists());
        assert!(
            calls().ends_with(&format!("profile delete {a} --yes\n")),
            "{}",
            calls()
        );
    }
    assert_eq!(fake.stopped.borrow().len(), 2);
    let started: Vec<String> = fake
        .started
        .borrow()
        .iter()
        .map(|u| u.label.to_string())
        .collect();
    assert_eq!(started, [gateway.to_string()]);
    let args = fake.started.borrow()[0].args.clone();
    assert_eq!(
        args,
        ["launch", "home", "gateway"].map(std::ffi::OsString::from)
    );
    assert!(runs.exists(), "the gateway runs again");
    let audit = lab.audit();
    assert!(
        audit.contains("services remove") && audit.contains("services start"),
        "{audit}"
    );
    assert_eq!(
        lab.summary("services start"),
        format!("installed {gateway} again")
    );

    // A gateway that cannot start again: the agent is deleted all the
    // same, and enclos says how to start it.
    *fake.refuse.borrow_mut() = Some("gateway".to_owned());
    let err = rm("other").unwrap_err().to_string();
    assert!(
        err.contains("its gateway could not start again")
            && err.contains("`enclos sandbox start home` starts its services again")
            && err.contains("after deleting agent home/other and its files, and its record"),
        "{err}"
    );
    assert!(!profile("other").exists());
    assert!(lab.engine.agents(&lab.name).unwrap().is_empty());
}

#[test]
fn a_delete_hermes_leaves_to_purge_is_finished_with_its_purge() {
    let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
    let lab = Lab::new();
    lab_with_profiles(&lab, &["main", "stuck"]);
    let calls = || std::fs::read_to_string(lab.home.join("hermes-calls")).unwrap();
    let rm = |a: &str| {
        lab.engine.remove_agent(
            &alice(),
            &lab.name,
            &a.parse().unwrap(),
            false,
            Confirm::Yes,
        )
    };
    // Hermes 0.23.0: the profile deleted, exit 1, the purge named.
    std::fs::write(lab.home.join("identity-pending"), "").unwrap();
    assert_eq!(
        done(rm("main").unwrap()),
        AgentRemoved::Deleted {
            kind: RuntimeKind::Hermes
        }
    );
    assert!(
        calls().ends_with("profile delete main --yes\nprofile purge-identity main\n"),
        "{}",
        calls()
    );
    assert!(!lab.home.join(".hermes/profiles/main").exists());
    let names: Vec<String> = lab
        .engine
        .agents(&lab.name)
        .unwrap()
        .iter()
        .map(|a| a.name.to_string())
        .collect();
    assert_eq!(names, ["stuck"]);

    // A purge that fails keeps the record, and says how to finish.
    std::fs::write(lab.home.join("purge-fails"), "").unwrap();
    let err = rm("stuck").unwrap_err().to_string();
    assert!(
        err.contains(
            "`hermes profile purge-identity stuck`, which finishes its delete, exited with 1"
        ) && err.contains("enclos connect home -- hermes profile purge-identity stuck")
            && err.contains("its record stays"),
        "{err}"
    );
    assert_eq!(lab.engine.agents(&lab.name).unwrap().len(), 1);
    // Once it is finished by hand, nothing is left: the record goes.
    assert_eq!(
        done(rm("stuck").unwrap()),
        AgentRemoved::RecordOnly {
            kind: RuntimeKind::Hermes,
            files: "~/.hermes/profiles/stuck".into(),
            why: FilesKept::RuntimeLacksIt,
        }
    );
    assert!(lab.engine.agents(&lab.name).unwrap().is_empty());
}

#[test]
fn an_agent_is_imported_with_the_runtime_s_own_import_and_its_archive_recorded() {
    let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
    let lab = Lab::new();
    done(lab.install(INSTALLS, Confirm::Yes).unwrap());
    // Larger than one read of the hashing buffer.
    let bytes: Vec<u8> = (0..200 * 1024).map(|i| (i % 251) as u8).collect();
    let archive = lab._dir.path().join("main-20261020.tar.gz");
    std::fs::write(&archive, &bytes).unwrap();
    let sha256 = crate::policy::sha256_hex(&bytes);
    let installers = lab.engine.layout.sandbox_dir("home").join("installers");
    let staged = installers.join(format!("agent-main.{}.tar.gz", std::process::id()));
    let planned = installers.join("agent-main.<pid>.tar.gz");
    let copies = || {
        std::fs::read_dir(&installers)
            .unwrap()
            .filter(|e| {
                e.as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with("agent-")
            })
            .count()
    };
    let main: AgentName = "main".parse().unwrap();

    // A dry run says what would happen and copies nothing.
    let Planned::DryRun(plan) = lab
        .engine
        .import_agent(&alice(), &lab.name, main.clone(), &archive, Confirm::DryRun)
        .unwrap()
    else {
        panic!("a dry run imported");
    };
    assert_eq!(
        plan.changes,
        [
            format!(
                "copy {} (sha256 {sha256} now) to a new file such as {}, beside the home of sandbox home, where the sandbox reads it and cannot write",
                archive.display(),
                planned.display()
            ),
            format!(
                "run `hermes profile import '{}' --name main` in sandbox home under policy v2: Hermes extracts the archive inside the sandbox",
                planned.display()
            ),
            "record agent home/main as imported from that archive".to_owned(),
        ]
    );
    assert_eq!(copies(), 0);
    assert!(!lab.home.join("hermes-calls").exists());

    // The runtime imports the staged copy inside the sandbox: the bytes
    // it reads are the archive's, and the copy goes once it served. The
    // archive and its hash are audited before the runtime runs, and
    // again with the record.
    let added = done(
        lab.engine
            .import_agent(&alice(), &lab.name, main.clone(), &archive, Confirm::Yes)
            .unwrap(),
    );
    assert_eq!(added.agent.name, main);
    let Added::Imported {
        end,
        archive: imported,
        copy_left,
    } = &added.how
    else {
        panic!("not imported: {:?}", added.how);
    };
    assert_eq!(end.exit, 0);
    assert_eq!(
        (imported.path.as_path(), imported.sha256.as_str()),
        (archive.as_path(), sha256.as_str())
    );
    assert!(copy_left.is_none());
    assert_eq!(
        std::fs::read_to_string(lab.home.join("hermes-calls")).unwrap(),
        format!(
            "profile import {} --name main\n-p main config set secrets.command.enabled false\n",
            staged.display()
        )
    );
    assert_eq!(
        std::fs::read(lab.home.join("imported-main")).unwrap(),
        bytes
    );
    assert!(!staged.exists());
    assert_eq!(lab.engine.agents(&lab.name).unwrap().len(), 1);
    // Read afresh each time: the audit log grows below.
    let outcome = |command: &str| {
        lab.engine
            .audit(None)
            .unwrap()
            .iter()
            .filter(|e| e.intent.command == command)
            .map(|e| e.finished.as_ref().unwrap().outcome.message.clone())
            .collect::<Vec<_>>()
    };
    assert_eq!(
        outcome("agent import"),
        [format!(
            "copied {} (sha256 {sha256}) to {}",
            archive.display(),
            staged.display()
        )]
    );
    // The import, then the copied `secrets.command` turned off.
    assert_eq!(outcome("agent import session").len(), 2);
    assert_eq!(
        outcome("agent add"),
        [format!(
            "imported from {} (sha256 {sha256})",
            archive.display()
        )]
    );
    // In that order: the copy is audited before the runtime runs.
    let commands: Vec<String> = lab
        .engine
        .audit(None)
        .unwrap()
        .into_iter()
        .map(|e| e.intent.command)
        .filter(|c| c.starts_with("agent "))
        .collect();
    assert_eq!(
        commands,
        [
            "agent import",
            "agent import session",
            "agent import session",
            "agent add"
        ]
    );

    // Refused before the archive is read: a known name, and a name that
    // is a command on the sandbox's PATH.
    let err = lab
        .engine
        .import_agent(&alice(), &lab.name, main.clone(), &archive, Confirm::Yes)
        .unwrap_err();
    assert!(err.to_string().contains("already has agent main"), "{err}");
    let missing = lab._dir.path().join("missing.tar.gz");
    let err = lab
        .engine
        .import_agent(
            &alice(),
            &lab.name,
            "curl".parse().unwrap(),
            &missing,
            Confirm::Yes,
        )
        .unwrap_err();
    assert!(
        err.to_string().contains("command on the sandbox's PATH"),
        "{err}"
    );

    // An archive that is not a plain file of the user's own is refused.
    let other: AgentName = "other".parse().unwrap();
    let refused = |path: &Path, what: &str| {
        let err = lab
            .engine
            .import_agent(&alice(), &lab.name, other.clone(), path, Confirm::Yes)
            .unwrap_err();
        assert!(err.to_string().contains(what), "{what}: {err}");
    };
    refused(&missing, "missing.tar.gz");
    refused(&missing, "Name an export");
    refused(lab._dir.path(), "is not a file");
    let link = lab._dir.path().join("link.tar.gz");
    std::os::unix::fs::symlink(&archive, &link).unwrap();
    refused(&link, "is a link");
    let inside = lab.home.join("export.tar.gz");
    std::fs::write(&inside, &bytes).unwrap();
    refused(&inside, "under a sandbox's folder");
    // Also through a link in a parent folder, and through `..`: only
    // where the opened file really is counts.
    let linked = lab._dir.path().join("exports");
    std::os::unix::fs::symlink(&lab.home, &linked).unwrap();
    refused(&linked.join("export.tar.gz"), "under a sandbox's folder");
    let sandboxes = lab.engine.layout.sandboxes_dir();
    refused(
        &sandboxes.join("../sandboxes/home/home/export.tar.gz"),
        "under a sandbox's folder",
    );
    assert_eq!(
        std::fs::read_to_string(lab.home.join("hermes-calls")).unwrap(),
        format!(
            "profile import {} --name main\n-p main config set secrets.command.enabled false\n",
            staged.display()
        )
    );

    // A failing import records nothing, leaves no copy, and says how
    // to delete what the runtime may have kept.
    std::fs::write(lab.home.join("hermes-fails"), "").unwrap();
    let err = lab
        .engine
        .import_agent(&alice(), &lab.name, other.clone(), &archive, Confirm::Yes)
        .unwrap_err();
    let text = err.to_string();
    assert!(
        text.contains("exit 3")
            && text.contains("enclos agent list home")
            && text.contains("hermes profile delete other --yes"),
        "{text}"
    );
    assert_eq!(copies(), 0);
    assert_eq!(lab.engine.agents(&lab.name).unwrap().len(), 1);
    // The copy is audited again, with its hash; no record is.
    let copied = outcome("agent import");
    assert_eq!(copied.len(), 2);
    assert!(
        copied[1].contains(&format!("(sha256 {sha256})")),
        "{copied:?}"
    );
    assert_eq!(outcome("agent add").len(), 1);
}

#[test]
fn an_install_with_unapplied_policy_edits_asks_first() {
    let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
    let lab = Lab::new();
    let file = lab.engine.layout.policy_file("home");
    let edited = std::fs::read_to_string(&file)
        .unwrap()
        .replace("allow_add = []", "allow_add = [\"example.com\"]");
    std::fs::write(&file, edited).unwrap();
    let err = lab.install(INSTALLS, Confirm::Ask).unwrap_err();
    assert!(matches!(err, Error::NeedsConfirmation { .. }), "{err}");
    assert!(err.to_string().contains("allow example.com"), "{err}");
    assert_eq!(lab.runtime(), None);
    let Planned::DryRun(plan) = lab.install(INSTALLS, Confirm::DryRun).unwrap() else {
        panic!("a dry run installed");
    };
    assert!(
        plan.changes.iter().any(|c| c == "also allow example.com"),
        "{plan:?}"
    );
    // Said yes: both apply.
    let end = done(lab.install(INSTALLS, Confirm::Yes).unwrap());
    assert!(end.installed);
    assert!(lab.allows("example.com") && lab.allows("chatgpt.com"));
}

/// A sandbox with Hermes recorded as its runtime, and a way to make a
/// Hermes profile in its home as `hermes profile create` would.
fn with_hermes() -> (TempDir, Engine, SandboxName, impl Fn(&str)) {
    let (dir, engine, name) = with_sandbox_on(FakeBackend::available(BackendKind::Seatbelt));
    engine
        .write(
            &alice(),
            "test",
            None,
            |_| String::new(),
            |lock| {
                let mut record = engine.state.get(&name)?.unwrap();
                record.runtime = Some(RuntimeKind::Hermes);
                engine.state.put(lock, &record)?;
                Ok(())
            },
        )
        .unwrap();
    let profiles = engine.sandbox_home(&name).join(".hermes/profiles");
    let make = move |agent: &str| {
        std::fs::create_dir_all(profiles.join(agent)).unwrap();
        std::fs::write(profiles.join(agent).join("config.yaml"), "").unwrap();
    };
    (dir, engine, name, make)
}

fn compared(check: AgentCheck) -> AgentDiff {
    match check {
        AgentCheck::Compared(diff) => diff,
        AgentCheck::Unreadable(why) => panic!("unreadable: {why}"),
    }
}

fn agent(name: &str) -> AgentName {
    name.parse().unwrap()
}

#[test]
fn an_agent_made_inside_the_sandbox_is_reported_then_adopted() {
    let (_dir, engine, name, make) = with_hermes();
    make("scout");
    make("my_bot");
    let diff = compared(engine.check_agents(&name).unwrap());
    assert_eq!(diff.untracked, [agent("scout")]);
    assert_eq!(diff.untrackable, [RuntimeAgentName::new("my_bot").unwrap()]);
    assert!(diff.missing.is_empty());
    let err = engine
        .remove_agent(&alice(), &name, &agent("scout"), false, Confirm::Yes)
        .unwrap_err();
    assert!(
        err.to_string()
            .contains("enclos does not track agent `scout`, which Hermes has"),
        "{err}"
    );
    assert!(
        err.to_string().contains("or remove it with Hermes's own"),
        "{err}"
    );

    // The alias Hermes made for it is on the sandbox's PATH, which does
    // not count as a command the agent would shadow.
    let bin = engine.sandbox_home(&name).join(".local/bin");
    std::fs::create_dir_all(&bin).unwrap();
    std::fs::write(bin.join("scout"), "#!/bin/sh\n").unwrap();
    let audited = engine.audit(None).unwrap().len();
    let Planned::DryRun(plan) = engine
        .add_agent(&alice(), &name, agent("scout"), Confirm::DryRun)
        .unwrap()
    else {
        panic!("a dry run adopted");
    };
    assert_eq!(
        plan.changes,
        ["record agent home/scout, which Hermes already has in the sandbox"]
    );
    assert!(engine.agents(&name).unwrap().is_empty());
    assert_eq!(engine.audit(None).unwrap().len(), audited);

    let added = done(
        engine
            .add_agent(&alice(), &name, agent("scout"), Confirm::Yes)
            .unwrap(),
    );
    assert_eq!(added.how, Added::Adopted);
    assert_eq!(added.agent.name, agent("scout"));
    assert!(
        compared(engine.check_agents(&name).unwrap())
            .untracked
            .is_empty()
    );
    // Adopting runs nothing in the sandbox: one audit entry, the record's,
    // and no session (the fake backend could not have run one anyway).
    let entries = engine.audit(None).unwrap();
    assert_eq!(entries.len(), audited + 1);
    let last = entries.last().unwrap();
    assert_eq!(last.intent.command, "agent add");
    assert_eq!(last.intent.target.as_deref(), Some("home/scout"));
    let outcome = &last.finished.as_ref().unwrap().outcome;
    assert_eq!(outcome.result, AuditResult::Ok);
    assert_eq!(outcome.message, "adopted");
    assert!(engine.show_sandbox(&name).unwrap().sessions.is_empty());
}

#[test]
fn an_import_is_refused_before_anything_runs_and_a_dry_run_copies_nothing() {
    let (dir, engine, name, make) = with_hermes();
    make("scout");
    let archive = dir.path().join("scout.tar.gz");
    std::fs::write(&archive, b"an export").unwrap();
    // Refused before anything runs: the fake backend would fail.
    let err = engine
        .import_agent(
            &alice(),
            &name,
            "scout".parse().unwrap(),
            &archive,
            Confirm::Yes,
        )
        .unwrap_err();
    let text = err.to_string();
    assert!(
        text.contains("needs a fresh name") && text.contains("enclos agent add home/scout"),
        "{text}"
    );
    let err = engine
        .import_agent(
            &alice(),
            &name,
            "default".parse().unwrap(),
            &archive,
            Confirm::Yes,
        )
        .unwrap_err();
    assert!(err.to_string().contains("built-in agent"), "{err}");
    // A dry run of a fresh name copies nothing and makes no folder.
    let Planned::DryRun(plan) = engine
        .import_agent(
            &alice(),
            &name,
            "fresh".parse().unwrap(),
            &archive,
            Confirm::DryRun,
        )
        .unwrap()
    else {
        panic!("a dry run imported");
    };
    assert!(
        plan.changes[0].starts_with(&format!("copy {} (sha256 ", archive.display())),
        "{plan:?}"
    );
    assert_eq!(
        plan.changes[2],
        "record agent home/fresh as imported from that archive"
    );
    assert!(engine.agents(&name).unwrap().is_empty());
    assert!(
        !engine
            .layout
            .sandbox_dir("home")
            .join("installers")
            .exists()
    );
}

#[test]
fn an_import_preserves_the_exit_code_when_the_backend_is_unavailable() {
    let (dir, mut engine, name, _make) = with_hermes();
    engine.backends = vec![Box::new(FakeBackend::unavailable(
        BackendKind::Seatbelt,
        "this host cannot run the backend",
    ))];
    let archive = dir.path().join("fresh.tar.gz");
    std::fs::write(&archive, b"an export").unwrap();
    let err = engine
        .import_agent(&alice(), &name, agent("fresh"), &archive, Confirm::Yes)
        .unwrap_err();
    assert_eq!(err.exit_code(), crate::error::exit::REFUSED, "{err}");
    let text = err.to_string();
    assert!(
        text.contains("this host cannot run the backend")
            && text.contains("did not finish")
            && text.contains("Nothing was recorded")
            && text.contains("enclos agent add home/fresh"),
        "{text}"
    );
    assert!(engine.agents(&name).unwrap().is_empty());
    let installers = engine.layout.sandbox_dir("home").join("installers");
    assert_eq!(std::fs::read_dir(installers).unwrap().count(), 0);
}

#[test]
fn an_import_whose_session_fails_records_nothing_and_leaves_no_copy() {
    let (dir, engine, name, _make) = with_hermes();
    let archive = dir.path().join("fresh.tar.gz");
    std::fs::write(&archive, b"an export").unwrap();
    // The fake backend cannot start a session: the copy is made and
    // audited, then the session fails.
    let err = engine
        .import_agent(&alice(), &name, agent("fresh"), &archive, Confirm::Yes)
        .unwrap_err();
    let text = err.to_string();
    assert!(
        text.contains("did not finish")
            && text.contains("Nothing was recorded")
            && text.contains("enclos agent add home/fresh"),
        "{text}"
    );
    assert!(engine.agents(&name).unwrap().is_empty());
    let installers = engine.layout.sandbox_dir("home").join("installers");
    assert_eq!(std::fs::read_dir(&installers).unwrap().count(), 0);
    let entries = engine.audit(None).unwrap();
    let copied: Vec<_> = entries
        .iter()
        .filter(|e| e.intent.command == "agent import")
        .collect();
    assert_eq!(copied.len(), 1);
    let outcome = &copied[0].finished.as_ref().unwrap().outcome;
    assert_eq!(outcome.result, AuditResult::Ok);
    assert!(
        outcome.message.contains(&archive.display().to_string())
            && outcome.message.contains("(sha256 "),
        "{}",
        outcome.message
    );
    assert!(!entries.iter().any(|e| e.intent.command == "agent add"));
}

#[test]
fn an_import_is_refused_when_the_runtimes_agents_cannot_be_read() {
    let (dir, engine, name, _make) = with_hermes();
    // Something in the sandbox replaced ~/.hermes with a link.
    let home = engine.sandbox_home(&name);
    std::os::unix::fs::symlink(dir.path(), home.join(".hermes")).unwrap();
    let archive = dir.path().join("fresh.tar.gz");
    std::fs::write(&archive, b"an export").unwrap();
    let err = engine
        .import_agent(&alice(), &name, agent("fresh"), &archive, Confirm::Yes)
        .unwrap_err();
    assert!(
        err.to_string()
            .contains("cannot tell whether agent fresh is already there"),
        "{err}"
    );
    assert!(
        !engine
            .layout
            .sandbox_dir("home")
            .join("installers")
            .exists()
    );
}

#[test]
fn an_agent_deleted_inside_the_sandbox_is_reported_missing() {
    let (_dir, engine, name, make) = with_hermes();
    for a in ["scout", "ranger", "half"] {
        make(a);
        done(
            engine
                .add_agent(&alice(), &name, agent(a), Confirm::Yes)
                .unwrap(),
        );
    }
    let profiles = engine.sandbox_home(&name).join(".hermes/profiles");
    // As `hermes profile delete` does: a tombstone, then the folder
    // removed. A delete that stopped halfway leaves the folder.
    for a in ["scout", "half"] {
        std::fs::create_dir_all(profiles.join(".deleted").join(a)).unwrap();
    }
    std::fs::remove_dir_all(profiles.join("scout")).unwrap();
    std::fs::remove_dir_all(profiles.join("ranger")).unwrap();
    let diff = compared(engine.check_agents(&name).unwrap());
    assert_eq!(
        diff.missing,
        [agent("half"), agent("ranger"), agent("scout")]
    );
    assert!(diff.untracked.is_empty());
    // What is left of the half-deleted one is Hermes's to delete: its
    // folder would refuse an agent of that name.
    let Planned::DryRun(plan) = engine
        .remove_agent(&alice(), &name, &agent("half"), false, Confirm::DryRun)
        .unwrap()
    else {
        panic!("a dry run plans");
    };
    assert_eq!(
        plan.changes,
        [
            "delete what is left of agent home/half (~/.hermes/profiles/half), which Hermes no longer lists, with Hermes's own command"
        ]
    );
    // `--keep-data` says what it leaves: the folder here, nothing there.
    let kept = |a: &str| match done(
        engine
            .remove_agent(&alice(), &name, &agent(a), true, Confirm::Yes)
            .unwrap(),
    ) {
        AgentRemoved::RecordOnly {
            why: FilesKept::Asked { left },
            ..
        } => left,
        other => panic!("{other:?}"),
    };
    assert_eq!(kept("half"), Ok(Leftover::Folder));
    assert_eq!(kept("scout"), Ok(Leftover::Nothing));
    // Nothing left to delete: removing it takes only the record, and
    // runs nothing in the sandbox (the fake backend would fail).
    assert_eq!(
        done(
            engine
                .remove_agent(&alice(), &name, &agent("ranger"), false, Confirm::Yes)
                .unwrap(),
        ),
        AgentRemoved::RecordOnly {
            kind: RuntimeKind::Hermes,
            files: "~/.hermes/profiles/ranger".into(),
            why: FilesKept::RuntimeLacksIt,
        }
    );
    assert!(engine.agents(&name).unwrap().is_empty());
}

#[test]
fn removing_an_agent_with_its_files_asks_first() {
    let (_dir, engine, name, make) = with_hermes();
    make("scout");
    done(
        engine
            .add_agent(&alice(), &name, agent("scout"), Confirm::Yes)
            .unwrap(),
    );
    let scout = agent("scout");
    let err = engine
        .remove_agent(&alice(), &name, &scout, false, Confirm::Ask)
        .unwrap_err();
    assert!(matches!(err, Error::NeedsConfirmation { .. }), "{err}");
    let Planned::DryRun(plan) = engine
        .remove_agent(&alice(), &name, &scout, false, Confirm::DryRun)
        .unwrap()
    else {
        panic!("a dry run plans");
    };
    assert_eq!(
        plan.changes,
        ["delete agent home/scout and its files, with Hermes's own command"]
    );
    // `--keep-data` needs no confirmation and leaves the files.
    let Planned::DryRun(plan) = engine
        .remove_agent(&alice(), &name, &scout, true, Confirm::DryRun)
        .unwrap()
    else {
        panic!("a dry run plans");
    };
    assert_eq!(
        plan.changes,
        ["remove the record of agent home/scout; its files stay (~/.hermes/profiles/scout)"]
    );
    assert_eq!(
        done(
            engine
                .remove_agent(&alice(), &name, &scout, true, Confirm::Ask)
                .unwrap(),
        ),
        AgentRemoved::RecordOnly {
            kind: RuntimeKind::Hermes,
            files: "~/.hermes/profiles/scout".into(),
            why: FilesKept::Asked {
                left: Ok(Leftover::Agent)
            },
        }
    );
    assert!(engine.agents(&name).unwrap().is_empty());
    assert!(
        engine
            .sandbox_home(&name)
            .join(".hermes/profiles/scout")
            .exists()
    );
}

#[test]
fn a_linked_hermes_folder_is_reported_unreadable_and_agent_add_refuses_to_guess() {
    let (_dir, engine, name, make) = with_hermes();
    make("scout");
    done(
        engine
            .add_agent(&alice(), &name, agent("scout"), Confirm::Yes)
            .unwrap(),
    );
    let hermes = engine.sandbox_home(&name).join(".hermes");
    let kept = engine.sandbox_home(&name).join("hermes-kept");
    std::fs::rename(&hermes, &kept).unwrap();
    std::os::unix::fs::symlink(&kept, &hermes).unwrap();
    let AgentCheck::Unreadable(why) = engine.check_agents(&name).unwrap() else {
        panic!("compared through a link");
    };
    assert_eq!(why.to_string(), "~/.hermes is a link");
    let audited = engine.audit(None).unwrap().len();
    let err = engine
        .add_agent(&alice(), &name, agent("ranger"), Confirm::Yes)
        .unwrap_err();
    assert!(
        err.to_string()
            .contains("cannot read Hermes's agents in sandbox home (~/.hermes is a link)"),
        "{err}"
    );
    assert_eq!(engine.audit(None).unwrap().len(), audited);
    let err = engine
        .remove_agent(&alice(), &name, &agent("ranger"), false, Confirm::Yes)
        .unwrap_err();
    assert!(
        err.to_string()
            .contains("has no agent `ranger`, and enclos cannot read"),
        "{err}"
    );
    // Deleting a tracked agent's files would need the list; the record
    // alone can still go, since it is enclos's.
    let err = engine
        .remove_agent(&alice(), &name, &agent("scout"), false, Confirm::Yes)
        .unwrap_err();
    assert!(
        err.to_string().contains("cannot read Hermes's agents")
            && err.to_string().contains("--keep-data"),
        "{err}"
    );
    done(
        engine
            .remove_agent(&alice(), &name, &agent("scout"), true, Confirm::Yes)
            .unwrap(),
    );
    assert!(engine.agents(&name).unwrap().is_empty());
}

#[test]
fn the_check_compares_names_both_ways() {
    let tracked = |n: &str| AgentRecord {
        name: n.parse().unwrap(),
        created_at: "2026-01-02T03:04:05Z".parse().unwrap(),
    };
    let names = |names: &[&str]| -> Vec<RuntimeAgentName> {
        names
            .iter()
            .map(|n| RuntimeAgentName::new(n).unwrap())
            .collect()
    };
    let found = names(&["main", "scout", "a"]);
    let diff = AgentDiff::compare(&found, &[tracked("main"), tracked("gone")], None);
    assert_eq!(diff.untracked, [agent("scout")]);
    assert_eq!(diff.untrackable, [RuntimeAgentName::new("a").unwrap()]);
    assert_eq!(diff.missing, [agent("gone")]);
    assert!(!diff.is_clean());
    assert!(AgentDiff::compare(&found[..1], &[tracked("main")], None).is_clean());
    // A runtime that lists its built-in agent: never untracked.
    let both = names(&["main", "default"]);
    let default = crate::runtime::BuiltinAgent::new("default");
    assert!(AgentDiff::compare(&both, &[tracked("main")], Some(default)).is_clean());
}

/// An installer whose `hermes gateway run` starts a second process and
/// waits, writing both pids to `gateway-pids` in the home.
const GATEWAY: &str = "#!/bin/sh
mkdir -p \"$HOME/.local/bin\"
cat > \"$HOME/.local/bin/hermes\" <<'STUB'
#!/bin/sh
[ \"$3\" = gateway ] || exit 0
/bin/sleep 600 &
printf '%s\\n%s\\n' $! $$ > \"$HOME/gateway-pids.part\"
mv \"$HOME/gateway-pids.part\" \"$HOME/gateway-pids\"
exec /bin/sleep 600
STUB
chmod 700 \"$HOME/.local/bin/hermes\"
";

/// An installer whose `hermes gateway run` starts a second process,
/// writes both pids to `gateway-pids` in the home, and exits 0 a moment
/// later, leaving the second running.
const LEAVES: &str = "#!/bin/sh
mkdir -p \"$HOME/.local/bin\"
cat > \"$HOME/.local/bin/hermes\" <<'STUB'
#!/bin/sh
[ \"$3\" = gateway ] || exit 0
/bin/sleep 600 &
printf '%s\\n%s\\n' $! $$ > \"$HOME/gateway-pids.part\"
mv \"$HOME/gateway-pids.part\" \"$HOME/gateway-pids\"
/bin/sleep 1
exit 0
STUB
chmod 700 \"$HOME/.local/bin/hermes\"
";

/// A gateway that exits 75 on USR1, as Hermes's does.
const RESTARTS: &str = "#!/bin/sh
mkdir -p \"$HOME/.local/bin\" \"$HOME/.hermes\"
printf 'model: a\\n' > \"$HOME/.hermes/config.yaml\"
cat > \"$HOME/.local/bin/hermes\" <<'STUB'
#!/bin/sh
[ \"$3\" = gateway ] || exit 0
trap 'exit 75' USR1
: > \"$HOME/gateway-up\"
i=0
while [ $i -lt 600 ]; do /bin/sleep 0.1; i=$((i+1)); done
exit 0
STUB
chmod 700 \"$HOME/.local/bin/hermes\"
";

#[test]
fn a_service_restarts_once_its_runtime_settings_change() {
    let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
    let lab = Lab::new();
    assert!(done(lab.install(RESTARTS, Confirm::Yes).unwrap()).installed);
    let home = lab.home.clone();
    let edit = std::thread::spawn(move || {
        let start = std::time::Instant::now();
        while !home.join("gateway-up").exists() {
            assert!(
                start.elapsed() < std::time::Duration::from_secs(30),
                "no gateway"
            );
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        std::fs::write(home.join(".hermes/.env"), "TELEGRAM_BOT_TOKEN=x\n").unwrap();
    });
    let ended = std::sync::atomic::AtomicBool::new(false);
    let end = lab
        .engine
        .launch_until(&alice(), &lab.name, "gateway", &ended)
        .unwrap();
    edit.join().unwrap();
    assert_eq!(end.exit, 75, "{end:?}");
    assert!(end.restarting, "{end:?}");
    assert_eq!(
        end.notes,
        ["~/.hermes/.env changed: asked the gateway service to restart"],
        "{end:?}"
    );
    let audit = lab.audit();
    assert!(audit.contains("service restart"), "{audit}");
    assert!(open_service_sessions(&lab).is_empty());
}

#[test]
fn a_settings_restart_that_could_not_be_recorded_is_asked_again() {
    use std::os::unix::fs::PermissionsExt;
    let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
    let lab = Lab::new();
    assert!(done(lab.install(RESTARTS, Confirm::Yes).unwrap()).installed);
    let home = lab.home.clone();
    let audit = lab.engine.layout.audit_log();
    let edit = std::thread::spawn(move || {
        // The gateway runs, and `launch` has recorded it: the audit made
        // read-only fails the restart, not the start's own entry.
        let log = crate::audit::jsonl::JsonlAuditLog::new(&audit);
        let launched = || {
            use crate::audit::AuditLog;
            log.entries(&Default::default())
                .unwrap()
                .iter()
                .any(|e| e.intent.command == "launch" && e.finished.is_some())
        };
        let start = std::time::Instant::now();
        while !home.join("gateway-up").exists() || !launched() {
            assert!(
                start.elapsed() < std::time::Duration::from_secs(30),
                "no gateway"
            );
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        let mode = |m| std::fs::set_permissions(&audit, std::fs::Permissions::from_mode(m));
        mode(0o400).unwrap();
        std::fs::write(home.join(".hermes/.env"), "TELEGRAM_BOT_TOKEN=x\n").unwrap();
        // The failed attempt comes 5 to 9 s after the write.
        std::thread::sleep(std::time::Duration::from_secs(20));
        mode(0o600).unwrap();
        std::fs::write(home.join(".hermes/.env"), "TELEGRAM_BOT_TOKEN=y\n").unwrap();
    });
    let ended = std::sync::atomic::AtomicBool::new(false);
    let end = lab
        .engine
        .launch_until(&alice(), &lab.name, "gateway", &ended)
        .unwrap();
    edit.join().unwrap();
    assert_eq!(end.exit, 75, "{end:?}");
    assert!(end.restarting, "{end:?}");
    assert!(
        end.notes.iter().any(|n| n.starts_with(
            "~/.hermes/.env changed, but the gateway service was not asked to restart"
        )),
        "{end:?}"
    );
    assert!(
        end.notes
            .contains(&"~/.hermes/.env changed: asked the gateway service to restart".to_owned()),
        "{end:?}"
    );
}

#[test]
fn a_restart_is_not_sent_while_a_session_is_recorded_under_the_lock() {
    use std::os::unix::process::CommandExt;
    let lab = Lab::new();
    let sleep = || {
        spawn_unmarked(
            std::process::Command::new("/bin/sleep")
                .arg("60")
                .process_group(0),
        )
        .unwrap()
    };
    let record = |child: &std::process::Child, kind| crate::model::session::SessionRecord {
        id: crate::model::session::SessionId(0),
        sandbox: lab.name.clone(),
        kind,
        service: None,
        version: 1,
        snapshot: crate::model::policy::SnapshotId("s".into()),
        compiled: None,
        pgid: Some(child.id()),
        root: crate::lifecycle::process::reference_of_child(child).unwrap(),
        cgroup: None,
        tracked: Vec::new(),
        started_at: crate::model::now(),
        ended_at: None,
    };
    // Stands for the service's program: USR1 ends a `sleep`.
    let mut service = sleep();
    let service_session = record(&service, crate::model::session::SessionKind::Service);
    let mut connected = sleep();
    {
        let lock = lab.engine.state.lock().unwrap();
        let sandbox = lab.engine.state.get(&lab.name).unwrap().unwrap();
        let session = record(&connected, crate::model::session::SessionKind::Interactive);
        lab.engine
            .state
            .start_session(&lock, &session, &sandbox)
            .unwrap();
    }
    let env = [crate::runtime::HomePath::new(".hermes/.env").unwrap()];
    let asked = lab
        .engine
        .ask_restart(
            &alice(),
            &service_session,
            crate::runtime::Signal::Usr1,
            &env,
        )
        .unwrap();
    assert_eq!(asked, None);
    std::thread::sleep(Duration::from_millis(200));
    assert!(service.try_wait().unwrap().is_none(), "signalled");
    assert!(!lab.audit().contains("service restart"), "{}", lab.audit());

    connected.kill().unwrap();
    connected.wait().unwrap();
    let asked = answered(|| {
        lab.engine
            .ask_restart(
                &alice(),
                &service_session,
                crate::runtime::Signal::Usr1,
                &env,
            )
            .unwrap()
    });
    assert_eq!(asked, Some(Ok(())));
    let status = service.wait().unwrap();
    assert_eq!(
        std::os::unix::process::ExitStatusExt::signal(&status),
        Some(USR1)
    );
    assert!(lab.audit().contains("service restart"), "{}", lab.audit());
}

#[test]
fn an_exec_session_does_not_hold_back_a_settings_restart() {
    use std::os::unix::process::CommandExt;
    let lab = Lab::new();
    let sleep = || {
        spawn_unmarked(
            std::process::Command::new("/bin/sleep")
                .arg("60")
                .process_group(0),
        )
        .unwrap()
    };
    let record = |child: &std::process::Child, kind| crate::model::session::SessionRecord {
        id: crate::model::session::SessionId(0),
        sandbox: lab.name.clone(),
        kind,
        service: None,
        version: 1,
        snapshot: crate::model::policy::SnapshotId("s".into()),
        compiled: None,
        pgid: Some(child.id()),
        root: crate::lifecycle::process::reference_of_child(child).unwrap(),
        cgroup: None,
        tracked: Vec::new(),
        started_at: crate::model::now(),
        ended_at: None,
    };
    let mut service = sleep();
    let service_session = record(&service, crate::model::session::SessionKind::Service);
    // A script's command, running: nobody is in a setup or a TUI.
    let mut exec = sleep();
    {
        let lock = lab.engine.state.lock().unwrap();
        let sandbox = lab.engine.state.get(&lab.name).unwrap().unwrap();
        let session = record(&exec, crate::model::session::SessionKind::Exec);
        lab.engine
            .state
            .start_session(&lock, &session, &sandbox)
            .unwrap();
    }
    let env = [crate::runtime::HomePath::new(".hermes/.env").unwrap()];
    let asked = answered(|| {
        lab.engine
            .ask_restart(
                &alice(),
                &service_session,
                crate::runtime::Signal::Usr1,
                &env,
            )
            .unwrap()
    });
    assert_eq!(asked, Some(Ok(())));
    let status = service.wait().unwrap();
    assert_eq!(
        std::os::unix::process::ExitStatusExt::signal(&status),
        Some(USR1)
    );
    exec.kill().unwrap();
    exec.wait().unwrap();
}

#[test]
fn a_settings_restart_waits_until_no_one_is_connected() {
    use std::os::unix::process::CommandExt;
    let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
    let lab = Lab::new();
    assert!(done(lab.install(RESTARTS, Confirm::Yes).unwrap()).installed);
    let mut setup = spawn_unmarked(
        std::process::Command::new("/bin/sleep")
            .arg("60")
            .process_group(0),
    )
    .unwrap();
    {
        let lock = lab.engine.state.lock().unwrap();
        let record = lab.engine.state.get(&lab.name).unwrap().unwrap();
        let session = crate::model::session::SessionRecord {
            id: crate::model::session::SessionId(0),
            sandbox: lab.name.clone(),
            kind: crate::model::session::SessionKind::Interactive,
            service: None,
            version: 1,
            snapshot: crate::model::policy::SnapshotId("s".into()),
            compiled: None,
            pgid: Some(setup.id()),
            root: crate::lifecycle::process::reference_of_child(&setup).unwrap(),
            cgroup: None,
            tracked: Vec::new(),
            started_at: crate::model::now(),
            ended_at: None,
        };
        lab.engine
            .state
            .start_session(&lock, &session, &record)
            .unwrap();
    }
    // Connected for longer than `SETTLE` after the change.
    let home = lab.home.clone();
    let edit = std::thread::spawn(move || {
        let start = std::time::Instant::now();
        while !home.join("gateway-up").exists() {
            assert!(
                start.elapsed() < std::time::Duration::from_secs(30),
                "no gateway"
            );
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        std::fs::write(home.join(".hermes/.env"), "TELEGRAM_BOT_TOKEN=x\n").unwrap();
        std::thread::sleep(std::time::Duration::from_secs(12));
        setup.kill().unwrap();
        setup.wait().unwrap();
        std::time::Instant::now()
    });
    let ended = std::sync::atomic::AtomicBool::new(false);
    let end = lab
        .engine
        .launch_until(&alice(), &lab.name, "gateway", &ended)
        .unwrap();
    let returned = std::time::Instant::now();
    let left = edit.join().unwrap();
    assert!(returned > left, "restarted while someone was connected");
    assert_eq!(end.exit, 75, "{end:?}");
    assert!(end.restarting, "{end:?}");
}

/// A runtime whose gateway records whether it was launched in enclos's
/// terminal, and exits.
const RECORDS_TERMINAL: &str = "#!/bin/sh
mkdir -p \"$HOME/.local/bin\"
cat > \"$HOME/.local/bin/hermes\" <<'STUB'
#!/bin/sh
[ \"$3\" = gateway ] || exit 0
printf '%s' \"${ENCLOS_FAKE_IN_TERMINAL:-unset}\" > \"$HOME/in-terminal\"
STUB
chmod 700 \"$HOME/.local/bin/hermes\"
";

fn pids_in(file: &Path) -> Vec<u32> {
    std::fs::read_to_string(file)
        .unwrap()
        .lines()
        .map(|l| l.parse().unwrap())
        .collect()
}

fn assert_gone(pids: &[u32]) {
    for pid in pids {
        let running = crate::lifecycle::process::reference(*pid).unwrap();
        assert!(running.is_none(), "pid {pid} still runs");
    }
}

fn open_service_sessions(lab: &Lab) -> Vec<crate::model::session::SessionRecord> {
    lab.engine
        .state
        .sessions(&lab.name, true)
        .unwrap()
        .into_iter()
        .filter(|s| s.kind == crate::model::session::SessionKind::Service)
        .collect()
}

/// A process the session's program double-forks, in a group of its own
/// and with no parent, still holds the session's marker (ADR 0030).
/// With what the session recorded forgotten, so that only the marker
/// can tell: `show` lists it, `status` counts the session as running,
/// and `sandbox stop` ends it and removes the marker. Before markers it
/// was not even seen.
#[test]
fn stop_ends_a_process_that_left_its_session_by_a_double_fork() {
    use std::time::{Duration, Instant};

    let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
    let lab = Lab::new();
    let escape = "/usr/bin/perl -e 'use POSIX; exit if fork; POSIX::setsid(); exit if fork; \
            open(my $f, \">\", \"$ENV{HOME}/escaped\") or die; print $f $$; close $f; \
            exec(\"/bin/sleep\", \"600\")'; /bin/sleep 1";
    done(
        lab.engine
            .connect(
                &alice(),
                &lab.name,
                vec!["/bin/sh".into(), "-c".into(), escape.into()],
                Confirm::Yes,
            )
            .unwrap(),
    );
    let file = lab.home.join("escaped");
    let start = Instant::now();
    while !file.exists() && start.elapsed() < Duration::from_secs(10) {
        std::thread::sleep(Duration::from_millis(50));
    }
    let pid: u32 = std::fs::read_to_string(&file)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    let escaped = crate::lifecycle::process::reference(pid).unwrap().unwrap();

    let session = lab
        .engine
        .state
        .sessions(&lab.name, true)
        .unwrap()
        .into_iter()
        .find(|s| s.kind == crate::model::session::SessionKind::Interactive)
        .unwrap();
    assert_ne!(
        crate::lifecycle::process::group_of(pid).unwrap(),
        session.pgid,
        "the process did not leave the session's group"
    );
    lab.engine
        .write(
            &alice(),
            "test",
            None,
            |_| String::new(),
            |lock| Ok(lab.engine.state.track(lock, session.id, &[])?),
        )
        .unwrap();
    let view = lab.engine.show_sandbox(&lab.name).unwrap();
    let listed = view
        .sessions
        .iter()
        .any(|v| v.session.id == session.id && v.members.iter().any(|m| m.pid == pid));
    let status = lab.engine.status(Some(&lab.name)).unwrap();
    let gone = status.sandboxes[0].gone_sessions;

    let report = done(
        lab.engine
            .stop_sandbox(&alice(), &lab.name, Confirm::Yes)
            .unwrap(),
    );
    let survived = crate::lifecycle::process::is_same(&escaped).unwrap();
    if survived {
        // The test's own process, checked by pid and start time.
        let _ = crate::lifecycle::process::signal_process(
            &escaped,
            crate::lifecycle::process::Signal::Kill,
        );
    }
    assert!(!survived, "the double-forked process survived the stop");
    assert!(report.survivors.is_empty(), "{:?}", report.survivors);
    assert!(listed, "show did not list the process holding the marker");
    assert_eq!(gone, 0, "status found the session gone");
    let left: Vec<_> = std::fs::read_dir(lab.engine.markers(&lab.name))
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert!(left.is_empty(), "markers left: {left:?}");
}

/// A member whose TERM handler forks a child and exits leaves an orphan
/// that neither its group nor its parent proves the session's. It holds
/// the marker, so the look after the first stop proves it, and it is
/// stopped too instead of surviving (ADR 0030).
#[test]
fn a_child_forked_while_stopping_is_stopped_through_its_marker() {
    use std::os::unix::process::CommandExt;
    use std::process::Stdio;
    use std::time::{Duration, Instant};

    let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
    let lab = Lab::new();
    let forked = lab.home.join("forked");
    let script = format!(
        "trap '(/bin/sleep 600 & echo $! > \"{}\") ; exit 0' TERM; while :; do /bin/sleep 0.1; done",
        forked.display()
    );
    let mut command = std::process::Command::new("/bin/sh");
    command
        .args(["-c", &script])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0);
    let marker = lab.engine.new_marker(&lab.name).unwrap();
    let (mut child, marked) = marker.spawn(&mut command).unwrap();
    let root = crate::lifecycle::process::reference_of_child(&child).unwrap();
    lab.engine.name_marker(&lab.name, marked, &root).unwrap();
    let session = crate::model::session::SessionRecord {
        id: crate::model::session::SessionId(0),
        sandbox: lab.name.clone(),
        kind: crate::model::session::SessionKind::Interactive,
        service: None,
        version: 1,
        snapshot: crate::model::policy::SnapshotId("s".into()),
        compiled: None,
        pgid: Some(child.id()),
        root,
        cgroup: None,
        tracked: Vec::new(),
        started_at: crate::model::now(),
        ended_at: None,
    };

    let stopped = lab
        .engine
        .stop_marked(
            &session,
            Duration::from_millis(500),
            crate::lifecycle::stop::stop,
        )
        .unwrap();
    let _ = child.wait();
    let start = Instant::now();
    while !forked.exists() && start.elapsed() < Duration::from_secs(5) {
        std::thread::sleep(Duration::from_millis(20));
    }
    let pid: u32 = std::fs::read_to_string(&forked)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    let child_ref = crate::lifecycle::process::reference(pid).unwrap();
    let alive = child_ref.is_some();
    if let Some(child_ref) = child_ref {
        // The test's own child, checked by pid and start time.
        let _ = crate::lifecycle::process::signal_process(
            &child_ref,
            crate::lifecycle::process::Signal::Kill,
        );
    }
    assert!(!alive, "the forked child survived: {stopped:?}");
    assert!(
        matches!(stopped, crate::lifecycle::stop::Stopped::Clean),
        "{stopped:?}"
    );
}

#[test]
fn a_runtime_service_told_to_end_stops_its_runtime_and_records_the_end() {
    use std::time::{Duration, Instant};

    let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
    let _term = crate::engine::launch::TERM_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let lab = Lab::new();
    assert!(done(lab.install(GATEWAY, Confirm::Yes).unwrap()).installed);
    let pids_file = lab.home.join("gateway-pids");
    // TERM to this process, as the service manager's stop sends it to
    // `enclos launch`, once the runtime runs: `launch` must catch it,
    // not die of it.
    let markers = lab.engine.markers(&lab.name);
    let teller = {
        let pids_file = pids_file.clone();
        let markers = markers.clone();
        std::thread::spawn(move || {
            // The stub gateway runs, and `launch` has named its marker
            // after it.
            let named = || {
                std::fs::read_dir(&markers).is_ok_and(|mut files| {
                    files.any(|f| {
                        f.is_ok_and(|f| f.file_name().to_string_lossy().starts_with("root-"))
                    })
                })
            };
            let start = Instant::now();
            while !pids_file.exists() || !named() {
                assert!(
                    start.elapsed() < Duration::from_secs(30),
                    "the stub gateway did not start"
                );
                std::thread::sleep(Duration::from_millis(50));
            }
            // Who holds the service's marker while it runs (ADR 0030),
            // looked at before TERM and checked after the join.
            let held = crate::lifecycle::marker::holders(&markers);
            signal_hook::low_level::raise(signal_hook::consts::SIGTERM).unwrap();
            held
        })
    };
    let end = lab.engine.launch(&alice(), &lab.name, "gateway").unwrap();
    let held = teller.join().unwrap().unwrap();
    assert_eq!(held.len(), 1, "{held:?}");
    let holders = held.values().next().unwrap();
    for pid in pids_in(&pids_file) {
        assert!(
            holders.contains(&pid),
            "pid {pid} holds no marker: {held:?}"
        );
    }
    assert!(
        !holders.contains(&std::process::id()),
        "launch holds the marker"
    );
    assert_eq!(std::fs::read_dir(&markers).unwrap().count(), 0);
    // TERM ends `sleep` within the first grace period: KILL would show
    // as signal 9, after `STOP_GRACE`.
    assert_eq!(end.signal, Some(15), "{end:?}");
    assert_eq!(end.left, Left::Nothing, "{end:?}");
    assert_gone(&pids_in(&pids_file));
    assert!(open_service_sessions(&lab).is_empty());
    assert!(lab.audit().contains("service end"), "{}", lab.audit());
}

#[test]
fn what_a_runtime_service_leaves_running_is_stopped_when_it_exits() {
    let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
    let lab = Lab::new();
    assert!(done(lab.install(LEAVES, Confirm::Yes).unwrap()).installed);
    let ended = std::sync::atomic::AtomicBool::new(false);
    let end = lab
        .engine
        .launch_until(&alice(), &lab.name, "gateway", &ended)
        .unwrap();
    assert_eq!(end.exit, 0, "{end:?}");
    // The service manager would start the service again: what this run
    // left would run beside the next.
    assert_eq!(end.left, Left::Nothing, "{end:?}");
    assert_gone(&pids_in(&lab.home.join("gateway-pids")));
    assert!(open_service_sessions(&lab).is_empty());
}

#[test]
fn a_launch_that_succeeds_after_one_that_failed_marks_the_sandbox_running() {
    let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
    let lab = Lab::new();
    assert!(done(lab.install(LEAVES, Confirm::Yes).unwrap()).installed);
    // As a `launch` that failed leaves it, for the service manager to
    // start it again.
    {
        let lock = lab.engine.state.lock().unwrap();
        let mut record = lab.engine.state.get(&lab.name).unwrap().unwrap();
        record.state = crate::model::sandbox::SandboxState::Failed {
            reason: "launch failed: for the test".into(),
        };
        lab.engine.state.put(&lock, &record).unwrap();
    }
    let ended = std::sync::atomic::AtomicBool::new(false);
    lab.engine
        .launch_until(&alice(), &lab.name, "gateway", &ended)
        .unwrap();
    let sessions = lab.engine.state.sessions(&lab.name, false).unwrap();
    assert!(
        sessions
            .iter()
            .any(|s| s.kind == crate::model::session::SessionKind::Service)
    );
    assert_eq!(
        lab.engine.state.get(&lab.name).unwrap().unwrap().state,
        crate::model::sandbox::SandboxState::Running
    );
}

#[test]
fn a_service_is_never_launched_in_enclos_s_terminal() {
    let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
    let lab = Lab::new();
    assert!(done(lab.install(RECORDS_TERMINAL, Confirm::Yes).unwrap()).installed);
    // Even when `enclos launch` runs in one, as when run by hand: the
    // service outlives that terminal.
    let ended = std::sync::atomic::AtomicBool::new(false);
    let end = lab
        .engine
        .launch_until(&alice(), &lab.name, "gateway", &ended)
        .unwrap();
    assert_eq!(end.exit, 0, "{end:?}");
    let seen = std::fs::read_to_string(lab.home.join("in-terminal")).unwrap();
    assert_eq!(seen, "false");
}

/// A runtime whose gateway records the service port it was given.
const RECORDS_SERVICE_PORT: &str = "#!/bin/sh
mkdir -p \"$HOME/.local/bin\"
cat > \"$HOME/.local/bin/hermes\" <<'STUB'
#!/bin/sh
[ \"$3\" = gateway ] || exit 0
printf '%s' \"${ENCLOS_FAKE_SERVICE_PORT:-unset}\" > \"$HOME/gateway-port\"
STUB
chmod 700 \"$HOME/.local/bin/hermes\"
";

/// A runtime whose gateway records its open-file limit, and whether a
/// variable of enclos's own environment reached it.
const RECORDS_LIMITS: &str = "#!/bin/sh
mkdir -p \"$HOME/.local/bin\"
cat > \"$HOME/.local/bin/hermes\" <<'STUB'
#!/bin/sh
[ \"$3\" = gateway ] || exit 0
printf '%s %s' \"$(ulimit -Hn)\" \"${CARGO_MANIFEST_DIR:-absent}\" > \"$HOME/gateway-limits\"
STUB
chmod 700 \"$HOME/.local/bin/hermes\"
";

/// A service and a session start under the policy's limits, and only
/// the sandbox's variables reach them through the shell that sets them.
#[test]
fn a_service_and_a_session_run_under_the_policys_limits() {
    let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
    let lab = Lab::new();
    assert!(done(lab.install(RECORDS_LIMITS, Confirm::Yes).unwrap()).installed);
    let before = lab.engine.layout.read_policy("home").unwrap();
    let after = format!("{before}\n[resources]\nopen_files = 64\n");
    lab.engine
        .policy_edit(&alice(), &lab.name, &before, &after, Confirm::Yes)
        .unwrap();
    let ended = std::sync::atomic::AtomicBool::new(false);
    let end = lab
        .engine
        .launch_until(&alice(), &lab.name, "gateway", &ended)
        .unwrap();
    assert_eq!(end.exit, 0, "{end:?}");
    let seen = std::fs::read_to_string(lab.home.join("gateway-limits")).unwrap();
    assert_eq!(seen, "64 absent");
    let records = vec![
        "/bin/sh".into(),
        "-c".into(),
        "printf '%s %s' \"$(ulimit -Hn)\" \"${CARGO_MANIFEST_DIR:-absent}\" > \"$HOME/session-limits\"".into(),
    ];
    done(
        lab.engine
            .connect(&alice(), &lab.name, records, Confirm::Yes)
            .unwrap(),
    );
    let seen = std::fs::read_to_string(lab.home.join("session-limits")).unwrap();
    assert_eq!(seen, "64 absent");
}

/// A runtime whose gateway records the secret it was given as $TOKEN.
const RECORDS_TOKEN: &str = "#!/bin/sh
mkdir -p \"$HOME/.local/bin\"
cat > \"$HOME/.local/bin/hermes\" <<'STUB'
#!/bin/sh
[ \"$3\" = gateway ] || exit 0
printf '%s' \"${TOKEN:-unset}\" > \"$HOME/gateway-token\"
cat \"$HERMES_MANAGED_DIR/.env\" > \"$HOME/gateway-env\" 2>&1
STUB
chmod 700 \"$HOME/.local/bin/hermes\"
";

/// A service and a session read the secrets their policy grants as they
/// start: Hermes's gateway from the `.env` of a folder only its sandbox
/// reads, never in its environment, and a session as variables (ADR
/// 0034). With one missing from the store, neither starts; with the
/// store locked, the service does not, and the sandbox says why.
#[test]
fn a_service_and_a_session_get_the_secrets_their_policy_grants() {
    use crate::model::secret::{SecretRef, SecretValue};
    use crate::secrets::{InMemory, SecretStore};
    use std::os::unix::fs::PermissionsExt;
    let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
    let store = std::rc::Rc::new(InMemory::default());
    let lab = Lab::with_secrets(Box::new(std::rc::Rc::clone(&store)));
    assert!(done(lab.install(RECORDS_TOKEN, Confirm::Yes).unwrap()).installed);
    let token: SecretRef = "home/token".parse().unwrap();
    let value = SecretValue::new("tok-123:a'b\\c".into()).unwrap();
    done(
        lab.engine
            .secret_set(&alice(), &token, Some(&value), Confirm::Yes)
            .unwrap(),
    );
    let before = lab.engine.layout.read_policy("home").unwrap();
    let after = format!("{before}\n[secrets]\nenv = {{ TOKEN = \"secret:home/token\" }}\n");
    lab.engine
        .policy_edit(&alice(), &lab.name, &before, &after, Confirm::Yes)
        .unwrap();

    let ended = std::sync::atomic::AtomicBool::new(false);
    let end = lab
        .engine
        .launch_until(&alice(), &lab.name, "gateway", &ended)
        .unwrap();
    assert_eq!(end.exit, 0, "{end:?}");
    let seen = std::fs::read_to_string(lab.home.join("gateway-token")).unwrap();
    assert_eq!(seen, "unset", "the value is in the gateway's environment");
    let file = std::fs::read_to_string(lab.home.join("gateway-env")).unwrap();
    assert_eq!(file, "TOKEN=\"tok-123:a'b\\\\c\"\n");
    let folder = lab.engine.layout.sandbox_secrets_dir("home");
    let mode = |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&folder), 0o700);
    assert_eq!(mode(&folder.join(".env")), 0o600);

    let records = vec![
        "/bin/sh".into(),
        "-c".into(),
        "printf '%s' \"$TOKEN\" > \"$HOME/session-token\"".into(),
    ];
    done(
        lab.engine
            .connect(&alice(), &lab.name, records.clone(), Confirm::Yes)
            .unwrap(),
    );
    let session = lab.home.join("session-token");
    assert_eq!(std::fs::read_to_string(&session).unwrap(), "tok-123:a'b\\c");
    // A locked store: the gateway is not started, and the sandbox is
    // marked failed, saying why.
    store.1.set(true);
    let err = lab
        .engine
        .launch_until(&alice(), &lab.name, "gateway", &ended)
        .unwrap_err();
    assert!(matches!(err.root(), Error::SecretsLocked { .. }), "{err}");
    let record = lab.engine.state.get(&lab.name).unwrap().unwrap();
    assert!(
        matches!(&record.state, crate::model::sandbox::SandboxState::Failed { reason } if reason.contains("locked")),
        "{:?}",
        record.state
    );
    store.1.set(false);
    // Gone once the sandbox stops.
    done(
        lab.engine
            .stop_sandbox(&alice(), &lab.name, Confirm::Yes)
            .unwrap(),
    );
    assert!(!folder.exists());

    store.remove(&token).unwrap();
    std::fs::remove_file(&session).unwrap();
    let err = lab
        .engine
        .connect(&alice(), &lab.name, records, Confirm::Yes)
        .unwrap_err();
    assert!(matches!(err, Error::SecretMissing { .. }), "{err}");
    assert!(!session.exists(), "the session ran");
    let err = lab
        .engine
        .launch_until(&alice(), &lab.name, "gateway", &ended)
        .unwrap_err();
    assert!(err.to_string().contains("$TOKEN"), "{err}");

    // The grant taken out, a file an earlier start left (a crash, a
    // logout) goes as the gateway starts again with no secrets.
    std::fs::create_dir_all(&folder).unwrap();
    std::fs::write(folder.join(".env"), "TOKEN=\"stale\"\n").unwrap();
    let now = lab.engine.layout.read_policy("home").unwrap();
    lab.engine
        .policy_edit(&alice(), &lab.name, &now, &before, Confirm::Yes)
        .unwrap();
    // The stub's `cat` of the file then fails: what it found is that.
    lab.engine
        .launch_until(&alice(), &lab.name, "gateway", &ended)
        .unwrap();
    assert!(!folder.exists());
    let found = std::fs::read_to_string(lab.home.join("gateway-env")).unwrap();
    assert!(!found.contains("stale"), "{found}");
}

/// `enclos launch` writes the sandbox's and each agent's secrets files
/// from the file store as it does from the Keychain (ADR 0034, ADR 0036).
#[test]
fn launch_writes_the_secrets_files_from_the_file_store() {
    use crate::model::secret::{SecretRef, SecretValue};
    use crate::secrets::file::FileStore;
    let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
    let dir = tempfile::tempdir().unwrap();
    let store = FileStore::new(dir.path().join("secrets.json"));
    let lab = Lab::with_secrets(Box::new(store));
    assert!(done(lab.install(RECORDS_TOKEN, Confirm::Yes).unwrap()).installed);
    for (secret, value) in [("home/token", "tok-1"), ("home/main-bot", "123:bot")] {
        let secret: SecretRef = secret.parse().unwrap();
        let value = SecretValue::new(value.into()).unwrap();
        done(
            lab.engine
                .secret_set(&alice(), &secret, Some(&value), Confirm::Yes)
                .unwrap(),
        );
    }
    let before = lab.engine.layout.read_policy("home").unwrap();
    let granted = format!(
        "{before}\n[secrets]\nenv = {{ TOKEN = \"secret:home/token\" }}\n[secrets.agents.main]\nenv = {{ TELEGRAM_BOT_TOKEN = \"secret:home/main-bot\" }}\n"
    );
    lab.engine
        .policy_edit(&alice(), &lab.name, &before, &granted, Confirm::Yes)
        .unwrap();
    let ended = std::sync::atomic::AtomicBool::new(false);
    let end = lab
        .engine
        .launch_until(&alice(), &lab.name, "gateway", &ended)
        .unwrap();
    assert_eq!(end.exit, 0, "{end:?}");
    assert_eq!(
        std::fs::read_to_string(lab.home.join("gateway-env")).unwrap(),
        "TOKEN=\"tok-1\"\n"
    );
    let file = lab.engine.layout.agent_secrets_file("home", "main");
    assert_eq!(
        std::fs::read_to_string(file).unwrap(),
        "TELEGRAM_BOT_TOKEN=\"123:bot\"\n"
    );
}

/// What the policy grants one agent goes to that agent's own file in
/// the secrets folder, never to the sandbox's `.env` every agent reads,
/// nor to a session (ADR 0036); it stays granted until the policy takes
/// it out, and the file goes with the grant.
#[test]
fn an_agents_secrets_go_to_a_file_of_its_own_and_to_no_session() {
    use crate::model::secret::{SecretRef, SecretValue};
    use crate::secrets::InMemory;
    use std::os::unix::fs::PermissionsExt;
    let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
    let store = std::rc::Rc::new(InMemory::default());
    let lab = Lab::with_secrets(Box::new(std::rc::Rc::clone(&store)));
    assert!(done(lab.install(RECORDS_TOKEN, Confirm::Yes).unwrap()).installed);
    for (secret, value) in [("home/token", "tok-1"), ("home/main-bot", "123:bot")] {
        let secret: SecretRef = secret.parse().unwrap();
        let value = SecretValue::new(value.into()).unwrap();
        done(
            lab.engine
                .secret_set(&alice(), &secret, Some(&value), Confirm::Yes)
                .unwrap(),
        );
    }
    let before = lab.engine.layout.read_policy("home").unwrap();
    let granted = format!(
        "{before}\n[secrets]\nenv = {{ TOKEN = \"secret:home/token\" }}\n[secrets.agents.main]\nenv = {{ TELEGRAM_BOT_TOKEN = \"secret:home/main-bot\" }}\n"
    );
    lab.engine
        .policy_edit(&alice(), &lab.name, &before, &granted, Confirm::Yes)
        .unwrap();

    let ended = std::sync::atomic::AtomicBool::new(false);
    let end = lab
        .engine
        .launch_until(&alice(), &lab.name, "gateway", &ended)
        .unwrap();
    assert_eq!(end.exit, 0, "{end:?}");
    let every = std::fs::read_to_string(lab.home.join("gateway-env")).unwrap();
    assert_eq!(
        every, "TOKEN=\"tok-1\"\n",
        "an agent's secret reached every agent"
    );
    let file = lab.engine.layout.agent_secrets_file("home", "main");
    assert_eq!(
        std::fs::read_to_string(&file).unwrap(),
        "TELEGRAM_BOT_TOKEN=\"123:bot\"\n"
    );
    assert_eq!(
        std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
        0o600
    );

    // A session gets the sandbox's secrets, not an agent's.
    let records = vec![
        "/bin/sh".into(),
        "-c".into(),
        "printf '%s' \"${TELEGRAM_BOT_TOKEN:-unset}\" > \"$HOME/session-bot\"".into(),
    ];
    done(
        lab.engine
            .connect(&alice(), &lab.name, records, Confirm::Yes)
            .unwrap(),
    );
    assert_eq!(
        std::fs::read_to_string(lab.home.join("session-bot")).unwrap(),
        "unset"
    );

    // Granted to an agent, a secret is not removed, and the refusal
    // names the agent.
    let bot: SecretRef = "home/main-bot".parse().unwrap();
    let err = lab
        .engine
        .secret_rm(&alice(), &bot, Confirm::Yes)
        .unwrap_err();
    assert!(
        err.to_string()
            .contains("$TELEGRAM_BOT_TOKEN for agent main"),
        "{err}"
    );

    // The grant taken out, the agent's file goes at the next start; the
    // sandbox's stays.
    let ungranted = format!("{before}\n[secrets]\nenv = {{ TOKEN = \"secret:home/token\" }}\n");
    lab.engine
        .policy_edit(&alice(), &lab.name, &granted, &ungranted, Confirm::Yes)
        .unwrap();
    lab.engine
        .launch_until(&alice(), &lab.name, "gateway", &ended)
        .unwrap();
    assert!(!file.exists());
    assert!(file.with_file_name(".env").exists());

    // A value no secrets file can hold, granted to an agent: refused
    // before anything is written, the sandbox's file kept as it was.
    let bad: SecretRef = "home/main-bot".parse().unwrap();
    let value = SecretValue::new("a${b}".into()).unwrap();
    done(
        lab.engine
            .secret_set(&alice(), &bad, Some(&value), Confirm::Yes)
            .unwrap(),
    );
    let env = file.with_file_name(".env");
    std::fs::write(&env, "KEPT=\"1\"\n").unwrap();
    lab.engine
        .policy_edit(&alice(), &lab.name, &ungranted, &granted, Confirm::Yes)
        .unwrap();
    let err = lab
        .engine
        .launch_until(&alice(), &lab.name, "gateway", &ended)
        .unwrap_err();
    assert!(
        matches!(err.root(), Error::SecretsFileRefused { .. }),
        "{err}"
    );
    assert!(!file.exists());
    assert_eq!(std::fs::read_to_string(&env).unwrap(), "KEPT=\"1\"\n");
}

/// `runtime configure` with settings only: the agent reads its own
/// secrets, and each setting names a secret only as a `${VAR}` the
/// policy grants it, never as the secret (ADR 0036).
#[test]
fn an_agent_is_given_settings_that_name_its_secrets() {
    use crate::engine::Setting;
    use crate::model::secret::{SecretRef, SecretValue};
    use crate::secrets::InMemory;
    let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
    let store = std::rc::Rc::new(InMemory::default());
    let lab = Lab::with_secrets(Box::new(std::rc::Rc::clone(&store)));
    assert!(done(lab.install(INSTALLS, Confirm::Yes).unwrap()).installed);
    let calls = || std::fs::read_to_string(lab.home.join("hermes-calls")).unwrap_or_default();
    let set = |settings: &[&str]| {
        let settings: Vec<Setting> = settings.iter().map(|s| s.parse().unwrap()).collect();
        lab.engine
            .configure_agent(&alice(), &lab.name, None, None, &settings, Confirm::Yes)
    };
    // Nothing asked: the agent reads its own secrets, and only that.
    let configured = done(set(&[]).unwrap());
    assert_eq!(configured.agent.as_str(), "default");
    assert!(configured.settings.is_empty() && configured.channel.is_none());
    assert_eq!(calls().lines().count(), 3, "{}", calls());
    assert!(calls().contains("-p default config set secrets.command.enabled true"));

    // A secret named by a variable the policy does not grant: refused,
    // saying how to grant it, and nothing runs.
    let runs = calls().lines().count();
    let err = set(&["platforms.discord.token=${DISCORD_BOT_TOKEN}"]).unwrap_err();
    assert!(
        err.to_string()
            .contains("grants agent default no $DISCORD_BOT_TOKEN")
            && err.to_string().contains("[secrets.agents.default]"),
        "{err}"
    );
    // A secret written as itself, where the name says it is one.
    let err = set(&["platforms.discord.token=123:abc"]).unwrap_err();
    assert!(err.to_string().contains("looks like a secret"), "{err}");
    assert_eq!(calls().lines().count(), runs, "{}", calls());

    // Granted to the agent: set as written, the value never in a command.
    let token: SecretRef = "home/discord".parse().unwrap();
    let value = SecretValue::new("999:discord".into()).unwrap();
    done(
        lab.engine
            .secret_set(&alice(), &token, Some(&value), Confirm::Yes)
            .unwrap(),
    );
    let before = lab.engine.layout.read_policy("home").unwrap();
    let after = format!(
        "{before}\n[secrets.agents.default]\nenv = {{ DISCORD_BOT_TOKEN = \"secret:home/discord\" }}\n"
    );
    lab.engine
        .policy_edit(&alice(), &lab.name, &before, &after, Confirm::Yes)
        .unwrap();
    let configured = done(
        set(&[
            "platforms.discord.token=${DISCORD_BOT_TOKEN}",
            "DISCORD_ALLOWED_USERS=111",
        ])
        .unwrap(),
    );
    assert_eq!(
        configured.settings,
        ["platforms.discord.token", "DISCORD_ALLOWED_USERS"]
    );
    assert!(
        calls().ends_with(
            "-p default config set platforms.discord.token ${DISCORD_BOT_TOKEN}\n-p default config set DISCORD_ALLOWED_USERS 111\n"
        ),
        "{}",
        calls()
    );
    assert!(!calls().contains("999:discord"));
}

/// What the channel tests read of a bot `runtime configure` set up.
#[derive(Debug)]
struct Bot {
    agent: crate::runtime::RuntimeAgentName,
    token: String,
    answers: Vec<crate::model::channel::ChannelUser>,
    reachable: bool,
}

/// `runtime configure --channel`, with no other setting.
#[allow(clippy::too_many_arguments)]
fn configure_channel(
    engine: &Engine,
    by: &crate::model::audit::Actor,
    name: &SandboxName,
    agent: Option<&crate::model::agent::AgentName>,
    channel: crate::model::channel::Channel,
    token: Option<String>,
    answers: &[crate::model::channel::ChannelUser],
    confirm: Confirm,
) -> crate::error::Result<Planned<Bot>> {
    let request = crate::engine::ChannelRequest {
        channel,
        token,
        answers: answers.to_vec(),
    };
    Ok(
        match engine.configure_agent(by, name, agent, Some(request), &[], confirm)? {
            Planned::DryRun(plan) => Planned::DryRun(plan),
            Planned::Done(done) => {
                let Some(crate::engine::ChannelSet::Bot {
                    token,
                    answers,
                    reachable,
                    ..
                }) = done.channel
                else {
                    panic!("a bot was asked for: {:?}", done.channel);
                };
                Planned::Done(Bot {
                    agent: done.agent,
                    token,
                    answers,
                    reachable,
                })
            }
        },
    )
}

/// The built-in agent's bot is set up with the runtime's own commands,
/// once the policy grants it its token (ADR 0036); the value goes into
/// no command.
#[test]
fn a_channel_is_set_up_with_the_runtimes_commands_once_its_token_is_granted() {
    use crate::model::channel::{Channel, ChannelUser};
    use crate::model::secret::{SecretRef, SecretValue};
    use crate::secrets::InMemory;
    let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
    let store = std::rc::Rc::new(InMemory::default());
    let lab = Lab::with_secrets(Box::new(std::rc::Rc::clone(&store)));
    assert!(done(lab.install(INSTALLS, Confirm::Yes).unwrap()).installed);
    let calls = || std::fs::read_to_string(lab.home.join("hermes-calls")).unwrap_or_default();
    let users: Vec<ChannelUser> = vec!["111".parse().unwrap(), "222".parse().unwrap()];
    let configure = |users: &[ChannelUser], confirm| {
        configure_channel(
            &lab.engine,
            &alice(),
            &lab.name,
            None,
            Channel::Telegram,
            None,
            users,
            confirm,
        )
    };

    let err = configure(&users, Confirm::Yes).unwrap_err();
    assert!(
        err.to_string().contains("enclos secret set home/telegram"),
        "{err}"
    );
    let err = configure(&[], Confirm::Yes).unwrap_err();
    assert!(err.to_string().contains("--allow-user"), "{err}");
    assert!(!calls().contains("config set"), "{}", calls());

    let token: SecretRef = "home/telegram".parse().unwrap();
    let value = SecretValue::new("123:tok".into()).unwrap();
    done(
        lab.engine
            .secret_set(&alice(), &token, Some(&value), Confirm::Yes)
            .unwrap(),
    );
    let before = lab.engine.layout.read_policy("home").unwrap();
    // Granted to the whole sandbox, it would reach every agent and win
    // over each one's own (ADR 0036): refused, saying where it goes.
    let sandbox_wide =
        format!("{before}\n[secrets]\nenv = {{ TELEGRAM_BOT_TOKEN = \"secret:home/telegram\" }}\n");
    let err = lab
        .engine
        .policy_edit(&alice(), &lab.name, &before, &sandbox_wide, Confirm::Yes)
        .unwrap_err();
    assert!(
        matches!(&err, Error::Policy(e) if e.is_refused())
            && err.to_string().contains("[secrets.agents.default]"),
        "{err}"
    );
    assert!(!calls().contains("config set"), "{}", calls());
    let after = format!(
        "{before}\n[secrets.agents.default]\nenv = {{ TELEGRAM_BOT_TOKEN = \"secret:home/telegram\" }}\n"
    );
    lab.engine
        .policy_edit(&alice(), &lab.name, &before, &after, Confirm::Yes)
        .unwrap();

    // A token Hermes's own setup left in plain text in the home is
    // refused until its line goes, though the policy grants one too.
    let env = lab.home.join(".hermes/.env");
    std::fs::create_dir_all(env.parent().unwrap()).unwrap();
    std::fs::write(
        &env,
        "TELEGRAM_ALLOWED_USERS=1\nTELEGRAM_BOT_TOKEN=999:plain\n",
    )
    .unwrap();
    let err = configure(&users, Confirm::Yes).unwrap_err();
    assert!(
        err.to_string()
            .contains("holds TELEGRAM_BOT_TOKEN in plain text"),
        "{err}"
    );
    assert!(!calls().contains("config set"), "{}", calls());
    std::fs::write(&env, "TELEGRAM_ALLOWED_USERS=1\n").unwrap();

    let Planned::DryRun(plan) = configure(&users, Confirm::DryRun).unwrap() else {
        panic!("a dry run configured the channel");
    };
    assert_eq!(plan.changes.len(), 6, "{plan:?}");
    // The agent reads its own secrets file, then the token by name.
    let file = lab.engine.layout.agent_secrets_file("home", "default");
    assert!(
        plan.changes[0].contains("secrets.command.command")
            && plan.changes[0].contains(&file.display().to_string()),
        "{plan:?}"
    );
    assert!(
        plan.changes[4].contains("platforms.telegram.token '${TELEGRAM_BOT_TOKEN}'"),
        "{plan:?}"
    );
    assert!(!calls().contains("config set"), "{}", calls());

    // Each person once.
    let twice: Vec<ChannelUser> = ["222", "111", "222"]
        .iter()
        .map(|u| u.parse().unwrap())
        .collect();
    let set = done(configure(&twice, Confirm::Yes).unwrap());
    assert_eq!(set.token, "TELEGRAM_BOT_TOKEN");
    assert_eq!(set.answers, users);
    assert!(
        set.reachable,
        "the assistant template reaches the public web"
    );
    assert_eq!(set.agent.as_str(), "default");
    // Its secrets file, then who it answers, the bot turned on last.
    assert!(
        calls().ends_with(&format!(
            "-p default config set secrets.command.command cat '{}'\n-p default config set secrets.command.override_existing true\n-p default config set secrets.command.enabled true\n-p default config set TELEGRAM_ALLOWED_USERS 111,222\n-p default config set platforms.telegram.token ${{TELEGRAM_BOT_TOKEN}}\n-p default config set platforms.telegram.enabled true\n",
            file.display()
        )),
        "{}",
        calls()
    );
    assert!(!calls().contains("123:tok"));
    let configured = |lab: &Lab| {
        lab.engine
            .audit(None)
            .unwrap()
            .iter()
            .filter(|e| e.intent.command == "runtime configure")
            .count()
    };
    assert_eq!(configured(&lab), 6, "{}", lab.audit());

    // A variable of another name: refused while the usual one is
    // granted too, which Hermes would read first.
    let usual = lab.engine.layout.read_policy("home").unwrap();
    let both = usual.replace(
        "TELEGRAM_BOT_TOKEN = ",
        "TELEGRAM_BOT_TOKEN_MAIN = \"secret:home/telegram\", TELEGRAM_BOT_TOKEN = ",
    );
    lab.engine
        .policy_edit(&alice(), &lab.name, &usual, &both, Confirm::Yes)
        .unwrap();
    let named = |token: &str| {
        configure_channel(
            &lab.engine,
            &alice(),
            &lab.name,
            None,
            Channel::Telegram,
            Some(token.to_owned()),
            &users,
            Confirm::Yes,
        )
    };
    let runs = calls().lines().count();
    let err = named("TELEGRAM_BOT_TOKEN_MAIN").unwrap_err();
    assert!(
        err.to_string()
            .contains("also gives agent default $TELEGRAM_BOT_TOKEN"),
        "{err}"
    );
    // Granted alone, it sets the bot up; a token Hermes's setup left in
    // the home under the usual name is refused for it too.
    let alone = usual.replace("TELEGRAM_BOT_TOKEN = ", "TELEGRAM_BOT_TOKEN_MAIN = ");
    lab.engine
        .policy_edit(&alice(), &lab.name, &both, &alone, Confirm::Yes)
        .unwrap();
    std::fs::write(&env, "TELEGRAM_BOT_TOKEN=999:plain\n").unwrap();
    let err = named("TELEGRAM_BOT_TOKEN_MAIN").unwrap_err();
    assert!(
        err.to_string()
            .contains("holds TELEGRAM_BOT_TOKEN in plain text"),
        "{err}"
    );
    assert_eq!(calls().lines().count(), runs, "{}", calls());
    std::fs::write(&env, "").unwrap();
    let set = done(named("TELEGRAM_BOT_TOKEN_MAIN").unwrap());
    assert_eq!(set.token, "TELEGRAM_BOT_TOKEN_MAIN");
    assert!(
        calls().contains("${TELEGRAM_BOT_TOKEN_MAIN}"),
        "{}",
        calls()
    );
    for bad in ["1BAD", "A}B", "PATH"] {
        let err = named(bad).unwrap_err();
        assert!(
            err.to_string().contains("cannot hold the bot's token"),
            "{err}"
        );
    }
    lab.engine
        .policy_edit(&alice(), &lab.name, &alone, &usual, Confirm::Yes)
        .unwrap();

    // A command that fails stops the rest, and a later one names what
    // ran before it.
    std::fs::write(lab.home.join("hermes-fails"), "").unwrap();
    let runs = calls().lines().count();
    let err = configure(&users, Confirm::Yes).unwrap_err();
    assert!(err.to_string().contains("exited with 3"), "{err}");
    assert!(!matches!(err, Error::FailedAfter { .. }), "{err}");
    assert_eq!(calls().lines().count(), runs + 1, "{}", calls());
    std::fs::remove_file(lab.home.join("hermes-fails")).unwrap();
    std::fs::write(lab.home.join("hermes-token-fails"), "").unwrap();
    let err = configure(&users, Confirm::Yes).unwrap_err();
    assert!(matches!(err, Error::FailedAfter { .. }), "{err}");
    assert!(err.to_string().contains("TELEGRAM_ALLOWED_USERS"), "{err}");
    assert!(!calls().ends_with("enabled true\n"), "{}", calls());
    std::fs::remove_file(lab.home.join("hermes-token-fails")).unwrap();

    // Under an allowlist that leaves Telegram out: set up, and said.
    let before = lab.engine.layout.read_policy("home").unwrap();
    let after = before.replace("[network]\n", "[network]\nmode = \"allowlist\"\n");
    lab.engine
        .policy_edit(&alice(), &lab.name, &before, &after, Confirm::Yes)
        .unwrap();
    let Planned::DryRun(plan) = configure(&users, Confirm::DryRun).unwrap() else {
        panic!("a dry run configured the channel");
    };
    assert!(
        plan.changes
            .last()
            .unwrap()
            .contains("enclos policy allow home api.telegram.org"),
        "{plan:?}"
    );
    assert!(!done(configure(&users, Confirm::Yes).unwrap()).reachable);
    done(
        lab.engine
            .policy_allow(&alice(), &lab.name, "api.telegram.org", Confirm::Yes)
            .unwrap(),
    );
    assert!(done(configure(&users, Confirm::Yes).unwrap()).reachable);
}

/// A token granted only by the pending policy waits for it: nothing
/// runs before `policy apply`.
#[test]
fn a_channel_whose_token_is_only_pending_is_refused() {
    use crate::model::channel::{Channel, ChannelUser};
    use crate::model::secret::{SecretRef, SecretValue};
    use crate::secrets::InMemory;
    let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
    let store = std::rc::Rc::new(InMemory::default());
    let lab = Lab::with_secrets(Box::new(std::rc::Rc::clone(&store)));
    assert!(done(lab.install(INSTALLS, Confirm::Yes).unwrap()).installed);
    let token: SecretRef = "home/telegram".parse().unwrap();
    let value = SecretValue::new("123:tok".into()).unwrap();
    done(
        lab.engine
            .secret_set(&alice(), &token, Some(&value), Confirm::Yes)
            .unwrap(),
    );
    // A session under rules the grant changes keeps it pending.
    let sleeping = super::sandbox::Sleeping::new();
    let mut session = super::sandbox::session_of(&lab.engine, &lab.name, sleeping.process());
    session.compiled = Some("/compiled/at-launch.sb".into());
    super::sandbox::put(&lab.engine, &session);
    let before = lab.engine.layout.read_policy("home").unwrap();
    let after = format!(
        "{before}\n[secrets.agents.default]\nenv = {{ TELEGRAM_BOT_TOKEN = \"secret:home/telegram\" }}\n"
    );
    lab.engine
        .policy_edit(&alice(), &lab.name, &before, &after, Confirm::Ask)
        .unwrap();
    let users: Vec<ChannelUser> = vec!["111".parse().unwrap()];
    let err = configure_channel(
        &lab.engine,
        &alice(),
        &lab.name,
        None,
        Channel::Telegram,
        None,
        &users,
        Confirm::Yes,
    )
    .unwrap_err();
    assert!(
        err.to_string().contains("enclos policy apply home"),
        "{err}"
    );
    let calls = std::fs::read_to_string(lab.home.join("hermes-calls")).unwrap_or_default();
    assert!(!calls.contains("config set"), "{calls}");
    drop(sleeping);
}

/// An agent's own bot (ADR 0036): set up for an agent the sandbox has,
/// its token granted to that agent alone, and read from that agent's
/// secrets file; the built-in agent's grant is not that agent's.
#[test]
fn an_agent_is_given_a_bot_of_its_own() {
    use crate::model::channel::{Channel, ChannelUser};
    use crate::model::secret::{SecretRef, SecretValue};
    use crate::secrets::InMemory;
    let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
    let store = std::rc::Rc::new(InMemory::default());
    let lab = Lab::with_secrets(Box::new(std::rc::Rc::clone(&store)));
    assert!(done(lab.install(INSTALLS, Confirm::Yes).unwrap()).installed);
    let main: crate::model::agent::AgentName = "main".parse().unwrap();
    let users: Vec<ChannelUser> = vec!["111".parse().unwrap()];
    let configure = |agent: &crate::model::agent::AgentName| {
        configure_channel(
            &lab.engine,
            &alice(),
            &lab.name,
            Some(agent),
            Channel::Telegram,
            None,
            &users,
            Confirm::Yes,
        )
    };
    // Not an agent of the sandbox yet: refused, saying how to add it.
    let err = configure(&main).unwrap_err();
    assert!(
        err.to_string().contains("enclos agent add home/main"),
        "{err}"
    );
    done(
        lab.engine
            .add_agent(&alice(), &lab.name, main.clone(), Confirm::Yes)
            .unwrap(),
    );
    let bot: SecretRef = "home/main-telegram".parse().unwrap();
    let value = SecretValue::new("123:main".into()).unwrap();
    done(
        lab.engine
            .secret_set(&alice(), &bot, Some(&value), Confirm::Yes)
            .unwrap(),
    );
    // Granted to the built-in agent only: not main's, and the message
    // names main's section and a secret of its own.
    let before = lab.engine.layout.read_policy("home").unwrap();
    let to_default = format!(
        "{before}\n[secrets.agents.default]\nenv = {{ TELEGRAM_BOT_TOKEN = \"secret:home/main-telegram\" }}\n"
    );
    lab.engine
        .policy_edit(&alice(), &lab.name, &before, &to_default, Confirm::Yes)
        .unwrap();
    let err = configure(&main).unwrap_err();
    assert!(
        err.to_string()
            .contains("gives agent main no $TELEGRAM_BOT_TOKEN")
            && err.to_string().contains("[secrets.agents.main]")
            && err
                .to_string()
                .contains("enclos secret set home/main-telegram"),
        "{err}"
    );
    let to_main = to_default.replace("[secrets.agents.default]", "[secrets.agents.main]");
    lab.engine
        .policy_edit(&alice(), &lab.name, &to_default, &to_main, Confirm::Yes)
        .unwrap();
    let set = done(configure(&main).unwrap());
    assert_eq!(set.agent.as_str(), "main");
    let calls = std::fs::read_to_string(lab.home.join("hermes-calls")).unwrap();
    let file = lab.engine.layout.agent_secrets_file("home", "main");
    assert!(
        calls.contains(&format!(
            "-p main config set secrets.command.command cat '{}'\n",
            file.display()
        )),
        "{calls}"
    );
    assert!(
        calls.ends_with("-p main config set platforms.telegram.enabled true\n"),
        "{calls}"
    );
    assert!(!calls.contains("-p default config set"), "{calls}");
    assert!(!calls.contains("123:main"), "{calls}");
}

/// `runtime configure --channel app`, with `--allow-user` and
/// `--token-env` given as `answers` and `token`.
fn configure_app(
    lab: &Lab,
    answers: &[crate::model::channel::ChannelUser],
    token: Option<&str>,
    confirm: Confirm,
) -> crate::error::Result<Planned<crate::engine::Configured>> {
    let request = crate::engine::ChannelRequest {
        channel: crate::model::channel::Channel::App,
        token: token.map(str::to_owned),
        answers: answers.to_vec(),
    };
    lab.engine
        .configure_agent(&alice(), &lab.name, None, Some(request), &[], confirm)
}

/// The app channel's files enclos staged in `installers/` and left there.
fn staged_app_files(lab: &Lab) -> Vec<String> {
    let dir = lab.engine.layout.sandbox_installers("home");
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    entries
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with("app-"))
        .collect()
}

/// Grants the built-in agent `MOBILE_APP_TOKEN` in the policy, from a
/// secret stored for it, with `confirm` (`Ask` leaves it pending while a
/// session runs under the old rules).
fn grant_app_token(lab: &Lab, confirm: Confirm) {
    use crate::model::secret::{SecretRef, SecretValue};
    let token: SecretRef = "home/app".parse().unwrap();
    let value = SecretValue::new("0123abcd".into()).unwrap();
    done(
        lab.engine
            .secret_set(&alice(), &token, Some(&value), Confirm::Yes)
            .unwrap(),
    );
    let before = lab.engine.layout.read_policy("home").unwrap();
    let after = format!(
        "{before}\n[secrets.agents.default]\nenv = {{ MOBILE_APP_TOKEN = \"secret:home/app\" }}\n"
    );
    lab.engine
        .policy_edit(&alice(), &lab.name, &before, &after, confirm)
        .unwrap();
}

/// The app channel (ADR 0042, proposed): refused, with nothing run or
/// staged, while its token is not the agent's own or when asked for
/// people or a token variable the bridge decides instead; a dry run
/// stages nothing; set up, the plugin is in the agent's home, turned on,
/// told its socket, and nothing staged is left behind.
#[test]
fn the_app_channel_is_set_up_once_the_agent_alone_holds_its_token() {
    use crate::model::channel::ChannelUser;
    use crate::model::secret::{SecretRef, SecretValue};
    use crate::secrets::InMemory;
    let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
    let store = std::rc::Rc::new(InMemory::default());
    // In /tmp: the socket's path must fit in 103 bytes, which macOS's own
    // temporary folder, deep as it is, leaves no room for.
    let root = super::Root {
        parent: "/tmp".into(),
        leaf: "e".to_owned(),
    };
    let lab = Lab::with_secrets_under(Box::new(std::rc::Rc::clone(&store)), &root);
    assert!(done(lab.install(INSTALLS, Confirm::Yes).unwrap()).installed);
    let calls = || std::fs::read_to_string(lab.home.join("hermes-calls")).unwrap_or_default();
    let nothing_ran = |lab: &Lab| {
        assert!(!calls().contains("plugins enable"), "{}", calls());
        assert!(!calls().contains("MOBILE_APP"), "{}", calls());
        assert!(
            staged_app_files(lab).is_empty(),
            "{:?}",
            staged_app_files(lab)
        );
    };

    // People to answer, or another token variable: the bridge decides
    // both, so each is refused rather than ignored.
    let users: Vec<ChannelUser> = vec!["111".parse().unwrap()];
    let err = configure_app(&lab, &users, None, Confirm::Yes).unwrap_err();
    assert!(
        err.to_string().contains("`--allow-user` does not apply"),
        "{err}"
    );
    let err = configure_app(&lab, &[], Some("MY_TOKEN"), Confirm::Yes).unwrap_err();
    assert!(
        err.to_string().contains("`--token-env` does not apply")
            && err.to_string().contains("$MOBILE_APP_TOKEN"),
        "{err}"
    );
    nothing_ran(&lab);

    // No token granted: refused, saying how to make and grant one.
    let err = configure_app(&lab, &[], None, Confirm::Yes).unwrap_err();
    assert!(
        err.to_string()
            .contains("gives agent default no $MOBILE_APP_TOKEN")
            && err
                .to_string()
                .contains("enclos secret set home/default-app")
            && err.to_string().contains("[secrets.agents.default]"),
        "{err}"
    );
    nothing_ran(&lab);

    // Granted to the whole sandbox, every agent would hold it: the
    // policy itself is refused, so one token is one agent's.
    let shared: SecretRef = "home/shared-app".parse().unwrap();
    let value = SecretValue::new("0123abcd".into()).unwrap();
    done(
        lab.engine
            .secret_set(&alice(), &shared, Some(&value), Confirm::Yes)
            .unwrap(),
    );
    let before = lab.engine.layout.read_policy("home").unwrap();
    let sandbox_wide =
        format!("{before}\n[secrets]\nenv = {{ MOBILE_APP_TOKEN = \"secret:home/shared-app\" }}\n");
    let err = lab
        .engine
        .policy_edit(&alice(), &lab.name, &before, &sandbox_wide, Confirm::Yes)
        .unwrap_err();
    assert!(
        matches!(&err, Error::Policy(e) if e.is_refused())
            && err.to_string().contains("secrets.env.MOBILE_APP_TOKEN"),
        "{err}"
    );
    nothing_ran(&lab);

    grant_app_token(&lab, Confirm::Yes);
    // A dry run names the copy and runs nothing, and stages nothing.
    let Planned::DryRun(plan) = configure_app(&lab, &[], None, Confirm::DryRun).unwrap() else {
        panic!("a dry run set the app channel up");
    };
    assert!(
        plan.changes
            .iter()
            .any(|c| c.contains("run `cp '~/.hermes/plugins/enclos/plugin.yaml'")),
        "{plan:?}"
    );
    assert!(
        plan.changes
            .iter()
            .any(|c| c.contains("plugins enable enclos")),
        "{plan:?}"
    );
    nothing_ran(&lab);

    let Planned::Done(configured) = configure_app(&lab, &[], None, Confirm::Yes).unwrap() else {
        panic!("not a dry run");
    };
    let socket = lab.engine.layout.agent_app_socket("home", "default");
    assert_eq!(
        configured.channel,
        Some(crate::engine::ChannelSet::App {
            token: "MOBILE_APP_TOKEN".to_owned(),
            socket: socket.clone(),
        })
    );
    assert_eq!(
        configured.settings,
        [
            "MOBILE_APP_SOCKET",
            "MOBILE_APP_ALLOW_ALL",
            "MOBILE_APP_HOME_CHANNEL",
            "agent.clarify_timeout"
        ]
    );
    assert_eq!(
        std::fs::read_to_string(lab.home.join(".hermes/plugins/enclos/plugin.yaml")).unwrap(),
        include_str!("../../../channels/hermes/enclos/plugin.yaml")
    );
    assert!(
        calls().ends_with(&format!(
            "-p default plugins enable enclos\n-p default config set MOBILE_APP_SOCKET {}\n-p default config set MOBILE_APP_ALLOW_ALL true\n-p default config set MOBILE_APP_HOME_CHANNEL home.home.default\n-p default config set agent.clarify_timeout 3600\n",
            socket.display()
        )),
        "{}",
        calls()
    );
    assert!(!calls().contains("0123abcd"), "{}", calls());
    assert!(
        staged_app_files(&lab).is_empty(),
        "{:?}",
        staged_app_files(&lab)
    );
}

/// The app channel's token granted only by the pending policy waits for
/// it: nothing runs, and nothing is staged, before `policy apply`.
#[test]
fn an_app_channel_whose_token_is_only_pending_is_refused() {
    use crate::secrets::InMemory;
    let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
    let store = std::rc::Rc::new(InMemory::default());
    let lab = Lab::with_secrets(Box::new(std::rc::Rc::clone(&store)));
    assert!(done(lab.install(INSTALLS, Confirm::Yes).unwrap()).installed);
    // A session under rules the grant changes keeps it pending.
    let sleeping = super::sandbox::Sleeping::new();
    let mut session = super::sandbox::session_of(&lab.engine, &lab.name, sleeping.process());
    session.compiled = Some("/compiled/at-launch.sb".into());
    super::sandbox::put(&lab.engine, &session);
    grant_app_token(&lab, Confirm::Ask);
    let err = configure_app(&lab, &[], None, Confirm::Yes).unwrap_err();
    assert!(
        err.to_string()
            .contains("pending policy of sandbox home gives agent default $MOBILE_APP_TOKEN")
            && err.to_string().contains("enclos policy apply home"),
        "{err}"
    );
    let calls = std::fs::read_to_string(lab.home.join("hermes-calls")).unwrap_or_default();
    assert!(!calls.contains("plugins enable"), "{calls}");
    assert!(staged_app_files(&lab).is_empty());
    drop(sleeping);
}

/// A socket path longer than a Unix socket's may be is refused before
/// anything runs or is staged, saying to move ENCLOS_HOME.
#[test]
fn an_app_channel_whose_socket_path_is_too_long_is_refused() {
    use crate::secrets::InMemory;
    let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
    let store = std::rc::Rc::new(InMemory::default());
    let root = super::Root {
        leaf: "e".repeat(80),
        ..super::Root::usual()
    };
    let lab = Lab::with_secrets_under(Box::new(std::rc::Rc::clone(&store)), &root);
    assert!(done(lab.install(INSTALLS, Confirm::Yes).unwrap()).installed);
    grant_app_token(&lab, Confirm::Yes);
    let socket = lab.engine.layout.agent_app_socket("home", "default");
    assert!(socket.as_os_str().len() > 103, "{}", socket.display());
    let err = configure_app(&lab, &[], None, Confirm::Yes).unwrap_err();
    assert!(
        err.to_string()
            .contains("longer than a Unix socket's path may be")
            && err.to_string().contains("ENCLOS_HOME"),
        "{err}"
    );
    let calls = std::fs::read_to_string(lab.home.join("hermes-calls")).unwrap_or_default();
    assert!(!calls.contains("plugins enable"), "{calls}");
    assert!(staged_app_files(&lab).is_empty());
}

/// A session is given the port its gateway listens on, and says why when
/// it is given none; the gateway's own launch is given none (ADR 0028).
#[test]
fn a_session_is_given_its_gateways_port_and_the_gateway_none() {
    let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
    let lab = Lab::new();
    assert!(done(lab.install(RECORDS_SERVICE_PORT, Confirm::Yes).unwrap()).installed);
    let ended = std::sync::atomic::AtomicBool::new(false);
    let end = lab
        .engine
        .launch_until(&alice(), &lab.name, "gateway", &ended)
        .unwrap();
    assert_eq!(end.exit, 0, "{end:?}");
    let seen = std::fs::read_to_string(lab.home.join("gateway-port")).unwrap();
    assert_eq!(seen, "none");

    let records = vec![
        "/bin/sh".into(),
        "-c".into(),
        "printf '%s' \"$ENCLOS_FAKE_SERVICE_PORT\" > \"$HOME/session-port\"".into(),
    ];
    let session_port = || std::fs::read_to_string(lab.home.join("session-port")).unwrap();
    // No gateway running: none, and why.
    let end = done(
        lab.engine
            .connect(&alice(), &lab.name, records.clone(), Confirm::Yes)
            .unwrap(),
    );
    assert_eq!(session_port(), "none");
    assert!(
        end.notes
            .iter()
            .any(|n| n.contains("cannot reach the gateway (the gateway is not running)")),
        "{:?}",
        end.notes
    );
    // A gateway listening: its port, and nothing to say.
    let (gateway, port) = super::listener::gateway(&lab.engine, &lab.name, 1);
    let end = lab
        .engine
        .connect(&alice(), &lab.name, records, Confirm::Yes);
    super::listener::end(gateway);
    let end = done(end.unwrap());
    assert_eq!(session_port(), port.to_string());
    assert!(
        !end.notes.iter().any(|n| n.contains("cannot reach")),
        "{:?}",
        end.notes
    );
}

#[test]
fn a_launch_ends_a_service_session_whose_launch_was_killed() {
    let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
    let lab = Lab::new();
    assert!(done(lab.install(LEAVES, Confirm::Yes).unwrap()).installed);
    // As the service manager's timeout leaves it: a session open, its
    // process gone.
    let dead = spawn_unmarked(&mut std::process::Command::new("/usr/bin/true")).unwrap();
    let root = crate::lifecycle::process::reference_of_child(&dead).unwrap();
    let mut dead = dead;
    dead.wait().unwrap();
    record_service_session(&lab, "gateway", root, None);
    assert_eq!(open_service_sessions(&lab).len(), 1);
    let ended = std::sync::atomic::AtomicBool::new(false);
    lab.engine
        .launch_until(&alice(), &lab.name, "gateway", &ended)
        .unwrap();
    assert!(open_service_sessions(&lab).is_empty());
}

/// Records an open session of the runtime service `service` whose
/// program is `root`, as a `launch` would have.
fn record_service_session(
    lab: &Lab,
    service: &str,
    root: crate::model::session::ProcessRef,
    pgid: Option<u32>,
) -> crate::model::session::SessionId {
    lab.engine
        .write(
            &alice(),
            "test",
            None,
            |_| String::new(),
            |lock| {
                let (version, snapshot) = lab.engine.state.active_policy(&lab.name)?.unwrap();
                let session = crate::model::session::SessionRecord {
                    id: crate::model::session::SessionId(0),
                    sandbox: lab.name.clone(),
                    kind: crate::model::session::SessionKind::Service,
                    service: Some(service.to_owned()),
                    version: version.version,
                    snapshot: snapshot.id,
                    compiled: None,
                    pgid,
                    root,
                    cgroup: None,
                    tracked: Vec::new(),
                    started_at: crate::model::now(),
                    ended_at: None,
                };
                Ok(lab.engine.state.put_session(lock, &session)?)
            },
        )
        .unwrap()
}

/// A `sleep` this test starts in a process group of its own, standing in
/// for the runtime of a service whose `launch` was killed: still running,
/// with nothing waiting for it but this test.
fn orphan_runtime() -> (std::process::Child, crate::model::session::ProcessRef) {
    use std::os::unix::process::CommandExt;
    let child = spawn_unmarked(
        std::process::Command::new("/bin/sleep")
            .arg("600")
            .process_group(0),
    )
    .unwrap();
    let root = crate::lifecycle::process::reference_of_child(&child).unwrap();
    (child, root)
}

/// Waits for the stub gateway to write its pids, runs `then`, then sets
/// `ended`.
fn end_once_started(
    pids_file: PathBuf,
    ended: std::sync::Arc<std::sync::atomic::AtomicBool>,
    then: impl FnOnce() + Send + 'static,
) -> std::thread::JoinHandle<Vec<u32>> {
    use std::time::{Duration, Instant};
    std::thread::spawn(move || {
        let start = Instant::now();
        while !pids_file.exists() {
            assert!(
                start.elapsed() < Duration::from_secs(30),
                "the stub gateway did not start"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        let pids = pids_in(&pids_file);
        then();
        ended.store(true, std::sync::atomic::Ordering::Relaxed);
        pids
    })
}

#[test]
fn a_launch_stops_a_live_session_of_its_service_before_starting_another() {
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;

    let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
    let lab = Lab::new();
    assert!(done(lab.install(GATEWAY, Confirm::Yes).unwrap()).installed);
    // The gateway a killed `launch` left running, and another service's
    // runtime, which this launch has no reason to touch.
    let (mut prior, prior_root) = orphan_runtime();
    let prior_id = record_service_session(&lab, "gateway", prior_root, Some(prior.id()));
    let (mut other, other_root) = orphan_runtime();
    let other_id = record_service_session(&lab, "mail", other_root, Some(other.id()));

    let ended = Arc::new(AtomicBool::new(false));
    // Whether the prior gateway still ran once the new one started; a
    // zombie, not yet reaped by this test, does not count.
    let prior_pid = prior.id();
    let prior_ran = std::sync::Arc::new(AtomicBool::new(true));
    let teller = {
        let prior_ran = Arc::clone(&prior_ran);
        end_once_started(
            lab.home.join("gateway-pids"),
            Arc::clone(&ended),
            move || {
                let running = crate::lifecycle::process::reference(prior_pid).unwrap();
                prior_ran.store(running.is_some(), std::sync::atomic::Ordering::Relaxed);
            },
        )
    };
    let end = lab
        .engine
        .launch_until(&alice(), &lab.name, "gateway", &ended)
        .unwrap();
    let started = teller.join().unwrap();

    assert!(
        !prior_ran.load(std::sync::atomic::Ordering::Relaxed),
        "the prior gateway still ran when the new one started"
    );
    prior.wait().unwrap();
    assert_eq!(end.left, Left::Nothing, "{end:?}");
    assert_gone(&started);
    // The other service's session is untouched.
    assert!(
        other.try_wait().unwrap().is_none(),
        "the other service's runtime was ended"
    );
    let open = open_service_sessions(&lab);
    assert_eq!(
        open.iter().map(|s| s.id).collect::<Vec<_>>(),
        [other_id],
        "{open:?}"
    );
    // The launch's audit entry says what it stopped.
    let audit = lab.audit();
    assert!(
        audit.contains(&format!(
            "after stopping and ending gateway service session {prior_id}, left by an earlier launch"
        )),
        "{audit}"
    );
    other.kill().unwrap();
    other.wait().unwrap();
}

/// Runs the gateway once, after `change` did what it does to the sandbox's
/// `tmp`, and says whether that is then a folder.
fn tmp_is_a_folder_after_a_launch(change: impl FnOnce(&Path)) -> bool {
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;

    let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
    let lab = Lab::new();
    assert!(done(lab.install(GATEWAY, Confirm::Yes).unwrap()).installed);
    let tmp = lab
        .engine
        .layout
        .sandbox_home(lab.name.as_str())
        .join("tmp");
    change(&tmp);
    let ended = Arc::new(AtomicBool::new(false));
    let teller = end_once_started(lab.home.join("gateway-pids"), Arc::clone(&ended), || {});
    lab.engine
        .launch_until(&alice(), &lab.name, "gateway", &ended)
        .unwrap();
    teller.join().unwrap();
    tmp.symlink_metadata().is_ok_and(|found| found.is_dir())
}

/// A sandbox may remove the folder `TMPDIR` names: a service gets it back as
/// it starts, as every other session does.
#[test]
fn a_service_gets_back_the_tmp_folder_its_sandbox_removed() {
    assert!(tmp_is_a_folder_after_a_launch(|tmp| {
        std::fs::remove_dir_all(tmp).unwrap();
    }));
}

/// What a sandbox leaves in its place cannot keep a service from starting,
/// or the service manager would start it again and again.
#[test]
fn a_file_a_sandbox_left_in_place_of_tmp_keeps_no_service_from_starting() {
    assert!(tmp_is_a_folder_after_a_launch(|tmp| {
        std::fs::remove_dir_all(tmp).unwrap();
        std::fs::write(tmp, "a file").unwrap();
    }));
}

/// A session starts in the group it records, for every kind of start: the
/// process tree alone would not show a mistake here, as `stop` would still
/// find the program.
#[test]
fn a_session_starts_in_the_group_it_records_as_what_it_was_started_for() {
    use crate::engine::start::{CommandKind, Group, Starting};
    use crate::lifecycle::process::group_of;
    use crate::model::session::SessionKind;

    let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
    let lab = Lab::new();
    assert!(done(lab.install(GATEWAY, Confirm::Yes).unwrap()).installed);
    let me = std::process::id();
    let mine = group_of(me).unwrap();
    let command = |group| Starting::Command {
        kind: CommandKind::Interactive,
        group,
        reads: &[],
    };
    let sleep = ["/bin/sleep".into(), "30".into()];
    for (starting, kind, service, ours, recorded_ours) in [
        (
            command(Group::Own),
            SessionKind::Interactive,
            None,
            false,
            false,
        ),
        (
            command(Group::ThisProcess),
            SessionKind::Interactive,
            None,
            true,
            true,
        ),
        (
            command(Group::Caller),
            SessionKind::Interactive,
            None,
            true,
            false,
        ),
        (
            Starting::Service { service: "gateway" },
            SessionKind::Service,
            Some("gateway".to_owned()),
            false,
            false,
        ),
    ] {
        let lock = lab.engine.state.lock().unwrap();
        let started = lab
            .engine
            .start_session(&lock, &lab.name, &sleep, starting, || Ok(()));
        drop(lock);
        let Ok(mut started) = started else {
            panic!("{starting:?} did not start");
        };
        let child = started.child.id();
        let group = group_of(child).unwrap();
        started.child.kill().unwrap();
        started.child.wait().unwrap();
        assert_eq!(group, if ours { mine } else { Some(child) }, "{starting:?}");
        let pgid = started.session.pgid;
        match (recorded_ours, ours) {
            (true, _) => assert_eq!(pgid, Some(me), "{starting:?}"),
            (false, true) => assert_eq!(pgid, None, "{starting:?}"),
            (false, false) => assert_eq!(pgid, Some(child), "{starting:?}"),
        }
        assert_eq!(started.session.kind, kind, "{starting:?}");
        assert_eq!(started.session.service, service, "{starting:?}");
    }
}

/// `sh` writes its pid, then becomes a long sleep: what a start that fails
/// must end.
fn writes_its_pid_and_sleeps(pid_file: &Path) -> Vec<std::ffi::OsString> {
    vec![
        "/bin/sh".into(),
        "-c".into(),
        "echo $$ > \"$0.new\"; mv \"$0.new\" \"$0\"; exec /bin/sleep 30".into(),
        pid_file.into(),
    ]
}

fn wait_for_pid(pid_file: &Path) -> u32 {
    use std::time::{Duration, Instant};
    let begun = Instant::now();
    while !pid_file.exists() {
        assert!(
            begun.elapsed() < Duration::from_secs(10),
            "it did not start"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    pids_in(pid_file)[0]
}

/// A start that fails once the program runs and before its marker is named,
/// for either kind of session, ends the program, and leaves no session open
/// and no marker behind.
#[test]
fn a_start_that_fails_before_it_is_recorded_ends_its_program() {
    use crate::engine::start::{CommandKind, Group, Starting};
    use crate::model::session::SessionKind;
    use std::cell::Cell;

    let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
    let lab = Lab::new();
    assert!(done(lab.install(GATEWAY, Confirm::Yes).unwrap()).installed);
    let pid_file = lab.home.join("program-pid");
    let command = writes_its_pid_and_sleeps(&pid_file);
    for starting in [
        Starting::Command {
            kind: CommandKind::Interactive,
            group: Group::Own,
            reads: &[],
        },
        Starting::Service { service: "gateway" },
    ] {
        let _ = std::fs::remove_file(&pid_file);
        let pid = Cell::new(0);
        let lock = lab.engine.state.lock().unwrap();
        let started = lab
            .engine
            .start_session(&lock, &lab.name, &command, starting, || {
                pid.set(wait_for_pid(&pid_file));
                Err::<(), _>(Error::Session {
                    what: "refused before it was recorded".into(),
                })
            });
        drop(lock);
        let Err(error) = started else {
            panic!("a start that failed was recorded");
        };
        assert!(error.to_string().contains("refused before"), "{error}");
        assert_eq!(
            crate::lifecycle::process::reference(pid.get()).unwrap(),
            None
        );
        let open = lab.engine.state.sessions(&lab.name, true).unwrap();
        assert!(
            open.iter().all(|s| s.kind == SessionKind::Proxy),
            "{open:?}"
        );
        let left: Vec<_> = std::fs::read_dir(lab.engine.markers(&lab.name))
            .map_or_else(|_| Vec::new(), |files| files.flatten().collect());
        assert!(left.is_empty(), "{left:?}");
    }
}

/// The state's write is the failure a start can really meet: by then the
/// marker is named, and the program is ended all the same.
#[test]
fn a_session_that_cannot_be_written_ends_its_program() {
    use crate::engine::start::Starting;
    use crate::model::session::SessionKind;
    use std::cell::Cell;

    let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
    let lab = Lab::new();
    assert!(done(lab.install(GATEWAY, Confirm::Yes).unwrap()).installed);
    let pid_file = lab.home.join("program-pid");
    let command = writes_its_pid_and_sleeps(&pid_file);
    let conn = rusqlite::Connection::open(lab.engine.layout.state_db()).unwrap();
    conn.execute_batch(
        "CREATE TRIGGER no_session BEFORE INSERT ON sessions
             BEGIN SELECT RAISE(ABORT, 'injected failure'); END;",
    )
    .unwrap();
    let pid = Cell::new(0);
    let lock = lab.engine.state.lock().unwrap();
    let started = lab.engine.start_session(
        &lock,
        &lab.name,
        &command,
        Starting::Service { service: "gateway" },
        || {
            pid.set(wait_for_pid(&pid_file));
            Ok(())
        },
    );
    drop(lock);
    conn.execute_batch("DROP TRIGGER no_session").unwrap();
    let Err(error) = started else {
        panic!("a session that was not written started");
    };
    assert!(error.to_string().contains("injected failure"), "{error}");
    assert_eq!(
        crate::lifecycle::process::reference(pid.get()).unwrap(),
        None
    );
    let open = lab.engine.state.sessions(&lab.name, true).unwrap();
    assert!(
        open.iter().all(|s| s.kind == SessionKind::Proxy),
        "{open:?}"
    );
}

/// A program that cannot start is named, for either kind of session, and
/// leaves no marker.
#[test]
fn a_program_that_cannot_start_is_named_and_leaves_no_marker() {
    use crate::engine::start::{CommandKind, Group, Starting};

    let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
    let lab = Lab::new();
    assert!(done(lab.install(GATEWAY, Confirm::Yes).unwrap()).installed);
    let command = ["/nonexistent/program".into()];
    for (starting, says) in [
        (
            Starting::Command {
                kind: CommandKind::Interactive,
                group: Group::Own,
                reads: &[],
            },
            format!("could not start /nonexistent/program in {}:", lab.name),
        ),
        (
            Starting::Service { service: "gateway" },
            format!(
                "could not start the {} gateway service:",
                RuntimeKind::Hermes
            ),
        ),
    ] {
        let lock = lab.engine.state.lock().unwrap();
        let started = lab
            .engine
            .start_session(&lock, &lab.name, &command, starting, || Ok(()));
        drop(lock);
        let Err(error) = started else {
            panic!("a program that does not exist started");
        };
        assert!(error.to_string().starts_with(&says), "{error}");
        let left: Vec<_> = std::fs::read_dir(lab.engine.markers(&lab.name))
            .map_or_else(|_| Vec::new(), |files| files.flatten().collect());
        assert!(left.is_empty(), "{left:?}");
    }
}

/// A `launch` ends what another service's killed `launch` left recorded,
/// which `stop_sessions`, asked only about its own service, would not reach.
#[test]
fn a_launch_ends_a_dead_session_of_another_service() {
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;

    let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
    let lab = Lab::new();
    assert!(done(lab.install(GATEWAY, Confirm::Yes).unwrap()).installed);
    let dead = record_service_session(&lab, "mail", super::sandbox::gone_process(), None);
    let ended = Arc::new(AtomicBool::new(false));
    let teller = end_once_started(lab.home.join("gateway-pids"), Arc::clone(&ended), || {});
    lab.engine
        .launch_until(&alice(), &lab.name, "gateway", &ended)
        .unwrap();
    teller.join().unwrap();
    let open = open_service_sessions(&lab);
    assert!(open.iter().all(|s| s.id != dead), "{open:?}");
}

#[test]
fn a_runtime_that_outlives_being_told_to_end_is_audited_and_its_session_stays_open() {
    use crate::lifecycle::stop::{Stopped, Survivor, Why};
    use crate::model::audit::AuditResult;
    use crate::model::session::Member;
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;

    let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
    // Nothing survives KILL on demand: this stop sends no signal and
    // reports the program as having survived both.
    let lab = Lab::stopping_with(|_, session, _| {
        Ok(Stopped::Survivors(vec![Survivor {
            member: Member {
                pid: session.root.pid,
                started: session.root.started.clone(),
                command: "hermes".into(),
            },
            why: Why::Survived,
        }]))
    });
    assert!(done(lab.install(GATEWAY, Confirm::Yes).unwrap()).installed);
    let ended = Arc::new(AtomicBool::new(false));
    let teller = end_once_started(lab.home.join("gateway-pids"), Arc::clone(&ended), || {});
    let err = lab
        .engine
        .launch_until(&alice(), &lab.name, "gateway", &ended)
        .unwrap_err();
    let started = teller.join().unwrap();
    assert!(err.to_string().contains("survived TERM and KILL"), "{err}");

    // The end is audited as failed, naming what still runs.
    let entries = lab.engine.audit(None).unwrap();
    let last = entries.last().unwrap();
    assert_eq!(last.intent.command, "service end");
    let outcome = &last.finished.as_ref().expect("finished").outcome;
    assert_eq!(outcome.result, AuditResult::Failed, "{outcome:?}");
    let open = open_service_sessions(&lab);
    assert_eq!(open.len(), 1, "{open:?}");
    let message = &outcome.message;
    assert!(
        message.contains(&format!("pid {} hermes", open[0].root.pid)),
        "{message}"
    );
    assert!(
        message.contains(&format!("session {} stays open", open[0].id)),
        "{message}"
    );
    assert_eq!(err.to_string(), *message);
    // The session stays open while its program runs; `sandbox stop`,
    // with the real stop, ends it.
    drop(lab);
    assert_gone(&started);
}

#[test]
fn a_runtime_enclos_cannot_stop_is_audited_and_its_session_stays_open() {
    use crate::lifecycle::process::PsError;
    use crate::model::audit::AuditResult;
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;

    let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
    // `ps` failing whenever the members are stopped: nothing is signalled.
    let lab = Lab::stopping_with(|_, _, _| Err(PsError::new("ps failed")));
    assert!(done(lab.install(GATEWAY, Confirm::Yes).unwrap()).installed);
    let ended = Arc::new(AtomicBool::new(false));
    let teller = end_once_started(lab.home.join("gateway-pids"), Arc::clone(&ended), || {});
    let err = lab
        .engine
        .launch_until(&alice(), &lab.name, "gateway", &ended)
        .unwrap_err();
    let started = teller.join().unwrap();
    assert!(
        err.to_string()
            .contains("could not stop the members of session"),
        "{err}"
    );

    // `launch` returns instead of trying again forever, and the end is
    // audited as failed.
    let entries = lab.engine.audit(None).unwrap();
    let last = entries.last().unwrap();
    assert_eq!(last.intent.command, "service end");
    let outcome = &last.finished.as_ref().expect("finished").outcome;
    assert_eq!(outcome.result, AuditResult::Failed, "{outcome:?}");
    assert!(outcome.message.contains("ps failed"), "{outcome:?}");
    let open = open_service_sessions(&lab);
    assert_eq!(open.len(), 1, "{open:?}");
    drop(lab);
    assert_gone(&started);
}

#[test]
fn a_launch_refuses_to_start_beside_an_earlier_session_that_does_not_stop() {
    use crate::lifecycle::stop::{Stopped, Survivor, Why};
    use crate::model::audit::AuditResult;
    use crate::model::session::Member;
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

    // The pid of the one runtime this stop reports as surviving KILL,
    // without signalling it; every other session it stops for real.
    static STUBBORN: AtomicU32 = AtomicU32::new(0);
    let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
    let lab = Lab::stopping_with(|cgroups, session, grace| {
        if session.root.pid != STUBBORN.load(Ordering::Relaxed) {
            return crate::lifecycle::stop::stop(cgroups, session, grace);
        }
        Ok(Stopped::Survivors(vec![Survivor {
            member: Member {
                pid: session.root.pid,
                started: session.root.started.clone(),
                command: "hermes".into(),
            },
            why: Why::Survived,
        }]))
    });
    assert!(done(lab.install(GATEWAY, Confirm::Yes).unwrap()).installed);
    // Two gateways that killed launches left: the first stops, the
    // second does not.
    let (mut first, first_root) = orphan_runtime();
    let first_id = record_service_session(&lab, "gateway", first_root, Some(first.id()));
    let (mut stubborn, stubborn_root) = orphan_runtime();
    STUBBORN.store(stubborn.id(), Ordering::Relaxed);
    let stubborn_id = record_service_session(&lab, "gateway", stubborn_root, Some(stubborn.id()));

    let ended = AtomicBool::new(false);
    let err = lab
        .engine
        .launch_until(&alice(), &lab.name, "gateway", &ended)
        .unwrap_err()
        .to_string();
    // It names the process to end, and the session it already ended.
    assert!(
        err.contains(&format!(
            "the gateway service session {stubborn_id} of sandbox {} did not stop (pid {} hermes: still runs after TERM and KILL)",
            lab.name,
            stubborn.id()
        )),
        "{err}"
    );
    assert!(err.contains("a second gateway was not started"), "{err}");
    assert!(err.contains("End what still runs"), "{err}");
    assert!(
        err.contains(&format!(
            "after stopping and ending gateway service session {first_id}, left by an earlier launch"
        )),
        "{err}"
    );

    // No gateway started; the first is stopped and its session ended;
    // the stubborn one's session stays open.
    assert!(!lab.home.join("gateway-pids").exists());
    assert!(
        first.try_wait().unwrap().is_some(),
        "the first gateway runs"
    );
    let open = open_service_sessions(&lab);
    assert_eq!(
        open.iter().map(|s| s.id).collect::<Vec<_>>(),
        [stubborn_id],
        "{open:?}"
    );
    // The failed launch entry says all of it.
    let entries = lab.engine.audit(None).unwrap();
    let last = entries.last().unwrap();
    assert_eq!(last.intent.command, "launch");
    let outcome = &last.finished.as_ref().expect("finished").outcome;
    assert_eq!(outcome.result, AuditResult::Failed, "{outcome:?}");
    assert_eq!(outcome.message, err);
    // `sandbox stop`, with the real stop, ends the stubborn runtime.
    drop(lab);
    stubborn.wait().unwrap();
}

#[test]
fn a_start_ends_the_proxy_a_connect_started_and_leaves_other_sessions() {
    use crate::model::session::SessionKind;
    use crate::service::fake::FakeServices;

    let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
    let fake = std::rc::Rc::new(FakeServices::default());
    let lab = Lab::with_services(Some(Box::new(std::rc::Rc::clone(&fake))));
    // The install starts a proxy as `connect` would, and records it.
    assert!(done(lab.install(INSTALLS, Confirm::Yes).unwrap()).installed);
    let sessions = lab.engine.state.sessions(&lab.name, true).unwrap();
    let proxy = sessions
        .iter()
        .find(|s| s.kind == SessionKind::Proxy)
        .expect("the install recorded a proxy")
        .clone();
    // Another session, which `start` has no reason to end.
    let mut other = spawn_unmarked(std::process::Command::new("/bin/sleep").arg("60")).unwrap();
    let root = crate::lifecycle::process::reference_of_child(&other).unwrap();
    lab.engine
        .write(
            &alice(),
            "test",
            None,
            |_| String::new(),
            |lock| {
                let (version, snapshot) = lab.engine.state.active_policy(&lab.name)?.unwrap();
                let session = crate::model::session::SessionRecord {
                    id: crate::model::session::SessionId(0),
                    sandbox: lab.name.clone(),
                    kind: SessionKind::Interactive,
                    service: None,
                    version: version.version,
                    snapshot: snapshot.id,
                    compiled: None,
                    pgid: None,
                    root,
                    cgroup: None,
                    tracked: Vec::new(),
                    started_at: crate::model::now(),
                    ended_at: None,
                };
                lab.engine.state.put_session(lock, &session)?;
                Ok(())
            },
        )
        .unwrap();

    lab.engine.start_sandbox(&alice(), &lab.name).unwrap();
    assert_eq!(fake.started.borrow().len(), 2);
    assert_gone(&[proxy.root.pid]);
    let open = lab.engine.state.sessions(&lab.name, true).unwrap();
    assert!(
        open.iter().all(|s| s.kind != SessionKind::Proxy),
        "{open:?}"
    );
    assert_eq!(
        open.iter()
            .filter(|s| s.kind == SessionKind::Interactive)
            .count(),
        1
    );
    assert!(
        other.try_wait().unwrap().is_none(),
        "the other session's program was ended"
    );
    other.kill().unwrap();
    other.wait().unwrap();
}
