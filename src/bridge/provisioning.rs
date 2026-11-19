//! Provisioning for the host's person for the mobile app. Every
//! change goes through the same engine and audit log as its CLI command.

use std::io::Read;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};

use enclos_protocol::device::{RuntimeInfo, RuntimeRelease, SandboxInfo};
use serde_json::Value;

use crate::engine::{Engine, INSTALL_STOP_TIME, Releases, RuntimeVersions, SandboxSpec};
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

const MOBILE_RUNTIMES: [RuntimeKind; 2] = [RuntimeKind::Hermes, RuntimeKind::OpenClaw];

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
        let runtime = runtime.parse::<RuntimeKind>().map_err(|e| e.to_string())?;
        if !MOBILE_RUNTIMES.contains(&runtime) {
            return Err(format!(
                "Install {} and set up its app channel from the host.",
                runtime.display_name()
            ));
        }
        Ok(Self::Install {
            name: sandbox.parse::<SandboxName>().map_err(|e| e.to_string())?,
            runtime,
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

/// The sandboxes for the host's person.
#[derive(Debug)]
pub struct Listed {
    pub sandboxes: Vec<SandboxInfo>,
    /// Whether a runtime's latest release was missing or kept too long,
    /// and was not looked up: a lookup is due.
    pub lookup_due: bool,
    /// What went wrong keeping the releases, for the bridge's log.
    pub notes: Vec<String>,
}

/// Clears the flag of a lookup under way when the lookup ends.
struct Running<'a>(&'a AtomicBool);

impl Drop for Running<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

/// Data a worker needs to open its own engine and to run enclos. It
/// contains no connection, database or device keys.
pub struct Host {
    layout: Layout,
    executable: PathBuf,
    /// Whether a thread looks the runtimes' releases up now.
    looking_up: AtomicBool,
}

impl Host {
    pub fn new(layout: Layout, executable: PathBuf) -> Self {
        Self {
            layout,
            executable,
            looking_up: AtomicBool::new(false),
        }
    }

    /// The sandboxes, at once, with what is kept of each runtime's latest
    /// release (ADR 0074, proposed), and whether a lookup is due.
    pub fn sandboxes(&self) -> Result<Listed, String> {
        let releases = Releases::kept();
        let sandboxes = sandbox_list(&self.engine(), &releases)?;
        Ok(Listed {
            sandboxes,
            lookup_due: releases.due(),
            notes: releases.notes(),
        })
    }

    /// The sandboxes once each of their runtimes' latest release is looked
    /// up, which can take 10 seconds a runtime; none when another thread is
    /// looking them up already. The sandboxes are read after the lookups,
    /// so a list sent meanwhile, after a sandbox was made, is not undone.
    pub fn sandboxes_looked_up(&self) -> Option<Result<Listed, String>> {
        if self.looking_up.swap(true, Ordering::SeqCst) {
            return None;
        }
        // Cleared however this ends, a panic included, so lookups go on.
        let _running = Running(&self.looking_up);
        let engine = self.engine();
        let releases = Releases::looking_up();
        let listed = engine.list_sandboxes().map_err(|e| e.to_string());
        Some(listed.and_then(|views| {
            let mut kinds: Vec<RuntimeKind> = Vec::new();
            for kind in views.iter().filter_map(|v| v.record.runtime) {
                if !kinds.contains(&kind) {
                    kinds.push(kind);
                }
            }
            for kind in kinds {
                engine.look_up_release(kind, &releases);
            }
            // Each runtime is found once: this pass waits on nothing.
            let sandboxes = sandbox_list(&engine, &releases)?;
            Ok(Listed {
                sandboxes,
                lookup_due: false,
                notes: releases.notes(),
            })
        }))
    }

    fn engine(&self) -> Engine {
        Engine::open(self.layout.clone(), crate::state::Wait::Command)
    }

    pub fn runtimes(&self) -> Vec<RuntimeInfo> {
        MOBILE_RUNTIMES.into_iter().map(|kind| RuntimeInfo {
            runtime: kind.to_string(),
            name: kind.display_name().to_owned(),
            description: "An agent runtime installed inside this sandbox. Login and app channel setup follow on the host.".to_owned(),
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
                // The CLI stops the installer and all it started, records
                // that and undoes the install: it knows the session.
                &format!("--time-limit={}", INSTALL_TIMEOUT.as_secs()),
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
        let Some(status) = wait_at_most(
            &mut child,
            INSTALL_TIMEOUT + INSTALL_STOP_TIME,
            INSTALL_STOP_GRACE,
        )?
        else {
            return Err(format!(
                "the installer did not finish within {} minutes, and enclos, which was to stop it, had not exited 5 minutes later, so it was killed: what the installer started may still run, with the runtime's destinations still in the sandbox's policy; check the sandbox on the host (`enclos sandbox show`, `enclos audit`)",
                INSTALL_TIMEOUT.as_secs() / 60
            ));
        };
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

/// How long a runtime install asked from the phone may run. Nobody watches
/// it at a terminal, and the sandbox stays busy for the phone while it
/// runs: one that hangs (a download that never ends, a prompt nobody
/// answers) is stopped rather than held for good. An hour leaves a slow
/// host and network room. `runtime install --time-limit` enforces it.
const INSTALL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60 * 60);
/// How long the CLI has to end, once told to (TERM), when it did not
/// within its own limit and the time it takes to stop, before its process
/// group is killed.
const INSTALL_STOP_GRACE: std::time::Duration = std::time::Duration::from_secs(30);

/// Waits for `child`, which leads a process group of its own, at most
/// `limit`: its exit status, or `None` when it ran longer and was stopped.
/// Its group is then sent TERM and, after `grace` or as soon as `child`
/// exits, KILL, so nothing of the group outlives it; `child` is reaped
/// once its group is killed, so the group's id cannot be another's yet.
/// What it started in other process groups is the CLI's to stop.
fn wait_at_most(
    child: &mut std::process::Child,
    limit: std::time::Duration,
    grace: std::time::Duration,
) -> Result<Option<std::process::ExitStatus>, String> {
    use rustix::process::{Pid, Signal, WaitId, WaitIdOptions, kill_process_group, waitid};
    let poll = std::time::Duration::from_millis(200);
    let lost = |e: std::io::Error| format!("cannot wait for the installer: {e}");
    let started = std::time::Instant::now();
    while started.elapsed() < limit {
        if let Some(status) = child.try_wait().map_err(lost)? {
            return Ok(Some(status));
        }
        std::thread::sleep(poll.min(limit.saturating_sub(started.elapsed())));
    }
    let group = Pid::from_raw(child.id() as i32).ok_or("the installer has no process id")?;
    let _ = kill_process_group(group, Signal::TERM);
    // Whether it exited, without reaping it.
    let exited = || {
        let options = WaitIdOptions::EXITED | WaitIdOptions::NOWAIT | WaitIdOptions::NOHANG;
        waitid(WaitId::Pid(group), options).map(|status| status.is_some())
    };
    let told = std::time::Instant::now();
    while told.elapsed() < grace && !exited().map_err(|e| lost(e.into()))? {
        std::thread::sleep(poll);
    }
    let _ = kill_process_group(group, Signal::KILL);
    child.wait().map_err(lost)?;
    Ok(None)
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

fn sandbox_list(engine: &Engine, releases: &Releases) -> Result<Vec<SandboxInfo>, String> {
    engine
        .list_sandboxes()
        .map_err(|e| e.to_string())
        .map(|views| {
            views
                .into_iter()
                .map(|view| {
                    let name = &view.record.name;
                    let versions = view
                        .record
                        .runtime
                        .map(|kind| engine.runtime_versions(name, kind, releases));
                    let told = versions.map(released).unwrap_or_default();
                    SandboxInfo {
                        sandbox: name.to_string(),
                        runtime: view.record.runtime.map(|kind| kind.to_string()),
                        state: match view.record.state {
                            SandboxState::Created => "created",
                            SandboxState::Running => "running",
                            SandboxState::Stopped => "stopped",
                            SandboxState::Failed { .. } => "failed",
                        }
                        .to_owned(),
                        runtime_version: told.version,
                        runtime_release: told.release,
                        runtime_outdated: told.outdated,
                    }
                })
                .collect()
        })
}

/// What a device is told of a runtime's versions: what the host knows,
/// leaving out what it cannot tell.
fn released(versions: RuntimeVersions) -> Released {
    Released {
        version: versions.version.known().cloned(),
        release: versions.latest.known().map(|latest| RuntimeRelease {
            version: latest.version.clone(),
            checked: latest.checked,
        }),
        outdated: versions.outdated.known().copied(),
    }
}

/// A sandbox's runtime versions, as a device is told them.
#[derive(Debug, Default, PartialEq, Eq)]
struct Released {
    version: Option<String>,
    release: Option<RuntimeRelease>,
    outdated: Option<bool>,
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

    /// `script` run by `sh`, leading a process group of its own, as the
    /// CLI that runs the installer is.
    fn group_child(script: &str) -> std::process::Child {
        Command::new("/bin/sh")
            .args(["-c", script])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .process_group(0)
            .spawn()
            .unwrap()
    }

    #[test]
    fn the_cli_has_an_hour_then_five_minutes_as_docs_protocol_says() {
        use std::time::Duration;
        assert_eq!(INSTALL_TIMEOUT, Duration::from_secs(3600));
        assert_eq!(INSTALL_STOP_TIME, Duration::from_secs(5 * 60));
        assert_eq!(INSTALL_STOP_GRACE, Duration::from_secs(30));
    }

    #[test]
    fn an_installer_that_ends_in_time_gives_its_status() {
        use std::time::Duration;
        let mut child = group_child("exit 3");
        let status = wait_at_most(&mut child, Duration::from_secs(10), Duration::ZERO)
            .unwrap()
            .unwrap();
        assert_eq!(status.code(), Some(3));
    }

    /// Whether `pid`, which this test started, is gone, looked at for up
    /// to 5 seconds: what it was a child of is gone too, and the system
    /// reaps it.
    fn gone(pid: u32) -> bool {
        let pid = rustix::process::Pid::from_raw(pid as i32).unwrap();
        let started = std::time::Instant::now();
        while started.elapsed() < std::time::Duration::from_secs(5) {
            if rustix::process::test_kill_process(pid).is_err() {
                return true;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        false
    }

    /// The pid `script` writes to `pid` in `dir`, once written.
    fn written_pid(dir: &std::path::Path) -> u32 {
        let file = dir.join("pid");
        let started = std::time::Instant::now();
        loop {
            if let Ok(text) = std::fs::read_to_string(&file)
                && let Ok(pid) = text.trim().parse()
            {
                return pid;
            }
            assert!(started.elapsed() < std::time::Duration::from_secs(5));
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }

    #[test]
    fn an_installer_past_its_time_is_stopped_then_killed() {
        use std::time::{Duration, Instant};
        // Ends on TERM: stopped within its grace, with what it started
        // in its group, which ignores TERM, killed rather than left.
        let dir = tempfile::tempdir().unwrap();
        let mut child = group_child(&format!(
            "(trap '' TERM; exec sleep 30) & echo $! > '{0}/pid.part' && mv '{0}/pid.part' '{0}/pid'; exec sleep 30",
            dir.path().display()
        ));
        let member = written_pid(dir.path());
        let started = Instant::now();
        let waited = wait_at_most(
            &mut child,
            Duration::from_millis(300),
            Duration::from_secs(10),
        );
        assert_eq!(waited, Ok(None));
        assert!(started.elapsed() < Duration::from_secs(5));
        assert!(child.try_wait().unwrap().is_some(), "reaped");
        assert!(gone(member), "pid {member} of its group still runs");
        // Ignores TERM (and so does its `sleep`): killed after the grace.
        let dir = tempfile::tempdir().unwrap();
        let mut child = group_child(&format!(
            "trap '' TERM; sleep 30 & echo $! > '{0}/pid.part' && mv '{0}/pid.part' '{0}/pid'; wait",
            dir.path().display()
        ));
        let member = written_pid(dir.path());
        let started = Instant::now();
        let waited = wait_at_most(
            &mut child,
            Duration::from_millis(300),
            Duration::from_millis(500),
        );
        assert_eq!(waited, Ok(None));
        assert!(started.elapsed() < Duration::from_secs(5));
        assert!(child.try_wait().unwrap().is_some(), "reaped");
        assert!(gone(member), "pid {member} of its group still runs");
    }

    #[test]
    fn a_sandbox_lists_its_runtime_version_and_the_kept_release_without_waiting() {
        use crate::audit::jsonl::JsonlAuditLog;
        use crate::backend::fake::FakeBackend;
        use crate::state::StateStore;
        use crate::state::sqlite::SqliteStateStore;

        let dir = tempfile::tempdir().unwrap();
        let layout = Layout::at(dir.path().join("data"));
        let state = || {
            SqliteStateStore::new(
                layout.state_db(),
                layout.state_lock(),
                crate::state::Wait::Command,
            )
        };
        let engine = Engine::new(
            layout.clone(),
            Box::new(state()),
            Box::new(JsonlAuditLog::new(layout.audit_log())),
            vec![Box::new(FakeBackend::available(BackendKind::Seatbelt))],
        );
        engine.init(&actor(), Confirm::Yes).unwrap();
        let name: SandboxName = "lab".parse().unwrap();
        create(&engine, &actor(), name.clone(), "minimal".parse().unwrap()).unwrap();
        // Hermes recorded, with the stamp its installer writes.
        let store = state();
        let lock = store.lock().unwrap();
        let mut record = store.get(&name).unwrap().unwrap();
        record.runtime = Some(RuntimeKind::Hermes);
        store.put(&lock, &record).unwrap();
        drop(lock);
        let checkout = layout.sandbox_home("lab").join(".hermes/hermes-agent");
        std::fs::create_dir_all(&checkout).unwrap();
        std::fs::write(
            checkout.join("install-stamp.json"),
            r#"{"baseVersion": "0.23.1"}"#,
        )
        .unwrap();

        // Nothing kept: the version installed at once, and a lookup due.
        let releases = Releases::kept();
        let listed = sandbox_list(&engine, &releases).unwrap();
        assert_eq!(listed[0].runtime_version.as_deref(), Some("0.23.1"));
        assert_eq!(listed[0].runtime_release, None);
        assert!(releases.due());

        // Kept: sent as it is, with whether it is newer and checked.
        let at = crate::model::now().as_second();
        let kept = format!(r#"{{"hermes": {{"at": {at}, "version": "0.23.2"}}}}"#);
        std::fs::write(layout.runtime_releases(), kept).unwrap();
        let releases = Releases::kept();
        let listed = sandbox_list(&engine, &releases).unwrap();
        assert_eq!(
            listed[0].runtime_release,
            Some(RuntimeRelease {
                version: "0.23.2".into(),
                checked: true,
            })
        );
        assert_eq!(listed[0].runtime_outdated, Some(true));
        assert!(!releases.due());

        // Kept longer than its keep time: still sent, and a lookup due.
        let old = at - 7 * 3600;
        let kept = format!(r#"{{"hermes": {{"at": {old}, "version": "0.23.2"}}}}"#);
        std::fs::write(layout.runtime_releases(), kept).unwrap();
        let releases = Releases::kept();
        let listed = sandbox_list(&engine, &releases).unwrap();
        assert!(listed[0].runtime_release.is_some());
        assert!(releases.due());

        // A lookup that just failed, with nothing found before: no release,
        // and none due, so an offline host does not look up at each request.
        let failed = format!(r#"{{"hermes": {{"at": {at}, "failed": "offline"}}}}"#);
        std::fs::write(layout.runtime_releases(), failed).unwrap();
        let releases = Releases::kept();
        let listed = sandbox_list(&engine, &releases).unwrap();
        assert_eq!(listed[0].runtime_release, None);
        assert_eq!(listed[0].runtime_outdated, None);
        assert!(!releases.due());

        // Turned off: the version still, no release, nothing due.
        let mut config = std::fs::read_to_string(layout.config_file()).unwrap();
        config.push_str("runtime_releases = false\n");
        std::fs::write(layout.config_file(), config).unwrap();
        std::fs::remove_file(layout.runtime_releases()).unwrap();
        let releases = Releases::kept();
        let listed = sandbox_list(&engine, &releases).unwrap();
        assert_eq!(listed[0].runtime_version.as_deref(), Some("0.23.1"));
        assert_eq!(listed[0].runtime_release, None);
        assert!(!releases.due());
    }

    #[test]
    fn one_lookup_runs_at_a_time_and_the_next_runs_after_one_that_failed() {
        let dir = tempfile::tempdir().unwrap();
        // Never initialised: listing fails, as the lookup would.
        let host = Host::new(Layout::at(dir.path().join("none")), "/unused".into());
        host.looking_up.store(true, Ordering::SeqCst);
        assert!(host.sandboxes_looked_up().is_none(), "one runs already");
        host.looking_up.store(false, Ordering::SeqCst);
        assert!(matches!(host.sandboxes_looked_up(), Some(Err(_))));
        assert!(!host.looking_up.load(Ordering::SeqCst), "cleared after it");
        assert!(host.sandboxes_looked_up().is_some());
    }

    #[test]
    fn a_device_is_told_what_the_host_knows_of_a_runtimes_versions() {
        use crate::engine::{Fact, LatestRelease};
        let latest = |version: &str| {
            Fact::Known(LatestRelease {
                version: version.into(),
                checked: false,
            })
        };
        let versions = |version: Fact<String>, latest, outdated| RuntimeVersions {
            version,
            latest,
            outdated,
        };
        // The version installed is newer than the latest release.
        let told = released(versions(
            Fact::Known("0.24.0".into()),
            latest("0.23.2"),
            Fact::Known(false),
        ));
        assert_eq!(told.version.as_deref(), Some("0.24.0"));
        assert_eq!(told.outdated, Some(false));
        // The latest release unknown: the version alone.
        let told = released(versions(
            Fact::Known("0.23.1".into()),
            Fact::CannotTell("offline".into()),
            Fact::CannotTell("the latest release is not known".into()),
        ));
        assert_eq!(
            told,
            Released {
                version: Some("0.23.1".into()),
                ..Released::default()
            }
        );
        // The version installed unknown: the release, and no comparison.
        let told = released(versions(
            Fact::Absent,
            latest("2026.11.6"),
            Fact::CannotTell("the version installed is not known".into()),
        ));
        assert_eq!((told.version, told.outdated), (None, None));
        assert!(told.release.is_some());
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
        assert!(sandbox_list(&engine, &Releases::kept()).unwrap().is_empty());
        create(
            &engine,
            &actor(),
            "lab".parse().unwrap(),
            "minimal".parse().unwrap(),
        )
        .unwrap();
        assert_eq!(
            sandbox_list(&engine, &Releases::kept()).unwrap(),
            vec![SandboxInfo {
                sandbox: "lab".into(),
                runtime: None,
                state: "created".into(),
                runtime_version: None,
                runtime_release: None,
                runtime_outdated: None,
            }]
        );
        assert!(engine.app_agents().unwrap().agents.is_empty());
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
test "$#" = 8 && test "$1" = --json && test "$2" = runtime && test "$3" = install && test "$4" = hermes && test "$5" = --sandbox && test "$6" = lab && test "$7" = "--requested-by=owner@example.org (device phone-1)" && test "$8" = --time-limit=3600 || exit 10
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

#[cfg(test)]
mod mobile_runtime_tests {
    use super::*;

    #[test]
    fn openclaw_is_available_for_phone_provisioning_with_its_app_channel() {
        let host = Host::new(Layout::at(std::path::Path::new("/unused")), PathBuf::new());
        assert!(
            host.runtimes()
                .iter()
                .any(|info| info.runtime == "openclaw")
        );
        assert!(Operation::install("lab", "openclaw").is_ok());
        assert!(Operation::install("lab", "hermes").is_ok());
    }
}
