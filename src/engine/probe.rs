//! `enclos policy test`: runs the escape probes inside a sandbox and checks
//! from the host what they managed to do (design §5, ADR 0016).

use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

use super::Engine;
use crate::backend::Launch;
use crate::error::{Error, Result};
use crate::model::audit::Actor;
use crate::model::sandbox::SandboxName;
use crate::policy::paths::{PathContext, real_path};
use crate::probes::{HostCheck, Outcome, Probe, ProbeInputs, ProbeResult, judge, probes};

/// What `enclos policy test` found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestReport {
    pub results: Vec<ProbeResult>,
    /// Whether the host-service probes ran.
    pub host_services: bool,
}

impl TestReport {
    pub fn open(&self) -> usize {
        self.results
            .iter()
            .filter(|r| matches!(r.outcome, Outcome::Open(_)))
            .count()
    }
}

impl Engine {
    /// Runs every probe in the sandbox under its active policy.
    pub fn policy_test(
        &self,
        by: &Actor,
        name: &SandboxName,
        host_services: bool,
    ) -> Result<TestReport> {
        let summary = |r: &TestReport| format!("{} probes, {} open", r.results.len(), r.open());
        self.write(by, "policy test", Some(name.to_string()), summary, |lock| {
            let record = self.state.get(name)?.ok_or_else(|| Error::NoSuchSandbox {
                name: name.to_string(),
            })?;
            let ports = [record.port_base];
            let compiled = self.compile_policy(name, &ports)?;
            self.ensure_proxy(lock, &record)?;
            let policy = self.policy(name)?.snapshot.policy;
            let ctx = self.sandbox_context(name, &ports);
            std::fs::create_dir_all(ctx.home.join("tmp")).ok();
            let backend = self.backend_of(name)?;

            // The one process the signal probe aims at: started here, in a
            // group of its own, and always ended below.
            let mut outside = Command::new("/bin/sleep")
                .arg("60")
                .process_group(0)
                .spawn()
                .map_err(|e| Error::Session {
                    what: format!("cannot start the signal probe's target: {e}"),
                })?;
            let paths = PathContext {
                user_home: ctx.user_home.clone(),
                sandbox_home: ctx.home.clone(),
            };
            let inputs = ProbeInputs {
                user_home: ctx.user_home.clone(),
                data: ctx.data.clone(),
                config_file: ctx.config_file.clone(),
                other_sandboxes: self
                    .state
                    .list()?
                    .iter()
                    .filter(|r| r.name != *name)
                    .map(|r| self.layout.sandbox_dir(r.name.as_str()))
                    .collect(),
                read_deny: policy
                    .fs
                    .read_deny
                    .iter()
                    .filter_map(|e| paths.expand(e).ok())
                    .map(|p| real_path(&p))
                    .collect(),
                host_sockets: host_sockets(&ctx.user_home),
                outside_pid: outside.id(),
                tag: std::process::id(),
                host_services,
            };
            let mut results = Vec::new();
            for probe in probes(&inputs) {
                let launch = Launch {
                    program: "/bin/sh".into(),
                    args: vec!["-c".into(), probe.script.clone().into()],
                    proxy_port: record.port_base,
                    env: Vec::new(),
                };
                let out = backend
                    .wrap(&compiled, &ctx, &launch)
                    .stdin(Stdio::null())
                    .output();
                let outcome = match out {
                    Ok(out) => {
                        let text = format!(
                            "{}{}",
                            String::from_utf8_lossy(&out.stdout),
                            String::from_utf8_lossy(&out.stderr)
                        );
                        let own = judge(&probe, out.status.success(), &text);
                        settle(&probe, own, &mut outside)
                    }
                    Err(e) => Outcome::Skipped(format!("could not run: {e}")),
                };
                results.push(ProbeResult {
                    route: probe.route,
                    name: probe.name,
                    outcome,
                });
            }
            let _ = outside.kill();
            let _ = outside.wait();
            Ok(TestReport {
                results,
                host_services,
            })
        })
    }
}

/// Unix sockets of host services that exist on this host.
fn host_sockets(user_home: &std::path::Path) -> Vec<PathBuf> {
    let mut sockets: Vec<PathBuf> = std::env::var_os("SSH_AUTH_SOCK")
        .map(PathBuf::from)
        .into_iter()
        .collect();
    sockets.push(user_home.join(".docker/run/docker.sock"));
    sockets.push(PathBuf::from("/var/run/docker.sock"));
    sockets.into_iter().filter(|s| s.exists()).collect()
}

/// Checks from the host what the probe left, removes it, and gives the
/// final outcome: open if either the probe or the host saw it through.
fn settle(probe: &Probe, own: Outcome, outside: &mut std::process::Child) -> Outcome {
    let seen = match &probe.host {
        HostCheck::None => None,
        HostCheck::File(path) => path.exists().then(|| {
            let _ = std::fs::remove_file(path);
            format!("created {} (removed)", path.display())
        }),
        HostCheck::LaunchdJob(label) => {
            let listed = Command::new("/bin/launchctl")
                .arg("list")
                .output()
                .is_ok_and(|o| String::from_utf8_lossy(&o.stdout).contains(label.as_str()));
            listed.then(|| {
                let _ = Command::new("/bin/launchctl")
                    .args(["remove", label])
                    .status();
                format!("submitted launchd job {label} (removed)")
            })
        }
        HostCheck::PreferencesDomain(domain) => {
            let written = Command::new("/usr/bin/defaults")
                .args(["read", domain])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .is_ok_and(|s| s.success());
            written.then(|| {
                let _ = Command::new("/usr/bin/defaults")
                    .args(["delete", domain])
                    .status();
                format!("wrote preferences domain {domain} (deleted)")
            })
        }
        HostCheck::Process(_) => {
            std::thread::sleep(Duration::from_millis(100));
            outside
                .try_wait()
                .ok()
                .flatten()
                .map(|_| "the process outside was ended".to_owned())
        }
    };
    match (seen, own) {
        (Some(evidence), _) => Outcome::Open(evidence),
        (None, own) => own,
    }
}
