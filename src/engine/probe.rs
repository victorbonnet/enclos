//! `enclos policy test`: runs the escape probes inside a sandbox and checks
//! from the host what they managed to do (design §5, ADR 0016).

use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

use super::Engine;
use crate::backend::{Launch, SandboxContext};
use crate::error::{Error, Result};
use crate::layout::LayoutError;
use crate::model::audit::Actor;
use crate::model::plan::{Confirm, Plan, Planned};
use crate::model::sandbox::SandboxName;
use crate::policy::paths::{PathContext, real_path};
use crate::probes::{HostCheck, Outcome, Probe, ProbeInputs, ProbeResult, conclude, judge, probes};

/// What `enclos policy test` found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestReport {
    pub results: Vec<ProbeResult>,
    /// Whether the host-service probes ran.
    pub host_services: bool,
}

impl TestReport {
    fn count(&self, which: impl Fn(&Outcome) -> bool) -> usize {
        self.results.iter().filter(|r| which(&r.outcome)).count()
    }

    pub fn closed(&self) -> usize {
        self.count(|o| matches!(o, Outcome::Closed))
    }

    pub fn open(&self) -> usize {
        self.count(|o| matches!(o, Outcome::Open(_)))
    }

    pub fn inconclusive(&self) -> usize {
        self.count(|o| matches!(o, Outcome::Inconclusive(_)))
    }

    /// Probes that could not run: their routes were not tested.
    pub fn not_run(&self) -> usize {
        self.count(|o| matches!(o, Outcome::NotRun(_)))
    }

    /// Whether the test passed: nothing got through, and every probe ran.
    /// An inconclusive probe does not fail it, but does not count as closed.
    pub fn passed(&self) -> bool {
        self.open() == 0 && self.not_run() == 0
    }
}

impl Engine {
    /// Runs every probe in the sandbox under its active policy.
    pub fn policy_test(
        &self,
        by: &Actor,
        name: &SandboxName,
        host_services: bool,
        confirm: Confirm,
    ) -> Result<Planned<TestReport>> {
        if confirm == Confirm::DryRun {
            return self.plan_test(name, host_services).map(Planned::DryRun);
        }
        let summary = |r: &TestReport| {
            format!(
                "{} probes: {} closed, {} open, {} inconclusive, {} not run",
                r.results.len(),
                r.closed(),
                r.open(),
                r.inconclusive(),
                r.not_run()
            )
        };
        self.write(by, "policy test", Some(name.to_string()), summary, |lock| {
            let record = self.state.get(name)?.ok_or_else(|| Error::NoSuchSandbox {
                name: name.to_string(),
            })?;
            let compiled = self.compile_policy(name, record.proxy_port)?;
            self.ensure_proxy(lock, &record)?;
            let ctx = self.sandbox_context(name, record.proxy_port);
            // TMPDIR inside the sandbox (the policy denies /tmp): without it,
            // the probes would fail for a reason that is not the policy.
            let tmp = ctx.home.join("tmp");
            std::fs::create_dir_all(&tmp)
                .map_err(|source| LayoutError::Io { path: tmp, source })?;
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
            let inputs = self.probe_inputs(name, &ctx, outside.id(), host_services);
            let mut results = Vec::new();
            for probe in probes(&inputs?) {
                let outcome = match control(&probe) {
                    Err(why) => Outcome::NotRun(why),
                    Ok(control) => {
                        let launch = Launch {
                            program: "/bin/sh".into(),
                            args: vec!["-c".into(), probe.script.clone().into()],
                            env: Vec::new(),
                        };
                        let out = backend
                            .wrap(&compiled, &ctx, &launch)
                            .stdin(Stdio::null())
                            .output();
                        match out {
                            Ok(out) => {
                                let own = judge(&probe, out.status.success(), &output(&out));
                                let seen = settle(&probe, own, &mut outside);
                                let control =
                                    control.as_ref().map(|(ok, text)| (*ok, text.as_str()));
                                conclude(seen, control)
                            }
                            Err(e) => Outcome::NotRun(format!("could not run it: {e}")),
                        }
                    }
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
        .map(Planned::Done)
    }

    /// What the probes are built from. `outside` is the process the signal
    /// probe aims at.
    fn probe_inputs(
        &self,
        name: &SandboxName,
        ctx: &SandboxContext,
        outside: u32,
        host_services: bool,
    ) -> Result<ProbeInputs> {
        let policy = self.policy(name)?.snapshot.policy;
        let paths = PathContext {
            user_home: ctx.user_home.clone(),
            sandbox_home: ctx.home.clone(),
        };
        Ok(ProbeInputs {
            user_home: ctx.user_home.clone(),
            data: self.layout.data().to_owned(),
            config_file: self.layout.config_file(),
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
            outside_pid: outside,
            tag: std::process::id(),
            host_services,
        })
    }

    /// What `policy test` would do, without doing it.
    fn plan_test(&self, name: &SandboxName, host_services: bool) -> Result<Plan> {
        let record = self.state.get(name)?.ok_or_else(|| Error::NoSuchSandbox {
            name: name.to_string(),
        })?;
        let version = self.policy(name)?.version.version;
        let ctx = self.sandbox_context(name, record.proxy_port);
        let count = probes(&self.probe_inputs(name, &ctx, 0, host_services)?).len();
        let mut changes = Vec::new();
        if !self.proxy_runs(name)? {
            changes.push(format!(
                "start the proxy of sandbox {name} on port {}",
                record.proxy_port
            ));
        }
        changes.push(format!(
            "run {count} escape probes in sandbox {name} under policy v{version}{}",
            match host_services {
                true =>
                    ", host-service routes included: they act on this Mac if a rule does not hold",
                false => "",
            }
        ));
        Ok(Plan {
            changes,
            ..Plan::default()
        })
    }
}

/// Runs the probe's control outside the sandbox: its success and output,
/// none when the probe has no control, or why it could not run.
fn control(probe: &Probe) -> std::result::Result<Option<(bool, String)>, String> {
    let Some(script) = &probe.control else {
        return Ok(None);
    };
    let out = Command::new("/bin/sh")
        .args(["-c", script])
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("could not run its check outside the sandbox: {e}"))?;
    Ok(Some((out.status.success(), output(&out))))
}

fn output(out: &std::process::Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
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

#[cfg(test)]
mod tests {
    use super::*;

    fn report(outcomes: Vec<Outcome>) -> TestReport {
        TestReport {
            results: outcomes
                .into_iter()
                .map(|outcome| ProbeResult {
                    route: "r",
                    name: "n".into(),
                    outcome,
                })
                .collect(),
            host_services: false,
        }
    }

    #[test]
    fn a_test_passes_only_when_every_probe_ran_and_none_got_through() {
        assert!(report(vec![Outcome::Closed]).passed());
        // Inconclusive shows nothing either way: listed, not failed.
        let mixed = report(vec![Outcome::Closed, Outcome::Inconclusive("x".into())]);
        assert!(mixed.passed());
        assert_eq!((mixed.closed(), mixed.inconclusive()), (1, 1));
        let unrun = report(vec![Outcome::NotRun("x".into()); 3]);
        assert!(!unrun.passed());
        assert_eq!(unrun.not_run(), 3);
        assert!(!report(vec![Outcome::Closed, Outcome::Open("x".into())]).passed());
    }
}
