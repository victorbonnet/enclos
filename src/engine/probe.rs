//! `enclos policy test`: runs the escape probes inside a sandbox and checks
//! from the host what they managed to do (design §5, ADR 0016).

use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use signal_hook::consts::SIGTERM;

use super::Engine;
use crate::backend::{Launch, SandboxContext};
use crate::error::{Error, Result};
use crate::layout::LayoutError;
use crate::model::audit::Actor;
use crate::model::plan::{Confirm, Plan, Planned};
use crate::model::sandbox::SandboxName;
use crate::policy::paths::{PathContext, real_path};
use crate::probes::{
    HostCheck, Outcome, Probe, ProbeInputs, ProbeResult, Proof, Run, host_service_probes, not_here,
    outcome, probes, sandboxed_script,
};

/// What `enclos policy test` found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestReport {
    pub results: Vec<ProbeResult>,
    /// Whether the host-service probes ran.
    pub host_services: bool,
    /// What was not probed because it is not on this host.
    pub not_here: Vec<String>,
}

impl TestReport {
    fn count(&self, which: impl Fn(&Outcome) -> bool) -> usize {
        self.results.iter().filter(|r| which(&r.outcome)).count()
    }

    pub fn closed(&self) -> usize {
        self.count(|o| matches!(o, Outcome::Closed))
    }

    /// Closed probes whose route Seatbelt itself closes, whatever the
    /// compiled policy says: they show no rule enclos adds.
    pub fn closed_by_platform(&self) -> usize {
        self.count_closed(|r| r.closed_by_platform.is_some())
    }

    /// Closed probes that show a rule enclos adds.
    pub fn closed_by_enclos(&self) -> usize {
        self.count_closed(|r| r.closed_by_platform.is_none())
    }

    fn count_closed(&self, which: impl Fn(&ProbeResult) -> bool) -> usize {
        self.results
            .iter()
            .filter(|r| r.outcome == Outcome::Closed && which(r))
            .count()
    }

    pub fn open(&self) -> usize {
        self.count(|o| matches!(o, Outcome::Open(_)))
    }

    pub fn inconclusive(&self) -> usize {
        self.count(|o| matches!(o, Outcome::Inconclusive(_)))
    }

    /// Probes that could not run or be checked: their routes were not tested.
    pub fn not_run(&self) -> usize {
        self.count(|o| matches!(o, Outcome::NotRun(_)))
    }

    /// Whether the test passed: nothing got through, every probe ran, and at
    /// least one was shown closed by an enclos rule. An inconclusive probe
    /// does not fail it, but a test where none was closed, or only those
    /// Seatbelt itself closes, showed nothing about the policy.
    pub fn passed(&self) -> bool {
        self.open() == 0 && self.not_run() == 0 && self.closed_by_enclos() > 0
    }
}

/// How long the signal probe's target lives at most: longer than any test,
/// so that it ending on its own is never taken for the probe's TERM.
const TARGET_LIFETIME: &str = "3600";

/// The process the signal probe aims at, started by this command in a group
/// of its own, and always ended when the test ends.
struct Target(Child);

impl Target {
    fn start() -> Result<Target> {
        Command::new("/bin/sleep")
            .arg(TARGET_LIFETIME)
            .process_group(0)
            .spawn()
            .map(Target)
            .map_err(|e| Error::Session {
                what: format!("cannot start the signal probe's target: {e}"),
            })
    }
}

impl Drop for Target {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
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
            let platform = match r.closed_by_platform() {
                0 => String::new(),
                n => format!(" ({n} by Seatbelt itself)"),
            };
            format!(
                "{} probes: {} closed{platform}, {} open, {} inconclusive, {} not run",
                r.results.len(),
                r.closed(),
                r.open(),
                r.inconclusive(),
                r.not_run()
            )
        };
        self.wait_service_proxy(name)?;
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

            let mut target = Target::start()?;
            let inputs = self.probe_inputs(name, &ctx, Some(target.0.id()))?;
            let mut list = probes(&inputs);
            if host_services {
                list.extend(host_service_probes(&inputs));
            }
            let mut results = Vec::new();
            for probe in list {
                let run_in_sandbox = |script: String| {
                    let launch = Launch {
                        program: "/bin/sh".into(),
                        args: vec!["-c".into(), script.into()],
                        env: Vec::new(),
                    };
                    backend
                        .wrap(&compiled, &ctx, &launch)
                        .stdin(Stdio::null())
                        .output()
                };
                let outcome = run_probe(&probe, run_in_sandbox, &mut target.0);
                results.push(ProbeResult::of(probe, outcome));
            }
            Ok(TestReport {
                results,
                host_services,
                not_here: not_here(&inputs),
            })
        })
        .map(Planned::Done)
    }

    /// What the probes are built from. `target` is the process the signal
    /// probe aims at.
    fn probe_inputs(
        &self,
        name: &SandboxName,
        ctx: &SandboxContext,
        target: Option<u32>,
    ) -> Result<ProbeInputs> {
        let policy = self.policy(name)?.snapshot.policy;
        let paths = PathContext {
            user_home: ctx.user_home.clone(),
            sandbox_home: ctx.home.clone(),
        };
        // Every stored policy was validated, so each entry expands; one that
        // does not is an error, never a path silently left out.
        let expand = |entries: &[String]| {
            entries
                .iter()
                .map(|e| paths.expand(e).map(|p| real_path(&p)))
                .collect::<std::result::Result<Vec<_>, String>>()
                .map_err(|reason| Error::Session {
                    what: format!(
                        "the policy of sandbox {name} has a path enclos cannot expand: {reason}"
                    ),
                })
        };
        let read_deny = expand(&policy.fs.read_deny)?;
        let mut writes = expand(&policy.fs.write)?;
        writes.push(real_path(&ctx.home));
        Ok(ProbeInputs {
            user_home: ctx.user_home.clone(),
            data: self.layout.data().to_owned(),
            config_file: self.layout.config_file(),
            sandbox_dir: self.layout.sandbox_dir(name.as_str()),
            writes,
            other_sandboxes: self
                .state
                .list()?
                .iter()
                .filter(|r| r.name != *name)
                .map(|r| self.layout.sandbox_dir(r.name.as_str()))
                .collect(),
            read_deny,
            host_sockets: host_sockets(&ctx.user_home),
            target,
            tag: std::process::id(),
        })
    }

    /// What `policy test` would do, without doing it.
    fn plan_test(&self, name: &SandboxName, host_services: bool) -> Result<Plan> {
        let record = self.state.get(name)?.ok_or_else(|| Error::NoSuchSandbox {
            name: name.to_string(),
        })?;
        let version = self.policy(name)?.version.version;
        let ctx = self.sandbox_context(name, record.proxy_port);
        let inputs = self.probe_inputs(name, &ctx, None)?;
        // The signal probe needs its target, which a dry run does not start.
        let mut count = probes(&inputs).len() + 1;
        if host_services {
            count += host_service_probes(&inputs).len();
        }
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

/// Runs one probe: its control on the host, a look at the host before, the
/// probe in the sandbox through `run_in_sandbox`, and a look at the host
/// after.
fn run_probe(
    probe: &Probe,
    run_in_sandbox: impl FnOnce(String) -> std::io::Result<std::process::Output>,
    target: &mut Child,
) -> Outcome {
    let control = match control(probe) {
        Ok(control) => control,
        Err(why) => return Outcome::NotRun(why),
    };
    if let Some(check) = &probe.host
        && let Err(why) = before(check, target)
    {
        return Outcome::NotRun(why);
    }
    let run = match run_in_sandbox(sandboxed_script(probe)) {
        Ok(out) => Run::read(
            out.status.success(),
            &String::from_utf8_lossy(&out.stdout),
            &String::from_utf8_lossy(&out.stderr),
        ),
        Err(e) => Run::NotRun(format!("could not run it: {e}")),
    };
    let seen = match &probe.host {
        Some(check) => after(check, target),
        None => Ok(None),
    };
    let control = control.as_ref().map(|(ok, text)| (*ok, text.as_str()));
    outcome(probe, run, seen, control)
}

/// Runs the probe's control on the host: its success and output, none when
/// the probe's proof is the proxy's answer, or why it could not run.
fn control(probe: &Probe) -> std::result::Result<Option<(bool, String)>, String> {
    let Proof::Control { control, .. } = &probe.proof else {
        return Ok(None);
    };
    let out = Command::new("/bin/sh")
        .args(["-c", control.as_str()])
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("could not run its control outside the sandbox: {e}"))?;
    Ok(Some((out.status.success(), output(&out))))
}

fn output(out: &std::process::Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// Whether what the host check looks for is on the host now, or why it
/// cannot tell.
fn present(check: &HostCheck) -> std::result::Result<bool, String> {
    match check {
        HostCheck::File(path) => path
            .try_exists()
            .map_err(|e| format!("cannot look for {}: {e}", path.display())),
        // Absent when the tool says so; any other failure cannot tell.
        HostCheck::LaunchdJob(label) => {
            listed("/bin/launchctl", &["list", label], "Could not find service")
        }
        HostCheck::PreferencesDomain(domain) => {
            listed("/usr/bin/defaults", &["read", domain], "does not exist")
        }
        HostCheck::Target => Ok(false),
    }
}

fn listed(program: &str, args: &[&str], absent: &str) -> std::result::Result<bool, String> {
    let out = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("cannot run {program}: {e}"))?;
    let text = output(&out);
    match (out.status.success(), text.contains(absent)) {
        (true, _) => Ok(true),
        (false, true) => Ok(false),
        (false, false) => Err(format!(
            "{program} {} failed ({}): {}",
            args.join(" "),
            out.status,
            text.trim()
        )),
    }
}

/// Before the probe: what it would leave must not be there yet, and the
/// signal probe's target must still run, or the check after could not tell.
fn before(check: &HostCheck, target: &mut Child) -> std::result::Result<(), String> {
    match check {
        HostCheck::Target => match target.try_wait() {
            Ok(None) => Ok(()),
            Ok(Some(status)) => Err(format!("its target ended before the probe ({status})")),
            Err(e) => Err(format!("cannot look at its target: {e}")),
        },
        check => match present(check)? {
            false => Ok(()),
            true => Err(format!(
                "{} was already there, so the probe could not tell",
                describe(check)
            )),
        },
    }
}

/// After the probe: what it left on the host, removed, with whether removing
/// it worked; none when it left nothing; or why the host could not tell.
fn after(check: &HostCheck, target: &mut Child) -> std::result::Result<Option<String>, String> {
    if let HostCheck::Target = check {
        std::thread::sleep(Duration::from_millis(100));
        return match target.try_wait() {
            Ok(None) => Ok(None),
            Ok(Some(status)) if status.signal() == Some(SIGTERM) => {
                Ok(Some("the process outside was ended by TERM".to_owned()))
            }
            Ok(Some(status)) => Err(format!("its target ended on its own ({status})")),
            Err(e) => Err(format!("cannot look at its target: {e}")),
        };
    }
    if !present(check)? {
        return Ok(None);
    }
    let removed = match check {
        HostCheck::File(path) => std::fs::remove_file(path).map_err(|e| e.to_string()),
        HostCheck::LaunchdJob(label) => removed("/bin/launchctl", &["remove", label]),
        HostCheck::PreferencesDomain(domain) => removed("/usr/bin/defaults", &["delete", domain]),
        HostCheck::Target => unreachable!("handled above"),
    };
    let cleanup = match removed {
        Ok(()) => "removed".to_owned(),
        Err(why) => format!("STILL THERE: {why}; {}", by_hand(check)),
    };
    Ok(Some(format!("left {} ({cleanup})", describe(check))))
}

fn removed(program: &str, args: &[&str]) -> std::result::Result<(), String> {
    let out = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("cannot run {program}: {e}"))?;
    match out.status.success() {
        true => Ok(()),
        false => Err(format!("{program} failed: {}", output(&out).trim())),
    }
}

fn describe(check: &HostCheck) -> String {
    match check {
        HostCheck::File(path) => format!("the file {}", path.display()),
        HostCheck::LaunchdJob(label) => format!("the launchd job {label}"),
        HostCheck::PreferencesDomain(domain) => format!("the preferences domain {domain}"),
        HostCheck::Target => "the signal probe's target".to_owned(),
    }
}

fn by_hand(check: &HostCheck) -> String {
    match check {
        HostCheck::File(path) => format!("remove it with `rm {}`", path.display()),
        HostCheck::LaunchdJob(label) => format!("remove it with `launchctl remove {label}`"),
        HostCheck::PreferencesDomain(d) => format!("delete it with `defaults delete {d}`"),
        HostCheck::Target => String::new(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{ExitStatus, Output};

    fn report(outcomes: Vec<Outcome>) -> TestReport {
        TestReport {
            results: outcomes
                .into_iter()
                .map(|outcome| ProbeResult {
                    route: "r",
                    name: "n".into(),
                    outcome,
                    closed_by_platform: None,
                })
                .collect(),
            host_services: false,
            not_here: Vec::new(),
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_launchd_job_or_preferences_domain_nobody_made_is_absent() {
        // Read-only lookups of names no one uses.
        let label = format!("org.enclos.probe.absent.{}", std::process::id());
        assert_eq!(present(&HostCheck::LaunchdJob(label.clone())), Ok(false));
        assert_eq!(present(&HostCheck::PreferencesDomain(label)), Ok(false));
    }

    #[test]
    fn a_test_passes_only_when_every_probe_ran_none_got_through_and_one_was_closed() {
        assert!(report(vec![Outcome::Closed]).passed());
        // Inconclusive shows nothing either way: listed, not failed.
        let mixed = report(vec![Outcome::Closed, Outcome::Inconclusive("x".into())]);
        assert!(mixed.passed());
        assert_eq!((mixed.closed(), mixed.inconclusive()), (1, 1));
        let unrun = report(vec![Outcome::NotRun("x".into()); 3]);
        assert!(!unrun.passed());
        assert_eq!(unrun.not_run(), 3);
        // Seatbelt's own refusal of setuid programs shows no enclos rule.
        let mut platform = report(vec![Outcome::Closed, Outcome::Inconclusive("x".into())]);
        for r in &mut platform.results {
            r.closed_by_platform = Some("Seatbelt itself");
        }
        assert!(!platform.passed());
        assert_eq!(platform.closed_by_platform(), 1);
        platform
            .results
            .extend(report(vec![Outcome::Closed]).results);
        assert!(platform.passed());
        assert_eq!(
            (platform.closed_by_platform(), platform.closed_by_enclos()),
            (1, 1)
        );
        assert!(!report(vec![Outcome::Closed, Outcome::Open("x".into())]).passed());
        // Nothing closed is nothing shown.
        assert!(!report(vec![Outcome::Inconclusive("x".into()); 2]).passed());
        assert!(!report(Vec::new()).passed());
    }

    fn inputs(dir: &std::path::Path, target: u32) -> ProbeInputs {
        ProbeInputs {
            user_home: dir.to_owned(),
            data: dir.join("enclos"),
            config_file: dir.join("enclos/config.toml"),
            sandbox_dir: dir.join("enclos/sandboxes/home"),
            other_sandboxes: Vec::new(),
            writes: Vec::new(),
            read_deny: Vec::new(),
            host_sockets: Vec::new(),
            target: Some(target),
            tag: 7,
        }
    }

    fn probe_of(route: &str, dir: &std::path::Path, target: u32) -> Probe {
        probes(&inputs(dir, target))
            .into_iter()
            .find(|p| p.route == route)
            .unwrap()
    }

    /// A sandbox run that printed the marker and failed, as a refusal does.
    fn refused(_script: String) -> std::io::Result<Output> {
        Ok(Output {
            status: ExitStatus::from_raw(1 << 8),
            stdout: b"enclos-probe-ran\n".to_vec(),
            stderr: b"Operation not permitted\n".to_vec(),
        })
    }

    #[test]
    fn a_sandbox_that_refused_the_policy_runs_no_probe() {
        let dir = tempfile::tempdir().unwrap();
        let mut target = Target::start().unwrap();
        let write = probe_of("writes", dir.path(), target.0.id());
        let not_applied = |_: String| {
            Ok(Output {
                status: ExitStatus::from_raw(65 << 8),
                stdout: Vec::new(),
                stderr: b"sandbox-exec: policy.sb: No such file or directory\n".to_vec(),
            })
        };
        assert!(matches!(
            run_probe(&write, not_applied, &mut target.0),
            Outcome::NotRun(why) if why.contains("sandbox-exec")
        ));
        assert_eq!(run_probe(&write, refused, &mut target.0), Outcome::Closed);
    }

    #[test]
    fn a_file_the_probe_left_is_open_and_removed_and_one_there_before_is_not_run() {
        let dir = tempfile::tempdir().unwrap();
        let mut target = Target::start().unwrap();
        let write = probe_of("writes", dir.path(), target.0.id());
        let Some(HostCheck::File(file)) = write.host.clone() else {
            panic!("the write probe checks a file");
        };
        let wrote = |_: String| {
            std::fs::write(&file, "x").unwrap();
            refused(String::new())
        };
        assert!(matches!(
            run_probe(&write, wrote, &mut target.0),
            Outcome::Open(why) if why.contains("(removed)")
        ));
        assert!(!file.exists());

        std::fs::write(&file, "the user's").unwrap();
        assert!(matches!(
            run_probe(&write, refused, &mut target.0),
            Outcome::NotRun(why) if why.contains("already there")
        ));
        assert_eq!(std::fs::read_to_string(&file).unwrap(), "the user's");
    }

    #[test]
    fn the_signal_probe_is_open_only_when_its_target_got_term() {
        let dir = tempfile::tempdir().unwrap();
        let mut target = Target::start().unwrap();
        let signal = probe_of("signals", dir.path(), target.0.id());
        assert_eq!(run_probe(&signal, refused, &mut target.0), Outcome::Closed);
        let pid = target.0.id().to_string();
        let terminated = |_: String| {
            Command::new("/bin/kill")
                .args(["-TERM", &pid])
                .status()
                .unwrap();
            refused(String::new())
        };
        assert!(matches!(
            run_probe(&signal, terminated, &mut target.0),
            Outcome::Open(why) if why.contains("TERM")
        ));
        // A target that ended before the probe tells nothing.
        assert!(matches!(
            run_probe(&signal, refused, &mut target.0),
            Outcome::NotRun(why) if why.contains("ended before")
        ));
    }
}
