//! `enclos policy test`: runs the escape probes inside a sandbox and checks
//! from the host what they managed to do (design §5, ADR 0016).

use std::ffi::OsString;
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::PathBuf;

use crate::backend::{Baseline, LaunchLimits};
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
use crate::policy::paths::{FsPaths, PathContext};
use crate::probes::{
    Closer, HostCheck, Outcome, Probe, ProbeInputs, ProbeResult, Proof, ReportNotes, Run,
    ToolCheck, missing_workspaces, not_here, outcome, probes, sandboxed_script,
};

/// What `enclos policy test` found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestReport {
    pub results: Vec<ProbeResult>,
    /// Whether the host-service probes ran.
    pub host_services: bool,
    /// What was not probed because it is not on this host.
    pub not_here: Vec<String>,
    /// Whether the policy lets the sandbox listen on TCP (ADR 0028): open by
    /// the policy, so the report says so rather than probing it closed.
    pub listens: bool,
    /// The baseline the probes ran on: `(allow default)` only when a
    /// comparison asks for it (ADR 0006), which the report says. None for a
    /// backend that has no baseline.
    pub baseline: Option<Baseline>,
    /// What the report says of the backend's probes.
    pub notes: ReportNotes,
}

impl TestReport {
    fn count(&self, which: impl Fn(&Outcome) -> bool) -> usize {
        self.results.iter().filter(|r| which(&r.outcome)).count()
    }

    pub fn closed(&self) -> usize {
        self.count(|o| matches!(o, Outcome::Closed))
    }

    /// Closed probes whose route the baseline closed, on something it
    /// refuses the tool before the rule the probe tests is reached.
    pub fn closed_by_baseline(&self) -> usize {
        self.count_closed(|r| closer(r) == Some(Closer::Baseline))
    }

    /// The closed probes that show something other than their route's
    /// rule, as the report says them: ` (1 by Seatbelt itself, 2 by the
    /// (deny default) baseline)`, or nothing.
    pub fn closed_apart(&self) -> String {
        let said: Vec<String> = [Closer::Backend, Closer::Baseline]
            .into_iter()
            .filter_map(|by| {
                let closed = self
                    .results
                    .iter()
                    .filter(|r| r.outcome == Outcome::Closed && closer(r) == Some(by));
                let first = closed.clone().next()?.closed_by?;
                Some(format!("{} {}", closed.count(), first.by()))
            })
            .collect();
        match said.is_empty() {
            true => String::new(),
            false => format!(" ({})", said.join(", ")),
        }
    }

    /// Closed probes whose route the backend itself closes, whatever the
    /// compiled policy says: they show no rule enclos adds.
    pub fn closed_by_backend(&self) -> usize {
        self.count_closed(|r| closer(r) == Some(Closer::Backend))
    }

    /// Closed probes their route's own rule closed: neither the backend
    /// itself nor the baseline, which closes a route whether or not its rule
    /// is there, so shows nothing of the rule.
    pub fn closed_by_rule(&self) -> usize {
        self.count_closed(|r| r.closed_by.is_none())
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
    /// least one was shown closed by its route's rule. An inconclusive probe
    /// does not fail it, but a test where none was closed, or only those
    /// the backend itself or the baseline closes, showed nothing about the
    /// policy's rules.
    pub fn passed(&self) -> bool {
        self.open() == 0 && self.not_run() == 0 && self.closed_by_rule() > 0
    }
}

/// What closed a probe apart from its route's rule, if anything.
fn closer(result: &ProbeResult) -> Option<Closer> {
    result.closed_by.map(|by| by.closer)
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

/// The terminal the terminal probes try to open: opened by this command,
/// as a terminal app opens one for each tab, and closed when the test ends.
struct OtherTerminal {
    _main: OwnedFd,
    path: PathBuf,
}

impl OtherTerminal {
    fn open() -> Result<OtherTerminal> {
        OtherTerminal::open_pty().map_err(|e| Error::Session {
            what: format!(
                "cannot open a terminal for the terminal probes: {e}. If many terminal tabs are open, close some and run `enclos policy test` again"
            ),
        })
    }

    fn open_pty() -> rustix::io::Result<OtherTerminal> {
        use rustix::pty::{OpenptFlags, grantpt, openpt, ptsname, unlockpt};
        let main = openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY)?;
        grantpt(&main)?;
        unlockpt(&main)?;
        let name = ptsname(&main, Vec::new())?;
        Ok(OtherTerminal {
            _main: main,
            path: PathBuf::from(OsString::from_vec(name.into_bytes())),
        })
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
            let platform = r.closed_apart();
            let baseline = match r.baseline {
                Some(Baseline::AllowDefault) => ", on the (allow default) comparison baseline",
                Some(Baseline::DenyDefault) | None => "",
            };
            format!(
                "{} probes: {} closed{platform}, {} open, {} inconclusive, {} not run{baseline}",
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
            let backend = self.backend_of(name)?;
            // On Seatbelt, the baseline's refused lookups count as closed
            // only on `(deny default)`, as the file compiled for these probes
            // says. Read before anything is started for the probes.
            let text = std::fs::read_to_string(&compiled).map_err(|source| LayoutError::Io {
                path: compiled.clone(),
                source,
            })?;
            let mut own = backend
                .own_probes(Some(&text))
                .map_err(|why| Error::Session {
                    what: format!("{} {why}", compiled.display()),
                })?;
            // The limits the sandbox's processes run under, which the
            // resource probes show.
            let limits = self.launch_limits(&record, &self.active_policy(name)?.1.policy)?;
            self.ensure_proxy(lock, &record)?;
            let ctx = self.sandbox_context(name, record.proxy_port);
            // TMPDIR inside the sandbox (the policy denies /tmp): without it,
            // the probes would fail for a reason that is not the policy.
            let tmp = ctx.home.join("tmp");
            std::fs::create_dir_all(&tmp)
                .map_err(|source| LayoutError::Io { path: tmp, source })?;

            let mut target = Target::start()?;
            let terminal = OtherTerminal::open()?;
            let _set_up = own.set_up(&self.layout, name);
            let inputs = self.probe_inputs(
                name,
                &ctx,
                Some(target.0.id()),
                Some(terminal.path.clone()),
                limits.clone(),
            )?;
            let mut list = probes(&inputs, own.as_ref());
            if host_services {
                list.extend(own.host_services(&inputs));
            }
            let mut results = Vec::new();
            for probe in list {
                let run_in_sandbox = |script: String| {
                    let launch = Launch {
                        program: "/bin/sh".into(),
                        args: vec!["-c".into(), script.into()],
                        env: Vec::new(),
                        // The probes are enclos's own scripts: they get no
                        // more than a service does.
                        in_terminal: false,
                        service_port: None,
                        limits: limits.clone(),
                    };
                    backend
                        .wrap(&compiled, &ctx, &launch)
                        .stdin(Stdio::null())
                        .output()
                };
                let outcome = run_probe(&probe, run_in_sandbox, &mut target.0);
                results.push(ProbeResult::of(probe, outcome));
            }
            results.extend(missing_workspaces(&inputs));
            Ok(TestReport {
                results,
                host_services,
                not_here: not_here(&inputs, own.as_ref()),
                listens: inputs.listen,
                baseline: own.baseline(),
                notes: own.notes(),
            })
        })
        .map(Planned::Done)
    }

    /// What the probes are built from. `target` is the process the signal
    /// probe aims at, `other_terminal` the terminal the terminal probes try
    /// to open, and `limits` those the probes run under, which the resource
    /// probes show.
    pub(super) fn probe_inputs(
        &self,
        name: &SandboxName,
        ctx: &SandboxContext,
        target: Option<u32>,
        other_terminal: Option<PathBuf>,
        limits: LaunchLimits,
    ) -> Result<ProbeInputs> {
        let policy = self.policy(name)?.snapshot.policy;
        let paths = PathContext {
            user_home: ctx.user_home.clone(),
            sandbox_home: ctx.home.clone(),
        };
        // Every stored policy was validated, so each entry expands; one that
        // does not is an error, never a path silently left out. The compiler
        // starts from the same paths, so the probes check what it denies.
        let fs = FsPaths::of(&policy.fs, &paths).map_err(|reason| Error::Session {
            what: format!("the policy of sandbox {name} has a path enclos cannot expand: {reason}"),
        })?;
        let unmovable = fs.unmovable();
        let home = fs.home.clone();
        let mut workspaces: Vec<PathBuf> = Vec::new();
        for path in &fs.writes {
            if *path != home && !workspaces.contains(path) {
                workspaces.push(path.clone());
            }
        }
        let mut writes = fs.writes.clone();
        writes.push(home.clone());
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
            read_deny: fs.read_deny,
            home,
            workspaces,
            unmovable,
            host_sockets: host_sockets(&ctx.user_home),
            proxy_port: ctx.proxy_port,
            listen: policy.net.listen,
            target,
            other_terminal,
            tag: std::process::id(),
            limits,
        })
    }

    /// What `policy test` would do, without doing it.
    fn plan_test(&self, name: &SandboxName, host_services: bool) -> Result<Plan> {
        let record = self.state.get(name)?.ok_or_else(|| Error::NoSuchSandbox {
            name: name.to_string(),
        })?;
        let version = self.policy(name)?.version.version;
        let ctx = self.sandbox_context(name, record.proxy_port);
        // A dry run starts no target and opens no terminal: placeholders
        // stand for them, only to count the probes that use them.
        let limits = self.launch_limits(&record, &self.policy(name)?.snapshot.policy)?;
        // Not `backend_of`: a dry run asks nothing of the host, so it counts
        // the probes of a backend this host cannot run too. No compiled file
        // is read: the baseline only changes what closes a probe, not how
        // many run.
        let backend = match self.backends.iter().find(|b| b.kind() == record.backend) {
            Some(backend) => backend.as_ref(),
            None => self.backend_of(name)?,
        };
        let mut own = backend
            .own_probes(None)
            .map_err(|what| Error::Session { what })?;
        own.count_only(name);
        let inputs = self.probe_inputs(
            name,
            &ctx,
            Some(0),
            Some(PathBuf::from("/dev/ttys0")),
            limits,
        )?;
        let mut count = probes(&inputs, own.as_ref()).len();
        if host_services {
            count += own.host_services(&inputs).len();
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
                true => format!(
                    ", host-service routes included: they act on {} if a rule does not hold",
                    own.notes().host
                ),
                false => String::new(),
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
pub(super) fn run_probe(
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
/// the probe's proof is the proxy's 403 alone, or why it could not run.
fn control(probe: &Probe) -> std::result::Result<Option<(bool, String)>, String> {
    let control = match &probe.proof {
        Proof::Control { control, .. } | Proof::OnlyTheProxy { control } => control,
        Proof::ProxyRefuses => return Ok(None),
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
        HostCheck::Tool(tool) => listed(tool),
        HostCheck::Target => Ok(false),
    }
}

fn listed(tool: &ToolCheck) -> std::result::Result<bool, String> {
    let out = Command::new(tool.program)
        .args(&tool.look)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("cannot run {}: {e}", tool.program))?;
    let text = output(&out);
    match (out.status.success(), text.contains(tool.absent)) {
        (true, _) => Ok(true),
        (false, true) => Ok(false),
        (false, false) => Err(format!(
            "{} {} failed ({}): {}",
            tool.program,
            tool.look.join(" "),
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
        HostCheck::Tool(tool) => removed(tool),
        HostCheck::Target => unreachable!("handled above"),
    };
    let cleanup = match removed {
        Ok(()) => "removed".to_owned(),
        Err(why) => format!("STILL THERE: {why}; {}", by_hand(check)),
    };
    Ok(Some(format!("left {} ({cleanup})", describe(check))))
}

fn removed(tool: &ToolCheck) -> std::result::Result<(), String> {
    let out = Command::new(tool.program)
        .args(&tool.remove)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("cannot run {}: {e}", tool.program))?;
    match out.status.success() {
        true => Ok(()),
        false => Err(format!("{} failed: {}", tool.program, output(&out).trim())),
    }
}

fn describe(check: &HostCheck) -> String {
    match check {
        HostCheck::File(path) => format!("the file {}", path.display()),
        HostCheck::Tool(tool) => tool.what.clone(),
        HostCheck::Target => "the signal probe's target".to_owned(),
    }
}

fn by_hand(check: &HostCheck) -> String {
    match check {
        HostCheck::File(path) => format!("remove it with `rm {}`", path.display()),
        HostCheck::Tool(tool) => tool.by_hand.clone(),
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
    use crate::backend::seatbelt::probes::{BEFORE_THE_RULE, ITSELF, NOTES, SeatbeltProbes};
    use std::process::{ExitStatus, Output};

    fn report(outcomes: Vec<Outcome>) -> TestReport {
        TestReport {
            results: outcomes
                .into_iter()
                .map(|outcome| ProbeResult {
                    route: "r",
                    name: "n".into(),
                    outcome,
                    closed_by: None,
                })
                .collect(),
            host_services: false,
            not_here: Vec::new(),
            listens: false,
            baseline: Some(Baseline::DenyDefault),
            notes: NOTES,
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_launchd_job_or_preferences_domain_nobody_made_is_absent() {
        // Read-only lookups of names no one uses.
        let label = format!("org.enclos.probe.absent.{}", std::process::id());
        let job = crate::backend::seatbelt::probes::launchd_job(&label);
        let domain = crate::backend::seatbelt::probes::preferences_domain(&label);
        assert_eq!(present(&HostCheck::Tool(job)), Ok(false));
        assert_eq!(present(&HostCheck::Tool(domain)), Ok(false));
    }

    /// What closed apart from a route's rule is said by who, and a test the
    /// baseline alone closed shows no rule: deleting `(deny lsopen)` must
    /// not leave it READY on what the baseline refuses.
    #[test]
    fn closures_apart_from_the_rules_are_said_by_who() {
        let mut r = report(vec![Outcome::Closed; 4]);
        r.results[0].closed_by = Some(ITSELF);
        r.results[1].closed_by = Some(BEFORE_THE_RULE);
        r.results[2].closed_by = Some(BEFORE_THE_RULE);
        assert_eq!(
            r.closed_apart(),
            " (1 by Seatbelt itself, 2 by the (deny default) baseline)"
        );
        assert_eq!((r.closed_by_backend(), r.closed_by_baseline()), (1, 2));
        assert_eq!(report(vec![Outcome::Closed]).closed_apart(), "");
        let mut baseline_only = report(vec![Outcome::Closed]);
        baseline_only.results[0].closed_by = Some(BEFORE_THE_RULE);
        assert!(!baseline_only.passed());
        assert_eq!(baseline_only.closed_by_rule(), 0);
        baseline_only
            .results
            .extend(report(vec![Outcome::Closed]).results);
        assert!(baseline_only.passed());
        assert_eq!(baseline_only.closed_by_rule(), 1);
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
            r.closed_by = Some(ITSELF);
        }
        assert!(!platform.passed());
        assert_eq!(platform.closed_by_backend(), 1);
        platform
            .results
            .extend(report(vec![Outcome::Closed]).results);
        assert!(platform.passed());
        assert_eq!(
            (platform.closed_by_backend(), platform.closed_by_rule()),
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
            home: dir.join("enclos/sandboxes/home/home"),
            workspaces: Vec::new(),
            unmovable: Vec::new(),
            host_sockets: Vec::new(),
            proxy_port: 41001,
            listen: false,
            target: Some(target),
            other_terminal: None,
            tag: 7,
            limits: Default::default(),
        }
    }

    fn probe_of(route: &str, dir: &std::path::Path, target: u32) -> Probe {
        probes(
            &inputs(dir, target),
            &SeatbeltProbes::on(Baseline::AllowDefault),
        )
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
