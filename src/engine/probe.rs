//! `enclos policy test`: runs the escape probes inside a sandbox and checks
//! from the host what they managed to do (design §5, ADR 0016).

use std::ffi::OsString;
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStringExt;
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
use crate::model::secret::{SecretRef, SecretValue};
use crate::policy::paths::{FsPaths, PathContext};
use crate::probes::{
    ClosedBy, HostCheck, KEYCHAIN_PROBE_VALUE, KeychainItem, Outcome, Probe, ProbeInputs,
    ProbeResult, Proof, Run, host_service_probes, missing_workspaces, not_here, outcome, probes,
    sandboxed_script,
};
use crate::secrets::SecretStore;
use crate::secrets::keychain::Keychain;

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
    /// Whether the probes ran on the `(allow default)` baseline, which only
    /// a comparison asks for (ADR 0006): the report says so.
    pub allow_default: bool,
}

impl TestReport {
    fn count(&self, which: impl Fn(&Outcome) -> bool) -> usize {
        self.results.iter().filter(|r| which(&r.outcome)).count()
    }

    pub fn closed(&self) -> usize {
        self.count(|o| matches!(o, Outcome::Closed))
    }

    /// Closed probes whose route the `(deny default)` baseline closed, on a
    /// lookup it refuses before the rule the probe tests is reached.
    pub fn closed_by_baseline(&self) -> usize {
        self.count_closed(|r| r.closed_by == Some(ClosedBy::Baseline))
    }

    /// The closed probes that show something other than their route's
    /// rule, as the report says them: ` (1 by Seatbelt itself, 2 by the
    /// (deny default) baseline)`, or nothing.
    pub fn closed_apart(&self) -> String {
        let said: Vec<String> = [
            (self.closed_by_platform(), "by Seatbelt itself"),
            (self.closed_by_baseline(), "by the (deny default) baseline"),
        ]
        .into_iter()
        .filter(|(n, _)| *n > 0)
        .map(|(n, by)| format!("{n} {by}"))
        .collect();
        match said.is_empty() {
            true => String::new(),
            false => format!(" ({})", said.join(", ")),
        }
    }

    /// Closed probes whose route Seatbelt itself closes, whatever the
    /// compiled policy says: they show no rule enclos adds.
    pub fn closed_by_platform(&self) -> usize {
        self.count_closed(|r| r.closed_by == Some(ClosedBy::Seatbelt))
    }

    /// Closed probes that show something enclos adds: a rule of the route,
    /// or the `(deny default)` baseline, which is part of what it compiles.
    pub fn closed_by_enclos(&self) -> usize {
        self.count_closed(|r| r.closed_by != Some(ClosedBy::Seatbelt))
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

/// A throwaway item the "read a keychain item" probe tries to read from
/// inside the sandbox: stored in the default keychain, or the one
/// `ENCLOS_KEYCHAIN` names, under a service of its own,
/// `enclos.<install>.probe`, so it never stands for a secret, and removed
/// when the test ends. Where none can be stored (Linux, no default
/// keychain, a store that failed or did not answer), the report says why
/// the probe did not run.
struct KeychainProbe {
    store: Keychain,
    secret: SecretRef,
    item: KeychainItem,
}

impl KeychainProbe {
    fn store(
        layout: &crate::layout::Layout,
        name: &SandboxName,
    ) -> std::result::Result<KeychainProbe, String> {
        if !cfg!(target_os = "macos") {
            return Err("the Keychain is macOS's".to_owned());
        }
        let install = layout
            .install_id()
            .map_err(|e| format!("enclos cannot tell its install apart: {e}"))?;
        let service = format!("enclos.{install}.probe");
        let store = Keychain::from_env(service.clone());
        let secret: SecretRef = format!("{name}/probe")
            .parse()
            .map_err(|e| format!("{e}"))?;
        let value = SecretValue::new(KEYCHAIN_PROBE_VALUE.to_owned()).expect("not empty");
        if let Err(e) = store.set(&secret, &value) {
            // A store that went through but did not read back leaves an
            // item: it goes too. One refused before anything ran left none.
            let left = match e.untouched {
                true => String::new(),
                false => match store.remove(&secret) {
                    Ok(_) => String::new(),
                    Err(gone) => format!(
                        "; removing what it may have left failed too ({gone}): it is {}",
                        store.whereabouts(&secret)
                    ),
                },
            };
            return Err(format!("enclos could not store a test item: {e}{left}"));
        }
        Ok(KeychainProbe {
            item: KeychainItem {
                service,
                account: secret.to_string(),
                file: store.file().map(ToOwned::to_owned),
            },
            store,
            secret,
        })
    }
}

impl Drop for KeychainProbe {
    fn drop(&mut self) {
        if let Err(e) = self.store.remove(&self.secret) {
            eprintln!(
                "warning: the keychain item probe's test item stays: {e}; it is {}",
                self.store.whereabouts(&self.secret)
            );
        }
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
            let baseline = match r.allow_default {
                true => ", on the (allow default) comparison baseline",
                false => "",
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
            // The baseline's refused lookups count as closed only on
            // `(deny default)`, as the file compiled for these probes says.
            // Read before anything is started for the probes.
            let text = std::fs::read_to_string(&compiled).map_err(|source| LayoutError::Io {
                path: compiled.clone(),
                source,
            })?;
            let baseline = crate::backend::seatbelt::Baseline::of_compiled(&text).ok_or_else(
                || Error::Session {
                    what: format!(
                        "{} names no baseline enclos writes, though enclos just wrote it: a bug of enclos, or the file was edited meanwhile",
                        compiled.display()
                    ),
                },
            )?;
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
            let backend = self.backend_of(name)?;

            let mut target = Target::start()?;
            let terminal = OtherTerminal::open()?;
            let keychain = KeychainProbe::store(&self.layout, name);
            let mut inputs =
                self.probe_inputs(name, &ctx, Some(target.0.id()), Some(terminal.path.clone()))?;
            inputs.lookups_refused = baseline == crate::backend::seatbelt::Baseline::DenyDefault;
            let allow_default = !inputs.lookups_refused;
            inputs.keychain_item = keychain
                .as_ref()
                .map(|k| k.item.clone())
                .map_err(Clone::clone);
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
                not_here: not_here(&inputs),
                listens: inputs.listen,
                allow_default,
            })
        })
        .map(Planned::Done)
    }

    /// What the probes are built from. `target` is the process the signal
    /// probe aims at, and `other_terminal` the terminal the terminal probes
    /// try to open.
    pub(super) fn probe_inputs(
        &self,
        name: &SandboxName,
        ctx: &SandboxContext,
        target: Option<u32>,
        other_terminal: Option<PathBuf>,
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
            lookups_refused: false,
            target,
            other_terminal,
            tag: std::process::id(),
            keychain_item: Err("not probed here".into()),
            limits: policy.resources.clone(),
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
        let mut inputs =
            self.probe_inputs(name, &ctx, Some(0), Some(PathBuf::from("/dev/ttys0")))?;
        inputs.keychain_item = match cfg!(target_os = "macos") {
            true => Ok(KeychainItem {
                service: "enclos.probe".into(),
                account: format!("{name}/probe"),
                file: None,
            }),
            false => Err("the Keychain is macOS's".to_owned()),
        };
        let mut count = probes(&inputs).len();
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
                    closed_by: None,
                })
                .collect(),
            host_services: false,
            not_here: Vec::new(),
            listens: false,
            allow_default: false,
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

    /// What closed apart from a route's rule is said by who, and a route the
    /// baseline closed still shows something enclos compiles.
    #[test]
    fn closures_apart_from_the_rules_are_said_by_who() {
        let mut r = report(vec![Outcome::Closed; 4]);
        r.results[0].closed_by = Some(ClosedBy::Seatbelt);
        r.results[1].closed_by = Some(ClosedBy::Baseline);
        r.results[2].closed_by = Some(ClosedBy::Baseline);
        assert_eq!(
            r.closed_apart(),
            " (1 by Seatbelt itself, 2 by the (deny default) baseline)"
        );
        assert_eq!((r.closed_by_platform(), r.closed_by_baseline()), (1, 2));
        assert_eq!(report(vec![Outcome::Closed]).closed_apart(), "");
        let mut baseline_only = report(vec![Outcome::Closed]);
        baseline_only.results[0].closed_by = Some(ClosedBy::Baseline);
        assert!(baseline_only.passed());
        assert_eq!(baseline_only.closed_by_enclos(), 1);
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
            r.closed_by = Some(ClosedBy::Seatbelt);
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
            home: dir.join("enclos/sandboxes/home/home"),
            workspaces: Vec::new(),
            unmovable: Vec::new(),
            host_sockets: Vec::new(),
            proxy_port: 41001,
            listen: false,
            lookups_refused: false,
            target: Some(target),
            other_terminal: None,
            tag: 7,
            keychain_item: Err("not probed here".into()),
            limits: Default::default(),
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
