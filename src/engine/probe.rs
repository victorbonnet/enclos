//! `enclos policy test`: runs the escape probes inside a sandbox and checks
//! from the host what they managed to do (design §5, ADR 0016).

use std::ffi::OsString;
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::PathBuf;

use crate::backend::LaunchLimits;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use signal_hook::consts::SIGTERM;

use super::Engine;
use super::policy::leaving_out;
use super::start::SCOPE_END_WAIT;
use crate::backend::{Launch, SandboxContext};
use crate::error::{Error, Result};
use crate::layout::LayoutError;
use crate::lifecycle::cgroup::Scopes;
use crate::model::audit::Actor;
use crate::model::plan::{Confirm, Plan, Planned};
use crate::model::sandbox::SandboxName;
use crate::model::unenforced::NotEnforced;
use crate::policy::paths::{FsPaths, PathContext};
use crate::probes::{
    Closer, HostCheck, Outcome, Probe, ProbeInputs, ProbeResult, Proof, ReportNotes, Run,
    TARGET_VARIABLE, ToolCheck, not_here, outcome, probes, sandboxed_script, set_aside_notices,
    with_real_paths,
};

struct ProbeRun<'a> {
    store: &'a dyn crate::state::StateStore,
    tag: String,
}
impl Drop for ProbeRun<'_> {
    fn drop(&mut self) {
        if let Err(e) = self.store.end_probe(&self.tag) {
            eprintln!("enclos: could not close diagnostic run metadata: {e}");
        }
    }
}
fn tag_probe(probe: &mut Probe, tag: &str) {
    let mark = |script: &str| {
        script.replace(
            "/usr/bin/curl ",
            &format!("/usr/bin/curl --proxy-header 'X-Enclos-Probe: {tag}' "),
        )
    };
    probe.script = mark(&probe.script);
    match &mut probe.proof {
        Proof::Control { control, .. } | Proof::OnlyTheProxy { control } => {
            *control = crate::probes::HostScript::new(mark(control.as_str()))
        }
        Proof::ProxyRefuses => (),
    }
}

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
    /// What the report says of the backend's probes, the baseline they ran
    /// on included.
    pub notes: ReportNotes,
    /// What enclos itself said on the probes' sessions, each once, such as
    /// that the kernel has no Landlock (design §5): not any probe's answer.
    pub notices: Vec<String>,
    /// What the sandbox's policy sets that this host does not enforce, with
    /// whether each is accepted (ADR 0038): the probes ran without it.
    pub not_enforced: Vec<NotEnforced>,
}

impl TestReport {
    fn count(&self, which: impl Fn(&Outcome) -> bool) -> usize {
        self.results.iter().filter(|r| which(&r.outcome)).count()
    }

    pub fn closed(&self) -> usize {
        self.count(|o| matches!(o, Outcome::Closed))
    }

    /// The closed probes that show something other than their route's rule,
    /// counted by what closed them (` (1 by ..., 2 by ...)`), or nothing.
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

    /// Closed probes their route's own rule closed: neither the backend
    /// itself nor the baseline, which closes a route whether or not its rule
    /// is there, so shows nothing of the rule.
    pub fn closed_by_rule(&self) -> usize {
        self.results
            .iter()
            .filter(|r| r.outcome == Outcome::Closed && r.closed_by.is_none())
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

    /// Whether the test passed: nothing got through, every probe ran, at
    /// least one was shown closed by its route's rule, and every field this
    /// host does not enforce is accepted (ADR 0038). An inconclusive probe
    /// does not fail it, but a test where none was closed, or only those
    /// the backend itself or the baseline closes, showed nothing about the
    /// policy's rules.
    pub fn passed(&self) -> bool {
        self.open() == 0
            && self.not_run() == 0
            && self.closed_by_rule() > 0
            && self.not_accepted().next().is_none()
    }

    /// The fields this host does not enforce that are not accepted, or
    /// accepted at another value.
    pub fn not_accepted(&self) -> impl Iterator<Item = &NotEnforced> {
        self.not_enforced.iter().filter(|n| !n.is_accepted())
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
/// of its own, and always ended when the test ends. It carries
/// [`TARGET_VARIABLE`], so that a probe of its environment tells it apart.
struct Target(Child);

impl Target {
    fn start() -> Result<Target> {
        Command::new("/bin/sleep")
            .arg(TARGET_LIFETIME)
            .env(TARGET_VARIABLE, "1")
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
            let baseline = r
                .notes
                .comparison
                .map(|c| format!(", on {c}"))
                .unwrap_or_default();
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
            // Each probe runs in a scope, as a session's program does: on a
            // host whose systemd cannot start one, nothing starts.
            if let Some(what) = self.scopes.as_ref().and_then(Scopes::refusal) {
                return Err(Error::Session { what });
            }
            let record = self.state.get(name)?.ok_or_else(|| Error::NoSuchSandbox {
                name: name.to_string(),
            })?;
            let compiled = self.compile_policy(name, record.proxy_port)?;
            let backend = self.backend_of(name)?;
            // Read before anything starts: the backend's probes depend on
            // what was compiled.
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
            // resource probes show, without what this host does not
            // enforce: the report names each, and fails on one not
            // accepted rather than refusing to probe.
            let policy = self.active_policy(name)?.1.policy;
            let not_enforced = self.not_enforced(name, record.backend, &policy)?;
            let limits = leaving_out(self.checked_limits(&record, &policy)?, &not_enforced);
            self.ensure_proxy(lock, &record)?;
            self.ensure_holder(&record)?;
            let ctx = self.sandbox_context(name, record.proxy_port);
            // TMPDIR inside the sandbox (the policy denies /tmp): without it,
            // the probes would fail for a reason that is not the policy.
            let tmp = ctx.home.join("tmp");
            std::fs::create_dir_all(&tmp)
                .map_err(|source| LayoutError::Io { path: tmp, source })?;

            let mut target = Target::start()?;
            let terminal = OtherTerminal::open()?;
            let inputs = self.probe_inputs(
                name,
                &ctx,
                Some(target.0.id()),
                Some(terminal.path.clone()),
                limits.clone(),
            )?;
            let _set_up = own.set_up(&self.layout, name, &inputs);
            let mut list = probes(&inputs, own.as_ref());
            if host_services {
                list.extend(own.host_services(&inputs));
            }
            let mut results = Vec::new();
            let mut notices: Vec<String> = Vec::new();
            let tag: String = crate::bridge::ids::random_bytes(32)
                .map_err(|e| Error::Session {
                    what: e.to_string(),
                })?
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            self.state.begin_probe(name, &tag)?;
            let _run = ProbeRun {
                store: self.state.as_ref(),
                tag: tag.clone(),
            };
            for mut probe in list {
                tag_probe(&mut probe, &tag);
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
                        reads: Vec::new(),
                    };
                    let wrapped = backend
                        .wrap(&compiled, &ctx, &launch)
                        .map_err(std::io::Error::other)?;
                    let mut out = self.run_scoped(name, wrapped, &launch.limits)?;
                    let (stderr, said) = set_aside_notices(&out.stdout, &out.stderr);
                    out.stderr = stderr;
                    for notice in said {
                        if !notices.contains(&notice) {
                            notices.push(notice);
                        }
                    }
                    Ok(out)
                };
                let outcome = run_probe(&probe, run_in_sandbox, &mut target.0);
                results.push(ProbeResult::of(probe, outcome));
            }
            results.extend(own.folders_not_run(&inputs));
            Ok(TestReport {
                results,
                host_services,
                not_here: not_here(&inputs, own.as_ref()),
                listens: inputs.listen,
                notes: own.notes(),
                notices,
                not_enforced,
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
        let record = self.state.get(name)?.ok_or_else(|| Error::NoSuchSandbox {
            name: name.to_string(),
        })?;
        let mut hidden_files = self.layout.hidden_files();
        if record.backend.binds_the_hosts_root() {
            hidden_files = with_real_paths(&hidden_files, &self.layout.run_dir());
        }
        Ok(ProbeInputs {
            user_home: ctx.user_home.clone(),
            data: self.layout.data().to_owned(),
            config_file: self.layout.config_file(),
            hidden_files,
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
        let policy = self.policy(name)?.snapshot.policy;
        let not_enforced = self.not_enforced(name, record.backend, &policy)?;
        let limits = leaving_out(self.checked_limits(&record, &policy)?, &not_enforced);
        // Not `backend_of`: a dry run asks nothing of the host, so it also
        // counts for a backend this host cannot run. It reads no compiled
        // file, which changes what closes a probe, not how many run.
        let backend = match self.backends.iter().find(|b| b.kind() == record.backend) {
            Some(backend) => backend.as_ref(),
            None => self.backend_of(name)?,
        };
        let mut own = backend
            .own_probes(None)
            .map_err(|what| Error::Session { what })?;
        let inputs = self.probe_inputs(
            name,
            &ctx,
            Some(0),
            Some(PathBuf::from("/dev/ttys0")),
            limits,
        )?;
        own.count_only(&self.layout, name, &inputs);
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

    /// Runs `wrapped`, a probe of sandbox `name`, to its end with no input,
    /// in a scope of the sandbox's slice held to `limits`, as a session's
    /// program runs where this engine has scopes (design §8), then ends what
    /// it left there.
    fn run_scoped(
        &self,
        name: &SandboxName,
        wrapped: Command,
        limits: &LaunchLimits,
    ) -> std::io::Result<std::process::Output> {
        let (mut scoped, scope) = self
            .in_scope(name, wrapped, limits)
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        let output = scoped.stdin(Stdio::null()).output()?;
        if let Some(scope) = scope {
            scope.end(SCOPE_END_WAIT).map_err(|e| {
                std::io::Error::other(format!("cannot end what it left in its scope: {e}"))
            })?;
        }
        Ok(output)
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

/// Whether `tool` finds what it looks up, or, by one of its `absent`
/// messages, says it is not there.
fn listed(tool: &ToolCheck) -> std::result::Result<bool, String> {
    let out = Command::new(tool.program)
        .args(&tool.look)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("cannot run {}: {e}", tool.program))?;
    let text = output(&out);
    let says_absent = tool.absent.iter().any(|message| text.contains(message));
    match (out.status.success(), says_absent) {
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
    sockets.push(user_home.join(".1password/agent.sock"));
    sockets.push(user_home.join(".bitwarden-ssh-agent.sock"));
    sockets.push(PathBuf::from("/var/run/docker.sock"));
    sockets.into_iter().filter(|s| s.exists()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::seatbelt::Baseline;
    use crate::backend::seatbelt::probes::{BEFORE_THE_RULE, ITSELF, SeatbeltProbes, notes_on};
    use std::process::{ExitStatus, Output};

    #[test]
    fn a_password_managers_ssh_agent_in_the_home_is_a_host_socket() {
        let home = tempfile::tempdir().unwrap();
        let (one, bit) = (
            home.path().join(".1password/agent.sock"),
            home.path().join(".bitwarden-ssh-agent.sock"),
        );
        assert!(!host_sockets(home.path()).contains(&one));
        std::fs::create_dir(one.parent().unwrap()).unwrap();
        std::fs::write(&one, "").unwrap();
        std::fs::write(&bit, "").unwrap();
        let found = host_sockets(home.path());
        assert!(found.contains(&one) && found.contains(&bit), "{found:?}");
    }

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
            notes: notes_on(Baseline::DenyDefault),
            notices: Vec::new(),
            not_enforced: Vec::new(),
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

    /// Either wording of a missing domain reads absent, whatever the macOS
    /// here says; any other failure cannot tell.
    #[test]
    fn a_preferences_domain_is_absent_by_either_message_of_defaults() {
        let saying = |message: &str| {
            let script = format!("echo \"{message}\" >&2; exit 1");
            HostCheck::Tool(ToolCheck {
                program: "/bin/sh",
                look: vec!["-c".to_owned(), script],
                ..crate::backend::seatbelt::probes::preferences_domain("x")
            })
        };
        assert_eq!(present(&saying("Domain 'x' not found.")), Ok(false));
        assert_eq!(present(&saying("Domain x does not exist")), Ok(false));
        assert!(present(&saying("Could not read it")).is_err());
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
        assert_eq!(platform.closed_apart(), " (1 by Seatbelt itself)");
        platform
            .results
            .extend(report(vec![Outcome::Closed]).results);
        assert!(platform.passed());
        assert_eq!(platform.closed_apart(), " (1 by Seatbelt itself)");
        assert_eq!(platform.closed_by_rule(), 1);
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
            hidden_files: crate::probes::hidden_in(&dir.join("enclos")),
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

#[cfg(test)]
mod diagnostic_source_tests {
    use super::*;
    #[test]
    fn diagnostic_provenance_tags_the_sandbox_attempt_and_its_host_control() {
        let script = "/usr/bin/curl --proxy http://127.0.0.1:41000 https://10.0.0.1/";
        let mut probe = Probe {
            route: "network",
            name: "private address".into(),
            script: script.into(),
            proof: Proof::OnlyTheProxy {
                control: crate::probes::HostScript::new(script),
            },
            host: None,
            closed_by: None,
        };
        let tag = "a".repeat(64);
        tag_probe(&mut probe, &tag);
        assert!(
            probe
                .script
                .contains(&format!("--proxy-header 'X-Enclos-Probe: {tag}'"))
        );
        let Proof::OnlyTheProxy { control } = probe.proof else {
            panic!("wrong proof")
        };
        assert!(control.as_str().contains(&tag));
    }
}
