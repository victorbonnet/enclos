//! `enclos policy`: show a sandbox's policy, allow a destination, edit
//! `policy.toml`, apply or discard the pending change, or test the policy.

use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use clap::{Args, Subcommand};

use enclos::engine::{Discarded, Engine, PolicyApplied, PolicyView, Restarted, TestReport};
use enclos::error::{Error, Result, exit};
use enclos::layout::LayoutError;
use enclos::model::audit::Actor;
use enclos::model::plan::{Confirm, Planned};
use enclos::model::policy::{NetMode, Policy};
use enclos::model::sandbox::SandboxName;
use enclos::probes::{HOST_SERVICE_ROUTES, NOT_PROBED, Outcome};

#[derive(Args)]
pub struct PolicyArgs {
    #[command(subcommand)]
    verb: PolicyVerb,
}

#[derive(Subcommand)]
enum PolicyVerb {
    /// Show the sandbox's active policy, and the change pending if there is one.
    Show {
        sandbox: SandboxName,
        /// Show the pending policy in full instead.
        #[arg(long)]
        pending: bool,
    },
    /// Let the sandbox reach a destination: host, host:port or *.domain. Applies at once.
    Allow {
        sandbox: SandboxName,
        destination: String,
    },
    /// Edit the sandbox's policy.toml in $VISUAL or $EDITOR, then apply it:
    /// at once, or pending while sessions run under rules it changes.
    Edit { sandbox: SandboxName },
    /// Restart the sandbox into its pending policy.
    Apply { sandbox: SandboxName },
    /// Drop the pending policy, and any edit of policy.toml not applied.
    Discard { sandbox: SandboxName },
    /// Try each way out of the sandbox from inside it; every probe must fail.
    Test {
        sandbox: SandboxName,
        /// Also probe routes that could act on this Mac if a rule did not
        /// hold (open, Apple Events, launchd, preferences). For CI and VMs.
        #[arg(long)]
        host_services: bool,
    },
}

pub fn run(engine: &Engine, by: &Actor, confirm: Confirm, args: PolicyArgs) -> Result<u8> {
    match args.verb {
        PolicyVerb::Test {
            sandbox,
            host_services,
        } => {
            return Ok(
                match engine.policy_test(by, &sandbox, host_services, confirm)? {
                    Planned::DryRun(plan) => {
                        plan.changes.iter().for_each(|c| println!("Would {c}."));
                        exit::OK
                    }
                    Planned::Done(report) => print_test(&sandbox, &report),
                },
            );
        }
        PolicyVerb::Show { sandbox, pending } => print_policy(&engine.policy(&sandbox)?, pending)?,
        PolicyVerb::Allow {
            sandbox,
            destination,
        } => {
            return print_allowed(
                engine,
                &sandbox,
                &destination,
                engine.policy_allow(by, &sandbox, &destination, confirm)?,
            );
        }
        PolicyVerb::Edit { sandbox } => return edit(engine, by, &sandbox, confirm),
        PolicyVerb::Apply { sandbox } => {
            return match engine.policy_apply(by, &sandbox, confirm)? {
                Planned::DryRun(plan) => {
                    plan.changes.iter().for_each(|c| println!("Would {c}."));
                    Ok(exit::OK)
                }
                Planned::Done(restarted) => print_restarted(engine, &sandbox, &restarted),
            };
        }
        PolicyVerb::Discard { sandbox } => {
            print_discarded(&sandbox, engine.policy_discard(by, &sandbox, confirm)?)
        }
    }
    Ok(exit::OK)
}

fn print_policy(view: &PolicyView, pending: bool) -> Result<()> {
    let (version, snap) = (&view.version, &view.snapshot);
    if pending {
        let Some((p, pending)) = &view.pending else {
            return Err(Error::NoPendingPolicy {
                sandbox: view.sandbox.to_string(),
            });
        };
        println!(
            "Sandbox {}: pending policy (snapshot {}), template {}, by {}@{} at {}; v{} is in force until `enclos policy apply {}`",
            view.sandbox,
            p.snapshot.short(),
            pending.inputs.template,
            p.by.user,
            p.by.host,
            p.at.strftime("%Y-%m-%d %H:%M:%S UTC"),
            version.version,
            view.sandbox,
        );
        print_rules(&pending.policy);
        return Ok(());
    }
    println!(
        "Sandbox {}: policy v{} (snapshot {}), template {}, by {}@{} at {}",
        view.sandbox,
        version.version,
        snap.id.short(),
        snap.inputs.template,
        version.by.user,
        version.by.host,
        version.at.strftime("%Y-%m-%d %H:%M:%S UTC"),
    );
    print_rules(&snap.policy);
    match &view.pending {
        Some((p, pending)) => {
            println!(
                "\nPending (snapshot {}, by {}@{} at {}): it waits for a restart, as sessions run under rules it changes:",
                p.snapshot.short(),
                p.by.user,
                p.by.host,
                p.at.strftime("%Y-%m-%d %H:%M:%S UTC"),
            );
            for change in enclos::engine::policy_differences(&snap.policy, &pending.policy) {
                println!("  {change}");
            }
            println!(
                "`enclos policy apply {0}` restarts the sandbox into it; `enclos policy discard {0}` drops it. `enclos policy show {0} --pending` shows it in full.",
                view.sandbox
            );
        }
        None => println!(
            "\nChange it with `enclos policy edit {}` (it edits {}).",
            view.sandbox,
            view.file.display()
        ),
    }
    Ok(())
}

fn print_rules(policy: &Policy) {
    println!("\nFiles (everything else is readable)");
    println!("  writable:   {}", policy.fs.write.join(", "));
    println!(
        "  unreadable: {} paths, and enclos's own files",
        policy.fs.read_deny.len()
    );
    for path in &policy.fs.read_deny {
        println!("    {path}");
    }
    match policy.net.mode {
        NetMode::Public => {
            println!("\nNetwork: public web (every connection is logged)");
            println!("  mode:    public: any public address on ports 80 and 443");
            println!(
                "           never loopback, link-local or metadata addresses, nor private ones unless listed below"
            );
        }
        NetMode::Allowlist => {
            println!("\nNetwork: allowlist (every other destination is denied and logged)");
            println!("  mode:    allowlist: only the destinations below");
        }
    }
    if policy.net.allow.is_empty() {
        println!("  allowed: nothing listed");
    } else {
        println!("  allowed: {}", policy.net.allow.join(", "));
    }
    if !policy.net.private.is_empty() {
        println!(
            "  private addresses allowed for: {}",
            policy.net.private.join(", ")
        );
    }
    if policy.net.listen {
        println!(
            "  listening: allowed on TCP, any port but enclos's proxy ports, on every address: what listens in this sandbox can serve the network"
        );
    }
}

fn print_allowed(
    engine: &Engine,
    sandbox: &SandboxName,
    destination: &str,
    planned: Planned<PolicyApplied>,
) -> Result<u8> {
    let applied = match planned {
        Planned::DryRun(plan) => {
            for change in plan.changes {
                println!("Would {change}.");
            }
            return Ok(exit::OK);
        }
        Planned::Done(applied) => applied,
    };
    let version = applied.version.version;
    match (applied.changed, &applied.pending) {
        (false, None) => {
            println!("Sandbox {sandbox} already allows {destination} (policy v{version}).")
        }
        (false, Some(_)) => println!(
            "Sandbox {sandbox} already allows {destination} (policy v{version}), and so does its pending change."
        ),
        (true, _) => println!(
            "Sandbox {sandbox} now allows {destination}: policy v{version}, in force at once."
        ),
    }
    if !applied.also.is_empty() {
        println!("The change also does this:");
        for change in &applied.also {
            println!("  {change}");
        }
    }
    print_outcome(engine, sandbox, &applied)
}

/// Says whether a change waits as the pending policy, or how the restart
/// that applied it went.
fn print_outcome(engine: &Engine, sandbox: &SandboxName, applied: &PolicyApplied) -> Result<u8> {
    if let Some(p) = &applied.pending {
        println!(
            "A change waits as the pending policy of sandbox {sandbox} (snapshot {}): sessions run under rules it changes, and keep them until they restart.",
            p.snapshot.short()
        );
        println!(
            "`enclos policy apply {sandbox}` restarts the sandbox into it; `enclos policy discard {sandbox}` drops it."
        );
    }
    match &applied.restarted {
        Some(restarted) => print_restarted(engine, sandbox, restarted),
        None => Ok(exit::OK),
    }
}

/// How a restart into the pending policy went: what stopped, the version
/// now in force, and the services started again.
fn print_restarted(engine: &Engine, sandbox: &SandboxName, r: &Restarted) -> Result<u8> {
    if let Some(stopped) = &r.stopped {
        let code = super::sandbox::print_stop(sandbox, stopped);
        if code != exit::OK {
            return Ok(code);
        }
    }
    println!(
        "Sandbox {sandbox} runs under policy v{} from now on.",
        r.version.version
    );
    if r.stopped.as_ref().is_some_and(|s| !s.stopped.is_empty()) {
        println!("Sessions it ended can connect again with `enclos connect {sandbox}`.");
    }
    match r.started.is_empty() {
        true => Ok(exit::OK),
        false => super::sandbox::print_started(engine, sandbox, &r.started),
    }
}

fn print_discarded(sandbox: &SandboxName, planned: Planned<Discarded>) {
    let discarded = match planned {
        Planned::DryRun(plan) => {
            plan.changes.iter().for_each(|c| println!("Would {c}."));
            return;
        }
        Planned::Done(d) => d,
    };
    let version = discarded.version.version;
    match (&discarded.pending, &discarded.kept) {
        (None, None) => println!(
            "Sandbox {sandbox} has nothing pending: its policy.toml is policy v{version}'s."
        ),
        (Some(p), _) => println!(
            "Dropped the pending policy of sandbox {sandbox} (snapshot {}); policy v{version} stays in force.",
            p.snapshot.short()
        ),
        (None, Some(_)) => println!(
            "Put back the policy.toml of policy v{version} in sandbox {sandbox}, dropping the edits not applied."
        ),
    }
    if let Some(kept) = &discarded.kept {
        println!("What policy.toml held is kept in {}.", kept.display());
    }
}

/// `policy edit`: a draft of `policy.toml` beside it, opened in the user's
/// editor, then applied. A draft an earlier edit left, because the policy
/// it held was not accepted, is opened again instead.
fn edit(engine: &Engine, by: &Actor, sandbox: &SandboxName, confirm: Confirm) -> Result<u8> {
    let file = engine.policy(sandbox)?.file;
    let io = |path: &Path| {
        let path = path.to_owned();
        move |source| Error::Layout(LayoutError::Io { path, source })
    };
    let before = std::fs::read_to_string(&file).map_err(io(&file))?;
    let draft = file.with_file_name("policy.toml.edit");
    let start = match std::fs::read_to_string(&draft) {
        Ok(kept) => {
            println!("Continuing the edit kept in {}.", draft.display());
            kept
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => before.clone(),
        Err(source) => return Err(io(&draft)(source)),
    };
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&draft)
        .and_then(|mut f| std::io::Write::write_all(&mut f, start.as_bytes()))
        .map_err(io(&draft))?;
    run_editor(&draft)?;
    let after = std::fs::read_to_string(&draft).map_err(io(&draft))?;
    let kept = |error: Error| Error::WithContext {
        what: format!(
            "{error}\nYour edit is kept in {}; `enclos policy edit {sandbox}` opens it again, and `rm` it to start over.",
            draft.display()
        ),
        error: Box::new(error),
    };
    if after == before {
        let _ = std::fs::remove_file(&draft);
        println!("No change to the policy of sandbox {sandbox}.");
        return Ok(exit::OK);
    }
    let applied = match engine.policy_edit(by, sandbox, &before, &after, confirm) {
        Ok(Planned::DryRun(plan)) => {
            plan.changes.iter().for_each(|c| println!("Would {c}."));
            println!(
                "Your edit is kept in {}; `enclos policy edit {sandbox}` opens it again.",
                draft.display()
            );
            return Ok(exit::OK);
        }
        Ok(Planned::Done(applied)) => applied,
        Err(e) => return Err(kept(e)),
    };
    let _ = std::fs::remove_file(&draft);
    match (&applied.pending, applied.changed) {
        (None, false) => println!("No change to the policy of sandbox {sandbox}."),
        (None, true) => println!(
            "Sandbox {sandbox} has policy v{}, in force at once for the network and for sessions started from now on.",
            applied.version.version
        ),
        (Some(_), _) => println!(
            "Sandbox {sandbox} keeps policy v{} for now.",
            applied.version.version
        ),
    }
    for change in &applied.also {
        println!("  {change}");
    }
    print_outcome(engine, sandbox, &applied)
}

/// Opens `path` in `$VISUAL`, else `$EDITOR`, else `vi`, through `sh` so
/// that an editor given with its options (`code --wait`) works.
fn run_editor(path: &Path) -> Result<()> {
    let editor = ["VISUAL", "EDITOR"]
        .into_iter()
        .filter_map(|var| std::env::var(var).ok())
        .find(|v| !v.trim().is_empty())
        .unwrap_or_else(|| "vi".to_owned());
    let status = std::process::Command::new("/bin/sh")
        .arg("-c")
        .arg(format!("{editor} \"$1\""))
        .arg("sh")
        .arg(path)
        .status()
        .map_err(|e| Error::Session {
            what: format!("cannot run the editor `{editor}`: {e}"),
        })?;
    if !status.success() {
        return Err(Error::Session {
            what: format!(
                "the editor `{editor}` did not exit cleanly ({status}), so nothing was applied. Your edit is kept in {}",
                path.display()
            ),
        });
    }
    Ok(())
}

fn print_test(sandbox: &SandboxName, report: &TestReport) -> u8 {
    println!("Escape probes in sandbox {sandbox}: each tries one way out and must fail.");
    for r in &report.results {
        let (mark, detail) = match &r.outcome {
            Outcome::Closed => (
                "closed      ",
                r.closed_by_platform
                    .map(|why| format!("  ({why})"))
                    .unwrap_or_default(),
            ),
            Outcome::Open(why) => ("OPEN        ", format!("  <- {why}")),
            Outcome::Inconclusive(why) => ("inconclusive", format!("  ({why})")),
            Outcome::NotRun(why) => ("NOT RUN     ", format!("  <- {why}")),
        };
        println!("  {mark}  {:<16} {}{detail}", r.route, r.name);
    }
    if !report.host_services {
        println!(
            "Host-service routes ({}) were not probed; CI probes them with --host-services.",
            HOST_SERVICE_ROUTES.join(", ")
        );
    }
    if !report.not_here.is_empty() {
        println!(
            "Not probed, as it is not on this host: {}.",
            report.not_here.join("; ")
        );
    }
    println!(
        "No probe tries these routes yet: {}.",
        NOT_PROBED.join(", ")
    );
    if report.listens {
        println!(
            "Open by the policy: listening on TCP, on any port but enclos's proxy ports, on every address (ADR 0028); the bind probes show only that the proxy ports stay closed. What listens in this sandbox can serve the network."
        );
    }
    println!(
        "Closed means the probe was refused in the sandbox while its control, a harmless check, worked on this host (for the probes through the proxy: the proxy answered 403). It does not mean no other way out exists."
    );
    if report.inconclusive() > 0 {
        println!(
            "{} probes were inconclusive: they failed for a reason other than the policy, so they show nothing about it.",
            report.inconclusive()
        );
    }
    // Last, after a blank line, so it is what the user reads.
    println!();
    match report.passed() {
        true => {
            println!("{}", verdict(sandbox, report));
            exit::OK
        }
        false => {
            eprintln!("{}", verdict(sandbox, report));
            exit::ERROR
        }
    }
}

/// Whether the sandbox is ready, in one line: READY when the test passed,
/// with what it showed, or NOT READY with every reason it did not.
fn verdict(sandbox: &SandboxName, report: &TestReport) -> String {
    let total = report.results.len();
    if report.passed() {
        let platform = match report.closed_by_platform() {
            0 => String::new(),
            n => format!(" ({n} by Seatbelt itself)"),
        };
        let shown = match report.closed() == total {
            true => format!("all {total} shown closed{platform}"),
            false => format!(
                "{} of {total} shown closed{platform}, {} could not be checked on this Mac (inconclusive above), none open",
                report.closed(),
                report.inconclusive()
            ),
        };
        return format!("READY: no probe got out of sandbox {sandbox}: {shown}.");
    }
    let mut why = Vec::new();
    if report.open() > 0 {
        why.push(format!(
            "{} of {total} probes got out (OPEN above)",
            report.open()
        ));
    }
    if report.not_run() > 0 {
        why.push(format!(
            "{} could not run or be checked, so their routes were not tested (NOT RUN above)",
            report.not_run()
        ));
    }
    if report.open() == 0 && report.not_run() == 0 {
        why.push("no probe was shown closed by an enclos rule, so the test showed nothing about the policy".to_owned());
    }
    let stop = match report.open() > 0 {
        true => " Do not use it until this is fixed.",
        false => "",
    };
    format!("NOT READY: sandbox {sandbox}: {}.{stop}", why.join("; "))
}

#[cfg(test)]
mod tests {
    use super::*;
    use enclos::probes::ProbeResult;

    fn report(outcome: Outcome) -> TestReport {
        reports(vec![outcome])
    }

    fn reports(outcomes: Vec<Outcome>) -> TestReport {
        TestReport {
            results: outcomes
                .into_iter()
                .map(|outcome| ProbeResult {
                    route: "writes",
                    name: "write outside the home".into(),
                    outcome,
                    closed_by_platform: None,
                })
                .collect(),
            host_services: false,
            not_here: Vec::new(),
            listens: false,
        }
    }

    #[test]
    fn the_test_ends_saying_whether_the_sandbox_is_ready() {
        let lab: SandboxName = "lab".parse().unwrap();
        let closed = || Outcome::Closed;
        assert_eq!(
            verdict(&lab, &reports(vec![closed(), closed()])),
            "READY: no probe got out of sandbox lab: all 2 shown closed."
        );
        assert_eq!(
            verdict(
                &lab,
                &reports(vec![closed(), closed(), Outcome::Inconclusive("x".into())])
            ),
            "READY: no probe got out of sandbox lab: 2 of 3 shown closed, 1 could not be checked on this Mac (inconclusive above), none open."
        );
        assert_eq!(
            verdict(
                &lab,
                &reports(vec![
                    closed(),
                    Outcome::Open("x".into()),
                    Outcome::NotRun("y".into())
                ])
            ),
            "NOT READY: sandbox lab: 1 of 3 probes got out (OPEN above); 1 could not run or be checked, so their routes were not tested (NOT RUN above). Do not use it until this is fixed."
        );
        assert_eq!(
            verdict(&lab, &report(Outcome::Inconclusive("x".into()))),
            "NOT READY: sandbox lab: no probe was shown closed by an enclos rule, so the test showed nothing about the policy."
        );
    }

    #[test]
    fn the_exit_code_fails_on_an_open_route_a_probe_not_run_or_nothing_closed() {
        let home: SandboxName = "home".parse().unwrap();
        assert_eq!(print_test(&home, &report(Outcome::Closed)), exit::OK);
        for failing in [
            Outcome::Open("x".into()),
            Outcome::NotRun("x".into()),
            Outcome::Inconclusive("x".into()),
        ] {
            assert_eq!(print_test(&home, &report(failing)), exit::ERROR);
        }
    }
}
