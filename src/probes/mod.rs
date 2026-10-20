//! Escape probes for `enclos policy test` (design §5, ADR 0016): each tries
//! one way out of the sandbox, from inside it, and must fail.
//!
//! A failure proves something only if the policy caused it, so every probe
//! carries its proof. Most have a control: a harmless check run on the host
//! first, which shows the route works there (the same read or connection
//! with its output discarded, a check that a folder is writable, or, for a
//! host service whose use outside would act on this Mac, a read-only check
//! that the service is there). When the control fails too, the probe is
//! inconclusive, not closed: `crontab -l` fails anyway for an account
//! without a crontab, and a connection fails anyway on a host that is
//! offline. The proxy probe is its own proof: the proxy answers 403.
//!
//! Each probe's script prints a marker before anything else, so a sandbox
//! that never ran it (`sandbox-exec` refusing the compiled policy) is not
//! taken for a refusal.
//!
//! The probes of [`probes`] are harmless even when a rule does not hold. The
//! ones of [`host_service_probes`] could act on the host if they succeeded
//! (opening a folder in Finder, an Apple Event, a launchd job, a preferences
//! write): they run only with `--host-services`, which CI's macOS runners
//! ask for. A launchd job or preferences domain they leave is checked from
//! the host and removed; LaunchServices and the Apple Event leave nothing to
//! check, so they count as closed only with the refusal the rule gives.

use std::path::{Path, PathBuf};

/// How a probe's own result is read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expect {
    /// Closed when the script fails.
    Fails,
    /// Closed when it fails with this text in its output: the refusal the
    /// Seatbelt rule was shown to give. Any other failure is inconclusive.
    FailsWith(&'static str),
    /// Closed when the output does not contain this text.
    OutputLacks(&'static str),
    /// An Apple Event to Finder. An answer, a refusal by TCC (-1743) or a
    /// wait on Finder (-1712) all mean the event left the sandbox: open
    /// (ADR 0016). Closed on the refusal Seatbelt gives (-600); any other
    /// failure is inconclusive.
    AppleEventBlocked,
}

/// A `/bin/sh -c` script run on the host, outside the sandbox. Only this
/// module makes one, and each is harmless whatever the policy says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostScript(String);

impl HostScript {
    fn new(script: impl Into<String>) -> HostScript {
        HostScript(script.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// What shows that a probe's failure is the policy's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Proof {
    /// The probe's reading, and a control that must work on the host.
    Control { expect: Expect, control: HostScript },
    /// The proxy answers 403: the proxy is what the probe tests, so there is
    /// nothing to try outside.
    ProxyRefuses,
}

/// What the host checks, before the probe and after it, and removes if the
/// probe left it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostCheck {
    /// A file the probe tries to create outside the sandbox.
    File(PathBuf),
    LaunchdJob(String),
    PreferencesDomain(String),
    /// The process the host started for the signal probe: ended by TERM if
    /// the signal got out.
    Target,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Probe {
    /// The route it belongs to, as the report names it (design §5).
    pub route: &'static str,
    pub name: String,
    /// A `/bin/sh -c` script run inside the sandbox.
    pub script: String,
    pub proof: Proof,
    pub host: Option<HostCheck>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Refused in the sandbox, with its proof: its control worked on the
    /// host, or the proxy answered 403.
    Closed,
    /// The route is open: what showed it.
    Open(String),
    /// It failed, but its control failed on the host too, or it failed for
    /// another reason than the policy's refusal: it shows nothing.
    Inconclusive(String),
    /// The probe could not be run or checked, with why: the route was not
    /// tested.
    NotRun(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeResult {
    pub route: &'static str,
    pub name: String,
    pub outcome: Outcome,
}

impl ProbeResult {
    pub fn of(probe: Probe, outcome: Outcome) -> ProbeResult {
        ProbeResult {
            route: probe.route,
            name: probe.name,
            outcome,
        }
    }
}

/// The routes of [`host_service_probes`], as the report names them.
pub const HOST_SERVICE_ROUTES: &[&str] =
    &["launchservices", "apple events", "launchd", "preferences"];

/// Routes of design §5 that no probe tries yet. `policy test` names them, so
/// that a test that passed is not read as covering them.
pub const NOT_PROBED: &[&str] = &[
    "posting synthetic input events",
    "`at` jobs",
    "installing a crontab",
    "registering a login item",
    "typing into the terminal (TIOCSTI)",
];

/// What the probes are built from.
#[derive(Debug, Clone)]
pub struct ProbeInputs {
    pub user_home: PathBuf,
    /// The enclos data folder and `config.toml`.
    pub data: PathBuf,
    pub config_file: PathBuf,
    /// Other sandboxes' folders.
    pub other_sandboxes: Vec<PathBuf>,
    /// The policy's read deny list, expanded.
    pub read_deny: Vec<PathBuf>,
    /// Unix sockets of host services that exist here (SSH agent, Docker).
    pub host_sockets: Vec<PathBuf>,
    /// The process the host started for the signal probe; none when nothing
    /// will run (a dry run), and then there is no signal probe.
    pub target: Option<u32>,
    /// Makes names of things a probe might create unique.
    pub tag: u32,
}

/// A path as one shell word.
pub fn sh_quote(path: &Path) -> String {
    format!("'{}'", path.display().to_string().replace('\'', "'\\''"))
}

fn probe(
    route: &'static str,
    name: impl Into<String>,
    script: impl Into<String>,
    expect: Expect,
    control: impl Into<String>,
) -> Probe {
    Probe {
        route,
        name: name.into(),
        script: script.into(),
        proof: Proof::Control {
            expect,
            control: HostScript::new(control),
        },
        host: None,
    }
}

/// A probe whose control is the same script, run on the host: it only reads
/// or connects, and its output is discarded.
fn same_outside(route: &'static str, name: impl Into<String>, script: &str) -> Probe {
    probe(route, name, script, Expect::Fails, script)
}

/// Reads a file's first byte, or lists a folder: either is a read of its
/// content. On the host too, as the control.
fn read_probe(route: &'static str, path: &Path) -> Probe {
    let read = match path.is_dir() {
        true => format!("/bin/ls {} >/dev/null", sh_quote(path)),
        false => format!("/usr/bin/head -c 1 {} >/dev/null", sh_quote(path)),
    };
    same_outside(route, format!("read {}", path.display()), &read)
}

/// A probe that writes `file`, controlled by whether its folder is writable
/// on the host, and checked by whether the file appeared.
fn write_probe(route: &'static str, name: &str, file: PathBuf) -> Probe {
    let folder = file.parent().unwrap_or(&file);
    let mut write = probe(
        route,
        name,
        format!("echo x > {}", sh_quote(&file)),
        Expect::Fails,
        format!("test -w {}", sh_quote(folder)),
    );
    write.host = Some(HostCheck::File(file));
    write
}

/// The probes that are harmless even if a rule does not hold: run wherever
/// `policy test` runs, the user's Mac included.
pub fn probes(i: &ProbeInputs) -> Vec<Probe> {
    let mut list = Vec::new();
    for path in i.read_deny.iter().filter(|p| p.exists()) {
        list.push(read_probe("sensitive files", path));
    }
    for path in [
        i.data.join("state.db"),
        i.data.join("audit.jsonl"),
        i.config_file.clone(),
    ] {
        if path.exists() {
            list.push(read_probe("enclos files", &path));
        }
    }
    for dir in &i.other_sandboxes {
        list.push(read_probe("other sandboxes", dir));
    }
    list.push(write_probe(
        "enclos files",
        "write in the enclos folder",
        i.data.join(format!("enclos-probe-{}", i.tag)),
    ));
    list.push(write_probe(
        "writes",
        "write outside the home",
        i.user_home.join(format!("enclos-probe-{}", i.tag)),
    ));

    list.push(Probe {
        route: "network",
        name: "an unlisted destination through the proxy".into(),
        script: "/usr/bin/curl -s -o /dev/null -w '%{http_connect}' --max-time 15 https://probe.enclos.invalid/".into(),
        proof: Proof::ProxyRefuses,
        host: None,
    });
    // The same connections outside the sandbox only open and close a
    // connection; they fail on a host that is offline.
    list.push(same_outside(
        "network",
        "a direct connection, around the proxy",
        "/usr/bin/nc -z -w 3 1.1.1.1 443",
    ));
    list.push(same_outside(
        "dns",
        "DNS on port 53",
        "/usr/bin/nc -z -w 3 1.1.1.1 53",
    ));
    list.push(probe(
        "dns",
        "a name lookup through mDNSResponder",
        "/usr/bin/dscacheutil -q host -a name example.com",
        Expect::OutputLacks("address"),
        "/usr/bin/dscacheutil -q host -a name example.com | /usr/bin/grep -q address",
    ));
    for socket in &i.host_sockets {
        list.push(same_outside(
            "host sockets",
            format!("connect to {}", socket.display()),
            &format!("/usr/bin/nc -U -w 2 {} </dev/null", sh_quote(socket)),
        ));
    }
    if let Some(target) = i.target {
        // Signal 0 only checks that a signal could be sent.
        let mut signal = probe(
            "signals",
            "signal a process outside the sandbox",
            format!("kill -TERM {target}"),
            Expect::Fails,
            format!("kill -0 {target}"),
        );
        signal.host = Some(HostCheck::Target);
        list.push(signal);
    }
    let keychain = i.user_home.join("Library/Keychains/login.keychain-db");
    if keychain.exists() {
        // Its settings (lock timeout), not its items.
        let info = format!(
            "/usr/bin/security show-keychain-info {} >/dev/null 2>&1",
            sh_quote(&keychain)
        );
        list.push(same_outside(
            "keychain",
            "read the login keychain's settings",
            &info,
        ));
    }
    // Reads, with the output discarded: an account without a crontab makes
    // the crontab probe inconclusive.
    list.push(same_outside(
        "pasteboard",
        "read the pasteboard",
        "/usr/bin/pbpaste >/dev/null",
    ));
    list.push(same_outside(
        "crontab",
        "read the crontab",
        "/usr/bin/crontab -l >/dev/null",
    ));
    list
}

/// What [`probes`] leaves out because it is not on this host, so that the
/// report says so instead of leaving those routes out silently.
pub fn not_here(i: &ProbeInputs) -> Vec<String> {
    let mut absent = Vec::new();
    let missing = i.read_deny.iter().filter(|p| !p.exists()).count();
    match (missing, i.read_deny.len()) {
        (0, _) => {}
        (m, n) if m == n => absent.push(format!(
            "sensitive files (none of the {n} denied paths exists here)"
        )),
        (m, n) => absent.push(format!(
            "{m} of the {n} denied sensitive paths (they do not exist here)"
        )),
    }
    if i.host_sockets.is_empty() {
        absent.push("host sockets (no SSH agent or Docker socket here)".to_owned());
    }
    if !i
        .user_home
        .join("Library/Keychains/login.keychain-db")
        .exists()
    {
        absent.push("keychain (no login keychain here)".to_owned());
    }
    absent
}

/// The probes that could act on the host if a rule did not hold: CI and VMs
/// only (`--host-services`). Their controls only check that the service is
/// there; they never use it.
pub fn host_service_probes(i: &ProbeInputs) -> Vec<Probe> {
    // A session with Finder, which LaunchServices and Apple Events need.
    let finder = "/usr/bin/pgrep -x Finder >/dev/null";
    let mut list = vec![
        // `open <folder>` reports the refusal (-54, design §5). Not `open
        // -R`: inside the sandbox it exits 0 although Finder reveals nothing,
        // so its exit code says nothing (ADR 0016).
        probe(
            "launchservices",
            "open a folder through LaunchServices",
            "/usr/bin/open -g /System",
            Expect::FailsWith("-54"),
            finder,
        ),
        probe(
            "apple events",
            "send an Apple Event to Finder",
            "/usr/bin/osascript -e 'with timeout of 8 seconds' -e 'tell application \"Finder\" to count windows' -e 'end timeout'",
            Expect::AppleEventBlocked,
            finder,
        ),
    ];
    let label = format!("org.enclos.probe.{}", i.tag);
    let mut job = probe(
        "launchd",
        "submit a launchd job",
        format!("/bin/launchctl submit -l {label} -- /usr/bin/true"),
        Expect::Fails,
        "/bin/launchctl print gui/$(/usr/bin/id -u) >/dev/null 2>&1",
    );
    job.host = Some(HostCheck::LaunchdJob(label));
    list.push(job);
    let domain = format!("org.enclos.probe.{}", i.tag);
    let mut prefs = probe(
        "preferences",
        "write preferences through cfprefsd",
        format!("/usr/bin/defaults write {domain} probe -string written"),
        Expect::Fails,
        "/usr/bin/defaults domains >/dev/null 2>&1",
    );
    prefs.host = Some(HostCheck::PreferencesDomain(domain));
    list.push(prefs);
    list
}

/// What the sandbox printed first for a script it ran.
const MARKER: &str = "enclos-probe-ran";

/// The probe's script as the sandbox runs it: the marker first.
pub fn sandboxed_script(probe: &Probe) -> String {
    format!("printf '{MARKER}\\n'; {}", probe.script)
}

/// One run of a probe in the sandbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Run {
    /// The sandbox ran the script: whether it succeeded, and its output.
    Ran { succeeded: bool, output: String },
    /// The sandbox did not run it, with why.
    NotRun(String),
}

impl Run {
    /// Reads what the sandbox printed: without the marker, the script never
    /// ran, whatever the exit status says.
    pub fn read(succeeded: bool, stdout: &str, stderr: &str) -> Run {
        match stdout
            .strip_prefix(MARKER)
            .and_then(|s| s.strip_prefix('\n'))
        {
            Some(rest) => Run::Ran {
                succeeded,
                output: format!("{rest}{stderr}"),
            },
            None => Run::NotRun(match last_line(&format!("{stdout}{stderr}")) {
                line if line.is_empty() => "the sandbox did not run it".to_owned(),
                line => format!("the sandbox did not run it: {line}"),
            }),
        }
    }
}

/// The final outcome of a probe, from its run, what the host saw after it,
/// and its control's success and output. The only way a probe becomes
/// closed: its proof must hold.
pub fn outcome(
    probe: &Probe,
    run: Run,
    seen: Result<Option<String>, String>,
    control: Option<(bool, &str)>,
) -> Outcome {
    let own = match run {
        Run::Ran { succeeded, output } => judge(probe, succeeded, &output),
        Run::NotRun(why) => Outcome::NotRun(why),
    };
    match (seen, own) {
        // What the host found outweighs anything the probe said.
        (Ok(Some(evidence)), _) => Outcome::Open(evidence),
        (_, Outcome::Open(why)) => Outcome::Open(why),
        (Err(why), _) => Outcome::NotRun(format!("could not check from the host: {why}")),
        (Ok(None), Outcome::Closed) => match (&probe.proof, control) {
            (Proof::ProxyRefuses, _) => Outcome::Closed,
            (Proof::Control { .. }, Some((true, _))) => Outcome::Closed,
            (Proof::Control { .. }, Some((false, output))) => {
                Outcome::Inconclusive(match last_line(output) {
                    line if line.is_empty() => "it fails outside the sandbox too".to_owned(),
                    line => format!("it fails outside the sandbox too: {line}"),
                })
            }
            (Proof::Control { .. }, None) => Outcome::NotRun("its control did not run".into()),
        },
        (Ok(None), own) => own,
    }
}

/// Reads a probe's own result. Closed here is not yet proof: [`outcome`]
/// adds the host check and the control.
fn judge(probe: &Probe, succeeded: bool, output: &str) -> Outcome {
    let expect = match &probe.proof {
        Proof::ProxyRefuses => {
            return match output.trim() {
                "403" => Outcome::Closed,
                // curl reached no proxy at all.
                "" | "000" => Outcome::NotRun("could not reach the sandbox's proxy".into()),
                other => Outcome::Open(format!("the proxy answered `{other}`, not 403")),
            };
        }
        Proof::Control { expect, .. } => expect,
    };
    match expect {
        Expect::Fails | Expect::FailsWith(_) if succeeded => {
            Outcome::Open(format!("it succeeded: {}", last_line(output)))
        }
        Expect::Fails => Outcome::Closed,
        Expect::FailsWith(refusal) if output.contains(refusal) => Outcome::Closed,
        Expect::FailsWith(refusal) => Outcome::Inconclusive(format!(
            "it failed, but not with the policy's refusal ({refusal}): {}",
            last_line(output)
        )),
        Expect::OutputLacks(text) if output.contains(text) => {
            Outcome::Open(format!("output has `{text}`"))
        }
        Expect::OutputLacks(_) => Outcome::Closed,
        Expect::AppleEventBlocked if succeeded => {
            Outcome::Open(format!("Finder answered: {}", last_line(output)))
        }
        Expect::AppleEventBlocked if output.contains("-1743") => Outcome::Open(
            "the event reached macOS's privacy check (TCC refused it, -1743), so Seatbelt did not block it".into(),
        ),
        Expect::AppleEventBlocked if output.contains("-1712") => Outcome::Open(
            "the event reached Finder, which did not answer in time (-1712), so Seatbelt did not block it".into(),
        ),
        Expect::AppleEventBlocked if output.contains("-600") => Outcome::Closed,
        Expect::AppleEventBlocked => Outcome::Inconclusive(format!(
            "the event failed, but not with the policy's refusal (-600): {}",
            last_line(output)
        )),
    }
}

fn last_line(output: &str) -> String {
    output
        .trim()
        .lines()
        .last()
        .unwrap_or("")
        .chars()
        .take(100)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inputs(dir: &Path) -> ProbeInputs {
        ProbeInputs {
            user_home: dir.to_owned(),
            data: dir.join("enclos"),
            config_file: dir.join("enclos/config.toml"),
            other_sandboxes: vec![dir.join("enclos/sandboxes/lab")],
            read_deny: vec![dir.to_owned(), dir.join("does-not-exist")],
            host_sockets: vec![dir.join("agent.sock")],
            target: Some(4242),
            tag: 7,
        }
    }

    fn all(dir: &Path) -> Vec<Probe> {
        let i = inputs(dir);
        probes(&i)
            .into_iter()
            .chain(host_service_probes(&i))
            .collect()
    }

    fn find<'a>(list: &'a [Probe], route: &str) -> &'a Probe {
        list.iter().find(|p| p.route == route).unwrap()
    }

    fn ran(succeeded: bool, output: &str) -> Run {
        Run::Ran {
            succeeded,
            output: output.into(),
        }
    }

    /// The outcome when the host saw nothing and the control worked.
    fn proven(p: &Probe, run: Run) -> Outcome {
        outcome(p, run, Ok(None), Some((true, "")))
    }

    #[test]
    fn host_service_probes_are_apart_and_the_harmless_ones_never_use_a_host_service() {
        let dir = tempfile::tempdir().unwrap();
        let routes: Vec<&str> = probes(&inputs(dir.path()))
            .iter()
            .map(|p| p.route)
            .collect();
        for route in ["launchservices", "apple events", "launchd", "preferences"] {
            assert!(!routes.contains(&route), "{route}");
        }
        for route in ["network", "signals", "writes", "pasteboard", "crontab"] {
            assert!(routes.contains(&route), "{route}");
        }
        let host: Vec<&str> = host_service_probes(&inputs(dir.path()))
            .iter()
            .map(|p| p.route)
            .collect();
        assert_eq!(host, HOST_SERVICE_ROUTES);
    }

    #[test]
    fn the_harmless_probes_never_need_a_host_service_check() {
        let dir = tempfile::tempdir().unwrap();
        for p in probes(&inputs(dir.path())) {
            assert!(
                !matches!(
                    p.host,
                    Some(HostCheck::LaunchdJob(_) | HostCheck::PreferencesDomain(_))
                ),
                "{} acts on a host service",
                p.name
            );
        }
    }

    #[test]
    fn what_is_not_on_this_host_is_said() {
        let dir = tempfile::tempdir().unwrap();
        let mut i = inputs(dir.path());
        i.host_sockets.clear();
        let absent = not_here(&i).join("; ");
        assert!(
            absent.contains("1 of the 2 denied sensitive paths"),
            "{absent}"
        );
        assert!(absent.contains("host sockets"), "{absent}");
        assert!(absent.contains("keychain"), "{absent}");
        i.read_deny = vec![dir.path().join("gone")];
        assert!(
            not_here(&i)
                .join("; ")
                .contains("none of the 1 denied paths")
        );
    }

    #[test]
    fn a_host_service_control_never_repeats_what_the_probe_does() {
        let dir = tempfile::tempdir().unwrap();
        for p in host_service_probes(&inputs(dir.path())) {
            let Proof::Control { control, .. } = &p.proof else {
                panic!("{} has no control", p.name);
            };
            assert_ne!(control.as_str(), p.script, "{}", p.name);
            for acting in ["open ", "osascript", "submit", "defaults write"] {
                assert!(!control.as_str().contains(acting), "{}", p.name);
            }
        }
    }

    #[test]
    fn what_the_host_checks_is_what_the_script_touches() {
        let dir = tempfile::tempdir().unwrap();
        for p in all(dir.path()) {
            match &p.host {
                Some(HostCheck::File(path)) => {
                    assert!(p.script.contains(&sh_quote(path)), "{}", p.name)
                }
                Some(HostCheck::LaunchdJob(label)) => assert!(p.script.contains(label.as_str())),
                Some(HostCheck::PreferencesDomain(d)) => assert!(p.script.contains(d.as_str())),
                Some(HostCheck::Target) => assert!(p.script.contains("4242")),
                None => {}
            }
        }
    }

    #[test]
    fn without_a_target_there_is_no_signal_probe() {
        let dir = tempfile::tempdir().unwrap();
        let mut i = inputs(dir.path());
        i.target = None;
        assert!(!probes(&i).iter().any(|p| p.route == "signals"));
    }

    #[test]
    fn missing_sensitive_paths_are_not_probed_and_paths_are_quoted() {
        let dir = tempfile::tempdir().unwrap();
        let list = probes(&inputs(dir.path()));
        assert!(!list.iter().any(|p| p.name.contains("does-not-exist")));
        assert_eq!(sh_quote(Path::new("/a b/it's")), "'/a b/it'\\''s'");
    }

    #[test]
    fn a_script_the_sandbox_never_ran_is_not_a_refusal() {
        // `sandbox-exec` refusing the compiled policy exits non-zero without
        // running the script: no marker.
        let refused = Run::read(
            false,
            "",
            "sandbox-exec: policy.sb: No such file or directory\n",
        );
        assert!(matches!(&refused, Run::NotRun(why) if why.contains("sandbox-exec")));
        let dir = tempfile::tempdir().unwrap();
        for p in all(dir.path()) {
            let got = proven(&p, refused.clone());
            assert!(matches!(got, Outcome::NotRun(_)), "{}: {got:?}", p.name);
        }
        let script = sandboxed_script(&find(&all(dir.path()), "crontab").clone());
        assert!(script.starts_with("printf 'enclos-probe-ran\\n'; "));
        assert_eq!(
            Run::read(false, "enclos-probe-ran\n403", "err\n"),
            ran(false, "403err\n")
        );
    }

    #[test]
    fn a_probe_that_fails_outside_the_sandbox_too_proves_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let list = all(dir.path());
        let cron = find(&list, "crontab");
        let failed = ran(false, "crontab: Operation not permitted");
        assert_eq!(proven(cron, failed.clone()), Outcome::Closed);
        let no_crontab = Some((false, "crontab: no crontab for alice"));
        assert!(matches!(
            outcome(cron, failed.clone(), Ok(None), no_crontab),
            Outcome::Inconclusive(why) if why.contains("no crontab")
        ));
        assert_eq!(
            outcome(cron, failed.clone(), Ok(None), Some((false, ""))),
            Outcome::Inconclusive("it fails outside the sandbox too".into())
        );
        // A probe with a control is never closed without it.
        assert!(matches!(
            outcome(cron, failed, Ok(None), None),
            Outcome::NotRun(_)
        ));
        // An open route stays open, whatever the control says.
        assert!(matches!(
            outcome(cron, ran(true, ""), Ok(None), Some((false, ""))),
            Outcome::Open(_)
        ));
    }

    #[test]
    fn what_the_host_saw_decides_first() {
        let dir = tempfile::tempdir().unwrap();
        let list = all(dir.path());
        let write = find(&list, "writes");
        let refused = ran(false, "Operation not permitted");
        let seen = Ok(Some("created it (removed)".to_owned()));
        assert!(matches!(
            outcome(write, refused.clone(), seen.clone(), Some((true, ""))),
            Outcome::Open(_)
        ));
        assert!(matches!(
            outcome(write, Run::NotRun("x".into()), seen, None),
            Outcome::Open(_)
        ));
        // A host check that could not run tests nothing.
        assert!(matches!(
            outcome(write, refused, Err("launchctl failed".into()), Some((true, ""))),
            Outcome::NotRun(why) if why.contains("could not check from the host")
        ));
    }

    #[test]
    fn the_proxy_probe_is_closed_by_a_403_and_not_run_without_a_proxy() {
        let dir = tempfile::tempdir().unwrap();
        let list = all(dir.path());
        let proxy = list
            .iter()
            .find(|p| p.proof == Proof::ProxyRefuses)
            .unwrap();
        assert_eq!(
            outcome(proxy, ran(true, "403"), Ok(None), None),
            Outcome::Closed
        );
        assert!(matches!(proven(proxy, ran(true, "200")), Outcome::Open(_)));
        assert!(matches!(proven(proxy, ran(true, "502")), Outcome::Open(_)));
        assert!(matches!(
            proven(proxy, ran(false, "000")),
            Outcome::NotRun(_)
        ));
    }

    #[test]
    fn host_services_count_only_the_refusal_seatbelt_gives() {
        let dir = tempfile::tempdir().unwrap();
        let list = all(dir.path());
        let open = find(&list, "launchservices");
        let refused = "LSOpenURLsWithRole() failed with error -54 for the file /System.";
        assert_eq!(proven(open, ran(false, refused)), Outcome::Closed);
        let other = "LSOpenURLsWithRole() failed with error -10810 for the file /System.";
        assert!(matches!(
            proven(open, ran(false, other)),
            Outcome::Inconclusive(_)
        ));

        let ae = find(&list, "apple events");
        assert!(matches!(proven(ae, ran(true, "3")), Outcome::Open(_)));
        let tcc = "execution error: Not authorized to send Apple events to Finder. (-1743)";
        assert!(matches!(proven(ae, ran(false, tcc)), Outcome::Open(_)));
        let timeout = "execution error: Finder got an error: AppleEvent timed out. (-1712)";
        assert!(matches!(proven(ae, ran(false, timeout)), Outcome::Open(_)));
        let blocked = "execution error: Finder got an error: Application isn't running. (-600)";
        assert_eq!(proven(ae, ran(false, blocked)), Outcome::Closed);
        // Finder not running makes -600 too: the control then fails.
        assert!(matches!(
            outcome(ae, ran(false, blocked), Ok(None), Some((false, ""))),
            Outcome::Inconclusive(_)
        ));
        let broken = "execution error: An error of type -10004 has occurred. (-10004)";
        assert!(matches!(
            proven(ae, ran(false, broken)),
            Outcome::Inconclusive(_)
        ));
    }

    #[test]
    fn results_are_read_by_what_each_probe_expects() {
        let dir = tempfile::tempdir().unwrap();
        let list = all(dir.path());
        assert_eq!(
            proven(find(&list, "writes"), ran(false, "")),
            Outcome::Closed
        );
        assert!(matches!(
            proven(find(&list, "writes"), ran(true, "")),
            Outcome::Open(_)
        ));
        let dns = list
            .iter()
            .find(|p| {
                matches!(
                    &p.proof,
                    Proof::Control {
                        expect: Expect::OutputLacks(_),
                        ..
                    }
                )
            })
            .unwrap();
        assert!(matches!(
            proven(dns, ran(true, "ip_address: 93.184.216.34")),
            Outcome::Open(_)
        ));
        assert_eq!(proven(dns, ran(true, "")), Outcome::Closed);
    }
}
