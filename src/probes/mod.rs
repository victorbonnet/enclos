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
//! offline. The probes through the proxy are their own proof: the proxy answers
//! 403.
//!
//! Each probe's script prints a marker before anything else, so a sandbox
//! that never ran it (`sandbox-exec` refusing the compiled policy) is not
//! taken for a refusal.
//!
//! A few routes are closed by Seatbelt itself, under any profile: it refuses
//! to run setuid programs such as `crontab` and `at`, even under a bare
//! `(allow default)`. Those probes carry a note saying so, which the report
//! repeats, so that their being closed is not read as proof of a rule enclos
//! adds.
//!
//! The probes of [`probes`] are harmless even when a rule does not hold. The
//! ones of [`host_service_probes`] could act on the host if they succeeded
//! (opening a folder in Finder, an Apple Event, a launchd job, a preferences
//! write): they run only with `--host-services`, which CI's macOS runners
//! ask for. A launchd job or preferences domain they leave is checked from
//! the host and removed; LaunchServices and the Apple Event leave nothing to
//! check, so they count as closed only with the refusal the rule gives.

use std::path::{Path, PathBuf};

use crate::policy::paths::is_within;

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
    /// What closes the route when no rule enclos adds does: Seatbelt itself,
    /// whatever the profile says.
    pub closed_by_platform: Option<&'static str>,
}

/// Seatbelt refuses to run a setuid program under any profile: shown on
/// macOS 26.5.2 with `sandbox-exec -p '(version 1)(allow default)'`, where
/// `crontab -l` and `atq` fail with `Operation not permitted`.
pub const SETUID_REFUSED: &str =
    "Seatbelt itself refuses to run setuid programs, under any profile; no enclos rule is tested";

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
    /// The probe's [`Probe::closed_by_platform`].
    pub closed_by_platform: Option<&'static str>,
}

impl ProbeResult {
    pub fn of(probe: Probe, outcome: Outcome) -> ProbeResult {
        ProbeResult {
            route: probe.route,
            name: probe.name,
            outcome,
            closed_by_platform: probe.closed_by_platform,
        }
    }
}

/// The routes of [`host_service_probes`], as the report names them.
pub const HOST_SERVICE_ROUTES: &[&str] =
    &["launchservices", "apple events", "launchd", "preferences"];

/// Routes of design §5 and ADR 0016 that no probe tries yet. `policy test`
/// names them, so that a test that passed is not read as covering them.
pub const NOT_PROBED: &[&str] = &[
    "bootstrapping or loading a launchd job",
    "installing a crontab",
    "submitting an `at` job",
    "registering a login item",
    "posting synthetic input events",
    "writing the pasteboard",
    "typing into the terminal (TIOCSTI)",
    "reading a keychain item",
];

/// What the probes are built from.
#[derive(Debug, Clone)]
pub struct ProbeInputs {
    pub user_home: PathBuf,
    /// The enclos data folder and `config.toml`.
    pub data: PathBuf,
    pub config_file: PathBuf,
    /// The sandbox's own folder, which holds its `policy.toml` and
    /// `compiled/`, and its home.
    pub sandbox_dir: PathBuf,
    /// Other sandboxes' folders.
    pub other_sandboxes: Vec<PathBuf>,
    /// The policy's write grants, the sandbox home included, expanded.
    pub writes: Vec<PathBuf>,
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
        closed_by_platform: None,
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

/// A probe that opens an existing `file` for writing and writes nothing, so
/// that it changes nothing even if the rule does not hold: for files that
/// matter, such as the sandbox's `policy.toml`. Opening for writing is what
/// Seatbelt's write rules refuse (`file-write-data`); a read deny alone does
/// not. Controlled by whether the file is writable on the host. Built only
/// for a file that exists, as `>>` would create one that does not.
fn open_for_writing_probe(route: &'static str, name: &str, file: &Path) -> Probe {
    probe(
        route,
        name,
        format!("true >> {}", sh_quote(file)),
        Expect::Fails,
        format!("test -w {}", sh_quote(file)),
    )
}

/// A write of `path`, a deny-list entry under one of the policy's write
/// grants, which the deny list must still refuse (ADR 0015): a new file in
/// it when it is a folder, the file itself, unchanged, when it is a file.
fn denied_under_grant_probe(path: &Path, tag: u32) -> Probe {
    let name = format!("write {}, under a write grant", path.display());
    match path.is_dir() {
        true => write_probe(
            "sensitive files",
            &name,
            path.join(format!("enclos-probe-{tag}")),
        ),
        false => open_for_writing_probe("sensitive files", &name, path),
    }
}

/// A program Seatbelt refuses to run under any profile, setuid: closed by
/// the platform, which the report says.
fn setuid_probe(route: &'static str, name: &str, script: &str) -> Probe {
    let mut setuid = probe(
        route,
        name,
        script,
        Expect::FailsWith("Operation not permitted"),
        script,
    );
    setuid.closed_by_platform = Some(SETUID_REFUSED);
    setuid
}

/// The user's LaunchAgents folder, which launchd loads at login.
fn launch_agents(i: &ProbeInputs) -> PathBuf {
    i.user_home.join("Library/LaunchAgents")
}

/// A request through the sandbox's proxy, which must answer 403. Even with
/// `NO_PROXY` set in the sandbox, curl is told to use the proxy.
fn proxy_probe(name: &str, url: &str) -> Probe {
    Probe {
        route: "network",
        name: name.into(),
        script: format!(
            "/usr/bin/curl -s -o /dev/null -w '%{{http_connect}}' --max-time 15 --noproxy '' {url}"
        ),
        proof: Proof::ProxyRefuses,
        host: None,
        closed_by_platform: None,
    }
}

/// The probes that are harmless even if a rule does not hold: run wherever
/// `policy test` runs, the user's Mac included.
pub fn probes(i: &ProbeInputs) -> Vec<Probe> {
    let mut list = Vec::new();
    for path in i.read_deny.iter().filter(|p| p.exists()) {
        list.push(read_probe("sensitive files", path));
    }
    // A grant never covers the deny list: writing there is refused even
    // inside a granted workspace or the sandbox home.
    for path in i.read_deny.iter().filter(|p| p.exists()) {
        if i.writes.iter().any(|w| is_within(path, w)) {
            list.push(denied_under_grant_probe(path, i.tag));
        }
    }
    for path in [
        i.data.join("state.db"),
        i.data.join("state.lock"),
        i.data.join("audit.jsonl"),
        i.config_file.clone(),
        i.data.join("run"),
    ] {
        if path.exists() {
            list.push(read_probe("enclos files", &path));
        }
    }
    for dir in &i.other_sandboxes {
        list.push(read_probe("other sandboxes", dir));
        list.push(write_probe(
            "other sandboxes",
            &format!("write in {}", dir.join("home").display()),
            dir.join("home").join(format!("enclos-probe-{}", i.tag)),
        ));
    }
    list.push(write_probe(
        "enclos files",
        "write in the enclos folder",
        i.data.join(format!("enclos-probe-{}", i.tag)),
    ));
    // The sandbox's own policy and compiled policy: writing them would widen
    // its own policy at the next start.
    let policy_file = i.sandbox_dir.join("policy.toml");
    if policy_file.exists() {
        list.push(open_for_writing_probe(
            "enclos files",
            "write the sandbox's own policy.toml",
            &policy_file,
        ));
    }
    list.push(write_probe(
        "enclos files",
        "write in the sandbox's own compiled folder",
        i.sandbox_dir
            .join("compiled")
            .join(format!("enclos-probe-{}", i.tag)),
    ));
    list.push(write_probe(
        "writes",
        "write outside the home",
        i.user_home.join(format!("enclos-probe-{}", i.tag)),
    ));
    // launchd loads `*.plist` files from here at login. The probe's file has
    // no `.plist` suffix and is not a property list, and it is removed at
    // once if the rule did not hold, so it is harmless here too.
    let agents = launch_agents(i);
    if agents.is_dir() {
        list.push(write_probe(
            "launch agents",
            "write in ~/Library/LaunchAgents",
            agents.join(format!("enclos-probe-{}", i.tag)),
        ));
    }

    // Refused in either network mode (ADR 0025): a port public mode does not
    // open, and addresses no mode reaches, asked for by name through the proxy.
    list.push(proxy_probe(
        "an unlisted port through the proxy",
        "https://probe.enclos.invalid:8443/",
    ));
    for (what, address) in [
        ("loopback", "127.0.0.1"),
        ("the cloud metadata address", "169.254.169.254"),
        ("a private address", "10.0.0.1"),
    ] {
        list.push(proxy_probe(
            &format!("{what} through the proxy"),
            &format!("https://{address}/"),
        ));
    }
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
    // Reads, with the output discarded.
    list.push(same_outside(
        "pasteboard",
        "read the pasteboard",
        "/usr/bin/pbpaste >/dev/null",
    ));
    // Setuid programs, refused by Seatbelt itself. An account without a
    // crontab makes the crontab probe inconclusive.
    list.push(setuid_probe(
        "crontab",
        "read the crontab",
        "/usr/bin/crontab -l >/dev/null",
    ));
    list.push(setuid_probe(
        "at",
        "list the `at` queue",
        "/usr/bin/atq >/dev/null",
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
    if !launch_agents(i).is_dir() {
        absent.push("launch agents (no ~/Library/LaunchAgents here)".to_owned());
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
            sandbox_dir: dir.join("enclos/sandboxes/home"),
            other_sandboxes: vec![dir.join("enclos/sandboxes/lab")],
            writes: vec![dir.join("enclos/sandboxes/home/home")],
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
        for route in [
            "network",
            "signals",
            "writes",
            "other sandboxes",
            "pasteboard",
            "crontab",
            "at",
        ] {
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

    fn named<'a>(list: &'a [Probe], name: &str) -> Option<&'a Probe> {
        list.iter().find(|p| p.name.contains(name))
    }

    #[test]
    fn the_deny_list_is_probed_for_writes_under_a_grant() {
        let dir = tempfile::tempdir().unwrap();
        let work = dir.path().join("work");
        std::fs::create_dir_all(work.join(".secrets")).unwrap();
        std::fs::write(work.join(".env"), "TOKEN=x").unwrap();
        std::fs::create_dir_all(dir.path().join("outside/.ssh")).unwrap();
        let mut i = inputs(dir.path());
        i.writes.push(work.clone());
        i.read_deny = vec![
            work.join(".secrets"),
            work.join(".env"),
            work.join("absent"),
            dir.path().join("outside/.ssh"),
        ];
        let list = probes(&i);
        let under: Vec<&Probe> = list
            .iter()
            .filter(|p| p.name.ends_with("under a write grant"))
            .collect();
        assert_eq!(under.len(), 2, "{under:?}");
        // A folder: a new file in it, checked and removed by the host.
        let folder = named(&list, ".secrets, under").unwrap();
        assert_eq!(
            folder.host,
            Some(HostCheck::File(work.join(".secrets/enclos-probe-7")))
        );
        // A file: opened for writing, never changed.
        let file = named(&list, ".env, under").unwrap();
        assert_eq!(
            file.script,
            format!("true >> {}", sh_quote(&work.join(".env")))
        );
        assert_eq!(file.host, None);
        assert_eq!(file.route, "sensitive files");
        // Not under a grant, or not here: only the read is probed, if any.
        assert!(named(&list, "outside/.ssh, under").is_none());
        assert!(named(&list, "absent").is_none());
    }

    #[test]
    fn the_sandbox_s_own_policy_and_compiled_folder_are_probed_for_writes() {
        let dir = tempfile::tempdir().unwrap();
        let i = inputs(dir.path());
        let list = probes(&i);
        // No policy.toml here: `>>` would create one, so there is no probe.
        assert!(named(&list, "policy.toml").is_none());
        let compiled = named(&list, "compiled folder").unwrap();
        assert_eq!(compiled.route, "enclos files");
        assert_eq!(
            compiled.host,
            Some(HostCheck::File(
                i.sandbox_dir.join("compiled/enclos-probe-7")
            ))
        );

        std::fs::create_dir_all(&i.sandbox_dir).unwrap();
        let policy = i.sandbox_dir.join("policy.toml");
        std::fs::write(&policy, "extends = \"assistant\"\n").unwrap();
        let list = probes(&i);
        let write = named(&list, "policy.toml").unwrap();
        assert_eq!(write.route, "enclos files");
        let Proof::Control { control, .. } = &write.proof else {
            panic!("the policy.toml probe has a control");
        };
        assert_eq!(control.as_str(), format!("test -w {}", sh_quote(&policy)));
    }

    #[test]
    fn opening_a_file_for_writing_changes_nothing_even_where_it_is_allowed() {
        // What the probe does if the rule does not hold, run on the host.
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("policy.toml");
        std::fs::write(&file, "extends = \"assistant\"\n").unwrap();
        let before = std::fs::metadata(&file).unwrap().modified().unwrap();
        let probe = open_for_writing_probe("enclos files", "write it", &file);
        let status = std::process::Command::new("/bin/sh")
            .args(["-c", &probe.script])
            .status()
            .unwrap();
        assert!(status.success());
        assert_eq!(
            std::fs::read_to_string(&file).unwrap(),
            "extends = \"assistant\"\n"
        );
        assert_eq!(
            std::fs::metadata(&file).unwrap().modified().unwrap(),
            before
        );
    }

    #[test]
    fn the_launch_agents_probe_writes_a_file_launchd_never_loads() {
        let dir = tempfile::tempdir().unwrap();
        let i = inputs(dir.path());
        assert!(!probes(&i).iter().any(|p| p.route == "launch agents"));
        assert!(not_here(&i).join("; ").contains("launch agents"));

        let agents = dir.path().join("Library/LaunchAgents");
        std::fs::create_dir_all(&agents).unwrap();
        let list = probes(&i);
        let write = find(&list, "launch agents");
        let Some(HostCheck::File(file)) = &write.host else {
            panic!("the launch agents probe checks its file from the host");
        };
        assert_eq!(file.parent(), Some(agents.as_path()));
        // launchd loads `*.plist` property lists: this is neither.
        assert_ne!(file.extension().and_then(|e| e.to_str()), Some("plist"));
        assert_eq!(write.script, format!("echo x > {}", sh_quote(file)));
        assert!(!not_here(&i).join("; ").contains("launch agents"));
    }

    #[test]
    fn setuid_probes_say_seatbelt_itself_closes_them() {
        let dir = tempfile::tempdir().unwrap();
        for p in all(dir.path()) {
            let setuid = matches!(p.route, "crontab" | "at");
            assert_eq!(
                p.closed_by_platform.is_some(),
                setuid,
                "{}: {:?}",
                p.name,
                p.closed_by_platform
            );
            if setuid {
                let result = ProbeResult::of(p.clone(), Outcome::Closed);
                assert_eq!(result.closed_by_platform, Some(SETUID_REFUSED));
                // Closed only on the exec refusal; anything else ran it.
                let refused = ran(false, "/bin/sh: /usr/bin/atq: Operation not permitted");
                assert_eq!(proven(&p, refused), Outcome::Closed);
                assert!(matches!(
                    proven(&p, ran(false, "crontab: no crontab for alice")),
                    Outcome::Inconclusive(_)
                ));
            }
        }
    }

    #[test]
    fn the_routes_no_probe_tries_are_named() {
        for route in [
            "bootstrapping",
            "installing a crontab",
            "submitting an `at` job",
            "login item",
            "synthetic input",
            "writing the pasteboard",
            "TIOCSTI",
            "keychain item",
        ] {
            assert!(
                NOT_PROBED.iter().any(|r| r.contains(route)),
                "{route} is missing from {NOT_PROBED:?}"
            );
        }
        // These have probes now.
        for probed in ["LaunchAgent", "`at` jobs"] {
            assert!(!NOT_PROBED.iter().any(|r| r.contains(probed)), "{probed}");
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
