//! Escape probes for `enclos policy test` (design §5, ADR 0016): each tries
//! one way out of the sandbox, from inside it, and must fail.
//!
//! Probes are built to be harmless even when a rule does not hold. The ones
//! that could act on the host if they succeeded (opening an app, an Apple
//! Event, a launchd job, a preferences write) run only with
//! `--host-services`, which CI's macOS runners use; whatever they manage to
//! create is checked from the host and removed.
//!
//! A probe that only has to fail proves something only if the same thing
//! works outside the sandbox: `crontab -l` fails anyway for an account
//! without a crontab, and a connection fails anyway on a host that is
//! offline. Each such probe has a control, a harmless check run on the host
//! first; when the control fails too, the probe is inconclusive, not closed.
//! The host-service probes have none, since running them outside would act
//! on this Mac; what they leave is checked from the host instead.

use std::path::{Path, PathBuf};

/// How a probe's result is read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expect {
    /// Closed when the command fails.
    Fails,
    /// Closed when the output does not contain this text.
    OutputLacks(&'static str),
    /// Closed when the proxy answered 403.
    ProxyRefuses,
    /// Closed when no Apple Event got out. An answer, a refusal by TCC
    /// (-1743) or a wait on Finder (-1712) all mean the event left the
    /// sandbox: Seatbelt did not block it (ADR 0016).
    AppleEventBlocked,
}

/// What the host checks after the probe, and removes if it is there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostCheck {
    None,
    /// A file the probe tried to create outside the sandbox.
    File(PathBuf),
    LaunchdJob(String),
    PreferencesDomain(&'static str),
    /// A process the host started, which the probe tried to signal.
    Process(u32),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Probe {
    /// The route it belongs to, as design §5 names them.
    pub route: &'static str,
    pub name: String,
    /// A `/bin/sh -c` script run inside the sandbox.
    pub script: String,
    pub expect: Expect,
    pub host: HostCheck,
    /// A harmless `/bin/sh -c` script run on the host, outside the sandbox,
    /// that succeeds when the route works there.
    pub control: Option<String>,
}

impl Probe {
    fn control(mut self, script: impl Into<String>) -> Probe {
        self.control = Some(script.into());
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The probe failed in the sandbox, and its control worked outside it.
    Closed,
    /// The route is open: what showed it.
    Open(String),
    /// The probe failed, but so did its control outside the sandbox: the
    /// failure shows nothing about the policy.
    Inconclusive(String),
    /// The probe could not be run, with why: the route was not tested.
    NotRun(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeResult {
    pub route: &'static str,
    pub name: String,
    pub outcome: Outcome,
}

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
    /// A process the host started for the signal probe.
    pub outside_pid: u32,
    /// Makes names of things a probe might create unique.
    pub tag: u32,
    pub host_services: bool,
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
) -> Probe {
    Probe {
        route,
        name: name.into(),
        script: script.into(),
        expect,
        host: HostCheck::None,
        control: None,
    }
}

/// Reads a file, or lists a folder: either is a read of its content.
fn read(path: &Path) -> String {
    if path.is_dir() {
        format!("/bin/ls {} >/dev/null", sh_quote(path))
    } else {
        format!("/bin/cat {} >/dev/null", sh_quote(path))
    }
}

/// Whether this user may read `path`, without reading it.
fn readable(path: &Path) -> String {
    match path.is_dir() {
        true => format!("test -r {0} -a -x {0}", sh_quote(path)),
        false => format!("test -r {}", sh_quote(path)),
    }
}

/// A probe that reads `path`, controlled by whether the user may.
fn read_probe(route: &'static str, path: &Path) -> Probe {
    probe(
        route,
        format!("read {}", path.display()),
        read(path),
        Expect::Fails,
    )
    .control(readable(path))
}

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
    let in_enclos = i.data.join(format!("enclos-probe-{}", i.tag));
    let mut write = probe(
        "enclos files",
        "write in the enclos folder",
        format!("echo x > {}", sh_quote(&in_enclos)),
        Expect::Fails,
    )
    .control(format!("test -w {}", sh_quote(&i.data)));
    write.host = HostCheck::File(in_enclos);
    list.push(write);
    let outside = i.user_home.join(format!("enclos-probe-{}", i.tag));
    let mut write = probe(
        "writes",
        "write outside the home",
        format!("echo x > {}", sh_quote(&outside)),
        Expect::Fails,
    )
    .control(format!("test -w {}", sh_quote(&i.user_home)));
    write.host = HostCheck::File(outside);
    list.push(write);

    list.push(probe(
        "network",
        "an unlisted destination through the proxy",
        "/usr/bin/curl -s -o /dev/null -w '%{http_connect}' --max-time 15 https://probe.enclos.invalid/",
        Expect::ProxyRefuses,
    ));
    // The same connections outside the sandbox: they only open and close
    // a connection, and fail on a host that is offline.
    let direct = "/usr/bin/nc -z -w 3 1.1.1.1 443";
    list.push(
        probe(
            "network",
            "a direct connection, around the proxy",
            direct,
            Expect::Fails,
        )
        .control(direct),
    );
    let dns = "/usr/bin/nc -z -w 3 1.1.1.1 53";
    list.push(probe("dns", "DNS on port 53", dns, Expect::Fails).control(dns));
    list.push(
        probe(
            "dns",
            "a name lookup through mDNSResponder",
            "/usr/bin/dscacheutil -q host -a name example.com",
            Expect::OutputLacks("address"),
        )
        .control("/usr/bin/dscacheutil -q host -a name example.com | /usr/bin/grep -q address"),
    );
    for socket in &i.host_sockets {
        list.push(
            probe(
                "host sockets",
                format!("connect to {}", socket.display()),
                format!("/usr/bin/nc -U -w 2 {} </dev/null", sh_quote(socket)),
                Expect::Fails,
            )
            .control(format!("test -S {0} -a -w {0}", sh_quote(socket))),
        );
    }
    let mut signal = probe(
        "signals",
        "signal a process outside the sandbox",
        format!("kill -TERM {}", i.outside_pid),
        Expect::Fails,
    )
    // Signal 0 only checks that a signal could be sent.
    .control(format!("kill -0 {}", i.outside_pid));
    signal.host = HostCheck::Process(i.outside_pid);
    list.push(signal);
    let keychain = i.user_home.join("Library/Keychains/login.keychain-db");
    if keychain.exists() {
        // Its settings (lock timeout), not its items.
        let info = format!(
            "/usr/bin/security show-keychain-info {}",
            sh_quote(&keychain)
        );
        list.push(
            probe(
                "keychain",
                "read the login keychain's settings",
                info.clone(),
                Expect::Fails,
            )
            .control(format!("{info} >/dev/null 2>&1")),
        );
    }
    // The controls read the pasteboard and the crontab outside the sandbox,
    // and discard them; an account without a crontab makes this probe
    // inconclusive.
    let paste = "/usr/bin/pbpaste >/dev/null";
    list.push(
        probe(
            "synthetic input",
            "read the pasteboard",
            paste,
            Expect::Fails,
        )
        .control(paste),
    );
    let cron = "/usr/bin/crontab -l >/dev/null";
    list.push(probe("at and crontab", "list crontab", cron, Expect::Fails).control(cron));

    if i.host_services {
        // `open <folder>` asks LaunchServices to open it, and reports the
        // refusal. Not `open -R`: inside the sandbox it exits 0 although Finder
        // reveals nothing (shown in CI on macOS 14, 15 and 26 by checking
        // Finder's front window from outside), so its exit code says nothing.
        list.push(probe(
            "launchservices",
            "open a folder through LaunchServices",
            "/usr/bin/open -g /System",
            Expect::Fails,
        ));
        list.push(probe(
            "apple events",
            "send an Apple Event to Finder",
            "/usr/bin/osascript -e 'with timeout of 8 seconds' -e 'tell application \"Finder\" to count windows' -e 'end timeout'",
            Expect::AppleEventBlocked,
        ));
        let label = format!("org.enclos.probe.{}", i.tag);
        let mut job = probe(
            "launchd",
            "submit a launchd job",
            format!("/bin/launchctl submit -l {label} -- /usr/bin/true"),
            Expect::Fails,
        );
        job.host = HostCheck::LaunchdJob(label);
        list.push(job);
        let mut prefs = probe(
            "preferences",
            "write preferences through cfprefsd",
            "/usr/bin/defaults write org.enclos.probe probe -string written",
            Expect::Fails,
        );
        prefs.host = HostCheck::PreferencesDomain("org.enclos.probe");
        list.push(prefs);
    }
    list
}

/// Reads a probe's own result; the host check comes on top.
pub fn judge(probe: &Probe, succeeded: bool, output: &str) -> Outcome {
    match &probe.expect {
        Expect::Fails if succeeded => Outcome::Open(format!("it succeeded: {}", last_line(output))),
        Expect::Fails => Outcome::Closed,
        Expect::OutputLacks(text) if output.contains(text) => {
            Outcome::Open(format!("output has `{text}`"))
        }
        Expect::OutputLacks(_) => Outcome::Closed,
        Expect::ProxyRefuses if output.trim() == "403" => Outcome::Closed,
        Expect::ProxyRefuses => {
            Outcome::Open(format!("the proxy answered `{}`, not 403", output.trim()))
        }
        Expect::AppleEventBlocked if succeeded => {
            Outcome::Open(format!("Finder answered: {}", last_line(output)))
        }
        Expect::AppleEventBlocked if output.contains("-1743") => Outcome::Open(
            "the event reached macOS's privacy check (TCC refused it, -1743), so Seatbelt did not block it".into(),
        ),
        Expect::AppleEventBlocked if output.contains("-1712") => Outcome::Open(
            "the event reached Finder, which did not answer in time (-1712), so Seatbelt did not block it".into(),
        ),
        Expect::AppleEventBlocked => Outcome::Closed,
    }
}

/// The final outcome once the control is known: a probe that failed is
/// closed only if the control, run outside the sandbox, succeeded.
/// `control` is the control's success and output, when the probe has one.
pub fn conclude(outcome: Outcome, control: Option<(bool, &str)>) -> Outcome {
    match (outcome, control) {
        (Outcome::Closed, Some((false, output))) => {
            Outcome::Inconclusive(match last_line(output) {
                line if line.is_empty() => "it fails outside the sandbox too".to_owned(),
                line => format!("it fails outside the sandbox too: {line}"),
            })
        }
        (outcome, _) => outcome,
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

    fn inputs(host_services: bool) -> ProbeInputs {
        let dir = std::env::temp_dir();
        ProbeInputs {
            user_home: dir.clone(),
            data: dir.join("enclos"),
            config_file: dir.join("enclos/config.toml"),
            other_sandboxes: vec![dir.join("enclos/sandboxes/lab")],
            read_deny: vec![dir.clone(), dir.join("does-not-exist")],
            host_sockets: vec![],
            outside_pid: 4242,
            tag: 7,
            host_services,
        }
    }

    #[test]
    fn host_service_probes_run_only_when_asked() {
        let routes = |on| {
            probes(&inputs(on))
                .iter()
                .map(|p| p.route)
                .collect::<Vec<_>>()
        };
        let safe = routes(false);
        assert!(!safe.contains(&"launchd") && !safe.contains(&"apple events"));
        assert!(safe.contains(&"network") && safe.contains(&"signals") && safe.contains(&"writes"));
        let all = routes(true);
        assert!(
            all.contains(&"launchd")
                && all.contains(&"launchservices")
                && all.contains(&"preferences")
        );
    }

    #[test]
    fn missing_sensitive_paths_are_not_probed_and_paths_are_quoted() {
        let list = probes(&inputs(false));
        assert!(!list.iter().any(|p| p.name.contains("does-not-exist")));
        assert_eq!(sh_quote(Path::new("/a b/it's")), "'/a b/it'\\''s'");
    }

    #[test]
    fn an_apple_event_that_left_the_sandbox_is_open_whoever_refused_it() {
        let list = probes(&inputs(true));
        let ae = list.iter().find(|p| p.route == "apple events").unwrap();
        assert_eq!(ae.expect, Expect::AppleEventBlocked);
        assert!(matches!(judge(ae, true, "3"), Outcome::Open(_)));
        let tcc = "execution error: Not authorized to send Apple events to Finder. (-1743)";
        assert!(matches!(judge(ae, false, tcc), Outcome::Open(_)));
        let timeout = "execution error: Finder got an error: AppleEvent timed out. (-1712)";
        assert!(matches!(judge(ae, false, timeout), Outcome::Open(_)));
        let blocked = "execution error: An error of type -10004 has occurred. (-10004)";
        assert_eq!(judge(ae, false, blocked), Outcome::Closed);
    }

    #[test]
    fn a_probe_that_fails_outside_the_sandbox_too_proves_nothing() {
        let list = probes(&inputs(false));
        let cron = list.iter().find(|p| p.route == "at and crontab").unwrap();
        let failed = judge(cron, false, "crontab: Operation not permitted");
        assert_eq!(failed, Outcome::Closed);
        let no_crontab = "crontab: no crontab for alice";
        assert!(matches!(
            conclude(failed.clone(), Some((false, no_crontab))),
            Outcome::Inconclusive(why) if why.contains("no crontab")
        ));
        assert_eq!(conclude(failed, Some((true, ""))), Outcome::Closed);
        // An open route stays open, whatever the control says.
        let open = judge(cron, true, "");
        assert_eq!(conclude(open.clone(), Some((false, ""))), open);
    }

    #[test]
    fn every_probe_that_runs_here_has_a_control_and_host_services_have_none() {
        for p in probes(&inputs(false)) {
            let needs = p.expect != Expect::ProxyRefuses;
            assert_eq!(p.control.is_some(), needs, "{}", p.name);
        }
        let safe: Vec<String> = probes(&inputs(false)).into_iter().map(|p| p.name).collect();
        for p in probes(&inputs(true)) {
            if !safe.contains(&p.name) {
                assert!(p.control.is_none(), "{} would act on the host", p.name);
            }
        }
    }

    #[test]
    fn results_are_read_by_what_each_probe_expects() {
        let list = probes(&inputs(false));
        let find = |route| list.iter().find(|p| p.route == route).unwrap();
        assert_eq!(judge(find("writes"), false, ""), Outcome::Closed);
        assert!(matches!(judge(find("writes"), true, ""), Outcome::Open(_)));
        let proxy = list
            .iter()
            .find(|p| p.expect == Expect::ProxyRefuses)
            .unwrap();
        assert_eq!(judge(proxy, true, "403"), Outcome::Closed);
        assert!(matches!(judge(proxy, true, "200"), Outcome::Open(_)));
        let dns = list
            .iter()
            .find(|p| matches!(p.expect, Expect::OutputLacks(_)))
            .unwrap();
        assert!(matches!(
            judge(dns, true, "ip_address: 93.184.216.34"),
            Outcome::Open(_)
        ));
        assert_eq!(judge(dns, true, ""), Outcome::Closed);
    }
}
