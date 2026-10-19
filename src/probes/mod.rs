//! Escape probes for `enclos policy test` (design §5, ADR 0016): each tries
//! one way out of the sandbox, from inside it, and must fail.
//!
//! Probes are built to be harmless even when a rule does not hold. The ones
//! that could act on the host if they succeeded (opening an app, an Apple
//! Event, a launchd job, a preferences write) run only with
//! `--host-services`, which CI's macOS runners use; whatever they manage to
//! create is checked from the host and removed.

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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Closed,
    /// The route is open: what showed it.
    Open(String),
    Skipped(String),
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

pub fn probes(i: &ProbeInputs) -> Vec<Probe> {
    let mut list = Vec::new();
    for path in i.read_deny.iter().filter(|p| p.exists()) {
        list.push(probe(
            "sensitive files",
            format!("read {}", path.display()),
            read(path),
            Expect::Fails,
        ));
    }
    for path in [
        i.data.join("state.db"),
        i.data.join("audit.jsonl"),
        i.config_file.clone(),
    ] {
        if path.exists() {
            list.push(probe(
                "enclos files",
                format!("read {}", path.display()),
                read(&path),
                Expect::Fails,
            ));
        }
    }
    for dir in &i.other_sandboxes {
        list.push(probe(
            "other sandboxes",
            format!("read {}", dir.display()),
            read(dir),
            Expect::Fails,
        ));
    }
    let in_enclos = i.data.join(format!("enclos-probe-{}", i.tag));
    let mut write = probe(
        "enclos files",
        "write in the enclos folder",
        format!("echo x > {}", sh_quote(&in_enclos)),
        Expect::Fails,
    );
    write.host = HostCheck::File(in_enclos);
    list.push(write);
    let outside = i.user_home.join(format!("enclos-probe-{}", i.tag));
    let mut write = probe(
        "writes",
        "write outside the home",
        format!("echo x > {}", sh_quote(&outside)),
        Expect::Fails,
    );
    write.host = HostCheck::File(outside);
    list.push(write);

    list.push(probe(
        "network",
        "an unlisted destination through the proxy",
        "/usr/bin/curl -s -o /dev/null -w '%{http_connect}' --max-time 15 https://probe.enclos.invalid/",
        Expect::ProxyRefuses,
    ));
    list.push(probe(
        "network",
        "a direct connection, around the proxy",
        "/usr/bin/nc -z -w 3 1.1.1.1 443",
        Expect::Fails,
    ));
    list.push(probe(
        "dns",
        "DNS on port 53",
        "/usr/bin/nc -z -w 3 1.1.1.1 53",
        Expect::Fails,
    ));
    list.push(probe(
        "dns",
        "a name lookup through mDNSResponder",
        "/usr/bin/dscacheutil -q host -a name example.com",
        Expect::OutputLacks("address"),
    ));
    for socket in &i.host_sockets {
        list.push(probe(
            "host sockets",
            format!("connect to {}", socket.display()),
            format!("/usr/bin/nc -U -w 2 {} </dev/null", sh_quote(socket)),
            Expect::Fails,
        ));
    }
    let mut signal = probe(
        "signals",
        "signal a process outside the sandbox",
        format!("kill -TERM {}", i.outside_pid),
        Expect::Fails,
    );
    signal.host = HostCheck::Process(i.outside_pid);
    list.push(signal);
    let keychain = i.user_home.join("Library/Keychains/login.keychain-db");
    if keychain.exists() {
        list.push(probe(
            "keychain",
            "read the login keychain's settings",
            format!(
                "/usr/bin/security show-keychain-info {}",
                sh_quote(&keychain)
            ),
            Expect::Fails,
        ));
    }
    list.push(probe(
        "synthetic input",
        "read the pasteboard",
        "/usr/bin/pbpaste >/dev/null",
        Expect::Fails,
    ));
    list.push(probe(
        "at and crontab",
        "list crontab",
        "/usr/bin/crontab -l >/dev/null",
        Expect::Fails,
    ));

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
            Expect::Fails,
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
