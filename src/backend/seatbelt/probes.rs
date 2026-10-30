//! Seatbelt's own escape probes (design §5, ADR 0016), and how it refuses:
//! the shared set is in [`crate::probes`].
//!
//! A few routes are closed by Seatbelt itself, whatever the compiled policy
//! says: it refuses to run setuid programs such as `crontab` and `at`, even
//! under a bare `(allow default)`. Others are closed under `(deny default)`
//! by the baseline before the rule they test is reached: LaunchServices and
//! Apple Events at least, where the baseline refuses something the tool
//! needs (which operation is not traced; a lookup is likely). Those probes
//! carry a note saying so ([`ClosedBy`]), which the report repeats, so that
//! their being closed is not read as proof of the route's own rule.
//!
//! The probes of [`OwnProbes::host_services`] could act on the host if they
//! succeeded (opening a folder in Finder, an Apple Event, a launchd job, a
//! preferences write, a file in `~/Library/LaunchAgents`): they run only
//! with `--host-services`, which CI's macOS runners ask for. A launchd job,
//! preferences domain or file they leave is checked from the host and
//! removed; LaunchServices and the Apple Event leave nothing to check, so
//! they count as closed only with a refusal Seatbelt gives: on `(allow
//! default)` the rule's own (-54, -600), and on `(deny default)` only what
//! the baseline's refusal makes the tool say (-10661, -1728); the rule's
//! there reads inconclusive, as it would mean the baseline let the tool
//! through.

use std::any::Any;
use std::path::{Path, PathBuf};

use crate::backend::Baseline;
use crate::layout::Layout;
use crate::model::sandbox::SandboxName;
use crate::model::secret::{SecretRef, SecretValue};
use crate::probes::{
    ClosedBy, Closer, Expect, HostCheck, HostScript, Outcome, OwnProbes, OwnReading, Probe,
    ProbeInputs, Proof, Refusal, ReportNotes, ToolCheck, curl_through_proxy, into_itself,
    last_line, probe, same_outside, sh_quote, write_probe,
};
use crate::secrets::SecretStore;
use crate::secrets::keychain::Keychain;

/// What `osascript` says when the policy's rule refuses the event.
pub const AE_REFUSED: &str = "(-600)";
/// What `osascript` says when the `(deny default)` baseline refuses what it
/// needs to reach Finder, likely its lookup (macOS 15 and 26, CI; not
/// traced): `Can’t get application
/// "Finder". (-1728)`. Finder's own -1728, `Finder got an error: Can’t get
/// …`, means the event reached it, and does not match.
pub const AE_LOOKUP_REFUSED: &str = "application \"Finder\". (-1728)";
/// What `open` says when the policy's `lsopen` rule refuses it.
pub const LS_REFUSED: &str = "error -54 ";
/// What `open` says when the `(deny default)` baseline refuses what it needs
/// of LaunchServices, likely its lookup (macOS 15 and 26, CI; not traced).
pub const LS_LOOKUP_REFUSED: &str = "Code=-10661";

/// What a program says when Seatbelt refuses it.
const NOT_PERMITTED: &str = "Operation not permitted";

/// Seatbelt itself, whatever the compiled policy says.
pub const ITSELF: ClosedBy = ClosedBy::new(
    Closer::Backend,
    "seatbelt",
    "by Seatbelt itself",
    SETUID_REFUSED,
);

/// The `(deny default)` baseline, which refuses something the tool needs
/// before the operation the route's rule refuses is tried.
pub const BEFORE_THE_RULE: ClosedBy = ClosedBy::new(
    Closer::Baseline,
    "baseline",
    "by the (deny default) baseline",
    LOOKUP_REFUSED,
);

/// Under `(deny default)`, the baseline refuses first.
const LOOKUP_REFUSED: &str = "on (deny default) the baseline refuses something the tool needs (likely a lookup; not traced) before the route's rule is reached; the rule itself is shown only by a run on (allow default), as enclos's CI makes";

/// Seatbelt refuses to run a setuid program whatever the compiled policy
/// says: shown on macOS 26.5.2, with read-only commands, under
/// `sandbox-exec -p '(version 1)(allow default)'` alone, where the shell
/// reports `/bin/sh: /usr/bin/atq: Operation not permitted` (and the same for
/// `crontab -l` and `at -l`).
const SETUID_REFUSED: &str =
    "Seatbelt itself refuses to run setuid programs, whatever the policy; no enclos rule is tested";

/// The routes of [`OwnProbes::host_services`], as the report names them.
pub const HOST_SERVICE_ROUTES: &[&str] = &[
    "launchservices",
    "apple events",
    "launchd",
    "preferences",
    "launch agents",
];

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
];

/// A Keychain item the host stores for the probe that tries to read one from
/// inside the sandbox, and removes after. Its value is
/// [`KEYCHAIN_PROBE_VALUE`], which `security` prints as
/// [`KEYCHAIN_PROBE_HEX`], since enclos stores values as hex.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeychainItem {
    pub service: String,
    pub account: String,
    /// The keychain file, when it is not the user's default one.
    pub file: Option<PathBuf>,
}

pub const KEYCHAIN_PROBE_VALUE: &str = "enclos-probe";
const KEYCHAIN_PROBE_HEX: &str = "656e636c6f732d70726f6265";

/// What a report says of Seatbelt's probes.
pub const NOTES: ReportNotes = ReportNotes {
    host: "this Mac",
    folder_moves: "renames and clones",
    only_apart: ", only by Seatbelt itself or the (deny default) baseline if any",
    host_service_routes: HOST_SERVICE_ROUTES,
    not_probed: NOT_PROBED,
};

/// A launchd job a probe tries to leave.
pub(crate) fn launchd_job(label: &str) -> ToolCheck {
    ToolCheck {
        what: format!("the launchd job {label}"),
        program: "/bin/launchctl",
        look: vec!["list".to_owned(), label.to_owned()],
        absent: "Could not find service",
        remove: vec!["remove".to_owned(), label.to_owned()],
        by_hand: format!("remove it with `launchctl remove {label}`"),
    }
}

/// A preferences domain a probe tries to leave.
pub(crate) fn preferences_domain(domain: &str) -> ToolCheck {
    ToolCheck {
        what: format!("the preferences domain {domain}"),
        program: "/usr/bin/defaults",
        look: vec!["read".to_owned(), domain.to_owned()],
        absent: "does not exist",
        remove: vec!["delete".to_owned(), domain.to_owned()],
        by_hand: format!("delete it with `defaults delete {domain}`"),
    }
}

/// An Apple Event to Finder, closed on `refusal`: the policy rule's
/// ([`AE_REFUSED`]) on `(allow default)`, and on `(deny default)` what
/// `osascript` says when the baseline refuses what it needs to reach Finder
/// ([`AE_LOOKUP_REFUSED`]). An answer, a refusal by TCC (-1743) or a wait on
/// Finder (-1712) all mean the event left the sandbox: open (ADR 0016). Any
/// other failure is inconclusive.
fn apple_event(refusal: &str, succeeded: bool, output: &str) -> Outcome {
    if succeeded {
        return Outcome::Open(format!("Finder answered: {}", last_line(output)));
    }
    // What shows the event left is matched loosely, what shows it did not
    // strictly.
    if output.contains("-1743") {
        return Outcome::Open(
            "the event reached macOS's privacy check (TCC refused it, -1743), so Seatbelt did not block it".into(),
        );
    }
    if output.contains("-1712") {
        return Outcome::Open(
            "the event reached Finder, which did not answer in time (-1712), so Seatbelt did not block it".into(),
        );
    }
    if output.contains(refusal) {
        return Outcome::Closed;
    }
    Outcome::Inconclusive(format!(
        "the event failed, but not with the refusal expected on this baseline, {refusal}: {}",
        last_line(output)
    ))
}

const EVENT_REFUSED: OwnReading = OwnReading {
    label: "apple event blocked: (-600)",
    read: |succeeded, output| apple_event(AE_REFUSED, succeeded, output),
};

const EVENT_LOOKUP_REFUSED: OwnReading = OwnReading {
    label: "apple event blocked: application \"Finder\". (-1728)",
    read: |succeeded, output| apple_event(AE_LOOKUP_REFUSED, succeeded, output),
};

/// A loopback address a bind probe tries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Loopback {
    V4,
    V6,
}

impl Loopback {
    fn shown(self) -> &'static str {
        match self {
            Loopback::V4 => "127.0.0.1",
            Loopback::V6 => "[::1]",
        }
    }
}

/// A script that binds TCP `port` on `at` and exits at once: it never
/// listens, so nothing can connect even if the bind is allowed. Port 0 lets
/// the system choose one. `perl` ships with macOS and prints the error it
/// gets, Seatbelt's `Operation not permitted` included, after `bind: `, so
/// a refusal of anything else is not taken for the bind's.
fn bind_script(at: Loopback, port: u16) -> String {
    let (family, address) = match at {
        Loopback::V4 => (
            "AF_INET",
            format!("sockaddr_in({port}, inet_aton(\"127.0.0.1\"))"),
        ),
        Loopback::V6 => (
            "AF_INET6",
            format!("pack_sockaddr_in6({port}, inet_pton(AF_INET6, \"::1\"))"),
        ),
    };
    format!(
        "/usr/bin/perl -MSocket=:all -e 'socket(my $s, {family}, SOCK_STREAM, 0) or die \"socket: $!\\n\"; bind($s, {address}) or die \"bind: $!\\n\"'"
    )
}

/// What a bind Seatbelt refused prints.
const BIND_REFUSED: &str = "bind: Operation not permitted";

/// Listening (ADR 0028), on 127.0.0.1 and on `[::1]`. Without `listen`, no
/// TCP bind at all. With it, any port but the proxy range, so the probes bind
/// the sandbox's own proxy port: Seatbelt refuses before the port is found
/// in use, so the bind is refused the same way while the proxy holds it,
/// where the host would get `Address already in use`. The control is a bind
/// of the same address on a port the system chooses, on the host: where
/// `[::1]` is not configured it fails, and that probe is inconclusive. That
/// listening itself is open when allowed is said by the report, not shown
/// as closed.
pub(crate) fn listen_probes(listen: bool, proxy_port: u16) -> Vec<Probe> {
    [Loopback::V4, Loopback::V6]
        .into_iter()
        .map(|at| {
            let (name, port) = match listen {
                false => (format!("bind a TCP port on {}", at.shown()), 0),
                true => (
                    format!(
                        "bind the sandbox's proxy port, {proxy_port}, on {}",
                        at.shown()
                    ),
                    proxy_port,
                ),
            };
            probe(
                "network",
                name,
                bind_script(at, port),
                Expect::FailsWith(Refusal::any_of(&[BIND_REFUSED])),
                bind_script(at, 0),
            )
        })
        .collect()
}

/// A setuid program, which Seatbelt refuses to run whatever the compiled
/// policy says: closed by the platform, which the report says. Closed only
/// on the shell's own refusal to run `program` (`refusal`), so that a
/// program that ran and then failed is not taken for it.
fn setuid_probe(
    route: &'static str,
    name: &str,
    program: &str,
    args: &str,
    refusal: &'static str,
) -> Probe {
    let script = format!("{program} {args}");
    let mut setuid = probe(
        route,
        name,
        &script,
        Expect::FailsWith(Refusal::any_of(&[refusal])),
        &script,
    );
    setuid.closed_by = Some(ITSELF);
    setuid
}

/// The user's LaunchAgents folder, which launchd loads at login.
fn launch_agents(i: &ProbeInputs) -> PathBuf {
    i.user_home.join("Library/LaunchAgents")
}

/// Clones `folder` into itself, with clonefileat(2) (syscall 462, with
/// `AT_FDCWD`) through perl, which has no call of its own for it: refused by
/// the filesystem whatever the policy, so nothing is copied.
fn clone_probe(folder: &Path, tag: u32, own: &dyn OwnProbes) -> Probe {
    into_itself(
        "clones",
        "clone",
        "syscall(462, -2, $ARGV[0], -2, $ARGV[1], 0) == 0",
        folder,
        tag,
        own,
    )
}

/// The proxy port on `[::1]`. On macOS 26.5.2 the Seatbelt rule was shown
/// to open the port there too, so the proxy listens there; whatever the
/// sandbox reaches at that address must be the proxy.
fn ipv6_loopback_probe(port: u16) -> Probe {
    let url = format!("--proxy 'http://[::1]:{port}' https://probe.enclos.invalid:8443/");
    let script = format!("{}; echo \" $?\"", curl_through_proxy(&url));
    Probe {
        route: "network",
        name: "the proxy port on IPv6 loopback reaches only the proxy".into(),
        script: script.clone(),
        proof: Proof::OnlyTheProxy {
            control: HostScript::new(script),
        },
        host: None,
        closed_by: None,
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
    fn store(layout: &Layout, name: &SandboxName) -> std::result::Result<KeychainProbe, String> {
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
            crate::notes::say(&format!(
                "the keychain item probe's test item stays: {e}; it is {}",
                self.store.whereabouts(&self.secret)
            ));
        }
    }
}

/// Seatbelt's probes of a sandbox whose compiled policy is on one baseline.
pub struct SeatbeltProbes {
    /// On `(deny default)` the baseline refuses what it does not allow
    /// before a route's rule.
    baseline: Baseline,
    /// The item the host stored for the "read a keychain item" probe, or why
    /// none could be stored (Linux, no default keychain, a store that
    /// failed), and then that probe is not run. A dry run on macOS gets a
    /// placeholder, only to count it.
    pub(super) keychain_item: Result<KeychainItem, String>,
}

impl SeatbeltProbes {
    pub fn on(baseline: Baseline) -> SeatbeltProbes {
        SeatbeltProbes {
            baseline,
            keychain_item: Err("not probed here".into()),
        }
    }
}

impl OwnProbes for SeatbeltProbes {
    fn name(&self) -> &'static str {
        "Seatbelt"
    }

    fn refusal(&self) -> Refusal {
        Refusal::any_of(&[NOT_PERMITTED])
    }

    fn notes(&self) -> ReportNotes {
        NOTES
    }

    fn baseline(&self) -> Option<Baseline> {
        Some(self.baseline)
    }

    fn set_up(&mut self, layout: &Layout, name: &SandboxName) -> Box<dyn Any> {
        let keychain = KeychainProbe::store(layout, name);
        self.keychain_item = keychain
            .as_ref()
            .map(|k| k.item.clone())
            .map_err(Clone::clone);
        Box::new(keychain)
    }

    fn count_only(&mut self, name: &SandboxName) {
        self.keychain_item = match cfg!(target_os = "macos") {
            true => Ok(KeychainItem {
                service: "enclos.probe".into(),
                account: format!("{name}/probe"),
                file: None,
            }),
            false => Err("the Keychain is macOS's".to_owned()),
        };
    }

    fn of_folder(&self, folder: &Path, i: &ProbeInputs) -> Vec<Probe> {
        vec![clone_probe(folder, i.tag, self)]
    }

    fn network(&self, i: &ProbeInputs) -> Vec<Probe> {
        let mut list = vec![ipv6_loopback_probe(i.proxy_port)];
        list.extend(listen_probes(i.listen, i.proxy_port));
        list
    }

    fn dns(&self, _i: &ProbeInputs) -> Vec<Probe> {
        vec![probe(
            "dns",
            "a name lookup through mDNSResponder",
            "/usr/bin/dscacheutil -q host -a name example.com",
            Expect::OutputLacks("address"),
            "/usr/bin/dscacheutil -q host -a name example.com | /usr/bin/grep -q address",
        )]
    }

    fn before_limits(&self, i: &ProbeInputs) -> Vec<Probe> {
        let keychain = login_keychain(i);
        if !keychain.exists() {
            return Vec::new();
        }
        // Its settings (lock timeout), not its items.
        let info = format!(
            "/usr/bin/security show-keychain-info {} >/dev/null 2>&1",
            sh_quote(&keychain)
        );
        vec![same_outside(
            "keychain",
            "read the login keychain's settings",
            &info,
        )]
    }

    fn last(&self, _i: &ProbeInputs) -> Vec<Probe> {
        let mut list = Vec::new();
        if let Ok(item) = &self.keychain_item {
            // Through `security` and the security daemon, as a program in the
            // sandbox would read a secret: closed when the value does not come
            // back. The control reads it on the host.
            let file = item
                .file
                .as_ref()
                .map(|f| format!(" {}", sh_quote(f)))
                .unwrap_or_default();
            let read = format!(
                "/usr/bin/security find-generic-password -s {} -a {} -w{file} 2>/dev/null",
                sh_quote(Path::new(&item.service)),
                sh_quote(Path::new(&item.account)),
            );
            list.push(probe(
                "keychain",
                "read a keychain item",
                read.clone(),
                Expect::OutputLacks(KEYCHAIN_PROBE_HEX),
                format!("{read} | /usr/bin/grep -q {KEYCHAIN_PROBE_HEX}"),
            ));
        }
        list.push(same_outside(
            "pasteboard",
            "read the pasteboard",
            "/usr/bin/pbpaste >/dev/null",
        ));
        // An account without a crontab makes the crontab probe inconclusive.
        list.push(setuid_probe(
            "crontab",
            "read the crontab",
            "/usr/bin/crontab",
            "-l >/dev/null",
            "/usr/bin/crontab: Operation not permitted",
        ));
        list.push(setuid_probe(
            "at",
            "list the `at` queue",
            "/usr/bin/atq",
            ">/dev/null",
            "/usr/bin/atq: Operation not permitted",
        ));
        list
    }

    fn host_services(&self, i: &ProbeInputs) -> Vec<Probe> {
        // A session with Finder, which LaunchServices and Apple Events need.
        let finder = "/usr/bin/pgrep -x Finder >/dev/null";
        // What closes LaunchServices and Apple Events, and why, on the baseline
        // the probes run under: on `(deny default)` only the baseline's refusal,
        // the rule's there meaning the baseline let the tool through.
        let (ls_refused, ae_refused, closed_by) = match self.baseline {
            Baseline::DenyDefault => (
                LS_LOOKUP_REFUSED,
                EVENT_LOOKUP_REFUSED,
                Some(BEFORE_THE_RULE),
            ),
            Baseline::AllowDefault => (LS_REFUSED, EVENT_REFUSED, None),
        };
        // `open <folder>` reports the rule's refusal (-54, design §5). Not `open
        // -R`: inside the sandbox it exits 0 although Finder reveals nothing,
        // so its exit code says nothing (ADR 0016).
        let mut launch_services = probe(
            "launchservices",
            "open a folder through LaunchServices",
            "/usr/bin/open -g /System",
            Expect::FailsWith(Refusal::any_of(&[ls_refused])),
            finder,
        );
        launch_services.closed_by = closed_by;
        let mut apple_events = probe(
            "apple events",
            "send an Apple Event to Finder",
            "/usr/bin/osascript -e 'with timeout of 8 seconds' -e 'tell application \"Finder\" to count windows' -e 'end timeout'",
            Expect::Own(ae_refused),
            finder,
        );
        apple_events.closed_by = closed_by;
        let mut list = vec![launch_services, apple_events];
        let label = format!("org.enclos.probe.{}", i.tag);
        let mut job = probe(
            "launchd",
            "submit a launchd job",
            format!("/bin/launchctl submit -l {label} -- /usr/bin/true"),
            Expect::Fails,
            "/bin/launchctl print gui/$(/usr/bin/id -u) >/dev/null 2>&1",
        );
        job.host = Some(HostCheck::Tool(launchd_job(&label)));
        list.push(job);
        let domain = format!("org.enclos.probe.{}", i.tag);
        let mut prefs = probe(
            "preferences",
            "write preferences through cfprefsd",
            format!("/usr/bin/defaults write {domain} probe -string written"),
            Expect::Fails,
            "/usr/bin/defaults domains >/dev/null 2>&1",
        );
        prefs.host = Some(HostCheck::Tool(preferences_domain(&domain)));
        list.push(prefs);
        // launchd loads `*.plist` property lists from here at login: the probe's
        // file is neither, and it is removed at once if the rule did not hold.
        // Whether macOS's background task management reacts to a new file here
        // is not shown, so this probe writes on the host only where asked.
        let agents = launch_agents(i);
        if agents.is_dir() {
            list.push(write_probe(
                "launch agents",
                "write in ~/Library/LaunchAgents",
                agents.join(format!("enclos-probe-{}", i.tag)),
            ));
        }
        list
    }

    fn not_here(&self, i: &ProbeInputs) -> Vec<String> {
        let mut absent = Vec::new();
        if !login_keychain(i).exists() {
            absent.push("keychain (no login keychain here)".to_owned());
        }
        if !launch_agents(i).is_dir() {
            absent.push("launch agents (no ~/Library/LaunchAgents here)".to_owned());
        }
        if let Err(why) = &self.keychain_item {
            absent.push(format!("keychain items ({why})"));
        }
        absent
    }
}

/// The user's login keychain.
fn login_keychain(i: &ProbeInputs) -> PathBuf {
    i.user_home.join("Library/Keychains/login.keychain-db")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probes::{ProbeResult, Run, outcome};

    fn inputs(dir: &Path) -> ProbeInputs {
        std::fs::create_dir_all(dir.join("it's here")).unwrap();
        ProbeInputs {
            user_home: dir.to_owned(),
            data: dir.join("enclos"),
            config_file: dir.join("enclos/config.toml"),
            sandbox_dir: dir.join("enclos/sandboxes/home"),
            other_sandboxes: vec![dir.join("enclos/sandboxes/lab")],
            writes: vec![dir.join("enclos/sandboxes/home/home")],
            read_deny: vec![dir.to_owned(), dir.join("does-not-exist")],
            home: dir.join("enclos/sandboxes/home/home"),
            workspaces: vec![dir.join("work")],
            unmovable: vec![dir.join("it's here"), dir.join("not-a-folder")],
            host_sockets: vec![dir.join("agent.sock")],
            proxy_port: 41001,
            listen: false,
            target: Some(4242),
            other_terminal: Some(PathBuf::from("/dev/ttys042")),
            tag: 7,
            limits: Default::default(),
        }
    }

    fn own() -> SeatbeltProbes {
        SeatbeltProbes::on(Baseline::DenyDefault)
    }

    fn probes(i: &ProbeInputs) -> Vec<Probe> {
        crate::probes::probes(i, &own())
    }

    fn not_here(i: &ProbeInputs) -> Vec<String> {
        crate::probes::not_here(i, &own())
    }

    fn all(dir: &Path) -> Vec<Probe> {
        let i = inputs(dir);
        probes(&i)
            .into_iter()
            .chain(own().host_services(&i))
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

    fn unreachable_ls() -> &'static str {
        "No application knows how to open URL file:///System/ (Error Domain=NSOSStatusErrorDomain Code=-10661 \"kLSApplicationNotFoundErr: E.g. no application claims the file\")"
    }

    #[test]
    fn host_service_probes_are_apart_and_the_harmless_ones_never_use_a_host_service() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("Library/LaunchAgents")).unwrap();
        let routes: Vec<&str> = probes(&inputs(dir.path()))
            .iter()
            .map(|p| p.route)
            .collect();
        for route in HOST_SERVICE_ROUTES {
            assert!(!routes.contains(route), "{route}");
        }
        for route in [
            "network",
            "signals",
            "terminals",
            "writes",
            "other sandboxes",
            "pasteboard",
            "crontab",
            "at",
        ] {
            assert!(routes.contains(&route), "{route}");
        }
        let host: Vec<&str> = own()
            .host_services(&inputs(dir.path()))
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
                !matches!(p.host, Some(HostCheck::Tool(_))),
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
        assert!(
            absent.contains("renames and clones of 1 of the 2 folders that cannot move"),
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
        for p in own().host_services(&inputs(dir.path())) {
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
    fn the_launch_agents_probe_writes_a_file_launchd_never_loads_and_only_where_asked() {
        let dir = tempfile::tempdir().unwrap();
        let i = inputs(dir.path());
        assert!(
            !own()
                .host_services(&i)
                .iter()
                .any(|p| p.route == "launch agents")
        );
        assert!(not_here(&i).join("; ").contains("launch agents"));

        let agents = dir.path().join("Library/LaunchAgents");
        std::fs::create_dir_all(&agents).unwrap();
        // It writes on the host if the rule does not hold: a host-service probe.
        assert!(!probes(&i).iter().any(|p| p.route == "launch agents"));
        let list = own().host_services(&i);
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
            // On `(deny default)`, as these inputs say, the host services
            // the baseline refuses something of (likely a lookup; not
            // traced) are the baseline's.
            let by = match p.route {
                "crontab" | "at" => Some(ITSELF),
                "launchservices" | "apple events" => Some(BEFORE_THE_RULE),
                _ => None,
            };
            assert_eq!(p.closed_by, by, "{}", p.name);
            if setuid {
                let result = ProbeResult::of(p.clone(), Outcome::Closed);
                assert_eq!(result.closed_by, Some(ITSELF));
                // Only a closed probe carries the note.
                let other = ProbeResult::of(p.clone(), Outcome::Inconclusive("x".into()));
                assert_eq!(other.closed_by, None);
                // Closed only on the shell's refusal to run the program, as
                // `/bin/sh` prints it; a program that ran and failed is not.
                let program = p.script.split(' ').next().unwrap();
                let refused = format!("/bin/sh: {program}: Operation not permitted");
                assert_eq!(proven(&p, ran(false, &refused)), Outcome::Closed);
                for after_it_ran in [
                    "crontab: no crontab for alice",
                    "crontab: /usr/lib/cron/tabs/alice: Operation not permitted",
                    "atq: /usr/lib/cron/jobs: Operation not permitted",
                ] {
                    assert!(
                        matches!(
                            proven(&p, ran(false, after_it_ran)),
                            Outcome::Inconclusive(_)
                        ),
                        "{}: {after_it_ran}",
                        p.name
                    );
                }
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
        ] {
            assert!(
                NOT_PROBED.iter().any(|r| r.contains(route)),
                "{route} is missing from {NOT_PROBED:?}"
            );
        }
    }

    #[test]
    fn a_keychain_item_is_probed_when_one_was_stored_and_said_missing_otherwise() {
        let dir = tempfile::tempdir().unwrap();
        let i = inputs(dir.path());
        assert!(!probes(&i).iter().any(|p| p.name == "read a keychain item"));
        assert!(not_here(&i).iter().any(|a| a.starts_with("keychain items")));
        let mut stored = own();
        stored.keychain_item = Ok(KeychainItem {
            service: "enclos.abc.probe".into(),
            account: "home/probe".into(),
            file: None,
        });
        let list = crate::probes::probes(&i, &stored);
        let probe = list
            .iter()
            .find(|p| p.name == "read a keychain item")
            .unwrap();
        assert!(
            probe
                .script
                .contains("find-generic-password -s 'enclos.abc.probe' -a 'home/probe' -w"),
            "{}",
            probe.script
        );
        assert!(
            matches!(&probe.proof, Proof::Control { expect: Expect::OutputLacks(hex), .. } if *hex == KEYCHAIN_PROBE_HEX)
        );
        assert!(
            !crate::probes::not_here(&i, &stored)
                .iter()
                .any(|a| a.starts_with("keychain items"))
        );
        // The value enclos stores, as `security` prints it back.
        let hex: String = KEYCHAIN_PROBE_VALUE
            .bytes()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(hex, KEYCHAIN_PROBE_HEX);
    }

    #[test]
    fn the_proxy_port_on_ipv6_loopback_must_reach_the_proxy_or_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let list = probes(&inputs(dir.path()));
        let p = list
            .iter()
            .find(|p| p.name.contains("IPv6 loopback"))
            .unwrap();
        assert_eq!(p.route, "network");
        let Proof::OnlyTheProxy { control } = &p.proof else {
            panic!("{:?}", p.proof);
        };
        // The control is the same request, from the host.
        assert_eq!(control.as_str(), p.script);
        assert!(
            p.script.contains("--proxy 'http://[::1]:41001'")
                && p.script.ends_with("; echo \" $?\""),
            "{}",
            p.script
        );
        let held = Some((true, "403 0\n"));
        // The proxy refused it, as it refuses that port. The script always
        // ends with `echo`, so it always succeeds.
        for answer in ["403 56\n", "403"] {
            assert_eq!(
                outcome(p, ran(true, answer), Ok(None), held),
                Outcome::Closed
            );
        }
        // No connection: the rule refused it, and the proxy holds the port.
        assert_eq!(
            outcome(p, ran(true, "000 7\n"), Ok(None), held),
            Outcome::Closed
        );
        // Without the proxy on `[::1]` from the host, no connection proves
        // nothing: the port is free for another program to take.
        for host in ["000 7\n", ""] {
            assert!(
                matches!(
                    outcome(p, ran(true, "000 7\n"), Ok(None), Some((true, host))),
                    Outcome::Inconclusive(why) if why.contains("another program could listen there")
                ),
                "{host}"
            );
        }
        assert!(matches!(
            outcome(p, ran(true, "000 7\n"), Ok(None), None),
            Outcome::NotRun(_)
        ));
        // Anything else answered, or accepted and said nothing.
        for other in ["200 0", "502 56", "000 28", "000 52", ""] {
            assert!(
                matches!(
                    outcome(p, ran(true, other), Ok(None), held),
                    Outcome::Open(_)
                ),
                "{other}"
            );
        }
    }

    #[test]
    fn host_services_count_only_the_refusal_seatbelt_gives() {
        let dir = tempfile::tempdir().unwrap();
        let list = all(dir.path());
        let open = find(&list, "launchservices");
        // On (deny default) the rule's own refusal would mean the lookup was
        // allowed: not shown closed.
        let refused = "LSOpenURLsWithRole() failed with error -54 for the file /System.";
        assert!(matches!(
            proven(open, ran(false, refused)),
            Outcome::Inconclusive(_)
        ));
        let other = "LSOpenURLsWithRole() failed with error -10810 for the file /System.";
        assert!(matches!(
            proven(open, ran(false, other)),
            Outcome::Inconclusive(_)
        ));
        // Under (deny default) the lookup itself is refused (CI, macOS 15
        // and 26).
        let unreachable = "No application knows how to open URL file:///System/ (Error Domain=NSOSStatusErrorDomain Code=-10661 \"kLSApplicationNotFoundErr: E.g. no application claims the file\")";
        assert_eq!(proven(open, ran(false, unreachable)), Outcome::Closed);
        assert!(matches!(proven(open, ran(true, "")), Outcome::Open(_)));

        let ae = find(&list, "apple events");
        assert!(matches!(proven(ae, ran(true, "3")), Outcome::Open(_)));
        let tcc = "execution error: Not authorized to send Apple events to Finder. (-1743)";
        assert!(matches!(proven(ae, ran(false, tcc)), Outcome::Open(_)));
        let timeout = "execution error: Finder got an error: AppleEvent timed out. (-1712)";
        assert!(matches!(proven(ae, ran(false, timeout)), Outcome::Open(_)));
        let blocked = "execution error: Finder got an error: Application isn't running. (-600)";
        assert!(matches!(
            proven(ae, ran(false, blocked)),
            Outcome::Inconclusive(_)
        ));
        let unreachable = "55:68: execution error: Can’t get application \"Finder\". (-1728)";
        assert_eq!(proven(ae, ran(false, unreachable)), Outcome::Closed);
        let broken = "execution error: An error of type -10004 has occurred. (-10004)";
        assert!(matches!(
            proven(ae, ran(false, broken)),
            Outcome::Inconclusive(_)
        ));
        // Finder's own -1728 means the event reached it.
        let answered = "execution error: Finder got an error: Can’t get window 1. (-1728)";
        assert!(!matches!(proven(ae, ran(false, answered)), Outcome::Closed));
        // A failed control, or a success, outweighs the codes.
        for (probe, text) in [(open, unreachable_ls()), (ae, unreachable)] {
            assert!(matches!(
                outcome(probe, ran(false, text), Ok(None), Some((false, ""))),
                Outcome::Inconclusive(_)
            ));
            assert!(matches!(proven(probe, ran(true, text)), Outcome::Open(_)));
            // Under deny default, a route closed so is the baseline's.
            assert_eq!(probe.closed_by, Some(BEFORE_THE_RULE));
        }
    }

    /// On `(allow default)` only the rules' own refusals close these routes:
    /// what a refused lookup says is inconclusive there, so the comparison
    /// shows the rules.
    #[test]
    fn on_allow_default_only_the_rules_refusals_close_the_host_services() {
        let dir = tempfile::tempdir().unwrap();
        let i = inputs(dir.path());
        let list = SeatbeltProbes::on(Baseline::AllowDefault).host_services(&i);
        let open = find(&list, "launchservices");
        let ae = find(&list, "apple events");
        assert!(matches!(
            proven(open, ran(false, unreachable_ls())),
            Outcome::Inconclusive(_)
        ));
        let lookup = "55:68: execution error: Can’t get application \"Finder\". (-1728)";
        assert!(matches!(
            proven(ae, ran(false, lookup)),
            Outcome::Inconclusive(_)
        ));
        let refused = "LSOpenURLsWithRole() failed with error -54 for the file /System.";
        assert_eq!(proven(open, ran(false, refused)), Outcome::Closed);
        let blocked = "execution error: Finder got an error: Application isn't running. (-600)";
        assert_eq!(proven(ae, ran(false, blocked)), Outcome::Closed);
        assert!(list.iter().all(|p| p.closed_by.is_none()));
    }

    #[test]
    fn a_rename_or_clone_is_closed_only_by_seatbelt_refusing_it_before_the_filesystem() {
        let dir = tempfile::tempdir().unwrap();
        let list = all(dir.path());
        for route in ["renames", "clones"] {
            let found: Vec<&Probe> = list.iter().filter(|p| p.route == route).collect();
            assert_eq!(found.len(), 1, "only folders that exist: {found:?}");
            let p = found[0];
            assert!(
                p.script.contains(&sh_quote(&dir.path().join("it's here"))),
                "{}",
                p.script
            );
            let refused = "Operation not permitted";
            assert_eq!(proven(p, ran(false, refused)), Outcome::Closed);
            assert!(matches!(
                proven(p, ran(false, "Invalid argument")),
                Outcome::Open(why) if why.contains("Seatbelt let the call through")
            ));
            assert!(matches!(proven(p, ran(true, "")), Outcome::Open(_)));
            let left = "it succeeded, so /x/enclos-probe-7 may now exist";
            assert_eq!(proven(p, ran(true, left)), Outcome::Open(left.into()));
            assert!(matches!(
                proven(p, ran(false, "No such file or directory")),
                Outcome::Inconclusive(_)
            ));
            // A control that did not get the filesystem's refusal says why,
            // and never lets the probe count as closed.
            for host in ["Operation not supported", left] {
                assert_eq!(
                    outcome(p, ran(false, refused), Ok(None), Some((false, host))),
                    Outcome::Inconclusive(format!(
                        "outside the sandbox, the filesystem did not refuse it with Invalid argument: {host}"
                    ))
                );
            }
        }
    }

    /// The controls themselves, run on the host on temporary folders: the
    /// filesystem refuses a folder into itself, so they work and nothing is
    /// made; on a folder no longer there, they fail and say why.
    #[cfg(target_os = "macos")]
    #[test]
    fn the_rename_and_clone_controls_work_on_a_folder_and_say_why_they_fail() {
        let dir = tempfile::tempdir().unwrap();
        let (here, gone) = (dir.path().join("here"), dir.path().join("gone"));
        std::fs::create_dir(&here).unwrap();
        std::fs::create_dir(&gone).unwrap();
        let controls = |folder: &Path| -> Vec<HostScript> {
            let mut i = inputs(dir.path());
            i.unmovable = vec![folder.to_owned()];
            probes(&i)
                .into_iter()
                .filter(|p| ["renames", "clones"].contains(&p.route))
                .map(|p| match p.proof {
                    Proof::Control { control, .. } => control,
                    Proof::ProxyRefuses | Proof::OnlyTheProxy { .. } => {
                        panic!("{} has no control", p.name)
                    }
                })
                .collect()
        };
        let run = |control: &HostScript| {
            let out = std::process::Command::new("/bin/sh")
                .args(["-c", control.as_str()])
                .output()
                .unwrap();
            let text = String::from_utf8_lossy(&out.stdout).into_owned()
                + &String::from_utf8_lossy(&out.stderr);
            (out.status.success(), text)
        };
        let (worked, failing) = (controls(&here), controls(&gone));
        assert_eq!((worked.len(), failing.len()), (2, 2));
        for control in &worked {
            let (ok, text) = run(control);
            assert!(ok, "{text}");
        }
        assert!(!here.join("enclos-probe-7").exists());
        std::fs::remove_dir(&gone).unwrap();
        for control in &failing {
            let (ok, text) = run(control);
            assert!(!ok && text.contains("No such file or directory"), "{text}");
        }
    }
}
