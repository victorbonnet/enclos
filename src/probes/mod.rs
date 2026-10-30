//! Escape probes for `enclos policy test` (design §5, ADR 0016): each tries
//! one way out of the sandbox, from inside it, and must fail.
//!
//! A failure proves something only if the policy caused it, so every probe
//! carries its proof. Most have a control: a harmless check run on the host
//! first, which shows the route works there (the same read, listing or
//! connection with its output discarded, the same open for writing of a file
//! that matters, which writes nothing, a check that a folder is writable, or,
//! for a host service whose use outside would act on the host, a read-only
//! check that the service is there). When the control fails too, the probe is
//! inconclusive, not closed: `crontab -l` fails anyway for an account
//! without a crontab, and a connection fails anyway on a host that is
//! offline. The probes through the proxy are their own proof: the proxy answers
//! 403. The one at the proxy port on `[::1]` also has a control: the proxy
//! must answer the same request from the host.
//!
//! Each probe's script prints a marker before anything else, so a sandbox
//! that never ran it (a backend refusing the compiled policy) is not
//! taken for a refusal.
//!
//! Every backend runs the probes of [`probes`], and adds its own through
//! [`OwnProbes`], which also says what its refusals look like. They are
//! harmless even when a rule does not hold; a backend's host-service probes
//! ([`OwnProbes::host_services`]) could act on the host if they succeeded,
//! and run only with `--host-services`.

use std::path::{Path, PathBuf};

use crate::backend::Baseline;
use crate::layout::Layout;
use crate::model::sandbox::SandboxName;
use crate::policy::paths::is_within;

/// What a program says when a backend refuses it: any one of these texts,
/// each the backend's own: one backend may refuse in one way, another by
/// what it leaves out of the sandbox, in several.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal(Vec<String>);

impl Refusal {
    pub fn any_of(texts: &[&str]) -> Refusal {
        Refusal(texts.iter().map(|t| (*t).to_owned()).collect())
    }

    fn is_in(&self, output: &str) -> bool {
        self.0.iter().any(|text| output.contains(text.as_str()))
    }

    /// As the report says it.
    pub fn shown(&self) -> String {
        self.0.join(" or ")
    }

    /// A `case` pattern that matches an output with any of the texts.
    fn case_pattern(&self) -> String {
        let each: Vec<String> = self.0.iter().map(|text| format!("*'{text}'*")).collect();
        each.join("|")
    }
}

/// A backend's own reading of a probe's result, for what the shared readings
/// of [`Expect`] do not cover. Told apart by its label.
#[derive(Debug, Clone, Copy)]
pub struct OwnReading {
    pub label: &'static str,
    /// From whether the script succeeded and what it printed. Closed here
    /// is not yet proof: [`outcome`] adds the host check and the control.
    pub read: fn(bool, &str) -> Outcome,
}

impl PartialEq for OwnReading {
    fn eq(&self, other: &OwnReading) -> bool {
        self.label == other.label
    }
}

impl Eq for OwnReading {}

/// How a probe's own result is read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expect {
    /// Closed when the script fails.
    Fails,
    /// Closed when it fails with one of these texts in its output: a refusal
    /// the backend was shown to give. Any other failure is inconclusive.
    FailsWith(Refusal),
    /// Closed when the output does not contain this text.
    OutputLacks(&'static str),
    /// A folder renamed or cloned into itself, which the filesystem refuses
    /// (`Invalid argument`; a volume that cannot clone refuses a clone with
    /// another error), so nothing moves or is copied even when the rule does
    /// not hold. Closed on the backend's refusal, which comes first; the
    /// filesystem's means the call got past `backend`: open. Any other
    /// failure is inconclusive. The control is the same call on the host,
    /// which works when the filesystem refuses it there.
    IntoItself {
        refusal: Refusal,
        backend: &'static str,
    },
    /// Read by the backend.
    Own(OwnReading),
}

/// What closes a route apart from a rule of its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Closer {
    /// The backend itself, whatever the compiled policy says.
    Backend,
    /// The compiled policy's baseline, which refuses something the tool
    /// needs before the operation the route's rule refuses is tried.
    Baseline,
}

/// Why a closed probe shows no rule of its route, in the backend's words.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClosedBy {
    pub closer: Closer,
    key: &'static str,
    by: &'static str,
    why: &'static str,
}

impl ClosedBy {
    /// `key` names it in a JSON report, `by` in a count (`1 by ...`), and
    /// `why` is what the report says of each probe it closed.
    pub const fn new(
        closer: Closer,
        key: &'static str,
        by: &'static str,
        why: &'static str,
    ) -> ClosedBy {
        ClosedBy {
            closer,
            key,
            by,
            why,
        }
    }

    /// Its name in a JSON report.
    pub fn key(self) -> &'static str {
        self.key
    }

    /// How a count of what it closed says it.
    pub fn by(self) -> &'static str {
        self.by
    }

    /// What the report says of it.
    pub fn why(self) -> &'static str {
        self.why
    }
}

/// A `/bin/sh -c` script run on the host, outside the sandbox. Only this
/// module makes one, and each is harmless whatever the policy says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostScript(String);

impl HostScript {
    pub(crate) fn new(script: impl Into<String>) -> HostScript {
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
    /// A request to the proxy port on `[::1]`, which must reach the proxy
    /// (it answers 403) or nothing (curl cannot connect, exit 7): never
    /// another program. The control, the same request from the host, must
    /// get the proxy's 403: it shows the proxy holds `[::1]` at the port, so
    /// no other program can listen there later. Both scripts print curl's
    /// code and exit status.
    OnlyTheProxy { control: HostScript },
}

/// Something on the host that a host tool looks up and removes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolCheck {
    /// What it is, as the report says it.
    pub what: String,
    pub program: &'static str,
    /// `program`'s arguments to look it up: it succeeds when it is there,
    /// and says `absent` when it is not.
    pub look: Vec<String>,
    pub absent: &'static str,
    /// `program`'s arguments to remove it.
    pub remove: Vec<String>,
    /// How the user removes it if that failed.
    pub by_hand: String,
}

/// What the host checks, before the probe and after it, and removes if the
/// probe left it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostCheck {
    /// A file the probe tries to create outside the sandbox.
    File(PathBuf),
    /// Something a backend's own probe tries to leave.
    Tool(ToolCheck),
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
    /// What closes the route apart from a rule of its own: the backend
    /// itself (no rule is tested), or the baseline (before the rule is
    /// reached).
    pub closed_by: Option<ClosedBy>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Refused in the sandbox, with its proof: its control worked on the
    /// host, or the proxy answered 403. For [`Proof::OnlyTheProxy`]: the
    /// proxy answered, or nothing did, and from the host the proxy answered.
    Closed,
    /// The route is open: what showed it.
    Open(String),
    /// It failed, but its control failed on the host too, or it failed for
    /// another reason than the expected refusal: it shows nothing.
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
    /// The probe's [`Probe::closed_by`], set only when the probe
    /// was closed.
    pub closed_by: Option<ClosedBy>,
}

impl ProbeResult {
    pub fn of(probe: Probe, outcome: Outcome) -> ProbeResult {
        let closed_by = match outcome {
            Outcome::Closed => probe.closed_by,
            _ => None,
        };
        ProbeResult {
            route: probe.route,
            name: probe.name,
            outcome,
            closed_by,
        }
    }
}

/// What a report says of a backend's probes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportNotes {
    /// The host, as a sentence says it.
    pub host: &'static str,
    /// What moves a folder that cannot move, as the probes try it.
    pub folder_moves: &'static str,
    /// Who else can close a probe, for a test where nothing else did: `,
    /// only by ... if any`, or nothing.
    pub only_apart: &'static str,
    /// The routes of [`OwnProbes::host_services`].
    pub host_service_routes: &'static [&'static str],
    /// Routes of design §5 and ADR 0016 that no probe tries yet. `policy
    /// test` names them, so that a test that passed is not read as covering
    /// them.
    pub not_probed: &'static [&'static str],
}

/// What a backend adds to the probes every backend runs, and how it refuses.
/// Each method places its probes in the list, so that a report reads route
/// by route.
pub trait OwnProbes {
    /// The backend's name, as a sentence says it.
    fn name(&self) -> &'static str;
    /// What its refusals look like.
    fn refusal(&self) -> Refusal;
    /// What a report says of its probes.
    fn notes(&self) -> ReportNotes;
    /// The baseline the probes run under, for a backend that has one.
    fn baseline(&self) -> Option<Baseline> {
        None
    }
    /// Sets up on the host what its probes need, once they will run; what
    /// it returns is held until the test ends, and undoes that when dropped.
    fn set_up(&mut self, _layout: &Layout, _name: &SandboxName) -> Box<dyn std::any::Any> {
        Box::new(())
    }
    /// Stands in for [`OwnProbes::set_up`] on a dry run, only to count the
    /// probes.
    fn count_only(&mut self, _name: &SandboxName) {}
    /// Probes of a folder that cannot move, beside its rename.
    fn of_folder(&self, _folder: &Path, _i: &ProbeInputs) -> Vec<Probe> {
        Vec::new()
    }
    /// Network probes, after the shared ones.
    fn network(&self, _i: &ProbeInputs) -> Vec<Probe> {
        Vec::new()
    }
    /// DNS probes, after the shared one.
    fn dns(&self, _i: &ProbeInputs) -> Vec<Probe> {
        Vec::new()
    }
    /// Probes that come after the terminals, before the limits.
    fn before_limits(&self, _i: &ProbeInputs) -> Vec<Probe> {
        Vec::new()
    }
    /// Probes that come last.
    fn last(&self, _i: &ProbeInputs) -> Vec<Probe> {
        Vec::new()
    }
    /// The probes that could act on the host if a rule did not hold: CI and
    /// VMs only (`--host-services`). Their controls only check that the
    /// service is there; they never use it.
    fn host_services(&self, _i: &ProbeInputs) -> Vec<Probe> {
        Vec::new()
    }
    /// What its probes leave out because it is not on this host.
    fn not_here(&self, _i: &ProbeInputs) -> Vec<String> {
        Vec::new()
    }
}

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
    /// The sandbox home, resolved: the sandbox writes inside it, but may not
    /// remove or rename it.
    pub home: PathBuf,
    /// The policy's workspaces, resolved, held to the same rule.
    pub workspaces: Vec<PathBuf>,
    /// The writable folders the sandbox must not move: the home, every
    /// workspace, and the folders inside them that hold a denied path.
    pub unmovable: Vec<PathBuf>,
    /// Unix sockets of host services that exist here (SSH agent, Docker).
    pub host_sockets: Vec<PathBuf>,
    /// The sandbox's proxy port.
    pub proxy_port: u16,
    /// Whether the policy lets the sandbox listen on TCP (ADR 0028).
    pub listen: bool,
    /// The process the host started for the signal probe; none when nothing
    /// will run (a dry run), and then there is no signal probe.
    pub target: Option<u32>,
    /// A terminal the host opened for the terminal probe, as a terminal app
    /// opens one for each tab; none on a dry run, and then there is no
    /// terminal probe.
    pub other_terminal: Option<PathBuf>,
    /// Makes names of things a probe might create unique.
    pub tag: u32,
    /// The limits the sandbox's processes run under, each of which gets a
    /// probe.
    pub limits: crate::backend::LaunchLimits,
}

/// A path as one shell word.
pub fn sh_quote(path: &Path) -> String {
    format!("'{}'", path.display().to_string().replace('\'', "'\\''"))
}

pub(crate) fn probe(
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
        closed_by: None,
    }
}

/// A probe whose control is the same script, run on the host: it only reads
/// or connects, and its output is discarded.
pub(crate) fn same_outside(route: &'static str, name: impl Into<String>, script: &str) -> Probe {
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
pub(crate) fn write_probe(route: &'static str, name: &str, file: PathBuf) -> Probe {
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

/// A probe that opens an existing regular `file` for writing and writes
/// nothing, so that it changes nothing even if the rule does not hold: for
/// files that matter, such as the sandbox's `policy.toml`. Opening for
/// writing is what a write rule refuses; a read deny alone does not. Its
/// control is the same open on the host, so a failure with another cause (a
/// flag, TCC) is inconclusive; it opens only a
/// file that is still there, as `>>` creates one that is not. Built only for
/// a regular file: opening a FIFO would wait for a reader. If the file is
/// removed between the control and the probe and the rule does not hold, the
/// sandbox creates it empty, and the probe is reported open.
fn open_for_writing_probe(route: &'static str, name: &str, file: &Path) -> Probe {
    let file = sh_quote(file);
    probe(
        route,
        name,
        format!("true >> {file}"),
        Expect::Fails,
        format!("test -f {file} && true >> {file}"),
    )
}

/// Whether a probe can read or write `path` without waiting: a folder or a
/// regular file, not a FIFO, socket or device.
fn probeable(path: &Path) -> bool {
    path.is_dir() || path.is_file()
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

/// A change to a folder itself that the file system refuses anyway (a
/// folder that is not empty cannot be removed, nor moved inside itself), so
/// the probe changes nothing whether the rule holds or not. The backend
/// checks before the file system does, so only its refusal is the policy's;
/// any other answer means the policy let the change through, which the
/// script reports as a success, so the probe reads as open. `prepare` runs
/// first, and if it fails the probe is inconclusive, never closed. The
/// control runs the same on the host, where the change must fail without
/// that refusal: then the refusal inside is the policy's, not a file flag's
/// or another rule's.
fn folder_probe(
    name: impl Into<String>,
    prepare: Option<String>,
    change: String,
    refusal: &Refusal,
) -> Probe {
    let prepare = prepare.map_or(String::new(), |p| {
        format!("{p} 2>/dev/null || {{ echo 'could not prepare the probe'; exit 2; }}; ")
    });
    let refused = format!(
        "out=$({change} 2>&1); case \"$out\" in {}) echo \"$out\"; exit 1;; esac",
        refusal.case_pattern()
    );
    probe(
        "writable folders",
        name,
        format!("{prepare}{refused}; echo \"the policy let it through: $out\""),
        Expect::FailsWith(refusal.clone()),
        format!("{prepare}{refused}"),
    )
}

/// Probes that the home and each workspace stay where they are: the
/// sandbox may neither remove nor rename them (design §5).
fn folder_probes(i: &ProbeInputs, refusal: &Refusal) -> Vec<Probe> {
    // The home holds `tmp/`, made again first so that it is never empty and
    // the removal never happens.
    let mut list = vec![folder_probe(
        "remove the sandbox home",
        Some(format!("/bin/mkdir -p {}", sh_quote(&i.home.join("tmp")))),
        format!("/bin/rmdir {}", sh_quote(&i.home)),
        refusal,
    )];
    // A workspace not made yet has nothing to rename: see
    // `missing_workspaces`.
    let workspaces = i.workspaces.iter().filter(|w| w.is_dir());
    for folder in std::iter::once(&i.home).chain(workspaces) {
        list.push(folder_probe(
            format!("rename {}", folder.display()),
            None,
            format!(
                "/bin/mv {} {}",
                sh_quote(folder),
                sh_quote(&folder.join("enclos-probe-moved"))
            ),
            refusal,
        ));
    }
    list
}

/// The workspaces that are not folders yet, each as a probe not run: the
/// sandbox may not create a workspace (design §5), so the user must, and
/// until then the report says why it was not probed.
pub fn missing_workspaces(i: &ProbeInputs) -> Vec<ProbeResult> {
    i.workspaces
        .iter()
        .filter(|w| !w.is_dir())
        .map(|w| ProbeResult {
            route: "writable folders",
            name: format!("rename {}", w.display()),
            outcome: Outcome::NotRun(
                "it is not a folder yet, and the sandbox may not create it: create it on the host"
                    .into(),
            ),
            closed_by: None,
        })
        .collect()
}

/// Renames `folder` into itself, with rename(2) through perl: the filesystem
/// refuses that whatever the policy, so the folder never moves, and the
/// same call on the host is the control.
fn rename_probe(folder: &Path, tag: u32, own: &dyn OwnProbes) -> Probe {
    into_itself(
        "renames",
        "rename",
        "rename($ARGV[0], $ARGV[1])",
        folder,
        tag,
        own,
    )
}

/// A probe whose perl `call` acts on `folder` and a path inside it
/// (`$ARGV[0]`, `$ARGV[1]`): see [`Expect::IntoItself`]. Both the probe and
/// its control print why they failed, and say what a success may have left.
pub(crate) fn into_itself(
    route: &'static str,
    verb: &str,
    call: &str,
    folder: &Path,
    tag: u32,
    own: &dyn OwnProbes,
) -> Probe {
    let script = |on_success: &str, on_failure: &str| {
        format!(
            "/usr/bin/perl -e 'if ({call}) {{ print \"it succeeded, so $ARGV[1] may now exist\\n\"; {on_success} }} {on_failure}' {} {}",
            sh_quote(folder),
            sh_quote(&folder.join(format!("enclos-probe-{tag}")))
        )
    };
    probe(
        route,
        format!("{verb} {}", folder.display()),
        script("exit 0", "die \"$!\\n\""),
        Expect::IntoItself {
            refusal: own.refusal(),
            backend: own.name(),
        },
        // The filesystem's refusal is the control working.
        script("exit 1", "exit 0 if $!{EINVAL}; die \"$!\\n\""),
    )
}

/// A request through the sandbox's proxy, which must answer 403. Even with
/// `NO_PROXY` set in the sandbox, curl is told to use the proxy.
fn proxy_probe(name: &str, url: &str) -> Probe {
    Probe {
        route: "network",
        name: name.into(),
        script: curl_through_proxy(url),
        proof: Proof::ProxyRefuses,
        host: None,
        closed_by: None,
    }
}

/// curl through the proxy, printing only the proxy's answer to CONNECT.
pub(crate) fn curl_through_proxy(url: &str) -> String {
    format!("/usr/bin/curl -s -o /dev/null -w '%{{http_connect}}' --max-time 15 --noproxy '' {url}")
}

/// The probes that are harmless even if a rule does not hold, every
/// backend's and `own`'s: run wherever `policy test` runs, the user's own
/// machine included.
pub fn probes(i: &ProbeInputs, own: &dyn OwnProbes) -> Vec<Probe> {
    let mut list = Vec::new();
    let refusal = own.refusal();
    for path in i.read_deny.iter().filter(|p| probeable(p)) {
        list.push(read_probe("sensitive files", path));
    }
    // A grant never covers the deny list: writing there is refused even
    // inside a granted workspace or the sandbox home.
    for path in i
        .read_deny
        .iter()
        .filter(|p| probeable(p) && i.writes.iter().any(|w| is_within(p, w)))
    {
        list.push(denied_under_grant_probe(path, i.tag));
    }
    for folder in i.unmovable.iter().filter(|f| f.is_dir()) {
        list.push(rename_probe(folder, i.tag, own));
        list.extend(own.of_folder(folder, i));
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
    // its own policy at the next start. Without a policy.toml, creating one
    // is the route, checked and removed by the host.
    let policy_file = i.sandbox_dir.join("policy.toml");
    list.push(match policy_file.is_file() {
        true => open_for_writing_probe(
            "enclos files",
            "write the sandbox's own policy.toml",
            &policy_file,
        ),
        false => write_probe(
            "enclos files",
            "create the sandbox's own policy.toml",
            policy_file,
        ),
    });
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
    list.extend(folder_probes(i, &refusal));

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
    list.extend(own.network(i));
    list.push(same_outside(
        "dns",
        "DNS on port 53",
        "/usr/bin/nc -z -w 3 1.1.1.1 53",
    ));
    list.extend(own.dns(i));
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
    if let Some(terminal) = &i.other_terminal {
        // Opened to read, as reading another tab's keystrokes would, then to
        // write, as writing into it would: either open is the route. Outside
        // too, where it only opens it, and writes nothing.
        let t = sh_quote(terminal);
        for (name, open) in [
            (
                "open a terminal that is not the session's, to read",
                format!(": < {t}"),
            ),
            (
                "open a terminal that is not the session's, to write",
                format!(": >> {t}"),
            ),
        ] {
            list.push(probe(
                "terminals",
                name,
                open.clone(),
                Expect::FailsWith(refusal.clone()),
                open,
            ));
        }
    }
    list.extend(own.before_limits(i));
    // Each limit a backend sets, as a process sees it, hard: closed when it
    // is no higher than the policy's (a hard limit no process without root
    // can raise). The control, the same check on the host, passes when the
    // host's own hard limit is higher than the policy's, or unlimited. A
    // value that does not read as a number is no proof: it reads open.
    if let Some(limit) = i.limits.open_files() {
        list.push(same_outside(
            "resources",
            format!("have a hard limit above {limit} open files"),
            &limit_script("-Hn", limit),
        ));
    }
    list.extend(own.last(i));
    list
}

/// What [`probes`] leaves out because it is not on this host, so that the
/// report says so instead of leaving those routes out silently.
pub fn not_here(i: &ProbeInputs, own: &dyn OwnProbes) -> Vec<String> {
    let mut absent = Vec::new();
    let missing = i.read_deny.iter().filter(|p| !p.exists()).count();
    let others = i
        .read_deny
        .iter()
        .filter(|p| p.exists() && !probeable(p))
        .map(|p| p.display().to_string())
        .collect::<Vec<_>>();
    match (missing, i.read_deny.len()) {
        (0, _) => {}
        (m, n) if m == n => absent.push(format!(
            "sensitive files (none of the {n} denied paths exists here)"
        )),
        (m, n) => absent.push(format!(
            "{m} of the {n} denied sensitive paths (they do not exist here)"
        )),
    }
    if !others.is_empty() {
        absent.push(format!(
            "denied paths that are neither a file nor a folder, which a probe could wait on: {}",
            others.join(", ")
        ));
    }
    let not_folders = i.unmovable.iter().filter(|f| !f.is_dir()).count();
    if not_folders > 0 {
        absent.push(format!(
            "{} of {not_folders} of the {} folders that cannot move (they are not folders here)",
            own.notes().folder_moves,
            i.unmovable.len()
        ));
    }
    if i.host_sockets.is_empty() {
        absent.push("host sockets (no SSH agent or Docker socket here)".to_owned());
    }
    absent.extend(own.not_here(i));
    absent
}

/// The script of a limit's probe: it succeeds, open, when the limit
/// `ulimit {flag}` reads is above `limit`, unlimited, or not a number.
pub(crate) fn limit_script(flag: &str, limit: u64) -> String {
    format!(
        "v=$(ulimit {flag}); case \"$v\" in unlimited) exit 0 ;; ''|*[!0-9]*) echo \"unreadable limit: $v\"; exit 0 ;; esac; test \"$v\" -gt {limit}"
    )
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
            (Proof::OnlyTheProxy { .. }, Some((_, host))) => match host.split_whitespace().next() {
                Some("403") => Outcome::Closed,
                _ => Outcome::Inconclusive(format!(
                    "from the host, the proxy does not answer on [::1] at its port (curl printed `{}`), so another program could listen there; is IPv6 loopback off?",
                    last_line(host)
                )),
            },
            (Proof::OnlyTheProxy { .. }, None) => Outcome::NotRun("its control did not run".into()),
            (Proof::Control { .. }, Some((true, _))) => Outcome::Closed,
            (Proof::Control { expect, .. }, Some((false, output))) => {
                let why = match expect {
                    Expect::IntoItself { .. } => {
                        "outside the sandbox, the filesystem did not refuse it with Invalid argument"
                    }
                    _ => "it fails outside the sandbox too",
                };
                Outcome::Inconclusive(match last_line(output) {
                    line if line.is_empty() => why.to_owned(),
                    line => format!("{why}: {line}"),
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
        Proof::OnlyTheProxy { .. } => {
            let mut words = output.split_whitespace();
            return match (words.next(), words.next()) {
                (Some("403"), _) => Outcome::Closed,
                // Nothing there to reach: the rule refused it, or nothing
                // listens, which only the control rules out.
                (Some("000"), Some("7")) => Outcome::Closed,
                _ => Outcome::Open(format!(
                    "curl printed `{}`: neither the proxy's 403 nor no connection",
                    last_line(output)
                )),
            };
        }
        Proof::Control { expect, .. } => expect,
    };
    match expect {
        Expect::Fails | Expect::FailsWith(_) if succeeded => {
            Outcome::Open(format!("it succeeded: {}", last_line(output)))
        }
        Expect::Fails => Outcome::Closed,
        Expect::FailsWith(refusal) if refusal.is_in(output) => Outcome::Closed,
        Expect::FailsWith(refusal) => Outcome::Inconclusive(format!(
            "it failed, but not with the expected refusal ({}): {}",
            refusal.shown(),
            last_line(output)
        )),
        Expect::OutputLacks(text) if output.contains(text) => {
            Outcome::Open(format!("output has `{text}`"))
        }
        Expect::OutputLacks(_) => Outcome::Closed,
        // Its script says what the call may have left.
        Expect::IntoItself { .. } if succeeded => Outcome::Open(match last_line(output) {
            line if line.is_empty() => "it succeeded".to_owned(),
            line => line,
        }),
        Expect::IntoItself { refusal, .. } if refusal.is_in(output) => Outcome::Closed,
        Expect::IntoItself { backend, .. } if output.contains("Invalid argument") => {
            Outcome::Open(format!(
                "the filesystem refused it (Invalid argument), so {backend} let the call through"
            ))
        }
        Expect::IntoItself { refusal, .. } => Outcome::Inconclusive(format!(
            "it failed, but not with the policy's refusal ({}): {}",
            refusal.shown(),
            last_line(output)
        )),
        Expect::Own(reading) => (reading.read)(succeeded, output),
    }
}

pub(crate) fn last_line(output: &str) -> String {
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
    use crate::backend::seatbelt::probes::SeatbeltProbes;
    use std::process::Command;

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

    /// The list of a real backend, whose refusal the texts below use.
    fn seatbelt() -> SeatbeltProbes {
        SeatbeltProbes::on(crate::backend::Baseline::DenyDefault)
    }

    fn probes(i: &ProbeInputs) -> Vec<Probe> {
        super::probes(i, &seatbelt())
    }

    fn all(dir: &Path) -> Vec<Probe> {
        let i = inputs(dir);
        probes(&i)
            .into_iter()
            .chain(seatbelt().host_services(&i))
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
    fn what_the_host_checks_is_what_the_script_touches() {
        let dir = tempfile::tempdir().unwrap();
        for p in all(dir.path()) {
            match &p.host {
                Some(HostCheck::File(path)) => {
                    assert!(p.script.contains(&sh_quote(path)), "{}", p.name)
                }
                Some(HostCheck::Tool(check)) => {
                    assert!(check.look.iter().any(|a| p.script.contains(a.as_str())))
                }
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
        // No policy.toml here: creating one is the route, checked by the host.
        let create = named(&list, "create the sandbox's own policy.toml").unwrap();
        assert_eq!(create.route, "enclos files");
        assert_eq!(
            create.host,
            Some(HostCheck::File(i.sandbox_dir.join("policy.toml")))
        );
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
        assert!(named(&list, "create the sandbox's own policy.toml").is_none());
        let write = named(&list, "write the sandbox's own policy.toml").unwrap();
        assert_eq!(write.route, "enclos files");
        assert_eq!(write.host, None);
        let Proof::Control { control, .. } = &write.proof else {
            panic!("the policy.toml probe has a control");
        };
        // The same open, on the host, only of a file that is there.
        let quoted = sh_quote(&policy);
        assert_eq!(
            control.as_str(),
            format!("test -f {quoted} && true >> {quoted}")
        );
    }

    #[test]
    fn the_state_lock_and_run_folder_are_probed_for_reads() {
        let dir = tempfile::tempdir().unwrap();
        let i = inputs(dir.path());
        std::fs::create_dir_all(i.data.join("run")).unwrap();
        std::fs::write(i.data.join("state.lock"), "").unwrap();
        let list = probes(&i);
        let lock = named(&list, "state.lock").unwrap();
        assert_eq!(lock.route, "enclos files");
        assert!(
            lock.script.starts_with("/usr/bin/head -c 1 "),
            "{}",
            lock.script
        );
        let run = list
            .iter()
            .find(|p| p.name == format!("read {}", i.data.join("run").display()))
            .unwrap();
        assert!(run.script.starts_with("/bin/ls "), "{}", run.script);
    }

    #[test]
    fn a_denied_path_that_is_neither_a_file_nor_a_folder_is_named_not_probed() {
        // Opening a FIFO waits for the other end: a probe would hang.
        let dir = tempfile::tempdir().unwrap();
        let fifo = dir.path().join("work/pipe");
        std::fs::create_dir_all(fifo.parent().unwrap()).unwrap();
        let made = std::process::Command::new("/usr/bin/mkfifo")
            .arg(&fifo)
            .status()
            .unwrap();
        assert!(made.success());
        let mut i = inputs(dir.path());
        i.writes.push(dir.path().join("work"));
        i.read_deny = vec![fifo.clone()];
        assert!(named(&probes(&i), "pipe").is_none());
        let absent = super::not_here(&i, &seatbelt()).join("; ");
        assert!(
            absent.contains("neither a file nor a folder") && absent.contains("work/pipe"),
            "{absent}"
        );
    }

    #[test]
    fn opening_a_file_for_writing_changes_nothing_even_where_it_is_allowed() {
        // What the probe does if the rule does not hold, run on the host.
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("policy.toml");
        std::fs::write(&file, "extends = \"assistant\"\n").unwrap();
        let before = std::fs::metadata(&file).unwrap().modified().unwrap();
        let probe = open_for_writing_probe("enclos files", "write it", &file);
        let Proof::Control { control, .. } = &probe.proof else {
            panic!("it has a control");
        };
        let sh = |script: &str| {
            std::process::Command::new("/bin/sh")
                .args(["-c", script])
                .status()
                .unwrap()
                .success()
        };
        assert!(sh(&probe.script));
        assert!(sh(control.as_str()));
        assert_eq!(
            std::fs::read_to_string(&file).unwrap(),
            "extends = \"assistant\"\n"
        );
        assert_eq!(
            std::fs::metadata(&file).unwrap().modified().unwrap(),
            before
        );
        // The control never creates the file it opens.
        let gone = dir.path().join("gone.toml");
        let gone = open_for_writing_probe("enclos files", "write it", &gone);
        let Proof::Control { control, .. } = &gone.proof else {
            panic!("it has a control");
        };
        assert!(!sh(control.as_str()));
        assert!(!dir.path().join("gone.toml").exists());
    }

    #[test]
    fn each_limit_set_is_probed_as_a_hard_limit() {
        let dir = tempfile::tempdir().unwrap();
        let mut i = inputs(dir.path());
        assert!(!probes(&i).iter().any(|p| p.route == "resources"));
        i.limits = crate::backend::LaunchLimits::of_checked(&crate::model::policy::Resources {
            open_files: Some(256),
            ..Default::default()
        })
        .unwrap();
        let list = probes(&i);
        let limits: Vec<(&str, &str)> = list
            .iter()
            .filter(|p| p.route == "resources")
            .map(|p| (p.name.as_str(), p.script.as_str()))
            .collect();
        assert_eq!(
            limits,
            [(
                "have a hard limit above 256 open files",
                limit_script("-Hn", 256).as_str()
            )]
        );
    }

    #[test]
    fn the_home_and_each_workspace_are_probed_and_only_the_policy_closes_them() {
        let dir = tempfile::tempdir().unwrap();
        let mut i = inputs(dir.path());
        // Only a workspace that exists has anything to rename.
        i.workspaces.push(dir.path().join("not-made-yet"));
        std::fs::create_dir(dir.path().join("work")).unwrap();
        let list = probes(&i);
        let folders: Vec<&Probe> = list
            .iter()
            .filter(|p| p.route == "writable folders")
            .collect();
        let names: Vec<&str> = folders.iter().map(|p| p.name.as_str()).collect();
        let home = dir.path().join("enclos/sandboxes/home/home");
        assert_eq!(
            names,
            [
                "remove the sandbox home".to_owned(),
                format!("rename {}", home.display()),
                format!("rename {}", dir.path().join("work").display()),
            ]
        );
        let missing = missing_workspaces(&i);
        assert_eq!(missing.len(), 1);
        assert!(matches!(&missing[0].outcome, Outcome::NotRun(_)));
        std::fs::create_dir_all(&home).unwrap();
        let on_host = |p: &Probe| {
            let Proof::Control { control, .. } = &p.proof else {
                panic!("{}", p.name)
            };
            Command::new("/bin/sh")
                .args(["-c", control.as_str()])
                .status()
                .unwrap()
                .success()
        };
        for p in &folders {
            // Each change is one the file system refuses anyway (a removal
            // of a folder made non-empty first, or a move inside itself),
            // and on the host it fails without the policy's refusal.
            assert!(on_host(p), "{}", p.name);
            assert!(matches!(
                proven(p, ran(false, "could not prepare the probe")),
                Outcome::Inconclusive(_)
            ));
            assert_eq!(
                proven(p, ran(false, "rmdir: x: Operation not permitted")),
                Outcome::Closed
            );
            // The file system's own refusal means the policy let it through.
            assert!(matches!(
                proven(
                    p,
                    ran(true, "the policy let it through: Directory not empty")
                ),
                Outcome::Open(_)
            ));
        }
        for folder in [&home, &dir.path().join("work")] {
            assert!(folder.is_dir() && !folder.join("enclos-probe-moved").exists());
        }
        // A home the host itself may not remove (a file flag): its control
        // fails, so `Operation not permitted` inside would prove nothing.
        // `chflags` and the user immutable flag are macOS's; Linux has no
        // such flag a user can set without root.
        #[cfg(target_os = "macos")]
        {
            let flag = |f: &str| {
                assert!(
                    Command::new("/usr/bin/chflags")
                        .args([f, home.to_str().unwrap()])
                        .status()
                        .unwrap()
                        .success()
                );
            };
            flag("uchg");
            let removal = on_host(folders[0]);
            flag("nouchg");
            assert!(!removal);
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
        let failed = ran(false, "/bin/sh: /usr/bin/crontab: Operation not permitted");
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
    fn a_terminal_is_probed_for_reading_and_writing_apart_and_closed_only_on_the_refusal() {
        let dir = tempfile::tempdir().unwrap();
        let list = probes(&inputs(dir.path()));
        let terminals: Vec<_> = list.iter().filter(|p| p.route == "terminals").collect();
        let scripts: Vec<_> = terminals.iter().map(|p| p.script.as_str()).collect();
        assert_eq!(scripts, [": < '/dev/ttys042'", ": >> '/dev/ttys042'"]);
        let refused = "/bin/sh: /dev/ttys042: Operation not permitted";
        for p in terminals {
            assert_eq!(proven(p, ran(false, refused)), Outcome::Closed);
            let busy = "/bin/sh: /dev/ttys042: Resource busy";
            assert!(matches!(
                proven(p, ran(false, busy)),
                Outcome::Inconclusive(_)
            ));
            assert!(matches!(proven(p, ran(true, "")), Outcome::Open(_)));
        }
        // A dry run opens no terminal, so there is no such probe.
        let mut none = inputs(dir.path());
        none.other_terminal = None;
        assert!(probes(&none).iter().all(|p| p.route != "terminals"));
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

    /// A backend with no probes of its own, refusing as one that leaves
    /// things out of the sandbox does.
    struct Plain;

    impl OwnProbes for Plain {
        fn name(&self) -> &'static str {
            "Plain"
        }

        fn refusal(&self) -> Refusal {
            Refusal::any_of(&["No such file or directory", "Read-only file system"])
        }

        fn notes(&self) -> ReportNotes {
            ReportNotes {
                host: "this host",
                folder_moves: "renames",
                only_apart: "",
                host_service_routes: &[],
                not_probed: &[],
            }
        }
    }

    /// The shared set names no route, command or word of another backend's,
    /// and needs none of its own to be complete.
    #[test]
    fn a_backend_with_no_probes_of_its_own_gets_the_shared_set() {
        let dir = tempfile::tempdir().unwrap();
        let i = inputs(dir.path());
        let list = super::probes(&i, &Plain);
        let routes: Vec<&str> = list.iter().map(|p| p.route).collect();
        for route in [
            "renames",
            "other sandboxes",
            "enclos files",
            "writes",
            "writable folders",
            "network",
            "dns",
            "host sockets",
            "signals",
            "terminals",
        ] {
            assert!(routes.contains(&route), "{route}");
        }
        for route in ["clones", "keychain", "pasteboard", "crontab", "at"] {
            assert!(!routes.contains(&route), "{route}");
        }
        for p in &list {
            assert!(!p.script.contains("Operation not permitted"), "{}", p.name);
            assert_eq!(p.closed_by, None, "{}", p.name);
        }
        assert!(Plain.host_services(&i).is_empty());
        assert!(
            super::not_here(&i, &Plain)
                .join("; ")
                .contains("renames of 1 of the 2 folders")
        );
    }

    /// Each text of a backend's refusal closes a probe, and another
    /// backend's does not.
    #[test]
    fn a_probe_is_closed_by_any_refusal_of_its_backend_and_no_other() {
        let dir = tempfile::tempdir().unwrap();
        let list = super::probes(&inputs(dir.path()), &Plain);
        for route in ["terminals", "writable folders", "renames"] {
            let p = find(&list, route);
            for refusal in [
                "/bin/sh: x: No such file or directory",
                "Read-only file system",
            ] {
                assert_eq!(proven(p, ran(false, refusal)), Outcome::Closed, "{route}");
            }
            assert!(
                matches!(
                    proven(p, ran(false, "Operation not permitted")),
                    Outcome::Inconclusive(why) if why.contains("No such file or directory or Read-only file system")
                ),
                "{route}"
            );
        }
        // What the filesystem says of a folder into itself is the backend's
        // letting it through, whichever backend it is.
        assert!(matches!(
            proven(find(&list, "renames"), ran(false, "Invalid argument")),
            Outcome::Open(why) if why.contains("Plain let the call through")
        ));
        // Each refusal in the script, so that either stops the folder probe.
        assert!(
            find(&list, "writable folders").script.contains(
                "case \"$out\" in *'No such file or directory'*|*'Read-only file system'*)"
            )
        );
    }
}
