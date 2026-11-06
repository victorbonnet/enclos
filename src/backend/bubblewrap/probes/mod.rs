//! bubblewrap's own escape probes (design §5, §13 milestone 3's step 5),
//! and how it refuses: the shared set is in [`crate::probes`].
//!
//! Linux's routes out are not macOS's: the session and system buses, the
//! `systemd --user` manager, every Unix socket on the host, abstract
//! sockets, the host's loopback and vsock, processes outside the session's
//! PID namespace, the terminal, setuid programs, namespaces, mounts and the
//! session's cgroup. Each probe has a control on the host, as on macOS. Most
//! make one call and read the errno it got ([`calls`]); what they aim at on
//! the host is read as the test starts ([`host`]).
//!
//! bubblewrap hides a path by leaving it out or by an empty stand-in, a
//! mask, so a read is closed when it reads nothing of what the host reads
//! there, not only when it fails. Sessions of one sandbox share its network
//! namespace (ADR 0039), so the abstract sockets probed are the host's and
//! the other sandboxes', never the sandbox's own. None of these probes
//! could act on the host if a rule did not hold, so none waits for
//! `--host-services`.

mod calls;
mod host;
mod sockets;
#[cfg(test)]
mod tests;

use std::any::Any;
use std::path::{Path, PathBuf};

use crate::layout::Layout;
use crate::model::sandbox::{BackendKind, SandboxName};
use crate::policy::paths::real_path;
use crate::probes::{
    ClosedBy, Closer, Expect, Outcome, OwnProbes, OwnReading, Probe, ProbeInputs, ProbeResult,
    Refusal, ReportNotes, TARGET_VARIABLE, missing_workspaces, probe, same_outside, sh_quote,
};
use calls::Numbers;
use host::HostFacts;
use sockets::Address;

/// bubblewrap itself, whatever the compiled policy says.
pub const ITSELF: ClosedBy = ClosedBy::new(
    Closer::Backend,
    "bubblewrap",
    "by bubblewrap itself",
    "bubblewrap itself runs every program with no_new_privs, whatever the policy, so a setuid or setgid program gains nothing; no enclos rule is tested",
);

/// What a program says when bubblewrap's sandbox refuses it: a path not
/// there (`dash` says `No such file`), a read-only mount, Landlock, or the
/// seccomp filter.
const REFUSALS: &[&str] = &[
    "No such file",
    "Read-only file system",
    "Permission denied",
    "Operation not permitted",
];

/// Routes of design §5 that no probe tries yet. `policy test` names them, so
/// that a test that passed is not read as covering them.
pub const NOT_PROBED: &[&str] = &[
    "installing a crontab",
    "submitting an `at` job",
    "a call through the session or system bus, polkit's included, beyond reaching it",
    "starting a unit through the `systemd --user` manager, beyond reaching it",
];

/// What a report says of bubblewrap's probes.
pub const NOTES: ReportNotes = ReportNotes {
    host: BackendKind::Bubblewrap.host(),
    folder_moves: "renames",
    listening: "Open by the policy: listening on TCP in the sandbox's own network namespace, which its sessions share (ADR 0039); the loopback probe shows only that the host's loopback stays out of reach.",
    only_apart: ", only by bubblewrap itself if any",
    host_service_routes: &[],
    not_probed: NOT_PROBED,
    baseline_key: None,
    comparison: None,
};

/// A read of a path the sandbox may not see, closed when it reads nothing
/// of it: bubblewrap leaves it out or shows an empty mask in its place.
const READS_NOTHING: OwnReading = OwnReading {
    label: "reads nothing",
    read: |succeeded, _| match succeeded {
        true => Outcome::Open("it read what the host reads there".to_owned()),
        false => Outcome::Closed,
    },
    when_control_fails: Some(
        "the host reads nothing of it either: it is empty or unreadable, so reading nothing shows nothing",
    ),
};

/// `crontab -l` without its group, which `no_new_privs` keeps it from
/// taking, cannot reach the spool: what it prints when the user has no
/// crontab says it did.
const CRONTAB: OwnReading = OwnReading {
    label: "crontab without its group",
    read: |succeeded, output| {
        if succeeded {
            Outcome::Open("it read the crontab, so crontab ran with its group".to_owned())
        } else if output.contains("no crontab for") {
            Outcome::Open("crontab reached the spool, so it ran with its group".to_owned())
        } else {
            Outcome::Closed
        }
    },
    when_control_fails: None,
};

/// bubblewrap's probes of one sandbox, with what they aim at on the host.
#[derive(Debug, Default)]
pub struct BubblewrapProbes {
    facts: HostFacts,
    /// What compile binds back of enclos's folders for this sandbox, at the
    /// path given and the real one: a listing of a folder that holds one
    /// leaves out its way there.
    given: Vec<PathBuf>,
}

impl BubblewrapProbes {
    /// Its home, `compiled/`, `secrets/` and the folder of its proxy's
    /// socket.
    fn given(layout: &Layout, name: &SandboxName) -> Vec<PathBuf> {
        let name = name.as_str();
        let mut given = vec![
            layout.sandbox_home(name),
            layout.sandbox_dir(name).join("compiled"),
            layout.sandbox_secrets_dir(name),
            layout.sandbox_run_dir(name).join("visible"),
        ];
        let real: Vec<PathBuf> = given.iter().map(|p| real_path(p)).collect();
        given.extend(real);
        given
    }
}

/// The name under `folder` that leads to `inside`, if `inside` is below it.
fn way_to(folder: &Path, inside: &Path) -> Option<PathBuf> {
    let below = inside.strip_prefix(folder).ok()?;
    below
        .components()
        .next()
        .map(|c| PathBuf::from(c.as_os_str()))
}

impl OwnProbes for BubblewrapProbes {
    fn refusal(&self) -> Refusal {
        Refusal::any_of(REFUSALS)
    }

    fn notes(&self) -> ReportNotes {
        NOTES
    }

    fn set_up(&mut self, layout: &Layout, name: &SandboxName, i: &ProbeInputs) -> Box<dyn Any> {
        self.given = Self::given(layout, name);
        let (facts, guard) = HostFacts::read(layout, name, i);
        self.facts = facts;
        guard
    }

    fn count_only(&mut self, layout: &Layout, name: &SandboxName, i: &ProbeInputs) {
        self.given = Self::given(layout, name);
        self.facts = HostFacts::counted(layout, name, i);
    }

    /// Closed when it reads no byte of a file, or no entry of a folder but
    /// those on the way to what the sandbox is given; its control reads at
    /// least one on the host.
    fn read(&self, route: &'static str, path: &Path) -> Probe {
        let count = match path.is_dir() {
            true => {
                let ways: String = self
                    .given
                    .iter()
                    .filter_map(|given| way_to(path, given))
                    .map(|way| format!(" | /usr/bin/grep -vxF -- {}", sh_quote(&way)))
                    .collect();
                format!(
                    "/bin/ls -A {} 2>/dev/null{ways} | /usr/bin/wc -l",
                    sh_quote(path)
                )
            }
            false => format!(
                "/usr/bin/head -c 1 {} 2>/dev/null | /usr/bin/wc -c",
                sh_quote(path)
            ),
        };
        let script = format!("test \"$({count})\" -gt 0");
        probe(
            route,
            format!("read {}", path.display()),
            script.clone(),
            Expect::Own(READS_NOTHING),
            script,
        )
    }

    /// The home and each workspace, whose parents are read-only, and the
    /// folders inside them that hold a mask, each a mount point.
    fn of_folder(&self, folder: &Path, i: &ProbeInputs) -> Vec<Probe> {
        let mut rename = calls::rename_beside(folder, i.tag);
        if *folder == i.home || i.workspaces.iter().any(|w| w == folder) {
            rename.route = "writable folders";
        }
        vec![rename]
    }

    fn folders(&self, i: &ProbeInputs) -> Vec<Probe> {
        vec![calls::remove_home(&i.home)]
    }

    fn folders_not_run(&self, i: &ProbeInputs) -> Vec<ProbeResult> {
        missing_workspaces(i)
    }

    fn network(&self, _i: &ProbeInputs) -> Vec<Probe> {
        let mut list: Vec<Probe> = self
            .facts
            .loopback_target
            .map(calls::connect_loopback)
            .into_iter()
            .collect();
        list.push(calls::vsock());
        list
    }

    fn dns(&self, _i: &ProbeInputs) -> Vec<Probe> {
        vec![same_outside(
            "dns",
            "look a name up through the host's resolver",
            "/usr/bin/getent hosts example.com >/dev/null",
        )]
    }

    fn before_limits(&self, i: &ProbeInputs) -> Vec<Probe> {
        let mut list = self.services();
        list.extend(self.sockets());
        list.extend(self.processes(i));
        for secrets in i.other_sandboxes.iter().map(|dir| dir.join("secrets")) {
            if secrets.exists() {
                list.push(self.read("other sandboxes", &secrets));
            }
        }
        list.push(calls::tiocsti());
        list.extend(self.privileges(i));
        if let Ok(procs) = &self.facts.manager_procs {
            // A write the read-only mount refuses at once; the session's
            // cgroup namespace would refuse it next (ENOENT).
            list.push(probe(
                "cgroup",
                "move a process out of its session's cgroup",
                format!("echo $$ > {}", sh_quote(procs)),
                Expect::FailsWith(Refusal::any_of(&["Read-only file system"])),
                format!("test -w {}", sh_quote(procs)),
            ));
        }
        list
    }

    fn not_here(&self, i: &ProbeInputs) -> Vec<String> {
        let facts = &self.facts;
        let mut absent = Vec::new();
        let mut missing = |there: bool, what: &str| {
            if !there {
                absent.push(what.to_owned());
            }
        };
        missing(
            facts.session_bus.is_some(),
            "the session bus (no address for it here)",
        );
        missing(
            facts.system_bus.is_some(),
            "the system bus (no socket here)",
        );
        missing(
            facts.runtime_dir.is_some(),
            "the `systemd --user` manager (no runtime folder here)",
        );
        missing(
            facts.abstract_target.is_some() && facts.loopback_target.is_some(),
            "a listener of enclos's own on the host (it could not listen)",
        );
        missing(
            !i.other_sandboxes.is_empty() && !facts.other_processes.is_empty(),
            "another sandbox's start-up environment (none of its processes runs here)",
        );
        missing(
            Numbers::here().is_some(),
            "ptrace, a user namespace and mounting (enclos does not know this architecture's system calls)",
        );
        for (program, route) in [
            (PASSWD, "a setuid program"),
            (CRONTAB_PROGRAM, "crontab"),
            (ATQ, "at"),
        ] {
            missing(
                Path::new(program).exists(),
                &format!("{route} ({program} is not installed here)"),
            );
        }
        if let Err(why) = &facts.manager_procs {
            absent.push(format!("the session's cgroup ({why})"));
        }
        absent
    }
}

const PASSWD: &str = "/usr/bin/passwd";
const CRONTAB_PROGRAM: &str = "/usr/bin/crontab";
const ATQ: &str = "/usr/bin/atq";

impl BubblewrapProbes {
    /// The buses and the user's manager, each through its own client, at
    /// the address the host has.
    fn services(&self) -> Vec<Probe> {
        let facts = &self.facts;
        let quoted = |text: &str| sh_quote(Path::new(text));
        let mut list = Vec::new();
        if let Some(address) = &facts.session_bus {
            list.push(same_outside(
                "session bus",
                "list the names on the session bus",
                &format!(
                    "DBUS_SESSION_BUS_ADDRESS={} /usr/bin/busctl --user --no-pager list >/dev/null 2>&1",
                    quoted(address)
                ),
            ));
        }
        if let Some(socket) = &facts.system_bus {
            list.push(same_outside(
                "system bus",
                "list the names on the system bus",
                &format!(
                    "DBUS_SYSTEM_BUS_ADDRESS={} /usr/bin/busctl --system --no-pager list >/dev/null 2>&1",
                    quoted(&format!("unix:path={}", socket.display()))
                ),
            ));
        }
        if let Some(dir) = &facts.runtime_dir {
            list.push(same_outside(
                "systemd --user",
                "ask the user's systemd manager for its version",
                &format!(
                    "XDG_RUNTIME_DIR={} /usr/bin/systemctl --user --no-pager show --property=Version >/dev/null 2>&1",
                    sh_quote(dir)
                ),
            ));
        }
        list
    }

    /// Every Unix socket that answers the user on the host, enclos's own
    /// abstract one, and those listening in the other sandboxes' network
    /// namespaces.
    fn sockets(&self) -> Vec<Probe> {
        let facts = &self.facts;
        let mut list = Vec::new();
        for socket in &facts.sockets {
            let shown = socket.address.shown();
            let route = match socket.address {
                Address::Path(_) => "host sockets",
                Address::Abstract(_) => "abstract sockets",
            };
            list.push(calls::connect_to(
                route,
                format!("connect to {shown}"),
                &shown,
                socket.kind,
            ));
        }
        if let Some(name) = &facts.abstract_target {
            list.push(calls::connect_to(
                "abstract sockets",
                format!("connect to @{name}, where enclos listens on the host"),
                &format!("@{name}"),
                1,
            ));
        }
        for other in &facts.other_sockets {
            let shown = other.socket.address.shown();
            let name = format!("connect to {shown}, of sandbox {}", other.sandbox);
            list.push(match other.socket.address {
                Address::Path(_) => {
                    calls::connect_to("other sandboxes", name, &shown, other.socket.kind)
                }
                Address::Abstract(_) => {
                    calls::connect_elsewhere(name, &shown, other.socket.kind, &other.table)
                }
            });
        }
        list
    }

    /// The process the host started for the signal probe and the other
    /// sandboxes' processes: attaching to one, and reading the start-up
    /// environment of each, which the host reads.
    fn processes(&self, i: &ProbeInputs) -> Vec<Probe> {
        let mut list = Vec::new();
        let Some(target) = i.target else {
            return list;
        };
        if let Some(numbers) = Numbers::here() {
            list.push(numbers.ptrace(target));
        }
        list.push(environment_probe(
            "read the start-up environment of a process outside the sandbox",
            target,
            &format!("{TARGET_VARIABLE}=1"),
        ));
        for other in &self.facts.other_processes {
            list.push(environment_probe(
                &format!(
                    "read the start-up environment of a process of sandbox {}",
                    other.sandbox
                ),
                other.pid,
                &format!(
                    "{}={}",
                    crate::backend::environment::SANDBOX_VARIABLE,
                    other.sandbox
                ),
            ));
        }
        list
    }

    /// Programs that would act with more than the user's rights, and the
    /// calls that make a namespace or a mount.
    fn privileges(&self, i: &ProbeInputs) -> Vec<Probe> {
        let mut list = Vec::new();
        let itself = |mut probe: Probe| {
            probe.closed_by = Some(ITSELF);
            probe
        };
        if Path::new(PASSWD).exists() {
            list.push(itself(same_outside(
                "setuid",
                "run a setuid program, passwd -S",
                &format!("{PASSWD} -S >/dev/null 2>&1"),
            )));
        }
        if Path::new(CRONTAB_PROGRAM).exists() {
            list.push(itself(probe(
                "crontab",
                "read the crontab",
                format!("{CRONTAB_PROGRAM} -l 2>&1 >/dev/null"),
                Expect::Own(CRONTAB),
                format!(
                    "{CRONTAB_PROGRAM} -l >/dev/null 2>&1 || {CRONTAB_PROGRAM} -l 2>&1 | /usr/bin/grep -q 'no crontab for'"
                ),
            )));
        }
        if Path::new(ATQ).exists() {
            list.push(itself(same_outside(
                "at",
                "list the `at` queue",
                &format!("{ATQ} >/dev/null 2>&1"),
            )));
        }
        if let Some(numbers) = Numbers::here() {
            list.push(numbers.user_namespace());
            list.push(numbers.mount(&PathBuf::from(format!("/enclos-probe-{}-missing", i.tag))));
        }
        list
    }
}

/// Reads the start-up environment of process `pid`, closed when `line` is
/// not in what it read; its control finds the line on the host. A pid the
/// session's own PID namespace happens to hold is another process, without
/// that line.
fn environment_probe(name: &str, pid: u32, line: &str) -> Probe {
    same_outside(
        "environment",
        name,
        &format!(
            "/usr/bin/tr '\\0' '\\n' < /proc/{pid}/environ | /usr/bin/grep -qxF -- {}",
            sh_quote(Path::new(line))
        ),
    )
}
