//! What bubblewrap's probes aim at on the host, read as the test starts:
//! the buses and the user's manager, every Unix socket that answers this
//! user, the processes and sockets of the other sandboxes, and two
//! listeners of enclos's own, which the guard [`HostFacts::read`] returns
//! holds until the test ends.

use std::any::Any;
use std::collections::BTreeMap;
use std::path::PathBuf;

use super::sockets::{self, Address, Socket};
use crate::backend::environment::SANDBOX_VARIABLE;
use crate::layout::Layout;
use crate::model::sandbox::SandboxName;
use crate::policy::paths::is_within;
use crate::probes::ProbeInputs;

/// Where Debian and Ubuntu put the system bus's socket.
pub(super) const SYSTEM_BUS: &str = "/run/dbus/system_bus_socket";

/// A process of another sandbox, which its start-up environment names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct OtherProcess {
    pub sandbox: String,
    pub pid: u32,
}

/// A socket listening in another sandbox's network namespace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct OtherSocket {
    pub sandbox: String,
    pub socket: Socket,
    /// That namespace's table, in its namespace holder's `/proc`.
    pub table: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct HostFacts {
    /// The user's runtime folder, where the user's manager and session bus
    /// listen.
    pub runtime_dir: Option<PathBuf>,
    /// The session bus's address.
    pub session_bus: Option<String>,
    /// The system bus's socket, when it is there.
    pub system_bus: Option<PathBuf>,
    /// The Unix sockets listening on the host that answer this user, less
    /// those the sandbox is given or the shared probes try.
    pub sockets: Vec<Socket>,
    /// The abstract socket enclos listens on for the test.
    pub abstract_target: Option<String>,
    /// The port enclos listens on at the host's 127.0.0.1 for the test.
    pub loopback_target: Option<u16>,
    /// A process of each other sandbox that runs one.
    pub other_processes: Vec<OtherProcess>,
    /// The sockets listening in the other sandboxes' network namespaces.
    pub other_sockets: Vec<OtherSocket>,
    /// The `cgroup.procs` of the user's manager, or why systemd did not say
    /// where it is.
    pub manager_procs: Result<PathBuf, String>,
}

impl Default for HostFacts {
    fn default() -> HostFacts {
        HostFacts {
            runtime_dir: None,
            session_bus: None,
            system_bus: None,
            sockets: Vec::new(),
            abstract_target: None,
            loopback_target: None,
            other_processes: Vec::new(),
            other_sockets: Vec::new(),
            manager_procs: Err("not looked for".to_owned()),
        }
    }
}

impl HostFacts {
    /// Read from this host for the probes of sandbox `name`, built from
    /// `i`, with enclos's two listeners, which the guard returned holds.
    pub fn read(layout: &Layout, name: &SandboxName, i: &ProbeInputs) -> (HostFacts, Box<dyn Any>) {
        let (abstract_target, loopback_target, guard) = listen(i.tag);
        let mut facts = HostFacts::buses();
        facts.sockets = host_sockets(layout, name, i, abstract_target.as_deref(), answers);
        facts.abstract_target = abstract_target;
        facts.loopback_target = loopback_target;
        facts.other_processes = other_processes(i);
        facts.other_sockets = other_sockets(layout, i);
        facts.manager_procs = crate::lifecycle::cgroup::manager_procs().map_err(|e| e.to_string());
        (facts, guard)
    }

    /// What a dry run counts with, asking nothing: stand-ins for enclos's
    /// listeners and the manager's cgroup, every listening socket listed
    /// whether or not it answers, and no other sandbox's process or socket.
    pub fn counted(layout: &Layout, name: &SandboxName, i: &ProbeInputs) -> HostFacts {
        let target = format!("enclos-probe-{}", i.tag);
        let mut facts = HostFacts::buses();
        facts.sockets = host_sockets(layout, name, i, Some(&target), |_| true);
        facts.abstract_target = Some(target);
        facts.loopback_target = Some(0);
        facts.manager_procs = Ok(PathBuf::from("/sys/fs/cgroup/cgroup.procs"));
        facts
    }

    /// The runtime folder and the buses, from this process's environment
    /// and where the host keeps them.
    fn buses() -> HostFacts {
        let uid = rustix::process::getuid().as_raw();
        let runtime_dir = std::env::var_os("XDG_RUNTIME_DIR")
            .filter(|dir| !dir.is_empty())
            .map(PathBuf::from)
            .or_else(|| Some(PathBuf::from(format!("/run/user/{uid}"))).filter(|d| d.is_dir()));
        let session_bus = std::env::var("DBUS_SESSION_BUS_ADDRESS")
            .ok()
            .filter(|address| !address.is_empty())
            .or_else(|| {
                let bus = runtime_dir.as_ref()?.join("bus");
                bus.exists().then(|| format!("unix:path={}", bus.display()))
            });
        HostFacts {
            runtime_dir,
            session_bus,
            system_bus: Some(PathBuf::from(SYSTEM_BUS)).filter(|bus| bus.exists()),
            ..HostFacts::default()
        }
    }
}

/// The sockets listening on the host that `keep` keeps, but the sandbox's
/// own: its proxy's, its only way out, and those inside what it may write,
/// which are its own; and but the ones the shared probes try, and enclos's
/// abstract `target`, which has a probe of its own.
fn host_sockets(
    layout: &Layout,
    name: &SandboxName,
    i: &ProbeInputs,
    target: Option<&str>,
    keep: impl Fn(&Socket) -> bool,
) -> Vec<Socket> {
    let Ok(table) = std::fs::read_to_string("/proc/net/unix") else {
        return Vec::new();
    };
    let own_proxy = layout.proxy_socket(name.as_str());
    sockets::listening(&table)
        .into_iter()
        .filter(|s| match &s.address {
            Address::Path(path) => {
                *path != own_proxy
                    && !i.host_sockets.contains(path)
                    && !i.writes.iter().any(|w| is_within(path, w))
            }
            Address::Abstract(name) => Some(name.as_str()) != target,
        })
        .filter(|s| keep(s))
        .collect()
}

/// The first process found of each other sandbox, by the variable that
/// names its sandbox in its start-up environment, as the host reads it.
fn other_processes(i: &ProbeInputs) -> Vec<OtherProcess> {
    let names: Vec<&str> = i
        .other_sandboxes
        .iter()
        .filter_map(|dir| dir.file_name()?.to_str())
        .collect();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };
    let prefix = format!("{SANDBOX_VARIABLE}=");
    let mut found: BTreeMap<String, u32> = BTreeMap::new();
    for entry in entries.flatten() {
        let Some(pid) = entry.file_name().to_str().and_then(|p| p.parse().ok()) else {
            continue;
        };
        let Ok(environ) = std::fs::read(entry.path().join("environ")) else {
            continue;
        };
        let named = environ
            .split(|b| *b == 0)
            .filter_map(|var| std::str::from_utf8(var).ok()?.strip_prefix(&prefix))
            .find(|sandbox| names.contains(sandbox));
        if let Some(sandbox) = named {
            found.entry(sandbox.to_owned()).or_insert(pid);
        }
    }
    found
        .into_iter()
        .map(|(sandbox, pid)| OtherProcess { sandbox, pid })
        .collect()
}

/// The sockets listening in each other sandbox's network namespace, from
/// the table of its namespace holder, where one answers.
#[cfg(target_os = "linux")]
fn other_sockets(layout: &Layout, i: &ProbeInputs) -> Vec<OtherSocket> {
    let mut found = Vec::new();
    for dir in &i.other_sandboxes {
        let Some(sandbox) = dir.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let holder = layout.holder_socket(sandbox);
        if !holder.exists() {
            continue;
        }
        // Its namespaces are closed at once: only its pid is needed.
        let Ok(answer) = super::super::holder::ask(&holder) else {
            continue;
        };
        let table = PathBuf::from(format!("/proc/{}/net/unix", answer.pid));
        let Ok(text) = std::fs::read_to_string(&table) else {
            continue;
        };
        found.extend(
            sockets::listening(&text)
                .into_iter()
                .map(|socket| OtherSocket {
                    sandbox: sandbox.to_owned(),
                    socket,
                    table: table.clone(),
                }),
        );
    }
    found
}

#[cfg(not(target_os = "linux"))]
fn other_sockets(_layout: &Layout, _i: &ProbeInputs) -> Vec<OtherSocket> {
    Vec::new()
}

#[cfg(target_os = "linux")]
fn answers(socket: &Socket) -> bool {
    sockets::answers(socket)
}

#[cfg(not(target_os = "linux"))]
fn answers(_socket: &Socket) -> bool {
    false
}

/// enclos's two listeners on the host, where it can make them: an abstract
/// Unix socket, `enclos-probe-<tag>`, and a TCP port on 127.0.0.1 outside
/// the proxies' range, which a sandbox's own relay may hold in its
/// namespace. Neither ever accepts: a connection waits in its backlog until
/// the guard drops them.
#[cfg(target_os = "linux")]
fn listen(tag: u32) -> (Option<String>, Option<u16>, Box<dyn Any>) {
    use crate::model::sandbox::{PORT_FIRST, PORT_LAST};
    use std::net::{Ipv4Addr, TcpListener};
    use std::os::linux::net::SocketAddrExt;
    use std::os::unix::net::{SocketAddr, UnixListener};
    let name = format!("enclos-probe-{tag}");
    let unix = SocketAddr::from_abstract_name(name.as_bytes())
        .and_then(|address| UnixListener::bind_addr(&address))
        .ok();
    let tcp = (0..64)
        .filter_map(|_| TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).ok())
        .find(|l| {
            l.local_addr()
                .is_ok_and(|a| !(PORT_FIRST..=PORT_LAST).contains(&a.port()))
        });
    let port = tcp
        .as_ref()
        .and_then(|l| l.local_addr().ok())
        .map(|a| a.port());
    let name = unix.as_ref().map(|_| name);
    (name, port, Box::new((unix, tcp)))
}

#[cfg(not(target_os = "linux"))]
fn listen(_tag: u32) -> (Option<String>, Option<u16>, Box<dyn Any>) {
    (None, None, Box::new(()))
}
