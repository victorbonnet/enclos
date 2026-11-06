//! How enclos looks at processes on Linux: from `/proc`, with no `unsafe`
//! code (ADR 0012). Markers' holders and listeners come from each process's
//! descriptors (`descriptors`) and network tables (`net`), the ephemeral
//! ports from `ip_local_port_range`. `lsof` gives the same on macOS;
//! `lifecycle` picks one of the two as `host`.

mod net;

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};

use super::descriptors::{self, Descriptors, PROC};
use super::listeners::ListenersError;
use super::marker::{Held, MarkerError};

/// The TCP addresses each of `pids` listens on, with the pid that holds it,
/// each read in its own network namespace.
pub fn tcp_listeners_of(pids: &[u32]) -> Result<Vec<(u32, SocketAddr)>, ListenersError> {
    listeners_of_under(Path::new(PROC), pids, Tables::Own)
}

/// Every process `/proc` shows listening on TCP at 127.0.0.1 port `port`,
/// in this process's network namespace.
pub fn tcp_listeners_at(port: u16) -> Result<Vec<(u32, SocketAddr)>, ListenersError> {
    listeners_at_under(Path::new(PROC), port, Tables::Own)
}

/// The TCP addresses each of `pids` listens on in the network namespace of
/// `namespace`, a process in it, with the pid that holds it: a socket of
/// theirs outside that namespace is not one.
pub fn tcp_listeners_in(
    namespace: u32,
    pids: &[u32],
) -> Result<Vec<(u32, SocketAddr)>, ListenersError> {
    listeners_of_under(Path::new(PROC), pids, Tables::Of(namespace))
}

/// Every process `/proc` shows listening on TCP at 127.0.0.1 port `port` in
/// the network namespace of `namespace`, a process in it.
pub fn tcp_listeners_at_in(
    namespace: u32,
    port: u16,
) -> Result<Vec<(u32, SocketAddr)>, ListenersError> {
    listeners_at_under(Path::new(PROC), port, Tables::Of(namespace))
}

/// The program that `root` started in a PID namespace of its own: the
/// process below it numbered 2 there, the first that the namespace's first
/// process started. Under bubblewrap, `root` is bubblewrap's outer process,
/// the namespace's first is `enclos inside`, and the second is the
/// session's command (`inside::command`). None when no such process runs,
/// as before the command starts.
pub fn program_in_pid_namespace(root: u32) -> Result<Option<u32>, ListenersError> {
    program_under(Path::new(PROC), root)
}

/// Whether processes `a` and `b` are in the same network namespace. An
/// error when either cannot be read, as when it is gone.
pub fn same_network(a: u32, b: u32) -> Result<bool, ListenersError> {
    same_network_under(Path::new(PROC), a, b)
}

/// The user owning the socket at `client` connected to `server`, both
/// TCP addresses in this process's network namespace, from the kernel's
/// tables: none unless they give exactly one, as when the client has closed
/// its end already. A table that cannot be read is an error; `tcp6` is
/// missing on a kernel without IPv6.
pub fn tcp_client_owner(
    client: SocketAddr,
    server: SocketAddr,
) -> Result<Option<u32>, ListenersError> {
    let net = Path::new(PROC).join("self/net");
    let mut tables = Vec::new();
    for table in ["tcp", "tcp6"] {
        let path = net.join(table);
        match std::fs::read_to_string(&path) {
            Ok(text) => tables.push(text),
            Err(e) if table == "tcp6" && e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(proc_error(format!("{}: {e}", path.display()))),
        }
    }
    Ok(net::client_owner(&tables, client, server))
}

/// The first and last port the system picks from for a bind on port 0.
pub fn ephemeral_ports() -> Result<(u16, u16), String> {
    let path = "/proc/sys/net/ipv4/ip_local_port_range";
    let text = std::fs::read_to_string(path).map_err(|e| format!("cannot read {path}: {e}"))?;
    net::port_range(&text).ok_or_else(|| format!("{path} gave `{}`", text.trim()))
}

/// The processes holding each named marker in `dir`, whose `entries` are
/// what the folder shows now.
pub fn marker_holders(dir: &Path, entries: std::fs::ReadDir) -> Result<Held, MarkerError> {
    marker_holders_under(Path::new(PROC), dir, entries)
}

/// The command that names the program listening at `port`.
pub fn port_holders_command(port: u16) -> String {
    format!("ss -ltnp sport = :{port}")
}

fn proc_error(e: impl std::fmt::Display) -> ListenersError {
    ListenersError::Proc(e.to_string())
}

/// The listening sockets `pid` sees, under `proc`: through its own folder, or
/// through a thread's when its main thread exited and others run on. `None`
/// only when no thread answers, so the process is gone.
fn tables_of(proc: &Path, pid: u32) -> Result<Option<BTreeMap<u64, SocketAddr>>, ListenersError> {
    if let Some(sockets) = net::listening_sockets(&proc.join(pid.to_string()).join("net"))? {
        return Ok(Some(sockets));
    }
    for thread in descriptors::other_threads(proc, pid).map_err(proc_error)? {
        if let Some(sockets) = net::listening_sockets(&thread.join("net"))? {
            return Ok(Some(sockets));
        }
    }
    Ok(None)
}

/// The inode of a descriptor's target, when it is a socket.
fn socket_inode(target: &Path) -> Option<u64> {
    target
        .to_str()?
        .strip_prefix("socket:[")?
        .strip_suffix(']')?
        .parse()
        .ok()
}

/// Which network tables a look reads.
#[derive(Debug, Clone, Copy)]
enum Tables {
    /// Each process's own, so a process in another network namespace is
    /// read in its own; this process's for a look at a port.
    Own,
    /// Those of the network namespace this process is in.
    Of(u32),
}

/// What `pids` listen on, under `proc`, in the network tables `tables` says.
fn listeners_of_under(
    proc: &Path,
    pids: &[u32],
    tables: Tables,
) -> Result<Vec<(u32, SocketAddr)>, ListenersError> {
    let namespace = match tables {
        Tables::Own => None,
        Tables::Of(namespace) => Some(namespace_tables(proc, namespace)?),
    };
    let mut found = BTreeSet::new();
    for &pid in pids {
        let own;
        let sockets = match &namespace {
            Some(sockets) => sockets,
            None => match tables_of(proc, pid)? {
                Some(sockets) => {
                    own = sockets;
                    &own
                }
                None => continue,
            },
        };
        match descriptors::of(proc, pid).map_err(proc_error)? {
            Descriptors::Open(open) => found.extend(
                open.iter()
                    .filter_map(|d| sockets.get(&socket_inode(&d.target)?))
                    .map(|addr| (pid, *addr)),
            ),
            Descriptors::Gone => {}
            // It exited since its tables were read, or it is one that cannot
            // be read: a look that could not happen is not "no listener".
            Descriptors::Unreadable if tables_of(proc, pid)?.is_none() => {}
            Descriptors::Unreadable => {
                return Err(proc_error(format!("pid {pid} cannot be read")));
            }
        }
    }
    Ok(found.into_iter().collect())
}

/// The listening sockets of the network namespace `namespace` is in; an
/// error when it is gone, as nothing else shows that namespace's tables.
fn namespace_tables(
    proc: &Path,
    namespace: u32,
) -> Result<BTreeMap<u64, SocketAddr>, ListenersError> {
    tables_of(proc, namespace)?.ok_or_else(|| {
        proc_error(format!(
            "pid {namespace}, whose network namespace was to be read, is gone"
        ))
    })
}

/// Every process under `proc` listening at 127.0.0.1 port `port`, in this
/// process's network namespace, or the one `tables` names.
fn listeners_at_under(
    proc: &Path,
    port: u16,
    tables: Tables,
) -> Result<Vec<(u32, SocketAddr)>, ListenersError> {
    let at = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let listening = || {
        let sockets = match tables {
            Tables::Own => {
                let net: PathBuf = proc.join("self").join("net");
                net::listening_sockets(&net)?
                    .ok_or_else(|| proc_error(format!("{} shows no TCP table", net.display())))?
            }
            Tables::Of(namespace) => namespace_tables(proc, namespace)?,
        };
        Ok(sockets
            .into_iter()
            .filter_map(|(inode, addr)| (addr == at).then_some(inode))
            .collect())
    };
    let held = || {
        let processes = descriptors::every_process(proc).map_err(proc_error)?;
        Ok(processes
            .into_iter()
            .map(|(pid, open)| {
                let sockets = open.iter().filter_map(|d| socket_inode(&d.target));
                (pid, sockets.collect())
            })
            .collect())
    };
    holders_among(at, listening, held)
}

/// A process's parent and its pid in each PID namespace from `proc`'s down
/// to its own, from the `PPid` and `NSpid` lines of its `status`.
fn parse_status(text: &str) -> Option<(u32, Vec<u32>)> {
    let field = |name: &str| {
        text.lines()
            .find_map(|line| line.strip_prefix(name)?.strip_prefix(':'))
            .map(str::trim)
    };
    let parent = field("PPid")?.parse().ok()?;
    let pids = field("NSpid")?
        .split_whitespace()
        .map(|word| word.parse().ok())
        .collect::<Option<Vec<u32>>>()?;
    (!pids.is_empty()).then_some((parent, pids))
}

/// What [`parse_status`] reads of every process under `proc`, by pid. A
/// process that exits meanwhile is left out.
fn lineages(proc: &Path) -> Result<BTreeMap<u32, (u32, Vec<u32>)>, ListenersError> {
    let mut found = BTreeMap::new();
    for entry in std::fs::read_dir(proc).map_err(proc_error)? {
        let entry = entry.map_err(proc_error)?;
        let Some(pid) = entry.file_name().to_str().and_then(|n| n.parse().ok()) else {
            continue;
        };
        let status = entry.path().join("status");
        let text = match std::fs::read_to_string(&status) {
            Ok(text) => text,
            Err(e) if descriptors::is_gone(&e) => continue,
            Err(e) => return Err(proc_error(format!("{}: {e}", status.display()))),
        };
        let lineage = parse_status(&text)
            .ok_or_else(|| proc_error(format!("{} does not read", status.display())))?;
        found.insert(pid, lineage);
    }
    Ok(found)
}

fn program_under(proc: &Path, root: u32) -> Result<Option<u32>, ListenersError> {
    let every = lineages(proc)?;
    let Some((_, root_pids)) = every.get(&root) else {
        return Ok(None);
    };
    // One PID namespace below the root's, numbered `inside` there.
    let below = |parent: u32, inside: u32| {
        every.iter().filter_map(move |(pid, (ppid, pids))| {
            let nested = pids.len() == root_pids.len() + 1 && pids.last() == Some(&inside);
            (*ppid == parent && nested).then_some(*pid)
        })
    };
    Ok(below(root, 1).find_map(|first| below(first, 2).next()))
}

fn same_network_under(proc: &Path, a: u32, b: u32) -> Result<bool, ListenersError> {
    let namespace = |pid: u32| {
        let link = proc.join(pid.to_string()).join("ns/net");
        std::fs::read_link(&link).map_err(|e| proc_error(format!("{}: {e}", link.display())))
    };
    Ok(namespace(a)? == namespace(b)?)
}

/// The processes `held`, each with its sockets, that hold a socket `listening`
/// gives at `at`. A socket no process shown holds, and that still listens
/// after the look, is a process that cannot be read: a look that could not
/// happen is not a port with fewer holders.
fn holders_among(
    at: SocketAddr,
    listening: impl Fn() -> Result<BTreeSet<u64>, ListenersError>,
    held: impl FnOnce() -> Result<Vec<(u32, BTreeSet<u64>)>, ListenersError>,
) -> Result<Vec<(u32, SocketAddr)>, ListenersError> {
    let sockets = listening()?;
    if sockets.is_empty() {
        return Ok(Vec::new());
    }
    let mut found = BTreeSet::new();
    let mut matched = BTreeSet::new();
    for (pid, open) in held()? {
        let shared: Vec<u64> = open.intersection(&sockets).copied().collect();
        if !shared.is_empty() {
            found.insert((pid, at));
            matched.extend(shared);
        }
    }
    let unmatched: BTreeSet<u64> = sockets.difference(&matched).copied().collect();
    if !unmatched.is_empty() && !unmatched.is_disjoint(&listening()?) {
        return Err(proc_error(format!(
            "a listener at {at} belongs to a process that cannot be read"
        )));
    }
    Ok(found.into_iter().collect())
}

/// The processes under `proc` holding each named marker in `dir`, whose
/// `entries` are what the folder shows now: as with `lsof +d`, a file already
/// removed from it is not listed, and a process working in it holds nothing.
fn marker_holders_under(
    proc: &Path,
    dir: &Path,
    entries: std::fs::ReadDir,
) -> Result<Held, MarkerError> {
    let folder_error = |e: io::Error| MarkerError::Folder(format!("{}: {e}", dir.display()));
    let mut markers = BTreeSet::new();
    for entry in entries {
        if let Some(name) = entry.map_err(folder_error)?.file_name().to_str()
            && name.starts_with("root-")
        {
            markers.insert(name.to_owned());
        }
    }
    let mut held = Held::new();
    if markers.is_empty() {
        return Ok(held);
    }
    // `/proc` writes real paths, and `dir` may not be one.
    let real = dir.canonicalize().map_err(folder_error)?;
    let processes =
        descriptors::every_process(proc).map_err(|e| MarkerError::Proc(e.to_string()))?;
    for (pid, open) in processes {
        for descriptor in open {
            let target = &descriptor.target;
            if target.parent() == Some(real.as_path())
                && let Some(name) = target.file_name().and_then(|n| n.to_str())
                && markers.contains(name)
                && descriptor
                    .opens()
                    .map_err(|e| MarkerError::Proc(e.to_string()))?
            {
                held.entry(name.to_owned()).or_default().insert(pid);
            }
        }
    }
    Ok(held)
}

#[cfg(test)]
mod tests;
