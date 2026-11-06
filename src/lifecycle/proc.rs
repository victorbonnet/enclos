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

/// The TCP addresses each of `pids` listens on, with the pid that holds it.
pub fn tcp_listeners_of(pids: &[u32]) -> Result<Vec<(u32, SocketAddr)>, ListenersError> {
    listeners_of_under(Path::new(PROC), pids)
}

/// Every process `/proc` shows listening on TCP at 127.0.0.1 port `port`.
pub fn tcp_listeners_at(port: u16) -> Result<Vec<(u32, SocketAddr)>, ListenersError> {
    listeners_at_under(Path::new(PROC), port)
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

/// What `pids` listen on, under `proc`. Each is read through its own network
/// tables, so a process in another network namespace is read in its own.
fn listeners_of_under(proc: &Path, pids: &[u32]) -> Result<Vec<(u32, SocketAddr)>, ListenersError> {
    let mut found = BTreeSet::new();
    for &pid in pids {
        let Some(sockets) = tables_of(proc, pid)? else {
            continue;
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

/// Every process under `proc` listening at 127.0.0.1 port `port`, in this
/// process's network namespace.
fn listeners_at_under(proc: &Path, port: u16) -> Result<Vec<(u32, SocketAddr)>, ListenersError> {
    let at = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let net: PathBuf = proc.join("self").join("net");
    let listening = || {
        let sockets = net::listening_sockets(&net)?
            .ok_or_else(|| proc_error(format!("{} shows no TCP table", net.display())))?;
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
