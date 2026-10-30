//! The TCP listeners a process holds, through `lsof` on macOS and `/proc` on
//! Linux, with no `unsafe` code (ADR 0012). enclos uses them to find a runtime
//! service's listener (ADR 0028): from the process enclos started for the
//! service, never from a file the sandbox writes.
//!
//! A look that fails is an error, never an empty answer, so "no listener" is
//! only ever what `lsof` or `/proc` said.

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::ops::RangeInclusive;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use super::descriptors::{self, Descriptors};

/// The listeners could not be told.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ListenersError {
    /// `lsof` could not answer.
    #[error("cannot look at listening sockets with /usr/sbin/lsof: {0}")]
    Lsof(String),
    /// `/proc` could not be read.
    #[error("cannot look at listening sockets in /proc: {0}")]
    Proc(String),
}

/// The TCP addresses `pid` listens on. A wildcard address (`*`, IPv4 or
/// IPv6) is given as `0.0.0.0`.
pub fn tcp_listeners(pid: u32) -> Result<Vec<SocketAddr>, ListenersError> {
    Ok(tcp_listeners_of(&[pid])?
        .into_iter()
        .map(|(_, addr)| addr)
        .collect())
}

/// The TCP addresses each of `pids` listens on, with the pid that holds it,
/// in one look. A process that is gone holds none.
pub fn tcp_listeners_of(pids: &[u32]) -> Result<Vec<(u32, SocketAddr)>, ListenersError> {
    if pids.is_empty() {
        return Ok(Vec::new());
    }
    if !cfg!(target_os = "macos") {
        return held_in_proc(Path::new(descriptors::PROC), pids);
    }
    let list = pids
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(",");
    lsof(&["-a", "-p", &list, "-iTCP", "-sTCP:LISTEN"])
}

/// Every process, of those `lsof` or `/proc` can show (the user's), that
/// listens on TCP at 127.0.0.1 port `port`, with the address it holds.
/// Another user's process cannot bind a port the user's holds, so the user's
/// are the ones that matter.
pub fn tcp_listeners_at(port: u16) -> Result<Vec<(u32, SocketAddr)>, ListenersError> {
    if !cfg!(target_os = "macos") {
        return holders_in_proc(Path::new(descriptors::PROC), port);
    }
    lsof(&[&format!("-iTCP@127.0.0.1:{port}"), "-sTCP:LISTEN"])
}

fn lsof(select: &[&str]) -> Result<Vec<(u32, SocketAddr)>, ListenersError> {
    let out = Command::new("/usr/sbin/lsof")
        .env("LC_ALL", "C")
        .arg("-nP")
        .args(select)
        .arg("-Fn")
        .stdin(Stdio::null())
        .output()
        .map_err(|e| ListenersError::Lsof(e.to_string()))?;
    listening(&out)
}

fn proc_error(e: impl std::fmt::Display) -> ListenersError {
    ListenersError::Proc(e.to_string())
}

/// The listening sockets in the network tables `net` holds, by inode.
/// `tcp6` is missing on a kernel without IPv6; `tcp` missing means the
/// process is gone (a zombie has no network tables), so `None`.
fn listening_sockets(net: &Path) -> Result<Option<BTreeMap<u64, SocketAddr>>, ListenersError> {
    let read = |table: &str| match std::fs::read_to_string(net.join(table)) {
        Ok(text) => Ok(Some(text)),
        Err(e) if descriptors::is_gone(&e) => Ok(None),
        Err(e) => Err(proc_error(format!("{}: {e}", net.join(table).display()))),
    };
    let Some(v4) = read("tcp")? else {
        return Ok(None);
    };
    let mut sockets = parse_table(&v4)?;
    if let Some(v6) = read("tcp6")? {
        sockets.extend(parse_table(&v6)?);
    }
    Ok(Some(sockets))
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
fn held_in_proc(proc: &Path, pids: &[u32]) -> Result<Vec<(u32, SocketAddr)>, ListenersError> {
    let mut found = BTreeSet::new();
    for &pid in pids {
        let net = proc.join(pid.to_string()).join("net");
        let Some(sockets) = listening_sockets(&net)? else {
            continue;
        };
        match descriptors::of(proc, pid).map_err(proc_error)? {
            Descriptors::Open(open) => found.extend(
                open.iter()
                    .filter_map(|t| sockets.get(&socket_inode(t)?))
                    .map(|addr| (pid, *addr)),
            ),
            Descriptors::Gone => {}
            // It exited since its tables were read, or it is one that cannot
            // be read: a look that could not happen is not "no listener".
            Descriptors::Unreadable if listening_sockets(&net)?.is_none() => {}
            Descriptors::Unreadable => {
                return Err(proc_error(format!("pid {pid} cannot be read")));
            }
        }
    }
    Ok(found.into_iter().collect())
}

/// Every process under `proc` that this user can read listening at
/// 127.0.0.1 port `port`, in this process's network namespace.
fn holders_in_proc(proc: &Path, port: u16) -> Result<Vec<(u32, SocketAddr)>, ListenersError> {
    let at = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let net: PathBuf = proc.join("self").join("net");
    let sockets = listening_sockets(&net)?
        .ok_or_else(|| proc_error(format!("{} shows no TCP table", net.display())))?;
    let sockets: BTreeSet<u64> = sockets
        .into_iter()
        .filter_map(|(inode, addr)| (addr == at).then_some(inode))
        .collect();
    if sockets.is_empty() {
        return Ok(Vec::new());
    }
    let mut found = BTreeSet::new();
    for (pid, open) in descriptors::every_process(proc).map_err(proc_error)? {
        if open
            .iter()
            .filter_map(|t| socket_inode(t))
            .any(|inode| sockets.contains(&inode))
        {
            found.insert((pid, at));
        }
    }
    Ok(found.into_iter().collect())
}

/// `TCP_LISTEN`, as `/proc/net/tcp` writes a socket's state.
const LISTEN: &str = "0A";

/// The listening sockets in a `/proc/net/tcp` or `tcp6` table, by inode: a
/// header, then a line for each socket, whose words 1, 3 and 9 are its local
/// address, state and inode. A line that cannot be read fails the look, as
/// a socket left out would read as no listener.
fn parse_table(text: &str) -> Result<BTreeMap<u64, SocketAddr>, ListenersError> {
    let mut sockets = BTreeMap::new();
    for line in text.lines().skip(1).filter(|l| !l.trim().is_empty()) {
        let unexpected = || proc_error(format!("unexpected line `{}`", line.trim()));
        let words: Vec<&str> = line.split_whitespace().collect();
        let [_, local, _, state, _, _, _, _, _, inode, ..] = words.as_slice() else {
            return Err(unexpected());
        };
        if *state == LISTEN {
            let addr = table_address(local).ok_or_else(unexpected)?;
            let inode = inode.parse().map_err(|_| unexpected())?;
            sockets.insert(inode, addr);
        }
    }
    Ok(sockets)
}

/// `0100007F:1F90`, or 32 hexadecimal digits before the colon for IPv6: each
/// group of 8 is a 32-bit word of the address as this machine's `%08X` prints
/// it, and the port is hexadecimal. A wildcard is given as `0.0.0.0`, as
/// from `lsof`; a v4-mapped address as the IPv4 one, which it is.
fn table_address(text: &str) -> Option<SocketAddr> {
    let (host, port) = text.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    let bytes = host
        .as_bytes()
        .chunks(8)
        .map(|word| {
            let word = u32::from_str_radix(std::str::from_utf8(word).ok()?, 16).ok()?;
            Some(word.to_ne_bytes())
        })
        .collect::<Option<Vec<[u8; 4]>>>()?
        .concat();
    let ip: IpAddr = match <[u8; 4]>::try_from(bytes.as_slice()) {
        Ok(v4) => Ipv4Addr::from(v4).into(),
        Err(_) => Ipv6Addr::from(<[u8; 16]>::try_from(bytes.as_slice()).ok()?).to_canonical(),
    };
    Some(match ip.is_unspecified() {
        true => SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)),
        false => SocketAddr::new(ip, port),
    })
}

/// What `lsof -Fn` answered. For processes with no such socket, or none at
/// all, it prints nothing and exits 1, with nothing on stderr; when one of
/// several is gone, it prints what the others hold and still exits 1 (macOS
/// 26.5.2). Any other failure, or a line that is not an address, means it
/// could not look.
fn listening(out: &Output) -> Result<Vec<(u32, SocketAddr)>, ListenersError> {
    let text = String::from_utf8_lossy(&out.stdout);
    let why = String::from_utf8_lossy(&out.stderr).trim().to_owned();
    match (out.status.code(), text.trim().is_empty(), why.is_empty()) {
        (Some(1), true, true) => return Ok(Vec::new()),
        (Some(0), false, _) | (Some(1), false, true) => {}
        _ => {
            return Err(ListenersError::Lsof(format!(
                "{}{}",
                out.status,
                match why.as_str() {
                    "" => String::new(),
                    why => format!(": {why}"),
                }
            )));
        }
    }
    let mut found = Vec::new();
    let mut pid = None;
    for line in text.lines() {
        // A `p<pid>` line starts each process; `f<fd>` names a descriptor.
        if let Some(p) = line.strip_prefix('p') {
            pid = Some(
                p.parse()
                    .map_err(|_| ListenersError::Lsof(format!("unexpected process `{p}`")))?,
            );
        } else if let Some(name) = line.strip_prefix('n') {
            let pid = pid.ok_or_else(|| {
                ListenersError::Lsof(format!("an address before any process: `{name}`"))
            })?;
            let addr = address(name)
                .ok_or_else(|| ListenersError::Lsof(format!("unexpected address `{name}`")))?;
            found.push((pid, addr));
        }
    }
    Ok(found)
}

/// `127.0.0.1:61374`, `[::1]:8080` or `*:9000`.
fn address(name: &str) -> Option<SocketAddr> {
    let (host, port) = name.rsplit_once(':')?;
    let port = port.parse().ok()?;
    let ip: IpAddr = match host {
        "*" => Ipv4Addr::UNSPECIFIED.into(),
        _ => host
            .strip_prefix('[')
            .and_then(|h| h.strip_suffix(']'))
            .unwrap_or(host)
            .parse()
            .ok()?,
    };
    Some(SocketAddr::new(ip, port))
}

/// The ports the system picks from for a bind on port 0, as `sysctl` gives
/// them on macOS and `/proc` on Linux; why not, when it cannot say.
pub fn ephemeral_ports() -> Result<RangeInclusive<u16>, String> {
    let (first, last) = match cfg!(target_os = "macos") {
        true => (
            sysctl_port("net.inet.ip.portrange.first")?,
            sysctl_port("net.inet.ip.portrange.last")?,
        ),
        false => {
            let path = "/proc/sys/net/ipv4/ip_local_port_range";
            let text =
                std::fs::read_to_string(path).map_err(|e| format!("cannot read {path}: {e}"))?;
            port_range(&text).ok_or_else(|| format!("{path} gave `{}`", text.trim()))?
        }
    };
    match first <= last {
        true => Ok(first..=last),
        false => Err(format!("the ephemeral ports run from {first} to {last}")),
    }
}

fn sysctl_port(name: &str) -> Result<u16, String> {
    let out = Command::new("/usr/sbin/sysctl")
        .args(["-n", name])
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("cannot run /usr/sbin/sysctl: {e}"))?;
    let text = String::from_utf8_lossy(&out.stdout);
    match out.status.success() {
        true => text
            .trim()
            .parse()
            .map_err(|_| format!("sysctl gave `{}` for {name}", text.trim())),
        false => Err(format!("sysctl could not read {name}: {}", out.status)),
    }
}

/// The two ports `ip_local_port_range` holds, and nothing else.
fn port_range(text: &str) -> Option<(u16, u16)> {
    let mut words = text.split_whitespace();
    let range = (words.next()?.parse().ok()?, words.next()?.parse().ok()?);
    words.next().is_none().then_some(range)
}

/// The service's port, out of what its process holds: the one it listens on
/// at 127.0.0.1 in `ephemeral`, where a bind on port 0 lands (ADR 0028), as
/// Hermes's gateway binds `127.0.0.1:0`. A port it binds by number, such as
/// Hermes's API server or webhooks, and one held on every address are not
/// taken for it: on every address, another process of the user could hold
/// 127.0.0.1 at that port, and a session would reach that one. None or
/// several such ports is never a guess.
pub fn one_port(held: &[SocketAddr], ephemeral: &RangeInclusive<u16>) -> Result<u16, NotOnePort> {
    let mut ports: Vec<u16> = held
        .iter()
        .filter(|a| a.ip() == IpAddr::V4(Ipv4Addr::LOCALHOST))
        .map(SocketAddr::port)
        .filter(|port| ephemeral.contains(port))
        .collect();
    ports.sort_unstable();
    ports.dedup();
    match ports.as_slice() {
        [] => Err(NotOnePort::None(format!(
            "it holds no TCP listener at 127.0.0.1 in the ephemeral ports, {} to {}",
            ephemeral.start(),
            ephemeral.end()
        ))),
        [port] => Ok(*port),
        several => Err(NotOnePort::Several(format!(
            "it listens on {} ephemeral ports at 127.0.0.1 ({}), so which is its own cannot be told",
            several.len(),
            several
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        ))),
    }
}

/// Why [`one_port`] gave no port.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NotOnePort {
    /// It holds none such yet, as a service still starting.
    #[error("{0}")]
    None(String),
    /// It holds several, and which is its own cannot be told.
    #[error("{0}")]
    Several(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt;
    use std::process::ExitStatus;

    #[test]
    fn the_service_port_is_the_one_ephemeral_port_at_127_0_0_1() {
        let a = |s: &str| s.parse::<SocketAddr>().unwrap();
        let ephemeral = 49152..=65535;
        assert_eq!(one_port(&[a("127.0.0.1:61374")], &ephemeral), Ok(61374));
        // Ports bound by number (Hermes's API server, webhooks) are left out.
        assert_eq!(
            one_port(
                &[a("127.0.0.1:8642"), a("0.0.0.0:8644"), a("127.0.0.1:61374")],
                &ephemeral
            ),
            Ok(61374)
        );
        // Every address is not taken for it: another process could hold
        // 127.0.0.1 at that port. Nor [::1], which `tcp4` does not reach,
        // nor another loopback address.
        for held in ["0.0.0.0:61374", "[::1]:61374", "127.0.0.2:61374"] {
            assert!(one_port(&[a(held)], &ephemeral).is_err(), "{held}");
        }
        assert!(one_port(&[a("127.0.0.1:8642")], &ephemeral).is_err());
        assert!(one_port(&[], &ephemeral).is_err());
        let err = one_port(&[a("127.0.0.1:50001"), a("127.0.0.1:50002")], &ephemeral).unwrap_err();
        assert!(matches!(err, NotOnePort::Several(_)), "{err}");
        assert!(
            err.to_string()
                .contains("2 ephemeral ports at 127.0.0.1 (50001, 50002)"),
            "{err}"
        );
        assert!(matches!(
            one_port(&[], &ephemeral),
            Err(NotOnePort::None(_))
        ));
    }

    fn out(code: i32, stdout: &str, stderr: &str) -> Output {
        Output {
            status: ExitStatus::from_raw(code << 8),
            stdout: stdout.as_bytes().to_vec(),
            stderr: stderr.as_bytes().to_vec(),
        }
    }

    #[test]
    fn the_ephemeral_ports_are_the_systems() {
        let ports = ephemeral_ports().unwrap();
        // A bind on port 0 lands in them.
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        assert!(ports.contains(&port), "{port} not in {ports:?}");
    }

    #[test]
    fn the_ephemeral_range_of_proc_is_two_ports() {
        assert_eq!(port_range("32768\t60999\n"), Some((32768, 60999)));
        for odd in ["", "32768", "1 2 3", "a b", "1 70000"] {
            assert_eq!(port_range(odd), None, "{odd}");
        }
    }

    /// A line of `/proc/net/tcp` for a socket in `state`.
    fn socket(local: &str, state: &str, inode: u64) -> String {
        format!(
            "   0: {local} 00000000:0000 {state} 00000000:00000000 00:00000000 00000000  1000        0 {inode} 1 0000000000000000 100 0 0 10 0\n"
        )
    }

    const HEADER: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n";

    #[test]
    fn a_table_gives_its_listening_sockets_by_inode() {
        let table = [
            HEADER.to_owned(),
            socket("0100007F:EFBE", "0A", 1),
            socket("00000000:2382", "0A", 2),
            // Established: not a listener.
            socket("0100007F:EFBE", "01", 3),
            socket("00000000000000000000000001000000:1F90", "0A", 4),
            socket("00000000000000000000000000000000:1F91", "0A", 5),
            socket("0000000000000000FFFF00000100007F:1F92", "0A", 6),
        ]
        .concat();
        let a = |s: &str| s.parse::<SocketAddr>().unwrap();
        assert_eq!(
            parse_table(&table).unwrap(),
            BTreeMap::from([
                (1, a("127.0.0.1:61374")),
                (2, a("0.0.0.0:9090")),
                (4, a("[::1]:8080")),
                (5, a("0.0.0.0:8081")),
                (6, a("127.0.0.1:8082")),
            ])
        );
    }

    #[test]
    fn a_table_with_a_line_it_cannot_read_is_an_error() {
        for line in [
            "   0: garbled\n".to_owned(),
            socket("zz:1F90", "0A", 1),
            socket("0100007F:EFBE", "0A", 0).replace(" 0 0 1 ", " 0 x 1 "),
        ] {
            let table = format!("{HEADER}{line}");
            assert!(parse_table(&table).is_err(), "{line}");
        }
    }

    /// Network tables in a `/proc` of a test's own.
    fn fake_net(net: &Path, tcp: &str) {
        std::fs::create_dir_all(net).unwrap();
        std::fs::write(net.join("tcp"), format!("{HEADER}{tcp}")).unwrap();
    }

    #[test]
    fn a_process_holds_the_listeners_its_descriptors_name_and_no_others() {
        let dir = tempfile::tempdir().unwrap();
        let proc = dir.path();
        let tcp = [
            socket("0100007F:EFBE", "0A", 11),
            socket("0100007F:EFBF", "0A", 12),
        ]
        .concat();
        fake_net(&proc.join("7/net"), &tcp);
        descriptors::fake_process(proc, 7, &["socket:[11]", "/some/file", "socket:[99]"]);
        // Gone: no tables, so it holds none.
        assert_eq!(
            held_in_proc(proc, &[7, 8]).unwrap(),
            [(7, "127.0.0.1:61374".parse().unwrap())]
        );
    }

    /// A process there with tables, whose descriptors cannot be read, is
    /// not one that holds nothing.
    #[test]
    fn a_process_that_cannot_be_read_is_an_error() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let proc = dir.path();
        fake_net(&proc.join("7/net"), "");
        descriptors::fake_process(proc, 7, &[]);
        let fd = proc.join("7/fd");
        std::fs::set_permissions(&fd, std::fs::Permissions::from_mode(0o000)).unwrap();
        let read = held_in_proc(proc, &[7]);
        std::fs::set_permissions(&fd, std::fs::Permissions::from_mode(0o700)).unwrap();
        let err = read.unwrap_err();
        assert!(err.to_string().contains("pid 7 cannot be read"), "{err}");
    }

    #[test]
    fn every_holder_of_the_port_is_named_and_a_port_not_listened_on_has_none() {
        let dir = tempfile::tempdir().unwrap();
        let proc = dir.path();
        let tcp = [
            socket("0100007F:EFBE", "0A", 11),
            // The same port on every address is not 127.0.0.1's.
            socket("00000000:EFBE", "0A", 12),
        ]
        .concat();
        fake_net(&proc.join("self/net"), &tcp);
        descriptors::fake_process(proc, std::process::id(), &[]);
        descriptors::fake_process(proc, 7, &["socket:[11]"]);
        descriptors::fake_process(proc, 8, &["socket:[11]"]);
        descriptors::fake_process(proc, 9, &["socket:[12]"]);
        let at: SocketAddr = "127.0.0.1:61374".parse().unwrap();
        assert_eq!(holders_in_proc(proc, 61374).unwrap(), [(7, at), (8, at)]);
        assert!(holders_in_proc(proc, 61375).unwrap().is_empty());
    }

    #[test]
    fn listeners_are_read_from_the_name_lines() {
        let got = listening(&out(
            0,
            "p32653\nf22\nn127.0.0.1:61374\nf23\nn[::1]:61374\nf24\nn*:9000\np41\nf5\nn127.0.0.1:61374\n",
            "",
        ))
        .unwrap();
        assert_eq!(
            got,
            [
                (32653, "127.0.0.1:61374".parse().unwrap()),
                (32653, "[::1]:61374".parse().unwrap()),
                (32653, "0.0.0.0:9000".parse().unwrap()),
                (41, "127.0.0.1:61374".parse().unwrap()),
            ]
        );
    }

    #[test]
    fn nothing_listed_is_no_listener_but_any_other_failure_is_an_error() {
        assert!(listening(&out(1, "", "")).unwrap().is_empty());
        // One of several gone: what the others hold, and exit 1.
        assert_eq!(
            listening(&out(1, "p7\nf3\nn127.0.0.1:80\n", "")).unwrap(),
            [(7, "127.0.0.1:80".parse().unwrap())]
        );
        assert!(listening(&out(1, "", "lsof: illegal option")).is_err());
        assert!(listening(&out(2, "", "")).is_err());
        assert!(listening(&out(0, "", "")).is_err());
        assert!(listening(&out(0, "p1\nf3\nnsomething odd\n", "")).is_err());
        assert!(listening(&out(0, "f3\nn127.0.0.1:80\n", "")).is_err());
    }

    #[test]
    fn this_process_is_seen_listening_by_pid_and_by_port() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let found = tcp_listeners(std::process::id()).unwrap();
        assert!(found.iter().any(|a| a.port() == port), "{found:?}");
        let holders = tcp_listeners_at(port).unwrap();
        assert_eq!(
            holders,
            [(
                std::process::id(),
                SocketAddr::from((Ipv4Addr::LOCALHOST, port))
            )]
        );
    }
}
