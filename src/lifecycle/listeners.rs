//! The TCP listeners a process holds, through `lsof`, with no `unsafe`
//! code (ADR 0012). enclos uses them to find a runtime service's
//! listener (ADR 0028): from the process enclos started for the service,
//! never from a file the sandbox writes.
//!
//! A `lsof` that fails is an error, never an empty answer, so "no listener"
//! is only ever what `lsof` said.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::ops::RangeInclusive;
use std::process::{Command, Output, Stdio};

/// `lsof` could not answer.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("cannot look at listening sockets with /usr/sbin/lsof: {0}")]
pub struct LsofError(String);

/// The TCP addresses `pid` listens on. A wildcard address (`*`, IPv4 or
/// IPv6) is given as `0.0.0.0`.
pub fn tcp_listeners(pid: u32) -> Result<Vec<SocketAddr>, LsofError> {
    Ok(tcp_listeners_of(&[pid])?
        .into_iter()
        .map(|(_, addr)| addr)
        .collect())
}

/// The TCP addresses each of `pids` listens on, with the pid that holds it,
/// in one look. A process that is gone holds none.
fn tcp_listeners_of(pids: &[u32]) -> Result<Vec<(u32, SocketAddr)>, LsofError> {
    if pids.is_empty() {
        return Ok(Vec::new());
    }
    let list = pids
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(",");
    lsof(&["-a", "-p", &list, "-iTCP", "-sTCP:LISTEN"])
}

/// Every process, of those `lsof` can see (the user's), that listens on TCP
/// at 127.0.0.1 port `port`, with the address it holds. Another user's
/// process cannot bind a port the user's holds, so the user's are the ones
/// that matter.
pub fn tcp_listeners_at(port: u16) -> Result<Vec<(u32, SocketAddr)>, LsofError> {
    lsof(&[&format!("-iTCP@127.0.0.1:{port}"), "-sTCP:LISTEN"])
}

fn lsof(select: &[&str]) -> Result<Vec<(u32, SocketAddr)>, LsofError> {
    let out = Command::new("/usr/sbin/lsof")
        .env("LC_ALL", "C")
        .arg("-nP")
        .args(select)
        .arg("-Fn")
        .stdin(Stdio::null())
        .output()
        .map_err(|e| LsofError(e.to_string()))?;
    listening(&out)
}

/// What `lsof -Fn` answered. For processes with no such socket, or none at
/// all, it prints nothing and exits 1, with nothing on stderr; when one of
/// several is gone, it prints what the others hold and still exits 1 (macOS
/// 26.5.2). Any other failure, or a line that is not an address, means it
/// could not look.
fn listening(out: &Output) -> Result<Vec<(u32, SocketAddr)>, LsofError> {
    let text = String::from_utf8_lossy(&out.stdout);
    let why = String::from_utf8_lossy(&out.stderr).trim().to_owned();
    match (out.status.code(), text.trim().is_empty(), why.is_empty()) {
        (Some(1), true, true) => return Ok(Vec::new()),
        (Some(0), false, _) | (Some(1), false, true) => {}
        _ => {
            return Err(LsofError(format!(
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
                    .map_err(|_| LsofError(format!("unexpected process `{p}`")))?,
            );
        } else if let Some(name) = line.strip_prefix('n') {
            let pid =
                pid.ok_or_else(|| LsofError(format!("an address before any process: `{name}`")))?;
            let addr =
                address(name).ok_or_else(|| LsofError(format!("unexpected address `{name}`")))?;
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
/// them on macOS; why not, when it cannot say.
pub fn ephemeral_ports() -> Result<RangeInclusive<u16>, String> {
    let read = |name: &str| -> Result<u16, String> {
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
    };
    let (first, last) = (
        read("net.inet.ip.portrange.first")?,
        read("net.inet.ip.portrange.last")?,
    );
    match first <= last {
        true => Ok(first..=last),
        false => Err(format!("the ephemeral ports run from {first} to {last}")),
    }
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

    // macOS's sysctl names; Linux has its own range.
    #[cfg(target_os = "macos")]
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

    // `lsof` at that path is macOS's, where sandboxes listen (ADR 0028).
    #[cfg(target_os = "macos")]
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
