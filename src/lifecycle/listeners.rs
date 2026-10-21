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

/// The TCP addresses `pid` listens on. A wildcard address (`*`) is given as
/// `0.0.0.0`.
pub fn tcp_listeners(pid: u32) -> Result<Vec<SocketAddr>, LsofError> {
    Ok(tcp_listeners_of(&[pid])?
        .into_iter()
        .map(|(_, addr)| addr)
        .collect())
}

/// The TCP addresses each of `pids` listens on, with the pid that holds it,
/// in one look. A process that is gone holds none.
pub fn tcp_listeners_of(pids: &[u32]) -> Result<Vec<(u32, SocketAddr)>, LsofError> {
    if pids.is_empty() {
        return Ok(Vec::new());
    }
    let list = pids
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let out = Command::new("/usr/sbin/lsof")
        .env("LC_ALL", "C")
        .args(["-nP", "-a", "-p", &list, "-iTCP", "-sTCP:LISTEN", "-Fn"])
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

/// The ports the system picks from for a bind on port 0. `sysctl` gives
/// them on macOS; IANA's dynamic ports, macOS's default, when it cannot.
pub fn ephemeral_ports() -> RangeInclusive<u16> {
    let read = |name: &str| -> Option<u16> {
        let out = Command::new("/usr/sbin/sysctl")
            .args(["-n", name])
            .stdin(Stdio::null())
            .output()
            .ok()?;
        String::from_utf8_lossy(&out.stdout).trim().parse().ok()
    };
    match (
        read("net.inet.ip.portrange.first"),
        read("net.inet.ip.portrange.last"),
    ) {
        (Some(first), Some(last)) if first <= last => first..=last,
        _ => 49152..=65535,
    }
}

/// The service's port, out of what its process holds: the one it listens on
/// at 127.0.0.1, or every IPv4 address, in `ephemeral`, where a bind on port
/// 0 lands (ADR 0028). A port it binds by number, such as Hermes's API
/// server or webhooks, is not taken for it; none or several such ports is
/// never a guess.
pub fn one_port(held: &[SocketAddr], ephemeral: &RangeInclusive<u16>) -> Result<u16, String> {
    let mut ports: Vec<u16> = held
        .iter()
        .filter(|a| match a.ip() {
            IpAddr::V4(ip) => ip.is_loopback() || ip.is_unspecified(),
            IpAddr::V6(_) => false,
        })
        .map(SocketAddr::port)
        .filter(|port| ephemeral.contains(port))
        .collect();
    ports.sort_unstable();
    ports.dedup();
    match ports.as_slice() {
        [] => Err(format!(
            "it holds no TCP listener on 127.0.0.1 in the ephemeral ports, {} to {}",
            ephemeral.start(),
            ephemeral.end()
        )),
        [port] => Ok(*port),
        several => Err(format!(
            "it listens on {} ephemeral ports at 127.0.0.1 ({}), so which is its own cannot be told",
            several.len(),
            several
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt;
    use std::process::ExitStatus;

    #[test]
    fn the_service_port_is_the_one_ephemeral_port_on_127_0_0_1() {
        let a = |s: &str| s.parse::<SocketAddr>().unwrap();
        let ephemeral = 49152..=65535;
        assert_eq!(one_port(&[a("127.0.0.1:61374")], &ephemeral), Ok(61374));
        assert_eq!(one_port(&[a("0.0.0.0:61374")], &ephemeral), Ok(61374));
        // Ports bound by number (Hermes's API server, webhooks) are left out.
        assert_eq!(
            one_port(
                &[a("127.0.0.1:8642"), a("0.0.0.0:8644"), a("127.0.0.1:61374")],
                &ephemeral
            ),
            Ok(61374)
        );
        // [::1] is not where `tcp4` reaches.
        assert!(one_port(&[a("[::1]:61374")], &ephemeral).is_err());
        assert!(one_port(&[a("127.0.0.1:8642")], &ephemeral).is_err());
        assert!(one_port(&[], &ephemeral).is_err());
        let err = one_port(&[a("127.0.0.1:50001"), a("127.0.0.1:50002")], &ephemeral).unwrap_err();
        assert!(
            err.contains("2 ephemeral ports at 127.0.0.1 (50001, 50002)"),
            "{err}"
        );
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
        let ports = ephemeral_ports();
        assert!(ports.start() <= ports.end());
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
            "p32653\nf22\nn127.0.0.1:61374\nf23\nn[::1]:61374\nf24\nn*:9000\n",
            "",
        ))
        .unwrap();
        assert_eq!(
            got,
            [
                (32653, "127.0.0.1:61374".parse().unwrap()),
                (32653, "[::1]:61374".parse().unwrap()),
                (32653, "0.0.0.0:9000".parse().unwrap()),
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

    // `lsof` at that path is macOS's, where the forward runs (ADR 0028).
    #[cfg(target_os = "macos")]
    #[test]
    fn this_process_is_seen_listening() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let found = tcp_listeners(std::process::id()).unwrap();
        assert!(found.iter().any(|a| a.port() == port), "{found:?}");
    }
}
