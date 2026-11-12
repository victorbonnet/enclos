//! The TCP listeners a process holds, as the host shows them (`lsof` on
//! macOS, `/proc` on Linux; see `host`), with no `unsafe` code (ADR 0012).
//! enclos uses them to find a runtime service's listener (ADR 0028): from the
//! process enclos started for the service, never from a file the sandbox
//! writes.
//!
//! A look that fails is an error, never an empty answer, so "no listener" is
//! only ever what `lsof` or `/proc` said.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::ops::RangeInclusive;

use super::host;

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
    host::tcp_listeners_of(pids)
}

/// Every process, of those `lsof` or `/proc` can show (the user's), that
/// listens on TCP at 127.0.0.1 port `port`, with the address it holds.
/// Another user's process cannot bind a port the user's holds, so the user's
/// are the ones that matter.
pub fn tcp_listeners_at(port: u16) -> Result<Vec<(u32, SocketAddr)>, ListenersError> {
    host::tcp_listeners_at(port)
}

/// The TCP addresses `pid` listens on in the network namespace of
/// `namespace`, a process in it. From `/proc`: only Linux gives a sandbox a
/// network namespace of its own (ADR 0039).
pub fn tcp_listeners_in(namespace: u32, pid: u32) -> Result<Vec<SocketAddr>, ListenersError> {
    Ok(super::proc::tcp_listeners_in(namespace, &[pid])?
        .into_iter()
        .map(|(_, addr)| addr)
        .collect())
}

/// Every process, of those `/proc` can show, that listens on TCP at
/// 127.0.0.1 port `port` in the network namespace of `namespace`, a process
/// in it, with the address it holds.
pub fn tcp_listeners_at_in(
    namespace: u32,
    port: u16,
) -> Result<Vec<(u32, SocketAddr)>, ListenersError> {
    super::proc::tcp_listeners_at_in(namespace, port)
}

/// The ports the system picks from for a bind on port 0, as `sysctl` gives
/// them on macOS and `/proc` on Linux; why not, when it cannot say.
pub fn ephemeral_ports() -> Result<RangeInclusive<u16>, String> {
    let (first, last) = host::ephemeral_ports()?;
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
    one_port_matching(held, ephemeral, true)
}

/// A configured-port service's one positive TCP port at 127.0.0.1, out of
/// the sockets its process holds. Other addresses and port 0 do not count;
/// multiple ports are refused. This selects a candidate only: the caller
/// must still verify ownership and reject reserved proxy ports.
pub fn one_loopback_port(held: &[SocketAddr]) -> Result<u16, NotOnePort> {
    one_port_matching(held, &(1..=u16::MAX), false)
}

fn one_port_matching(
    held: &[SocketAddr],
    candidates: &RangeInclusive<u16>,
    ephemeral: bool,
) -> Result<u16, NotOnePort> {
    let mut ports: Vec<u16> = held
        .iter()
        .filter(|a| a.ip() == IpAddr::V4(Ipv4Addr::LOCALHOST))
        .map(SocketAddr::port)
        .filter(|port| candidates.contains(port))
        .collect();
    ports.sort_unstable();
    ports.dedup();
    match ports.as_slice() {
        [] if ephemeral => Err(NotOnePort::None(format!(
            "it holds no TCP listener at 127.0.0.1 in the ephemeral ports, {} to {}",
            candidates.start(),
            candidates.end()
        ))),
        [] => Err(NotOnePort::None(
            "it holds no positive TCP listener at 127.0.0.1".to_owned(),
        )),
        [port] => Ok(*port),
        several => Err(NotOnePort::Several(format!(
            "it listens on {} {}ports at 127.0.0.1 ({}), so which is its own cannot be told",
            several.len(),
            if ephemeral { "ephemeral " } else { "" },
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

    #[test]
    fn a_configured_listener_selects_one_positive_ipv4_loopback_port() {
        let a = |s: &str| s.parse::<SocketAddr>().unwrap();
        for port in [1024, 18789, 61374, u16::MAX] {
            assert_eq!(
                one_loopback_port(&[a(&format!("127.0.0.1:{port}"))]),
                Ok(port)
            );
        }
        for at in [
            "127.0.0.1:0",
            "127.0.0.2:18789",
            "0.0.0.0:18789",
            "[::1]:18789",
        ] {
            assert!(
                matches!(one_loopback_port(&[a(at)]), Err(NotOnePort::None(_))),
                "{at}"
            );
        }
        assert!(matches!(
            one_loopback_port(&[a("127.0.0.1:18789"), a("127.0.0.1:61374")]),
            Err(NotOnePort::Several(_))
        ));
        assert_eq!(
            one_loopback_port(&[a("127.0.0.1:18789"), a("127.0.0.1:18789")]),
            Ok(18789)
        );
    }

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

    #[test]
    fn the_ephemeral_ports_are_the_systems() {
        let ports = ephemeral_ports().unwrap();
        // A bind on port 0 lands in them.
        let port = crate::test_ports::tcp_listener(Ipv4Addr::LOCALHOST)
            .local_addr()
            .unwrap()
            .port();
        assert!(ports.contains(&port), "{port} not in {ports:?}");
    }

    /// A real one, read by pid and by port.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_process_whose_main_thread_exited_is_seen_listening() {
        use crate::lifecycle::process::{headless, headless_port};
        use std::process::Command;
        let mut child = headless(&mut Command::new("/usr/bin/python3"))
            .spawn()
            .unwrap();
        let port = headless_port(&mut child);
        let by_pid = tcp_listeners(child.id());
        let by_port = tcp_listeners_at(port);
        let _ = child.kill();
        let _ = child.wait();
        let at = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
        assert_eq!(by_pid.unwrap(), [at]);
        assert!(by_port.unwrap().contains(&(child.id(), at)));
    }

    #[test]
    fn this_process_is_seen_listening_by_pid_and_by_port() {
        let listener = crate::test_ports::tcp_listener(Ipv4Addr::LOCALHOST);
        let port = listener.local_addr().unwrap().port();
        let found = tcp_listeners(std::process::id()).unwrap();
        assert!(found.iter().any(|a| a.port() == port), "{found:?}");
        let holders = tcp_listeners_at(port).unwrap();
        // Another test's program between fork and exec may hold a copy.
        let at = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
        assert!(holders.contains(&(std::process::id(), at)), "{holders:?}");
    }
}
