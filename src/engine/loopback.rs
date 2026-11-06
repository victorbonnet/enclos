//! Whether a program listens on a loopback port, seen by connecting to it.
//!
//! A connection to a port nothing listens on can be given that same port as
//! its own, where the system picks local ports from a range that holds it
//! (Linux's ephemeral range holds the proxy range): it then connects to
//! itself. Closed as usual, it would leave the port in `TIME-WAIT` for a
//! minute, where no proxy could listen. So a connection that reached itself
//! counts as nothing listening, and is reset as it closes, which leaves the
//! port free at once.

use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

/// Whether a program listens at `addr`: a connection made within `wait`
/// reaches another socket than its own.
pub(super) fn listens(addr: SocketAddr, wait: Duration) -> bool {
    TcpStream::connect_timeout(&addr, wait).is_ok_and(reached_another)
}

/// Whether `stream` reached another socket than its own; one that reached
/// itself is reset as it closes.
fn reached_another(stream: TcpStream) -> bool {
    let itself = stream.local_addr().ok() == stream.peer_addr().ok();
    if itself {
        // A linger of zero makes the close a reset, which skips TIME-WAIT.
        let _ = rustix::net::sockopt::set_socket_linger(&stream, Some(Duration::ZERO));
    }
    !itself
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    /// A port on 127.0.0.1 nothing listens on, outside the proxy range.
    fn free() -> SocketAddr {
        crate::test_ports::tcp_listener(Ipv4Addr::LOCALHOST)
            .local_addr()
            .unwrap()
    }

    #[test]
    fn a_listener_is_seen_and_a_closed_port_is_not() {
        let listener = crate::test_ports::tcp_listener(Ipv4Addr::LOCALHOST);
        let wait = Duration::from_millis(200);
        assert!(listens(listener.local_addr().unwrap(), wait));
        assert!(!listens(free(), wait));
    }

    /// A connection to itself is made on purpose here; Linux takes one with
    /// no listener (TCP's simultaneous open), macOS refuses it (EINVAL).
    #[cfg(target_os = "linux")]
    mod to_itself {
        use std::net::TcpListener;

        use rustix::net::{AddressFamily, SocketType};

        use super::*;

        /// A connection from a port on 127.0.0.1 to that same port: what the
        /// system makes when it gives a connection the port it connects to.
        /// The port is held from its bind on, so no other test takes it.
        fn to_itself() -> (TcpStream, SocketAddr) {
            let socket = crate::test_ports::clear_of_proxies(|| {
                let socket =
                    rustix::net::socket(AddressFamily::INET, SocketType::STREAM, None).unwrap();
                rustix::net::bind(&socket, &SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
                let port = TcpStream::from(socket.try_clone().unwrap())
                    .local_addr()
                    .unwrap()
                    .port();
                (socket, port)
            });
            let stream = TcpStream::from(socket);
            let addr = stream.local_addr().unwrap();
            rustix::net::connect(&stream, &addr).unwrap();
            (stream, addr)
        }

        #[test]
        fn a_connection_to_itself_is_no_listener_and_leaves_its_port_free() {
            let (stream, addr) = to_itself();
            assert_eq!(stream.peer_addr().unwrap(), addr);
            assert!(!reached_another(stream));
            TcpListener::bind(addr).unwrap();
        }

        /// The control: closed as usual, the same connection keeps the port
        /// from a listener for as long as `TIME-WAIT` lasts.
        #[test]
        fn a_connection_to_itself_closed_as_usual_keeps_its_port_from_a_listener() {
            let (stream, addr) = to_itself();
            drop(stream);
            let err = TcpListener::bind(addr).unwrap_err();
            assert_eq!(err.kind(), std::io::ErrorKind::AddrInUse, "{err}");
        }
    }
}
