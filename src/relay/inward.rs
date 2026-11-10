//! The way in (ADR 0040; design §6): the relay from the host to a port of
//! 127.0.0.1 in a sandbox's network namespace, which the host cannot reach
//! otherwise. The namespace holder serves it on a Unix socket in the
//! sandbox's host-only run folder, which no session mounts. Each connection
//! there names its port first, in two bytes in network order, and the rest
//! is carried as it is, read by neither end.

use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, TcpStream};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use super::{OWN_DESCRIPTORS, carry, connections_for, say, serve_each};
use crate::net::budget;

/// How long a connection has to name its port before it is closed.
const NAMING: Duration = Duration::from_secs(5);

/// The host's way to the ports of one sandbox's network namespace: the
/// namespace holder's socket for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WayIn {
    socket: PathBuf,
}

impl WayIn {
    pub fn new(socket: &Path) -> WayIn {
        WayIn {
            socket: socket.to_owned(),
        }
    }

    /// Whether a namespace holder answers on it: one started by an enclos
    /// without it does not.
    pub fn answers(&self) -> io::Result<()> {
        UnixStream::connect(&self.socket).map(drop)
    }

    /// A connection to 127.0.0.1 at `port` in the sandbox's network
    /// namespace. Nobody listening there closes it unanswered.
    pub fn connect(&self, port: u16) -> io::Result<UnixStream> {
        let mut stream = UnixStream::connect(&self.socket)?;
        stream.write_all(&port.to_be_bytes())?;
        Ok(stream)
    }
}

/// Passes each connection on `listener` to 127.0.0.1 at the port it names,
/// in this process's network namespace, until the process ends. A port
/// nobody listens on closes the connection.
pub fn serve(listener: UnixListener) -> ! {
    serve_up_to(
        listener,
        connections_for(budget::descriptors_to_share(OWN_DESCRIPTORS)),
        crate::proxy::IDLE_TIMEOUT,
    )
}

fn serve_up_to(listener: UnixListener, max: usize, limit: Duration) -> ! {
    // Said once until it clears, not for every connection.
    let unreachable = AtomicBool::new(false);
    serve_each(
        || listener.accept().map(|(client, _)| client),
        max,
        move |client: UnixStream| {
            let Some(port) = named_port(&client) else {
                return;
            };
            match TcpStream::connect((Ipv4Addr::LOCALHOST, port)) {
                Ok(service) => {
                    unreachable.store(false, Ordering::Relaxed);
                    carry(&client, &service, limit);
                }
                Err(e) => {
                    if !unreachable.swap(true, Ordering::Relaxed) {
                        say(format_args!("cannot reach 127.0.0.1:{port}: {e}"));
                    }
                }
            }
        },
    )
}

/// The port `client` names in its first two bytes, within [`NAMING`]: none
/// for a client that names none, or port 0.
fn named_port(client: &UnixStream) -> Option<u16> {
    client.set_read_timeout(Some(NAMING)).ok()?;
    let mut named = [0; 2];
    (&*client).read_exact(&mut named).ok()?;
    client.set_read_timeout(None).ok()?;
    Some(u16::from_be_bytes(named)).filter(|port| *port != 0)
}

#[cfg(test)]
mod tests {
    use std::thread;

    use super::*;

    /// The way in served by a relay in this process, on a socket of its
    /// own.
    fn served() -> (WayIn, tempfile::TempDir) {
        let folder = tempfile::tempdir().unwrap();
        let socket = folder.path().join("inward.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        thread::spawn(move || serve_up_to(listener, 4, Duration::from_secs(5)));
        (WayIn::new(&socket), folder)
    }

    #[test]
    fn a_connection_reaches_the_port_it_names_both_ways() {
        let (way_in, _folder) = served();
        let service = crate::test_ports::tcp_listener(Ipv4Addr::LOCALHOST);
        let port = service.local_addr().unwrap().port();
        let echo = thread::spawn(move || {
            let (mut accepted, _) = service.accept().unwrap();
            let mut asked = [0; 5];
            accepted.read_exact(&mut asked).unwrap();
            accepted.write_all(b"page:").unwrap();
            accepted.write_all(&asked).unwrap();
        });
        let mut client = way_in.connect(port).unwrap();
        client.write_all(b"hello").unwrap();
        client.shutdown(std::net::Shutdown::Write).unwrap();
        let mut answer = String::new();
        client.read_to_string(&mut answer).unwrap();
        echo.join().unwrap();
        assert_eq!(answer, "page:hello");
    }

    #[test]
    fn a_port_nobody_listens_on_closes_the_connection_unanswered() {
        let (way_in, _folder) = served();
        let port = {
            let gone = crate::test_ports::tcp_listener(Ipv4Addr::LOCALHOST);
            gone.local_addr().unwrap().port()
        };
        let mut client = way_in.connect(port).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(30)))
            .unwrap();
        let mut answer = Vec::new();
        let _ = client.read_to_end(&mut answer);
        assert!(answer.is_empty(), "{answer:?}");
    }

    #[test]
    fn a_connection_that_names_no_port_is_closed() {
        let folder = tempfile::tempdir().unwrap();
        let socket = folder.path().join("inward.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let client = UnixStream::connect(&socket).unwrap();
        let (accepted, _) = listener.accept().unwrap();
        (&client).write_all(&[0]).unwrap();
        drop(client);
        assert_eq!(named_port(&accepted), None);

        let client = UnixStream::connect(&socket).unwrap();
        let (accepted, _) = listener.accept().unwrap();
        (&client).write_all(&0u16.to_be_bytes()).unwrap();
        assert_eq!(named_port(&accepted), None);

        let client = UnixStream::connect(&socket).unwrap();
        let (accepted, _) = listener.accept().unwrap();
        (&client).write_all(&[0xa0, 0x29]).unwrap();
        assert_eq!(named_port(&accepted), Some(41001));
    }

    #[test]
    fn a_way_in_nobody_serves_does_not_answer() {
        let folder = tempfile::tempdir().unwrap();
        let way_in = WayIn::new(&folder.path().join("inward.sock"));
        assert!(way_in.answers().is_err());
        assert!(way_in.connect(80).is_err());
        let (served, _folder) = served();
        served.answers().unwrap();
    }
}
