//! The Unix sockets a network namespace listens on, as its `/proc/net/unix`
//! table lists them, and whether one answers this process: `wrap` masks the
//! host's under the user's home at each launch, and the escape probes try
//! each one.

use std::collections::BTreeSet;
use std::path::PathBuf;

/// The table of this process's network namespace: the host's, for enclos.
pub const HOST_TABLE: &str = "/proc/net/unix";

/// The files the host's sockets that take clients are bound to, as
/// [`HOST_TABLE`] lists them now; none where it cannot be read, as on macOS.
pub fn host_paths() -> Vec<PathBuf> {
    std::fs::read_to_string(HOST_TABLE)
        .map(|table| paths_in(&table))
        .unwrap_or_default()
}

/// The files the sockets of `table` that take clients are bound to.
pub fn paths_in(table: &str) -> Vec<PathBuf> {
    listening(table)
        .into_iter()
        .filter_map(|socket| match socket.address {
            Address::Path(path) => Some(path),
            Address::Abstract(_) => None,
        })
        .collect()
}

/// `SOCK_STREAM`, `SOCK_DGRAM` and `SOCK_SEQPACKET`, as the table writes a
/// socket's type: the same numbers on x86_64 and arm64.
const STREAM: u32 = 1;
const DATAGRAM: u32 = 2;
const SEQPACKET: u32 = 5;
/// `__SO_ACCEPTCON`, the flag of a socket that listens.
const LISTENING: u32 = 0x0001_0000;

/// Where a Unix socket is bound.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Address {
    /// A file.
    Path(PathBuf),
    /// A name in a network namespace's abstract namespace, without the NUL
    /// it starts with.
    Abstract(String),
}

impl Address {
    /// As the table and the probes' programs write it: an abstract name
    /// after `@`.
    pub fn shown(&self) -> String {
        match self {
            Address::Path(path) => path.display().to_string(),
            Address::Abstract(name) => format!("@{name}"),
        }
    }
}

/// A socket a client could connect to.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Socket {
    pub address: Address,
    /// Its type, which a client's socket must have.
    pub kind: u32,
}

/// The sockets of a `/proc/net/unix` table a client could connect to: the
/// stream and seqpacket ones that listen and the datagram ones that are
/// bound, each address once. A line that does not read is left out, as is
/// a socket bound to no address: what reads the table only looks for
/// sockets to probe.
pub fn listening(table: &str) -> Vec<Socket> {
    let mut found = BTreeSet::new();
    for line in table.lines().skip(1) {
        let Some((fields, address)) = fields_and_address(line) else {
            continue;
        };
        let [_, _, _, flags, kind, _, _] = fields;
        let (Ok(flags), Ok(kind)) = (
            u32::from_str_radix(flags, 16),
            u32::from_str_radix(kind, 16),
        ) else {
            continue;
        };
        let takes_clients = match kind {
            STREAM | SEQPACKET => flags & LISTENING != 0,
            DATAGRAM => true,
            _ => false,
        };
        if !takes_clients || address.is_empty() {
            continue;
        }
        let address = match address.strip_prefix('@') {
            Some(name) => Address::Abstract(name.to_owned()),
            None => Address::Path(PathBuf::from(address)),
        };
        found.insert(Socket { address, kind });
    }
    let mut seen = BTreeSet::new();
    found
        .into_iter()
        .filter(|s| seen.insert(s.address.clone()))
        .collect()
}

/// A line's seven fields (`Num RefCount Protocol Flags Type St Inode`) and
/// what follows them, the address, which may hold spaces.
fn fields_and_address(line: &str) -> Option<([&str; 7], &str)> {
    let mut rest = line;
    let mut fields = [""; 7];
    for field in &mut fields {
        rest = rest.trim_start();
        let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
        if end == 0 {
            return None;
        }
        *field = &rest[..end];
        rest = &rest[end..];
    }
    Some((fields, rest.trim()))
}

/// Whether `socket` takes a connection from this process now: it connects
/// without waiting, so a server too busy to take one counts, as it is there.
#[cfg(target_os = "linux")]
pub fn answers(socket: &Socket) -> bool {
    use rustix::io::Errno;
    use rustix::net::{AddressFamily, SocketAddrUnix, SocketFlags, SocketType};
    let Ok(fd) = rustix::net::socket_with(
        AddressFamily::UNIX,
        SocketType::from_raw(socket.kind),
        SocketFlags::NONBLOCK | SocketFlags::CLOEXEC,
        None,
    ) else {
        return false;
    };
    let address = match &socket.address {
        Address::Path(path) => SocketAddrUnix::new(path.as_path()),
        Address::Abstract(name) => SocketAddrUnix::new_abstract_name(name.as_bytes()),
    };
    let Ok(address) = address else {
        return false;
    };
    match rustix::net::connect(&fd, &address) {
        Ok(()) => true,
        Err(e) => e == Errno::AGAIN || e == Errno::INPROGRESS,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEADER: &str = "Num       RefCount Protocol Flags    Type St Inode Path\n";

    fn line(flags: &str, kind: &str, state: &str, inode: u64, path: &str) -> String {
        format!("0000000000000000: 00000002 00000000 {flags} {kind} {state} {inode:>8} {path}\n")
    }

    fn path(text: &str, kind: u32) -> Socket {
        Socket {
            address: Address::Path(PathBuf::from(text)),
            kind,
        }
    }

    #[test]
    fn a_table_gives_what_a_client_could_connect_to_each_address_once() {
        let table = [
            HEADER.to_owned(),
            line("00010000", "0001", "01", 1, "/run/user/1000/bus"),
            // Accepted connections show the listener's path: not again.
            line("00000000", "0001", "03", 2, "/run/user/1000/bus"),
            // A stream socket that does not listen: a client's.
            line("00000000", "0001", "03", 3, "/tmp/client.sock"),
            line("00010000", "0005", "01", 4, "/run/udev/control"),
            line("00000000", "0002", "01", 5, "/run/systemd/journal/socket"),
            line("00010000", "0001", "01", 6, "@/tmp/.X11-unix/X0"),
            line("00010000", "0001", "01", 7, "/home/a b/with space.sock"),
            // Bound to nothing.
            line("00010000", "0001", "01", 8, ""),
        ]
        .concat();
        assert_eq!(
            listening(&table),
            [
                path("/home/a b/with space.sock", STREAM),
                path("/run/systemd/journal/socket", DATAGRAM),
                path("/run/udev/control", SEQPACKET),
                path("/run/user/1000/bus", STREAM),
                Socket {
                    address: Address::Abstract("/tmp/.X11-unix/X0".to_owned()),
                    kind: STREAM,
                },
            ]
        );
    }

    #[test]
    fn a_line_that_does_not_read_is_left_out() {
        let table = [
            HEADER.to_owned(),
            "garbled\n".to_owned(),
            line("zz", "0001", "01", 1, "/run/a"),
            line("00010000", "0001", "01", 2, "/run/b"),
        ]
        .concat();
        assert_eq!(listening(&table), [path("/run/b", STREAM)]);
    }

    #[test]
    fn an_abstract_name_is_shown_after_an_at_sign() {
        assert_eq!(Address::Abstract("x".into()).shown(), "@x");
        assert_eq!(Address::Path("/run/x".into()).shown(), "/run/x");
    }
}
