//! The TCP tables and the ephemeral port range, as `/proc` writes them.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;

use super::proc_error;
use crate::lifecycle::descriptors;
use crate::lifecycle::listeners::ListenersError;

/// The listening sockets in the network tables `net` holds, by inode.
/// `None` when `tcp` is missing: no thread runs behind `net` (the process is
/// gone, or this is the folder of a main thread that exited). `tcp6` is
/// missing on a kernel without IPv6.
pub(super) fn listening_sockets(
    net: &Path,
) -> Result<Option<BTreeMap<u64, SocketAddr>>, ListenersError> {
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

/// `TCP_ESTABLISHED`, as `/proc/net/tcp` writes a socket's state.
const ESTABLISHED: &str = "01";

/// The owner of the socket at `client` connected to `server`, from
/// `tables`, the texts of `/proc/net/tcp` and `tcp6`: the uid its line
/// gives, when its lines give exactly one. Only an established connection's
/// line counts: one in another state may name no owner, as a `TIME_WAIT`
/// line gives uid 0. A line that cannot be read names no one.
pub(super) fn client_owner(
    tables: &[String],
    client: SocketAddr,
    server: SocketAddr,
) -> Option<u32> {
    let mut owners = BTreeSet::new();
    for line in tables.iter().flat_map(|table| table.lines().skip(1)) {
        let words: Vec<&str> = line.split_whitespace().collect();
        let [_, local, remote, state, _, _, _, uid, ..] = words.as_slice() else {
            continue;
        };
        if *state == ESTABLISHED
            && table_address(local) == Some(client)
            && table_address(remote) == Some(server)
            && let Ok(uid) = uid.parse::<u32>()
        {
            owners.insert(uid);
        }
    }
    let mut owners = owners.into_iter();
    match (owners.next(), owners.next()) {
        (Some(owner), None) => Some(owner),
        _ => None,
    }
}

/// `0100007F:1F90`, or 32 hexadecimal digits before the colon for IPv6: each
/// group of 8 is a 32-bit word of the address as this host's `%08X` prints
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

/// The two ports `ip_local_port_range` holds, and nothing else.
pub(super) fn port_range(text: &str) -> Option<(u16, u16)> {
    let mut words = text.split_whitespace();
    let range = (words.next()?.parse().ok()?, words.next()?.parse().ok()?);
    words.next().is_none().then_some(range)
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;

    /// A line of `/proc/net/tcp` for a socket in `state`.
    pub(in crate::lifecycle::proc) fn socket(local: &str, state: &str, inode: u64) -> String {
        format!(
            "   0: {local} 00000000:0000 {state} 00000000:00000000 00:00000000 00000000  1000        0 {inode} 1 0000000000000000 100 0 0 10 0\n"
        )
    }

    /// A line of `/proc/net/tcp` for a connection from `local` to
    /// `remote` in `state`, whose socket `uid` owns.
    fn connection(local: &str, remote: &str, state: &str, uid: u32) -> String {
        format!(
            "   1: {local} {remote} {state} 00000000:00000000 00:00000000 00000000  {uid}        0 4242 1 0000000000000000 20 4 30 10 -1\n"
        )
    }

    const HEADER: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n";

    /// Network tables in a `/proc` of a test's own.
    pub(in crate::lifecycle::proc) fn fake_net(net: &Path, tcp: &str) {
        std::fs::create_dir_all(net).unwrap();
        std::fs::write(net.join("tcp"), format!("{HEADER}{tcp}")).unwrap();
    }

    #[test]
    fn the_ephemeral_range_of_proc_is_two_ports() {
        assert_eq!(port_range("32768\t60999\n"), Some((32768, 60999)));
        for odd in ["", "32768", "1 2 3", "a b", "1 70000"] {
            assert_eq!(port_range(odd), None, "{odd}");
        }
    }

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

    /// From 127.0.0.1:50000 to 127.0.0.1:41001, as the client's line and
    /// the server's write them, and a v4-mapped client in `tcp6`.
    #[test]
    fn a_clients_owner_is_its_established_lines_uid_and_no_other() {
        let a = |s: &str| s.parse::<SocketAddr>().unwrap();
        let (client, server) = (a("127.0.0.1:50000"), a("127.0.0.1:41001"));
        let (c, s) = ("0100007F:C350", "0100007F:A029");
        let v4 = |lines: &[String]| vec![format!("{HEADER}{}", lines.concat())];
        let owner = |tables: &[String]| client_owner(tables, client, server);
        // The server's own end names the server's user, not the client's.
        let both = [connection(c, s, "01", 1001), connection(s, c, "01", 1000)];
        assert_eq!(owner(&v4(&both)), Some(1001));
        // Gone, closing or in TIME_WAIT: no owner to give.
        assert_eq!(owner(&v4(&[connection(s, c, "01", 1000)])), None);
        for state in ["06", "08", "04"] {
            assert_eq!(
                owner(&v4(&[connection(c, s, state, 1001)])),
                None,
                "{state}"
            );
        }
        // Another client, or a client of another server.
        let other = [connection("0100007F:C351", s, "01", 1001)];
        assert_eq!(owner(&v4(&other)), None);
        let elsewhere = [connection(c, "0100007F:A02A", "01", 1001)];
        assert_eq!(owner(&v4(&elsewhere)), None);
        // Two lines that disagree name no one.
        let two = [connection(c, s, "01", 1001), connection(c, s, "01", 0)];
        assert_eq!(owner(&v4(&two)), None);
        // A dual-stack client's IPv4 connection is in tcp6, v4-mapped.
        let mapped = connection(
            "0000000000000000FFFF00000100007F:C350",
            "0000000000000000FFFF00000100007F:A029",
            "01",
            0,
        );
        let tables = [v4(&[]), vec![format!("{HEADER}{mapped}")]].concat();
        assert_eq!(owner(&tables), Some(0));
        // A line that cannot be read names no one.
        let garbled = [connection(c, s, "01", 1001).replace(" 1001 ", " x ")];
        assert_eq!(owner(&v4(&garbled)), None);
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
}
