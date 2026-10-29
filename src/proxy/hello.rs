//! The server name in a TLS ClientHello (design §6, server name check): the
//! client's first message on a tunnel, which travels unencrypted. Nothing is
//! decrypted; only the name the client asks the server for is read, from the
//! `server_name` extension, and whether the hello carries Encrypted Client
//! Hello.
//!
//! What a server could read another way is never taken for an answer: bytes
//! that start a TLS record are TLS, and anything in them that does not read
//! cleanly as one ClientHello, a malformed or repeated extension included,
//! is unreadable.

/// The most of a client's first bytes held to find its hello: a ClientHello
/// with post-quantum key shares stays well under this. A hello that is not
/// whole within it is unreadable, as soon as its records say it cannot be.
pub const MAX_HELLO: usize = 64 * 1024;

/// What a client's first bytes say about the name it asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FirstBytes {
    /// Not all of the hello is there yet: nothing changes before `needed`
    /// bytes are.
    Incomplete { needed: usize },
    /// The bytes do not start a TLS record: another protocol, which the
    /// check leaves alone.
    NotTls,
    /// TLS whose first message does not read as a ClientHello.
    Unreadable,
    /// A ClientHello: the name it asks for, if any, and whether it carries
    /// Encrypted Client Hello, when that name is its public one.
    ClientHello {
        server_name: Option<String>,
        encrypted: bool,
    },
}

const CHANGE_CIPHER_SPEC: u8 = 0x14;
const HANDSHAKE: u8 = 0x16;
/// The last TLS record type: heartbeat.
const LAST_RECORD_TYPE: u8 = 0x18;
const CLIENT_HELLO: u8 = 0x01;
/// The message type of an SSLv2-format ClientHello, after its length.
const SSL2_CLIENT_HELLO: u8 = 0x01;
const SERVER_NAME: u16 = 0x0000;
const ENCRYPTED_CLIENT_HELLO: u16 = 0xfe0d;
/// An `encrypted_client_hello` extension of the outer hello.
const ECH_OUTER: u8 = 0;

/// Reads the ClientHello in `bytes`, the first a client sent on a tunnel,
/// which may span several TLS records.
pub fn parse(bytes: &[u8]) -> FirstBytes {
    match bytes.first() {
        None => return FirstBytes::Incomplete { needed: 1 },
        Some(CHANGE_CIPHER_SPEC..=LAST_RECORD_TYPE) => {}
        // An SSLv2-format ClientHello (a two-byte length with its high bit
        // set, then CLIENT-HELLO): servers built on OpenSSL still take it
        // for TLS up to 1.2, and it can name no server, so it is closed as
        // unreadable rather than left alone as another protocol.
        Some(first) if first & 0x80 != 0 => match bytes.get(2) {
            None => return FirstBytes::Incomplete { needed: 3 },
            Some(&SSL2_CLIENT_HELLO) => return FirstBytes::Unreadable,
            Some(_) => return FirstBytes::NotTls,
        },
        Some(_) => return FirstBytes::NotTls,
    }
    // The handshake message, gathered from the records it spans. A server
    // reads TLS whatever else came first, so a first record of another type,
    // or a version that is not TLS's, is unreadable rather than not TLS.
    let mut handshake = Vec::new();
    let mut at = 0;
    loop {
        let Some(header) = bytes.get(at..at + 5) else {
            return FirstBytes::Incomplete { needed: at + 5 };
        };
        if header[0] != HANDSHAKE || header[1] != 3 {
            return FirstBytes::Unreadable;
        }
        let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
        let Some(fragment) = bytes.get(at + 5..at + 5 + length) else {
            return FirstBytes::Incomplete {
                needed: at + 5 + length,
            };
        };
        handshake.extend_from_slice(fragment);
        at += 5 + length;
        if handshake.len() >= 4 {
            if handshake[0] != CLIENT_HELLO {
                return FirstBytes::Unreadable;
            }
            let body = usize::from(handshake[1]) << 16
                | usize::from(handshake[2]) << 8
                | usize::from(handshake[3]);
            if handshake.len() >= 4 + body {
                return client_hello(&handshake[4..4 + body]).unwrap_or(FirstBytes::Unreadable);
            }
        }
        if at >= bytes.len() {
            return FirstBytes::Incomplete { needed: at + 5 };
        }
    }
}

/// The parts of a ClientHello's body this check reads; none when the body
/// does not read cleanly.
fn client_hello(body: &[u8]) -> Option<FirstBytes> {
    let mut r = Reader(body);
    r.take(2)?; // legacy version
    r.take(32)?; // random
    let session = usize::from(r.u8()?);
    r.take(session)?;
    let suites = usize::from(r.u16()?);
    r.take(suites)?;
    let compression = usize::from(r.u8()?);
    r.take(compression)?;
    let mut server_name = None;
    let mut encrypted = false;
    // A hello of TLS 1.2 and before may have no extensions at all.
    if !r.0.is_empty() {
        let extensions = usize::from(r.u16()?);
        let mut ext = Reader(r.take(extensions)?);
        let mut seen = Vec::new();
        while !ext.0.is_empty() {
            let kind = ext.u16()?;
            let length = usize::from(ext.u16()?);
            let data = ext.take(length)?;
            // A server might read the first of two, or the last.
            if seen.contains(&kind) {
                return None;
            }
            seen.push(kind);
            match kind {
                SERVER_NAME => server_name = Some(host_name(data)?),
                ENCRYPTED_CLIENT_HELLO => {
                    outer_ech(data)?;
                    encrypted = true;
                }
                _ => {}
            }
        }
    }
    if !r.0.is_empty() {
        return None;
    }
    Some(FirstBytes::ClientHello {
        server_name,
        encrypted,
    })
}

/// The host name of a `server_name` extension: its one entry of type
/// `host_name`, as text.
fn host_name(data: &[u8]) -> Option<String> {
    let mut r = Reader(data);
    let list = usize::from(r.u16()?);
    let mut names = Reader(r.take(list)?);
    if !r.0.is_empty() {
        return None;
    }
    let mut found = None;
    while !names.0.is_empty() {
        let kind = names.u8()?;
        let length = usize::from(names.u16()?);
        let name = names.take(length)?;
        if kind == 0 {
            // RFC 6066: one name of each type.
            if found.is_some() {
                return None;
            }
            found = Some(std::str::from_utf8(name).ok()?.to_owned());
        }
    }
    found
}

/// Checks an `encrypted_client_hello` extension reads as an outer hello's
/// (RFC 9849): its type, cipher suite, config id, encapsulated key and a
/// payload, and nothing after.
fn outer_ech(data: &[u8]) -> Option<()> {
    let mut r = Reader(data);
    if r.u8()? != ECH_OUTER {
        return None;
    }
    r.take(4)?; // cipher suite
    r.u8()?; // config id
    let enc = usize::from(r.u16()?);
    r.take(enc)?;
    let payload = usize::from(r.u16()?);
    if payload == 0 {
        return None;
    }
    r.take(payload)?;
    r.0.is_empty().then_some(())
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let (head, rest) = (self.0.get(..n)?, self.0.get(n..)?);
        self.0 = rest;
        Some(head)
    }

    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }

    fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|b| u16::from_be_bytes([b[0], b[1]]))
    }
}

/// Whether `name`, the server name a hello asks for, is `host`, the one the
/// tunnel was opened for: compared without case or one final dot.
pub fn same_host(name: &str, host: &str) -> bool {
    let plain = |s: &str| s.strip_suffix('.').unwrap_or(s).to_ascii_lowercase();
    plain(name) == plain(host)
}

/// A `server_name` extension naming `name`.
#[cfg(test)]
pub fn sni(name: &[u8]) -> (u16, Vec<u8>) {
    let mut list = vec![0];
    list.extend_from_slice(&(name.len() as u16).to_be_bytes());
    list.extend_from_slice(name);
    let mut data = (list.len() as u16).to_be_bytes().to_vec();
    data.extend_from_slice(&list);
    (SERVER_NAME, data)
}

/// An `encrypted_client_hello` extension as an outer hello carries it.
#[cfg(test)]
pub fn ech() -> (u16, Vec<u8>) {
    (
        ENCRYPTED_CLIENT_HELLO,
        vec![ECH_OUTER, 0, 1, 0, 1, 7, 0, 1, 0xee, 0, 2, 0xaa, 0xbb],
    )
}

/// A ClientHello asking for `name`, with ECH when `encrypted`, in records
/// of at most `record` bytes: for tests here and in the proxy's.
#[cfg(test)]
pub fn client_hello_bytes(name: Option<&str>, encrypted: bool, record: usize) -> Vec<u8> {
    let mut extensions: Vec<_> = name.map(|n| sni(n.as_bytes())).into_iter().collect();
    if encrypted {
        extensions.push(ech());
    }
    hello_with(&extensions, 600, record)
}

/// A ClientHello carrying `extensions` as they are, then `padding` bytes
/// of padding, as real hellos carry, in records of at most `record` bytes.
#[cfg(test)]
pub fn hello_with(extensions: &[(u16, Vec<u8>)], padding: usize, record: usize) -> Vec<u8> {
    let mut block = Vec::new();
    for (kind, data) in extensions {
        block.extend_from_slice(&kind.to_be_bytes());
        block.extend_from_slice(&(data.len() as u16).to_be_bytes());
        block.extend_from_slice(data);
    }
    block.extend_from_slice(&0x0015u16.to_be_bytes());
    block.extend_from_slice(&(padding as u16).to_be_bytes());
    block.extend(std::iter::repeat_n(0, padding));
    let mut body = vec![3, 3];
    body.extend_from_slice(&[7; 32]);
    body.push(0);
    body.extend_from_slice(&2u16.to_be_bytes());
    body.extend_from_slice(&[0x13, 0x01]);
    body.extend_from_slice(&[1, 0]);
    body.extend_from_slice(&(block.len() as u16).to_be_bytes());
    body.extend_from_slice(&block);
    in_records(&handshake_of(&body), record)
}

#[cfg(test)]
fn handshake_of(body: &[u8]) -> Vec<u8> {
    let mut handshake = vec![CLIENT_HELLO];
    handshake.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    handshake.extend_from_slice(body);
    handshake
}

#[cfg(test)]
fn in_records(handshake: &[u8], record: usize) -> Vec<u8> {
    let mut bytes = Vec::new();
    for fragment in handshake.chunks(record) {
        bytes.extend_from_slice(&[HANDSHAKE, 3, 1]);
        bytes.extend_from_slice(&(fragment.len() as u16).to_be_bytes());
        bytes.extend_from_slice(fragment);
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    fn named(name: &str) -> FirstBytes {
        FirstBytes::ClientHello {
            server_name: Some(name.into()),
            encrypted: false,
        }
    }

    #[test]
    fn the_name_a_hello_asks_for_is_read_across_records() {
        for record in [16_384, 100, 1] {
            let bytes = client_hello_bytes(Some("api.example.com"), false, record);
            assert_eq!(parse(&bytes), named("api.example.com"), "{record}");
            // Cut anywhere, it waits for the rest, and says how much more
            // must come before anything changes.
            for cut in 0..bytes.len() {
                match parse(&bytes[..cut]) {
                    FirstBytes::Incomplete { needed } => {
                        assert!(needed > cut && needed <= bytes.len(), "{record} {cut}")
                    }
                    other => panic!("{record} {cut}: {other:?}"),
                }
            }
            // What follows the hello changes nothing.
            let mut more = bytes.clone();
            more.extend_from_slice(&[0x17, 3, 3, 0, 2, 1, 2]);
            assert_eq!(parse(&more), named("api.example.com"));
        }
    }

    #[test]
    fn a_hello_with_no_name_or_with_ech_says_so() {
        let none = FirstBytes::ClientHello {
            server_name: None,
            encrypted: false,
        };
        assert_eq!(parse(&client_hello_bytes(None, false, 16_384)), none);
        assert_eq!(
            parse(&client_hello_bytes(
                Some("public.example.net"),
                true,
                16_384
            )),
            FirstBytes::ClientHello {
                server_name: Some("public.example.net".into()),
                encrypted: true
            }
        );
        // A TLS 1.2 hello may carry no extensions at all.
        let mut body = vec![3, 3];
        body.extend_from_slice(&[7; 32]);
        body.extend_from_slice(&[0, 0, 2, 0x00, 0x2f, 1, 0]);
        assert_eq!(parse(&in_records(&handshake_of(&body), 16_384)), none);
    }

    #[test]
    fn other_protocols_are_not_tls() {
        assert_eq!(parse(b""), FirstBytes::Incomplete { needed: 1 });
        for other in [
            &b"GET / HTTP/1.1\r\n"[..],
            b"SSH-2.0-OpenSSH\r\n",
            b"EHLO x\r\n",
            &[0x80, 1, 2],
        ] {
            assert_eq!(parse(other), FirstBytes::NotTls, "{other:?}");
        }
        // An SSLv2-format ClientHello names no server: closed, not let by.
        assert_eq!(parse(&[0x80, 0x2e]), FirstBytes::Incomplete { needed: 3 });
        assert_eq!(parse(&[0x80, 0x2e, 0x01, 3, 1]), FirstBytes::Unreadable);
    }

    /// Only an entry of type `host_name` names the server, as a server
    /// reads it: an extension with one of another type alone is
    /// unreadable, and beside a `host_name` it is skipped.
    #[test]
    fn only_a_host_name_entry_names_the_server() {
        let entries = |list: &[(u8, &[u8])]| {
            let mut names = Vec::new();
            for (kind, name) in list {
                names.push(*kind);
                names.extend_from_slice(&(name.len() as u16).to_be_bytes());
                names.extend_from_slice(name);
            }
            let mut data = (names.len() as u16).to_be_bytes().to_vec();
            data.extend_from_slice(&names);
            parse(&hello_with(&[(SERVER_NAME, data)], 10, 16_384))
        };
        assert_eq!(entries(&[(1, b"api.example.com")]), FirstBytes::Unreadable);
        assert_eq!(
            entries(&[(1, b"evil.example.com"), (0, b"api.example.com")]),
            named("api.example.com")
        );
    }

    #[test]
    fn tls_that_does_not_read_cleanly_as_one_hello_is_unreadable() {
        let good = client_hello_bytes(Some("evil.example.com"), false, 100);
        let changed = |at: usize, byte: u8| {
            let mut bytes = good.clone();
            bytes[at] = byte;
            parse(&bytes)
        };
        // A first record of another version than TLS's.
        assert_eq!(changed(1, 0), FirstBytes::Unreadable);
        // A later record of another type or version.
        assert_eq!(changed(105, 0x17), FirstBytes::Unreadable);
        assert_eq!(changed(106, 2), FirstBytes::Unreadable);
        // A warning alert, or a change of cipher spec, before the hello.
        for first in [[0x15, 3, 1, 0, 2, 1, 0x5a], [0x14, 3, 1, 0, 1, 1, 0]] {
            assert_eq!(parse(&[&first[..], &good].concat()), FirstBytes::Unreadable);
        }
        // A handshake that is not a ClientHello.
        assert_eq!(
            parse(&[0x16, 3, 1, 0, 4, 0x02, 0, 0, 0]),
            FirstBytes::Unreadable
        );
        let unreadable = |extensions: &[(u16, Vec<u8>)]| {
            assert_eq!(
                parse(&hello_with(extensions, 10, 16_384)),
                FirstBytes::Unreadable,
                "{extensions:?}"
            )
        };
        // A name list longer than its extension, one cut short, a name not
        // UTF-8, two host names, two name extensions.
        let (kind, mut long) = sni(b"evil.example.com");
        long[1] += 1;
        unreadable(&[(kind, long)]);
        let (kind, short) = sni(b"evil.example.com");
        unreadable(&[(kind, short[..short.len() - 1].to_vec())]);
        unreadable(&[sni(b"evil\xff.example.com")]);
        let (kind, mut twice) = sni(b"evil.example.com");
        twice.extend_from_slice(&[0, 0, 3, b'a', b'.', b'b']);
        let list = (twice.len() - 2) as u16;
        twice[..2].copy_from_slice(&list.to_be_bytes());
        unreadable(&[(kind, twice)]);
        unreadable(&[sni(b"evil.example.com"), sni(b"api.example.com")]);
        // An ECH extension that is not an outer hello's.
        unreadable(&[sni(b"evil.example.com"), (0xfe0d, vec![0, 1, 2, 3])]);
        unreadable(&[sni(b"evil.example.com"), (0xfe0d, vec![1])]);
        // An extensions block longer than the hello: the padding's length
        // past its data.
        let one = client_hello_bytes(Some("evil.example.com"), false, 16_384);
        let mut bad = one.clone();
        let at = bad.len() - 601;
        bad[at] = 0xff;
        assert_eq!(parse(&bad), FirstBytes::Unreadable);
    }

    #[test]
    fn names_compare_without_case_or_one_final_dot() {
        assert!(same_host("API.Example.com.", "api.example.com"));
        assert!(!same_host("api.example.com..", "api.example.com"));
        assert!(!same_host("evil.example.com", "api.example.com"));
        assert!(!same_host("[::1]", "::1"));
        // A tunnel opened for an address: any name in its hello is another.
        assert!(!same_host("evil.example.com", "127.0.0.1"));
        assert!(!same_host("evil.example.com", "::1"));
    }
}
