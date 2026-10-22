//! The server name in a TLS ClientHello (design §6, server name check): the
//! client's first message on a tunnel, which travels unencrypted. Nothing is
//! decrypted; only the name the client asks the server for is read, from the
//! `server_name` extension, and whether the hello hides the real one
//! (Encrypted Client Hello).

/// The most of a client's first bytes read to find its hello: a ClientHello
/// with post-quantum key shares stays well under this.
pub const MAX_HELLO: usize = 64 * 1024;

/// What a client's first bytes say about the name it asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FirstBytes {
    /// Not all of the hello is there yet.
    Incomplete,
    /// The bytes are not a TLS handshake: another protocol, which the check
    /// leaves alone.
    NotTls,
    /// A TLS hello that does not parse.
    Unreadable,
    /// A ClientHello: the name it asks for, if any, and whether it hides the
    /// real one (ECH), in which case the name seen is the public one.
    ClientHello {
        server_name: Option<String>,
        encrypted: bool,
    },
}

const HANDSHAKE: u8 = 0x16;
const CLIENT_HELLO: u8 = 0x01;
const SERVER_NAME: u16 = 0x0000;
const ENCRYPTED_CLIENT_HELLO: u16 = 0xfe0d;

/// Reads the ClientHello in `bytes`, the first a client sent on a tunnel,
/// which may span several TLS records.
pub fn parse(bytes: &[u8]) -> FirstBytes {
    if bytes.is_empty() {
        return FirstBytes::Incomplete;
    }
    if bytes[0] != HANDSHAKE {
        return FirstBytes::NotTls;
    }
    // The handshake message, gathered from the records it spans.
    let mut handshake = Vec::new();
    let mut at = 0;
    loop {
        let Some(header) = bytes.get(at..at + 5) else {
            return FirstBytes::Incomplete;
        };
        if header[0] != HANDSHAKE || header[1] != 3 {
            return match handshake.is_empty() {
                true => FirstBytes::NotTls,
                false => FirstBytes::Unreadable,
            };
        }
        let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
        let Some(fragment) = bytes.get(at + 5..at + 5 + length) else {
            return FirstBytes::Incomplete;
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
            return FirstBytes::Incomplete;
        }
    }
}

/// The parts of a ClientHello's body this check reads.
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
    if !r.0.is_empty() {
        let extensions = usize::from(r.u16()?);
        let mut ext = Reader(r.take(extensions)?);
        while !ext.0.is_empty() {
            let kind = ext.u16()?;
            let length = usize::from(ext.u16()?);
            let data = ext.take(length)?;
            match kind {
                SERVER_NAME => server_name = host_name(data),
                ENCRYPTED_CLIENT_HELLO => encrypted = true,
                _ => {}
            }
        }
    }
    Some(FirstBytes::ClientHello {
        server_name,
        encrypted,
    })
}

/// The host name of a `server_name` extension.
fn host_name(data: &[u8]) -> Option<String> {
    let mut r = Reader(data);
    let list = usize::from(r.u16()?);
    let mut names = Reader(r.take(list)?);
    while !names.0.is_empty() {
        let kind = names.u8()?;
        let length = usize::from(names.u16()?);
        let name = names.take(length)?;
        if kind == 0 {
            return std::str::from_utf8(name).ok().map(str::to_owned);
        }
    }
    None
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
/// tunnel was opened for: compared without case or a final dot.
pub fn same_host(name: &str, host: &str) -> bool {
    let plain = |s: &str| s.trim_end_matches('.').to_ascii_lowercase();
    plain(name) == plain(host)
}

/// A ClientHello asking for `name`, with ECH when `encrypted`, in records
/// of at most `record` bytes: for tests here and in the proxy's.
#[cfg(test)]
pub fn client_hello_bytes(name: Option<&str>, encrypted: bool, record: usize) -> Vec<u8> {
    let mut extensions = Vec::new();
    if let Some(name) = name {
        let name = name.as_bytes();
        let mut list = vec![0];
        list.extend_from_slice(&(name.len() as u16).to_be_bytes());
        list.extend_from_slice(name);
        let mut data = (list.len() as u16).to_be_bytes().to_vec();
        data.extend_from_slice(&list);
        extensions.extend_from_slice(&SERVER_NAME.to_be_bytes());
        extensions.extend_from_slice(&(data.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&data);
    }
    if encrypted {
        extensions.extend_from_slice(&ENCRYPTED_CLIENT_HELLO.to_be_bytes());
        extensions.extend_from_slice(&4u16.to_be_bytes());
        extensions.extend_from_slice(&[0, 1, 2, 3]);
    }
    // Padding, as real hellos carry, so a hello spans records.
    extensions.extend_from_slice(&0x0015u16.to_be_bytes());
    extensions.extend_from_slice(&600u16.to_be_bytes());
    extensions.extend_from_slice(&[0; 600]);
    let mut body = vec![3, 3];
    body.extend_from_slice(&[7; 32]);
    body.push(0);
    body.extend_from_slice(&2u16.to_be_bytes());
    body.extend_from_slice(&[0x13, 0x01]);
    body.extend_from_slice(&[1, 0]);
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);
    let mut handshake = vec![CLIENT_HELLO];
    handshake.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    handshake.extend_from_slice(&body);
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

    #[test]
    fn the_name_a_hello_asks_for_is_read_across_records() {
        for record in [16_384, 100] {
            let bytes = client_hello_bytes(Some("api.example.com"), false, record);
            assert_eq!(
                parse(&bytes),
                FirstBytes::ClientHello {
                    server_name: Some("api.example.com".into()),
                    encrypted: false
                }
            );
            // Cut anywhere, it waits for the rest.
            for cut in [1, 5, 50, bytes.len() - 1] {
                assert_eq!(
                    parse(&bytes[..cut]),
                    FirstBytes::Incomplete,
                    "{record} {cut}"
                );
            }
        }
    }

    #[test]
    fn a_hello_with_no_name_or_an_encrypted_one_says_so() {
        assert_eq!(
            parse(&client_hello_bytes(None, false, 16_384)),
            FirstBytes::ClientHello {
                server_name: None,
                encrypted: false
            }
        );
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
    }

    #[test]
    fn other_protocols_and_broken_hellos_are_told_apart() {
        assert_eq!(parse(b""), FirstBytes::Incomplete);
        assert_eq!(parse(b"GET / HTTP/1.1\r\n"), FirstBytes::NotTls);
        assert_eq!(parse(b"SSH-2.0-OpenSSH\r\n"), FirstBytes::NotTls);
        // A handshake record that is not a ClientHello.
        assert_eq!(
            parse(&[0x16, 3, 1, 0, 4, 0x02, 0, 0, 0]),
            FirstBytes::Unreadable
        );
        // A ClientHello whose body is cut inside a length it states.
        let mut bad = client_hello_bytes(Some("a.example.com"), false, 16_384);
        let at = bad.len() - 601;
        bad[at] = 0xff;
        assert!(matches!(
            parse(&bad),
            FirstBytes::Unreadable | FirstBytes::ClientHello { .. }
        ));
    }

    #[test]
    fn names_compare_without_case_or_a_final_dot() {
        assert!(same_host("API.Example.com.", "api.example.com"));
        assert!(!same_host("evil.example.com", "api.example.com"));
    }
}
