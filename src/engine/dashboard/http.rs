//! The local dashboard's URL capability, held only by the host process
//! and the URL it prints. Each HTTP connection checks and rewrites its first
//! request and asks the runtime to close. Only a confirmed WebSocket 101
//! response turns the connection into a byte relay.

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::os::unix::net::UnixStream;
use std::time::Duration;

const MAX_HEADERS: usize = 64 * 1024;
const HEADER_WAIT: Duration = Duration::from_secs(5);

pub(super) struct Request {
    pub bytes: Vec<u8>,
    pub upgrade: bool,
}

pub(super) fn authorize(client: &mut TcpStream, prefix: &str) -> io::Result<Request> {
    client.set_read_timeout(Some(HEADER_WAIT))?;
    let bytes = read_headers(client)?;
    let end = header_end(&bytes).expect("read_headers found the terminator");
    let request = rewrite(&bytes, end, prefix)?;
    client.set_read_timeout(None)?;
    Ok(request)
}

fn header_end(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(4)
        .position(|part| part == b"\r\n\r\n")
        .map(|n| n + 4)
}

fn read_headers(stream: &mut impl Read) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    loop {
        if header_end(&bytes).is_some() {
            return Ok(bytes);
        }
        if bytes.len() == MAX_HEADERS {
            return Err(io::Error::new(
                io::ErrorKind::FileTooLarge,
                "dashboard headers exceed 64 KiB",
            ));
        }
        let mut part = [0; 4096];
        let left = part.len().min(MAX_HEADERS - bytes.len());
        let n = stream.read(&mut part[..left])?;
        if n == 0 {
            return Err(invalid());
        }
        bytes.extend_from_slice(&part[..n]);
    }
}

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid dashboard request")
}

fn tchar(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}

fn rewrite(bytes: &[u8], headers_end: usize, prefix: &str) -> io::Result<Request> {
    let mut lines = bytes[..headers_end - 2].split(|byte| *byte == b'\n');
    let first = lines
        .next()
        .and_then(|line| line.strip_suffix(b"\r"))
        .ok_or_else(invalid)?;
    let words: Vec<_> = first.split(|byte| *byte == b' ').collect();
    if words.len() != 3
        || words[0].is_empty()
        || !words[0].iter().copied().all(tchar)
        || !matches!(words[2], b"HTTP/1.1" | b"HTTP/1.0")
        || !words[1].iter().all(|byte| (0x21..=0x7e).contains(byte))
    {
        return Err(invalid());
    }
    let suffix = words[1]
        .strip_prefix(prefix.trim_end_matches('/').as_bytes())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "dashboard capability required",
            )
        })?;
    let mut path = Vec::new();
    match suffix.first() {
        None | Some(b'?') => path.push(b'/'),
        Some(b'/') => {}
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "dashboard capability required",
            ));
        }
    }
    path.extend_from_slice(suffix);
    let mut result = Vec::new();
    result.extend_from_slice(words[0]);
    result.push(b' ');
    result.extend_from_slice(&path);
    result.push(b' ');
    result.extend_from_slice(words[2]);
    result.extend_from_slice(b"\r\n");
    let mut upgrade = false;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let line = line.strip_suffix(b"\r").ok_or_else(invalid)?;
        if line.is_empty() {
            continue;
        }
        let colon = line
            .iter()
            .position(|byte| *byte == b':')
            .ok_or_else(invalid)?;
        let (key, value) = (&line[..colon], &line[colon + 1..]);
        if key.is_empty()
            || !key.iter().copied().all(tchar)
            || value
                .iter()
                .any(|byte| (*byte < 0x20 && *byte != b'\t') || *byte == 0x7f)
        {
            return Err(invalid());
        }
        if key.eq_ignore_ascii_case(b"upgrade") {
            upgrade = value.trim_ascii().eq_ignore_ascii_case(b"websocket");
        }
        if ![
            b"connection".as_slice(),
            b"proxy-connection",
            b"x-forwarded-prefix",
        ]
        .iter()
        .any(|name| key.eq_ignore_ascii_case(name))
        {
            result.extend_from_slice(line);
            result.extend_from_slice(b"\r\n");
        }
    }
    result.extend_from_slice(
        format!(
            "X-Forwarded-Prefix: {}\r\nConnection: {}\r\n\r\n",
            prefix.trim_end_matches('/'),
            if upgrade { "Upgrade" } else { "close" }
        )
        .as_bytes(),
    );
    result.extend_from_slice(&bytes[headers_end..]);
    Ok(Request {
        bytes: result,
        upgrade,
    })
}

pub(super) fn reject(client: &mut TcpStream, error: &io::Error) {
    let status = match error.kind() {
        io::ErrorKind::PermissionDenied => "403 Forbidden",
        io::ErrorKind::FileTooLarge => "431 Request Header Fields Too Large",
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => "408 Request Timeout",
        _ => "400 Bad Request",
    };
    respond(client, status);
}

fn respond(client: &mut TcpStream, status: &str) {
    let body = format!("{status}\n");
    let _ = client.set_write_timeout(Some(HEADER_WAIT));
    let _ = write!(
        client,
        "HTTP/1.1 {status}\r\nConnection: close\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    // Closing with unread request bytes resets TCP on macOS and can erase
    // the response before the browser sees it. Send FIN, then drain briefly
    // within a fixed byte budget; an error response never becomes a relay.
    let _ = client.shutdown(std::net::Shutdown::Write);
    let _ = client.set_read_timeout(Some(Duration::from_millis(200)));
    let mut remaining = MAX_HEADERS;
    let mut bytes = [0; 4096];
    let deadline = std::time::Instant::now() + Duration::from_millis(200);
    while remaining > 0 && std::time::Instant::now() < deadline {
        let limit = remaining.min(bytes.len());
        match client.read(&mut bytes[..limit]) {
            Ok(0) | Err(_) => break,
            Ok(n) => remaining -= n,
        }
    }
}

/// Do not tunnel an Upgrade attempt until the runtime actually switches.
/// A rejected handshake gets a complete error response and closes, even if
/// the runtime tries to keep that connection alive.
pub(super) fn begin(
    client: &mut TcpStream,
    upstream: &mut UnixStream,
    request: Request,
) -> io::Result<()> {
    upstream.set_write_timeout(Some(HEADER_WAIT))?;
    upstream.write_all(&request.bytes)?;
    if request.upgrade {
        upstream.set_read_timeout(Some(HEADER_WAIT))?;
        let answer = read_headers(upstream)?;
        let status = answer
            .split(|byte| *byte == b'\n')
            .next()
            .unwrap_or_default();
        if !status.starts_with(b"HTTP/1.1 101 ") {
            respond(client, "502 Bad Gateway");
            return Err(io::Error::other("dashboard refused WebSocket upgrade"));
        }
        client.set_write_timeout(Some(HEADER_WAIT))?;
        client.write_all(&answer)?;
        upstream.set_read_timeout(None)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(text: &[u8]) -> io::Result<Vec<u8>> {
        let end = text
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .unwrap()
            + 4;
        rewrite(text, end, "/capability/").map(|request| request.bytes)
    }

    #[test]
    fn the_capability_is_required_before_any_request_is_forwarded() {
        for path in [
            "/",
            "/api/auth/me",
            "/wrong/",
            "/capability-wrong/",
            "http://127.0.0.1/capability/",
        ] {
            assert!(
                request(format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n").as_bytes())
                    .is_err()
            );
        }
    }

    #[test]
    fn legal_header_names_and_opaque_values_are_preserved() {
        let out =
            request(b"GET /capability/ HTTP/1.1\r\nX_Trace.Id!#$%&'*+^`|~: \xff\r\n\r\n").unwrap();
        let field = b"X_Trace.Id!#$%&'*+^`|~: \xff\r\n";
        assert!(out.windows(field.len()).any(|part| part == field));
    }

    #[test]
    fn large_localhost_cookies_are_accepted_and_header_limits_are_explicit() {
        let text = format!(
            "GET /capability/ HTTP/1.1\r\nCookie: {}\r\n\r\n",
            "x".repeat(32 * 1024)
        );
        assert!(request(text.as_bytes()).is_ok());
        let too_large = vec![b'x'; MAX_HEADERS + 1];
        assert_eq!(
            read_headers(&mut io::Cursor::new(too_large))
                .unwrap_err()
                .kind(),
            io::ErrorKind::FileTooLarge
        );
        for text in [
            b"GET /capability/ HTTP/1.1\r\nBad Name: x\r\n\r\n".as_slice(),
            b"GET /capability/ HTTP/1.1\r\nGood: bad\x01value\r\n\r\n",
        ] {
            assert_eq!(
                request(text).unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
        }
        for (kind, status) in [
            (io::ErrorKind::InvalidData, "400 Bad Request"),
            (
                io::ErrorKind::FileTooLarge,
                "431 Request Header Fields Too Large",
            ),
        ] {
            let listener = crate::test_ports::tcp_listener(std::net::Ipv4Addr::LOCALHOST);
            let mut browser = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            let (mut server, _) = listener.accept().unwrap();
            reject(&mut server, &io::Error::new(kind, "invalid"));
            drop(server);
            let mut answer = String::new();
            browser.read_to_string(&mut answer).unwrap();
            assert!(answer.starts_with(&format!("HTTP/1.1 {status}\r\n")));
            assert!(answer.ends_with(&format!("{status}\n")));
        }
    }

    #[test]
    fn a_rejected_upgrade_cannot_relay_a_later_request() {
        let listener = crate::test_ports::tcp_listener(std::net::Ipv4Addr::LOCALHOST);
        let mut browser = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        browser.set_read_timeout(Some(HEADER_WAIT)).unwrap();
        let (mut client, _) = listener.accept().unwrap();
        let (mut upstream, mut runtime) = UnixStream::pair().unwrap();
        let server = std::thread::spawn(move || {
            runtime.set_read_timeout(Some(HEADER_WAIT)).unwrap();
            let _request = read_headers(&mut runtime).unwrap();
            runtime
                .write_all(
                    b"HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nContent-Length: 0\r\n\r\n",
                )
                .unwrap();
            let mut later = Vec::new();
            runtime.read_to_end(&mut later).unwrap();
            assert!(
                later.is_empty(),
                "relayed a request after a rejected upgrade"
            );
        });
        let bytes = b"GET /capability/ws HTTP/1.1\r\nUpgrade: websocket\r\n\r\n";
        let request = rewrite(bytes, bytes.len(), "/capability/").unwrap();
        browser
            .write_all(b"GET /capability/later HTTP/1.1\r\n\r\n")
            .unwrap();
        assert!(begin(&mut client, &mut upstream, request).is_err());
        drop(upstream);
        let _ = client.shutdown(std::net::Shutdown::Both);
        drop(client);
        let mut answer = String::new();
        let _ = browser.read_to_string(&mut answer);
        assert!(answer.starts_with("HTTP/1.1 502 Bad Gateway\r\n"));
        server.join().unwrap();
    }

    #[test]
    fn an_oversized_request_receives_431_despite_its_unread_remainder() {
        let listener = crate::test_ports::tcp_listener(std::net::Ipv4Addr::LOCALHOST);
        let mut browser = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        browser.set_read_timeout(Some(HEADER_WAIT)).unwrap();
        let server = std::thread::spawn(move || {
            let (mut client, _) = listener.accept().unwrap();
            let error = authorize(&mut client, "/capability/")
                .err()
                .expect("oversized");
            reject(&mut client, &error);
        });
        let request = format!(
            "GET /capability/ HTTP/1.1\r\nCookie: {}\r\n\r\n",
            "x".repeat(70000)
        );
        let _ = browser.write_all(request.as_bytes());
        let mut response = String::new();
        browser.read_to_string(&mut response).unwrap();
        assert!(response.starts_with("HTTP/1.1 431 Request Header Fields Too Large\r\n"));
        server.join().unwrap();
    }

    #[test]
    fn a_browser_can_refresh_the_basename_without_a_trailing_slash() {
        for path in ["/capability", "/capability?profile=default"] {
            let out = request(format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n").as_bytes())
                .unwrap();
            let target = if path.contains('?') {
                "/?profile=default"
            } else {
                "/"
            };
            assert!(
                String::from_utf8(out)
                    .unwrap()
                    .starts_with(&format!("GET {target} HTTP/1.1\r\n"))
            );
        }
    }

    #[test]
    fn paths_and_proxy_headers_are_rewritten_without_losing_query_body_or_websocket_upgrade() {
        let out = request(b"POST /capability/api/chat?profile=default HTTP/1.1\r\nHost: localhost\r\nX-Forwarded-Prefix: /forged\r\nConnection: keep-alive\r\nContent-Length: 3\r\n\r\nabc").unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(out.starts_with("POST /api/chat?profile=default HTTP/1.1\r\n"));
        assert!(out.contains("X-Forwarded-Prefix: /capability\r\nConnection: close\r\n"));
        assert!(!out.contains("forged") && !out.contains("keep-alive"));
        assert!(out.ends_with("\r\n\r\nabc"));
        let out = request(
            b"GET /capability/api/ws HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
        )
        .unwrap();
        assert!(
            String::from_utf8(out)
                .unwrap()
                .contains("Connection: Upgrade\r\n")
        );
    }
}
