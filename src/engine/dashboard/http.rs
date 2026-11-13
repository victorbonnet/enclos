//! The local dashboard's URL capability. A same-uid sandbox could retain
//! access to a proxy port from another enclos install. It must also know
//! the random path kept in this install's host-only dashboard lock.
//!
//! Each ordinary HTTP request closes its connection, so every request is
//! checked and rewritten. WebSocket upgrades become a byte-for-byte relay.

use std::io::{self, Read};
use std::net::TcpStream;
use std::time::Duration;

const MAX_HEADERS: usize = 16 * 1024;

pub(super) fn authorize(client: &mut TcpStream, prefix: &str) -> io::Result<Vec<u8>> {
    client.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut bytes = Vec::new();
    loop {
        if let Some(end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            let request = rewrite(&bytes, end + 4, prefix)?;
            client.set_read_timeout(None)?;
            return Ok(request);
        }
        if bytes.len() == MAX_HEADERS {
            return Err(refused());
        }
        let mut part = [0; 1024];
        let left = part.len().min(MAX_HEADERS - bytes.len());
        let n = client.read(&mut part[..left])?;
        if n == 0 {
            return Err(refused());
        }
        bytes.extend_from_slice(&part[..n]);
    }
}

fn refused() -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, "invalid dashboard request")
}

fn rewrite(bytes: &[u8], headers_end: usize, prefix: &str) -> io::Result<Vec<u8>> {
    let headers = std::str::from_utf8(&bytes[..headers_end]).map_err(|_| refused())?;
    let mut lines = headers.split("\r\n");
    let first = lines.next().ok_or_else(refused)?;
    let words: Vec<_> = first.split(' ').collect();
    if words.len() != 3 || !matches!(words[2], "HTTP/1.1" | "HTTP/1.0") {
        return Err(refused());
    }
    let suffix = words[1]
        .strip_prefix(prefix.trim_end_matches('/'))
        .ok_or_else(refused)?;
    let path = match suffix.as_bytes().first() {
        None => "/".to_owned(),
        Some(b'/') => suffix.to_owned(),
        Some(b'?') => format!("/{suffix}"),
        _ => return Err(refused()),
    };
    let mut fields = Vec::new();
    let mut upgrade = false;
    for line in lines.filter(|line| !line.is_empty()) {
        let (key, value) = line.split_once(':').ok_or_else(refused)?;
        if key.is_empty()
            || !key
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(refused());
        }
        if key.eq_ignore_ascii_case("upgrade") {
            upgrade = value.trim().eq_ignore_ascii_case("websocket");
        }
        if !["connection", "proxy-connection", "x-forwarded-prefix"]
            .iter()
            .any(|name| key.eq_ignore_ascii_case(name))
        {
            fields.push(line);
        }
    }
    let mut result = format!("{} {} {}\r\n", words[0], path, words[2]);
    for line in fields {
        result.push_str(line);
        result.push_str("\r\n");
    }
    result.push_str(&format!(
        "X-Forwarded-Prefix: {}\r\nConnection: {}\r\n\r\n",
        prefix.trim_end_matches('/'),
        if upgrade { "Upgrade" } else { "close" }
    ));
    let mut result = result.into_bytes();
    result.extend_from_slice(&bytes[headers_end..]);
    Ok(result)
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
        rewrite(text, end, "/capability/")
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
