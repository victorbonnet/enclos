//! Reading what a client asks the proxy for: `CONNECT host:port` for a
//! tunnel, or a plain-HTTP request with an absolute URL.

use std::io::{self, Read};

/// The most a request head may take before the proxy gives up on it.
pub const MAX_HEAD: usize = 16 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    /// `CONNECT host:port`: a tunnel, usually TLS.
    Connect { host: String, port: u16 },
    /// A plain-HTTP request with an absolute URL, to forward as origin-form.
    Http {
        method: String,
        host: String,
        port: u16,
        /// The path and query, starting with `/`.
        path: String,
        version: String,
        /// The header lines after the request line, without the final blank line.
        headers: Vec<String>,
        /// The length of the body that follows the head: its
        /// `Content-Length`, or 0 without one. The proxy forwards that much
        /// and no more, so the connection carries this one request. `None`
        /// when the head does not say where the body ends, or holds a line
        /// a server could read another way: the proxy refuses the request
        /// once it knows the destination, so the refusal is recorded.
        body: Option<u64>,
    },
}

/// Reads up to the end of the request head. Returns the head and any bytes
/// the client already sent after it.
pub fn read_head(stream: &mut impl Read) -> io::Result<(String, Vec<u8>)> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    loop {
        if let Some(end) = find(&buf, b"\r\n\r\n") {
            let rest = buf.split_off(end + 4);
            let head = String::from_utf8(buf)
                .map_err(|_| io::Error::other("request head is not UTF-8"))?;
            return Ok((head, rest));
        }
        if buf.len() > MAX_HEAD {
            return Err(io::Error::other("request head too long"));
        }
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "client closed before a full request",
            ));
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Parses a request head; `None` for anything the proxy does not serve.
pub fn parse(head: &str) -> Option<Request> {
    let mut lines = head.split("\r\n").filter(|l| !l.is_empty());
    let mut parts = lines.next()?.split(' ');
    let (method, target, version) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() || !matches!(version, "HTTP/1.0" | "HTTP/1.1") || !is_token(method) {
        return None;
    }
    if method.eq_ignore_ascii_case("CONNECT") {
        let (host, port) = split_host_port(target, None)?;
        return Some(Request::Connect { host, port });
    }
    let rest = target
        .strip_prefix("http://")
        .or_else(|| target.strip_prefix("HTTP://"))?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    // The path goes upstream as it is, so a CR or LF in it would end the
    // request line early.
    if authority.contains('@') || path.bytes().any(|b| b.is_ascii_control()) {
        return None;
    }
    let (host, port) = split_host_port(authority, Some(80))?;
    let headers: Vec<String> = lines.map(str::to_owned).collect();
    let body = body_length(&headers);
    Some(Request::Http {
        method: method.to_owned(),
        host,
        port,
        path: path.to_owned(),
        version: version.to_owned(),
        headers,
        body,
    })
}

/// The length of a plain-HTTP request's body: its `Content-Length`, or 0
/// without one. `None` when the proxy and the server could split what
/// follows the head differently, so that part of it could be read as a
/// second request: a `Transfer-Encoding`, lengths that are not one number
/// that fits in 64 bits, or a header line a server could read another way,
/// one without a `:`, with a name that is not a token (whitespace around
/// it, or a folded line), or with a control character other than a tab in
/// its value (a bare CR or LF would end the line early).
fn body_length(headers: &[String]) -> Option<u64> {
    let mut length = None;
    for line in headers {
        let (name, value) = line.split_once(':')?;
        if !is_token(name) || value.bytes().any(|b| b.is_ascii_control() && b != b'\t') {
            return None;
        }
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return None;
        }
        if !name.eq_ignore_ascii_case("content-length") {
            continue;
        }
        for value in value.split(',').map(|v| v.trim_matches([' ', '\t'])) {
            if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            let value: u64 = value.parse().ok()?;
            if length.is_some_and(|l| l != value) {
                return None;
            }
            length = Some(value);
        }
    }
    Some(length.unwrap_or(0))
}

/// Whether `text` is an HTTP token, as a method must be.
fn is_token(text: &str) -> bool {
    !text.is_empty()
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}

fn split_host_port(authority: &str, default: Option<u16>) -> Option<(String, u16)> {
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let (ip, after) = rest.split_once(']')?;
        (ip, after.strip_prefix(':'))
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (authority, None),
        }
    };
    let port = match port {
        Some(p) => p.parse().ok().filter(|p| *p != 0)?,
        None => default?,
    };
    (!host.is_empty()).then(|| (host.to_owned(), port))
}

/// The head to send upstream for a plain-HTTP request: origin-form, without
/// the proxy's own headers, and closed after one exchange. `Host` is made
/// from the authorized `host` and `port`, never taken from the client: a
/// different one could reach another site on the same address. A
/// `Content-Length` is sent as the one number `body` the proxy read from
/// the client's, so the server cannot read it another way.
pub fn origin_head(
    method: &str,
    path: &str,
    version: &str,
    headers: &[String],
    host: &str,
    port: u16,
    body: u64,
) -> String {
    let mut head = format!("{method} {path} {version}\r\n");
    let host = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_owned()
    };
    match port {
        80 => head.push_str(&format!("Host: {host}\r\n")),
        port => head.push_str(&format!("Host: {host}:{port}\r\n")),
    }
    let mut sent_length = false;
    for line in headers {
        let name = line
            .split(':')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        if matches!(
            name.as_str(),
            "host" | "proxy-connection" | "proxy-authorization" | "connection" | "keep-alive"
        ) {
            continue;
        }
        if name == "content-length" {
            if !sent_length {
                head.push_str(&format!("Content-Length: {body}\r\n"));
                sent_length = true;
            }
            continue;
        }
        head.push_str(line);
        head.push_str("\r\n");
    }
    head.push_str("Connection: close\r\n\r\n");
    head
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_and_absolute_requests_parse() {
        assert_eq!(
            parse("CONNECT api.example.com:443 HTTP/1.1\r\nHost: api.example.com:443\r\n\r\n"),
            Some(Request::Connect {
                host: "api.example.com".into(),
                port: 443
            })
        );
        assert_eq!(
            parse("CONNECT [2606:4700::1111]:443 HTTP/1.1\r\n\r\n"),
            Some(Request::Connect {
                host: "2606:4700::1111".into(),
                port: 443
            })
        );
        let Some(Request::Http {
            host, port, path, ..
        }) = parse("GET http://example.com:8080/a?b=1 HTTP/1.1\r\nHost: example.com\r\n\r\n")
        else {
            panic!("not parsed");
        };
        assert_eq!(
            (host.as_str(), port, path.as_str()),
            ("example.com", 8080, "/a?b=1")
        );
    }

    #[test]
    fn requests_the_proxy_does_not_serve_are_refused() {
        for bad in [
            "GET /relative HTTP/1.1\r\n\r\n",
            "CONNECT example.com HTTP/1.1\r\n\r\n",
            "CONNECT example.com:0 HTTP/1.1\r\n\r\n",
            "GET http://user@example.com/ HTTP/1.1\r\n\r\n",
            "GET https://example.com/ HTTP/1.1\r\n\r\n",
            "BREW pot HTCPCP/1.0\r\n\r\n",
            "GET http://example.com/ HTTP/1.9x\r\n\r\n",
            "G\x1b[2JET http://example.com/ HTTP/1.1\r\n\r\n",
            "GET http://example.com/a\nb HTTP/1.1\r\n\r\n",
        ] {
            assert_eq!(parse(bad), None, "{bad}");
        }
    }

    fn body(head: &str) -> Option<u64> {
        match parse(head) {
            Some(Request::Http { body, .. }) => body,
            other => panic!("{head}: {other:?}"),
        }
    }

    #[test]
    fn a_plain_http_body_is_as_long_as_its_content_length() {
        for (header, length) in [
            ("Accept: */*", 0),
            ("Content-Length: 0", 0),
            ("content-length: 12", 12),
            ("Content-Length:\t005 ", 5),
            ("Content-Length: 5\r\nContent-Length: 5, 5", 5),
            ("User-Agent: a\tb", 0),
        ] {
            let head = format!("POST http://example.com/ HTTP/1.1\r\n{header}\r\n\r\n");
            assert_eq!(body(&head), Some(length), "{header}");
        }
    }

    #[test]
    fn a_head_that_does_not_say_where_its_body_ends_has_no_length() {
        for (why, header) in [
            ("chunked", "Transfer-Encoding: chunked"),
            ("another coding", "transfer-encoding: identity"),
            ("both", "Content-Length: 4\r\nTransfer-Encoding: chunked"),
            ("two lengths", "Content-Length: 4\r\nContent-Length: 40"),
            ("a list of two", "Content-Length: 4, 40"),
            ("an empty one", "Content-Length:"),
            ("a trailing comma", "Content-Length: 4,"),
            ("a sign", "Content-Length: +4"),
            ("past 64 bits", "Content-Length: 99999999999999999999999"),
            ("no colon", "no colon"),
            ("space before the colon", "Content-Length : 40"),
            ("a folded line", "X-A: b\r\n Content-Length: 40"),
            ("a tab before the name", "\tContent-Length: 40"),
            (
                "a bare LF",
                "X: a\n\nGET /admin HTTP/1.1\nHost: other.example.net",
            ),
            ("a bare CR", "X: a\rContent-Length: 40"),
            ("a NUL", "X: a\0b"),
        ] {
            let head = format!("POST http://example.com/ HTTP/1.1\r\n{header}\r\n\r\n");
            assert_eq!(body(&head), None, "{why}");
        }
    }

    #[test]
    fn the_head_is_read_up_to_the_blank_line_and_the_rest_kept() {
        let mut input: &[u8] = b"CONNECT a.example.com:443 HTTP/1.1\r\n\r\nHELLO";
        let (head, rest) = read_head(&mut input).unwrap();
        assert!(head.starts_with("CONNECT"));
        assert_eq!(rest, b"HELLO");
    }

    #[test]
    fn forwarded_heads_drop_proxy_headers_and_close() {
        let head = origin_head(
            "GET",
            "/x",
            "HTTP/1.1",
            &[
                "Host: example.com".into(),
                "Proxy-Connection: keep-alive".into(),
                "Connection: keep-alive".into(),
                "Accept: */*".into(),
            ],
            "example.com",
            80,
            0,
        );
        assert_eq!(
            head,
            "GET /x HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\nConnection: close\r\n\r\n"
        );
    }

    #[test]
    fn the_forwarded_length_is_the_one_the_proxy_read() {
        let head = origin_head(
            "POST",
            "/",
            "HTTP/1.1",
            &[
                "Content-Length:\t005 ".into(),
                "Accept: */*".into(),
                "content-length: 5, 5".into(),
            ],
            "example.com",
            80,
            5,
        );
        assert_eq!(
            head,
            "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\nAccept: */*\r\nConnection: close\r\n\r\n"
        );
    }

    #[test]
    fn the_forwarded_host_is_the_authorized_one_not_the_clients() {
        let head = origin_head(
            "GET",
            "/private",
            "HTTP/1.1",
            &["Host: blocked.example.net".into(), "host:x".into()],
            "allowed.example.com",
            8080,
            0,
        );
        assert_eq!(
            head,
            "GET /private HTTP/1.1\r\nHost: allowed.example.com:8080\r\nConnection: close\r\n\r\n"
        );
        let v6 = origin_head("GET", "/", "HTTP/1.1", &[], "fd00::1", 80, 0);
        assert!(v6.contains("Host: [fd00::1]\r\n"), "{v6}");
    }
}
