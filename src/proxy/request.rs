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
    if parts.next().is_some() || !version.starts_with("HTTP/1.") {
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
    if authority.contains('@') {
        return None;
    }
    let (host, port) = split_host_port(authority, Some(80))?;
    Some(Request::Http {
        method: method.to_owned(),
        host,
        port,
        path: path.to_owned(),
        version: version.to_owned(),
        headers: lines.map(str::to_owned).collect(),
    })
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
/// the proxy's own headers, and closed after one exchange.
pub fn origin_head(method: &str, path: &str, version: &str, headers: &[String]) -> String {
    let mut head = format!("{method} {path} {version}\r\n");
    for line in headers {
        let name = line
            .split(':')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        if matches!(
            name.as_str(),
            "proxy-connection" | "proxy-authorization" | "connection" | "keep-alive"
        ) {
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
        ] {
            assert_eq!(parse(bad), None, "{bad}");
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
            ],
        );
        assert_eq!(
            head,
            "GET /x HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"
        );
    }
}
