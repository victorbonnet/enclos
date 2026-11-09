//! The pairing page (`docs/protocol.md`, Pairing): what a link to
//! `https://<bridge>/pair#…` opens on the phone. A chat or a note opens an
//! https link, not an app's own `enclos://` scheme; the page hands that link
//! to the app on a tap. The link's parameters come after `#`, which a
//! browser never sends, so the one-time code does not reach the bridge, its
//! transport or a log: the page is the same static file for everyone.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

/// The page's path on the bridge.
pub const PATH: &str = "/pair";

const PAGE: &str = include_str!("pair.html");

/// The https link to the pairing page for `link`, an `enclos://pair?…`
/// link: the bridge's address `url`, the path, and the link's parameters
/// after `#`.
pub fn link_to_page(url: &str, link: &str) -> Option<String> {
    let query = link.strip_prefix("enclos://pair?")?;
    Some(format!("{}{PATH}#{query}", url.trim_end_matches('/')))
}

/// Whether the connection asks for the pairing page, by its request line,
/// read without taking it: anything else goes on to the WebSocket handshake.
pub fn requested(stream: &TcpStream) -> bool {
    let wanted = format!("GET {PATH} ");
    let mut head = [0u8; 16];
    let start = Instant::now();
    loop {
        match stream.peek(&mut head) {
            Ok(n) if n >= wanted.len() || n == 0 => {
                return head[..n].starts_with(wanted.as_bytes())
                    || head[..n].starts_with(format!("GET {PATH}?").as_bytes());
            }
            Ok(_) if start.elapsed() < Duration::from_secs(2) => {
                std::thread::sleep(Duration::from_millis(10));
            }
            _ => return false,
        }
    }
}

/// Answers with the page and closes the connection.
pub fn serve(mut stream: TcpStream) -> std::io::Result<()> {
    // The request is read to its end, so closing does not reset the connection.
    let mut request = Vec::new();
    let mut part = [0u8; 1024];
    while !request.windows(4).any(|w| w == b"\r\n\r\n") && request.len() < 16 * 1024 {
        let n = stream.read(&mut part)?;
        if n == 0 {
            break;
        }
        request.extend_from_slice(&part[..n]);
    }
    write!(
        stream,
        "HTTP/1.1 200 OK\r\n\
         Content-Type: text/html; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Cache-Control: no-store\r\n\
         Referrer-Policy: no-referrer\r\n\
         X-Content-Type-Options: nosniff\r\n\
         Content-Security-Policy: default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'\r\n\
         Connection: close\r\n\r\n{PAGE}",
        PAGE.len()
    )?;
    stream.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    /// A connection whose client sent `request`: both ends, the server's first.
    fn served(request: &'static [u8]) -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        client.write_all(request).unwrap();
        let (server, _) = listener.accept().unwrap();
        (server, client)
    }

    #[test]
    fn the_page_link_carries_the_parameters_after_the_hash() {
        let link = "enclos://pair?v=1&host=mac&url=https://mac.tail1.ts.net&key=k&code=c&exp=1";
        assert_eq!(
            link_to_page("https://mac.tail1.ts.net", link).as_deref(),
            Some(
                "https://mac.tail1.ts.net/pair#v=1&host=mac&url=https://mac.tail1.ts.net&key=k&code=c&exp=1"
            )
        );
        assert_eq!(
            link_to_page("https://mac.tail1.ts.net", "https://example.com"),
            None
        );
    }

    #[test]
    fn a_request_for_the_page_gets_it_and_a_websocket_does_not() {
        let (server, mut client) = served(b"GET /pair HTTP/1.1\r\nHost: mac\r\n\r\n");
        assert!(requested(&server));
        serve(server).unwrap();
        let mut answer = String::new();
        client.read_to_string(&mut answer).unwrap();
        assert!(answer.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(answer.contains("Content-Security-Policy: default-src 'none'"));
        assert!(answer.ends_with("</html>\n"));

        let (server, _client) =
            served(b"GET / HTTP/1.1\r\nHost: mac\r\nUpgrade: websocket\r\n\r\n");
        assert!(!requested(&server));
        let (server, _client) = served(b"GET /pairing HTTP/1.1\r\n\r\n");
        assert!(!requested(&server));
    }
}
