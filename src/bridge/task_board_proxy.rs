//! Relays the authenticated browser's Kanban requests to a private runtime
//! dashboard. The browser cannot select the upstream or change boards.

use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use crate::engine::TaskBoardUpstream;

const IO_WAIT: Duration = Duration::from_secs(15);
const MAX_HEADER: usize = 64 * 1024;
const MAX_DOCUMENT: usize = 4 * 1024 * 1024;
const MAX_RESPONSE: u64 = 64 * 1024 * 1024;
const API: &str = "/api/plugins/kanban/";

#[derive(Clone, Copy, PartialEq, Eq)]
enum Route {
    Document,
    Plugins,
    Boards,
    Download,
    Other,
}

fn component(value: &str) -> bool {
    !matches!(value, "" | "." | "..")
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.@".contains(&b))
}

fn routes(method: &str, path: &str, task: &str) -> Option<Route> {
    let parts: Vec<_> = path.strip_prefix('/')?.split('/').collect();
    if parts.len() > 8 || parts.iter().any(|part| !component(part)) {
        return None;
    }
    if let Some(api) = path.strip_prefix(API) {
        return match (method, api.split('/').collect::<Vec<_>>().as_slice()) {
            ("GET", ["boards"]) => Some(Route::Boards),
            ("GET", ["attachments", _]) => Some(Route::Download),
            (
                "GET",
                [
                    "board" | "config" | "diagnostics" | "home-channels" | "stats" | "assignees"
                    | "model-options" | "projects" | "profiles" | "workflow" | "orchestration",
                ],
            )
            | ("GET", ["tasks", _])
            | ("GET", ["tasks", _, "attachments" | "log"]) => Some(Route::Other),
            ("PATCH", ["tasks", id]) | ("POST", ["tasks", id, "comments" | "specify"])
                if *id == task =>
            {
                Some(Route::Other)
            }
            _ => None,
        };
    }
    if method != "GET" {
        return None;
    }
    match parts.as_slice() {
        ["kanban"] => Some(Route::Document),
        ["api", "dashboard", "plugins"] => Some(Route::Plugins),
        ["api", "auth", "me"]
        | ["api", "status"]
        | ["api", "profiles"]
        | ["api", "profiles", "active"]
        | ["api", "dashboard", "theme" | "themes" | "font"]
        | ["favicon.ico"]
        | [
            "assets" | "fonts" | "fonts-terminal" | "ds-assets" | "locales",
            ..,
        ]
        | [
            "dashboard-plugins",
            "kanban",
            "dist",
            "index.js" | "style.css",
        ] => Some(Route::Other),
        [
            "dashboard-plugins",
            profile,
            "kanban",
            "dist",
            "index.js" | "style.css",
        ] if *profile == "@default" => Some(Route::Other),
        _ => None,
    }
}

fn scoped_target(target: &str, board: &str) -> Option<String> {
    if !component(board)
        || !board
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
    {
        return None;
    }
    if target
        .bytes()
        .any(|b| !(0x21..=0x7e).contains(&b) || b == b'#')
    {
        return None;
    }
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let mut pairs = Vec::new();
    for pair in query.split('&').filter(|pair| !pair.is_empty()) {
        let (key, _) = pair.split_once('=')?;
        // No alternate encodings of `board` or `profile` can reach the server.
        if key.is_empty() || !key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
            return None;
        }
        if !matches!(key, "board" | "profile") {
            pairs.push(pair);
        }
    }
    let board_query = format!("board={board}");
    if path.starts_with(API) {
        pairs.push(&board_query);
    }
    if pairs.is_empty() {
        Some(path.into())
    } else {
        Some(format!("{path}?{}", pairs.join("&")))
    }
}

fn safe_header(value: &[u8]) -> bool {
    value
        .iter()
        .all(|&b| b == b'\t' || (0x20..=0x7e).contains(&b))
}

fn header(out: &mut impl Write, name: &str, value: &[u8]) -> io::Result<()> {
    write!(out, "{name}: ")?;
    out.write_all(value)?;
    out.write_all(b"\r\n")
}

fn response_start(reader: &mut impl BufRead) -> io::Result<(u16, Vec<(String, String)>)> {
    let mut remaining = reader.take(MAX_HEADER as u64);
    let mut line = String::new();
    remaining.read_line(&mut line)?;
    let mut words = line.split_ascii_whitespace();
    if words.next() != Some("HTTP/1.1") {
        return Err(invalid());
    }
    let status = words
        .next()
        .and_then(|word| word.parse::<u16>().ok())
        .filter(|status| (100..600).contains(status))
        .ok_or_else(invalid)?;
    let mut headers = Vec::new();
    loop {
        line.clear();
        if remaining.read_line(&mut line)? == 0 {
            return Err(invalid());
        }
        if line == "\r\n" {
            return Ok((status, headers));
        }
        let (name, value) = line
            .strip_suffix("\r\n")
            .and_then(|line| line.split_once(':'))
            .ok_or_else(invalid)?;
        if !safe_header(value.as_bytes()) {
            return Err(invalid());
        }
        headers.push((name.to_ascii_lowercase(), value.trim().into()));
    }
}

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid task board response")
}

fn body_size(headers: &[(String, String)]) -> io::Result<Option<u64>> {
    let mut length: Option<u64> = None;
    for (name, value) in headers {
        match name.as_str() {
            "transfer-encoding" => return Err(invalid()),
            "content-length" if length.is_none() => {
                length = Some(
                    value
                        .parse()
                        .ok()
                        .filter(|n| *n <= MAX_RESPONSE)
                        .ok_or_else(invalid)?,
                );
            }
            "content-length" => return Err(invalid()),
            _ => {}
        }
    }
    Ok(length)
}

fn refuse(client: &mut TcpStream, status: &str, message: &str) -> io::Result<()> {
    write!(
        client,
        "HTTP/1.1 {status}\r\nConnection: close\r\nCache-Control: no-store\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\n\r\n{message}",
        message.len()
    )
}

fn rewrite_body(route: Route, raw: &[u8], board: &str) -> io::Result<Vec<u8>> {
    if route == Route::Document {
        let page = std::str::from_utf8(raw).map_err(|_| invalid())?;
        let (head, rest) = page.split_once("<head>").ok_or_else(invalid)?;
        // Hermes initializes Kanban from localStorage, not the URL. Seed
        // the board selected by the held task before the bundle starts.
        return Ok(format!("{head}<head><script>try{{localStorage.setItem('hermes.kanban.selectedBoard','{board}')}}catch{{}}</script>{rest}").into_bytes());
    }
    let mut data: serde_json::Value = serde_json::from_slice(raw).map_err(|_| invalid())?;
    match route {
        Route::Plugins => data.as_array_mut().ok_or_else(invalid)?.retain(|plugin| {
            plugin.get("name").and_then(serde_json::Value::as_str) == Some("kanban")
        }),
        Route::Boards => {
            data.get_mut("boards")
                .and_then(serde_json::Value::as_array_mut)
                .ok_or_else(invalid)?
                .retain(|item| item.get("slug").and_then(serde_json::Value::as_str) == Some(board));
            data["current"] = serde_json::Value::String(board.into());
        }
        _ => unreachable!(),
    }
    serde_json::to_vec(&data).map_err(|_| invalid())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn forward(
    client: &mut TcpStream,
    upstream: &TaskBoardUpstream,
    method: &str,
    target: &str,
    headers: &[(&str, &[u8])],
    body: &[u8],
    prefix: &str,
    board: &str,
    task: &str,
) -> io::Result<()> {
    client.set_write_timeout(Some(IO_WAIT))?;
    let path = target.split('?').next().unwrap_or_default();
    let Some(route) = routes(method, path, task) else {
        return refuse(
            client,
            "404 Not Found",
            "This request is outside the task board.\n",
        );
    };
    let Some(target) = scoped_target(target, board) else {
        return refuse(client, "400 Bad Request", "Invalid task board request.\n");
    };
    if headers.iter().any(|(name, _)| {
        name.eq_ignore_ascii_case("upgrade") || name.eq_ignore_ascii_case("service-worker")
    }) {
        return refuse(
            client,
            "400 Bad Request",
            "This task board resource is unavailable.\n",
        );
    }
    let mut socket = upstream.connect()?;
    socket.set_write_timeout(Some(IO_WAIT))?;
    socket.set_read_timeout(Some(IO_WAIT))?;
    write!(
        socket,
        "{method} {target} HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Forwarded-Prefix: {}\r\nAccept-Encoding: identity\r\n",
        prefix.trim_end_matches('/')
    )?;
    for (name, value) in headers {
        let name = name.to_ascii_lowercase();
        let allowed = matches!(
            name.as_str(),
            "accept" | "accept-language" | "content-type" | "range" | "x-hermes-session-token"
        );
        if allowed && safe_header(value) {
            header(&mut socket, &name, value)?;
        }
    }
    write!(
        socket,
        "Connection: close\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )?;
    socket.write_all(body)?;
    let mut response = BufReader::new(socket);
    let (status, headers) = response_start(&mut response)?;
    if status < 200 || (300..400).contains(&status) {
        return refuse(
            client,
            "502 Bad Gateway",
            "The private dashboard redirected or refused this request.\n",
        );
    }
    let rewrite =
        status == 200 && matches!(route, Route::Document | Route::Plugins | Route::Boards);
    let length = body_size(&headers)?;
    let mut output = Vec::new();
    if rewrite {
        if headers.iter().any(|(name, _)| name == "content-encoding") {
            return refuse(
                client,
                "502 Bad Gateway",
                "The dashboard sent an unsupported document encoding.\n",
            );
        }
        if length.is_some_and(|n| n > MAX_DOCUMENT as u64) {
            return refuse(
                client,
                "502 Bad Gateway",
                "The dashboard document is too large.\n",
            );
        }
        response
            .by_ref()
            .take(length.unwrap_or(MAX_DOCUMENT as u64 + 1))
            .read_to_end(&mut output)?;
        if output.len() > MAX_DOCUMENT || length.is_some_and(|n| n != output.len() as u64) {
            return Err(invalid());
        }
        output = rewrite_body(route, &output, board)?;
    }
    write!(
        client,
        "HTTP/1.1 {status} Task Board\r\nConnection: close\r\nCache-Control: no-store\r\nReferrer-Policy: no-referrer\r\nX-Content-Type-Options: nosniff\r\nContent-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self' data:; object-src 'none'; frame-ancestors 'none'; worker-src 'none'; frame-src 'none'; base-uri 'self'; form-action 'none'\r\n"
    )?;
    for (name, value) in headers {
        if name == "content-type"
            || (!rewrite
                && matches!(
                    name.as_str(),
                    "content-encoding" | "content-range" | "accept-ranges"
                ))
        {
            header(client, &name, value.as_bytes())?;
        }
    }
    if rewrite {
        write!(client, "Content-Length: {}\r\n", output.len())?;
    } else if let Some(length) = length {
        write!(client, "Content-Length: {length}\r\n")?;
    }
    if route == Route::Download {
        client.write_all(b"Content-Disposition: attachment\r\n")?;
    }
    client.write_all(b"\r\n")?;
    if rewrite {
        client.write_all(&output)
    } else {
        io::copy(&mut response.take(length.unwrap_or(MAX_RESPONSE)), client).map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_task_board_routes_and_assets_are_forwarded() {
        assert!(routes("GET", "/kanban", "t1").is_some());
        assert!(
            routes(
                "GET",
                "/dashboard-plugins/@default/kanban/dist/index.js",
                "t1"
            )
            .is_some()
        );
        assert!(routes("POST", "/api/plugins/kanban/tasks/t1/specify", "t1").is_some());
        for (method, path) in [
            ("GET", "/api/config"),
            ("GET", "/assets/../api/chat"),
            ("GET", "/assets/%2e%2e/api/chat"),
            ("GET", "/api/plugins/other/board"),
            ("POST", "/api/plugins/kanban/boards"),
            ("POST", "/api/plugins/kanban/tasks/t2/specify"),
            ("PATCH", "/api/plugins/kanban/tasks/t2"),
            ("GET", "/dashboard-plugins/kanban/plugin_api.py"),
        ] {
            assert!(routes(method, path, "t1").is_none(), "{method} {path}");
        }
    }

    #[test]
    fn an_api_request_always_uses_the_board_of_the_held_task() {
        assert_eq!(scoped_target("/api/plugins/kanban/board?board=other&include_archived=true&board=third&profile=fourth", "reviews").unwrap(), "/api/plugins/kanban/board?include_archived=true&board=reviews");
        assert!(scoped_target("/api/plugins/kanban/board?bo%61rd=other", "reviews").is_none());
        assert!(scoped_target("/api/plugins/kanban/board", "bad&escape").is_none());
    }

    #[test]
    fn only_kanban_and_the_selected_board_reach_the_dashboard_shell() {
        let plugins = rewrite_body(
            Route::Plugins,
            br#"[{"name":"kanban"},{"name":"diagnostics"}]"#,
            "reviews",
        )
        .unwrap();
        assert_eq!(plugins, br#"[{"name":"kanban"}]"#);
        let boards = rewrite_body(
            Route::Boards,
            br#"{"boards":[{"slug":"default"},{"slug":"reviews"}],"current":"default"}"#,
            "reviews",
        )
        .unwrap();
        assert_eq!(
            boards,
            br#"{"boards":[{"slug":"reviews"}],"current":"reviews"}"#
        );
        let document = rewrite_body(
            Route::Document,
            b"<html><head><script src=\"kanban.js\"></script></head></html>",
            "reviews",
        )
        .unwrap();
        assert!(
            String::from_utf8(document)
                .unwrap()
                .contains("selectedBoard','reviews')}catch{}</script><script src")
        );
    }
}
