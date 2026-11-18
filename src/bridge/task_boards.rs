//! Browser access to a held task's runtime board, on the bridge's HTTPS origin.
use super::*;
use crate::engine::{Engine, TaskBoardUpstream};
use crate::model::{audit::Actor, sandbox::SandboxName};
use base64::prelude::{BASE64_URL_SAFE_NO_PAD, Engine as _};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::sync::{Condvar, Weak};
use std::time::Instant;

const OPEN: &str = "/task-board/open";
const VIEW: &str = "/task-board/view/";
const TICKET_LIFE: Duration = Duration::from_secs(60);
const SESSION_LIFE: Duration = Duration::from_secs(15 * 60);
const START_WAIT: Duration = Duration::from_secs(24);
const MAX_TICKETS: usize = 32;
const MAX_SESSIONS: usize = 8;
const MAX_BROWSER_REQUESTS: usize = 24;
const MAX_HEAD: u64 = 16 * 1024;
const MAX_BODY: usize = 256 * 1024;
const COOKIE: &str = "enclos_board";
const BOOT: &str = include_str!("task_board_open.html");

fn token() -> io::Result<String> {
    random_bytes(32).map(|bytes| BASE64_URL_SAFE_NO_PAD.encode(bytes))
}

fn valid_token(text: &str) -> bool {
    text.len() == 43
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
}

fn board_slug(task: &str) -> Option<&str> {
    let (board, id) = task.split_once('/').unwrap_or(("default", task));
    (!board.is_empty()
        && board.len() <= 64
        && board
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"-_".contains(&b))
        && !id.is_empty()
        && !id.contains('/'))
    .then_some(board)
}

#[derive(Clone)]
struct Grant {
    device: Device,
    request: held_tasks::ResumeRequest,
    endpoint: AgentEndpoint,
    sandbox: SandboxName,
    board: String,
}

impl Grant {
    fn still_paired(&self, hub: &Hub, store: &Store, caller: &Caller) -> bool {
        self.device.node.as_deref() == Some(caller.node_id.as_str())
            && self.device.person == caller.login
            && hub
                .host_authority(store, &self.device, &caller.login)
                .is_ok()
            && hub.agents().contains(&self.endpoint)
    }
}

struct Ticket {
    grant: Grant,
    until: Instant,
}

#[derive(Clone)]
struct BrowserSession {
    grant: Grant,
    until: Instant,
    origin: String,
    cookie: String,
    dashboard: Arc<Dashboard>,
}

#[derive(Default)]
struct Records {
    tickets: HashMap<String, Ticket>,
    sessions: HashMap<String, BrowserSession>,
    dashboards: HashMap<String, Weak<Dashboard>>,
}

impl Records {
    fn sweep(&mut self, now: Instant) {
        self.tickets.retain(|_, ticket| ticket.until > now);
        self.sessions.retain(|_, session| session.until > now);
        self.dashboards
            .retain(|_, running| running.strong_count() > 0);
    }
}

#[derive(Default)]
pub(super) struct TaskBoards {
    records: Mutex<Records>,
    requests: AtomicUsize,
}

impl TaskBoards {
    pub(super) fn sweep(&self) {
        self.records
            .lock()
            .expect("not poisoned")
            .sweep(Instant::now());
    }

    fn issue(&self, ticket: String, grant: Grant) -> bool {
        let mut records = self.records.lock().expect("not poisoned");
        let now = Instant::now();
        records.sweep(now);
        // A repeated tap replaces this device's unused ticket for this board.
        records.tickets.retain(|_, old| {
            old.grant.device.id != grant.device.id
                || old.grant.sandbox != grant.sandbox
                || old.grant.board != grant.board
        });
        if records.tickets.len() >= MAX_TICKETS {
            return false;
        }
        records.tickets.insert(
            ticket,
            Ticket {
                grant,
                until: now + TICKET_LIFE,
            },
        );
        true
    }

    /// Wrong callers leave the ticket available for the intended browser.
    fn redeem(&self, key: &str, check: impl FnOnce(&Grant) -> bool) -> Option<Grant> {
        let mut records = self.records.lock().expect("not poisoned");
        records.sweep(Instant::now());
        let grant = &records.tickets.get(key)?.grant;
        // The closure only compares the transport identity, with no I/O.
        if !check(grant) {
            return None;
        }
        Some(records.tickets.remove(key)?.grant)
    }

    fn open(&self, hub: &Hub, grant: Grant, origin: String) -> Option<(String, BrowserSession)> {
        let id = token().ok()?;
        let cookie = token().ok()?;
        let mut records = self.records.lock().expect("not poisoned");
        let now = Instant::now();
        records.sweep(now);
        let key = grant.sandbox.as_str().to_owned();
        let running = records
            .dashboards
            .get(&key)
            .and_then(Weak::upgrade)
            .filter(|dashboard| !dashboard.ended());
        records.sessions.retain(|_, old| {
            old.grant.device.id != grant.device.id
                || old.grant.request.task != grant.request.task
                || old.grant.request.agent != grant.request.agent
        });
        if records.sessions.len() >= MAX_SESSIONS {
            return None;
        }
        let dashboard = running.unwrap_or_else(|| {
            let actor = authority::device_actor(&grant.device.person, &grant.device.id, None);
            let dashboard = Dashboard::start(hub.layout.clone(), grant.sandbox.clone(), actor);
            records.dashboards.insert(key, Arc::downgrade(&dashboard));
            dashboard
        });
        let session = BrowserSession {
            grant,
            until: now + SESSION_LIFE,
            origin,
            cookie,
            dashboard,
        };
        records.sessions.insert(id.clone(), session.clone());
        Some((id, session))
    }

    fn session(&self, id: &str) -> Option<BrowserSession> {
        let mut records = self.records.lock().expect("not poisoned");
        records.sweep(Instant::now());
        records.sessions.get(id).cloned()
    }

    fn forget(&self, id: &str) {
        self.records
            .lock()
            .expect("not poisoned")
            .sessions
            .remove(id);
    }
}

/// The last browser session drops this guard and ends the private dashboard.
struct Dashboard {
    stop: Arc<AtomicBool>,
    startup: Mutex<Startup>,
    changed: Condvar,
}

enum Startup {
    Starting,
    Ready(TaskBoardUpstream),
    Ended,
}

impl Dashboard {
    fn start(layout: crate::layout::Layout, sandbox: SandboxName, actor: Actor) -> Arc<Self> {
        let dashboard = Arc::new(Self {
            stop: Arc::new(AtomicBool::new(false)),
            startup: Mutex::new(Startup::Starting),
            changed: Condvar::new(),
        });
        let stop = Arc::clone(&dashboard.stop);
        let state = Arc::downgrade(&dashboard);
        std::thread::spawn(move || {
            let engine = Engine::open(layout, crate::state::Wait::Background);
            let result = engine.task_board_until(&actor, &sandbox, &stop, &mut |upstream| {
                if let Some(state) = state.upgrade() {
                    *state.startup.lock().expect("not poisoned") = Startup::Ready(upstream);
                    state.changed.notify_all();
                }
            });
            if let Some(state) = state.upgrade() {
                *state.startup.lock().expect("not poisoned") = Startup::Ended;
                state.changed.notify_all();
            }
            if let Err(error) = result {
                eprintln!("enclos app: task board for {sandbox}: {error}");
            }
        });
        dashboard
    }

    fn ended(&self) -> bool {
        matches!(*self.startup.lock().expect("not poisoned"), Startup::Ended)
    }

    fn upstream(&self, wait: Duration) -> Option<TaskBoardUpstream> {
        let state = self.startup.lock().expect("not poisoned");
        let (state, _) = self
            .changed
            .wait_timeout_while(state, wait, |state| matches!(state, Startup::Starting))
            .expect("not poisoned");
        match &*state {
            Startup::Ready(upstream) => Some(upstream.clone()),
            _ => None,
        }
    }
}

impl Drop for Dashboard {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

impl Hub {
    pub(super) fn task_board_link(
        &self,
        store: &Store,
        device: &Device,
        person: &str,
        of: MessageId,
        request: held_tasks::ResumeRequest,
    ) -> Result<ToDevice, ErrorBody> {
        let error = |code, message: &str| ErrorBody {
            of: Some(of.clone()),
            code,
            message: message.into(),
        };
        self.held_task_authority(store, device, person, &request)
            .map_err(|(code, why)| error(code, &why))?;
        let agents = self.agents();
        let endpoint = agents
            .iter()
            .find(|agent| agent.name == request.agent && agent.runtime == "hermes")
            .ok_or_else(|| {
                error(
                    ErrorCode::Unsupported,
                    "This agent has no task board the bridge can open.",
                )
            })?;
        let sandbox = endpoint
            .name
            .split_once('/')
            .and_then(|(sandbox, _)| sandbox.parse().ok())
            .ok_or_else(|| error(ErrorCode::NotFound, "No such task board."))?;
        let board = board_slug(request.task.as_str())
            .ok_or_else(|| {
                error(
                    ErrorCode::Unsupported,
                    "This task has a board name the bridge cannot open.",
                )
            })?
            .to_owned();
        if device.node.is_none() {
            return Err(error(
                ErrorCode::NotAllowed,
                "This device has no recorded transport identity.",
            ));
        }
        let ticket = token().map_err(|_| {
            error(
                ErrorCode::Internal,
                "The bridge could not open the task board. Try again.",
            )
        })?;
        store
            .log(
                Some(&device.id),
                Some(person),
                "held_task.board",
                Some(&format!("{} {}", request.agent, request.task)),
            )
            .map_err(|_| {
                error(
                    ErrorCode::Internal,
                    "The bridge could not record the board request. Try again.",
                )
            })?;
        if !self.task_boards.issue(
            ticket.clone(),
            Grant {
                device: device.clone(),
                request,
                endpoint: endpoint.clone(),
                sandbox,
                board,
            },
        ) {
            return Err(error(
                ErrorCode::Busy,
                "Too many board links are waiting. Try again shortly.",
            ));
        }
        Ok(ToDevice::HeldTaskBoardLink {
            of,
            path: format!("{OPEN}#{ticket}"),
        })
    }

    pub(super) fn serve_task_board(
        &self,
        mut client: TcpStream,
        waiting: Waiting,
        deadline: Sender<()>,
    ) {
        let Ok(request) = BrowserRequest::read(&client) else {
            let _ = write_response(
                &mut client,
                "400 Bad Request",
                "text/plain",
                "The board request cannot be read.",
                "",
            );
            return;
        };
        drop(deadline);
        drop(waiting);
        if self.task_boards.requests.fetch_add(1, Ordering::Relaxed) >= MAX_BROWSER_REQUESTS {
            self.task_boards.requests.fetch_sub(1, Ordering::Relaxed);
            let _ = write_response(
                &mut client,
                "503 Service Unavailable",
                "text/plain",
                "The bridge is busy. Try again.",
                "",
            );
            return;
        }
        let _request_slot = RequestSlot(&self.task_boards.requests);
        let _ = client.set_write_timeout(Some(WRITE_WAIT));
        let _ = self.serve_board_request(&mut client, request);
    }

    fn serve_board_request(
        &self,
        client: &mut TcpStream,
        request: BrowserRequest,
    ) -> io::Result<()> {
        let deny = |client: &mut TcpStream| {
            write_response(
                client,
                "403 Forbidden",
                "text/plain",
                "Open the board again from Enclos while connected to the host's network.",
                "",
            )
        };
        if request.method == "GET" && request.target == OPEN {
            return write_response(
                client,
                "200 OK",
                "text/html",
                BOOT,
                "Content-Security-Policy: default-src 'none'; script-src 'unsafe-inline'; connect-src 'self'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'\r\n",
            );
        }
        let Some(origin) = request.origin() else {
            return deny(client);
        };
        if (!matches!(request.method.as_str(), "GET" | "HEAD")
            || request.header("upgrade").is_some())
            && request.header("origin") != Some(origin.as_bytes())
        {
            return deny(client);
        }
        let Some(caller) = self.browser_caller(&request) else {
            return deny(client);
        };
        let Ok(store) = self.store() else {
            return deny(client);
        };
        if request.method == "POST" && request.target == OPEN {
            let Ok(ticket) = std::str::from_utf8(&request.body) else {
                return deny(client);
            };
            if !valid_token(ticket) {
                return deny(client);
            }
            let Some(grant) = self.task_boards.redeem(ticket, |g| {
                g.device.person == caller.login
                    && g.device.node.as_deref() == Some(caller.node_id.as_str())
            }) else {
                return deny(client);
            };
            if !grant.still_paired(self, &store, &caller)
                || self
                    .held_task_authority(&store, &grant.device, &caller.login, &grant.request)
                    .is_err()
            {
                return deny(client);
            }
            let unavailable = |client: &mut TcpStream| {
                write_response(
                    client,
                    "503 Service Unavailable",
                    "text/plain",
                    "The task board is unavailable. Return to Enclos and try again.",
                    "",
                )
            };
            let Some((id, session)) = self.task_boards.open(self, grant, origin) else {
                return unavailable(client);
            };
            if session.dashboard.upstream(START_WAIT).is_none() {
                self.task_boards.forget(&id);
                return unavailable(client);
            }
            if !session.grant.still_paired(self, &store, &caller)
                || self
                    .held_task_authority(
                        &store,
                        &session.grant.device,
                        &caller.login,
                        &session.grant.request,
                    )
                    .is_err()
            {
                self.task_boards.forget(&id);
                return deny(client);
            }
            let prefix = format!("{VIEW}{id}/");
            let cookie = format!(
                "Set-Cookie: {COOKIE}={}; Path={prefix}; Max-Age={}; Secure; HttpOnly; SameSite=Strict\r\n",
                session.cookie,
                SESSION_LIFE.as_secs()
            );
            return write_response(
                client,
                "200 OK",
                "text/plain",
                &format!("{prefix}kanban"),
                &cookie,
            );
        }
        let Some((id, path)) = request
            .target
            .strip_prefix(VIEW)
            .and_then(|suffix| suffix.split_once('/'))
        else {
            return deny(client);
        };
        if !valid_token(id) {
            return deny(client);
        }
        let Some(session) = self.task_boards.session(id) else {
            return deny(client);
        };
        if origin != session.origin
            || !request.has_session_cookie(&session.cookie)
            || !session.grant.still_paired(self, &store, &caller)
        {
            return deny(client);
        }
        let Some(upstream) = session.dashboard.upstream(Duration::ZERO) else {
            self.task_boards.forget(id);
            return write_response(
                client,
                "503 Service Unavailable",
                "text/plain",
                "The board has closed. Open it again from Enclos.",
                "",
            );
        };
        let _due = close_at(
            client,
            session.until.min(Instant::now() + Duration::from_secs(30)),
        )
        .map_err(io::Error::other)?;
        let headers: Vec<_> = request
            .headers
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_slice()))
            .collect();
        let task = session.grant.request.task.as_str();
        let native_task = task.split_once('/').map_or(task, |(_, id)| id);
        task_board_proxy::forward(
            client,
            &upstream,
            &request.method,
            &format!("/{path}"),
            &headers,
            &request.body,
            &format!("{VIEW}{id}/"),
            &session.grant.board,
            native_task,
        )
    }

    fn browser_caller(&self, request: &BrowserRequest) -> Option<Caller> {
        let login = std::str::from_utf8(request.header(self.transport.login_header())?).ok()?;
        let addresses =
            std::str::from_utf8(request.header(self.transport.address_header())?).ok()?;
        let caller = (self.whois)(&caller_address(addresses)?).ok()?;
        (caller.login == login).then_some(caller)
    }
}

struct RequestSlot<'a>(&'a AtomicUsize);

impl Drop for RequestSlot<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

struct BrowserRequest {
    method: String,
    target: String,
    headers: Vec<(String, Vec<u8>)>,
    body: Vec<u8>,
}

impl BrowserRequest {
    fn read(client: &TcpStream) -> io::Result<Self> {
        use tungstenite::http::{HeaderName, HeaderValue, Method, Uri};

        fn invalid() -> io::Error {
            io::Error::new(io::ErrorKind::InvalidData, "invalid board request")
        }

        let mut reader = BufReader::new(client);
        let mut header = (&mut reader).take(MAX_HEAD);
        let mut line = Vec::new();
        header.read_until(b'\n', &mut line)?;
        let line_text = std::str::from_utf8(line.strip_suffix(b"\r\n").ok_or_else(invalid)?)
            .map_err(|_| invalid())?;
        let mut fields = line_text.split(' ');
        let method = fields
            .next()
            .and_then(|method| method.parse::<Method>().ok())
            .ok_or_else(invalid)?
            .to_string();
        let target = fields
            .next()
            .filter(|target| target.starts_with('/') && !target.starts_with("//"))
            .and_then(|target| target.parse::<Uri>().ok())
            .ok_or_else(invalid)?;
        if fields.next() != Some("HTTP/1.1")
            || fields.next().is_some()
            || target.authority().is_some()
        {
            return Err(invalid());
        }
        let mut request = Self {
            method,
            target: target.to_string(),
            headers: Vec::new(),
            body: Vec::new(),
        };
        loop {
            line.clear();
            header.read_until(b'\n', &mut line)?;
            let value = line.strip_suffix(b"\r\n").ok_or_else(invalid)?;
            if value.is_empty() {
                break;
            }
            let i = value.iter().position(|&b| b == b':').ok_or_else(invalid)?;
            let name = HeaderName::from_bytes(&value[..i]).map_err(|_| invalid())?;
            let value = value[i + 1..].trim_ascii();
            HeaderValue::from_bytes(value).map_err(|_| invalid())?;
            request
                .headers
                .push((name.as_str().to_owned(), value.to_vec()));
        }
        if request
            .headers
            .iter()
            .any(|(name, _)| name == "transfer-encoding")
        {
            return Err(invalid());
        }
        let mut lengths = request
            .headers
            .iter()
            .filter(|(name, _)| name == "content-length");
        if let Some((_, bytes)) = lengths.next() {
            let length: usize = std::str::from_utf8(bytes)
                .ok()
                .filter(|s| s.bytes().all(|b| b.is_ascii_digit()))
                .and_then(|text| text.parse().ok())
                .filter(|n| *n <= MAX_BODY)
                .ok_or_else(invalid)?;
            if lengths.next().is_some() {
                return Err(invalid());
            }
            request.body.resize(length, 0);
            reader.read_exact(&mut request.body)?;
        }
        Ok(request)
    }

    fn header(&self, name: &str) -> Option<&[u8]> {
        let mut values = self
            .headers
            .iter()
            .filter(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_slice());
        let first = values.next()?;
        values.next().is_none().then_some(first)
    }

    fn origin(&self) -> Option<String> {
        let host = std::str::from_utf8(self.header("host")?).ok()?;
        if host.contains('@') || host.parse::<tungstenite::http::uri::Authority>().is_err() {
            return None;
        }
        Some(format!("https://{host}"))
    }

    fn has_session_cookie(&self, expected: &str) -> bool {
        let Some(raw) = self
            .header("cookie")
            .and_then(|bytes| std::str::from_utf8(bytes).ok())
        else {
            return false;
        };
        let mut matching = raw.split(';').filter_map(|cookie| {
            let (name, value) = cookie.trim().split_once('=')?;
            (name == COOKIE).then_some(value)
        });
        matching.next() == Some(expected) && matching.next().is_none()
    }
}

/// Peek without consuming the device's handshake. The existing first-request
/// deadline also bounds a fragmented browser header and body.
pub(super) fn requested(stream: &TcpStream) -> bool {
    let saved = stream.read_timeout().ok().flatten();
    let result = peek(stream);
    let _ = stream.set_read_timeout(saved);
    result
}

fn peek(stream: &TcpStream) -> bool {
    let deadline = Instant::now() + Duration::from_secs(2);
    let prefix = b"/task-board/";
    let mut bytes = [0u8; 64];
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() || stream.set_read_timeout(Some(left)).is_err() {
            return false;
        }
        let Ok(count) = stream.peek(&mut bytes) else {
            return false;
        };
        if count == 0 {
            return false;
        }
        let mut fields = bytes[..count].splitn(3, |byte| *byte == b' ');
        let _ = fields.next();
        if let Some(target) = fields.next() {
            if target.starts_with(prefix) {
                return true;
            }
            if !prefix.starts_with(target) || fields.next().is_some() {
                return false;
            }
        }
        if count == bytes.len() {
            return false;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn write_response(
    client: &mut TcpStream,
    status: &str,
    content: &str,
    body: &str,
    headers: &str,
) -> io::Result<()> {
    write!(
        client,
        "HTTP/1.1 {status}\r\nContent-Type: {content}; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\nReferrer-Policy: no-referrer\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: DENY\r\n{headers}Connection: close\r\n\r\n{body}",
        body.len()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use enclos_protocol::HeldTaskId;

    fn grant() -> Grant {
        Grant {
            device: Device {
                id: "phone".into(),
                name: "Pixel".into(),
                person: "owner@example.com".into(),
                noise_key: vec![],
                device_key: vec![],
                push_key: vec![],
                push_token: None,
                paired: 0,
                seen: None,
                node: Some("node-1".into()),
            },
            request: held_tasks::ResumeRequest {
                agent: "lab/main".into(),
                task: HeldTaskId::new("review/t1").unwrap(),
                revision: 1,
            },
            endpoint: AgentEndpoint {
                name: "lab/main".into(),
                runtime: "hermes".into(),
                socket: PathBuf::from("plugin.sock"),
                token: "test".into(),
            },
            sandbox: "lab".parse().unwrap(),
            board: "review".into(),
        }
    }

    #[test]
    fn a_ticket_is_single_use_and_a_wrong_node_cannot_consume_it() {
        let boards = TaskBoards::default();
        let ticket = token().unwrap();
        assert!(valid_token(&ticket));
        assert!(boards.issue(ticket.clone(), grant()));
        assert!(
            boards
                .redeem(&ticket, |g| g.device.node.as_deref() == Some("node-2"))
                .is_none()
        );
        assert!(
            boards
                .redeem(&ticket, |g| g.device.node.as_deref() == Some("node-1"))
                .is_some()
        );
        assert!(boards.redeem(&ticket, |_| true).is_none());
    }

    #[test]
    fn a_ticket_expires_and_a_new_tap_replaces_the_old_ticket() {
        let boards = TaskBoards::default();
        let first = token().unwrap();
        let second = token().unwrap();
        assert!(boards.issue(first.clone(), grant()));
        assert!(boards.issue(second.clone(), grant()));
        assert!(boards.redeem(&first, |_| true).is_none());
        boards
            .records
            .lock()
            .unwrap()
            .sweep(Instant::now() + TICKET_LIFE);
        assert!(boards.redeem(&second, |_| true).is_none());
    }

    fn request(bytes: &[u8]) -> io::Result<BrowserRequest> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let mut sender = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (receiver, _) = listener.accept().unwrap();
        sender.write_all(bytes).unwrap();
        sender.shutdown(std::net::Shutdown::Write).unwrap();
        assert!(requested(&receiver));
        BrowserRequest::read(&receiver)
    }

    #[test]
    fn the_browser_exchange_has_one_bounded_request_body() {
        let valid = request(b"POST /task-board/open HTTP/1.1\r\nHost: enclos.test\r\nOrigin: https://enclos.test\r\nContent-Length: 3\r\n\r\nabc").unwrap();
        assert_eq!(valid.body, b"abc");
        assert_eq!(valid.origin().as_deref(), Some("https://enclos.test"));
        for headers in [
            "Transfer-Encoding: chunked",
            "Content-Length: 3\r\nContent-Length: 3",
            "Content-Length: 10000000",
            "Content-Length: 4",
        ] {
            assert!(
                request(
                    format!("POST {OPEN} HTTP/1.1\r\nHost: enclos.test\r\n{headers}\r\n\r\nabc")
                        .as_bytes()
                )
                .is_err(),
                "{headers}"
            );
        }
    }

    #[test]
    fn board_routes_and_session_cookies_are_exact() {
        assert_eq!(board_slug("review/t_1"), Some("review"));
        assert_eq!(board_slug("t_1"), Some("default"));
        assert_eq!(board_slug("../t_1"), None);
        assert_eq!(board_slug("review/other/t_1"), None);
        let request_with_cookie = |cookie| {
            request(format!("GET {VIEW}session/kanban HTTP/1.1\r\nHost: enclos.test\r\nCookie: {cookie}\r\n\r\n").as_bytes()).unwrap()
        };
        assert!(request_with_cookie("other=one; enclos_board=abc").has_session_cookie("abc"));
        assert!(!request_with_cookie("other=abc").has_session_cookie("abc"));
        assert!(
            !request_with_cookie("enclos_board=abc; enclos_board=abc").has_session_cookie("abc")
        );
    }

    #[test]
    fn paired_browser_can_exchange_once_and_loses_access_when_unpaired() {
        use enclos_protocol::held_task::HeldTask;
        use std::os::unix::net::UnixListener;

        let folder = tempfile::tempdir().unwrap();
        let mut grant = grant();
        grant.endpoint.socket = folder.path().join("plugin.sock");
        let hub = Hub::new(
            Transport::Tailscale,
            Arc::new(|addr| {
                Ok(Caller {
                    login: "owner@example.com".into(),
                    node_id: if addr == "100.64.0.1" {
                        "node-1"
                    } else {
                        "node-2"
                    }
                    .into(),
                    node: "Pixel".into(),
                })
            }),
            folder.path().join("app.db"),
            crate::layout::Layout::at(folder.path().join("enclos")),
            vec![],
            vec![grant.endpoint.clone()],
            None,
            SILENCE,
        );
        let store = hub.store().unwrap();
        store.set_host(&grant.device.person).unwrap();
        store.add_device(&grant.device).unwrap();
        store
            .conversation("held-board", "lab", "main", &grant.device.person)
            .unwrap();
        let task: HeldTask = serde_json::from_value(serde_json::json!({
            "task":"review/t1", "title":"Review", "reason":"Decide",
            "since":1, "revision":"e:1", "resume":"Use the board", "resumable":false
        }))
        .unwrap();
        store
            .report_held_tasks("lab/main", "held-board", &[task])
            .unwrap();
        grant.request.revision = store
            .held_task("lab/main", "review/t1")
            .unwrap()
            .unwrap()
            .info
            .revision;

        let socket = folder.path().join("private-dashboard.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let dashboard = Arc::new(Dashboard {
            stop: Arc::new(AtomicBool::new(false)),
            startup: Mutex::new(Startup::Ready(TaskBoardUpstream::test_socket(socket))),
            changed: Condvar::new(),
        });
        hub.task_boards
            .records
            .lock()
            .unwrap()
            .dashboards
            .insert("lab".into(), Arc::downgrade(&dashboard));
        let upstream = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut request = BufReader::new(&stream);
            let mut text = String::new();
            request.read_line(&mut text).unwrap();
            assert_eq!(text, "GET /kanban HTTP/1.1\r\n");
            // Read the full request before replying and closing the socket.
            loop {
                text.clear();
                assert_ne!(request.read_line(&mut text).unwrap(), 0);
                if text == "\r\n" {
                    break;
                }
            }
            let body = "<html><head></head><body>test board</body></html>";
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            )
            .unwrap();
        });

        let browser = |method: &str,
                       target: &str,
                       addr: &str,
                       origin: &str,
                       cookie: &str,
                       body: &str| {
            let req = request(format!("{method} {target} HTTP/1.1\r\nHost: enclos.test\r\nOrigin: {origin}\r\nTailscale-User-Login: owner@example.com\r\nX-Forwarded-For: {addr}\r\nCookie: {cookie}\r\nContent-Length: {}\r\n\r\n{body}", body.len()).as_bytes()).unwrap();
            let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
            let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            client
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let (mut server, _) = listener.accept().unwrap();
            hub.serve_board_request(&mut server, req).unwrap();
            drop(server);
            let mut response = String::new();
            client.read_to_string(&mut response).unwrap();
            response
        };
        let ticket = token().unwrap();
        assert!(hub.task_boards.issue(ticket.clone(), grant));
        let exchange = |addr, origin| browser("POST", OPEN, addr, origin, "", &ticket);
        assert!(exchange("100.64.0.2", "https://enclos.test").starts_with("HTTP/1.1 403"));
        assert!(exchange("100.64.0.1", "https://other.test").starts_with("HTTP/1.1 403"));
        let response = exchange("100.64.0.1", "https://enclos.test");
        assert!(response.starts_with("HTTP/1.1 200"));
        assert!(response.contains("Secure; HttpOnly; SameSite=Strict"));
        let cookie = response
            .lines()
            .find_map(|l| l.strip_prefix("Set-Cookie: "))
            .unwrap()
            .split(';')
            .next()
            .unwrap();
        let target = response.split_once("\r\n\r\n").unwrap().1;
        assert!(exchange("100.64.0.1", "https://enclos.test").starts_with("HTTP/1.1 403"));
        let get = |cookie| {
            browser(
                "GET",
                target,
                "100.64.0.1",
                "https://enclos.test",
                cookie,
                "",
            )
        };
        assert!(get("").starts_with("HTTP/1.1 403"));
        assert!(get(cookie).contains("test board"));
        upstream.join().unwrap();
        store.remove_device("phone").unwrap();
        assert!(get(cookie).starts_with("HTTP/1.1 403"));
    }
}
