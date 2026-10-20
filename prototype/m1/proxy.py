"""Minimal CONNECT proxy for the milestone 1 prototype (throwaway, stdlib only).

Listens on 127.0.0.1:<port>, accepts CONNECT host:port (and plain-HTTP requests
with an absolute URI), checks the host against an allowlist, resolves it itself,
keeps only globally reachable addresses, connects by address and logs one JSON
line per connection. Everything else is denied.

    uv run --no-project python proxy.py --port 18080 --allow allow.txt --log net.jsonl
    uv run --no-project python proxy.py --port 18080 --learn --log net.jsonl

--learn allows any host whose addresses are public, and logs verdict "learn",
to discover which endpoints a program needs. The allowlist file is re-read on
every connection, so edits apply without a restart.
"""

import argparse
import ipaddress
import json
import select
import socket
import threading
import time
from urllib.parse import urlsplit

ARGS = None
LOG_LOCK = threading.Lock()


def log(event):
    event["at"] = time.strftime("%Y-%m-%dT%H:%M:%S")
    line = json.dumps(event, sort_keys=True)
    with LOG_LOCK:
        print(line, flush=True)
        if ARGS.log:
            with open(ARGS.log, "a") as f:
                f.write(line + "\n")


def load_allowlist():
    if not ARGS.allow:
        return []
    entries = []
    with open(ARGS.allow) as f:
        for raw in f:
            line = raw.split("#", 1)[0].strip().lower()
            if line:
                entries.append(line)
    return entries


def allowed(host, port):
    for entry in load_allowlist():
        name, _, eport = entry.partition(":")
        if int(eport or 443) != port:
            continue
        if name == host or (name.startswith("*.") and host.endswith(name[1:])):
            return True
    return False


def normalize(host):
    host = host.strip().strip("[]").lower().rstrip(".")
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError:
        return host


NAT64 = ipaddress.ip_network("64:ff9b::/96")
NAT64_LOCAL = ipaddress.ip_network("64:ff9b:1::/48")
SIX_TO_FOUR = ipaddress.ip_network("2002::/16")
TEREDO = ipaddress.ip_network("2001::/32")


def carried_v4(ip):
    """The IPv4 addresses an IPv6 address carries (ADR 0017, as src/net/addr.rs):
    mapped, NAT64 /96 and /48, 6to4, and Teredo's server and client."""
    if ip.ipv4_mapped:
        return [ip.ipv4_mapped]
    b = ip.packed
    v4 = lambda *o: ipaddress.IPv4Address(bytes(o))  # noqa: E731
    if ip in NAT64:
        return [v4(*b[12:16])]
    if ip in NAT64_LOCAL:
        return [v4(b[6], b[7], b[9], b[10])]
    if ip in SIX_TO_FOUR:
        return [v4(*b[2:6])]
    if ip in TEREDO:
        return [v4(*b[4:8]), v4(*(x ^ 0xFF for x in b[12:16]))]
    return []


def is_public(ip):
    """Global, and so is every IPv4 address it carries."""
    if isinstance(ip, ipaddress.IPv6Address):
        carried = carried_v4(ip)
        if carried:
            return all(c.is_global for c in carried)
    return ip.is_global


def public_addresses(host, port):
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    good = []
    for family, _, _, _, sockaddr in infos:
        if is_public(ipaddress.ip_address(sockaddr[0])) and (family, sockaddr) not in good:
            good.append((family, sockaddr))
    return good


def open_upstream(host, port, event):
    """Return a connected socket or None; fills event with verdict and reason."""
    host = normalize(host)
    event.update(host=host, port=port)
    if not ARGS.learn and not allowed(host, port):
        event.update(verdict="deny", reason="not-allowed")
        return None
    try:
        addrs = public_addresses(host, port)
    except OSError as e:
        event.update(verdict="deny", reason=f"resolve-failed: {e}")
        return None
    if not addrs:
        event.update(verdict="deny", reason="blocked-address")
        return None
    for family, sockaddr in addrs:
        try:
            s = socket.socket(family, socket.SOCK_STREAM)
            s.settimeout(15)
            s.connect(sockaddr)
            s.settimeout(None)
            event.update(verdict="learn" if ARGS.learn else "allow", addr=sockaddr[0])
            return s
        except OSError as e:
            event["last_error"] = str(e)
    event.update(verdict="deny", reason="connect-failed")
    return None


def pump(a, b, event):
    up = down = 0
    socks = [a, b]
    try:
        while True:
            readable, _, _ = select.select(socks, [], [], 300)
            if not readable:
                break
            for s in readable:
                data = s.recv(65536)
                if not data:
                    return up, down
                (b if s is a else a).sendall(data)
                if s is a:
                    up += len(data)
                else:
                    down += len(data)
    except OSError:
        pass
    finally:
        event.update(bytes_up=up, bytes_down=down)
    return up, down


HOP_BY_HOP = {"connection", "proxy-connection", "keep-alive", "proxy-authorization"}


def forward_one_request(conn, upstream, head, method, path, version, event):
    """Forwards exactly one plain-HTTP request, then only the answer, and the
    connection closes after it. A client that reuses the connection for
    another request, maybe to another origin, never has it sent here: it
    must connect again, and that request is checked and logged on its own."""
    lines, _, early = head.partition(b"\r\n\r\n")
    headers, length = [], 0
    for raw in lines.split(b"\r\n")[1:]:
        name = raw.split(b":", 1)[0].strip().lower().decode("latin-1")
        if name == "transfer-encoding":
            conn.sendall(b"HTTP/1.1 411 Length Required\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            event.update(verdict="deny", reason="chunked-request-body")
            return
        if name == "content-length":
            length = int(raw.split(b":", 1)[1])
        if name not in HOP_BY_HOP:
            headers.append(raw)
    body = early[:length]
    while len(body) < length:
        chunk = conn.recv(min(65536, length - len(body)))
        if not chunk:
            break
        body += chunk
    request = f"{method} {path} {version}\r\n".encode("latin-1")
    request += b"".join(h + b"\r\n" for h in headers) + b"Connection: close\r\n\r\n" + body
    upstream.sendall(request)
    up, down = len(request), 0
    try:
        while True:
            data = upstream.recv(65536)
            if not data:
                break
            conn.sendall(data)
            down += len(data)
    except OSError:
        pass
    event.update(bytes_up=up, bytes_down=down)


def read_head(conn):
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = conn.recv(4096)
        if not chunk:
            break
        data += chunk
        if len(data) > 65536:
            break
    return data


def handle(conn, peer):
    started = time.time()
    event = {"client_port": peer[1], "listener": ARGS.port}
    upstream = None
    try:
        head = read_head(conn)
        line = head.split(b"\r\n", 1)[0].decode("latin-1")
        parts = line.split()
        if len(parts) < 3:
            return
        method, target = parts[0].upper(), parts[1]
        event["method"] = method
        if method == "CONNECT":
            host, _, port = target.rpartition(":")
            upstream = open_upstream(host, int(port), event)
            if upstream is None:
                conn.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                return
            conn.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            rest = head.split(b"\r\n\r\n", 1)[1]
            if rest:
                upstream.sendall(rest)
            pump(conn, upstream, event)
        else:
            url = urlsplit(target)
            if url.scheme != "http" or not url.hostname:
                conn.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
                event.update(verdict="deny", reason="not-a-proxy-request", target=target)
                return
            upstream = open_upstream(url.hostname, url.port or 80, event)
            if upstream is None:
                conn.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                return
            path = url.path or "/"
            if url.query:
                path += "?" + url.query
            event["path"] = path
            forward_one_request(conn, upstream, head, method, path, parts[2], event)
    except Exception as e:  # noqa: BLE001 - a prototype logs and moves on
        event.setdefault("verdict", "error")
        event["error"] = repr(e)
    finally:
        event["duration_s"] = round(time.time() - started, 2)
        if "verdict" in event:
            log(event)
        for s in (conn, upstream):
            if s is not None:
                try:
                    s.close()
                except OSError:
                    pass


def main():
    global ARGS
    p = argparse.ArgumentParser()
    p.add_argument("--port", type=int, default=18080)
    p.add_argument("--allow", help="allowlist file: one host[:port] or *.domain per line")
    p.add_argument("--learn", action="store_true", help="allow any public destination, log it")
    p.add_argument("--log", help="append JSON lines here as well as to stdout")
    ARGS = p.parse_args()
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", ARGS.port))
    srv.listen(128)
    mode = "learn" if ARGS.learn else "allowlist"
    print(f"proxy listening on 127.0.0.1:{ARGS.port} ({mode})", flush=True)
    while True:
        conn, peer = srv.accept()
        threading.Thread(target=handle, args=(conn, peer), daemon=True).start()


if __name__ == "__main__":
    main()
