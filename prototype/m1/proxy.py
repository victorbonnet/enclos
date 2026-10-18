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


def public_addresses(host, port):
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    good = []
    for family, _, _, _, sockaddr in infos:
        ip = ipaddress.ip_address(sockaddr[0])
        carried = ip.ipv4_mapped if isinstance(ip, ipaddress.IPv6Address) else None
        if (carried or ip).is_global and (family, sockaddr) not in good:
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
            first, rest = head.split(b"\r\n", 1)
            upstream.sendall(f"{method} {path} {parts[2]}\r\n".encode("latin-1") + rest)
            pump(conn, upstream, event)
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
