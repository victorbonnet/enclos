# PROTOTYPE ONLY: blocking sendall and paired close on EOF are not production safe.
# M3-09 must implement bounded backpressure and independent half-closes,
# with large simultaneous bidirectional transfer and request-half-close tests.
"""The relay (design §5, Linux networking; M3-09 builds the real one): accepts
TCP connections on a listening socket inside the sandbox and forwards each to
the proxy's Unix socket, and nothing else. inside.py makes the listening
socket on 127.0.0.1 and calls serve() in a child process."""

import select
import socket
import threading


def pump(a, b):
    socks = [a, b]
    try:
        while True:
            readable, _, _ = select.select(socks, [], [], 600)
            if not readable:
                return
            for s in readable:
                data = s.recv(65536)
                if not data:
                    return
                (b if s is a else a).sendall(data)
    except OSError:
        pass
    finally:
        a.close()
        b.close()


def one(conn, path):
    up = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        up.connect(path)
    except OSError:
        conn.close()
        up.close()
        return
    pump(conn, up)


def serve(srv, path):
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=one, args=(conn, path), daemon=True).start()
