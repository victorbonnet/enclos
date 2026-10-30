"""The relay (design §5, Linux networking; M3-09 builds the real one): accepts
TCP connections on a listening socket inside the sandbox and forwards each to
the proxy's Unix socket, and nothing else. inside.py makes the listening
socket on 127.0.0.1 and calls serve() in a child process.

One thread per direction, so a direction blocked on a slow reader never holds
up the other, and the kernel's socket buffers are the only buffering. An EOF
ends one direction only. README.md says what M3-09 may take from this."""

import socket
import threading


def forward(src, dst, peer_gone):
    try:
        while data := src.recv(65536):
            dst.sendall(data)
        dst.shutdown(socket.SHUT_WR)
    except OSError:
        peer_gone()


def pump(a, b):
    def peer_gone():  # wakes the other direction, which may be blocked
        for s in (a, b):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    back = threading.Thread(target=forward, args=(b, a, peer_gone), daemon=True)
    back.start()
    forward(a, b, peer_gone)
    back.join()
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
