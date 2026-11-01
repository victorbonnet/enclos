"""Tests of the prototype's relay over a loopback port and a Unix socket in a
temporary folder. They touch no namespace and run no bubblewrap, so they run
anywhere:

    python3 -I prototype/m3/test_relay.py
"""

import hashlib
import os
import socket
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import relay  # noqa: E402

CHUNK = 64 * 1024
LARGE = 64 * 1024 * 1024  # far beyond the sockets' buffers
LIMIT = 30  # seconds; the old relay never ended, so a hang is a failure


class RelayTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        path = os.path.join(self.tmp.name, "proxy.sock")
        self.proxy = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.proxy.bind(path)
        self.proxy.listen(8)
        self.addCleanup(self.proxy.close)
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.bind(("127.0.0.1", 0))
        srv.listen(8)
        self.port = srv.getsockname()[1]
        self.addCleanup(srv.close)
        threading.Thread(target=relay.serve, args=(srv, path), daemon=True).start()

    def client(self):
        c = socket.create_connection(("127.0.0.1", self.port), timeout=LIMIT)
        self.addCleanup(c.close)
        return c

    def proxy_side(self, handle):
        """Run `handle` on the next connection the proxy gets; returns what
        it returned, or fails when it has not ended in time."""
        result = {}

        def run():
            conn, _ = self.proxy.accept()
            with conn:
                conn.settimeout(LIMIT)
                result["value"] = handle(conn)

        t = threading.Thread(target=run, daemon=True)
        t.start()

        def wait():
            t.join(LIMIT)
            self.assertFalse(t.is_alive(), "the proxy's side never ended")
            return result.get("value")

        return wait

    def in_time(self, target):
        t = threading.Thread(target=target, daemon=True)
        t.start()
        return t

    def test_a_large_transfer_both_ways_at_once(self):
        # An echo that writes each chunk back before it reads the next, as a
        # server that answers while still reading does. The relay must keep
        # the answers moving while its other direction is blocked.
        def echo(conn):
            while data := conn.recv(CHUNK):
                conn.sendall(data)
            conn.shutdown(socket.SHUT_WR)

        wait = self.proxy_side(echo)
        c = self.client()
        block = os.urandom(CHUNK)
        sent = hashlib.sha256()
        received = hashlib.sha256()
        counts = {"received": 0}

        def write():
            for _ in range(LARGE // CHUNK):
                c.sendall(block)
                sent.update(block)
            c.shutdown(socket.SHUT_WR)

        def read():
            while data := c.recv(CHUNK):
                received.update(data)
                counts["received"] += len(data)

        threads = [self.in_time(write), self.in_time(read)]
        for t in threads:
            t.join(LIMIT)
            self.assertFalse(t.is_alive(), "the transfer stalled")
        wait()
        self.assertEqual(counts["received"], LARGE)
        self.assertEqual(received.digest(), sent.digest())

    def test_a_client_half_close_leaves_the_answer_coming(self):
        def answer_after_eof(conn):
            got = b""
            while data := conn.recv(CHUNK):
                got += data
            conn.sendall(b"answer to " + got)

        wait = self.proxy_side(answer_after_eof)
        c = self.client()
        c.sendall(b"request")
        c.shutdown(socket.SHUT_WR)
        got = b""
        while data := c.recv(CHUNK):
            got += data
        self.assertEqual(got, b"answer to request")
        wait()

    def test_a_proxy_half_close_leaves_the_client_sending(self):
        def close_first(conn):
            conn.sendall(b"go ahead")
            conn.shutdown(socket.SHUT_WR)
            got = b""
            while data := conn.recv(CHUNK):
                got += data
            return got

        wait = self.proxy_side(close_first)
        c = self.client()
        got = b""
        while data := c.recv(CHUNK):
            got += data
        self.assertEqual(got, b"go ahead")
        c.sendall(b"still here")
        c.shutdown(socket.SHUT_WR)
        self.assertEqual(wait(), b"still here")

    def test_a_refused_proxy_closes_the_client(self):
        os.unlink(self.proxy.getsockname())
        c = self.client()
        self.assertEqual(c.recv(1), b"")


class PumpTest(unittest.TestCase):
    def test_a_reset_ends_both_directions(self):
        left, relay_left = socket.socketpair()
        right, relay_right = socket.socketpair()
        self.addCleanup(left.close)
        self.addCleanup(right.close)
        t = threading.Thread(target=relay.pump, args=(relay_left, relay_right), daemon=True)
        t.start()
        right.close()  # no half-close: the far end is gone
        left.settimeout(LIMIT)
        left.sendall(b"x")
        self.assertEqual(left.recv(1), b"")
        left.close()
        t.join(LIMIT)
        self.assertFalse(t.is_alive())


if __name__ == "__main__":
    unittest.main()
