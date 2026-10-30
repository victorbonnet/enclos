"""Tests of the host's path to a sandbox's service that need no sockets: the
WebSocket frames, the port the holder reads, the client's reading of a page
and the host's choice of a port by its holder. Pure, so it runs anywhere:

    python3 -I prototype/m3/test_host_path.py
"""

import importlib.util
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import relay  # noqa: E402
import wsmini  # noqa: E402


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), f"{HERE}/{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Frames(unittest.TestCase):
    def test_the_accept_key_is_the_rfcs_example(self):
        self.assertEqual(wsmini.accept_key("dGhlIHNhbXBsZSBub25jZQ=="), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")

    def test_a_frame_round_trips_at_every_length_form_masked_and_not(self):
        for n in (0, 125, 126, 65535, 65536):
            for mask in (None, b"\x01\x02\x03\x04"):
                frame = wsmini.encode(b"x" * n, mask=mask)
                self.assertEqual(wsmini.decode(frame), (wsmini.TEXT, b"x" * n, len(frame)))

    def test_a_partial_frame_waits_for_more(self):
        frame = wsmini.encode(b"hello", mask=b"\x01\x02\x03\x04")
        for cut in range(len(frame)):
            self.assertIsNone(wsmini.decode(frame[:cut]))


class Port(unittest.TestCase):
    def test_only_a_valid_port_is_read(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "service.port")
            self.assertIsNone(relay.read_port(path))
            for text, want in (("41000\n", 41000), ("0", None), ("70000", None), ("nope", None), ("", None)):
                with open(path, "w") as f:
                    f.write(text)
                self.assertEqual(relay.read_port(path), want, text)


class Page(unittest.TestCase):
    def test_assets_are_the_pages_own_paths_once_each(self):
        client = load("host-client")
        body = (b'<script src="/assets/a.js"></script><link href="./b.css">'
                b'<script src="/assets/a.js"></script><a href="https://example.com/x">')
        self.assertEqual(client.assets_of(body), ["/assets/a.js", "/b.css"])

    def test_the_token_goes_in_the_query_only_when_there_is_one(self):
        client = load("host-client")
        self.assertEqual(client.with_token("/api/ws", None), "/api/ws")
        self.assertEqual(client.with_token("/api/ws", "a b"), "/api/ws?token=a+b")
        self.assertEqual(client.with_token("/w?x=1", "t"), "/w?x=1&token=t")


class Terminal(unittest.TestCase):
    def test_typed_text_is_found_among_control_sequences(self):
        client = load("host-client")
        out = "\x1b[2J\x1b[1;1H\x1b]0;title\x07> \x1b[1menclos\x1b[0mmark\r\n"
        self.assertEqual(client.plain(out), "> enclosmark")


class Listeners(unittest.TestCase):
    def test_another_sessions_port_is_left_out(self):
        listeners = load("ns-listeners")
        ports = {40000: "1", 40001: "2", 40002: "3"}
        held = {"1": {"10:hermes"}, "2": {"20:python3"}}
        self.assertEqual(listeners.held_only(ports, held, ["10", "11"]), {40000: "1"})


if __name__ == "__main__":
    unittest.main()
