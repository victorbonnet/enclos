"""The plugin's protocol against the enclos-protocol crate's own fixtures.

    python3 -I -m unittest discover -s channels/hermes/tests
"""

import json
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
FIXTURES = os.path.join(HERE, "..", "..", "..", "crates", "enclos-protocol", "tests", "fixtures", "plugin")

from enclos import protocol  # noqa: E402


def fixture(name: str) -> bytes:
    with open(os.path.join(FIXTURES, name), "rb") as f:
        return f.read()


class FromTheBridge(unittest.TestCase):
    def test_every_fixture_the_bridge_sends_decodes(self):
        names = sorted(n for n in os.listdir(FIXTURES) if n.startswith("from_bridge_"))
        self.assertEqual(len(names), 3)
        for name in names:
            with self.subTest(name):
                self.assertEqual(protocol.decode_from_bridge(fixture(name)), json.loads(fixture(name)))

    def test_unknown_type_bad_fields_and_other_versions_are_told_apart(self):
        cases = [
            (b'{"v":1,"id":"m1","type":"message.edit"}', "unknown_type"),
            (b'{"v":1,"id":"m1","type":"message.in","text":"no conversation"}', "bad_message"),
            (b'{"v":2,"id":"m1","type":"ack","of":"m0"}', "version"),
            (b'{"id":"m1","type":"ack","of":"m0"}', "bad_message"),
            (b'{"v":1,"id":"","type":"ack","of":"m0"}', "bad_message"),
            (b'{"v":1,"id":"m1","type":"message.in","conversation":"c\\u0000","person":"p","text":"t"}', "bad_message"),
            (b"[1,2]", "bad_message"),
            (b" " * (protocol.MAX_MESSAGE_BYTES + 1), "bad_message"),
        ]
        for line, code in cases:
            with self.subTest(line[:40]):
                with self.assertRaises(protocol.DecodeError) as raised:
                    protocol.decode_from_bridge(line)
                self.assertEqual(raised.exception.code, code)

    def test_unknown_fields_are_ignored(self):
        message = protocol.decode_from_bridge(b'{"v":1,"id":"m1","type":"ack","of":"m0","later":true}')
        self.assertEqual(message["of"], "m0")


class ToTheBridge(unittest.TestCase):
    def assert_like_fixture(self, message, name):
        expected = json.loads(fixture(name))
        self.assertEqual(set(message), set(expected), name)
        for key in expected:
            if key != "id":
                self.assertEqual(message[key], expected[key], f"{name}: {key}")

    def test_messages_have_the_fixtures_shape(self):
        reply_to = json.loads(fixture("from_plugin_message_out_reply.json"))["reply_to"]
        self.assert_like_fixture(protocol.hello("hermes", "main"), "from_plugin_hello.json")
        self.assert_like_fixture(
            protocol.message_out("c-42", "14 °C and cloudy.", reply_to), "from_plugin_message_out_reply.json")
        self.assert_like_fixture(
            protocol.message_out("c-42", "Good morning: 9 °C in Paris."), "from_plugin_message_out_notify.json")
        self.assert_like_fixture(protocol.typing("c-42", True), "from_plugin_typing.json")

    def test_a_line_has_no_line_break_inside(self):
        line = protocol.encode_line(protocol.message_out("c-1", "two\nlines"))
        self.assertTrue(line.endswith(b"\n"))
        self.assertNotIn(b"\n", line[:-1])
        self.assertEqual(json.loads(line)["text"], "two\nlines")


class Token(unittest.TestCase):
    def test_only_the_agents_token_matches(self):
        self.assertTrue(protocol.token_matches("t0ken", "t0ken"))
        self.assertFalse(protocol.token_matches("t0ken2", "t0ken"))
        self.assertFalse(protocol.token_matches(None, "t0ken"))
        self.assertFalse(protocol.token_matches("", ""))


class Hint(unittest.TestCase):
    """The hint promises what the app draws, and nothing it does not."""

    def test_it_names_what_the_app_draws(self):
        for element in ("bold", "italic", "strikethrough", "inline code", "headings", "lists",
                        "quotes", "code blocks", "tables", "links", "newline"):
            with self.subTest(element):
                self.assertIn(element, protocol.PLATFORM_HINT)

    def test_it_says_images_and_html_are_not_drawn(self):
        self.assertIn("Images are not shown", protocol.PLATFORM_HINT)
        self.assertIn("HTML shows as literal text", protocol.PLATFORM_HINT)

    def test_it_stays_short_for_every_prompt(self):
        self.assertLess(len(protocol.PLATFORM_HINT), 600)


if __name__ == "__main__":
    unittest.main()
