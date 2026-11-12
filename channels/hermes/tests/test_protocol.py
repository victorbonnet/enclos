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
        self.assertEqual(len(names), 6)
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
            (b"[" * 100_000, "bad_message"),
            (b'{"v":1,"id":"m1","type":"error","code":"bad_message","message":"red \\u001b[31m"}', "bad_message"),
            (b'{"v":1,"id":"m1","type":"error","code":"bad_message","message":"two\\nlines"}', "bad_message"),
            (b'{"v":1,"id":"m1","type":"error","code":"bad_message","of":"","message":"x"}', "bad_message"),
        ]
        for line, code in cases:
            with self.subTest(line[:40]):
                with self.assertRaises(protocol.DecodeError) as raised:
                    protocol.decode_from_bridge(line)
                self.assertEqual(raised.exception.code, code)

    def test_unknown_fields_are_ignored(self):
        message = protocol.decode_from_bridge(b'{"v":1,"id":"m1","type":"ack","of":"m0","later":true}')
        self.assertEqual(message["of"], "m0")

    def test_the_hello_names_the_agents_home_or_not(self):
        self.assertEqual(protocol.decode_from_bridge(fixture("from_bridge_hello_home.json"))["home"], "home.lab.main")
        self.assertNotIn("home", protocol.decode_from_bridge(fixture("from_bridge_hello.json")))
        with self.assertRaises(protocol.DecodeError):
            protocol.decode_from_bridge(b'{"v":1,"id":"m1","type":"hello","token":"t","home":""}')


class Home(unittest.TestCase):
    def test_hermes_notices_about_itself_are_told_apart(self):
        notices = [
            "♻️ Gateway online — Hermes is back and ready.",
            "⚠️ Hermes is shutting down — your current task will be interrupted. When it is back online, "
            "send any message and I'll try to pick up where we left off.",
            "⚠️ Hermes is restarting — your current task will be interrupted.",
            "📬 No home channel is set for Enclos. A home channel is where Hermes delivers cron job results.",
        ]
        for text in notices:
            with self.subTest(text[:20]):
                self.assertTrue(protocol.is_notice(text))
        for text in ["Gateway online is a nice name", "Hermes is shutting down the server, as asked.", ""]:
            with self.subTest(text[:20]):
                self.assertFalse(protocol.is_notice(text))

    def test_a_reply_that_starts_as_a_notice_reads_as_one(self):
        # A notice is told by its first words only, as Hermes marks none: an
        # agent's reply that starts with the same words is taken for one
        # (a quiet line, and no title check). The choice, recorded.
        self.assertTrue(protocol.is_notice(
            "\u267b\ufe0f Gateway online \u2014 that is what the log said at 9:00."))

    def test_sethome_is_caught_however_written(self):
        for text in ["/sethome", "  /SetHome ", "/set-home now"]:
            self.assertTrue(protocol.is_home_command(text), text)
        for text in ["sethome", "/sethomes", "how do I /sethome?", ""]:
            self.assertFalse(protocol.is_home_command(text), text)


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
        self.assert_like_fixture(
            protocol.message_out("home.lab.main", "Gateway online", kind="status"),
            "from_plugin_message_out_status.json")
        self.assert_like_fixture(protocol.typing("c-42", True), "from_plugin_typing.json")
        self.assert_like_fixture(protocol.commands([
            ("new", "Start a new session (fresh session ID + history)", "[name]"),
            ("model", "Switch model for this session", "[model] [--provider name] [--global]"),
            ("stop", "Kill all running background processes", ""),
        ]), "from_plugin_commands.json")
        self.assert_like_fixture(
            protocol.title("c-42", "Paris weather this week"), "from_plugin_conversation_title.json")
        self.assert_like_fixture(
            protocol.tool("c-42", "call_7Hq2", "web_search", "start", label="weather Paris this week"),
            "from_plugin_tool_start.json")
        self.assert_like_fixture(
            protocol.tool("c-42", "call_7Hq2", "web_search", "end", ok=True, duration_ms=1840),
            "from_plugin_tool_end.json")

    def test_hermes_uniqueness_suffix_is_dropped(self):
        self.assertEqual(protocol.runtime_title("Paris weather #2"), "Paris weather")
        self.assertEqual(protocol.runtime_title("  Paris   weather "), "Paris weather")
        self.assertEqual(protocol.runtime_title("Issue #42 triage"), "Issue #42 triage")

    def test_a_title_is_one_short_line(self):
        message = protocol.title("c-1", "  Paris\nweather   " + "x" * 200)
        self.assertNotIn("\n", message["title"])
        self.assertTrue(message["title"].startswith("Paris weather x"))
        self.assertEqual(len(message["title"]), protocol.MAX_TITLE_CHARS)

    def test_a_line_has_no_line_break_inside(self):
        line = protocol.encode_line(protocol.message_out("c-1", "two\nlines"))
        self.assertTrue(line.endswith(b"\n"))
        self.assertNotIn(b"\n", line[:-1])
        self.assertEqual(json.loads(line)["text"], "two\nlines")


class Unsendable(unittest.TestCase):
    def test_what_the_bridge_would_refuse_is_named(self):
        self.assertIsNone(protocol.unsendable(protocol.message_out("c-1", "fine", "m0")))
        self.assertIsNone(protocol.unsendable(protocol.message_out("c-1", "x" * (protocol.MAX_MESSAGE_BYTES - 200))))
        for message in (
            protocol.message_out("", "hi"),
            protocol.message_out("c" * 129, "hi"),
            protocol.message_out("c-1\u0085", "hi"),
            protocol.message_out("c-1", "hi", "m\u0000"),
            protocol.message_out("c-1", "x" * protocol.MAX_MESSAGE_BYTES),
        ):
            with self.subTest(message["conversation"][:8]):
                self.assertIsNotNone(protocol.unsendable(message))


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

    def test_it_says_how_files_go_and_what_is_not_drawn(self):
        self.assertIn("MEDIA:/absolute/path/to/file", protocol.PLATFORM_HINT)
        self.assertIn("remote image in markdown is not loaded", protocol.PLATFORM_HINT)
        self.assertIn("message HTML shows as literal text", protocol.PLATFORM_HINT)

    def test_it_explains_how_to_send_a_static_artefact_and_its_limits(self):
        for detail in ("static HTML artefact", "self-contained UTF-8 .html", "inline CSS",
                       "data images/fonts", "JavaScript", "external resources, forms and automatic navigation are blocked",
                       "A tapped HTTP(S) link opens the browser", "once the person confirms its address"):
            self.assertIn(detail, protocol.PLATFORM_HINT)

    def test_it_says_what_an_image_shows_as_the_protocol_does(self):
        # docs/protocol.md, "What the agent says is markdown", and the app's spec
        self.assertIn("an image shows as its alt text, a link to it", protocol.PLATFORM_HINT)

    def test_it_stays_short_for_every_prompt(self):
        self.assertLess(len(protocol.PLATFORM_HINT), 1000)


class Files(unittest.TestCase):
    def test_an_html_artefact_uses_an_ordinary_file_attachment(self):
        expected = json.loads(fixture("from_plugin_message_out_html.json"))
        message = protocol.message_out(
            expected["conversation"], expected["text"], expected["reply_to"],
            [protocol.attachment(**expected["attachments"][0])])
        self.assertEqual({k: v for k, v in message.items() if k != "id"},
                         {k: v for k, v in expected.items() if k != "id"})

    def test_a_reply_with_an_image_has_the_fixtures_shape(self):
        expected = json.loads(fixture("from_plugin_message_out_image.json"))
        a = expected["attachments"][0]
        message = protocol.message_out(
            "c-42", expected["text"], expected["reply_to"],
            [protocol.attachment(a["file"], a["mime"], a["name"], a["size"])])
        self.assertEqual({k: v for k, v in message.items() if k != "id"},
                         {k: v for k, v in expected.items() if k != "id"})

    def test_local_markdown_images_are_taken_out_and_web_ones_stay(self):
        text = ("Here's your unicorn on the moon:\n\n"
                "![Unicorn on the moon](cache/generated/images/krea_1.png)\n\n"
                "And a [link](https://enclos.dev) and ![web](https://x.y/a.png).")
        rest, found = protocol.local_images(text)
        self.assertEqual(found, [("Unicorn on the moon", "cache/generated/images/krea_1.png")])
        self.assertEqual(rest, "Here's your unicorn on the moon:\n\n"
                               "And a [link](https://enclos.dev) and ![web](https://x.y/a.png).")

    def test_a_local_image_that_cannot_be_sent_stays_in_the_text(self):
        text = "Two:\n\n![a](images/a.png)\n\n![b](/etc/b.png)"
        rest, found = protocol.local_images(text, lambda path: path == "images/a.png")
        self.assertEqual(found, [("a", "images/a.png")])
        self.assertEqual(rest, "Two:\n\n![b](/etc/b.png)")

    def test_a_file_that_could_not_be_sent_is_said_in_the_text(self):
        self.assertEqual(protocol.with_files_not_sent("Here", []), "Here")
        self.assertEqual(protocol.with_files_not_sent("Here", ["a.pdf"]),
                         "Here\n\n(A file could not be sent: a.pdf)")
        self.assertEqual(protocol.with_files_not_sent("", ["a.pdf", "b.png"]),
                         "(A file could not be sent: a.pdf)\n(A file could not be sent: b.png)")


class CommandsTest(unittest.TestCase):
    def test_each_once_without_slash_and_without_what_the_app_does_not_offer(self):
        message = protocol.commands([
            ("/new", "Start a new\n session", "[name]"),
            ("new", "again", ""),
            ("sethome", "Set the home channel", ""),
            ("start", "Telegram's start", ""),
            ("usage", "Show token usage", "  "),
        ])
        self.assertEqual(message["commands"], [
            {"name": "new", "description": "Start a new session", "args": "[name]"},
            {"name": "usage", "description": "Show token usage"},
        ])

    def test_hello_says_commands_only_when_listed(self):
        self.assertNotIn("commands", protocol.hello("hermes", "main")["capabilities"])
        self.assertIn("commands", protocol.hello("hermes", "main", ("commands",))["capabilities"])


if __name__ == "__main__":
    unittest.main()
