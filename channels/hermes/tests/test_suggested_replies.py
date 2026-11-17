"""Reply metadata is scoped, visible and non-authoritative."""
import asyncio
import sys
import types
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from enclos import suggested_replies


class Replies(unittest.TestCase):
    def test_visible_distinct_bounded_replies_are_literal(self):
        labels = ["Fix Inbox filters", "Keep paused"]
        self.assertEqual(suggested_replies.validate(labels), labels)
        for bad in [[], ["same", "same"], ["Allow\nall"], ["Allow\u202eall"], ["x" * 257], [1], [str(i) for i in range(5)]]:
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                suggested_replies.validate(bad)


class Correlation(unittest.IsolatedAsyncioTestCase):
    async def test_a_new_person_message_and_timeout_discard_abandoned_turn_metadata(self):
        adapter = types.SimpleNamespace(_last_in={"home": ("m1", 1)}, _suggested_replies={})
        now = asyncio.get_running_loop().time()
        adapter._suggested_replies["home"] = (("m1", 1), now, ["Fix it"])
        self.assertEqual(suggested_replies.take(adapter, "another"), [])
        self.assertEqual(suggested_replies.take(adapter, "home", "older-message"), [])
        self.assertEqual(suggested_replies.take(adapter, "home"), ["Fix it"])
        self.assertEqual(suggested_replies.take(adapter, "home"), [])
        adapter._suggested_replies["home"] = (("m1", 1), now, ["Old"])
        adapter._last_in["home"] = ("m2", 2)
        self.assertEqual(suggested_replies.take(adapter, "home"), [])
        adapter._suggested_replies["home"] = (("m2", 2), now - 301, ["Old"])
        self.assertEqual(suggested_replies.take(adapter, "home"), [])
