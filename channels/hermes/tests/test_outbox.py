"""The outbox keeps messages in order until acknowledged, and survives a restart."""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from enclos import protocol  # noqa: E402
from enclos.outbox import Outbox  # noqa: E402


class OutboxTest(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.mkdtemp()

    def test_messages_wait_in_order_until_acknowledged(self):
        outbox = Outbox(self.folder)
        first, second = protocol.message_out("c-1", "one"), protocol.message_out("c-1", "two")
        self.assertTrue(outbox.put(first))
        self.assertTrue(outbox.put(second))
        self.assertEqual([m["text"] for m in Outbox(self.folder).pending()], ["one", "two"])
        self.assertTrue(outbox.acknowledge(first["id"]))
        self.assertFalse(outbox.acknowledge(first["id"]))
        self.assertEqual([m["text"] for m in outbox.pending()], ["two"])

    def test_it_refuses_past_its_limit(self):
        outbox = Outbox(self.folder, limit=1)
        self.assertTrue(outbox.put(protocol.message_out("c-1", "one")))
        self.assertFalse(outbox.put(protocol.message_out("c-1", "two")))
        self.assertEqual(len(outbox.pending()), 1)

    def test_its_folder_is_the_users_alone(self):
        folder = os.path.join(self.folder, "new")
        Outbox(folder)
        self.assertEqual(os.stat(folder).st_mode & 0o777, 0o700)


if __name__ == "__main__":
    unittest.main()
