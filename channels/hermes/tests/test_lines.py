"""Reading the bridge's lines: long ones read, too long ones dropped whole.

    python3 -I -m unittest discover -s channels/hermes/tests
"""

import asyncio
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))

from enclos import lines, protocol  # noqa: E402


def read_all(pieces: list[bytes], limit: int) -> list:
    """What `read_line` makes of `pieces`, arriving one after the other."""

    async def go() -> list:
        reader = asyncio.StreamReader(limit=limit)

        async def feed() -> None:
            for piece in pieces:
                reader.feed_data(piece)
                await asyncio.sleep(0)
            reader.feed_eof()

        feeding = asyncio.ensure_future(feed())
        out: list = []
        while True:
            try:
                line = await lines.read_line(reader)
            except lines.TooLong as e:
                out.append(("too long", e.message_id))
                continue
            if not line:
                break
            out.append(line)
        await feeding
        return out

    return asyncio.run(go())


class ReadLineTest(unittest.TestCase):
    def test_the_socket_reads_lines_up_to_the_protocols_limit(self):
        self.assertEqual(lines.LIMIT, protocol.MAX_MESSAGE_BYTES + 1)
        long = b'{"v":1,"id":"m-1","type":"message.in","text":"' + b"x" * 100_000 + b'"}\n'
        self.assertEqual(read_all([long], lines.LIMIT), [long])

    def test_a_line_too_long_is_dropped_whole_and_named_by_its_id(self):
        long = b'{"v":1,"id":"m-1","type":"message.in","text":"' + b"x" * 300 + b'"}\n'
        nxt = b'{"v":1,"id":"m-2","type":"ack","of":"x"}\n'
        # At once, and in pieces with no line break in the first.
        for pieces in ([long + nxt], [long[:100], long[100:250], long[250:] + nxt]):
            self.assertEqual(read_all(pieces, 64), [("too long", "m-1"), nxt], pieces)

    def test_a_line_too_long_without_an_id_or_an_end(self):
        self.assertEqual(read_all([b"y" * 300], 64), [("too long", None)])
        self.assertEqual(read_all([b"y" * 300 + b"\n", b"ok\n"], 64), [("too long", None), b"ok\n"])

    def test_the_last_line_without_a_break_is_read(self):
        self.assertEqual(read_all([b"a\n", b"b"], 64), [b"a\n", b"b"])


if __name__ == "__main__":
    unittest.main()
