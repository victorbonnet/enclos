"""The bridge's lines, as the plugin reads them off its socket.

A line may be as long as the protocol allows (1 MiB), past asyncio's 64 KiB
default. One longer than that is read to its end and dropped, so the next
line reads as it should, and the plugin answers it with an `error` naming
its id, when its first bytes hold one: the bridge then knows at once that
the message did not arrive, instead of waiting for an answer.
"""

import asyncio
import re

from . import protocol

# What the plugin's socket reads of one line: the protocol's most, and its
# line break.
LIMIT = protocol.MAX_MESSAGE_BYTES + 1

# A message's id, which the bridge writes second, after `v`.
_ID = re.compile(rb'"id"\s*:\s*"([^"\\\x00-\x1f]{1,128})"')
_HEAD = 512


class TooLong(Exception):
    """A line longer than the reader's limit, read to its end and dropped.
    `message_id` is its id, when its first bytes say it."""

    def __init__(self, message_id: str | None):
        super().__init__(f"a line longer than {protocol.MAX_MESSAGE_BYTES} bytes")
        self.message_id = message_id


async def read_line(reader: asyncio.StreamReader) -> bytes:
    """The next line, with its line break; what is left at the end, `b""`
    once nothing is. Raises TooLong for a line over the reader's limit."""
    try:
        return await reader.readuntil(b"\n")
    except asyncio.IncompleteReadError as e:
        return e.partial
    except asyncio.LimitOverrunError as e:
        consumed = e.consumed
    # Too long: what asyncio left in its buffer is read and dropped, a
    # piece at a time, up to the line's end.
    head = b""
    while True:
        try:
            piece = await reader.readexactly(consumed)
        except asyncio.IncompleteReadError as e:
            piece = e.partial
            head += piece[: max(0, _HEAD - len(head))]
            break
        head += piece[: max(0, _HEAD - len(head))]
        try:
            await reader.readuntil(b"\n")
            break
        except asyncio.IncompleteReadError:
            break
        except asyncio.LimitOverrunError as again:
            consumed = again.consumed
    found = _ID.search(head)
    raise TooLong(found.group(1).decode("utf-8", "replace") if found else None)
