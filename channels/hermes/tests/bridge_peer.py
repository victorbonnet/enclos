"""The Hermes plugin's adapter, listening on a socket for a real bridge, with the
standard-library stand-ins of test_adapter.py for the Hermes classes it uses.
The bridge's own tests start it, with the `python3` on PATH
(`src/bridge/server/connection_end_tests/incoming_tests.rs`):

    python3 -I bridge_peer.py <socket> <token>

It prints `listening`, then the first message Hermes would get, with its media,
as one line of JSON, and stops when its input closes."""

import asyncio
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.dirname(HERE), HERE]

from test_adapter import _hermes_stand_ins  # noqa: E402

sys.modules.update(_hermes_stand_ins())

from enclos.adapter import EnclosAdapter  # noqa: E402
from gateway.config import PlatformConfig  # noqa: E402


async def main(socket_path: str, token: str) -> None:
    adapter = EnclosAdapter(PlatformConfig({"socket": socket_path, "token": token}))
    if not await adapter.connect():
        sys.exit("cannot listen")
    print("listening", flush=True)
    for _ in range(1200):
        if adapter.received:
            break
        await asyncio.sleep(0.05)
    else:
        sys.exit("no message came")
    event = adapter.received[0]
    print(json.dumps({"text": event.text, "message_type": event.message_type, "media_urls": event.media_urls,
                      "media_types": event.media_types}), flush=True)
    # Connected until the bridge has stored the ack that follows
    await asyncio.get_running_loop().run_in_executor(None, sys.stdin.read)
    await adapter.disconnect()


if __name__ == "__main__":
    asyncio.run(main(*sys.argv[1:3]))
