"""Exercise the real fixture callback without leaking its runtime stand-ins."""
import os
from pathlib import Path
import subprocess
import sys
import unittest


class RefusalGateTests(unittest.TestCase):
    def test_protocol_error_waits_for_owned_release_and_ack_bypasses(self):
        code = r'''
import asyncio
import sys
sys.path.insert(0, sys.argv[1])
from bridge_peer import refusal_gate
from enclos import protocol

async def check():
    entered = asyncio.Event()
    released = asyncio.Event()
    written = []
    async def wait_for_release():
        entered.set()
        await released.wait()
    async def write(message):
        written.append(message)
        return "written"
    gated = refusal_gate(write, wait_for_release)
    refusal = protocol.error("operation_failed", "fixture", of="original")
    assert refusal["type"] == "error"
    task = asyncio.create_task(gated(refusal))
    gate_entered = asyncio.create_task(entered.wait())
    try:
        # Both branches terminate: a broken discriminator completes task;
        # a correct one reaches our owned, unreleased Event.
        await asyncio.wait({task, gate_entered}, return_when=asyncio.FIRST_COMPLETED)
        assert entered.is_set(), "real protocol.error bypassed refusal gate"
        assert not task.done(), "error completed before release"
        assert written == [], "writer invoked before release"
        ack = protocol.ack("ordinary")
        assert await gated(ack) == "written"
        assert written == [ack]
        released.set()
        assert await task == "written"
        assert written == [ack, refusal]
        assert written[1] is refusal, "gate changed envelope"
    finally:
        released.set()
        await asyncio.gather(task, return_exceptions=True)
        gate_entered.cancel()
        await asyncio.gather(gate_entered, return_exceptions=True)
asyncio.run(check())
'''
        result = subprocess.run(
            [sys.executable, "-I", "-c", code, os.fspath(Path(__file__).parent)],
            capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
