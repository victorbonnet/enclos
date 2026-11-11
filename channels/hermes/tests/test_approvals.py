import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
import types
from unittest.mock import Mock, patch
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from enclos import approvals, protocol

class Approvals(unittest.TestCase):
    def test_only_a_concrete_denied_file_operation_is_automatically_reported(self):
        self.assertEqual(approvals.blocked_file("write_file", {"path": "/work/a.txt"}, {"error": "Permission denied"}), ("write", "/work/a.txt"))
        for name, args, result in [("terminal", {"command": "cat secret"}, {"error": "Permission denied"}), ("write_file", {"path": "relative"}, {"error": "Permission denied"}), ("read_file", {"path": "/work/a"}, {"error": "File not found"}), ("read_file", {"path": "/work/a"}, {"content": "Permission denied is a phrase"})]:
            self.assertIsNone(approvals.blocked_file(name, args, result))

    def test_context_is_durable_and_replaced_not_appended(self):
        with tempfile.TemporaryDirectory() as d:
            socket = str(Path(d) / "main.sock")
            approvals.save_context(socket, "policy 1")
            approvals.save_context(socket, "policy 2: example.com is allowed")
            self.assertEqual(Path(socket + ".policy-context").read_text(), "policy 2: example.com is allowed")
            decoded = protocol.decode_from_bridge(protocol.encode_line({"v": 1, "id": "m", "type": "policy.context", "text": "policy 2"}))
            self.assertEqual(decoded["text"], "policy 2")

    def test_handler_uses_hermes_dictionary_call_contract(self):
        ctx = Mock()
        approvals.register(ctx, set(), lambda: "/absent/main.sock")
        handler = ctx.register_tool.call_args.kwargs["handler"]
        result = json.loads(handler({"kind": "write", "target": "/work/a"}))
        self.assertIn("error", result)  # no active Hermes conversation

    def test_the_tool_says_what_the_bridge_answered(self):
        import asyncio
        import threading

        class Bridge:
            """An agent's connection whose bridge answers each request with `reply`."""
            def __init__(self, loop, reply):
                self._loop, self._reply, self._answers = loop, reply, {}
                self._path = "/absent/main.sock"
                self._outbox = Mock()
                self._outbox.put.return_value = True

            async def _write(self, message):
                if self._reply == "silent":
                    return True
                if self._reply:
                    approvals.answered(self._answers, protocol.error("not_allowed", self._reply, message["id"]))
                approvals.answered(self._answers, protocol.ack(message["id"]))
                return True

        loop = asyncio.new_event_loop()
        threading.Thread(target=loop.run_forever, daemon=True).start()
        self.addCleanup(loop.call_soon_threadsafe, loop.stop)
        module = types.ModuleType("gateway.session_context")
        module.get_session_env = lambda name: "c1" if name == "HERMES_SESSION_CHAT_ID" else None

        def ask(reply):
            ctx = Mock()
            approvals.register(ctx, {Bridge(loop, reply)}, lambda: "/absent/main.sock")
            return json.loads(ctx.register_tool.call_args.kwargs["handler"]({"kind": "network", "target": "example.com:443"}))

        with patch.dict(sys.modules, {"gateway": types.ModuleType("gateway"), "gateway.session_context": module}):
            self.assertEqual(ask(None)["status"], "requested")
            closed = ask("A request for this scope was already closed.")
            self.assertNotIn("status", closed)
            self.assertIn("already closed", closed["error"])
            with patch.object(approvals, "ANSWER_SECONDS", 0.05):
                self.assertEqual(ask("silent")["status"], "queued")

    def test_request_has_no_authority_or_raw_tool_output(self):
        request = approvals.request("c1", "write", "/work/a")
        self.assertEqual(request["type"], "approval.request")
        self.assertNotIn("approve", request)
        with self.assertRaises(ValueError): approvals.request("c1", "exec", "rm")
