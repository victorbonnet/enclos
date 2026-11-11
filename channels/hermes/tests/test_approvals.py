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

    def test_a_request_goes_through_the_agents_the_conversation_reached(self):
        main, coder = Mock(_last_in={"c-main": ("m1", 0.0)}), Mock(_last_in={"g": ("m2", 0.0)})
        main._last_in["g"] = ("m3", 0.0)
        self.assertEqual(approvals.routes({main, coder}, "c-main"), [main])
        self.assertCountEqual(approvals.routes({main, coder}, "g"), [main, coder])
        # Before any message came: every connected agent; the bridge keeps it for the right one.
        self.assertCountEqual(approvals.routes({main, coder}, "new"), [main, coder])

    def test_only_an_enclos_conversation_files_a_request(self):
        env = {"HERMES_SESSION_PLATFORM": "telegram", "HERMES_SESSION_CHAT_ID": "12345"}
        module = types.ModuleType("gateway.session_context")
        module.get_session_env = lambda name: env.get(name)
        with patch.dict(sys.modules, {"gateway": types.ModuleType("gateway"), "gateway.session_context": module}):
            self.assertIsNone(approvals.session("enclos"))
            adapter = Mock(_last_in={"12345": ("m", 0.0)})
            ctx = Mock()
            approvals.register(ctx, {adapter}, lambda: "/absent/main.sock", "enclos")
            handler = ctx.register_tool.call_args.kwargs["handler"]
            self.assertIn("error", json.loads(handler({"kind": "write", "target": "/work/a"})))
            adapter._outbox.put.assert_not_called()
            env["HERMES_SESSION_PLATFORM"] = "enclos"
            self.assertEqual(approvals.session("enclos"), "12345")

    def test_request_has_no_authority_or_raw_tool_output(self):
        request = approvals.request("c1", "write", "/work/a")
        self.assertEqual(request["type"], "approval.request")
        self.assertNotIn("approve", request)
        with self.assertRaises(ValueError): approvals.request("c1", "exec", "rm")
