"""Selected conversation checks; no provider, credential or network calls."""
import contextlib
import os
import sys
import types
import unittest
from unittest.mock import Mock, patch
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from enclos import image_eligibility


class Eligibility(unittest.TestCase):
    def test_native_aux_neither_unknown_and_changed(self):
        source = object()
        runner = types.SimpleNamespace(_resolve_session_agent_runtime=Mock(return_value=("selected", {"provider": "fixture"})))
        def handler():
            pass
        adapter = types.SimpleNamespace(_message_handler=types.MethodType(handler, runner))
        mode, aux = Mock(return_value="native"), Mock(return_value=False)
        modules = {
            "hermes_cli.config": types.SimpleNamespace(load_config=lambda: {}),
            "agent.image_routing": types.SimpleNamespace(decide_image_input_mode=mode),
            "agent.auxiliary_client": types.SimpleNamespace(scoped_runtime_main=lambda r: contextlib.nullcontext()),
            "tools.vision_tools": types.SimpleNamespace(check_video_requirements=aux),
        }
        with patch.dict(sys.modules, modules):
            self.assertTrue(image_eligibility.available(adapter, source))
            runner._resolve_session_agent_runtime.assert_called_with(source=source, user_config={})
            mode.assert_called_with("fixture", "selected", {}, requested_provider="")
            mode.return_value = "text"
            aux.return_value = True
            self.assertTrue(image_eligibility.available(adapter, source))
            aux.return_value = False
            self.assertFalse(image_eligibility.available(adapter, source))
            runner._resolve_session_agent_runtime.side_effect = RuntimeError("unknown")
            self.assertFalse(image_eligibility.available(adapter, source))
            self.assertFalse(image_eligibility.available(types.SimpleNamespace(), source))
