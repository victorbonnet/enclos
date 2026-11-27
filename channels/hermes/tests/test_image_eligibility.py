"""Selected conversation checks; no provider, credential or network calls."""
import contextlib
import os
import sys
import types
import unittest
from pathlib import Path
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

    def test_resolves_inside_the_agents_profile_scope(self):
        # A multiplexed gateway refuses a provider's credentials read outside a
        # profile scope; the hello's check has no turn around it, so it enters
        # the agent's own scope first.
        home = "/agents/director"
        scopes = []

        @contextlib.contextmanager
        def profile_scope(path):
            scopes.append(path)
            yield

        def resolve(source=None, user_config=None):
            if not scopes:
                raise RuntimeError("could not read this profile's HERMES_CODEX_BASE_URL")
            return "selected", {"provider": "fixture"}

        runner = types.SimpleNamespace(_resolve_session_agent_runtime=resolve)
        def handler():
            pass
        adapter = types.SimpleNamespace(_message_handler=types.MethodType(handler, runner), _conversation_home=home)
        modules = {
            "hermes_cli.config": types.SimpleNamespace(load_config=lambda: {}),
            "agent.image_routing": types.SimpleNamespace(decide_image_input_mode=Mock(return_value="native")),
            "agent.auxiliary_client": types.SimpleNamespace(scoped_runtime_main=lambda r: contextlib.nullcontext()),
            "tools.vision_tools": types.SimpleNamespace(check_video_requirements=Mock(return_value=False)),
            "gateway.run": types.SimpleNamespace(_profile_runtime_scope=profile_scope),
        }
        with patch.dict(sys.modules, modules):
            self.assertTrue(image_eligibility.available(adapter))
            self.assertEqual(scopes, [Path(home)])
            # With no home, the check runs as before, and the refusal is a no.
            adapter._conversation_home = None
            scopes.clear()
            self.assertFalse(image_eligibility.available(adapter))
            self.assertEqual(scopes, [])
        # A Hermes without the helper runs the check as is.
        with patch.dict(sys.modules, {**modules, "gateway.run": types.SimpleNamespace()}):
            adapter._conversation_home = home
            scopes.clear()
            self.assertFalse(image_eligibility.available(adapter))
