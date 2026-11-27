"""Selected conversation checks; no provider, credential or network calls."""
import contextlib
import contextvars
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

    def _scoped_fixture(self, image_profiles):
        """An adapter captured at /profile/transport, with Hermes's profile scope
        as a context variable: the resolver refuses outside a scope, as a
        multiplexed gateway does, and images are native for `image_profiles`."""
        active = contextvars.ContextVar("profile", default=None)
        scopes = []

        @contextlib.contextmanager
        def profile_scope(path):
            scopes.append(path)
            token = active.set(str(path))
            try:
                yield
            finally:
                active.reset(token)

        def resolve(source=None, user_config=None):
            if active.get() is None:
                raise RuntimeError("could not read this profile's HERMES_CODEX_BASE_URL")
            return "selected", {"provider": active.get()}

        runner = types.SimpleNamespace(_resolve_session_agent_runtime=resolve)
        def handler():
            pass
        adapter = types.SimpleNamespace(_message_handler=types.MethodType(handler, runner),
                                        _conversation_home="/profile/transport")
        modules = {
            "hermes_cli.config": types.SimpleNamespace(load_config=lambda: {}),
            "agent.image_routing": types.SimpleNamespace(
                decide_image_input_mode=lambda provider, model, cfg, requested_provider="":
                    "native" if provider in image_profiles else "text"),
            "agent.auxiliary_client": types.SimpleNamespace(scoped_runtime_main=lambda r: contextlib.nullcontext()),
            "tools.vision_tools": types.SimpleNamespace(check_video_requirements=Mock(return_value=False)),
            "gateway.run": types.SimpleNamespace(_profile_runtime_scope=profile_scope),
        }
        return adapter, modules, active, scopes, profile_scope, resolve

    def test_hello_resolves_inside_the_agents_profile_scope(self):
        # The hello's check has no turn around it: it enters the agent's own scope.
        adapter, modules, _, scopes, _, _ = self._scoped_fixture({"/profile/transport"})
        with patch.dict(sys.modules, modules):
            self.assertTrue(image_eligibility.available(adapter))
            self.assertEqual(scopes, [Path("/profile/transport")])
            # With no home, the check runs unscoped, and the refusal is a no.
            adapter._conversation_home = None
            scopes.clear()
            self.assertFalse(image_eligibility.available(adapter))
            self.assertEqual(scopes, [])

    def test_arrival_keeps_the_routed_profiles_scope(self):
        # At arrival the conversation's routed profile is already in scope, and
        # it is the one that decides, whatever the transport profile takes.
        source = object()
        for routed_takes_images in (True, False):
            with self.subTest(routed_takes_images=routed_takes_images):
                images = {"/profile/routed"} if routed_takes_images else {"/profile/transport"}
                adapter, modules, active, scopes, _, _ = self._scoped_fixture(images)
                with patch.dict(sys.modules, modules):
                    token = active.set("/profile/routed")
                    try:
                        self.assertIs(image_eligibility.available(adapter, source), routed_takes_images)
                    finally:
                        active.reset(token)
                    self.assertEqual(scopes, [])

    def test_hermes_without_the_helper_runs_the_check_as_is(self):
        adapter, modules, active, scopes, _, _ = self._scoped_fixture({"/profile/ambient"})
        with patch.dict(sys.modules, {**modules, "gateway.run": types.SimpleNamespace()}):
            token = active.set("/profile/ambient")
            try:
                self.assertTrue(image_eligibility.available(adapter))
            finally:
                active.reset(token)
            self.assertEqual(scopes, [])
