"""The agent's model from the app: Hermes's inventory and model switch, here
test doubles that keep the agent's settings in memory."""
import contextvars
import json
import sys
import tempfile
import types
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from enclos import model, protocol

HOME = contextvars.ContextVar("home", default=None)


class FakeHermes:
    """Hermes's functions the manager uses, over one agent's settings."""

    def __init__(self, home):
        self.home = str(home)
        self.config = {"model": {"default": "model-1", "provider": "provider-a"}}
        self.scopes = []
        self.persisted = []
        self.switch_error = None
        self.providers = [
            {"slug": "provider-a", "name": "Provider A", "models": ["model-1", {"id": "model-2", "name": "Model Two"}],
             "total_models": 2},
            {"slug": "provider-b", "name": "Provider B", "models": [], "source": "canonical", "key_env": "B_API_KEY"},
            {"slug": "provider-c", "name": "Provider C", "models": ["c-1"], "authenticated": False},
            {"slug": "bad\u202eid", "name": "Hidden", "models": []},
        ]

    def scope(self, path):
        self.scopes.append(path)
        return HOME.set(path)

    def unscope(self, token):
        HOME.reset(token)

    def load_config(self):
        assert HOME.get() == self.home, "read inside the agent's scope"
        return json.loads(json.dumps(self.config))

    def context(self):
        block = self.config["model"]
        return types.SimpleNamespace(current_provider=block.get("provider", ""), current_model=block.get("default", ""),
                                     current_base_url="", user_providers={}, custom_providers=[])

    def payload(self, context, include_unconfigured=False, max_models=None):
        assert HOME.get() == self.home
        assert include_unconfigured, "providers not set up are listed too"
        return {"providers": self.providers}

    def switch(self, raw_input, current_provider, current_model, current_base_url="", current_api_key="",
               is_global=False, explicit_provider="", user_providers=None, custom_providers=None):
        assert is_global, "the agent's default, not one session's"
        if self.switch_error:
            return types.SimpleNamespace(success=False, error_message=self.switch_error)
        return types.SimpleNamespace(success=True, new_model=raw_input, target_provider=explicit_provider)

    def persist(self, result, config_path):
        assert HOME.get() == self.home
        self.persisted.append((result.target_provider, result.new_model, str(config_path)))
        self.config["model"] = {"default": result.new_model, "provider": result.target_provider}

    def functions(self):
        return {"home": lambda: self.home, "scope": self.scope, "unscope": self.unscope, "config": self.load_config,
                "context": self.context, "payload": self.payload, "switch": self.switch, "persist": self.persist}


class ModelTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.home = Path(self.dir.name).resolve()
        self.hermes = FakeHermes(self.home)
        self.manager = model.Manager("coder", home=self.home, functions=self.hermes.functions())

    def tearDown(self):
        self.dir.cleanup()

    def options(self):
        return self.manager.handle({"action": "options"})

    def test_options_list_providers_with_those_not_set_up_disabled(self):
        options = self.options()
        self.assertEqual(options["result"], "options")
        self.assertEqual(options["current"], {"model": "model-1", "provider": "provider-a"})
        self.assertEqual(options["applies"], "live")
        listed = {p["id"]: p for p in options["providers"]}
        self.assertEqual(list(listed), ["provider-a", "provider-b", "provider-c"], "a hidden character is left out")
        self.assertTrue(listed["provider-a"]["usable"])
        self.assertNotIn("setup", listed["provider-a"])
        self.assertFalse(listed["provider-b"]["usable"])
        self.assertIn("B_API_KEY", listed["provider-b"]["setup"])
        self.assertIn("hermes -p coder model", listed["provider-b"]["setup"])
        self.assertFalse(listed["provider-c"]["usable"], "the current provider without credentials")

    def test_models_of_one_provider(self):
        models = self.manager.handle({"action": "models", "provider": "provider-a"})
        self.assertEqual(models, {"result": "models", "provider": "provider-a", "limited": False,
                                  "models": [{"id": "model-1", "label": "model-1"},
                                             {"id": "model-2", "label": "Model Two"}]})
        with self.assertRaises(model.ModelError) as caught:
            self.manager.handle({"action": "models", "provider": "provider-z"})
        self.assertEqual(caught.exception.code, "not_found")

    def test_a_long_catalogue_is_cut_and_says_so(self):
        self.hermes.providers[0]["models"] = [f"m-{i}" for i in range(model.MAX_MODELS + 5)]
        self.hermes.providers[0]["total_models"] = model.MAX_MODELS + 5
        models = self.manager.handle({"action": "models", "provider": "provider-a"})
        self.assertEqual(len(models["models"]), model.MAX_MODELS)
        self.assertTrue(models["limited"])

    def test_set_saves_the_agents_default_with_hermes_own_switch(self):
        revision = self.options()["revision"]
        result = self.manager.handle({"action": "set", "provider": "provider-a", "model": "model-2", "revision": revision})
        self.assertEqual(result["result"], "set")
        self.assertEqual(result["previous"], {"model": "model-1", "provider": "provider-a"})
        self.assertEqual(result["current"], {"model": "model-2", "provider": "provider-a"})
        self.assertNotEqual(result["revision"], revision)
        self.assertEqual(result["applies"], "live")
        self.assertEqual(self.hermes.persisted, [("provider-a", "model-2", str(self.home / "config.yaml"))])
        self.assertTrue(all(scope == str(self.home) for scope in self.hermes.scopes))

    def test_a_stale_revision_is_refused(self):
        revision = self.options()["revision"]
        self.hermes.config["model"]["default"] = "changed-on-the-host"
        with self.assertRaises(model.ModelError) as caught:
            self.manager.handle({"action": "set", "provider": "provider-a", "model": "model-2", "revision": revision})
        self.assertEqual(caught.exception.code, "conflict")
        self.assertEqual(self.hermes.persisted, [])

    def test_a_provider_not_set_up_is_refused_before_hermes(self):
        revision = self.options()["revision"]
        with self.assertRaises(model.ModelError) as caught:
            self.manager.handle({"action": "set", "provider": "provider-b", "model": "b-1", "revision": revision})
        self.assertEqual(caught.exception.code, "not_allowed")
        self.assertEqual(self.hermes.persisted, [])

    def test_hermes_refusal_is_passed_on_and_nothing_saved(self):
        revision = self.options()["revision"]
        self.hermes.switch_error = "Model not found for provider-a"
        with self.assertRaises(model.ModelError) as caught:
            self.manager.handle({"action": "set", "provider": "provider-a", "model": "nope", "revision": revision})
        self.assertEqual(caught.exception.code, "not_allowed")
        self.assertIn("Model not found", str(caught.exception))
        self.assertEqual(self.hermes.persisted, [])

    def test_a_hermes_without_the_functions_turns_the_capability_off(self):
        functions = self.hermes.functions()
        del functions["persist"]
        manager = model.Manager("coder", home=self.home, functions=functions)
        self.assertTrue(manager.available, "given functions are trusted as given")
        off = model.Manager("coder", home=self.home, functions=None)
        if off.available:
            self.skipTest("a real Hermes is importable here")
        self.assertIsNotNone(off.unavailable)

    def test_requests_are_validated_when_decoded(self):
        line = json.dumps({"v": 1, "id": "m-1", "type": "model.request", "person": "p@example.com", "device": "d",
                           "action": "set", "provider": "provider-a", "model": "", "revision": "r"}).encode() + b"\n"
        with self.assertRaises(protocol.DecodeError):
            protocol.decode_from_bridge(line)
        good = json.dumps({"v": 1, "id": "m-2", "type": "model.request", "person": "p@example.com", "device": "d",
                           "action": "options"}).encode() + b"\n"
        self.assertEqual(protocol.decode_from_bridge(good)["action"], "options")


if __name__ == "__main__":
    unittest.main()
