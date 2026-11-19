"""The agent's model from the app: Hermes's inventory and model switch, here
test doubles that keep the agent's settings in memory; with a Hermes
installed (CI's `hermes-latest`), the real ones too."""
import asyncio
import contextvars
import importlib.util
import json
import os
import sys
import tempfile
import types
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from enclos import model, protocol

HOME = contextvars.ContextVar("home", default=None)
HERMES = importlib.util.find_spec("hermes_constants") is not None


class FakeHermes:
    """Hermes's functions the manager uses, over one agent's settings."""

    def __init__(self, home):
        self.home = str(home)
        self.config = {"model": {"default": "model-1", "provider": "provider-a"}}
        self.scopes = []
        self.persisted = []
        self.switch_error = None
        self.during_switch = None
        self.persist_error = None
        self.after_persist = None
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
        if isinstance(self.config, Exception):
            raise self.config
        return json.loads(json.dumps(self.config))

    def context(self):
        block = self.config["model"]
        return types.SimpleNamespace(current_provider=block.get("provider", ""), current_model=block.get("default", ""),
                                     current_base_url="", user_providers={}, custom_providers=[])

    def payload(self, context, include_unconfigured=False, max_models=None):
        assert HOME.get() == self.home
        assert include_unconfigured, "model providers not set up are listed too"
        return {"providers": self.providers}

    def switch(self, raw_input, current_provider, current_model, current_base_url="", current_api_key="",
               is_global=False, explicit_provider="", user_providers=None, custom_providers=None):
        assert is_global, "the agent's default, not one session's"
        if self.during_switch:
            self.during_switch()
        if self.switch_error:
            return types.SimpleNamespace(success=False, error_message=self.switch_error)
        return types.SimpleNamespace(success=True, new_model=raw_input, target_provider=explicit_provider)

    def persist(self, result, config_path):
        assert HOME.get() == self.home
        if self.persist_error:
            raise self.persist_error
        self.persisted.append((result.target_provider, result.new_model, str(config_path)))
        self.config["model"] = {"default": result.new_model, "provider": result.target_provider}
        if self.after_persist:
            self.after_persist()

    def functions(self, **extra):
        return {"home": lambda: self.home, "scope": self.scope, "unscope": self.unscope, "config": self.load_config,
                "context": self.context, "payload": self.payload, "switch": self.switch, "persist": self.persist,
                **extra}


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

    def set(self, revision, model_id="model-2", provider="provider-a"):
        return self.manager.handle({"action": "set", "provider": provider, "model": model_id, "revision": revision})

    def code_of(self, call):
        with self.assertRaises(model.ModelError) as caught:
            call()
        return caught.exception.code

    def test_options_list_model_providers_with_those_not_set_up_disabled(self):
        options = self.options()
        self.assertEqual(options["result"], "options")
        self.assertEqual(options["current"], {"model": "model-1", "provider": "provider-a"})
        self.assertEqual(options["applies"], "live", "no config.yaml: nothing to restart")
        listed = {p["id"]: p for p in options["providers"]}
        self.assertEqual(list(listed), ["provider-a", "provider-b", "provider-c"], "a hidden character is left out")
        self.assertTrue(listed["provider-a"]["usable"])
        self.assertNotIn("setup", listed["provider-a"])
        self.assertFalse(listed["provider-b"]["usable"])
        self.assertIn("B_API_KEY", listed["provider-b"]["setup"])
        self.assertIn("hermes -p coder model", listed["provider-b"]["setup"])
        self.assertFalse(listed["provider-c"]["usable"], "the current one without credentials")

    def test_applies_says_restart_when_enclos_will_restart_for_the_file(self):
        (self.home / "config.yaml").write_text("model:\n  default: model-1\nterminal:\n  backend: local\n")
        self.assertEqual(self.options()["applies"], "live")
        (self.home / "config.yaml").write_text("model: &m\n  default: model-1\nvision: *m\n")
        self.assertEqual(self.options()["applies"], "restart")

    def test_models_of_one_provider(self):
        models = self.manager.handle({"action": "models", "provider": "provider-a"})
        self.assertEqual(models, {"result": "models", "provider": "provider-a", "limited": False,
                                  "models": [{"id": "model-1", "label": "model-1"},
                                             {"id": "model-2", "label": "Model Two"}]})
        self.assertEqual(self.code_of(lambda: self.manager.handle({"action": "models", "provider": "provider-z"})),
                         "not_found")

    def test_a_long_catalogue_is_cut_to_the_count_and_the_size(self):
        self.hermes.providers[0]["models"] = [f"m-{i}" for i in range(model.MAX_MODELS + 5)]
        self.hermes.providers[0]["total_models"] = model.MAX_MODELS + 5
        models = self.manager.handle({"action": "models", "provider": "provider-a"})
        self.assertEqual(len(models["models"]), model.MAX_MODELS)
        self.assertTrue(models["limited"])
        self.hermes.providers[0]["models"] = [{"id": f"{i:0>190}", "name": f"{i:0>190}"} for i in range(model.MAX_MODELS)]
        self.hermes.providers[0]["total_models"] = model.MAX_MODELS
        self.manager._inventory = None
        big = self.manager.handle({"action": "models", "provider": "provider-a"})
        self.assertTrue(big["limited"])
        self.assertLessEqual(len(json.dumps(big).encode()), model.MAX_REPLY_BYTES)

    def test_set_saves_the_agents_default_with_hermes_own_switch(self):
        revision = self.options()["revision"]
        result = self.set(revision)
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
        self.assertEqual(self.code_of(lambda: self.set(revision)), "conflict")
        self.assertEqual(self.hermes.persisted, [])

    def test_a_change_made_while_hermes_checks_the_model_is_refused_not_merged(self):
        revision = self.options()["revision"]
        self.hermes.during_switch = lambda: self.hermes.config["model"].update(default="set-on-the-host")
        self.assertEqual(self.code_of(lambda: self.set(revision)), "conflict")
        self.assertEqual(self.hermes.persisted, [])

    def test_a_model_provider_not_set_up_is_refused_before_hermes(self):
        revision = self.options()["revision"]
        self.assertEqual(self.code_of(lambda: self.set(revision, "b-1", "provider-b")), "not_allowed")
        self.assertEqual(self.hermes.persisted, [])

    def test_hermes_refusal_is_passed_on_and_nothing_saved(self):
        revision = self.options()["revision"]
        self.hermes.switch_error = "Model not found for provider-a"
        with self.assertRaises(model.ModelError) as caught:
            self.set(revision, "nope")
        self.assertEqual(caught.exception.code, "not_allowed")
        self.assertIn("Model not found", str(caught.exception))
        self.assertEqual(self.hermes.persisted, [])

    def test_a_read_that_fails_says_why_and_changed_nothing(self):
        self.hermes.config = ValueError("config.yaml: mapping values are not allowed here")
        with self.assertRaises(model.ModelError) as caught:
            self.options()
        self.assertEqual(caught.exception.code, "agent_unavailable")
        self.assertIn("ValueError", str(caught.exception))
        self.assertIn("Nothing was changed", str(caught.exception))

    def test_a_save_that_fails_once_started_is_unknown(self):
        revision = self.options()["revision"]
        self.hermes.persist_error = OSError("disk full")
        self.assertEqual(self.code_of(lambda: self.set(revision)), "unknown")

    def test_a_saved_model_that_cannot_be_read_back_is_unknown_not_assumed(self):
        revision = self.options()["revision"]
        self.hermes.after_persist = lambda: self.hermes.config.update(model={"default": "x\u202ey"})
        self.assertEqual(self.code_of(lambda: self.set(revision)), "unknown")

    def test_a_home_that_is_another_agents_turns_the_capability_off(self):
        off = model.Manager("coder", home=self.home, functions=self.hermes.functions(profile=lambda home: "default"))
        self.assertFalse(off.available)
        self.assertIn("coder", off.unavailable)
        on = model.Manager("coder", home=self.home, functions=self.hermes.functions(profile=lambda home: "coder"))
        self.assertTrue(on.available)

    def test_the_capability_follows_the_functions_the_installed_hermes_has(self):
        # With a Hermes installed (CI's `hermes-latest`), the latest release
        # must still have every function the plugin uses; without one, the
        # capability is off and says why.
        # Use a named temporary profile without changing the launch settings.
        home = self.home / 'profiles' / 'coder'
        home.mkdir(parents=True)
        real = model.Manager("coder", home=home, functions=None)
        if HERMES:
            self.assertTrue(real.available, real.unavailable)
        else:
            self.assertFalse(real.available)
            self.assertIsNotNone(real.unavailable)

    def test_requests_are_validated_when_decoded(self):
        line = json.dumps({"v": 1, "id": "m-1", "type": "model.request", "person": "p@example.com", "device": "d",
                           "action": "set", "provider": "provider-a", "model": "", "revision": "r"}).encode() + b"\n"
        with self.assertRaises(protocol.DecodeError):
            protocol.decode_from_bridge(line)
        good = json.dumps({"v": 1, "id": "m-2", "type": "model.request", "person": "p@example.com", "device": "d",
                           "action": "options"}).encode() + b"\n"
        self.assertEqual(protocol.decode_from_bridge(good)["action"], "options")


class RestartRules(unittest.TestCase):
    """The same cases as enclos's `src/runtime/hermes/facts.rs`, whose rules
    `without_top_level` follows."""

    def test_a_change_of_the_model_block_alone_leaves_the_rest_the_same(self):
        before = "# Hermes\nmodel:\n  default: model-1\n  provider: provider-a\n\n  base_url: ''\nterminal:\n  backend: local\nplatforms:\n  - x\n"
        after = "# Hermes\nmodel:\n  default: model-2\n  provider: provider-b\nterminal:\n  backend: local\nplatforms:\n  - x\n"
        rest = model.without_top_level(before, "model")
        self.assertEqual(rest, "# Hermes\nterminal:\n  backend: local\nplatforms:\n  - x")
        self.assertEqual(model.without_top_level(after, "model"), rest)
        self.assertEqual(model.without_top_level("model_catalog:\n  x: 1\n", "model"), "model_catalog:\n  x: 1")

    def test_yaml_the_reader_does_not_follow_is_compared_whole(self):
        for unsure in ["model:\n\tdefault: x\n", "---\nmodel:\n  default: x\n", "model:\n  default: x\nmodel:\n  default: y\n",
                       "{model: x}\n", "base: &b\n  x: 1\nmodel:\n  <<: *b\n", "model:\n- x\n",
                       "model:  &route\n  default: x\nvision: *route\n", "model: !!map &route\n  default: x\n",
                       "model:\n  default: x\nfallbacks: [*route]\n", "[model, x]\n", "model:\n \tdefault: x\n"]:
            self.assertIsNone(model.without_top_level(unsure, "model"), unsure)

    def test_the_text_of_a_block_scalar_is_not_read_as_yaml(self):
        before = "model:\n  default: model-1\nagent:\n  system_prompt: |\n    - **Be brief**\n    Note: *always* cite.\n\n    ---\n  max_turns: 9\n"
        rest = model.without_top_level(before, "model")
        self.assertIsNotNone(rest)
        self.assertEqual(rest, model.without_top_level(before.replace("model-1", "model-2"), "model"))
        self.assertIn("    - **Be brief**", rest)
        self.assertIsNone(model.without_top_level("model: x\nnote: *always*\n", "model"))


@unittest.skipUnless(HERMES, "Hermes is not installed here; CI's hermes-latest runs these")
class WithTheInstalledHermes(unittest.TestCase):
    """Hermes's own inventory and save, in a temporary Hermes home."""

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.home = Path(self.dir.name).resolve()
        import hermes_constants
        self.token = hermes_constants.set_hermes_home_override(str(self.home))
        self.addCleanup(hermes_constants.reset_hermes_home_override, self.token)

    def tearDown(self):
        self.dir.cleanup()

    def test_with_no_login_hermes_lists_model_providers_the_agent_cannot_use(self):
        # A temporary home is no profile's: the check of the adapter's own
        # home is left out here.
        functions = model.Manager._hermes()
        functions.pop("profile")
        manager = model.Manager("default", home=self.home, functions=functions)
        self.assertTrue(manager.available, manager.unavailable)
        options = manager.handle({"action": "options"})
        self.assertTrue(options["providers"], "Hermes lists model providers to set up")
        unusable = [p for p in options["providers"] if not p["usable"]]
        self.assertTrue(unusable, "with no login, some model provider is not usable")
        self.assertTrue(all(p.get("setup") for p in unusable))

    def test_hermes_save_changes_the_model_block_alone(self):
        from hermes_cli import model_switch
        config = self.home / "config.yaml"
        config.write_text("# kept\nmodel:\n  default: old-model\n  provider: openrouter\nterminal:\n  backend: local\n"
                          "agent:\n  system_prompt: |\n    - **Be brief**\n")
        before = config.read_text()
        result = model_switch.ModelSwitchResult(success=True, new_model="new/model", target_provider="openrouter",
                                                is_global=True)
        model_switch.persist_model_selection(result, config)
        after = config.read_text()
        self.assertNotEqual(before, after)
        self.assertIn("new/model", after)
        self.assertEqual(model.without_top_level(before, "model"), model.without_top_level(after, "model"))


class Adapter(unittest.IsolatedAsyncioTestCase):
    """The adapter announces `model` when it can and answers on the socket."""

    async def test_the_adapter_announces_model_and_answers_a_request(self):
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        import test_adapter
        from unittest.mock import patch
        # The adapter tests' stand-ins for this test only: kept, they would
        # hide an installed Hermes from the tests that run after it.
        stand_ins = patch.dict(sys.modules, test_adapter._hermes_stand_ins())
        stand_ins.start()
        self.addCleanup(stand_ins.stop)
        sys.modules.pop("enclos.adapter", None)
        from enclos.adapter import EnclosAdapter
        from gateway.config import PlatformConfig
        directory = tempfile.mkdtemp()
        path = os.path.join(directory, "app", "main.sock")
        adapter = EnclosAdapter(PlatformConfig({"socket": path, "token": test_adapter.TOKEN}))
        hermes = FakeHermes(Path(directory).resolve())
        adapter._model = model.Manager("main", home=Path(directory), functions=hermes.functions())
        self.assertTrue(await adapter.connect())
        try:
            reader, writer = await asyncio.open_unix_connection(path, limit=protocol.MAX_MESSAGE_BYTES + 1)
            writer.write(test_adapter.line("hello", token=test_adapter.TOKEN))
            await writer.drain()
            hello = json.loads(await asyncio.wait_for(reader.readline(), 5))
            self.assertIn("model", hello["capabilities"])
            request = test_adapter.line("model.request", person="p@example.com", device="d", action="options")
            writer.write(request)
            await writer.drain()
            while True:
                answer = json.loads(await asyncio.wait_for(reader.readline(), 5))
                if answer["type"] in ("model.response", "error"):
                    break
            self.assertEqual(answer["type"], "model.response", answer)
            self.assertEqual(answer["of"], json.loads(request)["id"])
            self.assertEqual(answer["result"], "options")
            writer.close()
        finally:
            await asyncio.wait_for(adapter.disconnect(), 5)


if __name__ == "__main__":
    unittest.main()
