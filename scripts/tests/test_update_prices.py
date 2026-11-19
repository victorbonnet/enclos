"""Tests for scripts/update_prices.py (standard library only)."""

import os
import sys
import tomllib
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

import update_prices as up  # noqa: E402

A = "a" * 40
B = "b" * 40

HEAD = """[providers.anthropic]

[[models]]
provider = "anthropic"
id = "claude-hand"
aliases = ["claude-hand-alias"]
input = 1.0
output = 2.0
source = "checked by hand"

"""
FILE = HEAD + up.BEGIN + "\n" + up.END + "\n# after\n"


def litellm(**overrides):
    data = {
        "claude-new": {
            "litellm_provider": "anthropic",
            "mode": "chat",
            "input_cost_per_token": 3e-06,
            "output_cost_per_token": 1.5e-05,
            "cache_read_input_token_cost": 3e-07,
            "cache_creation_input_token_cost": 3.75e-06,
        },
        # Kept by hand, by id and by alias with a date: left out.
        "claude-hand": {"litellm_provider": "anthropic", "mode": "chat", "input_cost_per_token": 9e-06, "output_cost_per_token": 9e-06},
        "claude-hand-alias-20260101": {"litellm_provider": "anthropic", "mode": "chat", "input_cost_per_token": 9e-06, "output_cost_per_token": 9e-06},
        # Bare and prefixed: one entry, the bare one's.
        "deepseek-chat": {"litellm_provider": "deepseek", "mode": "chat", "input_cost_per_token": 2.8e-07, "output_cost_per_token": 4.2e-07},
        "deepseek/deepseek-chat": {"litellm_provider": "deepseek", "mode": "chat", "input_cost_per_token": 1e-06, "output_cost_per_token": 1e-06},
        "gemini/gemini-x": {"litellm_provider": "gemini", "mode": "chat", "input_cost_per_token": 1e-06, "output_cost_per_token": 2e-06},
        # Not a chat model, another provider, an id with a path, no output price.
        "dall-e": {"litellm_provider": "openai", "mode": "image_generation", "input_cost_per_token": 1e-06, "output_cost_per_token": 1e-06},
        "bedrock/claude": {"litellm_provider": "bedrock", "mode": "chat", "input_cost_per_token": 1e-06, "output_cost_per_token": 1e-06},
        "gemini/tuned/x": {"litellm_provider": "gemini", "mode": "chat", "input_cost_per_token": 1e-06, "output_cost_per_token": 1e-06},
        "gpt-in-only": {"litellm_provider": "openai", "mode": "chat", "input_cost_per_token": 1e-06},
        "sample_spec": {"note": "LiteLLM's own example"},
    }
    data.update(overrides)
    return data


def models(text):
    return {(m["provider"], m["id"]): m for m in tomllib.loads(text).get("models", [])}


class UpdatePrices(unittest.TestCase):
    def test_generated_entries_are_per_million_and_hand_ones_win(self):
        out, summary = up.rewrite(FILE, litellm(), A)
        got = models(out)
        new = got[("anthropic", "claude-new")]
        self.assertEqual((new["input"], new["output"], new["cache_read"], new["cache_write"]), (3.0, 15.0, 0.3, 3.75))
        self.assertEqual(new["source"], "litellm@" + A)
        self.assertEqual(got[("anthropic", "claude-hand")]["source"], "checked by hand")
        self.assertNotIn(("anthropic", "claude-hand-alias-20260101"), got)
        self.assertEqual(got[("deepseek", "deepseek-chat")]["input"], 0.28)
        self.assertIn(("gemini", "gemini-x"), got)
        for left_out in ("dall-e", "claude", "x", "gpt-in-only", "tuned/x"):
            self.assertFalse(any(k[1] == left_out for k in got), left_out)
        self.assertTrue(out.endswith(up.END + "\n# after\n"))
        self.assertIn("Added:", summary)

    def test_running_twice_changes_nothing_and_a_newer_commit_with_the_same_rates_keeps_the_source(self):
        once, _ = up.rewrite(FILE, litellm(), A)
        twice, summary = up.rewrite(once, litellm(), B)
        self.assertEqual(once, twice)
        self.assertNotIn("Rates changed", summary)

    def test_a_changed_rate_names_the_new_commit(self):
        once, _ = up.rewrite(FILE, litellm(), A)
        cheaper = litellm()
        cheaper["claude-new"] = dict(cheaper["claude-new"], output_cost_per_token=1e-05)
        out, summary = up.rewrite(once, cheaper, B)
        new = models(out)[("anthropic", "claude-new")]
        self.assertEqual((new["output"], new["source"]), (10.0, "litellm@" + B))
        self.assertEqual(models(out)[("gemini", "gemini-x")]["source"], "litellm@" + A)
        self.assertIn("Rates changed:\n- anthropic claude-new", summary)

    def test_what_is_not_a_price_or_a_commit_is_refused(self):
        for bad in (-1e-06, 2.0, "1e-06", True, float("nan")):
            data = litellm()
            data["claude-new"] = dict(data["claude-new"], input_cost_per_token=bad)
            with self.assertRaises(up.Refused, msg=repr(bad)):
                up.rewrite(FILE, data, A)
        with self.assertRaises(up.Refused):
            up.rewrite(FILE, litellm(), "main")
        with self.assertRaises(up.Refused):
            up.rewrite(FILE, [], A)

    def test_a_file_without_one_generated_block_is_refused(self):
        with self.assertRaises(up.Refused):
            up.rewrite(HEAD, litellm(), A)
        with self.assertRaises(up.Refused):
            up.rewrite(FILE + up.BEGIN + "\n" + up.END + "\n", litellm(), A)

    def test_an_id_a_terminal_or_toml_would_misread_is_left_out(self):
        data = {
            'claude-"x': {"litellm_provider": "anthropic", "mode": "chat", "input_cost_per_token": 1e-06, "output_cost_per_token": 1e-06},
            "claude-\u001b[31m": {"litellm_provider": "anthropic", "mode": "chat", "input_cost_per_token": 1e-06, "output_cost_per_token": 1e-06},
        }
        out, _ = up.rewrite(FILE, data, A)
        self.assertEqual(set(models(out)), {("anthropic", "claude-hand")})

    def test_the_bundled_list_reads_and_has_one_generated_block(self):
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "src", "prices.toml")
        with open(path, encoding="utf-8") as f:
            text = f.read()
        self.assertEqual((text.count(up.BEGIN), text.count(up.END)), (1, 1))
        doc = tomllib.loads(text)
        self.assertTrue(doc["providers"]["openai-codex"]["included"])
        self.assertTrue(doc["models"])


if __name__ == "__main__":
    unittest.main()
