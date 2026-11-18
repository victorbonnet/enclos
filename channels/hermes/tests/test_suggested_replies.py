"""Reply metadata is scoped, visible and non-authoritative."""
import json
import concurrent.futures
from unittest.mock import Mock, patch
import asyncio
import sys
import types
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from enclos import suggested_replies


class Replies(unittest.TestCase):
    def test_visible_distinct_bounded_replies_are_literal(self):
        labels = ["Fix Inbox filters", "Keep paused"]
        self.assertEqual(suggested_replies.validate(labels), labels)
        for bad in [[], ["same", "same"], ["Allow\nall"], ["Allow\u202eall"], ["x" * 257], [1], [str(i) for i in range(5)]]:
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                suggested_replies.validate(bad)


class Correlation(unittest.IsolatedAsyncioTestCase):
    async def test_a_new_person_message_and_timeout_discard_abandoned_turn_metadata(self):
        adapter = types.SimpleNamespace(_last_in={"home": ("m1", 1)}, _suggested_replies={})
        now = asyncio.get_running_loop().time()
        adapter._suggested_replies["home"] = suggested_replies.Pending(("m1", 1), now, ["Fix it"])
        self.assertEqual(suggested_replies.take(adapter, "another"), [])
        self.assertEqual(suggested_replies.take(adapter, "home", "older-message"), [])
        self.assertEqual(suggested_replies.take(adapter, "home"), ["Fix it"])
        self.assertEqual(suggested_replies.take(adapter, "home"), [])
        adapter._suggested_replies["home"] = suggested_replies.Pending(("m1", 1), now, ["Old"])
        adapter._last_in["home"] = ("m2", 2)
        self.assertEqual(suggested_replies.take(adapter, "home"), [])
        adapter._suggested_replies["home"] = suggested_replies.Pending(("m2", 2), now - 301, ["Old"])
        self.assertEqual(suggested_replies.take(adapter, "home"), [])


class Registration(unittest.TestCase):
    def handler(self, adapters):
        context = Mock()
        suggested_replies.register(context, adapters, "enclos")
        return context.register_tool.call_args.kwargs["handler"]

    def adapter(self):
        return types.SimpleNamespace(_loop=types.SimpleNamespace(call_soon_threadsafe=lambda fn: fn()), _last_in={}, _suggested_replies={})

    def test_review_no_session_is_a_descriptive_error(self):
        handler=self.handler([])
        with patch.object(suggested_replies.approvals, "session", return_value=None):
            self.assertTrue(json.loads(handler({"replies":["Fix it"]}))["error"])

    def test_review_all_routes_are_ready_only_after_successful_staging(self):
        adapters=[self.adapter(),self.adapter()]
        def submit(coro, _loop):
            future=concurrent.futures.Future(); future.set_result(asyncio.run(coro)); return future
        with patch.object(suggested_replies.approvals,"session",return_value="home"), patch.object(suggested_replies.approvals,"routes",return_value=adapters), patch.object(asyncio,"run_coroutine_threadsafe",side_effect=submit):
            result=json.loads(self.handler(adapters)({"replies":["Fix it"]}))
        self.assertEqual(result["status"],"ready")
        async def take(adapter):return suggested_replies.take(adapter,"home")
        for adapter in adapters:self.assertEqual(asyncio.run(take(adapter)),["Fix it"])

    def test_review_timeout_is_descriptive_and_cannot_partially_stage(self):
        adapters=[self.adapter(),self.adapter()]; late=[]
        def submit(coro, loop):
            future=concurrent.futures.Future()
            if loop is adapters[1]._loop:
                late.append(coro); future.set_exception(TimeoutError())
            else:future.set_result(asyncio.run(coro))
            return future
        with patch.object(suggested_replies.approvals,"session",return_value="home"), patch.object(suggested_replies.approvals,"routes",return_value=adapters), patch.object(asyncio,"run_coroutine_threadsafe",side_effect=submit):
            result=json.loads(self.handler(adapters)({"replies":["Fix it"]}))
        # Even a coroutine that completes after the handler's timeout must not publish choices.
        for coro in late:asyncio.run(coro)
        self.assertTrue(result["error"])
        async def take(adapter):return suggested_replies.take(adapter,"home")
        for adapter in adapters:self.assertEqual(asyncio.run(take(adapter)),[])
