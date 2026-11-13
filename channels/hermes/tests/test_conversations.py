"""Deletion is a native owner mutation, never a second writer of Hermes's database."""
import os
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from enclos import conversations


class NativeDeletion(unittest.IsolatedAsyncioTestCase):
    def fixture(self):
        row = {"runtime_revision": 17, "runtime_generation": 4}
        owner = types.SimpleNamespace(profile_id="/tmp/agent-profile", db=types.SimpleNamespace(get_session=Mock(return_value=row)),
                                      resolve=AsyncMock(return_value=types.SimpleNamespace(execution_state="idle", execution_generation=4)),
                                      cancel_queued=AsyncMock(), interrupt=AsyncMock(), _pending_rows=lambda ref: [])
        adapter = types.SimpleNamespace(name="enclos", _routines=types.SimpleNamespace(home_channel="home.lab.main"),
                                        _write=AsyncMock(), _title_checks={}, _titles={"chat": "Title"}, _last_in={"chat": ("m", 0)})
        ref = lambda profile, sid: types.SimpleNamespace(profile_id=profile, session_id=sid)
        cleaned = Mock()
        mutate = AsyncMock(return_value={"deleted_ids": ["session", "compressed"]})
        modules = {
            "gateway.session_contract": types.SimpleNamespace(Principal=lambda *args: args, SessionRef=ref),
            "gateway.session_mutations": types.SimpleNamespace(mutate_session=mutate),
            "gateway.session_route_recovery": types.SimpleNamespace(messaging_owner_ref=lambda owner, ref: ref),
            "hermes_state": types.SimpleNamespace(SessionDB=types.SimpleNamespace(_remove_session_files=cleaned)),
        }
        return adapter, owner, mutate, cleaned, modules

    async def test_native_revision_and_generation_fence_and_all_deleted_files_are_used_before_ack(self):
        adapter, owner, mutate, cleaned, modules = self.fixture()
        with patch.dict(sys.modules, modules), patch.object(conversations, "available", return_value=True), \
             patch.object(conversations, "authority", return_value=owner), patch.object(conversations, "session_id", return_value="session"):
            await conversations.handle(adapter, {"id": "request", "conversation": "chat"})
        params = mutate.await_args.args[3]
        self.assertEqual(params, {"session_id": "session", "request_id": "request", "expected_revision": 17,
                                  "expected_generation": 4, "operation": "delete", "payload": {}})
        self.assertEqual(cleaned.call_args_list[0].args, (Path("/tmp/agent-profile/sessions"), "session"))
        self.assertEqual(cleaned.call_args_list[1].args, (Path("/tmp/agent-profile/sessions"), "compressed"))
        self.assertEqual(adapter._write.await_args.args[0]["type"], "ack")
        self.assertNotIn("chat", adapter._titles)
        self.assertNotIn("chat", adapter._last_in)

    async def test_native_refusal_never_acknowledges_and_already_absent_chat_is_idempotent(self):
        adapter, owner, mutate, cleaned, modules = self.fixture()
        error = RuntimeError("session_busy")
        error.reason = "session_busy"
        mutate.side_effect = error
        with patch.dict(sys.modules, modules), patch.object(conversations, "available", return_value=True), \
             patch.object(conversations, "authority", return_value=owner), patch.object(conversations, "session_id", return_value="session"):
            await conversations.handle(adapter, {"id": "request", "conversation": "chat"})
            reply = adapter._write.await_args.args[0]
            self.assertEqual((reply["type"], reply["code"], reply["of"]), ("error", "conflict", "request"))
            cleaned.assert_not_called()
            self.assertIn("chat", adapter._titles)
            owner.db.get_session.return_value = None
            await conversations.handle(adapter, {"id": "retry", "conversation": "chat"})
            self.assertEqual(adapter._write.await_args.args[0]["type"], "ack")
            self.assertEqual(mutate.await_count, 1)

    async def test_home_and_unsupported_runtimes_never_enter_native_deletion(self):
        adapter, owner, mutate, cleaned, modules = self.fixture()
        with patch.dict(sys.modules, modules), patch.object(conversations, "available", return_value=False):
            await conversations.handle(adapter, {"id": "home", "conversation": "home.lab.main"})
            self.assertEqual(adapter._write.await_args.args[0]["code"], "not_allowed")
            await conversations.handle(adapter, {"id": "old", "conversation": "chat"})
            self.assertEqual(adapter._write.await_args.args[0]["code"], "unsupported")
        mutate.assert_not_awaited()
        cleaned.assert_not_called()

    async def test_running_and_queued_admissions_use_native_stop_and_cancel_before_delete(self):
        adapter, owner, mutate, cleaned, modules = self.fixture()
        owner._pending_rows = lambda ref: [{"status": "queued", "admission_id": "queued"}]
        owner.resolve.side_effect = [types.SimpleNamespace(execution_state="running", execution_generation=4),
                                     types.SimpleNamespace(execution_state="idle", execution_generation=4)]
        with patch.dict(sys.modules, modules), patch.object(conversations, "authority", return_value=owner), \
             patch.object(conversations, "session_id", return_value="session"), patch.object(conversations.asyncio, "sleep", new=AsyncMock()):
            await conversations.delete(adapter, "chat", "request")
        self.assertEqual(owner.cancel_queued.await_args.args[2], "queued")
        self.assertEqual(owner.interrupt.await_args.args[2], 4)
        mutate.assert_awaited_once()

    async def test_older_hermes_deletes_native_lineage_then_retires_routes_and_cache(self):
        home = Path('/tmp/owned-agent').resolve()
        actions = []
        db = types.SimpleNamespace(db_path=home/'state.db', get_compression_lineage=lambda sid: ['old', 'current'],
                                   delete_session=lambda sid, **kw: actions.append(('delete', sid, kw)))
        store = types.SimpleNamespace(_db_for_key=lambda key: db, peek_session_id=lambda key:'current',
                                      remove_by_session_id=lambda sid: actions.append(('retire', sid)))
        adapter = types.SimpleNamespace(_session_store=store, _conversation_home=home,
                                        gateway_runner=types.SimpleNamespace(_is_session_running=lambda key:False,
                                                                             _evict_cached_agent=lambda key:actions.append(('evict', key))))
        with patch.object(conversations, 'session_key', return_value='route'):
            await conversations.legacy_delete(adapter, 'chat')
        self.assertEqual([item[:2] for item in actions], [('delete','old'),('retire','old'),('delete','current'),('retire','current'),('evict','route')])
        for item in actions:
            if item[0]=='delete':
                self.assertEqual(item[2], {'sessions_dir':home/'sessions', 'exclude_active_write_guards':True})
        actions.clear()
        db.db_path = '/tmp/another-profile/state.db'
        with patch.object(conversations, 'session_key', return_value='route'):
            with self.assertRaises(conversations.DeleteError):
                await conversations.legacy_delete(adapter, 'chat')
        self.assertEqual(actions, [], 'a routed profile must never delete from the launch profile')

    async def test_both_real_actor_shapes_and_the_capability_probe_share_one_contract(self):
        from dataclasses import make_dataclass
        for name in ("SessionActor", "Principal"):
            with self.subTest(actor=name):
                adapter, owner, mutate, cleaned, modules = self.fixture()
                actor_type = make_dataclass(name, ["subject", "profile_id", "capabilities", "transport_id"])
                contract = modules["gateway.session_contract"]
                del contract.Principal
                setattr(contract, name, actor_type)
                adapter._session_store = object()
                with patch.dict(sys.modules, modules), patch.object(conversations, "authority", return_value=owner), \
                     patch.object(conversations, "session_id", return_value="session"):
                    self.assertTrue(conversations.available(adapter))
                    await conversations.handle(adapter, {"id": "native-actor", "conversation": "chat"})
                self.assertEqual(adapter._write.await_args.args[0]["type"], "ack")
                actor = mutate.await_args.args[1]
                self.assertIsInstance(actor, actor_type)
                self.assertEqual((actor.subject, actor.profile_id, actor.transport_id), ("enclos-app", owner.profile_id, "enclos-plugin"))

    async def test_missing_actor_or_ref_does_not_advertise_or_dispatch_deletion(self):
        for missing in ("Principal", "SessionRef"):
            with self.subTest(missing=missing):
                adapter, owner, mutate, cleaned, modules = self.fixture()
                adapter._session_store = object()
                delattr(modules["gateway.session_contract"], missing)
                with patch.dict(sys.modules, modules), patch.object(conversations, "authority", return_value=owner):
                    self.assertFalse(conversations.available(adapter))
                    await conversations.handle(adapter, {"id": "no-contract", "conversation": "chat"})
                self.assertEqual(adapter._write.await_args.args[0]["code"], "unsupported")
                mutate.assert_not_awaited()

    @unittest.skipUnless(os.environ.get("ENCLOS_HERMES_SOURCE"), "real Hermes checkout not supplied")
    async def test_real_checkout_actor_contract_supports_the_deletion_path(self):
        # Exercise the real source contract in hermes-latest CI and local probes;
        # only the live owner/database are stand-ins, never its public actor type.
        import importlib.util
        path = Path(os.environ["ENCLOS_HERMES_SOURCE"]) / "gateway/session_contract.py"
        spec = importlib.util.spec_from_file_location("_enclos_native_session_contract", path)
        contract = importlib.util.module_from_spec(spec)
        adapter, owner, mutate, cleaned, modules = self.fixture()
        modules["gateway.session_contract"] = contract
        modules[contract.__name__] = contract
        adapter._session_store = object()
        with patch.dict(sys.modules, modules), patch.object(conversations, "authority", return_value=owner), \
             patch.object(conversations, "session_id", return_value="session"):
            spec.loader.exec_module(contract)
            self.assertTrue(conversations.available(adapter))
            await conversations.handle(adapter, {"id": "real-contract", "conversation": "chat"})
        self.assertEqual(adapter._write.await_args.args[0]["type"], "ack")
        actor = mutate.await_args.args[1]
        expected = getattr(contract, "SessionActor", None) or contract.Principal
        self.assertIsInstance(actor, expected)
