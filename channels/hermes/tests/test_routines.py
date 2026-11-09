"""Routine contract checks; optionally exercise an isolated real Hermes checkout.

ENCLOS_HERMES_SOURCE=/path/to/hermes-agent python3.13 -m unittest discover ...
Only temporary profile homes are used; no scheduler is started or job executed.
"""

import copy
import importlib
import json
import os
import sys
import tempfile
import types
import unittest
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from enclos import protocol, routines


def definition(**values):
    return {"prompt": "Summarize the day", "schedule": {"kind": "interval", "minutes": 60}, **values}


def request(action, **values):
    return {"v": 1, "id": f"routine-{uuid.uuid4()}", "type": "routine.request", "action": action,
            "allowed_deliveries": ["home.lab.main", "conversation.mine"], **values}


class RoutineProtocol(unittest.TestCase):
    def test_typed_request_preserves_explicit_empty_toolsets(self):
        message = request("create", definition=definition(toolsets=[]))
        decoded = protocol.decode_from_bridge(protocol.encode_line(message))
        self.assertEqual(decoded["definition"]["toolsets"], [])

    def test_bad_request_never_reaches_native_runtime(self):
        cases = [request("delete", routine="j"), request("set_enabled", routine="j", revision="r", enabled="yes"),
                 request("create", definition=definition(schedule={"kind": "interval", "minutes": True})),
                 request("create", definition=definition(schedule={"kind": "interval", "minutes": 0})),
                 request("create", definition=definition(schedule={"kind": "once", "at": "2028-01-01T09:00:00"})),
                 request("create", definition=definition(script_only=True)),
                 request("create", definition=definition(prompt="a" * 8193))]
        for message in cases:
            with self.subTest(message=message), self.assertRaises(protocol.DecodeError):
                protocol.decode_from_bridge(protocol.encode_line(message))

    def test_untrusted_delivery_scope_is_rejected(self):
        message = request("list")
        del message["allowed_deliveries"]
        with self.assertRaises(protocol.DecodeError):
            protocol.decode_from_bridge(protocol.encode_line(message))

    def test_missing_native_runtime_does_not_advertise_routines(self):
        with patch.dict(sys.modules, {"cron": None}):
            manager = routines.Manager("/unused/socket")
            self.assertFalse(manager.available)
            with self.assertRaises(routines.RoutineError) as error:
                manager.handle(request("run", routine="native", revision="r"))
            self.assertEqual(error.exception.code, "unsupported")


class TransientReply(unittest.IsolatedAsyncioTestCase):
    async def test_control_result_is_written_without_chat_outbox(self):
        config = types.ModuleType("gateway.config")
        config.Platform = config.PlatformConfig = Mock
        shared = types.ModuleType("gateway.platforms._shared")
        shared.get_scoped_secret = Mock(return_value="")
        base = types.ModuleType("gateway.platforms.base")
        base.BasePlatformAdapter = object
        base.SendResult = Mock
        event = types.ModuleType("gateway.platforms.event")
        event.MessageEvent = event.MessageType = Mock
        modules = {"gateway": types.ModuleType("gateway"), "gateway.config": config,
                   "gateway.platforms": types.ModuleType("gateway.platforms"),
                   "gateway.platforms._shared": shared, "gateway.platforms.base": base,
                   "gateway.platforms.event": event}
        with patch.dict(sys.modules, modules):
            sys.modules.pop("enclos.adapter", None)
            adapter_module = importlib.import_module("enclos.adapter")
            adapter = adapter_module.EnclosAdapter.__new__(adapter_module.EnclosAdapter)
            adapter._routines = Mock()
            adapter._routines.handle.return_value = {"result": "deleted", "routine": "native"}
            adapter._outbox = Mock()
            adapter._write = AsyncMock(return_value=True)
            await adapter._on_line(protocol.encode_line(request("delete", id="routine-request", routine="native", revision="r")))
            result = adapter._write.call_args.args[0]
            self.assertEqual((result["type"], result["of"], result["result"]),
                             ("routine.response", "routine-request", "deleted"))
            adapter._outbox.put.assert_not_called()
            adapter.platform = "enclos"
            adapter.name = "app"
            adapter._loop = "live-loop"
            adapter.gateway_runner = types.SimpleNamespace(adapters={"enclos": "another-agent"})
            self.assertEqual(adapter._routine_runtime(), ({"enclos": adapter}, "live-loop"))
            adapter.gateway_runner._adapters_for_profile = Mock(side_effect=ImportError("old API"))
            self.assertEqual(adapter._routine_runtime(), ({"enclos": adapter}, "live-loop"))
        sys.modules.pop("enclos.adapter", None)


@unittest.skipUnless(os.environ.get("ENCLOS_HERMES_SOURCE"), "optional real Hermes checkout")
class NativeHermesRoutines(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.home = Path(self.temporary.name) / "profile"
        self.home.mkdir()
        self.env = patch.dict(os.environ, {"HERMES_HOME": str(self.home), "HERMES_TIMEZONE": "Europe/Paris"})
        self.env.start()
        self.addCleanup(self.env.stop)
        sys.path.insert(0, os.environ["ENCLOS_HERMES_SOURCE"])
        self.addCleanup(sys.path.remove, os.environ["ENCLOS_HERMES_SOURCE"])
        self.manager = routines.Manager(str(self.home / "main.sock"), home=self.home)
        self.assertTrue(self.manager.available)
        self.manager.home_channel = "home.lab.main"
        self.provider = Mock()
        self.provider.claim_fire.side_effect = lambda job_id, manual: self.manager.jobs.get_job(job_id)
        self.manager.provider = lambda: self.provider
        self.manager.dispatch = Mock()
        # Catalog discovery is separately optional; these tests exercise real job storage only.
        self.manager._options = lambda: {"timezone": "Europe/Paris", "features": [], "skills": [], "models": [], "toolsets": []}

    def create(self, **changes):
        return self.manager.handle(request("create", id="create-request", definition=definition(**changes)))["routine"]

    def mutate(self, action, routine, **changes):
        return self.manager.handle(request(action, routine=routine["id"], revision=routine["revision"], **changes))

    def native(self, routine):
        with self.manager._scope():
            return self.manager.jobs.get_job(routine["id"])

    def test_real_crud_and_pause_resume_run_queue_do_not_execute(self):
        routine = self.create(toolsets=[], delivery="home.lab.main")
        self.assertEqual(routine["definition"]["toolsets"], [])
        native = self.native(routine)
        self.assertEqual((native["deliver"], native["enabled_toolsets"]), ("enclos:home.lab.main", []))
        self.provider.register_job.assert_called_once()
        paused = self.mutate("set_enabled", routine, enabled=False)["routine"]
        self.assertFalse(paused["enabled"])
        resumed = self.mutate("set_enabled", paused, enabled=True)["routine"]
        self.assertTrue(resumed["enabled"])
        self.assertEqual(self.mutate("run", resumed)["result"], "run")
        self.assertIsNone(self.native(resumed)["last_run_at"])
        current = self.manager.handle(request("get", routine=routine["id"]))["routine"]
        self.assertEqual(self.mutate("delete", current)["result"], "deleted")
        self.assertIsNone(self.native(routine))

    def test_manual_run_hands_off_exact_claim_after_unlock_and_keeps_profile(self):
        routine = self.create()
        claimed = {"id": routine["id"], "execution_id": "native-attempt", "fire_claim": {"by": "owner"}}
        self.provider.claim_fire.side_effect = None
        self.provider.claim_fire.return_value = claimed
        handoff = []

        def dispatch(provider, snapshot):
            self.assertEqual(getattr(self.manager.jobs._jobs_lock_state, "depth", 0), 0)
            handoff.append(snapshot)

        self.manager.dispatch = dispatch
        self.mutate("run", routine)
        self.provider.claim_fire.assert_called_once_with(routine["id"], manual=True)
        self.assertIs(handoff[0], claimed)
        self.provider.fire_claimed.assert_not_called()
        self.manager.runtime = lambda: ({"enclos": "live-adapter"}, "live-loop")
        seen = []
        self.provider.fire_claimed.side_effect = lambda snapshot, **kwargs: seen.append((snapshot, kwargs, self.manager.constants.get_hermes_home()))
        with patch.dict(os.environ, {"HERMES_HOME": str(Path(self.temporary.name) / "another-profile")}):
            self.manager.execute(self.provider, claimed)
        self.assertIs(seen[0][0], claimed)
        self.assertEqual(seen[0][1], {"adapters": {"enclos": "live-adapter"}, "loop": "live-loop"})
        self.assertEqual(seen[0][2], self.home.resolve())
        paused = self.mutate("set_enabled", routine, enabled=False)["routine"]
        self.provider.claim_fire.reset_mock()
        with self.assertRaises(routines.RoutineError) as error:
            self.mutate("run", paused)
        self.assertIn("Resume", str(error.exception))
        self.provider.claim_fire.assert_not_called()

    def test_recent_run_replays_once_and_rechecks_current_delivery_authority(self):
        routine = self.create(delivery="home.lab.main")
        message = request("run", routine=routine["id"], revision=routine["revision"])
        first = self.manager.handle(message)
        self.assertEqual(self.manager.handle(copy.deepcopy(message)), first)
        self.provider.claim_fire.assert_called_once()
        self.manager.dispatch.assert_called_once()
        changed = {**message, "revision": "other"}
        with self.assertRaises(routines.RoutineError) as error:
            self.manager.handle(changed)
        self.assertEqual(error.exception.code, "conflict")
        with self.assertRaises(routines.RoutineError) as error:
            self.manager.handle({**message, "allowed_deliveries": []})
        self.assertEqual(error.exception.code, "unsupported")
        self.assertEqual(self.provider.claim_fire.call_count, 1)

    def test_recent_mutation_error_is_replayed_without_reapplying(self):
        routine = self.create()
        message = request("update", routine=routine["id"], revision="stale", definition=definition(prompt="New"))
        errors = []
        for _ in range(2):
            with self.assertRaises(routines.RoutineError) as error:
                self.manager.handle(message)
            errors.append((error.exception.code, str(error.exception)))
        self.assertEqual(errors[0], errors[1])
        self.assertEqual(self.native(routine)["prompt"], "Summarize the day")

    def test_create_request_id_cannot_be_reused_as_another_mutation(self):
        routine = self.create()
        with self.assertRaises(routines.RoutineError) as error:
            self.manager.handle(request("run", id="create-request", routine=routine["id"], revision=routine["revision"]))
        self.assertEqual(error.exception.code, "conflict")
        self.manager.dispatch.assert_not_called()

    def test_create_replay_and_changed_payload_and_deleted_tombstone(self):
        routine = self.create()
        self.assertEqual(self.create()["id"], routine["id"])
        with self.assertRaises(routines.RoutineError) as error:
            self.create(prompt="Another request")
        self.assertEqual(error.exception.code, "conflict")
        self.mutate("delete", routine)
        with self.assertRaises(routines.RoutineError) as error:
            self.create()
        self.assertEqual(error.exception.code, "not_found")

    def test_concurrent_replays_create_one_native_job_without_deadlock(self):
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = [executor.submit(self.create) for _ in range(4)]
            ids = [future.result(timeout=10)["id"] for future in futures]
        self.assertEqual(len(set(ids)), 1)
        self.assertEqual(len(self.manager.handle(request("list"))["routines"]), 1)

    def test_recovery_after_create_before_receipt_keeps_same_native_job(self):
        with patch.object(self.manager, "_save_receipt", side_effect=OSError("interrupted")):
            with self.assertRaises(routines.RoutineError):
                self.create()
        recovered = self.create()
        rows = self.manager.handle(request("list"))["routines"]
        self.assertEqual([row["id"] for row in rows], [recovered["id"]])

    def test_receipt_is_versioned_and_rejects_unbounded_or_unknown_data(self):
        routine = self.create()
        path = self.manager._receipt_path("create-request")
        receipt = json.loads(path.read_text())
        self.assertEqual(receipt["schema_version"], 1)
        for content in (json.dumps({**receipt, "schema_version": 999}), " " * 4097):
            path.write_text(content)
            with self.assertRaises(routines.RoutineError):
                self.create()
        self.assertIsNotNone(self.native(routine))

    def test_scheduler_registration_failure_reports_saved_without_duplication(self):
        self.provider.register_job.side_effect = RuntimeError("provider offline")
        with self.assertRaises(routines.RoutineError) as error:
            self.create()
        self.assertIn("was saved", str(error.exception))
        self.provider.register_job.side_effect = None
        routine = self.create()
        self.assertEqual(len(self.manager.handle(request("list"))["routines"]), 1)
        self.assertEqual(routine["id"], self.provider.register_job.call_args.args[0]["id"])

    def test_native_edit_conflicts_but_progress_does_not_and_patch_is_sparse(self):
        routine = self.create()
        with self.manager._scope():
            native = self.manager.jobs.get_job(routine["id"])
            next_run = native["next_run_at"]
            self.manager.jobs.update_job(routine["id"], {"repeat": {"times": 9, "completed": 2}, "reasoning_effort": "high"})
        with self.assertRaises(routines.RoutineError) as error:
            self.mutate("update", routine, definition=definition(prompt="New prompt"))
        self.assertEqual(error.exception.code, "conflict")
        fresh = self.manager.handle(request("get", routine=routine["id"]))["routine"]
        with self.manager._scope():
            self.manager.jobs.update_job(routine["id"], {"last_status": "ok", "repeat": {"times": 9, "completed": 3}})
        updated = self.mutate("update", fresh, definition=definition(prompt="New prompt"))["routine"]
        native = self.native(updated)
        self.assertEqual(native["next_run_at"], next_run)
        self.assertEqual(native["repeat"], {"times": 9, "completed": 3})
        self.assertEqual(native["reasoning_effort"], "high")

    def test_script_containment_and_workdir_validation_happen_without_execution(self):
        scripts = self.home / "scripts"
        scripts.mkdir()
        marker = self.home / "executed"
        (scripts / "report.py").write_text(f"open({str(marker)!r}, 'w').close()")
        (scripts / "outside.py").symlink_to(self.home / "SOUL.md")
        (self.home / "SOUL.md").write_text("outside scripts")
        for script in ("../SOUL.md", "outside.py", str(scripts / "report.py"), "missing.py"):
            with self.subTest(script=script), self.assertRaises(routines.RoutineError):
                self.create(script=script, script_only=True)
        with self.assertRaises(routines.RoutineError):
            self.create(working_directory="relative")
        routine = self.create(script="report.py", script_only=True, working_directory=str(self.home))
        self.assertTrue(self.native(routine)["no_agent"])
        self.assertFalse(marker.exists())

    def test_external_and_other_person_delivery_are_readonly_and_preserved(self):
        routine = self.create()
        for delivery in ("telegram:123", "enclos:conversation.other"):
            with self.manager._scope():
                self.manager.jobs.update_job(routine["id"], {"deliver": delivery})
            full = self.manager.handle(request("get", routine=routine["id"]))["routine"]
            self.assertFalse(full["editable"])
            self.assertNotIn("delivery", full["definition"])
            for action in ("delete", "run", "set_enabled", "update"):
                with self.subTest(action=action), self.assertRaises(routines.RoutineError):
                    self.mutate(action, full, enabled=False, definition=definition())
            self.assertEqual(self.native(routine)["deliver"], delivery)

    def test_hidden_native_delivery_endpoint_or_attachment_settings_are_readonly(self):
        routine = self.create()
        for key, value in (("base_url", "https://custom.example/v1"), ("failure_deliver", "enclos:conversation.other"),
                           ("attach_to_session", True), ("monitor_url", "https://example.com"), ("context_from", ["self"])):
            with self.manager._scope():
                updates = {field: None for field in ("base_url", "failure_deliver", "monitor_url", "context_from")}
                updates["attach_to_session"] = False
                updates[key] = value
                self.manager.jobs.update_job(routine["id"], updates)
            full = self.manager.handle(request("get", routine=routine["id"]))["routine"]
            self.assertFalse(full["editable"], key)
            for action in ("run", "update"):
                with self.subTest(key=key, action=action), self.assertRaises(routines.RoutineError):
                    self.mutate(action, full, definition=definition())
            self.assertEqual(self.native(routine)[key], value)

    def test_profile_is_captured_before_another_profile_becomes_active(self):
        constants = self.manager.constants
        token = constants.set_hermes_home_override(str(self.home))
        try:
            captured = routines.Manager(str(self.home / "second.sock"))
        finally:
            constants.reset_hermes_home_override(token)
        other = Path(self.temporary.name) / "other-profile"
        other.mkdir()
        token = constants.set_hermes_home_override(str(other))
        try:
            captured.provider = lambda: self.provider
            captured.handle(request("create", definition=definition()))
        finally:
            constants.reset_hermes_home_override(token)
        self.assertTrue((self.home / "cron" / "jobs.json").is_file())
        self.assertFalse((other / "cron" / "jobs.json").exists())

    def test_timezone_and_missing_optional_catalogs_remain_available(self):
        with self.manager._scope(), patch.dict(sys.modules, {"tools.skills_tool": None, "toolsets": None, "hermes_cli.inventory": None}):
            options = routines.Manager._options(self.manager)
        self.assertEqual(options["timezone"], "Europe/Paris")
        self.assertEqual((options["skills"], options["models"], options["toolsets"]), ([], [], []))
        self.assertIn("working_directory", options["features"])

    def test_model_choices_keep_same_id_with_different_providers(self):
        inventory = types.ModuleType("hermes_cli.inventory")
        inventory.load_picker_context = lambda: None
        inventory.build_models_payload = lambda context: {"providers": [
            {"slug": "provider-a", "models": ["shared-model"]},
            {"slug": "provider-b", "models": ["shared-model"]}]}
        with self.manager._scope(), patch.dict(sys.modules, {"tools.skills_tool": None, "toolsets": None, "hermes_cli.inventory": inventory}):
            options = routines.Manager._options(self.manager)
        self.assertEqual(options["models"], [
            {"id": "shared-model", "label": "provider-a: shared-model", "provider": "provider-a"},
            {"id": "shared-model", "label": "provider-b: shared-model", "provider": "provider-b"}])
        self.assertIn("script_only", options["features"])

    def test_page_bound_keeps_a_cursor_for_remaining_large_summaries(self):
        routine = self.create()
        native = self.native(routine)
        rows = [{**copy.deepcopy(native), "id": f"job-{number:03}", "name": "n" * 512,
                 "prompt": "p" * 8192, "last_error": "e" * 512, "paused_reason": "r" * 512,
                 "last_status": "s" * 512, "last_run_at": "t" * 512, "next_run_at": "t" * 512}
                for number in range(30)]
        with patch.object(self.manager.jobs, "list_jobs", return_value=rows):
            result = self.manager.handle(request("list"))
        self.assertLessEqual(len(json.dumps(result).encode()), 44000)
        self.assertLess(len(result["routines"]), 25)
        self.assertEqual(result["next_cursor"], result["routines"][-1]["id"])


if __name__ == "__main__":
    unittest.main()
