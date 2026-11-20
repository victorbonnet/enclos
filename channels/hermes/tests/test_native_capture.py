"""Public Hermes capture/retention resource proof, isolated from adapter stand-ins."""
import os
from pathlib import Path
import subprocess
import sys
import unittest


class PublicCapture(unittest.TestCase):
    def test_queued_bytes_outlive_plugin_staging_and_terminal_release(self):
        source = Path(os.environ.get("ENCLOS_HERMES_SOURCE", Path.home() / ".hermes/hermes-agent"))
        if not (source / "gateway/session_ingress_media.py").is_file():
            if "ENCLOS_HERMES_SOURCE" in os.environ:
                self.fail(f"Named Hermes source is missing: {source}")
            self.skipTest("Optional installed Hermes source absent")
        script = r'''
import os, tempfile, faulthandler, sys, types
sys.modules["gateway.run"] = types.ModuleType("gateway.run")
from native_source_fixture import verify
faulthandler.dump_traceback_later(15, exit=True)
from pathlib import Path
with tempfile.TemporaryDirectory() as temporary:
    os.environ['HERMES_HOME'] = temporary
    os.environ.pop('HERMES_PROFILE', None)
    from agent.image_routing import decide_image_input_mode
    cfg = {'providers': {'fixture': {'models': {'sees': {'supports_vision': True}, 'blind': {'supports_vision': False}}}}}
    assert decide_image_input_mode('fixture', 'sees', cfg) == 'native'
    assert decide_image_input_mode('fixture', 'blind', cfg) == 'text'
    from gateway.session_ingress_media import capture_native_media, release_admission_media, sweep_settled_media
    from native_storage_fixture import (SessionDB, create_session, admit_session_input,
        begin_runtime_epoch, cancel_session_input)
    stage = Path(temporary) / 'staging.txt'
    stage.write_bytes(b'original immutable bytes')
    media = capture_native_media([stage])
    captured = Path(media[0]['path'])
    assert captured != stage and captured.read_bytes() == stage.read_bytes()
    db = SessionDB(Path(temporary) / 'state.db')
    create_session(db, 's')
    epoch = begin_runtime_epoch(db, instance_id='fixture')
    row = admit_session_input(db, epoch=epoch, principal_id='p', session_id='s', request_id='delivery',
        payload={'text': 'read', 'attachments_v1': {'media': media, 'media_types': ['text/plain']}})
    stage.write_bytes(b'changed')
    stage.unlink()
    # Even an old queued input is owned by its admission, not the plugin path.
    os.utime(captured, (1, 1))
    release_admission_media(db, row['admission_id'])
    sweep_settled_media(db, now=200000)
    assert captured.read_bytes() == b'original immutable bytes'
    cancel_session_input(db, epoch=epoch, admission_id=row['admission_id'])
    release_admission_media(db, row['admission_id'])
    assert not captured.exists()
    db.close()
    verify()
'''
        env = dict(os.environ, PYTHONPATH=os.pathsep.join([str(source), str(Path(__file__).parent.resolve())]))
        result = subprocess.run([sys.executable, "-c", script], env=env, text=True, capture_output=True, timeout=25)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_actual_adapter_producer_authority(self):
        source = Path(os.environ.get("ENCLOS_HERMES_SOURCE", Path.home() / ".hermes/hermes-agent"))
        if not (source / "gateway/session_authority.py").is_file():
            if "ENCLOS_HERMES_SOURCE" in os.environ:
                self.fail(f"Named Hermes source is missing: {source}")
            self.skipTest("Optional installed Hermes source absent")
        env = dict(os.environ, PYTHONPATH=os.pathsep.join([str(source), str(Path(__file__).resolve().parents[1])]))
        result = subprocess.run([sys.executable, str(Path(__file__).with_name("native_ingress_fixture.py"))], env=env,
                                text=True, capture_output=True, timeout=25)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_actual_admission_preserves_prepared_write_uncertainty(self):
        source = Path(os.environ.get("ENCLOS_HERMES_SOURCE", Path.home() / ".hermes/hermes-agent"))
        if not (source / "gateway/session_authority.py").is_file():
            if "ENCLOS_HERMES_SOURCE" in os.environ:
                self.fail(f"Named Hermes source is missing: {source}")
            self.skipTest("Optional installed Hermes source absent")
        env = dict(os.environ, PYTHONPATH=os.pathsep.join([str(source), str(Path(__file__).resolve().parents[1])]))
        result = subprocess.run([sys.executable, str(Path(__file__).with_name("native_admission_fixture.py"))],
                                env=env, text=True, capture_output=True, timeout=25)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
