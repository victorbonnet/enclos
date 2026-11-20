"""Subprocess-only fixture: real ingress/capture/authority, no gateway bootstrap."""
import asyncio
from contextlib import asynccontextmanager
from pathlib import Path
import os
import sys
import tempfile
from types import SimpleNamespace, ModuleType
from unittest.mock import patch

# Fail closed if any dependency starts importing the bootstrap module.
sys.modules['gateway.run'] = ModuleType('gateway.run')
from enclos.adapter import EnclosAdapter
from gateway.config import GatewayConfig, Platform
from gateway.platforms.event import MessageEvent, MessageType
from gateway.session import SessionSource, SessionStore
from gateway.session_authority import SessionAuthority
from gateway.session_contract import SessionActor
from gateway.platforms import webhook_ingress
from hermes_state import SessionDB
from hermes_state_runtime import begin_runtime_epoch, get_session_admission

async def main(root):
    db = SessionDB(root / 'state.db')
    store = SessionStore(config=GatewayConfig(), sessions_dir=root / 'sessions')
    store._db = db
    adapter = SimpleNamespace(platform=Platform.TELEGRAM, name='fixture')
    runner = SimpleNamespace(_draining=False, _peek_session_state=lambda key: None, session_store=store,
        config=SimpleNamespace(multiplex_profiles=False),
        _adapter_flag=lambda *a: False, _adapter_profile_for_source=lambda s: None,
        _is_user_authorized_for_source=lambda *a, **kw: True,
        _session_key_for_source=store._generate_session_key, _adapter_for_source=lambda s: adapter, _is_session_running=lambda k: False)
    authority = SessionAuthority(runner, profile_id='fixture', instance_id='test', db=db,
        epoch=begin_runtime_epoch(db, instance_id='test'))
    runner.session_authority = authority
    # Only execution scheduling is held; admission and ledger are unmodified.
    authority._schedule = lambda ref: None
    @asynccontextmanager
    async def scope(a, event):
        assert a is adapter
        yield authority
    receipts = []
    adapter._incoming = SimpleNamespace(captured=lambda paths, r: receipts.append(r), release=lambda paths: None)
    path = root / 'staging.txt'
    path.write_bytes(b'actual producer bytes')
    event = MessageEvent(text='read', message_type=MessageType.DOCUMENT,
        source=SessionSource(platform=Platform.TELEGRAM, chat_id='c', user_id='u'),
        message_id='delivery', media_urls=[str(path)], media_types=['text/plain'],
        media_filenames=['staging.txt'], media_text_inlined=[False])
    # This is the explicit test-owned runtime/runner seam. Never replace producer,
    # capture, prepare_native, admit_native or the native write.
    with patch.object(webhook_ingress, 'producer_scope', scope):
        receipt = await EnclosAdapter._admit_files(adapter, event)
    assert receipts == [receipt]
    row = get_session_admission(db, admission_id=receipt.admission_id)
    assert row['request_id'] == 'delivery'
    captured = Path(row['payload']['native_text_v1']['media'][0]['path'])
    assert captured != path
    path.unlink()
    from gateway.session_ingress_media import release_admission_media, sweep_settled_media
    os.utime(captured, (1, 1))
    release_admission_media(db, receipt.admission_id)
    sweep_settled_media(db, now=200000)
    assert captured.read_bytes() == b'actual producer bytes'
    actor = SessionActor(row['principal_id'], 'fixture', frozenset({'session:submit', 'session:control'}), 'fixture')
    polled = await authority.receipt(actor, receipt.ref, receipt.admission_id)
    assert polled.admission_id == receipt.admission_id and polled.status == 'queued'
    db.close()
    # Reopen the actual ledger; old queued bytes survive without staging.
    db = SessionDB(root / 'state.db')
    row = get_session_admission(db, admission_id=receipt.admission_id)
    assert row['status'] == 'queued' and captured.read_bytes() == b'actual producer bytes'
    db.close()

with tempfile.TemporaryDirectory() as temporary:
    os.environ['HERMES_HOME'] = temporary
    os.environ.pop('HERMES_PROFILE', None)
    asyncio.run(main(Path(temporary)))

# Actual public image checks; only configuration and client construction are
# test-owned. The private conversation resolver remains a compatibility seam.
from enclos import image_eligibility
import agent.auxiliary_client as auxiliary
cfg = {'providers': {'fixture': {'models': {'sees': {'supports_vision': True}, 'blind': {'supports_vision': False}}}}}
source = SimpleNamespace(profile='secondary', chat_id='override')
selected = ['sees']
seen = []
def resolve(*, source, user_config):
    seen.append(source)
    assert source.profile == 'secondary' and source.chat_id == 'override'
    assert user_config is cfg
    return selected[0], {'provider': 'fixture'}
class Runner:
    _resolve_session_agent_runtime = staticmethod(resolve)
    def handle(self): pass
adapter = SimpleNamespace(_message_handler=Runner().handle)
with patch('hermes_cli.config.load_config', return_value=cfg):
    with patch.object(auxiliary, 'resolve_vision_provider_client', return_value=(None, None)):
        assert image_eligibility.available(adapter, source)
        selected[0] = 'blind'
        assert not image_eligibility.available(adapter, source)
    with patch.object(auxiliary, 'resolve_vision_provider_client', return_value=('fixture', object())):
        assert image_eligibility.available(adapter, source)
    selected[0] = None
    assert not image_eligibility.available(adapter, source)
assert all(value is source for value in seen)
