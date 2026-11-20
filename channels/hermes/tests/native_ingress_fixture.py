"""Subprocess-only fixture: real ingress/capture/authority, no gateway bootstrap."""
import asyncio
import collections
from datetime import UTC, datetime
from contextlib import asynccontextmanager
from pathlib import Path
import os
import sys
import tempfile
from types import SimpleNamespace, ModuleType
from unittest.mock import patch

# Fail closed if any dependency starts importing the bootstrap module.
sys.modules['gateway.run'] = ModuleType('gateway.run')
from native_source_fixture import verify
from enclos.adapter import EnclosAdapter
from gateway.config import GatewayConfig, Platform
from gateway.session import SessionSource, SessionStore
from gateway.session_authority import SessionAuthority
from gateway.session_contract import SessionActor
from gateway.platforms import webhook_ingress
from native_storage_fixture import (CURRENT, SessionDB, begin_runtime_epoch,
    get_session_admission, RuntimeStoreError)

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
    authority = SessionAuthority(runner, profile_id='fixture', instance_id='test', **({'persistence': db} if CURRENT else {'db': db}),
        epoch=begin_runtime_epoch(db, instance_id='test'))
    runner.session_authority = authority
    # Only execution scheduling is held; admission and ledger are unmodified.
    @asynccontextmanager
    async def scope(a, event):
        assert a is adapter
        yield authority
    releases = []
    receipts = []
    scheduled = []
    authority._schedule = scheduled.append
    written = []
    async def write(message):
        written.append(message)
        return True  # ACK may be lost; the next delivery uses a fresh plugin cache.
    events = []
    async def admit(event):
        events.append(event)
        return await EnclosAdapter._admit_files(adapter, event)
    adapter._write = write
    adapter._admit_files = admit
    adapter.build_source = lambda **kw: SessionSource(platform=Platform.TELEGRAM,
        chat_id=kw['chat_id'], user_id=kw['user_id'])
    adapter._interrupts = SimpleNamespace(admit=lambda e: None, complete=lambda e: None)
    adapter._incoming = SimpleNamespace(captured=lambda paths, r: receipts.append(r),
        release=lambda paths: releases.append(paths), admit=lambda paths: None, admission_ended=lambda paths: None)
    adapter._last_in = {}
    message = dict(id='delivery', text='read', conversation='c', person='u')
    class ReceivedTime:
        current = datetime(2026, 1, 1, tzinfo=UTC)
        @classmethod
        def now(cls, **kw):
            return cls.current
        fromtimestamp = staticmethod(datetime.fromtimestamp)
    async def deliver(directory, content):
        path = root / directory / 'staging.txt'
        path.parent.mkdir()
        path.write_bytes(content)
        adapter._seen = collections.OrderedDict()
        await EnclosAdapter._on_message(adapter, message,
            ([str(path)], ['text/plain'], ['staging.txt']))
        return path
    # Actual event construction and admission; only the runtime binding and
    # execution scheduler are test-owned. Restart loses the plugin seen cache.
    with patch.object(webhook_ingress, 'producer_scope', scope), patch('enclos.adapter.datetime', ReceivedTime):
        path = await deliver('first', b'actual producer bytes')
        receipt = receipts[0]
        path.unlink()
        ReceivedTime.current = datetime(2026, 1, 2, tzinfo=UTC)
        path = await deliver('retry', b'actual producer bytes')
        assert len(receipts) == 2 and receipts[1].admission_id == receipt.admission_id
        assert receipts[1].ref == receipt.ref
        try:
            await deliver('changed', b'changed bytes')
        except RuntimeStoreError as error:
            assert error.reason == 'admission_conflict', error
        else:
            raise AssertionError('same request with changed bytes must conflict')
    # The real authority refuses before native writes when retiring.
    authority.retiring = True
    with patch.object(webhook_ingress, 'producer_scope', scope):
        await deliver('refused', b'precommit')
    assert written[-1]['type'] == 'error' and written[-1]['of'] == 'delivery', written[-1]
    assert releases and Path(releases[-1][0]).read_bytes() == b'precommit'
    authority.retiring = False
    import sqlite3
    with sqlite3.connect(root / 'state.db') as conn:
        assert conn.execute('SELECT COUNT(*) FROM session_admissions').fetchone()[0] == 1
    assert scheduled and all(r == receipt.ref for r in scheduled)
    assert not hasattr(adapter, 'handle_message')  # no model execution path installed
    assert all(e.timestamp == datetime.fromtimestamp(0, tz=UTC) for e in events)
    assert all(e.media_filenames == ['staging.txt'] for e in events)
    texts = []
    async def handle_text(event):
        texts.append(event)
    adapter.handle_message = handle_text
    with patch('enclos.adapter.datetime', ReceivedTime):
        adapter._seen.clear()
        await EnclosAdapter._on_message(adapter, dict(message, id='ordinary-text'))
    assert len(texts) == 1 and texts[0].timestamp == ReceivedTime.current
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

verify()
