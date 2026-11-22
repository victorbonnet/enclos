"""Functional classification probe; real adapter+webhook, synthetic no-I/O admission collaborators."""
import asyncio, os, sys, tempfile, types
from pathlib import Path
from contextlib import asynccontextmanager
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SOURCE = Path(os.environ.get('ENCLOS_HERMES_SOURCE', Path.home() / '.hermes/hermes-agent')).resolve()
sys.path[:0] = [str(SOURCE), str(ROOT)]
sys.modules['gateway.run'] = types.ModuleType('gateway.run')  # never bootstrap a gateway

async def main():
    from enclos.adapter import EnclosAdapter, FileAdmissionRefused
    from gateway.platforms import webhook_ingress as ingress
    from gateway.session_authority import native_write_started
    from gateway import session_ingress_live_turn as live
    from hermes_cli import lifecycle
    from gateway.config import Platform
    from native_storage_fixture import RuntimeStoreError
    from native_source_fixture import verify
    verify()
    print("Verified Hermes source:", SOURCE, flush=True)
    @asynccontextmanager
    async def scope(adapter, event):
        yield types.SimpleNamespace(runner=object(), profile_id='fixture')
    @asynccontextmanager
    async def turn(key):
        yield
    async def prepared(*a):
        return {'native_text_v1': {}}, 'fixture'
    async def no_release(*a):
        pass
    async def after_write(*a):
        native_write_started.set(True)
        raise OSError('synthetic error after write-start boundary')
    async def success(*a):
        return types.SimpleNamespace(admission_id='receipt')
    async def transient(*a):
        raise RuntimeStoreError('runtime_draining')
    async def unknown(*a):
        raise ValueError('synthetic deterministic preparation refusal')
    event=types.SimpleNamespace(media_urls=['/synthetic/no-file-read'], message_id='fixture')
    releases=[]
    adapter=types.SimpleNamespace(platform=Platform.TELEGRAM, _incoming=types.SimpleNamespace(
        release=lambda p: releases.append(list(p)), admission_ended=lambda p: None))
    async def classify(label):
        releases.clear()
        try:
            await EnclosAdapter._admit_files(adapter,event)
        except FileAdmissionRefused:
            answer='terminal FileAdmissionRefused'
        except Exception as e:
            answer=type(e).__name__
        else:
            answer='success'
        print(label, answer, 'staging-release',bool(releases), flush=True)
        return answer
    with patch.object(ingress,'producer_scope',scope), patch.object(ingress,'_delivery_turn',turn), patch.object(ingress,'_prepared',prepared), patch.object(ingress,'_committed',return_value=None), patch.object(ingress,'_release_preparation',no_release), patch.object(lifecycle,'has_hook',return_value=False), patch.object(live,'was_consumed',return_value=False), patch.object(live,'may_answer_live_turn',return_value=False), patch.object(ingress,'_admit_native',after_write):
        assert await classify('ordinary path after write-start') == 'OSError'
        with patch.object(live,'may_answer_live_turn',return_value=True), patch.object(ingress,'_admit_once',after_write):
            assert await classify('live-turn prepared path after write-start') == 'OSError', 'prepared write uncertainty must survive marker restoration'
            assert not releases
        with patch.object(lifecycle, 'has_hook', return_value=True), patch.object(ingress, '_admit_once', after_write):
            assert await classify('hook prepared path after write-start') == 'OSError'
            assert not releases
        with patch.object(ingress, '_admit_native', success):
            adapter._incoming.captured = lambda paths, receipt: None
            assert await classify('ordinary no-hooks positive') == 'success'
            assert not releases
    with patch.object(ingress,'admit_producer',transient):
        assert await classify('runtime_draining before write') == 'terminal FileAdmissionRefused'
        assert releases == [event.media_urls]
    with patch.object(ingress,'admit_producer',unknown):
        assert await classify('ValueError before write') == 'ValueError'
    # Disconnect cancels only the caller: staging ownership lasts until the
    # shielded admission settles, and its eventual receipt is still recorded.
    entered, finish = asyncio.Event(), asyncio.Event()
    ended, captured = [], []
    adapter._incoming.admission_ended = lambda paths: ended.append(paths)
    adapter._incoming.captured = lambda paths, receipt: captured.append(receipt)
    async def delayed(*a):
        entered.set()
        await finish.wait()
        return await success()
    with patch.object(ingress, 'admit_producer', delayed):
        caller = asyncio.create_task(EnclosAdapter._admit_files(adapter, event))
        await entered.wait()
        caller.cancel()
        try:
            await caller
        except asyncio.CancelledError:
            pass
        assert adapter._native_admissions and not ended and not captured
        finish.set()
        await asyncio.gather(*adapter._native_admissions)
        await asyncio.sleep(0)
        assert len(ended) == len(captured) == 1
    await asyncio.sleep(0)
    assert not adapter._native_admissions
    verify()

with tempfile.TemporaryDirectory() as temporary:
    os.environ['HERMES_HOME']=temporary
    os.environ.pop('HERMES_PROFILE',None)
    asyncio.run(main())
print('Synthetic classification controls only; no real admission commit/model/gateway executed.')
