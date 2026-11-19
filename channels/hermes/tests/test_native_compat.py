"""Real persistence and authority contracts; no services or provider calls."""
import os
from pathlib import Path
import subprocess
import sys
import unittest


class NativeCompatibility(unittest.TestCase):
    @unittest.skipUnless(os.environ.get('ENCLOS_HERMES_SOURCE'), 'real Hermes checkout not supplied')
    def test_real_titles_and_owner_deletion(self):
        script = r'''
import asyncio, inspect, os, sys, tempfile
from pathlib import Path
from types import SimpleNamespace
sys.path[:0] = [sys.argv[1], sys.argv[2]]
from enclos import conversations
from enclos.adapter import EnclosAdapter
from gateway.session_authority import SessionAuthority, LiveSession
from gateway.session_contract import SessionRef
async def check():
    with tempfile.TemporaryDirectory() as tmp:
        user_home = Path(tmp) / "source"
        home = user_home / ".hermes/profiles/coder"
        home.mkdir(parents=True)
        os.environ['HERMES_HOME'] = str(home)
        os.environ['HOME'] = str(user_home)
        modern = 'persistence' in inspect.signature(SessionAuthority).parameters
        if modern:
            from persistence_assembly import open_persistence, profile_scope
            from persistence.conversation.sessions import NewSession
            db = open_persistence(profile_scope(home=home))
            db.sessions.create(NewSession(session_id='s', source='test'))
            db.sessions.create(NewSession(session_id='busy', source='test'))
            epoch = db.runtime.begin_epoch(instance_id='test')
            kwargs = {'persistence': db}
            get = db.sessions.get
        else:
            from hermes_state import SessionDB
            from hermes_state_runtime import begin_runtime_epoch
            db = SessionDB(home / 'state.db')
            db.create_session('s', 'test')
            db.create_session('busy', 'test')
            epoch = begin_runtime_epoch(db, instance_id='test')
            kwargs = {'db': db}
            get = db.get_session
        try:
            adapter = object.__new__(EnclosAdapter)
            adapter.gateway_runner = SimpleNamespace(_session_db=db)
            adapter._session_id = lambda chat: 's'
            adapter._titles = {}
            adapter._title_failure_told = False
            adapter.platform = SimpleNamespace(value='enclos')
            await adapter._rename('chat', 'Native title')
            assert (await adapter._session_title('chat')) == ('Native title', 'user')
            runner = SimpleNamespace(_draining=False, _evict_cached_agent=lambda key: None)
            owner = SessionAuthority(runner, profile_id=str(home), instance_id='test', epoch=epoch, **kwargs)
            runner.session_authority = owner
            owner.sessions['s'] = LiveSession(None, 'route')
            adapter._conversation_home = home
            Actor, Ref, mutate, _ = conversations.owner_api()
            actor = Actor('enclos-app', str(home), frozenset({'session:read', 'session:control'}), 'enclos-plugin')
            ref = Ref(str(home), 's')
            row = get('s')
            revision = row.runtime_revision if modern else row['runtime_revision']
            generation = row.runtime_generation if modern else row['runtime_generation']
            for field in ('expected_revision', 'expected_generation'):
                params = dict(session_id='s', request_id=field, expected_revision=revision,
                              expected_generation=generation, operation='delete', payload={})
                params[field] += 99
                try:
                    await mutate(owner, actor, ref, params)
                except Exception as error:
                    assert 'conflict' in str(error) or 'stale' in str(error), repr(error)
                else:
                    raise AssertionError('stale mutation accepted')
                assert get('s') is not None
            owner.sessions['busy'] = LiveSession(None, 'busy-route')
            if modern:
                db.admissions.admit(epoch=epoch, principal_id='enclos-app', session_id='busy', request_id='turn', payload={'text': 'pending'})
                db.admissions.claim(epoch=epoch, session_id='busy')
            else:
                from hermes_state_runtime import admit_session_input, claim_session_input
                admit_session_input(db, epoch=epoch, principal_id='enclos-app', session_id='busy', request_id='turn', payload={'text': 'pending'})
                claim_session_input(db, epoch=epoch, session_id='busy')
            busy = get('busy')
            try:
                await mutate(owner, actor, Ref(str(home), 'busy'), dict(session_id='busy', request_id='busy-delete',
                    expected_revision=busy.runtime_revision if modern else busy['runtime_revision'],
                    expected_generation=busy.runtime_generation if modern else busy['runtime_generation'], operation='delete', payload={}))
            except Exception as error:
                assert 'busy' in str(error), repr(error)
            else:
                raise AssertionError('active mutation accepted')
            assert get('busy') is not None
            sessions = home / 'sessions'; sessions.mkdir(exist_ok=True)
            transcript = sessions / 'session_s.json'; transcript.write_text('secret transcript')
            # Routing is a gateway concern; keep the native authority and mutation real.
            from unittest.mock import patch
            with patch.object(conversations, 'authority', return_value=owner), patch.object(conversations, 'session_id', return_value='s'):
                await conversations.delete(adapter, 'chat', 'delete')
            assert get('s') is None
            assert not transcript.exists()
            if modern:
                import importlib.util, json, sqlite3
                from persistence.conversation.messages import NewMessage
                from tools.tool_result_storage import write_pruned_original, _with_pointer
                spec = importlib.util.spec_from_file_location('transfer', sys.argv[3])
                transfer = importlib.util.module_from_spec(spec); spec.loader.exec_module(transfer)
                db.sessions.create(NewSession(session_id='archive', source='test'))
                expected = {}
                for n in range(2):
                    body = 'full original output ' + str(n)
                    written = write_pruned_original(body, 'archive', 'read_file', str(n))
                    assert written is not None
                    host_path, display_path = written
                    expected[Path(host_path).name] = body
                    stub = _with_pointer([{'type': 'text', 'text': 'short'}], display_path)
                    db.messages.append('archive', NewMessage(role='tool', content=stub, api_content=json.dumps(stub)))
                with sqlite3.connect(home / 'state.db') as raw:
                    raw.execute("UPDATE messages SET active=0 WHERE session_id='archive' AND id=(SELECT min(id) FROM messages WHERE session_id='archive')")
                (home / 'cache/pruned/unreferenced.txt').write_text('exclude')
                export_file = Path(tmp) / 'archive.tgz'
                transfer.export(user_home, 'coder', export_file)
                destination_home = Path(tmp) / 'restored'; destination_home.mkdir()
                transfer.restore(destination_home, 'renamed', export_file)
                destination = destination_home / '.hermes/profiles/renamed'
                for filename, body in expected.items():
                    assert (destination / 'cache/pruned' / filename).read_text() == body
                assert not (destination / 'cache/pruned/unreferenced.txt').exists()
                with sqlite3.connect(destination / 'state.db') as raw:
                    restored = raw.execute("SELECT content,api_content,active FROM messages WHERE session_id='archive'").fetchall()
                assert {r[2] for r in restored} == {0,1}
                for content, api, _ in restored:
                    assert str(destination / 'cache/pruned') in content
                    assert str(destination / 'cache/pruned') in json.loads(api)[-1]['text']

        finally:
            db.close()
asyncio.run(check())
'''
        result = subprocess.run([sys.executable, '-c', script, os.environ['ENCLOS_HERMES_SOURCE'], str(Path(__file__).parents[1]), str(Path(__file__).parents[3] / 'src/runtime/hermes/transfer.py')], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
