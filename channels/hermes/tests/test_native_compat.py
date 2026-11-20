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

    @unittest.skipUnless(os.environ.get('ENCLOS_HERMES_SOURCE'), 'real Hermes checkout not supplied')
    def test_real_recall_archive_roundtrip(self):
        # Separate processes isolate native HOME caches and let restore fail
        # independently of export. The controlled archive retains every original.
        script = r'''
import importlib.util, io, json, os, sqlite3, sys, tarfile, tempfile
from contextlib import closing
from pathlib import Path
sys.path.insert(0, sys.argv[1])
spec = importlib.util.spec_from_file_location('transfer', sys.argv[2])
t = importlib.util.module_from_spec(spec); spec.loader.exec_module(t)
cap, operation = int(sys.argv[3]), sys.argv[4]
with tempfile.TemporaryDirectory() as tmp:
    root = Path(tmp); home = root / 'source'
    profile = home / '.hermes/profiles/coder'; profile.mkdir(parents=True)
    os.environ.update(HOME=str(home), HERMES_HOME=str(profile))
    from persistence_assembly import open_persistence, profile_scope
    from persistence.conversation.sessions import NewSession
    from persistence.conversation.messages import NewMessage
    from tools.tool_result_storage import write_pruned_original, _with_pointer
    from tools.session_search_tool import session_search
    from agent.context_compressor_prune import terminal_stub
    store = open_persistence(profile_scope(home=profile))
    try:
        for sid in ('remembered', 'current'):
            store.sessions.create(NewSession(session_id=sid, source='cli'))
        body = b'OWNED SYNTHETIC ORIGINAL\n'
        host, display = write_pruned_original(body.decode(), 'remembered', 'terminal', 'probe')
        # Harmless command length places the native display boundary inside
        # the path, without editing the formatter or returned search JSON.
        prefix = terminal_stub({'command': 'printf control-' + 'x' * 60},
                               json.dumps({'output': 'ordinary output', 'exit_code': 0}), 1)
        # Longer ordinary tool context exercises native bookend/window caps.
        prefix = 'ordinary context ' + 'x' * (cap - 217) + prefix if cap > 200 else prefix
        stub = _with_pointer(prefix, display)
        store.messages.append('remembered', NewMessage(role='assistant' if cap == 1200 else 'tool', content=stub,
                              tool_name='terminal', tool_call_id='probe'))
        if cap == 1200:
            # Keep the long row outside the anchor window so native discovery
            # returns it through its separately capped opening bookend.
            for n in range(12):
                store.messages.append('remembered', NewMessage(role='tool', content='ordinary filler ' + str(n)))
            store.messages.append('remembered', NewMessage(role='tool', content='recallanchor'))
        (profile / 'memory.md').write_text('unrelated data')
        (profile / 'cache/pruned/unused.txt').write_text('excluded')
        (profile / 'cache/other').write_text('excluded')
        baseline = root / 'before.tgz'; t.export(home, 'coder', baseline)

        def verify(archive, name, recall=None):
            destination_home = root / name; destination_home.mkdir()
            t.restore(destination_home, 'renamed', archive)
            target = destination_home / '.hermes/profiles/renamed'
            assert (target / 'cache/pruned' / Path(host).name).read_bytes() == body
            assert (target / 'memory.md').read_text() == 'unrelated data'
            assert not (target / 'cache/pruned/unused.txt').exists()
            assert not (target / 'cache/other').exists()
            with closing(sqlite3.connect(target / 'state.db')) as raw:
                genuine = raw.execute("select content from messages where session_id='remembered'").fetchone()[0]
                assert genuine == stub.replace(display, str(target / 'cache/pruned' / Path(host).name))
                if recall is not None:
                    content, api = raw.execute("select content,api_content from messages where session_id='current'").fetchone()
                    # Full recovered messages relocate; cropped display data
                    # stays ordinary text, byte-for-byte.
                    expected = recall.replace(display, str(target / 'cache/pruned' / Path(host).name))
                    assert json.loads(content) == json.loads(expected), (content, expected)
                    assert json.loads(json.loads(api)['content']) == json.loads(expected)
            assert Path(host).read_bytes() == body

        verify(baseline, 'before-home')
        output = (session_search(session_id='remembered', persistence=store) if cap == 0 else
                  session_search(query='recallanchor' if cap == 1200 else 'terminal', role_filter='tool',
                                 current_session_id='current', persistence=store))
        payload = json.loads(output); assert payload['success'], payload
        result = payload['results'][0] if cap else payload
        if cap == 0:
            assert result['messages'][0]['content'] == stub
            excerpt = None
        elif cap == 200:
            excerpt = result['snippet']
            assert excerpt.endswith('...'), excerpt
            assert any(m['content'] == stub for m in result['messages'])
        else:
            rows = result['bookend_start'] if cap == 1200 else result['messages']
            cropped = next((m for m in rows if m.get('content_truncated')), None)
            assert cropped is not None, result
            excerpt = cropped['content']
            assert len(excerpt) == cap + 1 and excerpt.endswith('…'), excerpt
            assert cropped['original_content_chars'] == len(stub)
        if excerpt is not None:
            assert ' — full result: ' in excerpt and 'cache/pruned/' in excerpt, excerpt
            assert display not in excerpt, excerpt
        store.messages.append('current', NewMessage(role='tool', content=output,
            api_content=json.dumps({'content': output}), tool_name='session_search', tool_call_id='search'))
        archive = root / 'after.tgz'
        if operation == 'export':
            t.export(home, 'coder', archive)
        else:
            # Coherent native post-recall snapshot plus the COMPLETE pre-recall
            # archive. An old-base archive omitting originals is not causal proof.
            snapshot = root / 'post.db'
            with closing(sqlite3.connect(profile / 'state.db')) as src:
                with closing(sqlite3.connect(snapshot)) as dst:
                    src.backup(dst)
            with tarfile.open(baseline) as src, tarfile.open(archive, 'w:gz') as dst:
                for entry in src:
                    if entry.name == 'profile/state.db':
                        data = snapshot.read_bytes(); entry.size = len(data)
                        dst.addfile(entry, io.BytesIO(data))
                    else:
                        dst.addfile(entry, src.extractfile(entry))
        verify(archive, 'after-home', output)
    finally:
        store.close()
'''
        for cap in (0, 200, 1200, 4000):
            for operation in ('export', 'restore'):
                with self.subTest(cap=cap, operation=operation):
                    result = subprocess.run([
                        sys.executable, '-c', script, os.environ['ENCLOS_HERMES_SOURCE'],
                        str(Path(__file__).parents[3] / 'src/runtime/hermes/transfer.py'),
                        str(cap), operation], capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    @unittest.skipUnless(os.environ.get('ENCLOS_HERMES_SOURCE'), 'real Hermes checkout not supplied')
    def test_real_cross_profile_recall_archive_roundtrip(self):
        # Native session_search reading ANOTHER profile quotes that profile's
        # genuine pointers: display text only, never selected or rewritten.
        script = r'''
import importlib.util, io, json, os, sqlite3, sys, tarfile, tempfile
from contextlib import closing
from pathlib import Path
sys.path.insert(0, sys.argv[1])
spec = importlib.util.spec_from_file_location('transfer', sys.argv[2])
t = importlib.util.module_from_spec(spec); spec.loader.exec_module(t)
reader, other, form, operation = sys.argv[3:7]
with tempfile.TemporaryDirectory() as tmp:
    root = Path(tmp); home = root / 'source'
    homes = {name: home / '.hermes' if name == 'default' else home / '.hermes/profiles' / name for name in (reader, other)}
    os.environ['HOME'] = str(home)
    from persistence_assembly import open_persistence, profile_scope
    from persistence.conversation.sessions import NewSession
    from persistence.conversation.messages import NewMessage
    from tools.tool_result_storage import write_pruned_original, _with_pointer
    from tools.session_search_tool import session_search

    def seed(name, sid, body):
        # Each profile archives its own original through its own HERMES_HOME.
        homes[name].mkdir(parents=True, exist_ok=True)
        os.environ['HERMES_HOME'] = str(homes[name])
        store = open_persistence(profile_scope(home=homes[name]))
        store.sessions.create(NewSession(session_id=sid, source='cli'))
        host, display = write_pruned_original(body.decode(), sid, 'terminal', sid)
        stub = _with_pointer('short', display)
        store.messages.append(sid, NewMessage(role='tool', content=stub, tool_name='terminal', tool_call_id=sid))
        return store, host, display, stub

    theirs = b'FOREIGN SYNTHETIC ORIGINAL\n'
    foreign_store, foreign_host, foreign_display, foreign_stub = seed(other, 'theirs', theirs)
    foreign_store.close()
    assert foreign_display.startswith('~/.hermes/') and 'cache/pruned/' in foreign_display, foreign_display
    body = b'OWNED SYNTHETIC ORIGINAL\n'
    store, host, display, stub = seed(reader, 'mine', body)
    try:
        store.sessions.create(NewSession(session_id='current', source='cli'))
        baseline = root / 'before.tgz'; t.export(home, reader, baseline)
        output = (session_search(session_id=other + '/theirs', persistence=store) if form == 'link' else
                  session_search(session_id='theirs', profile=other, persistence=store))
        payload = json.loads(output); assert payload['success'] and payload['mode'] == 'read', payload
        assert [m['content'] for m in payload['messages']] == [foreign_stub], payload
        assert foreign_display in output and display not in output, output
        store.messages.append('current', NewMessage(role='tool', content=output,
            api_content=json.dumps({'content': output}), tool_name='session_search', tool_call_id='search'))
        archive = root / 'after.tgz'
        if operation == 'export':
            t.export(home, reader, archive)
        else:
            # Complete pre-recall archive plus the coherent post-recall snapshot.
            snapshot = root / 'post.db'
            with closing(sqlite3.connect(homes[reader] / 'state.db')) as src:
                with closing(sqlite3.connect(snapshot)) as dst:
                    src.backup(dst)
            with tarfile.open(baseline) as src, tarfile.open(archive, 'w:gz') as dst:
                for entry in src:
                    if entry.name == 'profile/state.db':
                        data = snapshot.read_bytes(); entry.size = len(data)
                        dst.addfile(entry, io.BytesIO(data))
                    else:
                        dst.addfile(entry, src.extractfile(entry))
        with tarfile.open(archive) as members:
            names = members.getnames()
        assert [n for n in names if n.startswith('profile/cache/')] == ['profile/cache/pruned/' + Path(host).name], names
        assert not any(Path(foreign_host).name in n for n in names), names
        destination_home = root / 'restored'; destination_home.mkdir()
        t.restore(destination_home, 'renamed', archive)
        target = destination_home / '.hermes/profiles/renamed'
        assert (target / 'cache/pruned' / Path(host).name).read_bytes() == body
        with closing(sqlite3.connect(target / 'state.db')) as raw:
            genuine = raw.execute("select content from messages where session_id='mine'").fetchone()[0]
            assert genuine == stub.replace(display, str(target / 'cache/pruned' / Path(host).name)), genuine
            content, api = raw.execute("select content,api_content from messages where session_id='current'").fetchone()
        assert content == output and api == json.dumps({'content': output}), (content, api)
        assert sorted(p.name for p in (destination_home / '.hermes/profiles').iterdir()) == ['renamed']
        assert not (destination_home / '.hermes/cache').exists()
        assert not list(destination_home.rglob(Path(foreign_host).name))
        assert Path(foreign_host).read_bytes() == theirs and Path(host).read_bytes() == body
    finally:
        store.close()
'''
        # default reads a named profile; a named profile reads another by link
        # and reads the root profile.
        for reader, other, form in (('default', 'other', 'profile'), ('coder', 'other', 'link'),
                                    ('coder', 'default', 'profile')):
            for operation in ('export', 'restore'):
                with self.subTest(reader=reader, other=other, form=form, operation=operation):
                    result = subprocess.run([
                        sys.executable, '-c', script, os.environ['ENCLOS_HERMES_SOURCE'],
                        str(Path(__file__).parents[3] / 'src/runtime/hermes/transfer.py'),
                        reader, other, form, operation], capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
