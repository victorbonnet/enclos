from contextlib import closing
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import sqlite3
import tarfile
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('transfer', Path(__file__).parents[1] / 'transfer.py')
transfer = importlib.util.module_from_spec(spec); spec.loader.exec_module(transfer)

class TransferTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name); self.source = self.base / 'source'; self.dest = self.base / 'dest'
        self.source.mkdir(); self.dest.mkdir(); self.profile = self.source / '.hermes/profiles/main'; self.profile.mkdir(parents=True)
        (self.profile / 'config.yaml').write_text('model: test\ncwd: ' + str(self.source / 'project') + '\n')
        self.archive = self.base / 'agent.tar.gz'
    def prose_rows(self):
        prose = [
            'Please explain how cache/pruned/example.txt is used.',
            'The path "cache/pruned/example.txt" is an example.',
            '`cache/pruned/example.txt`',
            '```python\npath = "cache/pruned/example.txt"\n```',
            str(self.profile / 'cache/pruned/example.txt'),
            'Explain "' + str(self.profile / 'cache/pruned/example.txt') + '".',
            '`' + str(self.profile / 'cache/pruned/example.txt') + '`, please.',
            '(' + str(self.profile / 'cache/pruned/example.txt') + ') is an example.',
        ]
        return [(text, api) for text in prose for api in (
            text, json.dumps([{'type': 'text', 'text': text}]),
            '\x00json:' + json.dumps({'content': [{'text': text}]}))]

    def write_prose(self):
        rows = self.prose_rows()
        with sqlite3.connect(self.profile / 'state.db') as db:
            db.execute('create table messages(content text, api_content text)')
            db.executemany('insert into messages values (?,?)', rows)
        return rows

    def assert_prose_restore(self, rows):
        transfer.restore(self.dest, 'renamed', self.archive)
        with sqlite3.connect(self.dest / '.hermes/profiles/renamed/state.db') as db:
            self.assertEqual(db.execute('select content, api_content from messages').fetchall(), rows)

    def test_incidental_prose_roundtrip(self):
        rows = self.write_prose()
        transfer.export(self.source, 'main', self.archive)
        self.assert_prose_restore(rows)

    def test_original_base_archive_with_prose_restores(self):
        rows = self.write_prose()
        # The original hermes-data-v1 export contains the manifest and raw
        # profile files, with no selected cache members. Build that format
        # directly so this regression also runs in shallow/source-only CI.
        metadata = json.dumps({'format': transfer.FORMAT, 'home': str(self.source),
                               'profile': str(self.profile), 'agent': 'main'}).encode()
        with tarfile.open(self.archive, 'w:gz') as archive:
            manifest = tarfile.TarInfo('manifest.json'); manifest.size = len(metadata)
            archive.addfile(manifest, io.BytesIO(metadata))
            for filename in ('config.yaml', 'state.db'):
                archive.add(self.profile / filename, arcname='profile/' + filename)
        self.assert_prose_restore(rows)

    def test_native_list_and_summary_pointer_forms(self):
        cache = self.profile / 'cache/pruned'; cache.mkdir(parents=True)
        path = str(cache / 'original.txt'); (cache / 'original.txt').write_text('exact original')
        heading = 'Archived tool output (exact originals; read_file a path to recover one):'
        forms = [json.dumps([{'type': 'text', 'text': 'full result: ' + path}]),
                 '\x00json:' + json.dumps([{'type': 'text', 'text': 'full result: ' + path}]),
                 'summary\n\n' + heading + '\n- ' + path]
        with sqlite3.connect(self.profile / 'state.db') as db:
            db.execute('create table messages(content text, api_content text)')
            db.executemany('insert into messages values (?,?)', [(f, json.dumps({'content': f})) for f in forms])
        transfer.export(self.source, 'main', self.archive)
        transfer.restore(self.dest, 'renamed', self.archive)
        target = self.dest / '.hermes/profiles/renamed'
        self.assertEqual((target / 'cache/pruned/original.txt').read_text(), 'exact original')
        with sqlite3.connect(target / 'state.db') as db:
            for content, api in db.execute('select * from messages'):
                self.assertNotIn(str(self.profile), content + api)
                self.assertIn(str(target), content)

    def test_referenced_pruned_archives_roundtrip_from_wal(self):
        cache = self.profile / 'cache/pruned'; cache.mkdir(parents=True)
        (cache / 'active.txt').write_text('full active output')
        (cache / 'inactive.json').write_text('{"full":"inactive"}')
        (cache / 'unused.txt').write_text('not durable')
        db = sqlite3.connect(self.profile / 'state.db'); self.addCleanup(db.close)
        db.execute('pragma journal_mode=wal')
        db.execute('create table messages(id integer primary key, content text, api_content text, active integer)')
        for n, name in enumerate(('active.txt', 'inactive.json')):
            pointer = 'short — full result: ' + str(cache / name)
            db.execute('insert into messages values (?,?,?,?)', (n, pointer, json.dumps([{'text': pointer}]), n))
        db.commit()
        transfer.export(self.source, 'main', self.archive)
        transfer.restore(self.dest, 'renamed', self.archive)
        target = self.dest / '.hermes/profiles/renamed'
        self.assertEqual((target / 'cache/pruned/active.txt').read_text(), 'full active output')
        self.assertFalse((target / 'cache/pruned/unused.txt').exists())
        with sqlite3.connect(target / 'state.db') as restored:
            for content, api in restored.execute('select content, api_content from messages'):
                self.assertIn(str(target / 'cache/pruned'), content)
                self.assertIn(str(target / 'cache/pruned'), json.loads(api)[0]['text'])

    def test_missing_or_linked_pruned_reference_refuses_export(self):
        cache = self.profile / 'cache/pruned'; cache.mkdir(parents=True)
        with sqlite3.connect(self.profile / 'state.db') as db:
            db.execute('create table messages(content text)')
            db.execute('insert into messages values (?)', ('short — full result: ' + str(cache / 'gone.txt'),))
        with self.assertRaises(ValueError): transfer.export(self.source, 'main', self.archive)
        self.assertFalse(self.archive.exists())
        outside = self.base / 'private'; outside.write_text('private')
        (cache / 'gone.txt').symlink_to(outside)
        with self.assertRaises(ValueError): transfer.export(self.source, 'main', self.archive)
        self.assertFalse(self.archive.exists())

    def test_outside_and_traversing_archive_pointers_are_refused(self):
        for pointer in ('/outside/cache/pruned/x.txt', str(self.profile / 'cache/pruned') + '/../secret',
                        '~/.hermes/profiles/another/cache/pruned/x.txt'):
            with self.subTest(pointer=pointer):
                with sqlite3.connect(self.profile / 'state.db') as db:
                    db.execute('create table if not exists messages(content text)')
                    db.execute('delete from messages')
                    db.execute('insert into messages values (?)', ('short — full result: ' + pointer,))
                with self.assertRaises(ValueError): transfer.export(self.source, 'main', self.archive)
                self.assertFalse(self.archive.exists())

    def test_archive_discovery_uses_exported_snapshot(self):
        cache = self.profile / 'cache/pruned'; cache.mkdir(parents=True)
        (cache / 'original.txt').write_text('snapshot original')
        original = 'short — full result: ' + str(cache / 'original.txt')
        with sqlite3.connect(self.profile / 'state.db') as db:
            db.execute('create table messages(content text)')
            db.execute('insert into messages values (?)', (original,))
        read_rows = transfer.message_archive_rows
        def concurrent_write(snapshot):
            self.assertNotEqual(snapshot, self.profile / 'state.db')
            with sqlite3.connect(self.profile / 'state.db') as db:
                db.execute('update messages set content=?', ('short — full result: ' + str(cache / 'missing.txt'),))
            return read_rows(snapshot)
        with patch.object(transfer, 'message_archive_rows', concurrent_write):
            transfer.export(self.source, 'main', self.archive)
        transfer.restore(self.dest, 'renamed', self.archive)
        target = self.dest / '.hermes/profiles/renamed'
        with sqlite3.connect(target / 'state.db') as db:
            self.assertEqual(db.execute('select content from messages').fetchone()[0],
                             'short — full result: ' + str(target / 'cache/pruned/original.txt'))

    def test_native_forms_keep_strict_path_validation(self):
        heading = 'Archived tool output (exact originals; read_file a path to recover one):'
        for path in ('/outside/cache/pruned/x.txt',
                     str(self.profile / 'cache/pruned/../secret'),
                     '~/.hermes/profiles/another/cache/pruned/x.txt',
                     str(self.profile / 'cache/pruned/x.txt') + '/child',
                     str(self.profile / 'cache/pruned/x.txt') + '`'):
            for form in ('short — full result: ' + path, 'full result: ' + path,
                         'summary\n\n' + heading + '\n- ' + path):
                for text in (form, json.dumps([{'text': form}]),
                             '\x00json:' + json.dumps({'content': form})):
                    with self.subTest(text=text), self.assertRaises(ValueError):
                        transfer.archive_pointers(text, self.profile)

    def test_genuine_missing_and_linked_forms_remain_required(self):
        cache = self.profile / 'cache/pruned'; cache.mkdir(parents=True)
        original = cache / 'missing.txt'
        outside = self.base / 'outside'; outside.write_text('unrelated')
        heading = 'Archived tool output (exact originals; read_file a path to recover one):'
        for linked in (False, True):
            if linked:
                original.symlink_to(outside)
            for form in ('short — full result: ' + str(original),
                         json.dumps([{'type': 'text', 'text': 'full result: ' + str(original)}]),
                         'summary\n\n' + heading + '\n- ' + str(original)):
                with self.subTest(linked=linked, form=form):
                    with sqlite3.connect(self.profile / 'state.db') as db:
                        db.execute('create table if not exists messages(role text, content text, api_content text)')
                        db.execute('delete from messages')
                        # Summary pointers are real dependencies even outside tool roles.
                        db.execute('insert into messages values (?,?,?)',
                                   ('assistant', form, json.dumps({'content': form})))
                    with self.assertRaises(ValueError):
                        transfer.export(self.source, 'main', self.archive)
                    self.assertFalse(self.archive.exists())
                    self.assertEqual(outside.read_text(), 'unrelated')

    def recall_outputs(self, full, crop=None, entry=None):
        # tools.session_search_tool shapes: _shape_message crops content to N
        # chars + '…'; _derived_snippet windows the anchor with '...' and
        # >>>term<<< marks. Both cut the pointer filename here.
        cut = full[:full.index('cache/pruned/') + len('cache/pruned/ori')]
        cropped = {'id': 1, 'role': 'tool', 'content': cut + '…', 'timestamp': 1.0,
                   **({'content_truncated': True, 'original_content_chars': len(full)} if crop is None else crop)}
        message = {'id': 1, 'role': 'tool', 'content': full, 'timestamp': 1.0, 'tool_name': 'terminal'}
        snippet = '...' + cut.replace('ok', '>>>ok<<<', 1) + '...'
        if entry is None:
            entry = {'session_id': 'remembered', 'when': 'now', 'matched_role': 'tool', 'match_message_id': 1,
                     'snippet': snippet, 'bookend_start': [cropped], 'messages': [message], 'bookend_end': []}
        else:
            entry = {**entry, 'snippet': snippet}
        discover = json.dumps({'success': True, 'mode': 'discover', 'results': [entry], 'count': 1})
        read = json.dumps({'success': True, 'session_id': 'remembered', 'messages': [cropped, message]})
        return {'discover': discover, 'read': read}, (cut + '…', snippet)

    def write_recall(self, outputs):
        with sqlite3.connect(self.profile / 'state.db') as db:
            db.execute('create table if not exists messages(role text, content text, api_content text)')
            db.execute('delete from messages')
            for output in outputs.values():
                for api in (json.dumps({'content': output}), '\x00json:' + json.dumps({'content': output})):
                    db.execute('insert into messages values (?,?,?)', ('tool', output, api))

    def test_native_recall_crops_are_display_data(self):
        cache = self.profile / 'cache/pruned'; cache.mkdir(parents=True)
        (cache / 'original.txt').write_text('exact original')
        path = str(cache / 'original.txt')
        outputs, crops = self.recall_outputs('ok — full result: ' + path)
        self.write_recall(outputs)
        transfer.export(self.source, 'main', self.archive)
        transfer.restore(self.dest, 'renamed', self.archive)
        target = self.dest / '.hermes/profiles/renamed'
        self.assertEqual((target / 'cache/pruned/original.txt').read_text(), 'exact original')
        expected = [json.loads(output.replace(path, str(target / 'cache/pruned/original.txt')))
                    for output in outputs.values()]
        with sqlite3.connect(target / 'state.db') as db:
            rows = db.execute('select content, api_content from messages').fetchall()
        self.assertEqual(len(rows), 4)
        for content, api in rows:
            api = json.loads(api.removeprefix('\x00json:'))['content']
            for text in (content, api):
                value = json.loads(text)
                self.assertIn(value, expected)
                self.assertNotIn(path, text)
                displayed = [m['content'] for m in value.get('messages', []) if m.get('content_truncated')]
                for result in value.get('results', []):
                    displayed += [result['snippet']] + [m['content'] for m in result['bookend_start']]
                self.assertTrue(displayed)
                for crop in displayed:
                    self.assertIn(crop, crops)

    def test_native_recall_shape_keeps_genuine_pointers_required(self):
        cache = self.profile / 'cache/pruned'; cache.mkdir(parents=True)
        outside = self.base / 'outside'; outside.write_text('unrelated')
        present = cache / 'original.txt'
        cases = [('missing full', 'ok — full result: ' + str(cache / 'missing.txt'), None, None)]
        for path in ('/outside/cache/pruned/x.txt', str(cache) + '/../secret', str(cache / 'linked.txt')):
            cases.append(('unsafe full', 'ok — full result: ' + path, None, None))
        # Another profile's pointer is display text only inside a recognized
        # native envelope; the helper's mode-less read output is not one.
        cases.append(('foreign outside recall', 'ok — full result: ~/.hermes/profiles/another/cache/pruned/x.txt', None, None))
        for crop in ({'original_content_chars': 99}, {'content_truncated': 'true', 'original_content_chars': 99},
                     {'content_truncated': 1, 'original_content_chars': 99}, {'content_truncated': True},
                     {'content_truncated': True, 'original_content_chars': '99'},
                     {'content_truncated': True, 'original_content_chars': True}):
            cases.append(('not a native crop', 'ok — full result: ' + str(present), crop, None))
        for entry in ({}, {'session_id': 'remembered'}, {'match_message_id': 1, 'bookend_start': []}):
            cases.append(('not a native entry', 'ok — full result: ' + str(present), None, entry))
        present.write_text('exact original'); (cache / 'linked.txt').symlink_to(outside)
        for label, full, crop, entry in cases:
            outputs, _ = self.recall_outputs(full, crop, entry)
            # A shape outside the native recognition is scanned as a whole.
            outputs = {'discover': outputs['discover']} if entry is not None else (
                {'read': outputs['read']} if crop is not None or label == 'foreign outside recall' else outputs)
            with self.subTest(label=label, full=full, crop=crop, entry=entry):
                self.write_recall(outputs)
                with self.assertRaises(ValueError):
                    transfer.export(self.source, 'main', self.archive)
                self.assertFalse(self.archive.exists())
                for text in outputs.values():
                    with self.assertRaises(ValueError):
                        transfer.rewrite_archive_text(text, self.profile, self.dest, self.profile, set())
        self.assertEqual(outside.read_text(), 'unrelated')

    HEADING = 'Archived tool output (exact originals; read_file a path to recover one):'

    def pointers(self, home, filename):
        # Absolute and ~/ display forms of a genuine pointer into a Hermes home.
        path = home / 'cache/pruned' / filename
        return [str(path), '~/' + str(path.relative_to(self.source))]

    def pointer_contents(self, pointer):
        # _with_pointer's inline suffix and list part (also as JSON text) and
        # archive_list_for_summary's headed list.
        part = [{'type': 'text', 'text': 'short'}, {'type': 'text', 'text': 'full result: ' + pointer}]
        return ['ok — full result: ' + pointer, part, json.dumps(part), 'summary\n\n' + self.HEADING + '\n- ' + pointer]

    def envelopes(self, contents):
        # tools.session_search_tool read, scroll and discover payloads.
        msgs = [{'id': n, 'role': 'tool', 'content': c, 'timestamp': 1.0} for n, c in enumerate(contents)]
        return [{'success': True, 'mode': 'read', 'session_id': 'theirs', 'link': '@session:other/theirs',
                 'session_meta': {}, 'message_count': len(msgs), 'truncated': False, 'messages': msgs},
                {'success': True, 'mode': 'scroll', 'session_id': 'theirs', 'messages': msgs},
                {'success': True, 'mode': 'discover', 'count': 1, 'results': [
                    {'session_id': 'theirs', 'bookend_start': msgs[:1], 'messages': msgs[1:-1], 'bookend_end': msgs[-1:]}]}]

    def stored_rows(self, value):
        # A recall output stored as a tool row, with JSON-in-JSON api_content.
        text = json.dumps(value)
        return [(text, json.dumps({'content': text})), (text, '\x00json:' + json.dumps({'content': text})),
                ('\x00json:' + text, text)]

    def write_rows(self, origin, rows):
        with closing(sqlite3.connect(origin / 'state.db')) as db, db:
            db.execute('create table if not exists messages(content text, api_content text)')
            db.execute('delete from messages')
            db.executemany('insert into messages values (?,?)', rows)

    def assert_refused(self, rows):
        self.write_rows(self.profile, rows)
        with self.assertRaises(ValueError): transfer.export(self.source, 'main', self.archive)
        self.assertFalse(self.archive.exists())
        for text in {text for row in rows for text in row}:
            with self.assertRaises(ValueError):
                transfer.rewrite_archive_text(text, self.profile, self.dest, self.profile, set())

    def cross_profile_roundtrip(self, reader):
        root = self.source / '.hermes'
        origin = root if reader == 'default' else root / 'profiles' / reader
        others = [root / 'profiles/other', root / 'profiles/main' if reader == 'default' else root]
        (origin / 'cache/pruned').mkdir(parents=True)
        (origin / 'cache/pruned/own.txt').write_text('own original')
        for other in others:
            (other / 'cache/pruned').mkdir(parents=True)
            (other / 'cache/pruned/foreign.txt').write_text('foreign ' + str(other))
        own = self.pointers(origin, 'own.txt')
        foreign = [c for other in others for p in self.pointers(other, 'foreign.txt') for c in self.pointer_contents(p)]
        display = [row for value in self.envelopes(foreign) for row in self.stored_rows(value)]
        mixed = [row for value in self.envelopes(foreign + [c for p in own for c in self.pointer_contents(p)])
                 for row in self.stored_rows(value)]
        stub = ('short — full result: ' + own[1],
                json.dumps([{'type': 'text', 'text': 'short'}, {'type': 'text', 'text': 'full result: ' + own[0]}]))
        self.write_rows(origin, [stub] + display + mixed)
        transfer.export(self.source, reader, self.archive)
        with tarfile.open(self.archive) as archive:
            names = archive.getnames()
        self.assertEqual([n for n in names if n.startswith('profile/cache/')], ['profile/cache/pruned/own.txt'])
        self.assertFalse([n for n in names if 'foreign' in n])
        transfer.restore(self.dest, 'renamed', self.archive)
        target = self.dest / '.hermes/profiles/renamed'
        moved = str(target / 'cache/pruned/own.txt')
        self.assertEqual(Path(moved).read_text(), 'own original')
        rebased = lambda row: tuple(text.replace(own[0], moved).replace(own[1], moved) for text in row)
        with closing(sqlite3.connect(target / 'state.db')) as db:
            restored = db.execute('select content, api_content from messages order by rowid').fetchall()
        # Own pointers relocate; each foreign display reference stays byte-identical.
        self.assertEqual(restored, [rebased(stub)] + display + [rebased(row) for row in mixed])
        self.assertNotEqual(mixed, [rebased(row) for row in mixed])
        self.assertEqual(sorted(p.name for p in (self.dest / '.hermes/profiles').iterdir()), ['renamed'])
        self.assertFalse((self.dest / '.hermes/cache').exists())
        self.assertEqual(list(self.dest.rglob('foreign.txt')), [])
        for other in others:
            self.assertEqual((other / 'cache/pruned/foreign.txt').read_text(), 'foreign ' + str(other))
            (other / 'cache/pruned/foreign.txt').unlink()
        # Never consulted: export still succeeds once the foreign originals are gone.
        transfer.export(self.source, reader, self.base / 'again.tgz')

    def test_named_agent_recall_of_other_profiles_is_display_text(self):
        self.cross_profile_roundtrip('main')

    def test_builtin_agent_recall_of_named_profiles_is_display_text(self):
        self.cross_profile_roundtrip('default')

    def test_recognized_recall_of_another_profile_is_display_text(self):
        outputs, _ = self.recall_outputs('ok — full result: ~/.hermes/profiles/another/cache/pruned/x.txt')
        self.assertEqual(transfer.archive_pointers(outputs['discover'], self.profile), [])
        self.assertEqual(transfer.rewrite_archive_text(outputs['discover'], self.profile, self.dest, self.profile, set()),
                         outputs['discover'])

    def test_foreign_pointer_in_own_stub_refuses(self):
        root = self.source / '.hermes'
        for home in (root, root / 'profiles/other'):
            (home / 'cache/pruned').mkdir(parents=True, exist_ok=True)
            (home / 'cache/pruned/foreign.txt').write_text('foreign')
            for pointer in self.pointers(home, 'foreign.txt'):
                for content in self.pointer_contents(pointer):
                    stub = content if isinstance(content, str) else json.dumps(content)
                    with self.subTest(stub=stub):
                        self.assert_refused([(stub, json.dumps({'content': stub}))])

    def test_unrecognized_recall_lookalikes_keep_foreign_pointers_strict(self):
        (self.source / '.hermes/profiles/other/cache/pruned').mkdir(parents=True)
        (self.source / '.hermes/profiles/other/cache/pruned/foreign.txt').write_text('foreign')
        full = 'ok — full result: ~/.hermes/profiles/other/cache/pruned/foreign.txt'
        msg = {'id': 1, 'role': 'tool', 'content': full, 'timestamp': 1.0}
        quiet = {**msg, 'content': 'ok'}
        read = {'success': True, 'mode': 'read', 'session_id': 'theirs', 'messages': [msg]}
        without = lambda value, key: {k: v for k, v in value.items() if k != key}
        for value in (without(read, 'success'), {**read, 'success': 'true'}, {**read, 'success': 1},
                      {**read, 'mode': 'browse'}, without(read, 'mode'), without(read, 'session_id'),
                      {**read, 'session_id': 7}, {**read, 'messages': [], 'bookend_start': [msg]},
                      {'success': True, 'mode': 'discover', 'results': [{'messages': [msg]}]},
                      {'success': True, 'mode': 'discover', 'results': [{'session_id': 7, 'messages': [msg]}]},
                      {'success': True, 'mode': 'discover', 'results': {'theirs': {'session_id': 'theirs', 'messages': [msg]}}},
                      {**read, 'messages': [without(msg, 'role')]}, {**read, 'messages': [{**msg, 'role': None}]},
                      {**read, 'messages': [{**quiet, 'tool_calls': [{'function': {'arguments': full}}]}]},
                      {**read, 'messages': [{**quiet, 'text': full}]},
                      {**read, 'messages': [quiet], 'title': full},
                      {**read, 'messages': [quiet], 'session_meta': {'title': full}}):
            with self.subTest(value=value):
                self.assert_refused(self.stored_rows(value))

    def test_malformed_foreign_pointer_in_native_recall_refuses(self):
        root = str(self.source / '.hermes')
        for pointer in (root + '/profiles/../cache/pruned/x.txt', root + '/profiles/UPPER/cache/pruned/x.txt',
                        root + '/profiles/a/b/cache/pruned/x.txt', root + '/profiles//cache/pruned/x.txt',
                        '~/.hermes/profiles/_x/cache/pruned/x.txt', '~/.hermes/profiles/' + 'a' * 65 + '/cache/pruned/x.txt',
                        str(self.base / 'elsewhere/.hermes/profiles/other/cache/pruned/x.txt'),
                        '/elsewhere/cache/pruned/x', root + '/profiles/other/cache/pruned/..',
                        '~/.hermes/profiles/other/cache/pruned/x.txt/child', '~/.hermes/profiles/other/cache/pruned/x.txt`'):
            for content in self.pointer_contents(pointer):
                for value in self.envelopes([content]):
                    with self.subTest(pointer=pointer, value=value):
                        self.assert_refused(self.stored_rows(value))

    def test_own_pointer_in_native_recall_stays_required(self):
        outside = self.base / 'outside'; outside.write_text('unrelated')
        foreign = 'ok — full result: ~/.hermes/profiles/other/cache/pruned/foreign.txt'
        for state in ('missing', 'moved', 'linked', 'linked directory'):
            shutil.rmtree(self.profile / 'cache', ignore_errors=True)
            cache = self.profile / 'cache/pruned'
            if state == 'linked directory':
                elsewhere = self.base / 'elsewhere'; elsewhere.mkdir(exist_ok=True)
                (elsewhere / 'own.txt').write_text('elsewhere')
                cache.parent.mkdir(parents=True); cache.symlink_to(elsewhere)
            else:
                cache.mkdir(parents=True)
                if state == 'moved': (cache / 'moved.txt').write_text('own original')
                if state == 'linked': (cache / 'own.txt').symlink_to(outside)
            for pointer in self.pointers(self.profile, 'own.txt'):
                for value in self.envelopes([foreign, 'ok — full result: ' + pointer]):
                    with self.subTest(state=state, pointer=pointer, value=value):
                        self.assert_refused(self.stored_rows(value))
        self.assertEqual(outside.read_text(), 'unrelated')

    def test_restore_refuses_cache_referenced_only_by_foreign_display_pointer(self):
        contents = [c for pointer in ('~/.hermes/profiles/other/cache/pruned/foreign.txt',
                                      str(self.source / '.hermes/cache/pruned/foreign.txt'))
                    for c in self.pointer_contents(pointer)]
        self.write_rows(self.profile, [row for value in self.envelopes(contents) for row in self.stored_rows(value)])
        transfer.export(self.source, 'main', self.archive)
        malicious = self.base / 'malicious.tgz'
        with tarfile.open(self.archive) as src, tarfile.open(malicious, 'w:gz') as dst:
            for item in src: dst.addfile(item, src.extractfile(item))
            item = tarfile.TarInfo('profile/cache/pruned/foreign.txt'); item.size = 4
            dst.addfile(item, io.BytesIO(b'data'))
        with self.assertRaisesRegex(ValueError, 'unreferenced cache in agent data'):
            transfer.restore(self.dest, 'renamed', malicious)
        self.assertFalse((self.dest / '.hermes/profiles/renamed').exists())
        self.assertFalse((self.dest / '.local/bin/renamed').exists())
        self.assertEqual([p for p in self.dest.iterdir() if p.name.startswith('.enclos-restore-')], [])
        self.assertEqual(list(self.dest.rglob('foreign.txt')), [])

    def test_missing_summary_original_refuses_restore_without_publication(self):
        cache = self.profile / 'cache/pruned'; cache.mkdir(parents=True)
        (cache / 'original.txt').write_text('exact')
        pointer = 'summary\n\nArchived tool output (exact originals; read_file a path to recover one):\n- ' + str(cache / 'original.txt')
        with sqlite3.connect(self.profile / 'state.db') as db:
            db.execute('create table messages(content text)')
            db.execute('insert into messages values (?)', (pointer,))
        transfer.export(self.source, 'main', self.archive)
        broken = self.base / 'broken.tgz'
        with tarfile.open(self.archive) as src, tarfile.open(broken, 'w:gz') as dst:
            for item in src:
                if item.name != 'profile/cache/pruned/original.txt':
                    dst.addfile(item, src.extractfile(item))
        with self.assertRaisesRegex(ValueError, 'missing durable archive'):
            transfer.restore(self.dest, 'renamed', broken)
        self.assertFalse((self.dest / '.hermes/profiles/renamed').exists())
        self.assertFalse((self.dest / '.local/bin/renamed').exists())

    def test_restore_rejects_unreferenced_or_other_cache_entries(self):
        transfer.export(self.source, 'main', self.archive)
        for entry in ('profile/cache/pruned/unreferenced.txt', 'profile/cache/other/private'):
            malicious = self.base / 'malicious.tgz'
            with tarfile.open(self.archive) as src, tarfile.open(malicious, 'w:gz') as dst:
                for item in src: dst.addfile(item, src.extractfile(item))
                item = tarfile.TarInfo(entry); item.size = 4
                dst.addfile(item, io.BytesIO(b'data'))
            with self.assertRaises(ValueError): transfer.restore(self.dest, 'renamed', malicious)
            self.assertFalse((self.dest / '.hermes/profiles/renamed').exists())

    def test_credentials_plugins_sqlite_wal_and_shared_files_survive_a_rename(self):
        (self.source / '.hermes/auth.json').write_text('{"refresh_token":"retain-exactly"}')
        plugin = self.profile / 'plugins/custom'; plugin.mkdir(parents=True)
        content = b'fields:\n  password: true\n'; (plugin / 'plugin.yaml').write_bytes(content)
        (self.profile / '.env').write_text('API_KEY=exact-secret\n')
        (self.profile / 'memory.md').write_text('remember')
        project = self.source / 'project'; project.mkdir(); (project / 'main.py').write_text('print(42)')
        (project / '.venv').mkdir(); (project / '.venv/arm-only').write_bytes(b'native')
        db = sqlite3.connect(self.profile / 'state.db'); self.addCleanup(db.close)
        db.execute('pragma journal_mode=wal'); db.execute('create table sessions(chat_id text,profile_name text)')
        db.execute('insert into sessions values (?,?)', ('home.old.main','main')); db.commit()
        transfer.export(self.source, 'main', self.archive)
        transfer.restore(self.dest,'renamed',self.archive,{'conversations':{'home.old.main':'home.new.renamed'}})
        p = self.dest / '.hermes/profiles/renamed'
        self.assertEqual((p / 'plugins/custom/plugin.yaml').read_bytes(), content)
        self.assertEqual((p / '.env').read_text(), 'API_KEY=exact-secret\n')
        self.assertEqual((p / 'auth.json').read_text(), '{"refresh_token":"retain-exactly"}')
        self.assertEqual((self.dest / 'project/main.py').read_text(),'print(42)')
        self.assertFalse((self.dest / 'project/.venv').exists())
        self.assertIn(str(self.dest / 'project'), (p / 'config.yaml').read_text())
        with sqlite3.connect(p / 'state.db') as out: self.assertEqual(out.execute('select * from sessions').fetchall(), [('home.new.renamed','renamed')])
        self.assertTrue((self.dest / '.local/bin/renamed').exists())
    def test_builtin_data_becomes_a_fresh_named_agent_without_other_agents_or_installations(self):
        root = self.source / '.hermes'; (root / 'state.db').write_bytes(b'not-a-database')
        (root / 'config.yaml').write_text('model: root')
        (root / 'tools').mkdir(); (root / 'tools/arm').write_bytes(b'ELF')
        (root / 'state.db').unlink()
        with sqlite3.connect(root / 'state.db') as db: db.execute('create table memory(text)'); db.execute("insert into memory values ('builtin')")
        transfer.export(self.source,'default',self.archive); transfer.restore(self.dest,'from-pi',self.archive)
        p = self.dest / '.hermes/profiles/from-pi'
        self.assertTrue((p / 'state.db').exists()); self.assertFalse((p / 'profiles').exists()); self.assertFalse((p / 'tools').exists())
        self.assertTrue((self.profile / 'config.yaml').exists())
    def test_existing_shared_files_are_not_overwritten(self):
        (self.source / 'project.txt').write_text('source'); (self.dest / 'project.txt').write_text('destination')
        transfer.export(self.source,'main',self.archive)
        with self.assertRaises(ValueError): transfer.restore(self.dest,'new-agent',self.archive)
        self.assertEqual((self.dest / 'project.txt').read_text(),'destination')
        self.assertFalse((self.dest / '.hermes/profiles/new-agent').exists())
    def test_external_data_links_are_refused(self):
        outside = self.base / 'private'; outside.write_text('host secret'); (self.profile / 'escape').symlink_to(outside)
        with self.assertRaises(ValueError): transfer.export(self.source,'main',self.archive)
        self.assertFalse(self.archive.exists())
    def test_profile_and_shared_credentials_are_both_preserved(self):
        root = self.source / '.hermes'
        (root / 'auth.json').write_text('{"providers":{"nous":{"access_token":"shared"}}}')
        (self.profile / 'auth.json').write_text('{"providers":{"anthropic":{"api_key":"own"}}}')
        (root / '.env').write_text('GLOBAL_KEY=global\nSAME=global\n')
        (self.profile / '.env').write_text('OWN_KEY=own\nSAME=own\n')
        transfer.export(self.source,'main',self.archive); transfer.restore(self.dest,'new-agent',self.archive)
        profile = self.dest / '.hermes/profiles/new-agent'
        self.assertEqual(set(json.loads((profile / 'auth.json').read_text())['providers']),{'nous','anthropic'})
        self.assertIn('GLOBAL_KEY=global',(profile / '.env').read_text())
        self.assertTrue((profile / '.env').read_text().endswith('SAME=own\n'))
        self.assertEqual((profile / '.enclos-shared-originals/auth.json').read_text(),(root / 'auth.json').read_text())
    def test_user_commands_persistent_app_storage_and_local_git_history_survive(self):
        for rel in ['bin/my-tool','.local/bin/my-command','.local/share/my-app/state','.cargo/credentials.toml','project/.git/HEAD']:
            p = self.source / rel; p.parent.mkdir(parents=True,exist_ok=True); p.write_text('user data')
        (self.source / '.local/bin/hermes').write_text('native runtime')
        transfer.export(self.source,'main',self.archive); transfer.restore(self.dest,'new-agent',self.archive)
        for rel in ['bin/my-tool','.local/bin/my-command','.local/share/my-app/state','.cargo/credentials.toml','project/.git/HEAD']:
            self.assertEqual((self.dest / rel).read_text(),'user data')
        self.assertFalse((self.dest / '.local/bin/hermes').exists())
    def test_foreign_executable_bytes_are_retained_outside_executable_paths(self):
        p = self.profile / 'bin/tool'; p.parent.mkdir(); header=bytearray(20); header[:4]=b'\x7fELF'; header[5]=1; header[18:20]=(65535).to_bytes(2,'little'); p.write_bytes(header)
        transfer.export(self.source,'main',self.archive); transfer.restore(self.dest,'new-agent',self.archive)
        restored=self.dest / '.hermes/profiles/new-agent'
        self.assertFalse((restored / 'bin/tool').exists())
        self.assertEqual((restored / '.enclos-foreign-tools/bin/tool').read_bytes(),header)
    def test_duplicate_archive_members_are_refused(self):
        with tarfile.open(self.archive,'w:gz') as out:
            for _ in range(2):
                entry=tarfile.TarInfo('profile/config.yaml'); entry.size=1; out.addfile(entry,io.BytesIO(b'x'))
        with self.assertRaises(ValueError): transfer.restore(self.dest,'new-agent',self.archive)
        self.assertFalse((self.dest / '.hermes/profiles/new-agent').exists())
    def test_archive_traversal_links_duplicates_and_installations_are_refused(self):
        for name, kind in [('../escape',tarfile.REGTYPE),('profile/link',tarfile.SYMTYPE),('profile/tools/evil',tarfile.REGTYPE),('home/.local/bin/hermes',tarfile.REGTYPE),('profile/../escape',tarfile.REGTYPE)]:
            with self.subTest(name=name):
                with tarfile.open(self.archive,'w:gz') as out:
                    info=tarfile.TarInfo(name); info.type=kind; info.linkname='../../escape'; info.size=1 if kind==tarfile.REGTYPE else 0
                    out.addfile(info,io.BytesIO(b'x') if info.size else None)
                with self.assertRaises(ValueError): transfer.restore(self.dest,'new-agent',self.archive)
                self.assertFalse((self.dest / '.hermes/profiles/new-agent').exists())


class OutputLimitTests(unittest.TestCase):
    def test_runtime_export_stops_at_the_write_limit_and_removes_partial_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / 'home'; profile=home / '.hermes/profiles/main'; profile.mkdir(parents=True)
            (profile / 'config.yaml').write_text('model: fixture')
            (profile / 'data').write_bytes(os.urandom(4096))
            archive=Path(tmp) / 'agent.tar.gz'
            with self.assertRaisesRegex(ValueError,'export size limit'):
                transfer.export(home,'main',archive,max_bytes=512)
            self.assertFalse(archive.exists())

if __name__ == '__main__': unittest.main()
