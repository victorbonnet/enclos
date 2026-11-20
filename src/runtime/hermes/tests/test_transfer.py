import importlib.util
import io
import json
import os
from pathlib import Path
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
        for path in ('/outside/cache/pruned/x.txt', str(cache) + '/../secret',
                     '~/.hermes/profiles/another/cache/pruned/x.txt', str(cache / 'linked.txt')):
            cases.append(('unsafe full', 'ok — full result: ' + path, None, None))
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
                {'read': outputs['read']} if crop is not None else outputs)
            with self.subTest(label=label, full=full, crop=crop, entry=entry):
                self.write_recall(outputs)
                with self.assertRaises(ValueError):
                    transfer.export(self.source, 'main', self.archive)
                self.assertFalse(self.archive.exists())
                for text in outputs.values():
                    with self.assertRaises(ValueError):
                        transfer.rewrite_archive_text(text, self.profile, self.dest, self.profile, set())
        self.assertEqual(outside.read_text(), 'unrelated')

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
