import importlib.util
import io
import json
import os
from pathlib import Path
import sqlite3
import tarfile
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('transfer', Path(__file__).parents[1] / 'transfer.py')
transfer = importlib.util.module_from_spec(spec); spec.loader.exec_module(transfer)

class TransferTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name); self.source = self.base / 'source'; self.dest = self.base / 'dest'
        self.source.mkdir(); self.dest.mkdir(); self.profile = self.source / '.hermes/profiles/main'; self.profile.mkdir(parents=True)
        (self.profile / 'config.yaml').write_text('model: test\ncwd: ' + str(self.source / 'project') + '\n')
        self.archive = self.base / 'agent.tar.gz'
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
                    db.execute('insert into messages values (?)', (pointer,))
                with self.assertRaises(ValueError): transfer.export(self.source, 'main', self.archive)
                self.assertFalse(self.archive.exists())

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
