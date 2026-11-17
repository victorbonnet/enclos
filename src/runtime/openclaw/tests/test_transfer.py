import importlib.util
import io
import json
from pathlib import Path
import sqlite3
import tarfile
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('transfer', Path(__file__).parents[1] / 'transfer.py')
transfer = importlib.util.module_from_spec(spec); spec.loader.exec_module(transfer)


class TransferTests(unittest.TestCase):
    def test_bridge_routes_rebase_ownership_without_rekeying_native_history_or_replaying(self):
        peer = transfer.digest(['old', 'alice'])
        result = transfer.imported_routes({'old': {'person': 'alice', 'peer': peer}}, {'old': 'new'}, 'bob', 'kilian')
        self.assertEqual(result['routes']['new'], {'person': 'bob', 'peer': peer, 'origin': {'v': 1, 'conversation': 'old', 'person': 'alice'}})
        self.assertEqual(result['outbox'], []); self.assertEqual(result['receipts'], {})
        again = transfer.imported_routes(result['routes'], {'new': 'third'}, 'carol', 'kilian')
        self.assertEqual(again['routes']['third']['peer'], peer)
        self.assertEqual(again['routes']['third']['origin']['conversation'], 'old')
        with self.assertRaises(ValueError): transfer.imported_routes({'old': {'person': 'alice', 'peer': 'forged'}}, {'old': 'new'}, 'bob', 'kilian')

    def test_home_route_preserves_native_peer_and_requires_destination_owner(self):
        peer = transfer.digest(['enclos-home', 'kilian', 'kilian', 'old-home'])
        route = {'kind': 'home', 'person': 'alice', 'peer': peer}
        result = transfer.imported_routes({'old-home': route}, {'old-home': 'new-home'}, 'bob', 'kilian')
        self.assertEqual(result['routes']['new-home']['peer'], peer)
        with self.assertRaises(ValueError): transfer.imported_routes({'old-home': route}, {'old-home': 'new-home'}, None, 'kilian')

    def test_native_snapshot_refuses_recovery_and_unconsumed_input_but_preserves_terminal_history(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / 'agent.sqlite'
            with sqlite3.connect(p) as db:
                db.execute('create table session_nodes(entry_json text)')
                db.execute('create table session_pending_inputs(state text,consumed_event_id text)')
                db.execute('insert into session_nodes values (?)', (json.dumps({'status': 'done', 'activeWriterRunId': 'historic', 'restartRecoveryTerminalRunIds': ['historic']}),))
            transfer.assert_idle_database(p)
            with sqlite3.connect(p) as db: db.execute("insert into session_pending_inputs values ('cancelled',null)")
            transfer.assert_idle_database(p)
            with sqlite3.connect(p) as db: db.execute("insert into session_pending_inputs values ('queued',null)")
            with self.assertRaises(ValueError): transfer.assert_idle_database(p)
            with sqlite3.connect(p) as db:
                db.execute('delete from session_pending_inputs'); db.execute('update session_nodes set entry_json=?', (json.dumps({'mainRestartRecovery': {'cycleId': 'pending'}}),))
            with self.assertRaises(ValueError): transfer.assert_idle_database(p)

    def test_archive_rejects_links_traversal_duplicates_and_runtime_control_files(self):
        cases = [('home/.openclaw/state/openclaw.sqlite', tarfile.REGTYPE), ('../escape', tarfile.REGTYPE),
                 ('home/bin/openclaw', tarfile.REGTYPE), ('agent/openclaw-agent.sqlite', tarfile.REGTYPE),
                 ('workspace/link', tarfile.SYMTYPE), ('home/.local/share/openclaw/bin/openclaw', tarfile.REGTYPE)]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for i, (name, kind) in enumerate(cases):
                with self.subTest(name=name):
                    p = root / f'{i}.tgz'; dest = root / f'dest-{i}'; dest.mkdir()
                    with tarfile.open(p, 'w:gz') as out:
                        entry = tarfile.TarInfo(name); entry.type = kind; entry.size = 1 if kind == tarfile.REGTYPE else 0; entry.linkname = '../../escape'
                        out.addfile(entry, io.BytesIO(b'x') if entry.size else None)
                    with self.assertRaises(ValueError): transfer.extract(p, dest)

    def test_snapshot_identity_and_shared_config_never_replace_another_agent(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp); (p / 'manifest.json').write_text(json.dumps({'database': {'role': 'agent', 'agentId': 'main'}}))
            transfer.assert_snapshot_identity(p, 'main')
            with self.assertRaises(ValueError): transfer.assert_snapshot_identity(p, 'kilian')
        target = {'plugins': {'entries': {'existing': {'enabled': True}}}}
        transfer.merge_shared(target, {'plugins': {'entries': {'codex': {'enabled': True}}}})
        self.assertTrue(target['plugins']['entries']['existing']['enabled'])
        with self.assertRaises(ValueError): transfer.merge_shared(target, {'plugins': {'entries': {'existing': {'enabled': False}}}})

    def test_runtime_installs_are_pruned_before_following_their_links(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp); root = home / '.local/share'; root.mkdir(parents=True)
            (root / 'openclaw').symlink_to('/outside-runtime'); (root / 'user-data').mkdir(); (root / 'user-data/state').write_text('persistent')
            files = list(transfer.regular_tree(home / '.local', home, Path('.local'), lambda rel: transfer.home_skip(rel, transfer.HELPERS)))
            self.assertEqual([str(rel) for rel, _ in files], ['.local/share/user-data/state'])
        self.assertTrue(transfer.valid_plugin_spec('@openclaw/codex@2026.11.3'))
        for value in ['codex@latest', '--option@1.2.3', 'https://untrusted/package.tgz']:
            self.assertFalse(transfer.valid_plugin_spec(value))

    def test_user_links_are_materialized_only_within_the_home_and_without_cycles(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp).resolve(); data = home / 'data'; data.mkdir(); (data / 'memory').write_text('kept')
            link = home / 'linked'; link.symlink_to(data)
            self.assertEqual([str(p) for p, _ in transfer.regular_tree(link, home)], ['memory'])
            (data / 'loop').symlink_to(data)
            with self.assertRaises(ValueError): list(transfer.regular_tree(link, home))
            (data / 'loop').unlink(); (data / 'external').symlink_to('/etc/passwd')
            with self.assertRaises(ValueError): list(transfer.regular_tree(link, home))

    def test_manifest_rejects_rekeying_relocation_and_foreign_authority_before_native_writes(self):
        meta = {'format': transfer.FORMAT, 'version': transfer.VERSION, 'home': '/sandbox', 'agent': 'main',
                'snapshot': 'native-id', 'workspace': '.openclaw/workspace', 'agent_config': {}, 'shared_config': {},
                'plugins': [], 'routes': {}, 'sharedAuth': {'profiles': {}}, 'localAuth': {'profiles': {}},
                'bindings': [], 'host_reference': {}}
        transfer.validate_manifest(meta, Path('/sandbox'), 'main')
        for patch in [{'agent': 'kilian'}, {'home': '/other'}, {'snapshot': '../escape'}, {'unexpected': True},
                      {'bindings': [['session:kilian:id', {}]]}, {'shared_config': {'gateway': {}}},
                      {'shared_config': {'agents': {'entries': {'foreign': {}}}}}]:
            with self.subTest(patch=patch), self.assertRaises(ValueError):
                transfer.validate_manifest({**meta, **patch}, Path('/sandbox'), 'main')


if __name__ == '__main__': unittest.main()
