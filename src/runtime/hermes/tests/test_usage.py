import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('usage', Path(__file__).parents[1] / 'usage.py')
usage = importlib.util.module_from_spec(spec); spec.loader.exec_module(usage)

# The columns of Hermes's `sessions` table the reader uses, as Hermes writes them.
FULL = ('id text primary key, source text, model text, title text, started_at real not null, '
        'ended_at real, last_activity_at real, api_call_count integer default 0, '
        'input_tokens integer default 0, output_tokens integer default 0, '
        'cache_read_tokens integer default 0, cache_write_tokens integer default 0, '
        'reasoning_tokens integer default 0, estimated_cost_usd real, actual_cost_usd real, '
        'cost_status text')


class UsageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)
        (self.home / '.hermes/profiles/scout').mkdir(parents=True)
        self.out = self.home / 'report.json'

    def db(self, agent, schema=FULL):
        path = usage.agent_db(str(self.home), agent)
        db = sqlite3.connect(path); self.addCleanup(db.close)
        db.execute('pragma journal_mode=wal'); db.execute('create table sessions(' + schema + ')')
        return db

    def run_reader(self, since, *agents):
        with mock.patch.dict(os.environ, {'HOME': str(self.home)}):
            usage.main(['-c', str(self.out), str(since), *agents])
        return {a['agent']: a for a in json.loads(self.out.read_text())['agents']}

    def test_chats_active_in_the_window_add_up_per_model_and_the_top_ones_are_listed(self):
        db = self.db('default')
        rows = [
            # id, source, model, title, started, ended, last, calls, in, out, cr, cw, reasoning, est, actual, status
            ('s1', 'enclos', 'gpt', 'Weather', 100, None, 1000, 26, 83087, 6084, 762752, 0, 0, 0.0, None, 'included'),
            ('s2', 'cli', 'gpt', None, 900, 950, None, 2, 10, 5, 0, 0, 1, 0.0, None, 'included'),
            ('s3', 'cron', 'flash', 'Old', 10, 20, 20, 1, 13154, 25, 0, 0, 0, 0.01, None, 'estimated'),
            ('s4', 'cli', 'flash', 'Paid', 800, None, 900, 1, 100, 10, 0, 0, 0, 0.5, 0.25, 'actual'),
        ]
        db.executemany('insert into sessions values (' + ','.join('?' * 16) + ')', rows); db.commit()
        report = self.run_reader(500, 'default', 'scout')
        default = report['default']
        self.assertTrue(default['found'])
        gpt, flash = default['models']
        self.assertEqual(gpt['model'], 'gpt')
        self.assertEqual(gpt['chats'], 2)
        self.assertEqual(gpt['calls'], 28)
        self.assertEqual(gpt['tokens'], {'input': 83097, 'output': 6089, 'cache_read': 762752,
                                         'cache_write': 0, 'reasoning': 1})
        self.assertEqual(gpt['cost'], {'usd': 0.0, 'kind': 'included'})
        # s3's last activity is before the window: left out whole.
        self.assertEqual(flash['chats'], 1)
        self.assertEqual(flash['cost'], {'usd': 0.25, 'kind': 'actual'})
        self.assertEqual([c['chat'] for c in default['top']], ['s1', 's4', 's2'])
        self.assertEqual(report['scout'], {'agent': 'scout', 'found': False, 'models': [], 'top': []})
        self.assertEqual(os.stat(self.out).st_mode & 0o777, 0o600)

    def test_a_count_an_older_hermes_does_not_keep_is_null_not_zero(self):
        db = self.db('scout', 'id text, model text, started_at real, input_tokens integer, '
                              'output_tokens integer, cost_status text')
        db.execute("insert into sessions values ('a', 'm', 100, 5, 7, 'mystery')"); db.commit()
        model = self.run_reader(0, 'scout')['scout']['models'][0]
        self.assertEqual(model['tokens'], {'input': 5, 'output': 7, 'cache_read': None,
                                           'cache_write': None, 'reasoning': None})
        self.assertIsNone(model['calls'])
        self.assertEqual(model['cost'], {'usd': None, 'kind': 'unknown'})

    def test_chats_of_several_cost_kinds_are_mixed(self):
        self.assertEqual(usage.cost_kind({'included', 'estimated'}), 'mixed')
        self.assertEqual(usage.cost_kind(set()), 'unknown')

    def test_a_report_already_there_is_never_replaced(self):
        self.out.write_text('{}')
        with self.assertRaises(FileExistsError):
            self.run_reader(0, 'default')
        self.out.unlink(); os.symlink(self.home / 'elsewhere', self.out)
        with self.assertRaises(FileExistsError):
            self.run_reader(0, 'default')
        self.assertFalse((self.home / 'elsewhere').exists())


if __name__ == '__main__':
    unittest.main()
