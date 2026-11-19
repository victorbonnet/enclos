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

    def per_model(self, db):
        db.execute('create table session_model_usage(session_id text, model text, task text, '
                   'api_call_count integer, input_tokens integer, output_tokens integer, '
                   'cache_read_tokens integer, cache_write_tokens integer, reasoning_tokens integer, '
                   'estimated_cost_usd real, actual_cost_usd real, cost_status text)')

    def test_every_call_counts_by_the_model_it_went_to_and_counters_beyond_the_rows_go_to_the_chats_model(self):
        db = self.db('default'); self.per_model(db)
        rows = [
            # A chat that switched model halfway; its counters (main loop only) say 3 calls, 300 in.
            ('s1', 'enclos', 'gpt', 'T', 100, None, 1000, 3, 300, 30, 0, 0, 0, 0.0, None, 'included'),
            # A chat from before the table: its counters alone.
            ('s2', 'cli', 'flash', None, 100, None, 1000, 1, 50, 5, 0, 0, 0, 0.01, None, 'estimated'),
        ]
        db.executemany('insert into sessions values (' + ','.join('?' * 16) + ')', rows)
        calls = [
            ('s1', 'gpt', '', 2, 200, 20, 0, 0, 2, 0.0, 0.0, 'included'),
            ('s1', 'big', '', 1, 90, 9, 0, 0, 0, 0.0, 0.0, 'included'),
            # A title the counters never see.
            ('s1', 'gpt', 'title_generation', 1, 40, 4, 0, 0, 0, 0.0, 0.0, 'included'),
        ]
        db.executemany('insert into session_model_usage values (' + ','.join('?' * 12) + ')', calls); db.commit()
        models = {m['model']: m for m in self.run_reader(0, 'default')['default']['models']}
        # gpt: its rows (240 in) and what the counters hold beyond all of s1's rows (300 - 330 -> 0).
        self.assertEqual(models['gpt']['tokens']['input'], 240)
        self.assertEqual(models['gpt']['calls'], 3)
        self.assertEqual(models['gpt']['tokens']['reasoning'], 2)
        self.assertEqual(models['big']['tokens']['input'], 90)
        self.assertEqual(models['flash']['tokens']['input'], 50)
        self.assertEqual(models['flash']['cost'], {'usd': 0.01, 'kind': 'estimated'})
        self.assertEqual(models['gpt']['chats'], 1)
        top = {c['chat']: c for c in self.run_reader_again(0)['default']['top']}
        self.assertEqual(top['s1']['tokens']['input'], 330)
        self.assertEqual(top['s1']['calls'], 4)

    def test_one_model_through_two_providers_is_two_rows_each_naming_its_provider(self):
        db = self.db('default', FULL + ', billing_provider text')
        db.execute('create table session_model_usage(session_id text, model text, task text, '
                   'billing_provider text, api_call_count integer, input_tokens integer, '
                   'output_tokens integer, cache_read_tokens integer, cache_write_tokens integer, '
                   'reasoning_tokens integer, estimated_cost_usd real, actual_cost_usd real, cost_status text)')
        rows = [
            ('s1', 'enclos', 'gpt-5.5', 'T', 100, None, 1000, 1, 100, 10, 0, 0, 0, 0.0, None, 'included', 'openai-codex'),
            ('s2', 'cli', 'gpt-5.5', None, 100, None, 1000, 1, 50, 5, 0, 0, 0, 0.1, None, 'estimated', 'openai'),
            # Hermes's empty default: not said.
            ('s3', 'cli', 'm', None, 100, None, 1000, 1, 7, 0, 0, 0, 0, 0.0, None, 'unknown', ''),
        ]
        db.executemany('insert into sessions values (' + ','.join('?' * 17) + ')', rows)
        calls = [
            ('s1', 'gpt-5.5', '', 'openai-codex', 1, 100, 10, 0, 0, 0, 0.0, 0.0, 'included'),
            # A background call whose row names no provider takes its chat's.
            ('s2', 'gpt-5.5', 'title_generation', '', 1, 4, 1, 0, 0, 0, 0.0, 0.0, None),
        ]
        db.executemany('insert into session_model_usage values (' + ','.join('?' * 13) + ')', calls); db.commit()
        models = {(m['model'], m['model_provider']): m for m in self.run_reader(0, 'default')['default']['models']}
        self.assertEqual(set(models), {('gpt-5.5', 'openai-codex'), ('gpt-5.5', 'openai'), ('m', None)})
        self.assertEqual(models[('gpt-5.5', 'openai-codex')]['tokens']['input'], 100)
        # s2: its title's row (4) and its counters beyond it (50 - 4).
        self.assertEqual(models[('gpt-5.5', 'openai')]['tokens']['input'], 50)

    def run_reader_again(self, since, *agents):
        self.out.unlink()
        return self.run_reader(since, *(agents or ('default',)))

    def test_counters_beyond_the_rows_are_counted_under_the_chats_model(self):
        db = self.db('default'); self.per_model(db)
        db.execute("insert into sessions values ('s1','cli','gpt',null,100,null,1000,5,500,50,0,0,0,0.0,null,'included')")
        db.execute("insert into session_model_usage values ('s1','gpt','',2,200,20,0,0,0,0.0,0.0,'included')"); db.commit()
        gpt = self.run_reader(0, 'default')['default']['models'][0]
        self.assertEqual((gpt['calls'], gpt['tokens']['input'], gpt['tokens']['output']), (5, 500, 50))

    def test_a_count_some_rows_lack_is_marked_at_least_and_one_no_row_has_is_null(self):
        db = self.db('default')
        db.executemany('insert into sessions values (' + ','.join('?' * 16) + ')', [
            ('s1', 'cli', 'm', None, 100, None, 1000, 1, 10, None, None, None, None, None, None, None),
            ('s2', 'cli', 'm', None, 100, None, 1000, 1, None, None, None, None, None, None, None, None),
        ]); db.commit()
        m = self.run_reader(0, 'default')['default']['models'][0]
        self.assertEqual(m['tokens']['input'], 10)
        self.assertIn('input', m['incomplete'])
        # Every row lacks output: unknown, not 0, and not "at least" either.
        self.assertIsNone(m['tokens']['output'])
        self.assertNotIn('output', m['incomplete'])
        self.assertEqual(m['cost'], {'usd': None, 'kind': 'unknown'})

    def test_a_state_db_without_sessions_or_that_is_not_one_says_why_for_that_agent_alone(self):
        (self.home / '.hermes/state.db').write_bytes(b'not a database' * 100)
        scout = usage.agent_db(str(self.home), 'scout')
        sqlite3.connect(scout).execute('create table other(x)').connection.commit()
        report = self.run_reader(0, 'default', 'scout')
        self.assertTrue(report['default']['error'].startswith('state.db: '))
        self.assertIn('no sessions table', report['scout']['error'])

    def test_an_infinite_cost_and_a_long_title_are_kept_out_of_the_report(self):
        db = self.db('default')
        db.execute("insert into sessions values ('s1','cli','m',?,100,null,1000,1,1,1,0,0,0,?,null,'estimated')",
                   ('t' * 1000, float('inf'))); db.commit()
        report = self.run_reader(0, 'default')['default']
        self.assertEqual(report['models'][0]['cost']['usd'], None)
        self.assertEqual(len(report['top'][0]['title']), usage.MAX_TEXT)

    def test_more_models_than_a_report_lists_are_summed_in_one_row(self):
        db = self.db('default')
        db.executemany('insert into sessions values (' + ','.join('?' * 16) + ')', [
            ('s%d' % i, 'cli', 'm%d' % i, None, 100, None, 1000, 1, 100 + i, 1, 0, 0, 0, 0.0, None, 'included')
            for i in range(usage.MAX_MODELS + 3)
        ]); db.commit()
        models = self.run_reader(0, 'default')['default']['models']
        self.assertEqual(len(models), usage.MAX_MODELS)
        self.assertEqual(models[-1]['model'], '4 other models')
        self.assertEqual(models[-1]['chats'], 4)
        self.assertEqual(sum(m['calls'] for m in models), usage.MAX_MODELS + 3)

    def test_a_reader_that_cannot_run_says_why_in_the_report(self):
        with mock.patch.dict(os.environ, {'HOME': str(self.home)}):
            usage.main(['-c', str(self.out), 'not a time', 'default'])
        report = json.loads(self.out.read_text())
        self.assertEqual(report['agents'], [])
        self.assertIn('ValueError', report['error'])


if __name__ == '__main__':
    unittest.main()
