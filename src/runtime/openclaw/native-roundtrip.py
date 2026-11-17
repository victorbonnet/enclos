"""Manual native probe, inside a sandbox with a supported private install.

    python3 -I /path/to/native-roundtrip.py

Uses only public fixture credentials. No real configuration or agents change.
"""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile

base = Path(__file__).parent
spec = importlib.util.spec_from_file_location('transfer', base / 'transfer.py')
t = importlib.util.module_from_spec(spec)
spec.loader.exec_module(t)
t.NATIVE_SOURCE = (base / 'transfer-native.mjs').read_text()
os.umask(0o077)
outer = Path.home()
prefix = outer / '.local/share/openclaw'


def fixture_home(home):
    home.mkdir()
    (home / '.local/share').mkdir(parents=True)
    (home / '.local/share/openclaw').symlink_to(prefix)


shared_writer = '''
import fs from 'node:fs';
import path from 'node:path';
import {createRequire} from 'node:module';
import {pathToFileURL} from 'node:url';
const root=path.dirname(path.dirname(fs.realpathSync(process.execPath)));
const require=createRequire(path.join(root,'lib/node_modules/openclaw/package.json'));
const auth=await import(pathToFileURL(require.resolve('openclaw/plugin-sdk/provider-auth')));
const result=await auth.updateAuthProfileStoreWithLock({stateDir:path.join(process.env.HOME,'.openclaw'),sharedStoreWrite:true,
  saveOptions:{filterExternalAuthProfiles:false,syncExternalCli:false},updater: store => {
    store.profiles['fixture-shared']={type:'api_key',provider:'openai',key:'public-shared-fixture'};
    store.profiles['fixture-priority']={type:'api_key',provider:'openai',key:'public-inherited-fixture'};
    return true;
  }});
if (!result) throw new Error('fixture shared-auth preparation failed');
'''

for agent in ['main', 'helper']:
    with tempfile.TemporaryDirectory(prefix='native-transfer-probe-', dir=outer / '.cache') as tmp:
        root = Path(tmp)
        home = root / 'home'
        fixture_home(home)
        workspace = home / '.openclaw' / ('workspace' if agent == 'main' else f'workspace-{agent}')
        t.initialize_config(home, agent, {'workspace': str(workspace)})
        workspace.mkdir()
        if agent == 'main':
            (workspace / 'MEMORY.md').write_text('native migration fixture memory\n')
            (workspace / 'uv.lock').write_text('fixture-lock\n')
        else:
            (workspace / 'empty').mkdir()
        result = subprocess.run([str(prefix / 'tools/node/bin/node'), '--input-type=module', '-e', shared_writer],
                                env=t.native_env(home), capture_output=True, timeout=120)
        assert result.returncode == 0, 'native shared-auth fixture setup refused'
        agent_dir = home / '.openclaw/agents' / agent / 'agent'
        data = home / 'fixture.json'
        binding = [f'session:{agent}:fixture-session', {'version': 1, 'state': 'cleared', 'sessionId': 'fixture-session', 'retired': True}]
        data.write_text(json.dumps({'sharedAuth': {'profiles': {}}, 'localAuth': {'profiles': {
            'fixture-priority': {'type': 'api_key', 'provider': 'openai', 'key': 'public-local-fixture'}}}, 'bindings': [binding]}))
        t.native_data(home, 'import', agent, data, agent_dir)
        data.unlink()
        archive = root / 'agent.tar.gz'
        t.export(home, agent, archive)
        home.rename(root / 'saved-source')
        fixture_home(home)
        if agent == 'helper':
            t.initialize_config(home, 'anchor', {'workspace': str(home / '.openclaw/workspace-anchor')})
            t.native(home, 'config', 'set', 'cron.enabled', 'true', '--json')
        t.restore(home, agent, archive, {'conversations': {}, 'destination_person': 'fixture-owner'})
        probe = home / 'probe.json'
        t.native_data(home, 'export', agent, probe, agent_dir)
        restored = json.loads(probe.read_text())
        assert restored['localAuth']['profiles']['fixture-shared']['key'] == 'public-shared-fixture'
        assert restored['localAuth']['profiles']['fixture-priority']['key'] == 'public-local-fixture'
        assert restored['sharedAuth']['profiles'] == {}, 'agent restoration changed shared auth'
        assert restored['bindings'] == [binding]
        if agent == 'main':
            assert (workspace / 'MEMORY.md').read_text() == 'native migration fixture memory\n'
            assert (workspace / 'uv.lock').read_text() == 'fixture-lock\n'
        else:
            assert (workspace / 'empty').is_dir()
            assert json.loads((home / '.openclaw/openclaw.json').read_text())['cron']['enabled'] is True
        expected_agents = {agent} if agent == 'main' else {'anchor', agent}
        assert {x['id'] for x in json.loads(t.native(home, 'agents', 'list', '--json'))} == expected_agents
        print(json.dumps({'agent': agent, 'native_roundtrip': True, 'auth_local': True, 'shared_auth_unchanged': True,
                          'codex_binding': True, 'workspace': True}), flush=True)
