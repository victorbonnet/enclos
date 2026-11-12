"""Prepare a test-only gateway token without putting its value in a launch argument."""
import json
import os
import pathlib
import secrets
import subprocess
import sys

work = pathlib.Path(sys.argv[1]).resolve()
enclos = pathlib.Path(sys.argv[2]).resolve()
home = work / 'state/sandboxes/m5openclaw/home'
folder = home.parent / 'secrets'
folder.mkdir(mode=0o700, exist_ok=True)
os.chmod(folder, 0o700)
path = folder / 'gateway.json'
with open(path, 'x', opener=lambda p, flags: os.open(p, flags, 0o600)) as out:
    json.dump({'GATEWAY_TOKEN': secrets.token_hex(32)}, out)

env = dict(os.environ, M5_WORK_DIR=str(work), ENCLOS_BIN=str(enclos))
probe = pathlib.Path(__file__).with_name('probe.sh')
settings = {
    'gateway.mode': 'local',
    'gateway.auth.mode': 'token',
    'secrets.providers.m5': {'source': 'file', 'path': str(path), 'mode': 'json'},
    'gateway.auth.token': {'source': 'file', 'provider': 'm5', 'id': '/GATEWAY_TOKEN'},
}
for key, value in settings.items():
    subprocess.run(['sh', str(probe), 'exec', 'config', 'set', key,
                    json.dumps(value), '--strict-json'], env=env, check=True)
