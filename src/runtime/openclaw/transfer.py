"""OpenClaw 2026.11.3 portable agent data; runs only inside the sandbox.

Native snapshots and public native APIs own database/auth/binding writes. The
archive retains native IDs and paths: upstream offers no lossless rekey/relocate.
"""
import hashlib
from contextlib import closing
import io
import json
import os
import platform
import pty
import re
import select
from pathlib import Path, PurePosixPath
import shutil
import sqlite3
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import uuid

FORMAT = 'openclaw-data-v1'
VERSION = '2026.11.3'
MAX_BYTES = 32 * 1024**3
REBUILDABLE = {'node_modules', '__pycache__', '.venv', 'venv'}
HOME_SKIP = {'.openclaw', '.cache', '.npm', '.bun', '.rustup', '.profile', '.bashrc', '.bash_profile', '.zshrc', 'tmp'}
HELPERS = {'openclaw', 'enclos-openclaw-agent', 'enclos-openclaw-delete.mjs', 'enclos-openclaw-enable-telegram', 'uv', 'uvx'}
NATIVE_SOURCE = ''


def fail(message):
    raise ValueError(message)


def checked_name(value):
    if not isinstance(value, str) or not 2 <= len(value) <= 41 or not value[0].islower() or not value.isascii() or any(c not in 'abcdefghijklmnopqrstuvwxyz0123456789-' for c in value):
        fail('invalid OpenClaw agent id')
    return value


def checked_id(value):
    if not isinstance(value, str) or not value or len(value.encode()) > 128 or any(ord(c) < 32 or 127 <= ord(c) <= 159 for c in value):
        fail('invalid bridge identifier')
    return value


def digest(value):
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, separators=(',', ':')).encode()).hexdigest()


def relative(value, home):
    path = Path(value)
    if not path.is_absolute() or not path.is_relative_to(home) or path == home:
        fail('OpenClaw data must remain inside its sandbox home')
    return str(path.relative_to(home))


def regular_tree(root, home, prefix=Path(), skip=None, ancestors=frozenset(), directories=False):
    if skip and skip(prefix): return
    if root.is_symlink():
        root = root.resolve(strict=True)
        if not root.is_relative_to(home): fail('linked agent data leaves its sandbox home')
    if root.is_dir():
        identity = (root.stat().st_dev, root.stat().st_ino)
        if identity in ancestors: fail('linked agent data contains a directory cycle')
        if directories: yield prefix, None
        for p in sorted(root.iterdir()):
            if p.name in REBUILDABLE | {'plugin-skills'} or p.name.endswith(('-wal', '-shm', '.sock', '.pid', '.pyc')):
                continue
            # Native Codex rebuilds these installation caches for the target CPU.
            if tuple((prefix / p.name).parts[-2:]) in {('plugins', 'cache'), ('plugins', 'marketplaces'), ('skills', '.system'), ('codex-home', 'tmp')}:
                continue
            yield from regular_tree(p, home, prefix / p.name, skip, ancestors | {identity}, directories)
    elif root.is_file():
        yield prefix, root
    elif not stat.S_ISSOCK(root.stat().st_mode):
        fail('unsupported special file in OpenClaw data')


def home_skip(rel, commands):
    if not rel.parts: return False
    if rel.parts[0] in HOME_SKIP or rel.parts[0].startswith('.enclos-'): return True
    if rel.parts[:2] in {('.local', 'lib'), ('.cargo', 'registry'), ('.cargo', 'git'), ('.cargo', 'bin'), ('bin', 'mktemp')}: return True
    if rel.parts[:2] == ('.local', 'share') and len(rel.parts) >= 3 and rel.parts[2].startswith(('openclaw', 'uv')): return True
    return (len(rel.parts) == 2 and rel.parts[0] == 'bin' or len(rel.parts) == 3 and rel.parts[:2] == ('.local', 'bin')) and rel.name in commands


def no_link_ancestors(target, home):
    relative(str(target), home)
    cursor = target
    while cursor != home:
        if cursor.is_symlink(): fail('linked destination data path')
        cursor = cursor.parent


def valid_plugin_spec(spec):
    return isinstance(spec, str) and re.fullmatch(r'(?:@[a-z0-9][a-z0-9_.-]*/)?[a-z0-9][a-z0-9_.-]*@[0-9]+\.[0-9]+\.[0-9]+(?:-[a-zA-Z0-9.-]+)?', spec) is not None


def assert_snapshot_identity(folder, agent):
    manifest = json.loads((folder / 'manifest.json').read_text())
    if manifest.get('database', {}).get('role') != 'agent' or manifest['database'].get('agentId') != agent:
        fail('native snapshot belongs to a different agent')


def copy_consistent(source, destination):
    destination.parent.mkdir(parents=True, exist_ok=True)
    with source.open('rb') as stream:
        sqlite = stream.read(16) == b'SQLite format 3\0'
    if sqlite:
        with closing(sqlite3.connect(source.as_uri() + '?mode=ro', uri=True)) as src, closing(sqlite3.connect(destination)) as dst:
            src.backup(dst)
    else:
        before = source.stat()
        shutil.copyfile(source, destination)
        after = source.stat()
        if (before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_ino, after.st_size, after.st_mtime_ns):
            fail('agent data changed during export; stop interactive writers and retry')
    destination.chmod(0o700 if source.stat().st_mode & 0o111 else 0o600)


def equal_files(first, second):
    if first.stat().st_size != second.stat().st_size: return False
    with first.open('rb') as a, second.open('rb') as b:
        while chunk := a.read(1024**2):
            if chunk != b.read(len(chunk)): return False
    return True


def terminal_command(command, env, timeout=600):
    # The pinned CLI requires a terminal before honoring global --yes for
    # npm provenance consent. Keep install mode (no --force/update), so its
    # native installer still refuses a concurrently created target plugin.
    master, slave = pty.openpty()
    output = bytearray(); deadline = time.monotonic() + timeout
    try:
        with subprocess.Popen(command, stdin=slave, stdout=slave, stderr=slave, env=env) as child:
            os.close(slave); slave = None
            try:
                while child.poll() is None or select.select([master], [], [], 0)[0]:
                    if time.monotonic() > deadline: raise subprocess.TimeoutExpired(command, timeout)
                    if not select.select([master], [], [], 0.1)[0]: continue
                    try: chunk = os.read(master, 8192)
                    except OSError: break  # The terminal slave closed.
                    if not chunk: break
                    output.extend(chunk[:max(0, 65536 - len(output))])
                child.wait(timeout=max(0.1, deadline - time.monotonic()))
            except BaseException:
                child.kill(); child.wait(); raise
            return subprocess.CompletedProcess(command, child.returncode, bytes(output), b'')
    finally:
        os.close(master)
        if slave is not None: os.close(slave)


def native(home, *args, terminal=False):
    command = [str(home / '.local/share/openclaw/bin/openclaw'), *args]
    result = terminal_command(command, native_env(home)) if terminal else subprocess.run(command, capture_output=True, env=native_env(home), timeout=600)
    if result.returncode:
        fd, diagnostic = tempfile.mkstemp(prefix='.enclos-native-transfer-error-', suffix='.log', dir=home)
        with os.fdopen(fd, 'wb') as out: out.write((result.stderr + result.stdout)[:65536])
        fail('native OpenClaw command refused the transfer; private diagnostic: ' + diagnostic)
    return result.stdout


def native_env(home):
    return {**os.environ, 'HOME': str(home), 'OPENCLAW_HOME': str(home), 'OPENCLAW_STATE_DIR': str(home / '.openclaw'),
            'OPENCLAW_CONFIG_PATH': str(home / '.openclaw/openclaw.json'), 'OPENCLAW_VERSION': VERSION,
            'OPENCLAW_NO_RESPAWN': '1', 'OPENCLAW_LOAD_SHELL_ENV': '0', 'OPENCLAW_EXEC_SHELL_SNAPSHOT': '0',
            'OPENCLAW_SUPERVISOR_MODE': 'external', 'OPENCLAW_SERVICE_REPAIR_POLICY': 'external',
            'ENCLOS_OPENCLAW_TRANSFER': '1'}


def initialize_config(home, agent, entry):
    # Author only a new native config. Existing config and native
    # ownership are never replaced; subsequent changes use the native CLI.
    file = home / '.openclaw/openclaw.json'
    file.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if not file.exists():
        fd = os.open(file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as out:
            json.dump({'agents': {'ownership': 'explicit', 'entries': {agent: entry}},
                       'cron': {'enabled': False}, 'hooks': {'enabled': False}}, out)


def native_data(home, operation, agent, file, agent_dir, credential_files=None):
    result = subprocess.run([str(home / '.local/share/openclaw/tools/node/bin/node'), '--input-type=module', '-e', NATIVE_SOURCE,
                             operation, agent, str(file), str(agent_dir), json.dumps(credential_files or {})], env=native_env(home), capture_output=True, timeout=240)
    if result.returncode:
        error = file.with_name(file.name + '.error')
        if error.is_file():
            fd, diagnostic = tempfile.mkstemp(prefix='.enclos-native-transfer-error-', suffix='.log', dir=home)
            with os.fdopen(fd, 'wb') as out: out.write(error.read_bytes()[:65536])
            fail('native OpenClaw transfer refused; private diagnostic: ' + diagnostic)
        fail('native OpenClaw credentials or binding transfer refused; no native ownership guard was bypassed')


def assert_idle_database(file):
    with sqlite3.connect(file.as_uri() + '?mode=ro', uri=True) as db:
        tables = {r[0] for r in db.execute("select name from sqlite_master where type='table'")}
        if 'session_nodes' not in tables:
            fail('native agent snapshot has no session catalog')
        for row in db.execute('select entry_json from session_nodes'):
            entry = json.loads(row[0])
            terminal = entry.get('restartRecoveryTerminalRunIds', [])
            recovery_runs = any(run.get('runId') not in terminal for run in entry.get('restartRecoveryRuns', []))
            if recovery_runs or entry.get('restartRecoveryDeliveryRunId') or entry.get('status') in {'running', 'queued'} or any(entry.get(k) for k in (
                    'mainRestartRecovery', 'pendingFinalDelivery', 'initializationPending',
                    'restartRecoveryBeforeAgentReplyState', 'restartRecoveryDeliveryReceiptState',
                    'restartRecoveryHarnessCompletion', 'subagentRecovery')):
                fail('OpenClaw has unresolved execution or delivery state; finish or stop its turns before exporting')
        if 'session_pending_inputs' in tables and db.execute("select 1 from session_pending_inputs where consumed_event_id is null and state in ('queued','interrupted') limit 1").fetchone():
            fail('OpenClaw has pending input; finish or cancel it before exporting')


def assert_idle_codex(agent_dir):
    # These native background queues are separate from OpenClaw's session
    # recovery. This format refuses their work rather than editing it away.
    for name, tables in [('queue_1.sqlite', ['queued_items']),
                         ('goals_1.sqlite', ['thread_goals', 'thread_goal_continuation_deferrals'])]:
        file = agent_dir / 'codex-home' / name
        if not file.exists(): continue
        with closing(sqlite3.connect(file.as_uri() + '?mode=ro', uri=True)) as db:
            for table in tables:
                if db.execute('select 1 from ' + table + ' limit 1').fetchone():
                    fail('Codex has persisted queue or goal state requiring a supported native export')


def projected_config(config, agent):
    defaults = dict(config.get('agents', {}).get('defaults', {}))
    defaults.pop('workspace', None); defaults.pop('systemAgent', None)
    if config.get('session', {}).get('store'):
        fail('custom shared native session stores need a supported ownership export')
    own = dict(config['agents']['entries'][agent])
    assert_local_codex(config, own)
    shared = {k: config[k] for k in ['tools', 'skills', 'models', 'messages', 'commands', 'session'] if k in config}
    shared['plugins'] = {'entries': {k: v for k, v in config.get('plugins', {}).get('entries', {}).items() if k != 'enclos'}}
    if defaults: shared['agents'] = {'defaults': defaults}
    if config.get('auth'): shared['auth'] = config['auth']
    # Shared schedulers, external messaging bindings and hooks are host-owned.
    # Restore their source configuration as reference only, never executable work.
    return own, shared


def assert_local_codex(config, own):
    codex = config.get('plugins', {}).get('entries', {}).get('codex', {}).get('config', {}).get('appServer', {})
    if codex.get('homeScope', 'agent') != 'agent' or codex.get('transport', 'stdio') != 'stdio' or any(
            codex.get(k) for k in ['url', 'command', 'args', 'remoteWorkspaceRoot', 'nativeHookRelay']):
        fail('external or user-scoped Codex state needs a supported native export')
    runtime = own.get('runtime', config.get('agents', {}).get('defaults', {}).get('runtime', {}))
    if runtime.get('type', 'native') != 'native':
        fail('external agent harness state needs a supported native export')


def plugin_spec(inspection):
    plugin, install = inspection['plugin'], inspection.get('install') or {}
    name, version = plugin.get('packageName'), plugin.get('packageVersion') or plugin.get('version')
    spec = f'{name}@{version}'
    if not valid_plugin_spec(spec): fail('native plugin has no exact package identity')
    if plugin.get('origin') != 'bundled' and (install.get('source') != 'npm' or install.get('resolvedName') != name or install.get('resolvedVersion') != version):
        fail('native plugin does not have verified exact npm provenance')
    return spec


def missing_plugins(inspections, wanted):
    installed = {x['plugin']['id']: x for x in inspections}
    missing = []
    for plugin in wanted:
        current = installed.get(plugin['id'])
        if current is None: missing.append(plugin['spec'])
        elif plugin_spec(current) != plugin['spec']: fail('conflicting destination native plugin version')
    return missing


def merge_shared(target, source):
    for key, value in source.items():
        if key not in target: target[key] = value
        elif isinstance(target[key], dict) and isinstance(value, dict): merge_shared(target[key], value)
        elif target[key] != value: fail('conflicting destination runtime settings; use a fresh matching sandbox')
    return target


def validate_manifest(meta, home, agent):
    fields = {'format', 'version', 'home', 'agent', 'snapshot', 'workspace', 'agent_config', 'shared_config',
              'plugins', 'routes', 'sharedAuth', 'localAuth', 'bindings', 'legacy_bindings', 'host_reference'}
    if not isinstance(meta, dict) or set(meta) != fields: fail('invalid OpenClaw export manifest')
    if meta['format'] != FORMAT or meta['version'] != VERSION: fail('unsupported OpenClaw data format or version')
    if meta['agent'] != agent: fail('OpenClaw native data currently retains its original agent id')
    if meta['home'] != str(home): fail('OpenClaw Codex continuation currently requires the same internal sandbox home path')
    if not isinstance(meta['snapshot'], str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,199}', meta['snapshot']): fail('invalid native snapshot reference')
    for key in ['agent_config', 'shared_config', 'routes', 'sharedAuth', 'localAuth', 'host_reference']:
        if not isinstance(meta[key], dict): fail('invalid OpenClaw export manifest section')
    if set(meta['shared_config']) - {'tools', 'skills', 'models', 'messages', 'commands', 'session', 'plugins', 'agents', 'auth'}:
        fail('host-owned configuration in agent export')
    if set(meta['shared_config'].get('agents', {})) - {'defaults'} or set(meta['shared_config'].get('plugins', {})) - {'entries'}:
        fail('foreign runtime ownership in agent export')
    if 'enclos' in meta['shared_config'].get('plugins', {}).get('entries', {}): fail('source app plugin configuration in export')
    if meta['shared_config'].get('session', {}).get('store'): fail('unsupported shared native session store')
    for key in ['sharedAuth', 'localAuth']:
        if not isinstance(meta[key].get('profiles'), dict): fail('invalid native credential data')
    if not isinstance(meta['bindings'], list) or len(meta['bindings']) > 50000: fail('invalid native bindings')
    if not isinstance(meta['legacy_bindings'], list) or len(meta['legacy_bindings']) > 50000: fail('invalid legacy native binding references')
    for record in meta['legacy_bindings']:
        if not isinstance(record, dict) or set(record) != {'key', 'value', 'rollout'} or not isinstance(record['key'], str) or not record['key'].startswith('conversation:') or not isinstance(record['value'], dict): fail('invalid legacy native binding reference')
        rollout = PurePosixPath(record['rollout'])
        if rollout.is_absolute() or any(x in {'.', '..'} for x in rollout.parts) or rollout.parts[:2] not in {('codex-home', 'sessions'), ('codex-home', 'archived_sessions')}: fail('invalid captured legacy rollout')
    keys = set()
    for binding in meta['bindings']:
        if not isinstance(binding, list) or len(binding) != 2 or not isinstance(binding[0], str) or not isinstance(binding[1], dict) or binding[0] in keys:
            fail('invalid or duplicate native binding')
        if not binding[0].startswith((f'session-key:{agent}:', f'session:{agent}:')): fail('foreign native binding')
        keys.add(binding[0])
    if not isinstance(meta['plugins'], list): fail('invalid native plugin declarations')
    for plugin in meta['plugins']:
        if not isinstance(plugin, dict) or set(plugin) != {'id', 'spec'} or not isinstance(plugin['id'], str) or not valid_plugin_spec(plugin['spec']): fail('invalid native plugin reference')
    if not isinstance(meta['workspace'], str) or not meta['workspace']: fail('invalid native workspace path')


def imported_routes(routes, mapping, person, agent):
    output = {}
    for old, route in routes.items():
        checked_id(old)
        if not isinstance(route, dict): fail('invalid native channel route')
        if old not in mapping: continue  # Shared/group history is not transferred.
        if not person: fail('pair the destination host before restoring channel routes')
        checked_id(person); new = checked_id(mapping[old])
        origin = route.get('origin') or {'v': 1, 'conversation': old, 'person': route.get('person')}
        if origin.get('v') != 1: fail('unsupported imported route provenance')
        source = checked_id(origin['conversation'])
        expected = digest(['enclos-home', agent, agent, source]) if route.get('kind') == 'home' else digest([source, checked_id(origin.get('person'))])
        if route.get('peer') != expected: fail('invalid native channel route provenance')
        output[new] = {**route, 'person': person, 'origin': origin}
    return {'v': 1, 'routes': output, 'outbox': [], 'receipts': {}}


class LimitedOutput:
    def __init__(self, stream, limit): self.stream, self.limit, self.size = stream, limit, 0
    def write(self, data):
        if self.size + len(data) > self.limit: fail('runtime export exceeds its size limit')
        size = self.stream.write(data); self.size += size; return size
    def flush(self): self.stream.flush()
    def tell(self): return self.size


def write_archive(data, output, limit):
    entries = sorted(data.rglob('*'))
    if sum(p.stat().st_size for p in entries if p.is_file()) > limit: fail('unpacked agent data exceeds its limit')
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, 'wb') as stream, tarfile.open(fileobj=LimitedOutput(stream, limit), mode='w:gz') as archive:
            for p in entries: archive.add(p, arcname=str(p.relative_to(data)), recursive=False)
    except BaseException:
        output.unlink(missing_ok=True); raise


def preserve_adjacent_files(agent_dir, home, destination):
    # A fresh generation keeps references from an earlier import intact.
    generation = uuid.uuid4().hex
    for item in sorted(agent_dir.parent.iterdir()):
        if item == agent_dir: continue
        for rel, file in regular_tree(item, home, Path(item.name), directories=True):
            target = destination / 'enclos-source-agent-files' / generation / rel
            if file is None: target.mkdir(parents=True, exist_ok=True)
            else: copy_consistent(file, target)


def export(home, agent, output, limit=MAX_BYTES, credential_files=None):
    checked_name(agent)
    with tempfile.TemporaryDirectory(prefix='.enclos-openclaw-export-', dir=home) as tmp:
        stage = Path(tmp); data = stage / 'data'; data.mkdir()
        agent_dir = home / '.openclaw/agents' / agent / 'agent'
        bundle = stage / 'native.json'; native_data(home, 'export', agent, bundle, agent_dir, credential_files)
        meta = json.loads(bundle.read_text()); cfg = meta['config']
        own = cfg.get('agents', {}).get('entries', {}).get(agent)
        if not isinstance(own, dict): fail('native agent is missing from the explicit roster')
        agent_dir = Path(own.get('agentDir', str(agent_dir)))
        if relative(str(agent_dir), home) != f'.openclaw/agents/{agent}/agent':
            fail('custom native agent directories are not supported for portable data')
        assert_idle_codex(agent_dir)
        workspace = Path(own.get('workspace', cfg.get('agents', {}).get('defaults', {}).get('workspace', '')))
        workspace_rel = relative(str(workspace), home)
        if not workspace.is_dir(): fail('agent workspace is missing')
        own, shared = projected_config(cfg, agent)
        inspections = json.loads(native(home, 'plugins', 'inspect', '--all', '--json'))
        plugins = []
        for inspection in inspections:
            plugin = inspection['plugin']
            if not plugin.get('enabled') or plugin['id'] == 'enclos' or plugin.get('origin') == 'bundled': continue
            plugins.append({'id': plugin['id'], 'spec': plugin_spec(inspection)})
        repository = stage / 'repository'
        native(home, 'backup', 'sqlite', 'create', '--agent', agent, '--repository', str(repository), '--json')
        snapshots = [p for p in repository.iterdir() if p.is_dir()]
        if len(snapshots) != 1: fail('native snapshot was not uniquely confirmed')
        snapshot = snapshots[0]; assert_snapshot_identity(snapshot, agent); assert_idle_database(snapshot / 'database.sqlite')
        shutil.copytree(snapshot, data / 'snapshot' / snapshot.name)
        for label, root in [('agent', agent_dir), ('workspace', workspace), ('shared-skills', home / '.openclaw/skills')]:
            if not root.exists(): continue
            for rel, file in regular_tree(root, home, directories=True):
                if label == 'agent' and str(rel) == 'openclaw-agent.sqlite': continue
                if file is None: (data / label / rel).mkdir(parents=True, exist_ok=True)
                else: copy_consistent(file, data / label / rel)
        # Native snapshots carry current session history. Adjacent old
        # sessions/import archives are retained as data outside native
        # discovery paths so a destination cannot re-ingest old work.
        preserve_adjacent_files(agent_dir, home, data / 'agent')
        commands = HELPERS | set(meta['agentNames'])
        for item in sorted(home.iterdir()):
            if item == output: continue
            for rel, file in regular_tree(item, home, Path(item.name), lambda rel: home_skip(rel, commands), directories=True):
                if file is None: (data / 'home' / rel).mkdir(parents=True, exist_ok=True)
                else: copy_consistent(file, data / 'home' / rel)
        state = home / '.enclos-app/openclaw-state' / agent / 'state.json'
        routes = json.loads(state.read_text()).get('routes', {}) if state.exists() else {}
        manifest = {'format': FORMAT, 'version': VERSION, 'home': str(home), 'agent': agent, 'snapshot': snapshot.name,
                    'workspace': workspace_rel, 'agent_config': own, 'shared_config': shared,
                    'plugins': plugins, 'routes': routes, 'sharedAuth': meta['sharedAuth'], 'localAuth': meta['localAuth'],
                    'bindings': meta['bindings'], 'legacy_bindings': meta['legacyBindings'], 'host_reference': {'channels': sorted(cfg.get('channels', {})), 'bindings': [b for b in cfg.get('bindings', []) if b.get('agentId') == agent], 'cron_enabled': cfg.get('cron', {}).get('enabled'), 'hooks_enabled': cfg.get('hooks', {}).get('enabled')}}
        text = json.dumps(manifest)
        if len(text.encode()) > 4 * 1024**2: fail('runtime manifest is too large')
        (data / 'manifest.json').write_text(text); (data / 'manifest.json').chmod(0o600)
        write_archive(data, output, limit)


def extract(source, destination, limit=MAX_BYTES):
    total = 0; seen = set()
    with tarfile.open(source) as archive:
        for entry in archive:
            p = PurePosixPath(entry.name)
            if not (entry.isfile() or entry.isdir() and entry.size == 0) or not p.parts or p.is_absolute() or str(p) != entry.name or '\\' in entry.name or any(x in {'.', '..'} for x in p.parts) or entry.name in seen:
                fail('unsafe or duplicate OpenClaw export entry')
            seen.add(entry.name); total += entry.size
            if total > limit or entry.size < 0: fail('unpacked agent data exceeds its limit')
            if p.parts[0] == 'home' and (len(p.parts) < 2 and not entry.isdir() or home_skip(Path(*p.parts[1:]), HELPERS)): fail('runtime or control data in shared home archive')
            if p.parts[0] == 'agent' and (len(p.parts) < 2 and not entry.isdir() or len(p.parts) >= 2 and p.parts[1] == 'openclaw-agent.sqlite' or p.parts[-1].endswith(('-wal', '-shm', '.sock', '.pid'))): fail('live native state in agent archive')
            if p.parts[0] not in {'manifest.json', 'snapshot', 'agent', 'workspace', 'shared-skills', 'home'}: fail('unknown runtime export entry')
            if entry.name == 'manifest.json' and entry.size > 4 * 1024**2: fail('runtime manifest is too large')
            target = destination.joinpath(*p.parts); target.parent.mkdir(parents=True, exist_ok=True)
            if entry.isdir():
                if p.parts[0] == 'manifest.json': fail('runtime manifest is not a regular file')
                target.mkdir(exist_ok=True, mode=0o700); continue
            with target.open('xb') as out: shutil.copyfileobj(archive.extractfile(entry), out)
            target.chmod(0o700 if entry.mode & 0o111 else 0o600)
    return json.loads((destination / 'manifest.json').read_text())


def restore(home, agent, source, context):
    checked_name(agent)
    with tempfile.TemporaryDirectory(prefix='.enclos-openclaw-import-', dir=home) as tmp:
        stage = Path(tmp); meta = extract(source, stage)
        validate_manifest(meta, home, agent)
        for record in meta['legacy_bindings']:
            if not (stage / 'agent' / record['rollout']).is_file(): fail('legacy native rollout bytes are missing')
        assert_idle_codex(stage / 'agent')
        workspace_rel = PurePosixPath(meta['workspace'])
        if workspace_rel.is_absolute() or any(p in {'.', '..'} for p in workspace_rel.parts): fail('invalid native workspace path')
        workspace = home.joinpath(*workspace_rel.parts); relative(str(workspace), home)
        if workspace_rel.parts[0].startswith('.enclos-') or home_skip(Path(*workspace_rel.parts), HELPERS) and workspace_rel.parts[0] != '.openclaw': fail('workspace collides with runtime control paths')
        if workspace_rel.parts[:2] in {('.openclaw', 'agents'), ('.openclaw', 'state'), ('.openclaw', 'npm'), ('.openclaw', 'plugins'), ('.openclaw', 'node-runtime')}: fail('workspace collides with native control data')
        no_link_ancestors(workspace, home)
        agent_dir = home / '.openclaw/agents' / agent / 'agent'
        no_link_ancestors(agent_dir, home)
        if agent_dir.exists() or agent_dir.is_symlink() or workspace.exists() or workspace.is_symlink(): fail('destination agent or workspace already exists')
        cfg_path = home / '.openclaw/openclaw.json'
        cfg = json.loads(cfg_path.read_text()) if cfg_path.exists() else {}
        if agent in cfg.get('agents', {}).get('entries', {}): fail('destination native agent already exists')
        projected = {key: cfg.get(key, {}) for key in meta['shared_config']}
        # The destination's system agent selection is not imported authority.
        if 'agents' in projected: projected['agents'] = {'defaults': {k: v for k, v in projected['agents'].get('defaults', {}).items() if k not in {'workspace', 'systemAgent'}}}
        merge_shared(projected, meta['shared_config'])
        assert_local_codex({**cfg, **projected}, meta['agent_config'])
        routes = imported_routes(meta['routes'], context.get('conversations', {}), context.get('destination_person'), agent)
        extras = stage / 'home'
        shared = stage / 'shared-skills'
        if shared.exists():
            for file in shared.rglob('*'):
                destination = extras / '.openclaw/skills' / file.relative_to(shared)
                if file.is_dir(): destination.mkdir(parents=True, exist_ok=True)
                else: copy_consistent(file, destination)
        if extras.exists():
            commands = HELPERS | set(cfg.get('agents', {}).get('entries', {})) | {agent}
            for file in extras.rglob('*'):
                rel = file.relative_to(extras)
                if home_skip(rel, commands) and rel.parts[:2] != ('.openclaw', 'skills'): fail('runtime command in shared user data')
                destination = home / rel
                no_link_ancestors(destination, home)
                if destination.exists() and (file.is_dir() != destination.is_dir() or file.is_file() and not equal_files(destination, file)): fail('conflicting shared user data at destination')
        snapshot = stage / 'snapshot' / meta['snapshot']
        assert_snapshot_identity(snapshot, agent)
        assert_idle_database(snapshot / 'database.sqlite')
        entry = {**meta['agent_config'], 'agentDir': str(agent_dir), 'workspace': str(workspace)}
        initialize_config(home, agent, entry)
        native(home, 'backup', 'sqlite', 'verify', str(snapshot), '--json')
        native_data(home, 'prepare', agent, stage / 'native-prepare.json', agent_dir)
        inspections = json.loads(native(home, 'plugins', 'inspect', '--all', '--json'))
        for spec in missing_plugins(inspections, meta['plugins']):
            native(home, '--yes', 'plugins', 'install', spec, '--pin', '--no-enable', terminal=True)
        # Foreign user executables are data, not runnable target installations.
        expected = {'x86_64': 62, 'aarch64': 183, 'arm64': 183}.get(platform.machine())
        for tree in ['agent', 'workspace', 'home', 'shared-skills']:
            root = stage / tree
            if not root.exists(): continue
            for executable in list(root.rglob('*')):
                if not executable.is_file(): continue
                with executable.open('rb') as f: header = f.read(20)
                if len(header) >= 20 and header[:4] == b'\x7fELF' and (sys.platform != 'linux' or int.from_bytes(header[18:20], 'little' if header[5] == 1 else 'big') != expected):
                    saved = stage / 'agent/enclos-foreign-executables' / tree / executable.relative_to(root)
                    saved.parent.mkdir(parents=True, exist_ok=True); executable.rename(saved)
        # Publish new agent-owned paths only. No existing destination data is replaced.
        agent_dir.parent.mkdir(parents=True, exist_ok=True)
        if (stage / 'agent').exists(): shutil.copytree(stage / 'agent', agent_dir)
        else: agent_dir.mkdir()
        native(home, 'backup', 'sqlite', 'restore', str(snapshot), '--target', str(agent_dir / 'openclaw-agent.sqlite'), '--json')
        if not (stage / 'workspace').is_dir(): fail('agent export has no workspace')
        workspace.parent.mkdir(parents=True, exist_ok=True); shutil.copytree(stage / 'workspace', workspace)
        if extras.exists():
            for file in extras.rglob('*'):
                destination = home / file.relative_to(extras)
                if file.is_dir(): destination.mkdir(parents=True, exist_ok=True)
                elif not destination.exists(): copy_consistent(file, destination)
        patch = {**projected, 'agents': {**projected.get('agents', {}), 'ownership': 'explicit',
            'entries': {agent: entry}}}
        # Source host messaging/schedules are omitted. Existing destination
        # switches stay unchanged; only a newly authored config disables them.
        file = stage / 'config-patch.json'; file.write_text(json.dumps(patch)); file.chmod(0o600)
        native(home, 'config', 'patch', '--file', str(file))
        data_file = stage / 'native-import.json'; data_file.write_text(json.dumps(meta)); data_file.chmod(0o600)
        native_data(home, 'import', agent, data_file, agent_dir)
        folder = home / '.enclos-app/openclaw-state' / agent
        folder.mkdir(parents=True, exist_ok=True, mode=0o700)
        target = folder / 'state.json'
        if target.exists() or target.is_symlink(): fail('destination channel state already exists')
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as out: json.dump(routes, out)
        (agent_dir / 'enclos-source-host-reference.json').write_text(json.dumps(meta['host_reference']))
        if meta['legacy_bindings']:
            # Preserve unrouted historical data without publishing native
            # conversation ownership, rewriting paths or reactivating work.
            with (agent_dir / f'enclos-legacy-codex-bindings-{uuid.uuid4().hex}.json').open('x') as reference:
                json.dump(meta['legacy_bindings'], reference)
        native(home, 'skills', 'list', '--agent', agent, '--json')


if __name__ == '__main__':
    try:
        NATIVE_SOURCE, operation, name, file, context = sys.argv[1:]
        os.umask(0o077)
        home = Path.home().resolve(); context = json.loads(context)
        if operation == 'export': export(home, name, Path(file), context.get('max_bytes', MAX_BYTES), context.get('credential_files'))
        elif operation == 'import': restore(home, name, Path(file), context)
        else: fail('unknown transfer operation')
    except Exception as error:
        print('OpenClaw transfer failed: ' + (str(error) if type(error) is ValueError else type(error).__name__), file=sys.stderr)
        sys.exit(1)
