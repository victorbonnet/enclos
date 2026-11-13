"""Hermes's complete portable data, run only inside the sandbox.

The outer Enclos format treats this payload as opaque. Native installations,
rebuildable caches and live process state do not belong to an agent export.
"""
import io
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import sqlite3
import stat
import sys
import tarfile
import tempfile

FORMAT = 'hermes-data-v1'
REBUILDABLE = {'.venv', 'venv', '__pycache__', 'node_modules'}
RUNTIME = {'hermes-agent', 'tools', 'installs', 'cache', 'profiles', 'backups', 'state-snapshots'}
TRANSIENT = {'gateway.pid', 'gateway.lock', 'gateway_state.json', 'processes.json', 'spawn-ledger.json', 'gateway-starts.log'}
HOME_SKIP = {'.profile', '.bashrc', '.bash_profile', '.zshrc', '.hermes', '.cache', '.rustup', '.npm', '.bun', 'tmp'}
SHARED = ('auth.json', '.env', 'shared', 'pairing', 'platforms/pairing', 'plugins', 'skills')


def valid_name(name):
    return 2 <= len(name) <= 41 and name[0].islower() and name.isascii() and all(c.islower() or c.isdigit() or c == '-' for c in name)


def files_at(path, home, seen=None):
    """Materialize internal links; refuse escapes and loops rather than omit data."""
    seen = set() if seen is None else seen
    if path.is_symlink():
        real = path.resolve(strict=True)
        if home not in real.parents or real in seen:
            raise ValueError('a data link leaves the sandbox home or forms a loop')
        seen = seen | {real}
    mode = path.stat().st_mode
    if stat.S_ISDIR(mode):
        for item in sorted(path.iterdir()):
            if item.name in REBUILDABLE or item.name.endswith(('-wal', '-shm', '.pyc', '.sock', '.pid', '.lock')) or item.name in TRANSIENT:
                continue
            for rel, file in files_at(item, home, seen):
                yield Path(item.name) / rel, file
    elif stat.S_ISREG(mode):
        yield Path(), path
    elif not stat.S_ISSOCK(mode):
        raise ValueError('unsupported special file in agent data')


def add_file(archive, source, name):
    with source.open('rb') as probe: sqlite = probe.read(16) == b'SQLite format 3\0'
    if sqlite:
        # SQLite's backup includes committed WAL content; copying the main file
        # alone loses messages even after a gateway exits.
        with tempfile.TemporaryDirectory() as tmp:
            dst = Path(tmp) / 'state.db'
            with sqlite3.connect(source.as_uri() + '?mode=ro', uri=True) as src:
                with sqlite3.connect(dst) as out:
                    src.backup(out)
            archive.add(dst, arcname=name, recursive=False)
    else:
        info = archive.gettarinfo(str(source), arcname=name)
        info.type = tarfile.REGTYPE
        info.linkname = ''
        info.mode = 0o700 if source.stat().st_mode & 0o111 else 0o600
        before = source.stat()
        with source.open('rb') as stream:
            archive.addfile(info, stream)
        after = source.stat()
        if (before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_ino, after.st_size, after.st_mtime_ns):
            raise ValueError('agent data changed while being exported; stop interactive writers and retry')


def export(home, name, output):
    root = home / '.hermes'
    profile = root if name == 'default' else root / 'profiles' / name
    if profile.is_symlink() or not profile.is_dir():
        raise ValueError('agent data is missing or linked')
    selected = {}
    if name != 'default':
        for rel in SHARED:
            src = root / rel
            if src.exists():
                for child, file in files_at(src, home):
                    selected['shared/' + str(Path(rel) / child)] = file
    for item in sorted(profile.iterdir()):
        if item.name in RUNTIME or item.name in TRANSIENT or item.name in REBUILDABLE or item.name.endswith(('-wal', '-shm', '.pid', '.lock')):
            continue
        for rel, file in files_at(item, home):
            selected['profile/' + str(Path(item.name) / rel)] = file
    runtime_commands = {'hermes', 'hermes-agent', 'hermes-acp', 'uv', 'uvx'}
    if (root / 'profiles').exists():
        runtime_commands.update(p.name for p in (root / 'profiles').iterdir() if p.is_dir())
    for item in sorted(home.iterdir()):
        if item.name in HOME_SKIP or item == output or item.name.startswith('.enclos-') or item.name.startswith('.enclos-export-'):
            continue
        for rel, file in files_at(item, home):
            key = Path(item.name) / rel
            if key.parts[:2] in {('.cargo', 'registry'), ('.cargo', 'git'), ('.cargo', 'bin')} or key.parts[:2] == ('.local', 'lib') or key.parts[:3] == ('.local', 'share', 'uv') or key.parts[:2] == ('bin', 'mktemp'):
                continue
            if key.parts[:2] == ('.local', 'bin') and len(key.parts) == 3 and key.name in runtime_commands:
                continue
            selected['home/' + str(key)] = file
    meta = json.dumps({'format': FORMAT, 'home': str(home), 'profile': str(profile), 'agent': name}).encode()
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, 'wb') as raw, tarfile.open(fileobj=raw, mode='w:gz') as archive:
            info = tarfile.TarInfo('manifest.json'); info.size = len(meta); info.mode = 0o600
            archive.addfile(info, io.BytesIO(meta))
            for key, file in sorted(selected.items()):
                add_file(archive, file, key)
    except BaseException:
        output.unlink(missing_ok=True)
        raise


def restore(home, name, source, context=None):
    # Built-in data can be exported and restored as a fresh named agent. Never
    # overwrite the destination's existing built-in agent or shared credentials.
    if name == 'default':
        raise ValueError('restore the built-in agent under a fresh agent name')
    root = home / '.hermes'
    profiles = root / 'profiles'
    profiles.mkdir(parents=True, exist_ok=True)
    if profiles.is_symlink() or (profiles / name).exists() or (profiles / name).is_symlink():
        raise ValueError('destination agent already exists or is linked')
    with tempfile.TemporaryDirectory(prefix='.enclos-restore-', dir=home) as tmp:
        stage = Path(tmp)
        seen = set(); metadata = None
        with tarfile.open(source) as archive:
            for item in archive:
                path = PurePosixPath(item.name)
                if (not item.isfile() or path.is_absolute() or str(path) != item.name or '\\' in item.name
                        or any(x in {'.', '..'} for x in path.parts) or item.name in seen):
                    raise ValueError('unsafe or duplicate runtime export entry')
                seen.add(item.name)
                stream = archive.extractfile(item)
                if item.name == 'manifest.json':
                    if item.size > 65536: raise ValueError('runtime manifest too large')
                    metadata = json.load(stream)
                    continue
                if not path.parts or path.parts[0] not in {'profile', 'home', 'shared'} or len(path.parts) < 2:
                    raise ValueError('unknown runtime export entry')
                if path.parts[0] in {'profile', 'shared'} and (path.parts[1] in RUNTIME or path.parts[1] in TRANSIENT):
                    raise ValueError('runtime installation or live state in agent data')
                if path.parts[0] == 'home' and (path.parts[1] in HOME_SKIP or path.parts[1].startswith('.enclos-') or path.parts[1:3] == ('.local', 'lib') or path.parts[1:4] == ('.local', 'share', 'uv') or (path.parts[1:3] == ('.local', 'bin') and path.name in {'hermes', 'hermes-agent', 'hermes-acp', 'uv', 'uvx'}) or path.parts[1:3] == ('bin', 'mktemp')):
                    raise ValueError('runtime installation in shared data')
                dest = stage.joinpath(*path.parts); dest.parent.mkdir(parents=True, exist_ok=True)
                with dest.open('xb') as out: shutil.copyfileobj(stream, out)
                dest.chmod(0o700 if item.mode & 0o111 else 0o600)
        if not isinstance(metadata, dict) or metadata.get('format') != FORMAT:
            raise ValueError('unsupported Hermes data export')
        if any(not isinstance(metadata.get(key), str) or not metadata[key] or len(metadata[key]) > 4096 for key in ('home', 'profile', 'agent')):
            raise ValueError('invalid Hermes data manifest')
        if not valid_name(metadata['agent']) or not Path(metadata['home']).is_absolute():
            raise ValueError('invalid Hermes data manifest')
        expected_profile = Path(metadata['home']) / '.hermes'
        if metadata['agent'] != 'default': expected_profile = expected_profile / 'profiles' / metadata['agent']
        if str(expected_profile) != metadata['profile']: raise ValueError('invalid Hermes profile origin')
        profile = stage / 'profile'
        if not profile.is_dir(): raise ValueError('empty agent data')
        destination = profiles / name
        shared = stage / 'shared'
        if shared.exists():
            for file in shared.rglob('*'):
                if not file.is_file(): continue
                rel = file.relative_to(shared); dest = profile / rel
                dest.parent.mkdir(parents=True, exist_ok=True)
                if not dest.exists(): shutil.copy2(file, dest)
                elif str(rel) in {'auth.json', '.env'}:
                    # Keep both original credential files as well as the effective
                    # profile-local credentials, avoiding changes to other agents.
                    original = profile / '.enclos-shared-originals' / rel
                    original.parent.mkdir(parents=True, exist_ok=True); shutil.copy2(file, original)
                    if str(rel) == '.env':
                        dest.write_bytes(file.read_bytes() + b'\n' + dest.read_bytes())
                    else:
                        def merge(base, own):
                            if isinstance(base, dict) and isinstance(own, dict):
                                return {key: merge(base.get(key), own[key]) if key in own else value for key, value in {**base, **own}.items()}
                            return own if own not in (None, [], {}) else base
                        dest.write_text(json.dumps(merge(json.loads(file.read_text()), json.loads(dest.read_text()))))
        # Rebase runtime settings, leaving chat logs, memories, auth and plugin
        # source unchanged. Never interpret any imported value as a command here.
        for p in list(profile.rglob('*')):
            if '.enclos-shared-originals' in p.parts: continue
            if p.is_file() and p.name != 'auth.json' and (p.suffix in {'.yaml', '.yml', '.toml', '.ini', '.cfg'} or p.name == '.env') and p.stat().st_size <= 1024 * 1024:
                text = p.read_text()
                text = text.replace(metadata['profile'], str(destination)).replace(metadata['home'], str(home))
                p.write_text(text)
        extras = stage / 'home'
        context = context or {}
        # Runtime-local session routing is owned here, never by the engine.
        mappings = context.get('conversations', {})
        for dbfile in profile.rglob('*.db'):
            with sqlite3.connect(dbfile) as db:
                tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                if 'sessions' not in tables: continue
                columns = {r[1] for r in db.execute('PRAGMA table_info(sessions)')}
                for col in ('chat_id', 'session_key'):
                    if col in columns:
                        for old, new in mappings.items():
                            db.execute('UPDATE sessions SET ' + col + ' = replace(' + col + ',?,?) WHERE instr(' + col + ',?)>0', (old, new, old))
                if 'profile_name' in columns:
                    db.execute('UPDATE sessions SET profile_name=?', (name,))
        alias = home / '.local/bin' / name
        alias.parent.mkdir(parents=True, exist_ok=True)
        if alias.exists() or alias.is_symlink(): raise ValueError('destination command already exists')
        # Preserve foreign executable bytes, but keep them off this host's PATH.
        import platform
        expected = {'x86_64': 62, 'aarch64': 183, 'arm64': 183}.get(platform.machine())
        for executable in list(profile.rglob('*')) + (list(extras.rglob('*')) if extras.exists() else []):
            if not executable.is_file(): continue
            in_profile = executable.is_relative_to(profile)
            relative = executable.relative_to(profile if in_profile else extras)
            if in_profile and relative.parts[0] == '.enclos-foreign-tools': continue
            with executable.open('rb') as stream: header = stream.read(20)
            foreign = header[:4] == b'\x7fELF' and (sys.platform != 'linux' or int.from_bytes(header[18:20], 'little' if header[5] == 1 else 'big') != expected)
            if foreign:
                saved = profile / '.enclos-foreign-tools' / (relative if in_profile else Path('shared-home') / relative)
                saved.parent.mkdir(parents=True, exist_ok=True); executable.rename(saved)
        if extras.exists():
            # Preflight every shared file before publishing anything. A second
            # import may share identical resources, never overwrite other agents.
            for p in extras.rglob('*'):
                if not p.is_file(): continue
                dest = home / p.relative_to(extras)
                cursor = home
                for part in dest.relative_to(home).parts:
                    cursor = cursor / part
                    if cursor.is_symlink(): raise ValueError('linked destination shared data')
                if dest.exists() and (not dest.is_file() or dest.read_bytes() != p.read_bytes()):
                    raise ValueError('conflicting shared data; restore into a fresh sandbox')
        # Publish only after all preflight and session remapping succeeded.
        # Roll back our new shared files if publication fails; never overwrite
        # a file another import or running agent created in the meantime.
        created = []; published = False
        try:
            if extras.exists():
                for p in extras.rglob('*'):
                    if not p.is_file(): continue
                    dest = home / p.relative_to(extras)
                    if dest.exists(): continue  # identical file, checked above
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o700 if p.stat().st_mode & 0o111 else 0o600)
                    created.append(dest)
                    with os.fdopen(fd, 'wb') as out, p.open('rb') as src: shutil.copyfileobj(src, out)
            profile.rename(destination); published = True
            fd = os.open(alias, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o700)
            created.append(alias)
            with os.fdopen(fd, 'w') as out: out.write('#!/bin/sh\nexec hermes -p ' + name + ' "$@"\n')
        except BaseException:
            for p in reversed(created): p.unlink(missing_ok=True)
            if published: destination.rename(profile)
            raise



if __name__ == '__main__':
    try:
        operation, name, path, context = sys.argv[1:]
        if not valid_name(name): raise ValueError('invalid agent name')
        home = Path.home().resolve()
        if operation == 'export': export(home, name, Path(path))
        elif operation == 'import': restore(home, name, Path(path), json.loads(context))
        else: raise ValueError('unknown transfer operation')
    except Exception as error:
        # File contents (including credentials) never enter the diagnostic.
        print('Hermes transfer failed: ' + (str(error) if type(error) is ValueError else type(error).__name__), file=sys.stderr)
        sys.exit(1)
