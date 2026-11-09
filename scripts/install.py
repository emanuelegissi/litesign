#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Per-user installation; invoked by install.sh or uninstall.sh."""
import sys

if sys.version_info < (3, 11):
    raise SystemExit("LiteSign installation requires Python 3.11 or later.")

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
import subprocess
import tempfile
import tomllib
from uuid import uuid4


NAMES = ('Sign as pdf', 'Sign as p7m', 'Extract p7m')
APP_ID = 'litesign-user-install-v1'
SOURCE = Path(__file__).resolve().parent.parent


def xdg_path(name, default):
    value = Path(os.environ.get(name) or default).expanduser()
    return value if value.is_absolute() else Path(default)


class Layout:
    def __init__(self):
        data = xdg_path('XDG_DATA_HOME', Path.home() / '.local/share')
        config = xdg_path('XDG_CONFIG_HOME', Path.home() / '.config')
        self.root = data / 'litesign'
        self.config = config / 'litesign/config.toml'
        self.manifest = self.root / 'install.json'
        self.current = self.root / 'current'
        self.releases = self.root / 'releases'
        self.files = {'launcher': Path.home() / '.local/bin/litesign'}
        self.files.update({name: data / 'nautilus/scripts' / name for name in NAMES})


def digest(content):
    return hashlib.sha256(content).hexdigest()


def snapshot(path):
    if path.is_symlink():
        raise RuntimeError(f'Refusing a symlink: {path}')
    if not path.exists():
        return None
    if not path.is_file():
        raise RuntimeError(f'Expected a regular file: {path}')
    return path.read_bytes(), stat.S_IMODE(path.stat().st_mode) & 0o777


def publish(path, content, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix='.litesign-', delete=False) as output:
            temporary = Path(output.name)
            os.fchmod(output.fileno(), mode)
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        if path.is_symlink():
            raise RuntimeError(f'Refusing a symlink: {path}')
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def load_manifest(layout):
    if layout.root.is_symlink() or layout.releases.is_symlink():
        raise RuntimeError('The LiteSign application directory must not be a symlink.')
    if not layout.root.exists():
        return None
    stored = snapshot(layout.manifest)
    if stored is None:
        raise RuntimeError(f'Refusing an unowned application directory: {layout.root}')
    record = json.loads(stored[0])
    releases = record.get('releases', [])
    if (record.get('application') != APP_ID or not releases or
            any(not isinstance(name, str) or not re.fullmatch(r'[0-9a-f]{32}', name) for name in releases) or
            record.get('current') not in releases or set(record.get('files', {})) != set(layout.files)):
        raise RuntimeError('Invalid LiteSign installation manifest.')
    return record


def check_destinations(layout, record):
    for name, path in layout.files.items():
        existing = snapshot(path)
        if existing is not None and (record is None or digest(existing[0]) != record['files'][name]):
            raise RuntimeError(f'Refusing to replace an unrelated or modified file: {path}')
    if layout.current.is_symlink():
        if record is None or os.readlink(layout.current) != 'releases/' + record['current']:
            raise RuntimeError('The installed current link has been modified.')
    elif layout.current.exists():
        raise RuntimeError('The installed current path is not a managed symlink.')


def choose_module(config):
    existing = snapshot(config)
    content = existing[0].decode('utf-8') if existing else ''
    document = tomllib.loads(content)
    smartcard = document.get('smartcard', {})
    if not isinstance(smartcard, dict) or not isinstance(smartcard.get('module', ''), str):
        raise RuntimeError('Existing [smartcard].module must be a path string.')
    default = smartcard.get('module', '').strip()
    if default:
        default = str((config.parent / Path(default).expanduser()).absolute())
    entered = input(f'Smartcard PKCS#11 module{f" [{default}]" if default else ""}: ').strip()
    value = entered or default
    if not value:
        raise RuntimeError('A smartcard module path is required.')
    module = Path(value).expanduser().absolute()
    if not module.is_file():
        raise RuntimeError(f'The smartcard module is not a regular file: {module}')
    with module.open('rb'):
        pass
    return module, existing


def build_release(release):
    # The venv stays at this permanent path: moving a venv breaks its shebangs.
    release.mkdir(parents=True)
    for name in ('litesign.py', 'requirements.txt', 'README.md',
                 'LICENSE', 'install.sh', 'uninstall.sh'):
        shutil.copy2(SOURCE / name, release / name)
    (release / 'assets').mkdir()
    shutil.copy2(SOURCE / 'assets/icon.png', release / 'assets/icon.png')
    shutil.copytree(SOURCE / 'scripts', release / 'scripts', ignore=shutil.ignore_patterns('__pycache__'))
    subprocess.run([sys.executable, '-m', 'venv', str(release / '.venv')], check=True)
    python = release / '.venv/bin/python'
    subprocess.run([str(python), '-m', 'pip', 'install', '-r', str(release / 'requirements.txt')], check=True)
    subprocess.run([str(python), '-c', 'import asn1crypto, pyhanko, pkcs11, PIL, keyring, tomlkit'], check=True)
    return python


def prepare_config(python, module, existing):
    # TOMLKit is installed only in the application venv, never in system Python.
    code = '''import sys, tomlkit
from litesign import DEFAULT_CONFIG
document = tomlkit.parse(sys.stdin.read() or DEFAULT_CONFIG)
if "smartcard" not in document:
    document["smartcard"] = tomlkit.table()
document["smartcard"]["module"] = sys.argv[1]
sys.stdout.write(tomlkit.dumps(document))
'''
    result = subprocess.run([str(python), '-c', code, str(module)], cwd=python.parent.parent.parent,
                            input=existing[0].decode('utf-8') if existing else '',
                            text=True, capture_output=True, check=True)
    return result.stdout.encode('utf-8')


def check_tools():
    for name in ('bash',):
        if not shutil.which(name):
            raise RuntimeError(f'Required command not found: {name}')
    for name in ('systemd-ask-password', 'notify-send', 'openssl', 'gs'):
        if not shutil.which(name):
            print(f'Warning: {name} is not installed.', file=sys.stderr)
    print('CAdES requires OpenSSL 3 and pkcs11-provider. Install system packages with your distribution tools.')
    print('Nautilus PIN entry requires systemd 257+ and a running per-user password agent.')
    print('PDF raster recovery requires Ghostscript (gs).')


def install(layout):
    record = load_manifest(layout)
    check_destinations(layout, record)
    expected = {path: snapshot(path) for path in (*layout.files.values(), layout.manifest)}
    module, old_config = choose_module(layout.config)
    check_tools()
    release = layout.releases / uuid4().hex
    written = []
    link_changed = False
    old_link = os.readlink(layout.current) if layout.current.is_symlink() else None
    link_temp = layout.root / ('.current-' + release.name)
    try:
        python = build_release(release)
        config = prepare_config(python, module, old_config)
        runner = shlex.quote(str(layout.current / 'scripts/nautilus-run.sh'))
        launcher = ('#!/usr/bin/env bash\n# Installed by LiteSign.\nexec ' +
                    shlex.quote(str(layout.current / '.venv/bin/python')) + ' ' +
                    shlex.quote(str(layout.current / 'litesign.py')) + ' "$@"\n').encode()
        files = {'launcher': launcher}
        for name in NAMES:
            template = (release / 'scripts/nautilus' / name).read_text()
            files[name] = template.replace('@NAUTILUS_RUNNER@', runner).encode()
        check_destinations(layout, record)
        if snapshot(layout.config) != old_config:
            raise RuntimeError('Configuration changed during installation; retry to preserve your edits.')
        expected[layout.config] = old_config
        if snapshot(layout.manifest) != expected[layout.manifest]:
            raise RuntimeError("Another installation changed the manifest; retry.")
        changes = [(layout.config, config, old_config[1] if old_config else 0o600)]
        changes.extend((layout.files[name], content, 0o755) for name, content in files.items())
        manifest = {'application': APP_ID, 'current': release.name,
                    'releases': (record['releases'] if record else []) + [release.name],
                    'files': {name: digest(content) for name, content in files.items()}}
        for path, content, mode in changes:
            before = snapshot(path)
            if before != expected[path]:
                raise RuntimeError(f"File changed during installation: {path}")
            publish(path, content, mode)
            written.append((path, before))
        os.symlink('releases/' + release.name, link_temp)
        os.replace(link_temp, layout.current)
        link_changed = True
        publish(layout.manifest, (json.dumps(manifest, indent=2) + '\n').encode())
    except BaseException:
        if link_changed:
            if old_link is None:
                layout.current.unlink()
            else:
                os.symlink(old_link, link_temp)
                os.replace(link_temp, layout.current)
        for path, before in reversed(written):
            if before is None:
                path.unlink(missing_ok=True)
            else:
                publish(path, *before)
        if release.exists():
            shutil.rmtree(release)
        if record is None:
            for directory in (layout.releases, layout.root):
                try:
                    directory.rmdir()
                except OSError:
                    pass
        raise
    finally:
        link_temp.unlink(missing_ok=True)
    print(f'Installed: {layout.files["launcher"]}')
    print(f'Configuration: {layout.config}')
    print('Nautilus Scripts: ' + ', '.join(NAMES))
    print('No terminal is launched. Missing/cancelled/timed-out PIN agents cause failure; saved PINs can avoid prompting.')
    print('Existing configuration settings were preserved. No vendor middleware was installed.')


def uninstall(layout):
    record = load_manifest(layout)
    if record is None:
        print('LiteSign is not installed.')
        return
    for name, path in layout.files.items():
        try:
            existing = snapshot(path)
        except RuntimeError:
            print(f'Keeping modified path: {path}', file=sys.stderr)
            continue
        if existing is not None:
            if digest(existing[0]) == record['files'][name]:
                path.unlink()
            else:
                print(f'Keeping modified file: {path}', file=sys.stderr)
    if layout.current.is_symlink() and os.readlink(layout.current) == 'releases/' + record['current']:
        layout.current.unlink()
    for name in record['releases']:
        directory = layout.releases / name
        if directory.is_symlink():
            print(f'Keeping modified path: {directory}', file=sys.stderr)
        elif directory.exists():
            shutil.rmtree(directory)
    layout.manifest.unlink()
    for directory in (layout.releases, layout.root):
        try:
            directory.rmdir()
        except OSError:
            pass
    print('LiteSign and its Nautilus scripts were uninstalled.')
    print('Configuration, keyring entries, documents and temporary logs were preserved.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('install', 'uninstall'))
    args = parser.parse_args()
    if os.geteuid() == 0:
        parser.error('Run as your regular desktop user, without sudo.')
    try:
        (install if args.action == 'install' else uninstall)(Layout())
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError, EOFError, KeyboardInterrupt) as error:
        print(f'LiteSign {args.action} failed: {error}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
