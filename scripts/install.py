#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Per-user installation; invoked by install.sh or uninstall.sh."""
import sys

if sys.version_info < (3, 11):
    raise SystemExit("LiteSign installation requires Python 3.11 or later.")

import argparse
import os
from pathlib import Path
import shlex
import shutil
import stat
import subprocess
import tempfile
import tomllib


NAMES = ('Sign as pdf', 'Sign as p7m', 'Extract p7m')
SOURCE = Path(__file__).resolve().parent.parent
APP_FILES = ('litesign.py', 'requirements.txt', 'README.md',
             'LICENSE', 'install.sh', 'uninstall.sh')


def xdg_path(name, default):
    value = Path(os.environ.get(name) or default).expanduser()
    return value if value.is_absolute() else Path(default)


class Layout:
    def __init__(self):
        data = xdg_path('XDG_DATA_HOME', Path.home() / '.local/share')
        config = xdg_path('XDG_CONFIG_HOME', Path.home() / '.config')
        self.root = data / 'litesign'
        self.config = config / 'litesign/config.toml'
        self.files = {'launcher': Path.home() / '.local/bin/litesign'}
        self.files.update({name: data / 'nautilus/scripts' / name for name in NAMES})


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


def check_root(root):
    if root.is_symlink():
        raise RuntimeError('The LiteSign application directory must not be a symlink.')
    if root.exists() and not root.is_dir():
        raise RuntimeError(f'Expected an application directory: {root}')


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


def build_application(root):
    # Create the venv at its final path: moving it breaks its shebangs.
    root.mkdir(parents=True)
    for name in APP_FILES:
        shutil.copy2(SOURCE / name, root / name)
    (root / 'assets').mkdir()
    shutil.copy2(SOURCE / 'assets/icon.png', root / 'assets/icon.png')
    shutil.copytree(SOURCE / 'scripts', root / 'scripts', ignore=shutil.ignore_patterns('__pycache__'))
    subprocess.run([sys.executable, '-m', 'venv', str(root / '.venv')], check=True)
    python = root / '.venv/bin/python'
    subprocess.run([str(python), '-m', 'pip', 'install', '-r', str(root / 'requirements.txt')], check=True)
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
    for name in ('notify-send', 'openssl', 'gs'):
        if not shutil.which(name):
            print(f'Warning: {name} is not installed.', file=sys.stderr)
    print('CAdES requires OpenSSL 3 and pkcs11-provider. Install system packages with your distribution tools.')
    print('PDF raster recovery requires Ghostscript (gs).')


def install(layout):
    check_root(layout.root)
    if SOURCE.resolve().is_relative_to(layout.root.resolve()):
        raise RuntimeError('Run installation from a source directory outside the application directory.')
    for name in (*APP_FILES, 'assets/icon.png', 'scripts/install.py', 'scripts/nautilus-run.sh',
                 *(f'scripts/nautilus/{name}' for name in NAMES)):
        if not (SOURCE / name).is_file():
            raise RuntimeError(f'Missing application source file: {SOURCE / name}')
    for path in layout.files.values():
        snapshot(path)
    module, old_config = choose_module(layout.config)
    check_tools()
    if layout.root.exists():
        shutil.rmtree(layout.root)
    python = build_application(layout.root)
    config = prepare_config(python, module, old_config)
    runner = shlex.quote(str(layout.root / 'scripts/nautilus-run.sh'))
    launcher = ('#!/usr/bin/env bash\n# Installed by LiteSign.\nexec ' +
                shlex.quote(str(python)) + ' ' +
                shlex.quote(str(layout.root / 'litesign.py')) + ' "$@"\n').encode()
    if snapshot(layout.config) != old_config:
        raise RuntimeError('Configuration changed during installation; retry to preserve your edits.')
    publish(layout.config, config, old_config[1] if old_config else 0o600)
    publish(layout.files['launcher'], launcher, 0o755)
    for name in NAMES:
        template = (layout.root / 'scripts/nautilus' / name).read_text()
        publish(layout.files[name], template.replace('@NAUTILUS_RUNNER@', runner).encode(), 0o755)
    print(f'Installed: {layout.files["launcher"]}')
    print(f'Configuration: {layout.config}')
    print('Nautilus Scripts: ' + ', '.join(NAMES))
    print('Nautilus signing requires a saved keyring PIN. Run LiteSign in a terminal first to enter and save it.')
    print('Existing configuration settings were preserved. No vendor middleware was installed.')


def uninstall(layout):
    check_root(layout.root)
    if layout.root.exists():
        shutil.rmtree(layout.root)
    for path in layout.files.values():
        path.unlink(missing_ok=True)
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
