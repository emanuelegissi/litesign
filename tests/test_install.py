"""Exercise installers in isolated directories; never install desktop or system packages."""
import importlib.util
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tomllib
from types import SimpleNamespace

import pytest


spec = importlib.util.spec_from_file_location('litesign_installer', Path(__file__).parents[1] / 'scripts/install.py')
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)


@pytest.fixture
def installation(tmp_path, monkeypatch):
    home = tmp_path / "user's home"
    home.mkdir()
    monkeypatch.setenv('HOME', str(home))
    monkeypatch.setattr(Path, 'home', classmethod(lambda cls: home))
    monkeypatch.setenv('XDG_DATA_HOME', str(home / 'data'))
    monkeypatch.setenv('XDG_CONFIG_HOME', str(home / 'config'))
    layout = installer.Layout()
    module = home / 'vendor "module".so'
    module.write_bytes(b'test-only middleware placeholder')
    prompts = []
    answer = [str(module)]
    monkeypatch.setattr('builtins.input', lambda prompt: prompts.append(prompt) or answer[0])
    calls = []
    real_run = subprocess.run

    def run(command, **kwargs):
        calls.append(command)
        if command[1:3] == ['-m', 'venv']:
            python = Path(command[3]) / 'bin/python'
            python.parent.mkdir(parents=True)
            python.write_text('#!/usr/bin/env bash\nexec ' + shlex.quote(sys.executable) + ' "$@"\n')
            python.chmod(0o755)
            return SimpleNamespace(returncode=0)
        if command[1:4] == ['-m', 'pip', 'install']:
            return SimpleNamespace(returncode=0)
        return real_run(command, **kwargs)

    monkeypatch.setattr(installer.subprocess, 'run', run)
    # Any subprocess notification invoked by a script goes to this stub.
    tools = home / 'test-tools'
    tools.mkdir()
    notify = tools / 'notify-send'
    notify.write_text('#!/usr/bin/env bash\nexit 0\n')
    notify.chmod(0o755)
    monkeypatch.setenv('PATH', str(tools) + os.pathsep + os.environ['PATH'])
    return SimpleNamespace(layout=layout, module=module, prompts=prompts, answer=answer,
                           calls=calls, home=home, real_run=real_run)


def test_install_creates_runnable_launcher_scripts_and_configuration(installation):
    env = installation
    installer.install(env.layout)
    config = tomllib.loads(env.layout.config.read_text())
    assert config['smartcard']['module'] == str(env.module)
    assert config['smartcard']['remember-pin'] is True
    assert env.layout.config.stat().st_mode & 0o777 == 0o600
    assert 'Smartcard PKCS#11 module' in env.prompts[0]
    assert (env.layout.root / 'litesign.py').is_file()
    assert (env.layout.root / '.venv/bin/python').is_file()
    assert not (env.layout.root / 'assets/mu_linux').exists()
    for path in env.layout.files.values():
        assert path.stat().st_mode & 0o777 == 0o755
    result = env.real_run([str(env.layout.files['launcher']), '--help'], capture_output=True, text=True)
    assert result.returncode == 0
    assert '--no-prompt' in result.stdout
    for name in ('current', 'releases', 'install.json'):
        assert not (env.layout.root / name).exists()


def test_reinstall_fully_replaces_application_and_launchers(installation):
    env = installation
    installer.install(env.layout)
    stale = env.layout.root / 'stale/nested/file'
    stale.parent.mkdir(parents=True)
    stale.write_text('obsolete application data')
    (env.layout.root / '.venv/stale-package').touch()
    (env.layout.root / 'litesign.py').write_text('modified application')
    (env.layout.root / 'assets/icon.png').write_bytes(b'modified icon')
    for path in env.layout.files.values():
        path.write_text('modified launcher')
    installer.install(env.layout)
    assert not (env.layout.root / 'stale').exists()
    assert not (env.layout.root / '.venv/stale-package').exists()
    for name in ('litesign.py', 'assets/icon.png'):
        assert (env.layout.root / name).read_bytes() == (installer.SOURCE / name).read_bytes()
    for path in env.layout.files.values():
        assert path.read_text().startswith('#!/usr/bin/env bash')
    result = env.real_run([str(env.layout.files['launcher']), '--help'], capture_output=True, text=True)
    assert result.returncode == 0


def test_reinstall_preserves_settings_comments_and_defaults_existing_module(installation):
    env = installation
    installer.install(env.layout)
    config = env.layout.config.read_text().replace('remember-pin = true', 'remember-pin = false # keep this')
    config = '# Custom settings\n' + config.replace('Digitally signed', 'Firmato digitalmente')
    env.layout.config.write_text(config)
    env.layout.config.chmod(0o640)
    env.answer[0] = ''
    installer.install(env.layout)
    assert str(env.module) in env.prompts[-1]
    assert env.layout.config.read_text() == config
    assert env.layout.config.stat().st_mode & 0o777 == 0o640


@pytest.mark.parametrize('existing', [False, True])
def test_failed_dependency_install_reports_failure_and_can_be_retried(installation, monkeypatch, capsys, existing):
    env = installation
    if existing:
        installer.install(env.layout)
        (env.layout.root / 'obsolete').touch()
    config = installer.snapshot(env.layout.config)
    run = installer.subprocess.run

    def fail(command, **kwargs):
        if command[1:4] == ['-m', 'pip', 'install']:
            raise subprocess.CalledProcessError(1, command)
        return run(command, **kwargs)

    monkeypatch.setattr(installer.subprocess, 'run', fail)
    monkeypatch.setattr(installer, 'Layout', lambda: env.layout)
    monkeypatch.setattr(installer.os, 'geteuid', lambda: 1000)
    monkeypatch.setattr(sys, 'argv', ['install.py', 'install'])
    assert installer.main() == 1
    assert 'LiteSign install failed' in capsys.readouterr().err
    assert installer.snapshot(env.layout.config) == config
    assert not (env.layout.root / 'obsolete').exists()
    monkeypatch.setattr(installer.subprocess, 'run', run)
    assert installer.main() == 0
    result = env.real_run([str(env.layout.files['launcher']), '--help'], capture_output=True, text=True)
    assert result.returncode == 0


@pytest.mark.parametrize('action', ['install', 'uninstall'])
def test_application_directory_symlink_is_refused(installation, action):
    env = installation
    target = env.home / 'unrelated'
    target.mkdir()
    keep = target / 'keep'
    keep.write_text('keep')
    env.layout.root.parent.mkdir(parents=True)
    env.layout.root.symlink_to(target, target_is_directory=True)
    with pytest.raises(RuntimeError, match='symlink'):
        getattr(installer, action)(env.layout)
    assert keep.read_text() == 'keep'


@pytest.mark.parametrize('nested', [False, True])
def test_install_refuses_source_inside_destination(installation, monkeypatch, nested):
    env = installation
    installer.install(env.layout)
    source = env.layout.root / 'nested' if nested else env.layout.root
    monkeypatch.setattr(installer, 'SOURCE', source)
    before = (env.layout.root / 'litesign.py').read_bytes()
    with pytest.raises(RuntimeError, match='outside the application directory'):
        installer.install(env.layout)
    assert (env.layout.root / 'litesign.py').read_bytes() == before


@pytest.mark.parametrize('problem', ['source', 'module', 'config_symlink'])
def test_invalid_inputs_leave_existing_application_intact(installation, monkeypatch, problem):
    env = installation
    installer.install(env.layout)
    before = (env.layout.root / 'litesign.py').read_bytes()
    if problem == 'source':
        monkeypatch.setattr(installer, 'SOURCE', env.home / 'missing-source')
    elif problem == 'module':
        env.answer[0] = '/missing/module.so'
    else:
        env.layout.config.unlink()
        env.layout.config.symlink_to(env.module)
    with pytest.raises(RuntimeError):
        installer.install(env.layout)
    assert (env.layout.root / 'litesign.py').read_bytes() == before


def test_config_modified_during_build_is_not_overwritten(installation, monkeypatch):
    env = installation
    installer.install(env.layout)
    original_build = installer.build_application
    config = env.layout.config.read_text() + '\n# concurrent edit\n'

    def edit(root):
        python = original_build(root)
        env.layout.config.write_text(config)
        return python

    monkeypatch.setattr(installer, 'build_application', edit)
    with pytest.raises(RuntimeError, match='changed during installation'):
        installer.install(env.layout)
    assert env.layout.config.read_text() == config


def test_uninstall_removes_managed_files_and_preserves_user_data(installation):
    env = installation
    installer.install(env.layout)
    config = env.layout.config.read_bytes()
    document = env.home / 'document-signed.pdf'
    document.write_bytes(b'keep document')
    unrelated = env.layout.files['Extract p7m'].parent / 'Unrelated script'
    unrelated.write_text('keep unrelated')
    env.layout.files['Sign as pdf'].write_text('user modification')
    # The installed uninstaller must also work while deleting its own directory.
    result = env.real_run(['bash', str(env.layout.root / 'uninstall.sh')], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert not env.layout.root.exists()
    assert all(not path.exists() for path in env.layout.files.values())
    assert env.layout.config.read_bytes() == config
    assert unrelated.read_text() == 'keep unrelated'
    assert document.read_bytes() == b'keep document'
    installer.uninstall(env.layout)


@pytest.mark.parametrize(('name', 'expected'), [
    ('Sign as pdf', ['--no-prompt', '--format', 'pades']),
    ('Sign as p7m', ['--no-prompt', '--format', 'cades']),
    ('Extract p7m', ['--extract']),
])
def test_nautilus_passes_selection_as_one_batch_without_shell_expansion(installation, name, expected):
    env = installation
    installer.install(env.layout)
    app = env.layout.root / 'litesign.py'
    app.write_text('import json, sys\nprint(json.dumps(sys.argv[1:]))\n')
    selection = ['two words.pdf', "apostrophe's.pdf", 'a\nnewline.pdf', '-leading.pdf',
                 '$(touch NOT_CREATED).pdf', 'résumé.pdf', '*.pdf']
    result = env.real_run([str(env.layout.files[name]), *selection], cwd=env.home,
                          capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == expected + ['--', *selection]
    assert not (env.home / 'NOT_CREATED').exists()


def test_nautilus_rejects_empty_or_nonlocal_selection(installation):
    env = installation
    installer.install(env.layout)
    for name in installer.NAMES:
        result = env.real_run([str(env.layout.files[name])], capture_output=True, text=True)
        assert result.returncode == 2
        assert 'No accessible local files selected' in result.stderr


@pytest.mark.parametrize('value', ['', '/missing/driver.so'])
def test_module_prompt_rejects_invalid_selection(installation, value):
    env = installation
    env.answer[0] = value
    with pytest.raises(RuntimeError):
        installer.install(env.layout)
    assert not env.layout.root.exists()


def test_shell_entry_points_parse():
    paths = [installer.SOURCE / name for name in ('install.sh', 'uninstall.sh', 'scripts/nautilus-run.sh')]
    paths.extend((installer.SOURCE / 'scripts/nautilus').iterdir())
    for path in paths:
        subprocess.run(['bash', '-n', str(path)], check=True)
