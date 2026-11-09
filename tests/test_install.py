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
    record = installer.load_manifest(env.layout)
    assert set(record['files']) == {'launcher', *installer.NAMES}
    assert not (env.layout.current / 'assets/mu_linux').exists()
    for path in env.layout.files.values():
        assert path.stat().st_mode & 0o777 == 0o755
    result = env.real_run([str(env.layout.files['launcher']), '--help'], capture_output=True, text=True)
    assert result.returncode == 0
    assert '--agent-only' in result.stdout
    assert env.layout.current.is_symlink()


def test_reinstall_preserves_settings_comments_and_defaults_existing_module(installation):
    env = installation
    installer.install(env.layout)
    previous = os.readlink(env.layout.current)
    config = env.layout.config.read_text().replace('remember-pin = true', 'remember-pin = false # keep this')
    config = '# Custom settings\n' + config.replace('Digitally signed', 'Firmato digitalmente')
    env.layout.config.write_text(config)
    env.answer[0] = ''
    installer.install(env.layout)
    assert str(env.module) in env.prompts[-1]
    assert env.layout.config.read_text() == config
    assert os.readlink(env.layout.current) != previous
    assert len(installer.load_manifest(env.layout)['releases']) == 2


@pytest.mark.parametrize('existing', [False, True])
def test_failed_dependency_install_keeps_previous_installation(installation, monkeypatch, existing):
    env = installation
    if existing:
        installer.install(env.layout)
    before = {path: installer.snapshot(path) for path in [env.layout.config, *env.layout.files.values()]}
    old_manifest = env.layout.manifest.read_bytes() if existing else None
    old_link = os.readlink(env.layout.current) if existing else None
    real_build = installer.build_release

    def fail(release):
        real_build(release)
        raise subprocess.CalledProcessError(1, ['pip', 'install'])

    monkeypatch.setattr(installer, 'build_release', fail)
    with pytest.raises(subprocess.CalledProcessError):
        installer.install(env.layout)
    assert {path: installer.snapshot(path) for path in before} == before
    if existing:
        assert env.layout.manifest.read_bytes() == old_manifest
        assert os.readlink(env.layout.current) == old_link
        assert len(list(env.layout.releases.iterdir())) == 1
    else:
        assert not env.layout.root.exists()


@pytest.mark.parametrize('existing', [False, True])
def test_failed_commit_rolls_back_files_config_and_current_link(installation, monkeypatch, existing):
    env = installation
    if existing:
        installer.install(env.layout)
    before = {path: installer.snapshot(path) for path in [env.layout.config, *env.layout.files.values()]}
    old_record = installer.load_manifest(env.layout) if existing else None
    publish = installer.publish

    def fail(path, *args):
        if path == env.layout.manifest:
            raise OSError('Cannot publish manifest')
        return publish(path, *args)

    monkeypatch.setattr(installer, 'publish', fail)
    with pytest.raises(OSError, match='manifest'):
        installer.install(env.layout)
    assert {path: installer.snapshot(path) for path in before} == before
    if existing:
        assert installer.load_manifest(env.layout) == old_record
        assert os.readlink(env.layout.current) == 'releases/' + old_record['current']
    else:
        assert not env.layout.root.exists()


@pytest.mark.parametrize('kind', ['script', 'launcher', 'app_directory', 'config_symlink'])
def test_installer_refuses_unowned_paths(installation, kind):
    env = installation
    if kind == 'app_directory':
        env.layout.root.mkdir(parents=True)
    elif kind == 'config_symlink':
        env.layout.config.parent.mkdir(parents=True)
        env.layout.config.symlink_to(env.module)
    else:
        path = env.layout.files['Sign as pdf' if kind == 'script' else 'launcher']
        path.parent.mkdir(parents=True)
        path.write_text('unrelated file')
    with pytest.raises(RuntimeError):
        installer.install(env.layout)
    assert not env.layout.manifest.exists()


def test_config_modified_during_build_is_not_overwritten(installation, monkeypatch):
    env = installation
    installer.install(env.layout)
    original_build = installer.build_release
    config = env.layout.config.read_text() + '\n# concurrent edit\n'

    def edit(release):
        python = original_build(release)
        env.layout.config.write_text(config)
        return python

    monkeypatch.setattr(installer, 'build_release', edit)
    with pytest.raises(RuntimeError, match='changed during installation'):
        installer.install(env.layout)
    assert env.layout.config.read_text() == config


def test_uninstall_keeps_config_documents_and_modified_scripts(installation):
    env = installation
    installer.install(env.layout)
    installer.install(env.layout)
    config = env.layout.config.read_bytes()
    document = env.home / 'document-signed.pdf'
    document.write_bytes(b'keep document')
    unrelated = env.layout.files['Extract p7m'].parent / 'Unrelated script'
    unrelated.write_text('keep unrelated')
    modified = env.layout.files['Sign as pdf']
    modified.write_text('user modification')
    installer.uninstall(env.layout)
    assert not env.layout.root.exists()
    assert not env.layout.files['launcher'].exists()
    assert not env.layout.files['Sign as p7m'].exists()
    assert not env.layout.files['Extract p7m'].exists()
    assert modified.read_text() == 'user modification'
    assert env.layout.config.read_bytes() == config
    assert unrelated.read_text() == 'keep unrelated'
    assert document.read_bytes() == b'keep document'
    installer.uninstall(env.layout)


@pytest.mark.parametrize(('name', 'expected'), [
    ('Sign as pdf', ['--agent-only', '--format', 'pades']),
    ('Sign as p7m', ['--agent-only', '--format', 'cades']),
    ('Extract p7m', ['--extract']),
])
def test_nautilus_passes_selection_as_one_batch_without_shell_expansion(installation, name, expected):
    env = installation
    installer.install(env.layout)
    app = env.layout.current / 'litesign.py'
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
