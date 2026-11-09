"""Optional desktop feedback and credential prompts, without desktop side effects."""
import json
from types import SimpleNamespace

import pytest

import litesign as ls


@pytest.fixture
def desktop(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(ls.shutil, 'which', lambda name: '/usr/bin/' + name)
    monkeypatch.setattr(ls.tempfile, 'tempdir', str(tmp_path))

    def run(command, **kwargs):
        calls.append((command, kwargs))
        return SimpleNamespace(returncode=0, stdout=b' 1234 \n', stderr=b'')

    monkeypatch.setattr(ls.subprocess, 'run', run)
    return calls


def test_systemd_prompt_is_private_and_does_not_use_its_credential_cache(desktop, monkeypatch, capsys):
    monkeypatch.setenv('CREDENTIALS_DIRECTORY', '/private/credentials')
    monkeypatch.setattr(ls, 'getpass', lambda *a: pytest.fail('Unexpected fallback'))
    assert ls.prompt_secret('New smart card PIN') == ' 1234 '
    command, options = desktop[0]
    assert command == ['/usr/bin/systemd-ask-password', '--echo=no', '--timeout=90', '--', 'New smart card PIN:']
    assert options['stdout'] == options['stderr'] == ls.subprocess.PIPE
    assert options['timeout'] == 95
    assert 'CREDENTIALS_DIRECTORY' not in options['env']
    assert all('cached' not in arg and 'keyname' not in arg for arg in command)
    assert capsys.readouterr() == ('', '')


def test_missing_systemd_uses_getpass(monkeypatch):
    prompts = []
    monkeypatch.setattr(ls, 'getpass', lambda label: prompts.append(label) or '1234')
    assert ls.prompt_pin() == '1234'
    assert prompts == ['Smart card PIN: ']


def test_disappearing_systemd_uses_getpass(desktop, monkeypatch):
    def missing(*a, **kw):
        raise FileNotFoundError('gone')

    monkeypatch.setattr(ls.subprocess, 'run', missing)
    monkeypatch.setattr(ls, 'getpass', lambda label: '1234')
    assert ls.prompt_pin() == '1234'


@pytest.mark.parametrize('mode', ['cancel', 'timeout', 'permission', 'empty', 'multiple', 'encoding'])
def test_failed_systemd_prompt_never_retries_or_exposes_output(desktop, monkeypatch, capsys, mode):
    secret = b'private-pin'

    def run(*a, **kw):
        if mode == 'timeout':
            raise ls.subprocess.TimeoutExpired('systemd-ask-password', 95, output=secret, stderr=secret)
        if mode == 'permission':
            raise PermissionError(secret.decode())
        output = {'cancel': secret, 'empty': b'\n', 'multiple': secret + b'\nother\n', 'encoding': b'\xff'}[mode]
        return SimpleNamespace(returncode=1 if mode == 'cancel' else 0, stdout=output, stderr=secret)

    monkeypatch.setattr(ls.subprocess, 'run', run)
    monkeypatch.setattr(ls, 'getpass', lambda *a: pytest.fail('Unexpected fallback after prompt'))
    with pytest.raises(ls.SetupError) as error:
        ls.prompt_pin()
    assert secret.decode() not in str(error.value)
    assert capsys.readouterr() == ('', '')


def test_short_feedback_uses_no_actions_or_logs(desktop, tmp_path):
    ls.notify_feedback('1 file extracted.\nSignatures not verified.', 0)
    command, options = desktop[0]
    assert command == ['/usr/bin/notify-send', '--app-name=LiteSign', '--urgency=normal',
                       '--', 'LiteSign', '1 file extracted.\nSignatures not verified.']
    assert options['timeout'] == 3
    assert options['stdout'] == options['stderr'] == ls.subprocess.DEVNULL
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize('report', ['A' * 301, 'a\nb\nc\nd\ne'])
def test_long_report_uses_private_temporary_log(desktop, tmp_path, capsys, report):
    ls.notify_feedback(report, 1)
    logs = list(tmp_path.glob('litesign-*.log'))
    assert len(logs) == 1
    assert logs[0].read_text() == report + '\n'
    assert logs[0].stat().st_mode & 0o777 == 0o600
    command, _ = desktop[0]
    assert '--urgency=critical' in command
    assert str(logs[0]) in command[-1]
    assert str(logs[0]) in capsys.readouterr().err
    assert len(command[-1]) < len(report) or len(report.splitlines()) > 4
    assert not any('action' in item or item == '--wait' for item in command)


def test_missing_notifier_keeps_terminal_output_and_exit_code(monkeypatch, tmp_path, capsys):
    def operation(argv):
        ls.feedback('Done')
        return 1

    monkeypatch.setattr(ls, 'run_cli', operation)
    monkeypatch.setattr(ls.tempfile, 'tempdir', str(tmp_path))
    assert ls.main([]) == 1
    assert capsys.readouterr() == ('Done\n', '')
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize('failure', ['timeout', 'missing', 'exit'])
def test_notification_failure_preserves_operation_result(desktop, monkeypatch, capsys, failure):
    def run(*a, **kw):
        if failure == 'timeout':
            raise ls.subprocess.TimeoutExpired('notify-send', 3)
        if failure == 'missing':
            raise FileNotFoundError('gone')
        return SimpleNamespace(returncode=1)

    monkeypatch.setattr(ls.subprocess, 'run', run)
    monkeypatch.setattr(ls, 'run_cli', lambda argv: ls.feedback('Done') or 0)
    assert ls.main([]) == 0
    assert capsys.readouterr() == ('Done\n', '')


def test_log_failure_still_reports_result(desktop, monkeypatch, capsys):
    def unwritable(*a, **kw):
        raise OSError('disk full')

    monkeypatch.setattr(ls.tempfile, 'NamedTemporaryFile', unwritable)
    monkeypatch.setattr(ls, 'run_cli', lambda argv: ls.feedback('A' * 400) or 0)
    assert ls.main([]) == 0
    assert 'Could not save' in capsys.readouterr().err
    assert 'Details could not be saved' in desktop[0][0][-1]


def test_feedback_redacts_secrets_including_encoded_forms(desktop, monkeypatch, tmp_path):
    def operation(argv):
        # Reports collected before a PIN was read must be redacted as well.
        ls.feedback('Old 1234, new 5678; encoded %31%32%33%34; mixed 56%37%38. ' + 'x' * 350)
        ls.remember_secret('1234')
        ls.remember_secret('5678')
        return 1

    monkeypatch.setattr(ls, 'run_cli', operation)
    assert ls.main([]) == 1
    report = next(tmp_path.glob('*.log')).read_text()
    assert report.count('[redacted]') == 4
    assert '1234' not in report and '5678' not in report
    assert ls._current_feedback.get() is None


def test_card_json_stdout_stays_valid_and_report_is_separate(desktop, monkeypatch, tmp_path, capsys):
    data = {'cards': [{'label': 'Example card', 'details': 'x' * 400}]}
    monkeypatch.setattr(ls, 'manage_card', lambda args: ls.feedback(json.dumps(data)) or 0)
    assert ls.main(['--card-info']) == 0
    captured = capsys.readouterr()
    assert json.loads(captured.out) == data
    assert 'Details:' in captured.err
    assert json.loads(next(tmp_path.glob('*.log')).read_text()) == data


def test_notification_markup_is_escaped(desktop):
    ls.notify_feedback('Failed: <document & notes>.pdf', 1)
    assert desktop[0][0][-1] == 'Failed: &lt;document &amp; notes&gt;.pdf'


def test_help_does_not_notify(desktop, capsys):
    with pytest.raises(SystemExit) as error:
        ls.main(['--help'])
    assert error.value.code == 0
    assert not desktop
    assert 'usage:' in capsys.readouterr().out


def test_cli_error_notifies_and_preserves_exit_code(desktop, capsys):
    with pytest.raises(SystemExit) as error:
        ls.main(['--invalid'])
    assert error.value.code == 2
    assert 'Invalid command line' in desktop[0][0][-1]
    assert 'error:' in capsys.readouterr().err


def test_agent_only_never_uses_terminal_when_helper_is_missing(monkeypatch):
    monkeypatch.setattr(ls, 'getpass', lambda *a: pytest.fail('Unexpected terminal prompt'))
    monkeypatch.setattr(ls, 'run_batch', lambda args: ls.prompt_pin())
    with pytest.raises(ls.SetupError, match='agent-only'):
        ls.main(['--agent-only', 'document.pdf'])
    assert ls._agent_only.get() is False


@pytest.mark.parametrize('outcome', ['success', 'disappeared', 'no_agent', 'timeout'])
def test_agent_only_uses_user_agent_without_fallback(desktop, monkeypatch, outcome):
    original_run = ls.subprocess.run

    def run(command, **kwargs):
        if 'systemd-ask-password' in command[0]:
            assert '--no-tty' in command and '--user' in command
            if outcome == 'disappeared':
                raise FileNotFoundError()
            if outcome == 'timeout':
                raise ls.subprocess.TimeoutExpired(command, 95)
            if outcome == 'no_agent':
                return SimpleNamespace(returncode=1)
        return original_run(command, **kwargs)

    monkeypatch.setattr(ls.subprocess, 'run', run)
    monkeypatch.setattr(ls, 'getpass', lambda *a: pytest.fail('Unexpected terminal fallback'))
    monkeypatch.setattr(ls, 'run_batch', lambda args: 0 if ls.prompt_pin() else 1)
    if outcome == 'success':
        assert ls.main(['--agent-only', 'document.pdf']) == 0
    else:
        with pytest.raises(ls.SetupError):
            ls.main(['--agent-only', 'document.pdf'])
    assert ls._agent_only.get() is False


@pytest.mark.parametrize('action', ['--extract', '--forget-pin'])
def test_agent_only_rejected_for_actions_without_pin(action):
    with pytest.raises(SystemExit) as error:
        ls.main(['--agent-only', action, 'document.p7m'])
    assert error.value.code == 2
