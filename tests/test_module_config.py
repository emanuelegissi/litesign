"""A configured PKCS#11 module is required without interactive setup."""
import sys

import pkcs11
import pytest

import litesign as ls


class NoTerminalInput:
    def isatty(self):
        pytest.fail('Module configuration must not depend on terminal availability')

    def readline(self):
        pytest.fail('Module configuration must not prompt for input')


@pytest.fixture
def no_card_access(monkeypatch):
    monkeypatch.setattr(sys, 'stdin', NoTerminalInput())
    monkeypatch.setattr(ls, 'prompt_pin', lambda: pytest.fail('Unexpected PIN prompt'))
    monkeypatch.setattr(ls, 'prompt_secret', lambda *args: pytest.fail('Unexpected credential prompt'))
    monkeypatch.setattr(pkcs11, 'lib', lambda *args: pytest.fail('Unexpected card access'))
    monkeypatch.setattr(ls, 'desktop_keyring', lambda: pytest.fail('Unexpected keyring access'))


@pytest.mark.parametrize('action', [
    ['--format', 'pades', 'input.pdf'], ['--format', 'cades', 'input.bin'],
    ['--card-info'], ['--change-pin'], ['--forget-pin'],
])
@pytest.mark.parametrize('smartcard', [
    '', '[smartcard]\n', '[smartcard]\nmodule = ""\n', '[smartcard]\nmodule = " \\t "\n',
])
def test_missing_or_blank_module_stops_all_commands(tmp_path, monkeypatch, capsys, no_card_access,
                                                   action, smartcard):
    config = tmp_path / 'config.toml'
    config.write_text(smartcard)
    monkeypatch.setattr(ls, 'config_path', lambda: config)
    assert ls.main(action) == 2
    output = capsys.readouterr()
    assert output.err == f'PKCS#11 module is not configured. Set [smartcard].module in {config}.\n'
    assert config.read_text() == smartcard
    assert 'module path: ' not in output.out + output.err


def test_first_run_creates_template_then_reports_missing_module(tmp_path, monkeypatch, capsys, no_card_access):
    config = tmp_path / 'litesign/config.toml'
    monkeypatch.setattr(ls, 'config_path', lambda: config)
    assert ls.main(['input.pdf']) == 2
    assert config.read_text() == ls.DEFAULT_CONFIG
    assert str(config) in capsys.readouterr().err


@pytest.mark.parametrize('target', ['missing.so', '.'])
def test_driver_must_still_be_a_file(tmp_path, target):
    with pytest.raises(ls.SetupError, match='driver not found'):
        ls.resolve_module(tmp_path / 'config.toml', target)
