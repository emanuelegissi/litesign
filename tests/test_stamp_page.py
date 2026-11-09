"""Numeric page overrides and page selection failures."""
from types import SimpleNamespace

import pytest

import litesign as ls


@pytest.mark.parametrize('configured', ['"first"', '"last"', '4', '0', '"invalid"'])
def test_page_override_takes_precedence_without_saving(tmp_path, configured):
    config = tmp_path / 'config.toml'
    config.write_text(f'[pades.stamp]\nstamp-page={configured}\n')
    before = config.read_bytes()
    _, stamp = ls.load_config(config, 'pades', stamp_page=2)
    assert stamp['stamp-page'] == 2
    assert config.read_bytes() == before


def test_default_stamp_page_is_last(tmp_path):
    _, stamp = ls.load_config(tmp_path / 'config.toml', 'pades')
    assert stamp['stamp-page'] == 'last'
    assert 'page' not in stamp


@pytest.mark.parametrize('value', ['0', '-1', '2.5', 'first', 'last', 'nan', 'inf', ''])
def test_cli_rejects_invalid_page_before_running(value, monkeypatch):
    monkeypatch.setattr(ls, 'run_batch', lambda args: pytest.fail('Invalid page reached signing'))
    with pytest.raises(SystemExit) as error:
        ls.main(['--stamp-page', value, '--', 'input.pdf'])
    assert error.value.code == 2


@pytest.mark.parametrize('value', [1, 2, 10])
def test_cli_accepts_positive_page_numbers(value, monkeypatch):
    def run(args):
        assert args.stamp_page == value
        assert type(args.stamp_page) is int
        return 0
    monkeypatch.setattr(ls, 'run_batch', run)
    assert ls.main(['--stamp-page', str(value), '--', 'input.pdf']) == 0


@pytest.mark.parametrize('action', [
    ['--format', 'cades'], ['--card-info'], ['--change-pin'], ['--forget-pin'],
])
def test_page_option_is_only_for_pades_signing(action):
    with pytest.raises(SystemExit) as error:
        ls.main([*action, '--stamp-page', '1'])
    assert error.value.code == 2


@pytest.mark.parametrize('selector', ['first', 'last', 1])
def test_empty_pdf_has_no_stamp_page(selector):
    writer = SimpleNamespace(root={'/Pages': {'/Count': 0}})
    with pytest.raises(ls.StampPageError, match='does not exist'):
        ls.find_page(writer, selector)
