"""Automatic PDF recovery using synthetic documents; no card or Ghostscript needed."""
from io import BytesIO
from pathlib import Path
from types import SimpleNamespace

import pytest
from pyhanko.pdf_utils.misc import PdfReadError, PdfWriteError
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.pdf_utils.writer import PageObject, PdfFileWriter
from pyhanko.pdf_utils import generic
from pyhanko.sign.validation import validate_pdf_signature
from pyhanko_certvalidator import ValidationContext

import litesign as ls
from test_stamp_position import software_signer


@pytest.fixture
def document(tmp_path):
    writer = PdfFileWriter()
    writer.insert_page(PageObject(writer.add_object(generic.StreamObject(stream_data=b'')),
                                  (0, 0, 600, 800)))
    buffer = BytesIO()
    writer.write(buffer)
    valid = buffer.getvalue()
    assert valid.count(b'/Producer') == 1
    source = tmp_path / 'input.pdf'
    source.write_bytes(valid.replace(b'/Producer', b' Producer'))
    _, stamp = ls.load_config(tmp_path / 'config.toml', 'pades')
    font, icon = ls.prepare_stamp(stamp)
    return SimpleNamespace(source=source, destination=tmp_path / 'signed.pdf',
                           valid=valid, stamp=stamp, font=font, icon=icon)


def sign(document, signer):
    with document.source.open('rb') as source:
        ls.sign_pdf(source, document.destination, signer, document.stamp,
                    document.font, document.icon)


@pytest.fixture
def converter(monkeypatch, document):
    calls = []
    monkeypatch.setattr(ls.shutil, 'which', lambda name: '/usr/bin/gs' if name == 'gs' else None)

    def run(command, **options):
        calls.append(command)
        output = Path(next(arg.split('=', 1)[1] for arg in command if arg.startswith('-sOutputFile=')))
        assert Path(command[-1]).read_bytes() == document.source.read_bytes()
        assert command[command.index('-f') + 1] == str(output.parent / 'input.pdf')
        assert '-sDEVICE=pdfimage24' in command and '-r300' in command
        assert '-sCompression=Flate' in command and '-dSAFER' in command
        assert options['timeout'] == 120 and options['stdin'] == ls.subprocess.DEVNULL
        assert output.parent.stat().st_mode & 0o777 == 0o700
        output.write_bytes(document.valid)
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(ls.subprocess, 'run', run)
    return calls


def test_metadata_error_recovers_and_signs(document, converter, software_signer, capsys):
    before = document.source.read_bytes()
    sign(document, software_signer)
    assert len(converter) == 1
    assert not Path(converter[0][-1]).parent.exists()
    assert document.source.read_bytes() == before
    assert 'Searchable text and interactive features will not be preserved' in capsys.readouterr().err
    with document.destination.open('rb') as stream:
        reader = PdfFileReader(stream)
        signature, = reader.embedded_signatures
        status = validate_pdf_signature(signature, signer_validation_context=ValidationContext(
            trust_roots=[software_signer.signing_cert], allow_fetching=False))
        assert status.intact and status.valid


def test_valid_pdf_does_not_convert(document, converter, software_signer):
    document.source.write_bytes(document.valid)
    sign(document, software_signer)
    assert not converter


@pytest.mark.parametrize('error', [ls.StampPositionError('placement'), ls.StampPageError('page'),
                                   ls.PinRejected('pin'), OSError('disk'), PdfWriteError('write')])
def test_non_parsing_errors_never_convert(document, converter, monkeypatch, error):
    document.destination.write_bytes(b'existing output')

    def fail(source, output, *args):
        output.write(b'partial output')
        raise error

    monkeypatch.setattr(ls, '_sign_pdf', fail)
    with pytest.raises(type(error), match=str(error)):
        sign(document, None)
    assert not converter
    assert document.destination.read_bytes() == b'existing output'
    assert not list(document.source.parent.glob('.litesign-*.tmp'))


def test_unknown_signatures_refuse_conversion(document, converter):
    document.source.write_bytes(b'not a PDF')
    with pytest.raises(ls.FileError, match='unable to check for existing signatures'):
        sign(document, None)
    assert not converter
    assert not document.destination.exists()


def test_existing_signature_refuses_conversion(document, converter, software_signer):
    document.source.write_bytes(document.valid)
    sign(document, software_signer)
    signed = document.destination.read_bytes()
    assert b'/Producer' in signed
    document.source.write_bytes(signed.replace(b'/Producer', b' Producer'))
    with pytest.raises(ls.FileError, match='existing signatures would be lost'):
        sign(document, software_signer)
    assert not converter
    assert document.destination.read_bytes() == signed


def test_missing_ghostscript(document, monkeypatch, software_signer):
    monkeypatch.setattr(ls.shutil, 'which', lambda name: None)
    with pytest.raises(ls.FileError, match='install Ghostscript'):
        sign(document, software_signer)
    assert not document.destination.exists()


@pytest.mark.parametrize('failure', ['exit', 'timeout', 'missing', 'unreadable', 'oserror'])
def test_conversion_failures_preserve_output(document, monkeypatch, software_signer, failure):
    calls = []
    monkeypatch.setattr(ls.shutil, 'which', lambda name: '/usr/bin/gs')
    before = document.source.read_bytes()
    document.destination.write_bytes(b'existing output')

    def run(command, **kwargs):
        calls.append(command)
        output = Path(next(arg.split('=', 1)[1] for arg in command if arg.startswith('-sOutputFile=')))
        if failure == 'timeout':
            raise ls.subprocess.TimeoutExpired(command, 120)
        if failure == 'oserror':
            raise OSError('cannot execute')
        if failure != 'missing':
            output.write_bytes(b'incomplete PDF')
        return SimpleNamespace(returncode=1 if failure == 'exit' else 0)

    monkeypatch.setattr(ls.subprocess, 'run', run)
    with pytest.raises(ls.FileError, match='Ghostscript|rasterized PDF'):
        sign(document, software_signer)
    assert len(calls) == 1
    assert not Path(calls[0][-1]).parent.exists()
    assert document.source.read_bytes() == before
    assert document.destination.read_bytes() == b'existing output'
    assert not list(document.source.parent.glob('.litesign-*.tmp'))


def test_retry_discards_partial_first_attempt(document, converter, monkeypatch):
    calls = []

    def attempt(source, output, *args):
        calls.append(source.read())
        if len(calls) == 1:
            output.write(b'partial output that must be discarded')
            raise PdfReadError('broken metadata')
        output.write(b'complete')

    monkeypatch.setattr(ls, '_sign_pdf', attempt)
    sign(document, None)
    assert len(calls) == 2 and len(converter) == 1
    assert document.destination.read_bytes() == b'complete'
