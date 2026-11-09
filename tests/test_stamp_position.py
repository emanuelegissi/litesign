"""Coordinate placement checks, with no hardware or desktop keyring access."""
import math
from types import SimpleNamespace

import pytest

# Register PAdES CMS attributes during collection, before other tests build CMS values.
from pyhanko.sign.signers import SimpleSigner

import litesign as ls


@pytest.mark.parametrize(('rotation', 'expected'), [
    (0, (15, 97, 45, 117)),
    (90, (23, 25, 43, 55)),
    (180, (115, 33, 145, 53)),
    (270, (117, 95, 137, 125)),
])
def test_custom_top_left_on_cropped_rotated_page(rotation, expected):
    assert ls.stamp_box((10, 20, 150, 130), rotation, 30, 20, 'right', 'bottom',
                        position=(5, 13)) == expected


def test_custom_fractional_coordinates_are_not_rounded_or_resized():
    assert ls.stamp_box((10.5, 20.25, 150.5, 130.25), 0, 30, 20, None, None,
                        position=(5.25, 13.5)) == (15.75, 96.75, 45.75, 116.75)


@pytest.mark.parametrize('rotation', [0, 90, 180, 270])
def test_custom_stamp_can_cover_entire_visible_page(rotation):
    width, height = (110, 140) if rotation in (90, 270) else (140, 110)
    assert ls.stamp_box((10, 20, 150, 130), rotation, width, height, None, None,
                        position=(0, 0)) == (10, 20, 150, 130)


@pytest.mark.parametrize('position', [(110, 90), (0, 0), (110, 0), (0, 90)])
def test_custom_stamp_can_touch_page_edges(position):
    box = ls.stamp_box((0, 0, 140, 110), 0, 30, 20, None, None, position=position)
    assert box[2] - box[0] == 30
    assert box[3] - box[1] == 20


@pytest.mark.parametrize('position', [
    (-1, 0), (0, -1), (141, 0), (0, 111), (111, 0), (0, 91),
    (math.nan, 0), (0, math.inf),
])
def test_custom_stamp_must_fit_completely(position):
    with pytest.raises(ls.StampPositionError, match='does not fit'):
        ls.stamp_box((0, 0, 140, 110), 0, 30, 20, None, None, position=position)


def test_automatic_placement_keeps_twelve_point_margin():
    with pytest.raises(ls.StampPositionError, match='12-point margin'):
        ls.stamp_box((0, 0, 140, 110), 0, 117, 20, 'right', 'bottom')


def test_renamed_settings_and_cli_override(tmp_path):
    config = tmp_path / 'config.toml'
    config.write_text('[pades.stamp]\nstamp-horizontal-position="left"\nstamp-vertical-position="top"\n')
    original = config.read_bytes()
    _, stamp = ls.load_config(config, 'pades')
    assert stamp['stamp-horizontal-position'] == 'left'
    assert stamp['stamp-vertical-position'] == 'top'
    assert stamp['stamp-position'] is None
    _, overridden = ls.load_config(config, 'pades', stamp_position=(1.5, 2.5))
    assert overridden['stamp-position'] == (1.5, 2.5)
    assert config.read_bytes() == original
    assert 'horizontal_position' not in ls.DEFAULT_CONFIG.replace('stamp-horizontal-position', '')
    assert 'vertical_position' not in ls.DEFAULT_CONFIG.replace('stamp-vertical-position', '')


@pytest.mark.parametrize('setting', ['stamp-horizontal-position', 'stamp-vertical-position'])
def test_invalid_automatic_setting_is_ignored_only_with_override(tmp_path, setting):
    config = tmp_path / 'config.toml'
    config.write_text(f'[pades.stamp]\n{setting}="invalid"\n')
    with pytest.raises(ls.SetupError, match=setting):
        ls.load_config(config, 'pades')
    _, stamp = ls.load_config(config, 'pades', stamp_position=(0, 0))
    assert stamp['stamp-position'] == (0, 0)


@pytest.mark.parametrize('coordinates', [
    ['1'], ['not-a-number', '2'], ['nan', '0'], ['0', 'inf'], ['-1', '0'], ['0', '-1'],
])
def test_cli_rejects_invalid_coordinates_before_accessing_card(coordinates):
    with pytest.raises(SystemExit) as error:
        ls.main(['--stamp-position', *coordinates, '--', 'document.pdf'])
    assert error.value.code == 2


@pytest.mark.parametrize('action', [
    ['--format', 'cades'], ['--card-info'], ['--change-pin'], ['--forget-pin'],
])
def test_cli_rejects_position_outside_pades_signing(action):
    with pytest.raises(SystemExit) as error:
        ls.main([*action, '--stamp-position', '1', '2'])
    assert error.value.code == 2


@pytest.mark.parametrize('failure_index', [0, 1])
@pytest.mark.parametrize('failure_kind', ['boundary', 'page'])
def test_stamp_error_stops_batch_and_preserves_outputs(tmp_path, monkeypatch, capsys, failure_index, failure_kind):
    from contextlib import nullcontext
    import pkcs11
    import pyhanko.sign.pkcs11 as signing

    module = tmp_path / 'driver.so'
    module.touch()
    config = tmp_path / 'config.toml'
    config.write_text(ls.DEFAULT_CONFIG.replace('module = ""', f'module = "{module}"')
                      .replace('remember-pin = true', 'remember-pin = false'))
    original_config = config.read_bytes()
    monkeypatch.setattr(ls, 'config_path', lambda: config)
    monkeypatch.setattr(ls, 'prepare_stamp', lambda stamp: (None, None))
    monkeypatch.setattr(ls, 'find_token', lambda *args, **kw: SimpleNamespace(
        flags=pkcs11.TokenFlag.TOKEN_INITIALIZED, open=lambda **kw: nullcontext(object())))
    monkeypatch.setattr(ls, 'prompt_pin', lambda: 'test-pin')
    monkeypatch.setattr(ls, 'select_certificate', lambda *args: (
        b'key', SimpleNamespace(public_key=SimpleNamespace(algorithm='rsa'))))
    monkeypatch.setattr(signing, 'PKCS11Signer', lambda *args, **kw: object())
    paths = [tmp_path / f'{i}.pdf' for i in range(3)]
    for path in paths:
        path.write_bytes(b'input')
        ls.output_path(path, 'pades').write_bytes(b'previous output')
    calls = []

    def sign(source, destination, signer, stamp, font, icon):
        calls.append(destination)
        assert stamp['stamp-position'] == [5.5, 6.5]
        assert stamp['stamp-page'] == 2
        if len(calls) - 1 == failure_index:
            if failure_kind == 'page':
                ls.find_page(SimpleNamespace(root={'/Pages': {'/Count': 1}}), stamp['stamp-page'])
            ls.stamp_box((0, 0, 10, 10), 0, 30, 20, None, None,
                         position=stamp['stamp-position'])
        with ls.open_output(destination, source) as output:
            output.write(b'signed')

    monkeypatch.setattr(ls, 'sign_pdf', sign)
    assert ls.main(['--stamp-page', '2', '--stamp-position', '5.5', '6.5', '--', *map(str, paths)]) == 1
    assert len(calls) == failure_index + 1
    for index, path in enumerate(paths):
        expected = b'signed' if index < failure_index else b'previous output'
        assert ls.output_path(path, 'pades').read_bytes() == expected
        assert path.read_bytes() == b'input'
    assert config.read_bytes() == original_config
    message = 'does not fit' if failure_kind == 'boundary' else 'Stamp page 2 does not exist'
    assert message in capsys.readouterr().err


@pytest.fixture(scope='module')
def software_signer():
    from datetime import timedelta, timezone
    from asn1crypto import keys, x509 as asn1_x509
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    from pyhanko_certvalidator.registry import SimpleCertificateStore

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Placement test')])
    now = ls.datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(1)
            .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(True, True, False, False, False, False, False, False, False),
                           critical=True)
            .sign(key, hashes.SHA256()))
    return SimpleSigner(
        asn1_x509.Certificate.load(cert.public_bytes(serialization.Encoding.DER)),
        keys.PrivateKeyInfo.load(key.private_bytes(serialization.Encoding.DER,
                                                  serialization.PrivateFormat.PKCS8,
                                                  serialization.NoEncryption())),
        SimpleCertificateStore(),
    )


def placement_pdf(path, rotation):
    from pyhanko.pdf_utils import generic as pdf
    from pyhanko.pdf_utils.writer import PageObject, PdfFileWriter

    writer = PdfFileWriter()
    for _ in range(2):
        writer.insert_page(PageObject(writer.add_object(pdf.StreamObject(stream_data=b'')),
                                      (0, 0, 600, 800)))
    page, _ = writer.find_page_for_modification(1)
    page = page.get_object()
    page[pdf.pdf_name('/Rotate')] = pdf.NumberObject(rotation)
    page[pdf.pdf_name('/CropBox')] = pdf.ArrayObject([pdf.NumberObject(n) for n in (20, 30, 580, 770)])
    with path.open('wb') as output:
        writer.write(output)


@pytest.mark.parametrize('rotation', [0, 90, 180, 270])
def test_signed_pdf_places_fractional_top_left_on_selected_page(tmp_path, software_signer, rotation):
    from pyhanko.pdf_utils.reader import PdfFileReader
    from pyhanko.sign.validation import validate_pdf_signature
    from pyhanko_certvalidator import ValidationContext

    source, destination = tmp_path / 'input.pdf', tmp_path / 'signed.pdf'
    placement_pdf(source, rotation)
    config = tmp_path / 'config.toml'
    config.write_text('[pades.stamp]\nstamp-page="first"\n')
    original_config = config.read_bytes()
    _, stamp = ls.load_config(config, 'pades', stamp_position=(5.25, 13.5), stamp_page=2)
    assert stamp['stamp-page'] == 2
    assert config.read_bytes() == original_config
    font, icon = ls.prepare_stamp(stamp)
    with source.open('rb') as stream:
        ls.sign_pdf(stream, destination, software_signer, stamp, font, icon)
    with destination.open('rb') as stream:
        reader = PdfFileReader(stream)
        signature = reader.embedded_signatures[0]
        first, _ = reader.find_page_for_modification(0)
        second, _ = reader.find_page_for_modification(1)
        assert not first.get_object().get('/Annots')
        assert len(second.get_object()['/Annots']) == 1
        left, bottom, right, top = map(float, signature.sig_field['/Rect'])
        if rotation == 0:
            assert (left, top) == (25.25, 756.5)
        elif rotation == 90:
            assert (left, bottom) == (33.5, 35.25)
        elif rotation == 180:
            assert (right, bottom) == (574.75, 43.5)
        else:
            assert (right, top) == (566.5, 764.75)
        assert 20 <= left < right <= 580
        assert 30 <= bottom < top <= 770
        status = validate_pdf_signature(signature, signer_validation_context=ValidationContext(
            trust_roots=[software_signer.signing_cert], allow_fetching=False))
        assert status.intact and status.valid


@pytest.mark.parametrize('position', [(5, 739), None])
def test_real_pdf_boundary_failure_preserves_output(tmp_path, software_signer, position):
    source, destination = tmp_path / 'input.pdf', tmp_path / 'signed.pdf'
    placement_pdf(source, 0)
    destination.write_bytes(b'previous signature')
    _, stamp = ls.load_config(tmp_path / 'config.toml', 'pades', stamp_position=position)
    # A very long location makes the automatic stamp too wide to fit as well.
    if position is None:
        stamp['location'] = 'A' * 500
    font, icon = ls.prepare_stamp(stamp)
    with source.open('rb') as stream, pytest.raises(ls.StampPositionError):
        ls.sign_pdf(stream, destination, software_signer, stamp, font, icon)
    assert destination.read_bytes() == b'previous signature'
    assert not list(tmp_path.glob('.litesign-*.tmp'))


def test_missing_page_preserves_existing_output(tmp_path, software_signer):
    source, destination = tmp_path / 'input.pdf', tmp_path / 'signed.pdf'
    placement_pdf(source, 0)
    destination.write_bytes(b'previous signature')
    _, stamp = ls.load_config(tmp_path / 'config.toml', 'pades', stamp_page=3)
    font, icon = ls.prepare_stamp(stamp)
    with source.open('rb') as stream, pytest.raises(ls.StampPageError, match='Stamp page 3 does not exist'):
        ls.sign_pdf(stream, destination, software_signer, stamp, font, icon)
    assert destination.read_bytes() == b'previous signature'
    assert not list(tmp_path.glob('.litesign-*.tmp'))
