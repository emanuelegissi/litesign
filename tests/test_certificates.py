"""Certificate selection tests using an in-memory token session."""

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
import pkcs11
import pytest

import litesign as ls


NOW = datetime(2026, 11, 8, 12, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def fixed_clock(monkeypatch):
    class FixedDatetime(datetime):
        @classmethod
        def now(cls, tz=None):
            return NOW.astimezone(tz) if tz is not None else NOW.replace(tzinfo=None)

    monkeypatch.setattr(ls, "datetime", FixedDatetime)


@pytest.fixture(scope="module")
def certificate():
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "LiteSign test")])

    def build(start, end, serial=1):
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                .public_key(key.public_key()).serial_number(serial)
                .not_valid_before(NOW + timedelta(seconds=start))
                .not_valid_after(NOW + timedelta(seconds=end))
                .sign(key, hashes.SHA256()))
        return cert.public_bytes(serialization.Encoding.DER)

    return build


def session_with(*certificates, keys=None):
    attr = pkcs11.Attribute
    # Renewed certificates can share the same private key and object ID.
    objects = {
        pkcs11.ObjectClass.PRIVATE_KEY: keys if keys is not None else [{attr.ID: b"signing-key"}],
        pkcs11.ObjectClass.CERTIFICATE: [
            {attr.ID: b"signing-key", attr.VALUE: cert} for cert in certificates
        ],
    }
    return SimpleNamespace(get_objects=lambda query: objects[query[attr.CLASS]])


@pytest.mark.parametrize(("start", "end"), [(-60, 60), (0, 60), (-60, 0)])
def test_select_certificate_accepts_current_validity_and_boundaries(certificate, start, end):
    cert_id, selected = ls.select_certificate(session_with(certificate(start, end)), pkcs11)
    assert cert_id == b"signing-key"
    assert selected.serial_number == 1


@pytest.mark.parametrize(("start", "end"), [(-60, -1), (1, 60)])
def test_select_certificate_skips_invalid_candidate(certificate, start, end):
    session = session_with(certificate(start, end, 1), certificate(-60, 60, 2))
    _, selected = ls.select_certificate(session, pkcs11)
    assert selected.serial_number == 2


@pytest.mark.parametrize("periods", [[(-60, -1)], [(1, 60)], [(-60, -1), (1, 60)]])
def test_select_certificate_reports_no_currently_valid_candidate(certificate, periods):
    session = session_with(*(certificate(start, end) for start, end in periods))
    with pytest.raises(ls.SetupError, match="No usable, currently valid signing certificate"):
        ls.select_certificate(session, pkcs11)


def test_select_certificate_preserves_first_valid_candidate(certificate):
    session = session_with(certificate(-60, 60, 1), certificate(-30, 120, 2))
    _, selected = ls.select_certificate(session, pkcs11)
    assert selected.serial_number == 1


class KeyWithUnreadableId:
    def __init__(self, error):
        self.error = error

    def __getitem__(self, attribute):
        assert attribute == pkcs11.Attribute.ID
        raise self.error


@pytest.mark.parametrize("error_type", [
    pkcs11.exceptions.AttributeTypeInvalid, pkcs11.exceptions.AttributeSensitive,
])
@pytest.mark.parametrize("has_usable_key", [False, True])
def test_select_certificate_handles_unreadable_key_individually(
    certificate, error_type, has_usable_key,
):
    keys = [KeyWithUnreadableId(error_type())]
    if has_usable_key:
        keys.append({pkcs11.Attribute.ID: b"signing-key"})
    session = session_with(certificate(-60, 60), keys=keys)
    if has_usable_key:
        cert_id, selected = ls.select_certificate(session, pkcs11)
        assert cert_id == b"signing-key"
        assert selected.serial_number == 1
    else:
        with pytest.raises(ls.SetupError, match="No usable, currently valid signing certificate"):
            ls.select_certificate(session, pkcs11)


@pytest.mark.parametrize("error_type", [
    pkcs11.exceptions.DeviceRemoved, pkcs11.exceptions.TokenNotPresent,
    pkcs11.exceptions.PinIncorrect, pkcs11.exceptions.PinLocked,
])
def test_select_certificate_preserves_fatal_key_errors(certificate, error_type):
    session = session_with(certificate(-60, 60), keys=[
        KeyWithUnreadableId(error_type()), {pkcs11.Attribute.ID: b"signing-key"},
    ])
    with pytest.raises(error_type):
        ls.select_certificate(session, pkcs11)


def test_select_certificate_reads_each_key_id_once(certificate):
    class KeyWithCountedReads:
        reads = 0

        def __getitem__(self, attribute):
            assert attribute == pkcs11.Attribute.ID
            self.reads += 1
            return b"signing-key"

    key = KeyWithCountedReads()
    cert_id, _ = ls.select_certificate(session_with(certificate(-60, 60), keys=[key]), pkcs11)
    assert cert_id == b"signing-key"
    assert key.reads == 1
