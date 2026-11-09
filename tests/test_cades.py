"""CAdES payload checks using software-generated signatures, without a token."""

from datetime import datetime, timedelta, timezone
from io import BytesIO

from asn1crypto import cms
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import NameOID
import pytest

import litesign as ls


PAYLOAD = b"\x00\xffbinary\nwith\r\nnewlines"


@pytest.fixture(scope="module")
def signed_envelope():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "LiteSign test")])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(1)
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=1)).sign(key, hashes.SHA256()))

    def build(payload=PAYLOAD, algorithms=("sha256",)):
        builder = pkcs7.PKCS7SignatureBuilder().set_data(payload)
        for algorithm in algorithms:
            builder = builder.add_signer(cert, key, getattr(hashes, algorithm.upper())())
        encoded = builder.sign(serialization.Encoding.DER, [pkcs7.PKCS7Options.Binary])
        return cms.ContentInfo.load(encoded)

    return build


@pytest.mark.parametrize("algorithm", ["sha256", "sha384", "sha512", "sha224"])
@pytest.mark.parametrize("payload", [PAYLOAD, b""])
def test_cosign_accepts_matching_payload_and_rewinds(signed_envelope, algorithm, payload):
    source = BytesIO(signed_envelope(payload, (algorithm,)).dump())
    assert ls.cosign_digest(source) == algorithm
    assert source.tell() == 0


def test_cosign_prefers_sha256_with_multiple_algorithms(signed_envelope):
    source = BytesIO(signed_envelope(algorithms=("sha512", "sha256")).dump())
    assert ls.cosign_digest(source) == "sha256"


@pytest.mark.parametrize("algorithm", ["sha256", "sha384", "sha512", "sha224"])
def test_cosign_rejects_tampered_payload(signed_envelope, algorithm):
    envelope = signed_envelope(algorithms=(algorithm,))
    envelope["content"]["encap_content_info"]["content"] = PAYLOAD + b"modified"
    with pytest.raises(ls.FileError, match="payload does not match"):
        ls.cosign_digest(BytesIO(envelope.dump()))


@pytest.mark.parametrize("algorithms", [("sha256", "sha256"), ("sha256", "sha512")])
def test_cosign_rejects_conflicting_signer_digest(signed_envelope, algorithms):
    envelope = signed_envelope(algorithms=algorithms)
    # A good digest on another signer must not hide this mismatch.
    signer = envelope["content"]["signer_infos"][-1]
    digest = next(attr for attr in signer["signed_attrs"] if attr["type"].native == "message_digest")
    digest["values"][0] = b"\x00" * len(digest["values"][0].native)
    with pytest.raises(ls.FileError, match="payload does not match"):
        ls.cosign_digest(BytesIO(envelope.dump()))


@pytest.mark.parametrize("malformation", ["duplicate_attribute", "multiple_values", "empty_values"])
def test_cosign_rejects_ambiguous_digest_attributes(signed_envelope, malformation):
    envelope = signed_envelope()
    attributes = envelope["content"]["signer_infos"][0]["signed_attrs"]
    digest = next(attr for attr in attributes if attr["type"].native == "message_digest")
    if malformation == "duplicate_attribute":
        attributes.append(digest.copy())
    elif malformation == "multiple_values":
        digest["values"].append(digest["values"][0].native)
    else:
        digest["values"] = []
    with pytest.raises(ls.FileError, match="ambiguous or empty"):
        ls.cosign_digest(BytesIO(envelope.dump()))


def test_cosign_rejects_missing_digest_attribute(signed_envelope):
    envelope = signed_envelope()
    signer = envelope["content"]["signer_infos"][0]
    signer["signed_attrs"] = [attr for attr in signer["signed_attrs"]
                              if attr["type"].native != "message_digest"]
    with pytest.raises(ls.FileError, match="no supported digest"):
        ls.cosign_digest(BytesIO(envelope.dump()))


def test_cosign_rejects_detached_payload(signed_envelope):
    envelope = signed_envelope()
    del envelope["content"]["encap_content_info"]["content"]
    with pytest.raises(ls.FileError, match="supported attached CAdES envelope"):
        ls.cosign_digest(BytesIO(envelope.dump()))


@pytest.mark.parametrize("existing_output", [False, True])
def test_tampered_payload_rejected_before_output_or_backend(
    signed_envelope, tmp_path, monkeypatch, existing_output,
):
    envelope = signed_envelope()
    envelope["content"]["encap_content_info"]["content"] = b"tampered"
    source = tmp_path / "input.p7m"
    source.write_bytes(envelope.dump())
    destination = tmp_path / "output.p7m"
    if existing_output:
        destination.write_bytes(b"previous output")
    backend = ls.OpenSSL.__new__(ls.OpenSSL)
    backend.cert_file = tmp_path / "unused.pem"
    backend.key = "unused"
    monkeypatch.setattr(backend, "run", lambda *args, **kwargs: pytest.fail("Unexpected OpenSSL call"))
    with source.open("rb") as stream, pytest.raises(ls.FileError, match="payload does not match"):
        backend.sign(stream, destination, cosign=True)
    if existing_output:
        assert destination.read_bytes() == b"previous output"
    else:
        assert not destination.exists()


@pytest.mark.parametrize("existing_output", [False, True])
@pytest.mark.parametrize(("stderr", "error_type"), [
    (b"", None),
    (b"signing failed", ls.BackendError),
    (b"CKR_PIN_INCORRECT", ls.PinRejected),
    (b"CKR_PIN_INVALID", ls.PinRejected),
    (b"CKR_PIN_LEN_RANGE", ls.PinRejected),
    (b"CKR_PIN_LOCKED", ls.SetupError),
    (b"CKR_DEVICE_REMOVED", ls.SetupError),
    (b"failed to login", ls.SetupError),
])
def test_cades_publishes_output_only_on_backend_success(
    tmp_path, monkeypatch, existing_output, stderr, error_type,
):
    from types import SimpleNamespace

    source = tmp_path / "input.bin"
    source.write_bytes(PAYLOAD)
    destination = tmp_path / "output.p7m"
    if existing_output:
        destination.write_bytes(b"old output")
    before = set(tmp_path.iterdir())
    backend = ls.OpenSSL.__new__(ls.OpenSSL)
    backend.cert_file = tmp_path / "unused.pem"
    backend.key = "unused"

    def run(args, *, stdin, stdout):
        assert stdin.read() == PAYLOAD
        stdout.write(b"partial" if error_type else b"complete signature")
        return SimpleNamespace(returncode=1 if error_type else 0, stderr=stderr)

    monkeypatch.setattr(backend, "run", run)
    with source.open("rb") as stream:
        if error_type is not None:
            with pytest.raises(error_type) as caught:
                backend.sign(stream, destination, cosign=False)
            assert type(caught.value) is error_type
        else:
            backend.sign(stream, destination, cosign=False)
    if error_type is None:
        assert destination.read_bytes() == b"complete signature"
        assert set(tmp_path.iterdir()) == before | {destination}
    else:
        if existing_output:
            assert destination.read_bytes() == b"old output"
        else:
            assert not destination.exists()
        assert set(tmp_path.iterdir()) == before
    assert source.read_bytes() == PAYLOAD


@pytest.mark.parametrize('payload', [PAYLOAD, b''])
@pytest.mark.parametrize('encoding', ['DER', 'CMS', 'PKCS7'])
def test_extract_exact_payload_without_card_or_config(signed_envelope, tmp_path, monkeypatch, capsys, payload, encoding):
    from asn1crypto.pem import armor

    for name in ('config_path', 'load_config', 'resolve_module', 'find_token', 'prompt_pin'):
        monkeypatch.setattr(ls, name, lambda *a, **kw: pytest.fail('Unexpected card/config access'))
    source = tmp_path / 'document.bin.P7M'
    encoded = signed_envelope(payload, ('sha256', 'sha512')).dump()
    if encoding != 'DER':
        encoded = armor(encoding, encoded)
    source.write_bytes(encoded)
    assert ls.main(['--extract', str(source)]) == 0
    assert source.with_suffix('').read_bytes() == payload
    assert source.read_bytes() == encoded
    assert source.with_suffix('').stat().st_mode & 0o777 == 0o600
    assert 'Signatures not verified.' in capsys.readouterr().out
    assert not list(tmp_path.glob('.litesign-*.tmp'))


def test_extract_one_nested_layer(signed_envelope, tmp_path):
    inner = signed_envelope().dump()
    source = tmp_path / 'document.bin.p7m.p7m'
    source.write_bytes(signed_envelope(inner).dump())
    assert ls.main(['--extract', str(source)]) == 0
    assert source.with_suffix('').read_bytes() == inner
    assert not (tmp_path / 'document.bin').exists()


def test_extraction_does_not_claim_signature_validation(signed_envelope, tmp_path, capsys):
    envelope = signed_envelope()
    envelope['content']['encap_content_info']['content'] = b'changed payload'
    source = tmp_path / 'document.p7m'
    source.write_bytes(envelope.dump())
    assert ls.main(['--extract', str(source)]) == 0
    assert source.with_suffix('').read_bytes() == b'changed payload'
    assert 'Signatures not verified.' in capsys.readouterr().out


@pytest.mark.parametrize('kind', ['malformed', 'truncated', 'trailing', 'detached', 'unsigned', 'encrypted', 'wrong_type'])
def test_extraction_rejects_unsupported_input(signed_envelope, tmp_path, kind):
    envelope = signed_envelope()
    if kind == 'detached':
        del envelope['content']['encap_content_info']['content']
    elif kind == 'unsigned':
        envelope['content']['signer_infos'] = []
    elif kind == 'wrong_type':
        envelope = cms.ContentInfo({'content_type': 'data', 'content': b'plain'})
    elif kind == 'encrypted':
        envelope = cms.ContentInfo({'content_type': 'encrypted_data', 'content': {
            'version': 'v0', 'encrypted_content_info': {'content_type': 'data',
                'content_encryption_algorithm': {'algorithm': 'aes256_cbc', 'parameters': b'0' * 16},
                'encrypted_content': b'encrypted'}}})
    encoded = envelope.dump()
    if kind == 'malformed':
        encoded = b'not a CMS envelope'
    elif kind == 'truncated':
        encoded = encoded[:-10]
    elif kind == 'trailing':
        encoded += b'unexpected trailing bytes'
    source = tmp_path / 'document.p7m'
    source.write_bytes(encoded)
    assert ls.main(['--extract', str(source)]) == 1
    assert not source.with_suffix('').exists()
    assert not list(tmp_path.glob('.litesign-*.tmp'))


@pytest.mark.parametrize('kind', ['file', 'directory', 'symlink', 'dangling_symlink', 'hardlink'])
def test_extraction_never_replaces_existing_destination(signed_envelope, tmp_path, kind):
    source = tmp_path / 'document.p7m'
    original = signed_envelope().dump()
    source.write_bytes(original)
    destination = source.with_suffix('')
    if kind == 'file':
        destination.write_bytes(b'keep me')
    elif kind == 'directory':
        destination.mkdir()
    elif kind == 'symlink':
        destination.symlink_to(source)
    elif kind == 'dangling_symlink':
        destination.symlink_to(tmp_path / 'missing')
    else:
        destination.hardlink_to(source)
    before = destination.lstat()
    assert ls.main(['--extract', str(source)]) == 1
    assert destination.lstat() == before
    assert source.read_bytes() == original
    if kind == 'file':
        assert destination.read_bytes() == b'keep me'
    assert not list(tmp_path.glob('.litesign-*.tmp'))


def test_extraction_refuses_destination_created_during_publication(signed_envelope, tmp_path, monkeypatch):
    source = tmp_path / 'document.p7m'
    source.write_bytes(signed_envelope().dump())
    real_link = ls.os.link

    def concurrent_destination(temporary, destination):
        destination.write_bytes(b'created concurrently')
        return real_link(temporary, destination)

    monkeypatch.setattr(ls.os, 'link', concurrent_destination)
    assert ls.main(['--extract', str(source)]) == 1
    assert source.with_suffix('').read_bytes() == b'created concurrently'
    assert not list(tmp_path.glob('.litesign-*.tmp'))


def test_extraction_write_failure_leaves_no_output(signed_envelope, tmp_path, monkeypatch):
    source = tmp_path / 'document.p7m'
    source.write_bytes(signed_envelope().dump())

    def disk_error(fd):
        raise OSError('Disk failure')

    monkeypatch.setattr(ls.os, 'fsync', disk_error)
    assert ls.main(['--extract', str(source)]) == 1
    assert not source.with_suffix('').exists()
    assert not list(tmp_path.glob('.litesign-*.tmp'))


def test_extraction_batch_continues_after_failure(signed_envelope, tmp_path, capsys):
    missing = tmp_path / 'missing.p7m'
    skipped = tmp_path / 'notes.txt'
    good = tmp_path / 'good.txt.p7m'
    good.write_bytes(signed_envelope().dump())
    assert ls.main(['--extract', str(missing), str(skipped), str(good)]) == 1
    assert good.with_suffix('').read_bytes() == PAYLOAD
    assert '1 file extracted · 1 skipped · 1 failed.' in capsys.readouterr().out
    assert ls.main(['--extract', str(skipped)]) == 3


@pytest.mark.parametrize('options', [[], ['--overwrite'], ['--format', 'pades'], ['--format=cades'],
    ['--stamp-page', '1'], ['--stamp-position', '0', '0'], ['--slot', '0'], ['--no-keyring'],
    ['--card-info'], ['--change-pin'], ['--forget-pin']])
def test_extract_invalid_cli_combinations(options):
    arguments = ['--extract', *options]
    if options:
        arguments.append('document.p7m')
    with pytest.raises(SystemExit) as error:
        ls.main(arguments)
    assert error.value.code == 2
