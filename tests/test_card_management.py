"""Card administration is tested with mocks, never a physical card or keyring."""
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import json
from types import SimpleNamespace

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
import keyring
import pkcs11
import pytest

import litesign as ls


OLD, NEW = "old-secret-582", "new-secret-391"
FLAGS = pkcs11.TokenFlag.TOKEN_INITIALIZED | pkcs11.TokenFlag.USER_PIN_INITIALIZED


@pytest.fixture
def card_env(tmp_path, monkeypatch):
    path = tmp_path / "config.toml"
    module = tmp_path / "driver.so"
    module.touch()
    path.write_text(ls.DEFAULT_CONFIG.replace('module = ""', f'module = "{module}"')
                    .replace('remember-pin = true', 'remember-pin = false'))
    monkeypatch.setattr(ls, "config_path", lambda: path)
    monkeypatch.setattr(keyring, "get_keyring", lambda: pytest.fail("Real keyring access"))
    state = SimpleNamespace(calls=[], prompts=[], objects={}, failure=None, close_failure=False,
                            secrets=[OLD, NEW, NEW], cached=OLD, keyring_failure=False)
    token = SimpleNamespace(label="Test card", serial=b"ABC123", manufacturer_id="Vendor",
                            model="Model", flags=FLAGS, hardware_version=(1, 0), firmware_version=(2, 1))
    slot = SimpleNamespace(slot_id=7, slot_description="Test reader", manufacturer_id="Vendor",
                           hardware_version=(1, 0), firmware_version=(1, 0), get_token=lambda: token,
                           get_mechanisms=lambda: {pkcs11.Mechanism.SHA256_RSA_PKCS})
    token.slot = slot

    def operation(*args):
        state.calls.append(args)
        if state.failure:
            raise state.failure

    session = SimpleNamespace(
        set_pin=lambda old, new: operation("set_pin", old, new),
        get_objects=lambda query: iter(state.objects.get(query[pkcs11.Attribute.CLASS], [])),
    )

    @contextmanager
    def open_session(**kwargs):
        state.calls.append(("open", kwargs))
        yield session
        if state.close_failure:
            raise RuntimeError(OLD + NEW)
        state.calls.append(("close",))

    token.open = open_session
    library = SimpleNamespace(get_tokens=lambda: state.tokens, cryptoki_version=(2, 40), library_version=(1, 0))
    monkeypatch.setattr(pkcs11, "lib", lambda path: library)

    def prompt(label):
        state.prompts.append(label)
        return state.secrets.pop(0)

    monkeypatch.setattr(ls, "prompt_secret", prompt)

    def get_password(*args):
        state.calls.append(("keyring_get",))
        return state.cached

    def set_password(service, account, password):
        state.calls.append(("keyring_set", password))
        if state.keyring_failure:
            raise RuntimeError(password)
        state.cached = password

    backend = SimpleNamespace(get_password=get_password, set_password=set_password,
                              delete_password=lambda *args: setattr(state, "cached", None))
    monkeypatch.setattr(ls, "desktop_keyring", lambda: backend)
    state.token, state.tokens, state.path = token, [token], path
    state.marker = ls.pin_cache_marker(ls.token_identity(token))
    state.configure = lambda text: path.write_text(path.read_text() + text)
    return state


def enable(state, key):
    state.path.write_text(state.path.read_text().replace(f"{key} = false", f"{key} = true"))


def test_change_pin_authenticates_as_user_and_invalidates_old_cache(card_env):
    assert ls.main(["--change-pin"]) == 0
    assert card_env.calls == [("open", {"rw": True, "user_pin": OLD}), ("set_pin", OLD, NEW), ("close",)]
    assert card_env.marker.exists()
    store = ls.PinStore(card_env.token)
    assert store.get() is None
    assert card_env.cached == OLD
    store.save(NEW)
    assert not card_env.marker.exists()
    assert store.get() == NEW


def test_change_pin_updates_keyring_only_after_card_success(card_env):
    enable(card_env, "remember-pin")
    assert ls.main(["--change-pin"]) == 0
    assert card_env.calls[-2:] == [("close",), ("keyring_set", NEW)]
    assert ls.PinStore(card_env.token).get() == NEW
    assert not card_env.marker.exists()


@pytest.mark.parametrize("flag", [pkcs11.TokenFlag.USER_PIN_LOCKED, pkcs11.TokenFlag.WRITE_PROTECTED,
                                  pkcs11.TokenFlag.PROTECTED_AUTHENTICATION_PATH])
def test_change_blocked_before_credentials(card_env, flag):
    card_env.token.flags |= flag
    assert ls.main(["--change-pin"]) == 2
    assert card_env.calls == card_env.prompts == []


@pytest.mark.parametrize("flag", [pkcs11.TokenFlag.TOKEN_INITIALIZED, pkcs11.TokenFlag.USER_PIN_INITIALIZED])
def test_no_activation_or_initial_pin_creation(card_env, flag):
    card_env.token.flags &= ~flag
    assert ls.main(["--change-pin"]) == 2
    assert card_env.calls == card_env.prompts == []


@pytest.mark.parametrize("secrets", [[OLD, NEW, "different"], [OLD, OLD, OLD]])
def test_invalid_new_pin_stops_before_card_and_cache_changes(card_env, secrets):
    card_env.secrets = secrets
    assert ls.main(["--change-pin"]) == 2
    assert card_env.calls == []
    assert not card_env.marker.exists()


def test_multiple_tokens_require_selection(card_env):
    other = SimpleNamespace(**vars(card_env.token))
    other.serial = b"different"
    other.slot = SimpleNamespace(**vars(card_env.token.slot))
    other.slot.slot_id = 9
    card_env.tokens.append(other)
    assert ls.main(["--change-pin"]) == 2
    assert card_env.prompts == []
    assert ls.main(["--change-pin", "--slot", "7"]) == 0


def test_duplicate_keyring_identity_rejected_even_with_slot(card_env):
    card_env.tokens.append(card_env.token)
    assert ls.main(["--change-pin", "--slot", "7"]) == 2
    assert card_env.calls == card_env.prompts == []


def test_replaced_card_is_not_modified(card_env):
    other = SimpleNamespace(**vars(card_env.token))
    other.serial = b"replacement"
    card_env.token.slot.get_token = lambda: other
    assert ls.main(["--change-pin"]) == 2
    assert card_env.calls == []
    assert not card_env.marker.exists()


def test_failed_cache_invalidation_prevents_card_change(card_env, monkeypatch):
    def fail(token):
        raise OSError("cannot write")
    monkeypatch.setattr(ls, "invalidate_saved_pin", fail)
    assert ls.main(["--change-pin"]) == 2
    assert card_env.calls == []


@pytest.mark.parametrize("exception", [pkcs11.exceptions.PinIncorrect, pkcs11.exceptions.PinLenRange,
                                       pkcs11.exceptions.FunctionNotSupported, RuntimeError])
def test_errors_never_retry_save_or_expose_any_credentials(card_env, capsys, exception):
    enable(card_env, "remember-pin")
    card_env.failure = exception(OLD + NEW)
    assert ls.main(["--change-pin", "--debug"]) == 2
    assert len(card_env.calls) == 2
    assert card_env.marker.exists()
    output = capsys.readouterr()
    for secret in (OLD, NEW):
        assert secret not in output.out + output.err


def test_keyring_failure_cannot_reuse_old_pin_after_success(card_env, capsys):
    enable(card_env, "remember-pin")
    card_env.keyring_failure = True
    assert ls.main(["--change-pin"]) == 0
    assert "PIN changed" in capsys.readouterr().out
    assert card_env.cached == OLD
    assert ls.PinStore(card_env.token).get() is None


def test_no_keyring_still_disables_stale_pin_reuse(card_env):
    enable(card_env, "remember-pin")
    assert ls.main(["--change-pin", "--no-keyring"]) == 0
    assert card_env.marker.exists()
    assert not any(call[0].startswith("keyring") for call in card_env.calls)


def test_cleanup_failure_reports_completed_mutation_without_retry(card_env, capsys):
    enable(card_env, "remember-pin")
    card_env.close_failure = True
    assert ls.main(["--change-pin"]) == 1
    output = capsys.readouterr()
    assert "was changed" in output.err
    assert "Do not repeat" in output.err
    assert card_env.marker.exists()
    assert len(card_env.calls) == 2
    assert NEW not in output.err


def test_info_authenticates_read_only_without_a_signing_certificate(card_env, capsys):
    assert ls.main(["--card-info"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["cards"][0]["reader"]["slot_id"] == 7
    assert data["cards"][0]["certificates"] == []
    assert card_env.calls == [("open", {"rw": False, "user_pin": OLD}), ("close",)]
    assert len(card_env.prompts) == 1


def test_info_prompts_without_using_keyring_even_when_enabled(card_env, capsys):
    enable(card_env, "remember-pin")
    assert ls.main(["--card-info"]) == 0
    json.loads(capsys.readouterr().out)
    assert card_env.calls == [("open", {"rw": False, "user_pin": OLD}), ("close",)]
    assert len(card_env.prompts) == 1


def test_info_reports_expired_certificate_and_unreadable_fields_individually(card_env, capsys):
    now = datetime.now(timezone.utc)
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Expired signer")])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(42).not_valid_before(now - timedelta(days=10))
            .not_valid_after(now - timedelta(days=1)).sign(key, hashes.SHA256()))
    attr = pkcs11.Attribute
    card_env.objects[pkcs11.ObjectClass.CERTIFICATE] = [
        {attr.ID: b"one", attr.VALUE: b"malformed"},
        {attr.ID: b"two", attr.VALUE: cert.public_bytes(serialization.Encoding.DER)},
    ]
    class PrivateKey:
        def __getitem__(self, attribute):
            assert attribute != attr.VALUE, "Must never request private key material"
            if attribute == attr.LABEL:
                return "Signing key"
            raise pkcs11.exceptions.AttributeSensitive(OLD)
    card_env.objects[pkcs11.ObjectClass.PRIVATE_KEY] = [PrivateKey()]
    assert ls.main(["--card-info"]) == 0
    data = json.loads(capsys.readouterr().out)["cards"][0]
    assert data["certificates"][0]["certificate"] == "unavailable or malformed"
    assert data["certificates"][1]["date_status"] == "expired"
    assert data["certificates"][1]["label"] == "unavailable"
    assert "Expired signer" in data["certificates"][1]["subject"]
    assert data["keys"][0]["label"] == "Signing key"
    assert data["keys"][0]["id"] == "unavailable"


@pytest.mark.parametrize("args", [
    ["--activate"], ["--card-info", "--login"], ["--unblock-pin"], ["--card-info", "input.pdf"],
    ["--login", "input.pdf"], ["--slot", "7", "input.pdf"], ["--change-pin", "--login"],
])
def test_invalid_management_arguments(args):
    with pytest.raises(SystemExit) as error:
        ls.main(args)
    assert error.value.code == 2


def test_info_does_not_fall_back_to_unauthenticated_metadata(card_env, capsys):
    def unavailable(**kwargs):
        assert kwargs == {"rw": False, "user_pin": OLD}
        raise pkcs11.exceptions.UserNotLoggedIn("hidden backend details")
    card_env.token.open = unavailable
    assert ls.main(["--card-info"]) == 2
    output = capsys.readouterr()
    assert output.out == ""
    assert len(card_env.prompts) == 1
    assert "hidden backend details" not in output.err


def test_info_lists_available_slots_then_authenticates_selected_card(card_env, capsys):
    other = SimpleNamespace(**vars(card_env.token))
    other.serial = b"SECOND"
    other.slot = SimpleNamespace(**vars(card_env.token.slot))
    other.slot.slot_id = 9
    other.slot.get_token = lambda: other
    card_env.tokens.append(other)
    assert ls.main(["--card-info"]) == 2
    output = capsys.readouterr()
    assert "Available slots: 7" in output.err
    assert "9 (" in output.err
    assert card_env.calls == card_env.prompts == []
    assert ls.main(["--card-info", "--slot", "9"]) == 0
    cards = json.loads(capsys.readouterr().out)["cards"]
    assert len(cards) == 1
    assert cards[0]["reader"]["slot_id"] == 9
    assert card_env.calls == [("open", {"rw": False, "user_pin": OLD}), ("close",)]


def test_warning_flags_are_shown_once_without_retry(card_env, capsys):
    card_env.token.flags |= pkcs11.TokenFlag.USER_PIN_FINAL_TRY
    assert ls.main(["--change-pin"]) == 0
    assert capsys.readouterr().err.count("next incorrect credential") == 1
    assert sum(call[0] == "set_pin" for call in card_env.calls) == 1


def test_info_authentication_leaves_pin_cache_untouched(card_env, capsys):
    enable(card_env, "remember-pin")
    assert ls.main(["--card-info"]) == 0
    json.loads(capsys.readouterr().out)
    assert card_env.calls == [("open", {"rw": False, "user_pin": OLD}), ("close",)]
    assert len(card_env.prompts) == 1
    assert not card_env.marker.exists()


def test_info_login_refuses_locked_pin_without_prompting(card_env):
    card_env.token.flags |= pkcs11.TokenFlag.USER_PIN_LOCKED
    assert ls.main(["--card-info"]) == 2
    assert card_env.calls == card_env.prompts == []


def test_info_login_requires_selection_with_multiple_cards(card_env):
    card_env.tokens.append(card_env.token)
    assert ls.main(["--card-info"]) == 2
    assert card_env.calls == card_env.prompts == []


def test_info_login_failure_does_not_retry_or_expose_pin(card_env, capsys):
    def rejected(**kwargs):
        card_env.calls.append(("open", kwargs))
        raise pkcs11.exceptions.PinIncorrect(OLD)
    card_env.token.open = rejected
    assert ls.main(["--card-info", "--debug"]) == 2
    assert card_env.calls == [("open", {"rw": False, "user_pin": OLD})]
    output = capsys.readouterr()
    assert OLD not in output.err + output.out
    assert not card_env.marker.exists()


def test_info_login_checks_card_identity_after_prompt(card_env):
    other = SimpleNamespace(**vars(card_env.token))
    other.serial = b"replacement"
    card_env.token.slot.get_token = lambda: other
    assert ls.main(["--card-info"]) == 2
    assert card_env.calls == []
