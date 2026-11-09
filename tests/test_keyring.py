"""PIN storage tests: all keyring and card operations stay in memory."""

from contextlib import nullcontext
from types import SimpleNamespace

import keyring
from keyring.backend import KeyringBackend
from keyring.backends import SecretService, chainer, kwallet, null
import pkcs11
import pytest

import litesign as ls


PIN = "239876"
OLD_PIN = "814972"


@pytest.fixture(autouse=True)
def block_real_keyring(monkeypatch):
    monkeypatch.setattr(keyring, "get_keyring", lambda: pytest.fail("Unexpected desktop keyring access"))


class MemoryKeyring(KeyringBackend):
    priority = 1

    def __init__(self):
        self.values = {}
        self.calls = []
        self.fail = None

    def get_password(self, service, username):
        self.calls.append("get")
        if self.fail == "get":
            raise RuntimeError(OLD_PIN)
        return self.values.get((service, username))

    def set_password(self, service, username, password):
        self.calls.append("set")
        if self.fail == "set":
            raise RuntimeError(password)
        self.values[service, username] = password

    def delete_password(self, service, username):
        self.calls.append("delete")
        if self.fail == "delete":
            raise RuntimeError(OLD_PIN)
        del self.values[service, username]


def card(serial=b"ABC123"):
    return SimpleNamespace(serial=serial, manufacturer_id="Test vendor", model="Test card",
                           label="Signing card", flags=pkcs11.TokenFlag.TOKEN_INITIALIZED)


@pytest.fixture
def memory(monkeypatch):
    backend = MemoryKeyring()
    monkeypatch.setattr(ls, "desktop_keyring", lambda: backend)
    return backend


@pytest.mark.parametrize("backend_class", [SecretService.Keyring, kwallet.DBusKeyring,
                                           kwallet.DBusKeyringKWallet4])
def test_selects_python_keyring_desktop_backend(monkeypatch, backend_class):
    backend = backend_class()
    monkeypatch.setattr(keyring, "get_keyring", lambda: backend)
    assert ls.desktop_keyring() is backend


@pytest.mark.parametrize("backend", [null.Keyring(), MemoryKeyring()])
def test_rejects_unapproved_keyring_backend(monkeypatch, backend):
    monkeypatch.setattr(keyring, "get_keyring", lambda: backend)
    with pytest.raises(ls.SetupError, match="Desktop keyring unavailable"):
        ls.desktop_keyring()


def test_chained_backend_never_receives_credential_calls(monkeypatch):
    unapproved = MemoryKeyring()
    approved = SecretService.Keyring()
    chain = chainer.ChainerBackend()
    monkeypatch.setattr(type(chain), "backends", [unapproved, approved])
    monkeypatch.setattr(keyring, "get_keyring", lambda: chain)
    monkeypatch.setattr(approved, "get_password", lambda *args: None)
    monkeypatch.setattr(approved, "set_password", lambda *args: None)
    store = ls.PinStore(card())
    assert store.get() is None
    store.save(PIN)
    assert store.backend is approved
    assert unapproved.calls == []


def test_backend_initialization_error_is_sanitized(monkeypatch):
    def fail():
        raise RuntimeError(OLD_PIN)
    monkeypatch.setattr(keyring, "get_keyring", fail)
    with pytest.raises(ls.SetupError) as caught:
        ls.desktop_keyring()
    assert OLD_PIN not in str(caught.value)
    assert caught.value.__cause__ is None


def test_pin_store_separates_cards_and_survives_label_changes(memory):
    first, second = card(), card(b"DEF456")
    store = ls.PinStore(first)
    store.save(PIN)
    assert ls.PinStore(second).get() is None
    first.label = "Renamed"
    assert ls.PinStore(first).get() == PIN
    assert ls.PinStore(first).forget() is True
    assert ls.PinStore(first).forget() is False


@pytest.mark.parametrize("serial", [b"", b"   ", b"000000", b"\x00\x00"])
def test_missing_card_identity_disables_storage(memory, serial):
    with pytest.raises(ls.SetupError, match="no reliable identity"):
        ls.PinStore(card(serial))
    assert memory.calls == []


def test_duplicate_card_identity_rejected_before_keyring(monkeypatch):
    first, second = card(), card()
    monkeypatch.setattr(pkcs11, "lib", lambda module: SimpleNamespace(get_tokens=lambda: [first, second]))
    with pytest.raises(ls.SetupError, match="Multiple cards"):
        ls.find_token("unused", unique_identity=True)
    assert ls.find_token("unused") is first


@pytest.mark.parametrize("value", ['"true"', '1', '[]'])
def test_remember_pin_requires_boolean(tmp_path, value):
    config = tmp_path / "config.toml"
    config.write_text(f"[smartcard]\nremember-pin = {value}\n")
    with pytest.raises(ls.SetupError, match="remember-pin must be true or false"):
        ls.load_config(config, "cades")


@pytest.fixture
def batch(tmp_path, monkeypatch, memory):
    import pyhanko.sign.pkcs11 as pyhanko_pkcs11

    token = card()
    state = SimpleNamespace(events=[], login_error=None, cert_error=None, sign_error=None)
    module = tmp_path / "driver.so"
    module.touch()
    config = tmp_path / "litesign" / "config.toml"
    config.parent.mkdir()
    config.write_text(ls.DEFAULT_CONFIG.replace('module = ""', f'module = "{module}"')
                      .replace('remember-pin = false', 'remember-pin = true'))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    source = tmp_path / "input.pdf"
    source.write_bytes(b"input")

    def prompt():
        state.events.append("prompt")
        return PIN

    def login(*, user_pin):
        state.events.append(("login", user_pin))
        if state.login_error:
            raise state.login_error
        return nullcontext(object())

    def select(session, module):
        state.events.append("certificate")
        if state.cert_error:
            raise state.cert_error
        return b"key", SimpleNamespace(public_key=SimpleNamespace(algorithm="rsa"))

    def write_signature(stream, destination, *args):
        state.events.append("sign")
        with ls.open_output(destination, stream) as output:
            output.write(b"signature")
            if state.sign_error:
                raise state.sign_error

    class Backend:
        def __init__(self, *args):
            state.events.append("openssl")

        def configure_signer(self, *args):
            state.events.append("configure")

        def set_pin(self, pin):
            state.events.append(("openssl-pin", pin))

        sign = staticmethod(write_signature)

    token.open = login
    monkeypatch.setattr(ls, "find_token", lambda *args, **kwargs: token)
    monkeypatch.setattr(ls, "prompt_pin", prompt)
    monkeypatch.setattr(ls, "select_certificate", select)
    monkeypatch.setattr(ls, "prepare_stamp", lambda stamp: (None, None))
    monkeypatch.setattr(ls, "sign_pdf", write_signature)
    monkeypatch.setattr(ls, "OpenSSL", Backend)
    monkeypatch.setattr(pyhanko_pkcs11, "PKCS11Signer", lambda *args, **kwargs: object())
    state.token, state.source, state.config = token, source, config
    state.key = (ls.PinStore.service, ls.token_identity(token))
    state.run = lambda mode="pades", extra=(): ls.main(["--debug", "--format", mode, *extra, str(source)])
    return state


@pytest.mark.parametrize("mode", ["pades", "cades"])
def test_saves_authenticated_pin_and_reuses_it(batch, memory, mode, capsys):
    original_set = memory.set_password

    def save(*args):
        assert "certificate" in batch.events
        original_set(*args)

    memory.set_password = save
    assert batch.run(mode) == 0
    assert memory.values[batch.key] == PIN
    assert batch.events.count("prompt") == 1
    assert batch.run(mode) == 0
    assert batch.events.count("prompt") == 1
    assert memory.calls.count("set") == 1
    assert PIN not in batch.config.read_text()
    captured = capsys.readouterr()
    assert PIN not in captured.out + captured.err


@pytest.mark.parametrize("mode", ["pades", "cades"])
@pytest.mark.parametrize("disable", ["config", "cli"])
def test_disabled_keyring_does_not_read_or_write(batch, memory, mode, disable):
    memory.values[batch.key] = OLD_PIN
    if disable == "config":
        batch.config.write_text(batch.config.read_text().replace('remember-pin = true', 'remember-pin = false'))
    extra = ["--no-keyring"] if disable == "cli" else []
    assert batch.run(mode, extra) == 0
    assert memory.calls == []
    assert memory.values[batch.key] == OLD_PIN
    assert ("login", PIN) in batch.events


@pytest.mark.parametrize("mode", ["pades", "cades"])
@pytest.mark.parametrize("error_type", [pkcs11.exceptions.PinIncorrect, pkcs11.exceptions.PinInvalid,
                                      pkcs11.exceptions.PinLenRange])
def test_rejected_saved_pin_is_removed_without_retry(batch, memory, mode, capsys, error_type):
    memory.values[batch.key] = OLD_PIN
    batch.login_error = error_type(OLD_PIN)
    assert batch.run(mode) == 2
    assert batch.key not in memory.values
    assert batch.events.count(("login", OLD_PIN)) == 1
    assert "prompt" not in batch.events
    assert "sign" not in batch.events
    captured = capsys.readouterr()
    assert OLD_PIN not in captured.out + captured.err
    assert "Saved PIN removed" in captured.err


@pytest.mark.parametrize("error", [pkcs11.exceptions.DeviceRemoved(), pkcs11.exceptions.TokenNotPresent(),
                                   pkcs11.exceptions.PinLocked()])
def test_other_login_errors_keep_saved_pin(batch, memory, error):
    memory.values[batch.key] = OLD_PIN
    batch.login_error = error
    assert batch.run() == 2
    assert memory.values[batch.key] == OLD_PIN
    assert "delete" not in memory.calls


@pytest.mark.parametrize("error_stage", ["login_error", "cert_error"])
def test_unverified_or_unusable_pin_is_not_saved(batch, memory, error_stage):
    setattr(batch, error_stage, ls.SetupError("test failure"))
    assert batch.run() == 2
    assert "set" not in memory.calls


@pytest.mark.parametrize("operation", ["get", "set"])
def test_keyring_failure_does_not_prevent_signing_or_leak_pin(batch, memory, operation, capsys):
    memory.fail = operation
    assert batch.run() == 0
    assert "prompt" in batch.events
    assert not memory.values
    if operation == "get":
        assert "set" not in memory.calls
    captured = capsys.readouterr()
    assert PIN not in captured.out + captured.err
    assert OLD_PIN not in captured.out + captured.err


def test_unavailable_backend_falls_back_to_prompt(batch, monkeypatch):
    def unavailable():
        raise ls.SetupError("Desktop keyring unavailable.")
    monkeypatch.setattr(ls, "desktop_keyring", unavailable)
    assert batch.run() == 0
    assert "prompt" in batch.events


@pytest.mark.parametrize("flag", [pkcs11.TokenFlag.USER_PIN_COUNT_LOW, pkcs11.TokenFlag.USER_PIN_FINAL_TRY,
                                  pkcs11.TokenFlag.USER_PIN_TO_BE_CHANGED])
def test_warning_flags_require_manual_pin(batch, memory, flag):
    memory.values[batch.key] = OLD_PIN
    batch.token.flags |= flag
    assert batch.run() == 0
    assert "get" not in memory.calls
    assert ("login", PIN) in batch.events
    assert memory.values[batch.key] == PIN


def test_locked_card_does_not_read_keyring_or_attempt_login(batch, memory):
    batch.token.flags |= pkcs11.TokenFlag.USER_PIN_LOCKED
    assert batch.run() == 2
    assert memory.calls == []
    assert batch.events == []


def test_failed_eviction_stops_and_explains_bypass(batch, memory, capsys):
    memory.values[batch.key] = OLD_PIN
    memory.fail = "delete"
    batch.login_error = pkcs11.exceptions.PinIncorrect()
    assert batch.run() == 2
    assert batch.events.count(("login", OLD_PIN)) == 1
    assert "prompt" not in batch.events
    assert "--no-keyring" in capsys.readouterr().err


@pytest.mark.parametrize("mode", ["pades", "cades"])
def test_signing_pin_rejection_removes_saved_pin(batch, memory, mode):
    memory.values[batch.key] = OLD_PIN
    batch.sign_error = ls.PinRejected("Smart card PIN rejected.") if mode == "cades" else pkcs11.exceptions.PinIncorrect()
    assert batch.run(mode) == 2
    assert batch.key not in memory.values
    assert batch.events.count("sign") == 1


@pytest.mark.parametrize("present", [False, True])
def test_forget_pin_without_files_login_or_signing(batch, memory, present):
    if present:
        memory.values[batch.key] = PIN
    batch.config.write_text(batch.config.read_text().replace('remember-pin = true', 'remember-pin = false')
                            .replace('stamp-page = "last"', 'stamp-page = 0'))
    assert ls.main(["--forget-pin"]) == 0
    assert batch.key not in memory.values
    assert batch.events == []


def test_forget_pin_failure_is_reported(batch, memory, capsys):
    memory.fail = "get"
    assert ls.main(["--forget-pin"]) == 2
    assert OLD_PIN not in capsys.readouterr().err
    assert batch.events == []


@pytest.mark.parametrize("args", [[], ["--forget-pin", "input.pdf"], ["--forget-pin", "--no-keyring"]])
def test_invalid_cli_combinations(args):
    with pytest.raises(SystemExit) as caught:
        ls.main(args)
    assert caught.value.code == 2


def test_card_without_serial_falls_back_without_keyring_calls(batch, memory):
    batch.token.serial = b""
    assert batch.run() == 0
    assert memory.calls == []
    assert "prompt" in batch.events


def test_batch_reuses_pin_without_additional_keyring_reads(batch, memory, tmp_path):
    memory.values[batch.key] = PIN
    second = tmp_path / "second.pdf"
    second.write_bytes(b"input")
    assert ls.main([str(batch.source), str(second)]) == 0
    assert memory.calls == ["get"]
    assert batch.events.count(("login", PIN)) == 1
    assert batch.events.count("sign") == 2


@pytest.mark.parametrize("error", [ls.SetupError("Card removed"), ls.BackendError("Backend failed")])
def test_other_signing_errors_do_not_delete_saved_pin(batch, memory, error):
    memory.values[batch.key] = PIN
    batch.sign_error = error
    assert batch.run("cades") in (1, 2)
    assert memory.values[batch.key] == PIN
    assert "delete" not in memory.calls


def test_manual_pin_failure_is_not_saved_or_retried(batch, memory):
    batch.login_error = pkcs11.exceptions.PinIncorrect()
    assert batch.run() == 2
    assert memory.values == {}
    assert memory.calls == ["get"]
    assert batch.events.count("prompt") == 1
    assert batch.events.count(("login", PIN)) == 1


def test_cancelled_keyring_unlock_falls_back_once(batch, memory, monkeypatch):
    def locked(*args):
        raise keyring.errors.KeyringLocked("Cancelled")
    monkeypatch.setattr(memory, "get_password", locked)
    assert batch.run() == 0
    assert batch.events.count("prompt") == 1
    assert "set" not in memory.calls


@pytest.mark.parametrize('mode', ['pades', 'cades'])
def test_agent_only_can_use_saved_pin_without_prompt(batch, memory, monkeypatch, mode):
    memory.values[batch.key] = PIN
    monkeypatch.setattr(ls, 'prompt_pin', lambda: pytest.fail('Unexpected password agent request'))
    assert batch.run(mode, extra=('--agent-only',)) == 0
    assert ('login', PIN) in batch.events
