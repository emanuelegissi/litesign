#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Bulk smart-card signing, P7M extraction and PIN management for Linux."""

import argparse
from contextlib import ExitStack, contextmanager
from contextvars import ContextVar
from datetime import datetime, timezone
from getpass import GetPassWarning, getpass
import hashlib
import html
import json
from importlib.metadata import PackageNotFoundError, version
import math
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import tomllib
from urllib.parse import quote, quote_from_bytes
from uuid import uuid4
import warnings


DEFAULT_CONFIG = """
[smartcard]
module = ""
remember-pin = true

[pades.stamp]
stamp-page = "last"
stamp-vertical-position = "bottom"
stamp-horizontal-position = "right"
icon-path = "@bundled"
location = ""
reason = "Digitally signed"
"""

DIGESTS = ("sha256", "sha384", "sha512", "sha224")


class SetupError(Exception):
    """A batch-level problem."""


class PinRejected(SetupError):
    """The backend explicitly rejected the supplied PIN."""


class FileError(Exception):
    """A problem with an individual input or output."""


class StampPageError(FileError):
    """The selected stamp page does not exist and must stop the batch."""


class StampPositionError(FileError):
    """Stamp placement cannot fit and must stop the batch."""


class BackendError(FileError):
    """An OpenSSL error whose details are available in debug mode."""


def diagnostic(error, pin):
    message = str(error)
    if pin:
        # Backends may render a value literally or URI-encoded.
        encoded = "".join(
            f"(?:{re.escape(char)}|{''.join(f'%{byte:02X}' for byte in char.encode())})"
            for char in pin
        )
        message = re.sub(encoded, "[redacted]", message, flags=re.I)
    return message


_current_feedback = ContextVar("litesign_feedback", default=None)
_agent_only = ContextVar("litesign_agent_only", default=False)


class UserFeedback:
    def __init__(self):
        self.messages = []
        self.secrets = set()

    def report(self):
        message = "".join(self.messages).strip()
        for secret in sorted(self.secrets, key=len, reverse=True):
            message = diagnostic(message, secret)
        return message


def feedback(*values, sep=" ", end="\n", **kwargs):
    # Capture only application messages, never password-helper output or prompts.
    print(*values, sep=sep, end=end, **kwargs)
    current = _current_feedback.get()
    if current is not None:
        current.messages.append(sep.join(map(str, values)) + end)


def remember_secret(secret):
    current = _current_feedback.get()
    if current is not None and secret:
        current.secrets.add(secret)
    return secret


def notify_feedback(report, status):
    executable = shutil.which("notify-send")
    if not executable:
        return
    summary = {0: "Operation completed.", 1: "Operation completed with errors.",
               2: "Operation failed or was cancelled.", 3: "No files processed."}.get(status, "Operation failed.")
    body = report or summary
    if len(body) > 300 or len(body.splitlines()) > 4:
        path = None
        try:
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", prefix="litesign-",
                                             suffix=".log", delete=False) as log:
                path = Path(log.name)
                log.write(body + "\n")
        except (OSError, UnicodeError):
            if path is not None:
                path.unlink(missing_ok=True)
            print("Could not save the feedback log; see terminal output.", file=sys.stderr)
            body = summary + " Details could not be saved; see terminal output."
        else:
            print(f"Details: {path}", file=sys.stderr)
            counts = next((line for line in reversed(body.splitlines()) if re.match(
                r"(?:[0-9]+ files? (?:signed|extracted)|No files signed)\b", line)), summary)
            body = f"{counts}\nDetails: {path}"
    subprocess.run([executable, "--app-name=LiteSign",
                    "--urgency=" + ("critical" if status in (1, 2) else "normal"),
                    "--", "LiteSign", html.escape(body, quote=False)],
                   stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                   timeout=3, check=False)


def config_path():
    base = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config")
    if not base.is_absolute():
        base = Path.home() / ".config"
    return base / "litesign" / "config.toml"


def load_config(path, mode, *, stamp_position=None, stamp_page=None):
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("x", encoding="utf-8") as file:
            file.write(DEFAULT_CONFIG)
    except FileExistsError:
        pass
    # Avoid including malformed configuration values in diagnostics.
    try:
        config = tomllib.loads(path.read_text(encoding="utf-8"))
    except (ValueError, UnicodeError) as error:
        raise SetupError(f"Invalid TOML in {path}.") from error
    smartcard = config.get("smartcard", {})
    if not isinstance(smartcard, dict) or not isinstance(smartcard.get("module", ""), str):
        raise SetupError("[smartcard] module must be a path string.")

    if type(smartcard.get("remember-pin", False)) is not bool:
        raise SetupError("[smartcard] remember-pin must be true or false.")

    stamp = None
    if mode == "pades":
        pades = config.get("pades", {})
        stamp = pades.get("stamp", {}) if isinstance(pades, dict) else None
        if not isinstance(stamp, dict):
            raise SetupError("[pades.stamp] must be a TOML table.")
        stamp = tomllib.loads(DEFAULT_CONFIG)["pades"]["stamp"] | stamp
        if stamp_page is not None:
            stamp["stamp-page"] = stamp_page
        page = stamp["stamp-page"]
        if page not in ("first", "last") and not (type(page) is int and page >= 1):
            raise SetupError('stamp-page must be "first", "last" or a positive integer.')
        stamp["stamp-position"] = stamp_position
        if stamp_position is None:
            if stamp["stamp-vertical-position"] not in ("top", "center", "bottom"):
                raise SetupError("Invalid stamp-vertical-position.")
            if stamp["stamp-horizontal-position"] not in ("left", "center", "right"):
                raise SetupError("Invalid stamp-horizontal-position.")
        for key in ("icon-path", "location", "reason"):
            if not isinstance(stamp[key], str):
                raise SetupError(f"Stamp {key} must be a string.")
        icon = stamp["icon-path"]
        if icon == "@bundled":
            stamp["icon-path"] = Path(__file__).resolve().parent / "assets" / "icon.png"
        else:
            stamp["icon-path"] = asset_path(path, icon) if icon else None
    return {"module": "", "remember-pin": False} | smartcard, stamp


def asset_path(config, value):
    return (config.parent / Path(value).expanduser()).absolute()


def output_path(source, mode):
    if mode == "pades":
        return source.with_name(source.stem + "-signed" + source.suffix)
    if source.suffix.lower() == ".p7m":
        payload = Path(source.stem)
        return source.with_name(payload.stem + "-signed" + payload.suffix + source.suffix)
    return source.with_name(source.stem + "-signed" + source.suffix + ".p7m")


@contextmanager
def open_output(path, source, *, replace_existing=True):
    source_info = os.fstat(source.fileno())

    def check_destination():
        try:
            info = path.lstat()
        except FileNotFoundError:
            return None
        if not replace_existing:
            raise FileError("Output already exists; extraction never overwrites files.")
        if stat.S_ISLNK(info.st_mode):
            raise FileError("Output is a symlink.")
        if not stat.S_ISREG(info.st_mode):
            raise FileError("Output is not a regular file.")
        if os.path.samestat(info, source_info):
            raise FileError("Output refers to the current input.")
        return info

    check_destination()
    temporary = None
    try:
        # The same directory keeps replacement on the destination filesystem.
        with tempfile.NamedTemporaryFile(
            mode="w+b", prefix=".litesign-", suffix=".tmp", dir=path.parent, delete=False,
        ) as output:
            temporary = Path(output.name)
            yield output
            info = check_destination()
            if info is not None:
                os.fchmod(output.fileno(), stat.S_IMODE(info.st_mode) & 0o777)
            output.flush()
            os.fsync(output.fileno())
        check_destination()
        if replace_existing:
            os.replace(temporary, path)
        else:
            # Linking publishes the complete file atomically and fails if any
            # destination appeared after the check, including a dangling symlink.
            os.link(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def prompt_secret(label):
    executable = shutil.which("systemd-ask-password")
    agent_only = _agent_only.get()
    if agent_only and not executable:
        raise SetupError("systemd-ask-password is required for agent-only PIN entry.")
    pin = None
    if executable:
        env = dict(os.environ)
        # Do not let systemd's default "password" credential replace a fresh prompt.
        env.pop("CREDENTIALS_DIRECTORY", None)
        try:
            result = subprocess.run(
                [executable, "--echo=no", "--timeout=90",
                 *(["--no-tty", "--user"] if agent_only else []), "--", label + ":"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, timeout=95, check=False,
            )
        except FileNotFoundError:
            if agent_only:
                raise SetupError("systemd-ask-password is required for agent-only PIN entry.") from None
            pass  # The helper disappeared after discovery; use the terminal.
        except subprocess.TimeoutExpired:
            raise SetupError("Credential prompt timed out.") from None
        except OSError:
            raise SetupError("Could not start the credential prompt.") from None
        else:
            if result.returncode:
                raise SetupError("Password agent unavailable, cancelled or failed." if agent_only else
                                 "Credential prompt cancelled or failed.")
            try:
                pin = result.stdout.removesuffix(b"\n").decode("utf-8")
            except UnicodeError:
                raise SetupError("Credential prompt returned an invalid response.") from None
            if "\n" in pin or "\r" in pin:
                raise SetupError("Credential prompt returned an invalid response.")
    if pin is None:
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("error", GetPassWarning)
                pin = getpass(label + ": ")
        except (EOFError, GetPassWarning) as error:
            raise SetupError("A terminal is required to enter credentials.") from error
    if not pin:
        raise SetupError("No credential entered.")
    return remember_secret(pin)


def prompt_pin():
    return prompt_secret("Smart card PIN")


def token_identity(token):
    """A stable lookup key available before login, independent of slot and label."""
    serial = token.serial.strip(b" \x00")
    manufacturer, model = token.manufacturer_id.strip(), token.model.strip()
    if not serial or not serial.strip(b"0") or not manufacturer or not model:
        return None
    identity = json.dumps([manufacturer, model, serial.hex()], ensure_ascii=True)
    return "v1:" + hashlib.sha256(identity.encode("ascii")).hexdigest()


def desktop_keyring():
    """Select one supported backend; never delegate credential calls to a chain."""
    try:
        import keyring
        from keyring.backends.chainer import ChainerBackend

        selected = keyring.get_keyring()
        candidates = selected.backends if type(selected) is ChainerBackend else [selected]
        allowed = {
            ("keyring.backends.SecretService", "Keyring"),
            ("keyring.backends.kwallet", "DBusKeyring"),
            ("keyring.backends.kwallet", "DBusKeyringKWallet4"),
        }
        for candidate in candidates:
            cls = type(candidate)
            if (cls.__module__, cls.__name__) in allowed:
                return candidate
    except Exception:
        # Backend errors can contain credentials; never expose their details.
        pass
    raise SetupError("Desktop keyring unavailable. Install keyring and enable Secret Service or KWallet.")


def pin_cache_marker(account):
    # A non-secret tombstone survives unavailable keyrings and interrupted changes.
    return config_path().parent / "invalid-pins" / account.replace(":", "-")


def invalidate_saved_pin(token):
    account = token_identity(token)
    if account is not None:
        marker = pin_cache_marker(account)
        marker.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with marker.open("wb") as file:
            file.flush()
            os.fsync(file.fileno())
        # Persist both the marker and a newly created invalid-pins directory.
        for parent in (marker.parent, marker.parent.parent):
            directory = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)


class PinStore:
    service = "litesign.smartcard.pin"

    def __init__(self, token):
        self.account = token_identity(token)
        if self.account is None:
            raise SetupError("PIN storage unavailable: the card has no reliable identity.")
        self.backend = desktop_keyring()

    def get(self):
        try:
            if pin_cache_marker(self.account).exists():
                return None
            pin = self.backend.get_password(self.service, self.account)
            if pin is not None and not isinstance(pin, str):
                raise ValueError("Invalid credential type")
            return pin or None
        except Exception:
            raise SetupError("Cannot read the desktop keyring; enter the PIN manually.") from None

    def save(self, pin):
        try:
            self.backend.set_password(self.service, self.account, pin)
            pin_cache_marker(self.account).unlink(missing_ok=True)
        except Exception:
            raise SetupError("Could not save the PIN in the desktop keyring.") from None

    def forget(self):
        try:
            if self.backend.get_password(self.service, self.account) is None:
                pin_cache_marker(self.account).unlink(missing_ok=True)
                return False
            self.backend.delete_password(self.service, self.account)
            pin_cache_marker(self.account).unlink(missing_ok=True)
            return True
        except Exception:
            raise SetupError("Could not remove the saved PIN. Use --no-keyring until --forget-pin succeeds.") from None


def resolve_module(path, module, debug=None):
    if not module.strip():
        raise SetupError(f"PKCS#11 module is not configured. Set [smartcard].module in {path}.")
    module = asset_path(path, module)
    if debug:
        debug(f"PKCS#11 module: {module}")
    if not module.is_file():
        raise SetupError(f"PKCS#11 driver not found: {module}. Install the vendor driver or OpenSC.")
    return module


def load_token(path, module, debug=None, *, unique_identity=False):
    module = resolve_module(path, module, debug)
    if unique_identity:
        token = find_token(module, debug, unique_identity=True)
    else:
        token = find_token(module, debug)
    return module, token


def forget_pin():
    try:
        path = config_path()
        smartcard, _ = load_config(path, "cades")
        _, token = load_token(path, smartcard["module"], unique_identity=True)
        removed = PinStore(token).forget()
    except SetupError as error:
        feedback(str(error), file=sys.stderr)
        return 2
    except (Exception, KeyboardInterrupt):
        # No credential is available to redact at this point.
        feedback("Could not forget the saved PIN. Check the card, configured driver and desktop keyring.", file=sys.stderr)
        return 2
    feedback("Saved PIN removed." if removed else "No saved PIN for this card.")
    return 0


def info_value(read):
    """Read independent metadata fields without exposing backend error text."""
    try:
        value = read()
        if isinstance(value, bytes):
            return value.hex()
        if isinstance(value, (set, frozenset)):
            return sorted(value)
        return getattr(value, "name", value)
    except Exception:
        return "unavailable"


def card_information(token, session, pkcs11):
    from asn1crypto import x509

    result = {name: info_value(lambda name=name: getattr(token, name)) for name in (
        "label", "serial", "manufacturer_id", "model", "hardware_version", "firmware_version",
    )}
    result["reader"] = {name: info_value(lambda name=name: getattr(token.slot, name)) for name in (
        "slot_id", "slot_description", "manufacturer_id", "hardware_version", "firmware_version",
    )}
    result["reader"]["flags"] = info_value(lambda: [flag.name for flag in pkcs11.SlotFlag if token.slot.flags & flag])
    result["flags"] = info_value(lambda: [flag.name for flag in pkcs11.TokenFlag if token.flags & flag])
    result["mechanisms"] = info_value(lambda: sorted(getattr(m, "name", hex(m)) for m in token.slot.get_mechanisms()))
    result["notes"] = (
        "Only metadata exposed by the driver in this session is shown. Unset warning flags "
        "do not guarantee remaining PIN attempts. Exact retry counts, PIN length limits, "
        "memory statistics and card clock are unavailable through this Python interface. "
        "Certificate date status does not validate signatures, trust or revocation."
    )
    if session is None:
        result["objects"] = "unavailable"
        return result
    attr = pkcs11.Attribute
    certificates = []
    try:
        for obj in session.get_objects({attr.CLASS: pkcs11.ObjectClass.CERTIFICATE}):
            item = {"label": info_value(lambda: obj[attr.LABEL]),
                    "id": info_value(lambda: obj[attr.ID])}
            certificates.append(item)
            try:
                cert = x509.Certificate.load(bytes(obj[attr.VALUE]))
                validity = cert["tbs_certificate"]["validity"]
                start, end = validity["not_before"].native, validity["not_after"].native
                now = datetime.now(timezone.utc)
                item.update({
                    "subject": info_value(lambda: cert.subject.human_friendly),
                    "issuer": info_value(lambda: cert.issuer.human_friendly),
                    "serial": info_value(lambda: str(cert.serial_number)),
                    "not_before": start.isoformat(), "not_after": end.isoformat(),
                    "date_status": "not yet valid" if now < start else "expired" if now > end else "valid",
                    "sha256": hashlib.sha256(cert.dump()).hexdigest(),
                    "public_key_algorithm": info_value(lambda: cert.public_key.algorithm),
                    "public_key_bits": info_value(lambda: cert.public_key.bit_size),
                    "key_usage": info_value(lambda: cert.key_usage_value.native if cert.key_usage_value else None),
                    "extended_key_usage": info_value(lambda: cert.extended_key_usage_value.native if cert.extended_key_usage_value else None),
                })
            except Exception:
                item["certificate"] = "unavailable or malformed"
    except Exception:
        result["certificate_enumeration"] = "incomplete or unavailable"
    result["certificates"] = certificates
    keys = []
    for kind in (pkcs11.ObjectClass.PUBLIC_KEY, pkcs11.ObjectClass.PRIVATE_KEY):
        try:
            for obj in session.get_objects({attr.CLASS: kind}):
                # Never request key material; unsupported attributes fail independently.
                item = {"class": kind.name}
                for name in ("LABEL", "ID", "KEY_TYPE", "MODULUS_BITS", "SIGN", "DECRYPT",
                             "SENSITIVE", "EXTRACTABLE", "ALWAYS_AUTHENTICATE"):
                    item[name.lower()] = info_value(lambda name=name: obj[getattr(attr, name)])
                keys.append(item)
        except Exception:
            result[kind.name.lower() + "_enumeration"] = "incomplete or unavailable"
    result["keys"] = keys
    return result


def management_target(token):
    return (token.slot.slot_id, token.manufacturer_id, token.model, token.serial, token.label)


def check_management_flags(token, pkcs11, *, warn=True):
    flags = token.flags
    flag = pkcs11.TokenFlag
    if not flags & flag.TOKEN_INITIALIZED or not flags & flag.USER_PIN_INITIALIZED:
        raise SetupError("Card or user PIN is not initialized. Activation is not supported.")
    if flags & flag.WRITE_PROTECTED:
        raise SetupError("The card is write protected.")
    if flags & flag.PROTECTED_AUTHENTICATION_PATH:
        raise SetupError("PIN management through a reader PIN pad is not supported. Use the vendor tool.")
    if flags & flag.USER_PIN_LOCKED:
        raise SetupError("User PIN is locked. Use the vendor tool.")
    if warn and flags & flag.USER_PIN_FINAL_TRY:
        feedback("Warning: the next incorrect credential may lock this card credential.", file=sys.stderr)
    elif warn and flags & flag.USER_PIN_COUNT_LOW:
        feedback("Warning: the card reports previous incorrect credential attempts.", file=sys.stderr)


def manage_card(args):
    changed = False
    attempted = False
    try:
        import pkcs11

        path = config_path()
        smartcard, _ = load_config(path, "cades")
        module = resolve_module(path, smartcard["module"])
        library = pkcs11.lib(str(module))
        tokens = list(library.get_tokens())
        selected = [token for token in tokens if args.slot is None or token.slot.slot_id == args.slot]
        if not selected:
            raise SetupError("No card found in the selected slot." if args.slot is not None else "Smart card not found.")
        if len(selected) != 1:
            choices = ", ".join(f"{token.slot.slot_id} ({token.label!r})" for token in selected)
            raise SetupError(f"Multiple cards found. Select --slot before entering credentials. Available slots: {choices}.")
        if args.card_info:
            token = selected[0]
            feedback(f"Reading slot {token.slot.slot_id}: {token.label!r}, serial {token.serial!r}", file=sys.stderr)
            if token.flags & pkcs11.TokenFlag.USER_PIN_LOCKED:
                raise SetupError("User PIN is locked.")
            if token.flags & (pkcs11.TokenFlag.USER_PIN_COUNT_LOW | pkcs11.TokenFlag.USER_PIN_FINAL_TRY):
                feedback("Warning: the card reports limited PIN attempts.", file=sys.stderr)
            identity = management_target(token)
            pin = remember_secret(prompt_pin())
            token = token.slot.get_token()
            if management_target(token) != identity:
                raise SetupError("The selected card changed. Run the command again.")
            if token.flags & pkcs11.TokenFlag.USER_PIN_LOCKED:
                raise SetupError("User PIN is locked.")
            with token.open(rw=False, user_pin=pin) as session:
                reports = [card_information(token, session, pkcs11)]
            feedback(json.dumps({"module": str(module),
                              "cryptoki_version": info_value(lambda: library.cryptoki_version),
                              "library_version": info_value(lambda: library.library_version),
                              "library_description": info_value(lambda: library.library_description),
                              "manufacturer_id": info_value(lambda: library.manufacturer_id),
                              "cards": reports}, indent=2))
            return 0

        token = selected[0]
        account = token_identity(token)
        if account and sum(token_identity(other) == account for other in tokens) != 1:
            raise SetupError("Multiple cards share the same keyring identity. Connect only the selected card.")
        identity = management_target(token)
        feedback(f"Selected slot {token.slot.slot_id}: {token.label!r}, serial {token.serial!r}", file=sys.stderr)
        check_management_flags(token, pkcs11)
        old_pin = remember_secret(prompt_secret("Current smart card PIN"))
        new = remember_secret(prompt_secret("New smart card PIN"))
        if new != remember_secret(prompt_secret("Confirm new smart card PIN")):
            raise SetupError("New PIN entries do not match. The card was not changed.")
        if old_pin == new:
            raise SetupError("The new PIN must differ from the current PIN.")
        # Recheck identity and flags after the user has spent time at the prompts.
        token = token.slot.get_token()
        if management_target(token) != identity:
            raise SetupError("The selected card changed. Run the command again.")
        check_management_flags(token, pkcs11, warn=False)
        invalidate_saved_pin(token)
        feedback("Saved PIN reuse is disabled until the new PIN is saved after success or authentication.", file=sys.stderr)
        attempted = True
        with token.open(rw=True, user_pin=old_pin) as session:
            session.set_pin(old_pin, new)
            changed = True
        feedback("Smart card PIN changed.")
        if smartcard["remember-pin"] and not args.no_keyring:
            try:
                PinStore(token).save(new)
            except Exception:
                feedback("The card was changed, but the new PIN could not be saved. Saved PIN reuse remains disabled; enter the new PIN when signing.", file=sys.stderr)
        return 0
    except (Exception, KeyboardInterrupt) as error:
        if changed:
            feedback("The card PIN was changed, but session cleanup failed. Saved PIN reuse remains disabled. Do not repeat the change; use the new PIN.", file=sys.stderr)
            return 1
        messages = {
            "ModuleNotFoundError": "A required Python dependency is missing. Install requirements.txt.",
            "PinIncorrect": "Credential rejected; no retry was attempted.",
            "PinInvalid": "Credential rejected; no retry was attempted.",
            "PinLenRange": "The PIN does not satisfy the card's length policy.",
            "PinLocked": "The card credential is locked.",
            "FunctionNotSupported": "The middleware does not support this operation. Use the vendor tool.",
            "TokenWriteProtected": "The card is write protected.",
            "KeyboardInterrupt": "Card management cancelled.",
        }
        # No backend exception messages or tracebacks, including in --debug: drivers
        # may echo the old or new PIN in their diagnostics.
        message = str(error) if isinstance(error, SetupError) else messages.get(
            type(error).__name__, "Card management failed. Check the card and middleware.")
        feedback(message, file=sys.stderr)
        if attempted:
            feedback("No automatic retry was made. Saved PIN reuse is disabled. If the card disconnected, check its state before repeating the operation.", file=sys.stderr)
        return 2


def select_certificate(session, pkcs11):
    from asn1crypto import x509

    attr = pkcs11.Attribute
    now = datetime.now(timezone.utc)
    keys = set()
    for key in session.get_objects({
        attr.CLASS: pkcs11.ObjectClass.PRIVATE_KEY, attr.SIGN: True,
    }):
        try:
            key_id = bytes(key[attr.ID])
        except (ValueError, TypeError, pkcs11.exceptions.AttributeTypeInvalid,
                pkcs11.exceptions.AttributeSensitive):
            continue
        if key_id:
            keys.add(key_id)
    for obj in session.get_objects({attr.CLASS: pkcs11.ObjectClass.CERTIFICATE}):
        try:
            cert_id = bytes(obj[attr.ID])
            if cert_id not in keys:
                continue
            cert = x509.Certificate.load(bytes(obj[attr.VALUE]))
            validity = cert["tbs_certificate"]["validity"]
            if not validity["not_before"].native <= now <= validity["not_after"].native:
                continue
            usage = cert.key_usage_value
            if usage is None or usage.native & {"digital_signature", "non_repudiation"}:
                return cert_id, cert
        except (ValueError, TypeError, pkcs11.exceptions.AttributeTypeInvalid,
                pkcs11.exceptions.AttributeSensitive):
            continue
    raise SetupError("No usable, currently valid signing certificate found on the smart card.")


def find_page(writer, selector):
    page_index = -1 if selector == "last" else 0 if selector == "first" else selector - 1
    page_count = writer.root["/Pages"]["/Count"]
    if page_count <= 0 or page_index >= page_count:
        raise StampPageError(f"Stamp page {selector} does not exist in this PDF ({page_count} pages).")
    page_ref, _ = writer.find_page_for_modification(page_index)

    props = {}
    node = page_ref.get_object()
    while node is not None:
        for key in ("/MediaBox", "/CropBox", "/Rotate"):
            if key in node and key not in props:
                props[key] = node[key]
        node = node.get("/Parent")
        if node is not None:
            node = node.get_object()
    media = [float(value) for value in props["/MediaBox"]]
    crop = [float(value) for value in props.get("/CropBox", media)]
    bounds = (max(crop[0], media[0]), max(crop[1], media[1]),
              min(crop[2], media[2]), min(crop[3], media[3]))
    return page_index, bounds, int(props.get("/Rotate", 0)) % 360


def stamp_box(bounds, rotation, width, height, horizontal, vertical, *, position=None):
    left, bottom, right, top = bounds
    raw_width, raw_height = right - left, top - bottom
    page_width, page_height = (raw_height, raw_width) if rotation in (90, 270) else (
        raw_width, raw_height
    )
    if not all(math.isfinite(value) for value in (*bounds, width, height)) or not (
        page_width > 0 and page_height > 0 and width > 0 and height > 0
    ):
        raise StampPositionError("Invalid page or stamp dimensions.")
    if position is None:
        inset = 12
        if not (width <= page_width - 2 * inset and height <= page_height - 2 * inset):
            raise StampPositionError("The stamp does not fit on the selected page with its 12-point margin.")
        x = {"left": inset, "center": (page_width - width) / 2,
             "right": page_width - width - inset}[horizontal]
        y = {"bottom": inset, "center": (page_height - height) / 2,
             "top": page_height - height - inset}[vertical]
    else:
        x, top_offset = position
        if not (math.isfinite(x) and math.isfinite(top_offset) and x >= 0 and top_offset >= 0
                and x + width <= page_width and top_offset + height <= page_height):
            raise StampPositionError(
                f"Stamp at ({x:g}, {top_offset:g}) with size {width:g} x {height:g} "
                f"does not fit on the selected page ({page_width:g} x {page_height:g})."
            )
        # Convert the displayed top-left position to displayed bottom-left coordinates.
        y = page_height - top_offset - height
    if rotation == 90:
        box = (raw_width - y - height, x, raw_width - y, x + width)
    elif rotation == 180:
        box = (raw_width - x - width, raw_height - y - height,
               raw_width - x, raw_height - y)
    elif rotation == 270:
        box = (y, raw_height - x - width, y + height, raw_height - x)
    elif rotation == 0:
        box = (x, y, x + width, y + height)
    else:
        raise FileError("Unsupported PDF page rotation.")
    x0, y0, x1, y1 = box
    if position is not None:
        return (x0 + left, y0 + bottom, x1 + left, y1 + bottom)
    return (math.ceil(x0 + left), math.ceil(y0 + bottom),
            math.floor(x1 + left), math.floor(y1 + bottom))


def stamp_art(font, icon, stamp, name, date):
    from PIL import Image, ImageDraw
    from textwrap import wrap

    scale = 3
    lines = wrap(stamp["reason"], width=38) + wrap(name, width=38)
    location = " ".join(stamp["location"].split())
    lines.append(f"{location}, {date}" if location else date)
    line_height = 12 * scale
    padding = 6 * scale
    # Measure visible glyph bounds while keeping a consistent baseline spacing.
    bounds = [font.getbbox(line, anchor="ls") for line in lines]
    text_top = min(box[1] + index * line_height for index, box in enumerate(bounds))
    text_bottom = max(box[3] + index * line_height for index, box in enumerate(bounds))
    text_height = text_bottom - text_top
    height = max((12 + 12 * len(lines)) * scale, text_height + 2 * padding)
    text_y = (height - text_height) // 2 - text_top
    if icon is not None:
        ink_bounds = icon.getchannel("A").getbbox()
        icon = icon.crop(ink_bounds) if ink_bounds else None
    if icon is not None:
        icon_width = max(1, round(icon.width * text_height / icon.height))
        icon = icon.resize((icon_width, text_height), Image.Resampling.LANCZOS)
        text_x = max(28 * scale, icon.width + 2 * padding)
    else:
        text_x = padding
    width = text_x + math.ceil(max(font.getlength(line) for line in lines)) + padding
    image = Image.new("RGBA", (width, height))
    draw = ImageDraw.Draw(image)
    draw.rounded_rectangle(
        (0, 0, width - 1, height - 1), radius=5 * scale,
        fill="white", outline="#abb2b9", width=2,
    )
    if icon:
        image.alpha_composite(icon, ((text_x - icon.width) // 2, (height - icon.height) // 2))
    for index, line in enumerate(lines):
        draw.text((text_x, text_y + index * line_height), line, fill="#27313a",
                  font=font, anchor="ls")
    return image


def prepare_stamp(stamp):
    from PIL import Image, ImageFont

    for family in ("DejaVuSans.ttf", "NotoSans-Regular.ttf", "LiberationSans-Regular.ttf"):
        try:
            font = ImageFont.truetype(family, 27)
            break
        except OSError:
            continue
    else:
        font = ImageFont.load_default(size=27)
    icon = None
    if stamp["icon-path"]:
        try:
            with Image.open(stamp["icon-path"], formats=["PNG"]) as image:
                icon = image.convert("RGBA")
        except (OSError, ValueError, Image.DecompressionBombError) as error:
            raise SetupError("The configured stamp icon must be a readable PNG.") from error
    return font, icon


def sign_pdf(source, destination, signer, stamp, font, icon):
    from pyhanko.pdf_utils.images import PdfImage
    from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
    from pyhanko.pdf_utils.layout import AxisAlignment, BoxConstraints, Margins, SimpleBoxLayoutRule
    from pyhanko.pdf_utils.misc import PdfError
    from pyhanko.sign.fields import FieldMDPAction, MDPPerm, SigFieldSpec, SigSeedSubFilter
    from pyhanko.sign.signers import PdfSignatureMetadata, PdfSigner
    from pyhanko.stamp import StaticStampStyle

    try:
        writer = IncrementalPdfFileWriter(source, strict=False)
    except PdfError as error:
        raise FileError(f"Cannot read PDF: {error}") from error
    for previous in writer.prev.embedded_signatures:
        lock = previous.fieldmdp
        if previous.docmdp_level == MDPPerm.NO_CHANGES or (
            lock is not None and lock.action in (FieldMDPAction.ALL, FieldMDPAction.EXCLUDE)
        ):
            raise FileError("Existing PDF signature permissions prevent adding a field.")

    page_index, bounds, rotation = find_page(writer, stamp["stamp-page"])
    subject = signer.signing_cert.subject.native
    name = subject.get("common_name") or signer.signing_cert.subject.human_friendly
    if isinstance(name, list):
        name = name[0]
    date = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M %Z")
    image = stamp_art(font, icon, stamp, name, date)
    box = stamp_box(bounds, rotation, math.ceil(image.width / 3), math.ceil(image.height / 3),
                    stamp["stamp-horizontal-position"], stamp["stamp-vertical-position"],
                    position=stamp.get("stamp-position"))
    image = image.rotate(rotation, expand=True)
    style = StaticStampStyle(
        border_width=0,
        background=PdfImage(image, box=BoxConstraints(box[2] - box[0], box[3] - box[1])),
        background_layout=SimpleBoxLayoutRule(AxisAlignment.ALIGN_MID, AxisAlignment.ALIGN_MID, margins=Margins()),
    )
    field = "LiteSign-" + uuid4().hex
    metadata = PdfSignatureMetadata(
        field_name=field, md_algorithm="sha256", subfilter=SigSeedSubFilter.PADES,
        location=stamp["location"] or None, reason=stamp["reason"] or None,
    )
    pdf_signer = PdfSigner(metadata, signer, stamp_style=style,
                           new_field_spec=SigFieldSpec(field, on_page=page_index, box=box))
    with open_output(destination, source) as output:
        pdf_signer.sign_pdf(writer, output=output)


def cosign_digest(source):
    from asn1crypto import cms

    try:
        envelope = cms.ContentInfo.load(source.read(), strict=True)
        if envelope["content_type"].native != "signed_data":
            raise ValueError("Expected SignedData.")
        data = envelope["content"]
        payload = data["encap_content_info"]["content"].native
        if payload is None:
            raise ValueError("Missing attached payload.")
        algorithms = {}
        # OpenSSL -resign reuses an existing digest without hashing the payload.
        # Check every supported candidate, including signers sharing an algorithm.
        for signer in data["signer_infos"]:
            digest = signer["digest_algorithm"]["algorithm"].native
            if digest not in DIGESTS:
                continue
            attributes = [attr for attr in signer["signed_attrs"]
                          if attr["type"].native == "message_digest"]
            if not attributes:
                continue
            if len(attributes) != 1 or len(attributes[0]["values"]) != 1:
                raise FileError("CAdES signer has an ambiguous or empty message digest attribute.")
            if digest not in algorithms:
                algorithms[digest] = hashlib.new(digest, payload).digest()
            if attributes[0]["values"][0].native != algorithms[digest]:
                raise FileError("CAdES payload does not match an existing signer's message digest.")
    except (TypeError, ValueError, KeyError) as error:
        raise FileError("Input is not a supported attached CAdES envelope.") from error
    for digest in DIGESTS:
        if digest in algorithms:
            source.seek(0)
            return digest
    raise FileError("CAdES envelope has no supported digest for co-signing.")


def attached_payload(source):
    from asn1crypto import cms, pem

    try:
        encoded = source.read()
        if pem.detect(encoded):
            label, _, encoded = pem.unarmor(encoded)
            if label not in ("CMS", "PKCS7"):
                raise ValueError("Unsupported PEM label.")
        envelope = cms.ContentInfo.load(encoded, strict=True)
        if envelope["content_type"].native != "signed_data":
            raise ValueError("Expected SignedData.")
        data = envelope["content"].native
        payload = data["encap_content_info"]["content"]
        if payload is None:
            raise FileError("Detached signature has no embedded content to extract.")
        if not isinstance(payload, bytes) or not data["signer_infos"]:
            raise ValueError("Expected signed binary content.")
        return payload
    except (TypeError, ValueError, KeyError, IndexError) as error:
        raise FileError("Input is not a supported attached CMS SignedData envelope.") from error


def run_extraction(args):
    extracted = skipped = failed = 0
    stopped = False
    try:
        import asn1crypto  # noqa: F401

        for source_path in args.paths:
            if source_path.suffix.lower() != ".p7m":
                skipped += 1
                if args.debug:
                    feedback(f"Skipped {source_path}: not a P7M path.", file=sys.stderr)
                continue
            try:
                if not source_path.is_file():
                    raise FileError("Input is missing or is not a regular file.")
                destination = source_path.with_suffix("")
                with source_path.open("rb") as source:
                    with open_output(destination, source, replace_existing=False) as output:
                        output.write(attached_payload(source))
                extracted += 1
                feedback(f"Extracted {source_path} → {destination}")
            except (OSError, FileError) as error:
                failed += 1
                feedback(f"{source_path}: {error}", file=sys.stderr)
                if args.debug and error.__cause__ is not None:
                    feedback(f"DEBUG: {error.__cause__}", file=sys.stderr)
    except (ImportError, KeyboardInterrupt) as error:
        stopped = True
        message = ("Extraction cancelled." if isinstance(error, KeyboardInterrupt) else
                   "Install Python dependencies with: python -m pip install -r requirements.txt")
        feedback(message, file=sys.stderr)
    parts = [f"{extracted} {'file' if extracted == 1 else 'files'} extracted"]
    parts.extend(f"{count} {label}" for label, count in (("skipped", skipped), ("failed", failed)) if count)
    feedback(" · ".join(parts) + ".")
    if extracted:
        feedback("Signatures not verified.")
    if stopped:
        return 1 if extracted or failed else 2
    if failed:
        return 1
    return 0 if extracted else 3


class OpenSSL:
    def __init__(self, stack, module, debug):
        self.exe = shutil.which("openssl")
        if not self.exe:
            raise SetupError("Install OpenSSL 3 with your distribution's package manager.")
        self.pin_fd = os.memfd_create("litesign-pin", os.MFD_CLOEXEC)
        stack.callback(os.close, self.pin_fd)
        self.directory = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="litesign-")))
        conf = self.directory / "openssl.cnf"
        conf.write_text(f"""openssl_conf = litesign_init
[litesign_init]
providers = litesign_providers
[litesign_providers]
default = default_sect
pkcs11 = pkcs11_sect
[default_sect]
activate = 1
[pkcs11_sect]
activate = 1
pkcs11-module-token-pin = file:/proc/self/fd/{self.pin_fd}
pkcs11-module-quirks = no-deinit
""", encoding="utf-8")
        # The provider is used in short-lived child processes. no-deinit avoids
        # shutdown-order crashes with modules that also depend on OpenSSL.
        self.env = dict(os.environ, OPENSSL_CONF=str(conf), PKCS11_PROVIDER_MODULE=str(module))
        self.env.pop("PKCS11_PROVIDER_DEBUG", None)
        debug(f"OpenSSL executable: {self.exe}")
        debug("Checking OpenSSL default and PKCS#11 providers.")
        result = self.run(["list", "-providers"], stdout=subprocess.PIPE)
        if result.returncode or not re.search(rb"(?m)^  pkcs11\s*$", result.stdout):
            raise SetupError(
                "Install the OpenSSL 3 pkcs11-provider package and ensure OpenSSL can load it. "
                + result.stderr.decode(errors="replace").strip()
            )

        for line in result.stdout.decode(errors="replace").splitlines():
            debug(line)

    def set_pin(self, pin):
        with os.fdopen(os.dup(self.pin_fd), "wb") as secret:
            secret.write(pin.encode() + b"\n")

    def run(self, args, *, stdin=subprocess.DEVNULL, stdout):
        return subprocess.run(
            [self.exe, *args, "-provider", "default", "-provider", "pkcs11"],
            stdin=stdin, stdout=stdout, stderr=subprocess.PIPE, env=self.env,
            pass_fds=(self.pin_fd,), check=False,
        )

    def configure_signer(self, token, cert_id, cert):
        from asn1crypto.pem import armor

        self.cert_file = self.directory / "signer.pem"
        self.cert_file.write_bytes(armor("CERTIFICATE", cert.dump()))
        serial = quote_from_bytes(token.serial.strip(), safe="")
        label = quote(token.label, safe="")
        key_id = "".join(f"%{byte:02X}" for byte in cert_id)
        self.key = f"pkcs11:token={label};serial={serial};id={key_id};type=private"

    def sign(self, source, destination, cosign):
        digest = cosign_digest(source) if cosign else "sha256"
        operation = ["-resign", "-inform", "DER"] if cosign else ["-sign", "-nodetach"]
        command = ["cms", *operation, "-cades", "-binary", "-outform", "DER",
                   "-md", digest, "-signer", str(self.cert_file), "-inkey", self.key]
        with open_output(destination, source) as output:
            result = self.run(command, stdin=source, stdout=output)
            if result.returncode:
                details = result.stderr.decode(errors="replace").strip()
                if re.search(r"\bCKR_PIN_(INCORRECT|INVALID|LEN_RANGE)\b", details, re.I):
                    raise PinRejected("Smart card PIN rejected.") from BackendError(details)
                if re.search(r"CKR_(PIN_LOCKED|TOKEN_NOT_PRESENT|DEVICE_REMOVED)|"
                             r"failed to login|no matching token", details, re.I):
                    raise SetupError("Smart card unavailable or PIN rejected. " + details)
                raise BackendError(details or f"OpenSSL exited with status {result.returncode}.")


def find_token(module, debug=None, *, unique_identity=False):
    import pkcs11

    try:
        library = pkcs11.lib(str(module))
    except (pkcs11.PKCS11Error, OSError) as error:
        raise SetupError("Cannot load the PKCS#11 driver. Check the module path and its dependencies.") from error
    tokens = list(library.get_tokens())
    if debug:
        driver_version = ".".join(map(str, library.library_version))
        debug(f"PKCS#11 driver version: {driver_version}. Tokens visible: {len(tokens)}.")
        for item in tokens:
            debug(f"Slot {item.slot.slot_id}: reader={item.slot.slot_description!r}, "
                  f"token={item.label!r}, manufacturer={item.manufacturer_id!r}, "
                  f"model={item.model!r}, flags={item.flags!r}")
    # SoftHSM and some middleware expose uninitialised slots as tokens.
    token = next((item for item in tokens if item.flags & pkcs11.TokenFlag.TOKEN_INITIALIZED), None)
    if token is None:
        raise SetupError("Smart card not found.")
    if unique_identity:
        identity = token_identity(token)
        if identity is not None and sum(
            item.flags & pkcs11.TokenFlag.TOKEN_INITIALIZED and token_identity(item) == identity
            for item in tokens
        ) > 1:
            raise SetupError("Multiple cards share the same identity. Use one signing card at a time.")
    if debug:
        debug(f"Selected token {token.label!r} in slot {token.slot.slot_id}.")
    return token


def report(signed, skipped, failed):
    parts = [f"{signed} {'file' if signed == 1 else 'files'} signed" if signed else "No files signed"]
    parts.extend(f"{count} {label}" for label, count in (("skipped", skipped), ("failed", failed)) if count)
    feedback(" · ".join(parts) + ".")


def run_batch(args):
    signed = skipped = failed = 0
    stopped = False
    pin = None
    sign = None
    pin_store = None
    saved_pin_in_use = False
    pin_errors = ()

    def debug(message):
        if args.debug:
            feedback(diagnostic(f"DEBUG: {message}", pin), file=sys.stderr, flush=True)

    def log_error(message, error=None):
        feedback(diagnostic(message, pin), file=sys.stderr)
        if args.debug and error is not None:
            feedback(diagnostic(f"{type(error).__name__}: {error}", pin), file=sys.stderr)
            if error.__cause__ is not None:
                cause = error.__cause__
                feedback(diagnostic(f"Caused by {type(cause).__name__}: {cause}", pin), file=sys.stderr)

    try:
        path = config_path()
        debug(f"Python {platform.python_version()} on {platform.system()} {platform.machine()}")
        debug(f"Mode: {args.format.upper()}. Batch size: {len(args.paths)}")
        debug(f"Configuration file: {path}")
        smartcard, stamp = load_config(
            path, args.format, stamp_position=args.stamp_position, stamp_page=args.stamp_page,
        )
        module = resolve_module(path, smartcard["module"], debug if args.debug else None)
        remember_pin = smartcard["remember-pin"] and not args.no_keyring
        if stamp is not None:
            placement = (f"position={stamp['stamp-position']}" if stamp["stamp-position"] is not None else
                         f"horizontal={stamp['stamp-horizontal-position']}, vertical={stamp['stamp-vertical-position']}")
            debug(f"Stamp: page={stamp['stamp-page']!r}, {placement}, icon={stamp['icon-path'] or 'disabled'}")
        with ExitStack() as stack:
            for source_path in args.paths:
                debug(f"Input: {source_path}")
                if args.format == "pades" and source_path.suffix.lower() != ".pdf":
                    skipped += 1
                    if args.debug:
                        feedback(diagnostic(f"Skipped {source_path}: not a PDF path.", pin), file=sys.stderr)
                    continue
                try:
                    if not source_path.is_file():
                        raise FileError("Input is missing or is not a regular file.")
                    source = source_path.open("rb", buffering=0)
                except (OSError, FileError) as error:
                    failed += 1
                    log_error(f"{source_path}: {error}")
                    continue

                with source:
                    destination = output_path(source_path, args.format)
                    debug(f"Output: {destination}")
                    if sign is None:
                        try:
                            import pkcs11
                            pin_errors = (pkcs11.exceptions.PinIncorrect, pkcs11.exceptions.PinInvalid,
                                          pkcs11.exceptions.PinLenRange)
                            import asn1crypto  # noqa: F401
                            if args.format == "pades":
                                from pyhanko.sign.pkcs11 import PKCS11Signer
                                font, icon = prepare_stamp(stamp)
                        except ImportError as error:
                            raise SetupError("Install Python dependencies with: python -m pip install -r requirements.txt") from error

                        if args.debug:
                            packages = ["python-pkcs11", "asn1crypto"]
                            if args.format == "pades":
                                packages.extend(["pyHanko", "Pillow"])
                            for package in packages:
                                try:
                                    installed = version(package)
                                except PackageNotFoundError:
                                    installed = "version metadata unavailable"
                                debug(f"{package}: {installed}")
                        token = find_token(
                            module, debug if args.debug else None, unique_identity=remember_pin,
                        )
                        if args.format == "cades":
                            backend = OpenSSL(stack, module, debug)
                        debug("Pre-login checks complete. Certificate and signing key selection follow authentication.")
                        flags = token.flags
                        if flags & pkcs11.TokenFlag.USER_PIN_LOCKED:
                            raise SetupError("Smart card PIN locked.")
                        if remember_pin:
                            try:
                                pin_store = PinStore(token)
                                caution = (pkcs11.TokenFlag.USER_PIN_COUNT_LOW |
                                           pkcs11.TokenFlag.USER_PIN_FINAL_TRY |
                                           pkcs11.TokenFlag.USER_PIN_TO_BE_CHANGED)
                                if flags & caution:
                                    log_error("Card reports a PIN warning; enter the PIN manually.")
                                else:
                                    pin = remember_secret(pin_store.get())
                                    saved_pin_in_use = pin is not None
                            except SetupError as error:
                                log_error(str(error))
                                pin_store = None
                        if pin is None:
                            pin = remember_secret(prompt_pin())
                        else:
                            debug("Using the saved PIN for this card.")

                        if args.format == "pades":
                            session = stack.enter_context(token.open(user_pin=pin))
                            cert_id, cert = select_certificate(session, pkcs11)
                            signer = PKCS11Signer(session, signing_cert=cert, key_id=cert_id)
                            sign = lambda src, dst, _path: sign_pdf(src, dst, signer, stamp, font, icon)
                        else:
                            with token.open(user_pin=pin) as session:
                                cert_id, cert = select_certificate(session, pkcs11)
                                backend.configure_signer(token, cert_id, cert)
                            backend.set_pin(pin)
                            sign = lambda src, dst, src_path: backend.sign(
                                src, dst, src_path.suffix.lower() == ".p7m"
                            )
                        debug(f"Selected a signing certificate using {cert.public_key.algorithm.upper()}.")
                        if pin_store is not None and not saved_pin_in_use:
                            try:
                                pin_store.save(pin)
                                saved_pin_in_use = True
                                debug("PIN saved in the desktop keyring.")
                            except SetupError as error:
                                log_error(str(error))
                                pin_store = None

                    debug("Starting signature.")
                    try:
                        sign(source, destination, source_path)
                    except (StampPositionError, StampPageError) as error:
                        failed += 1
                        raise SetupError(f"{source_path}: {error}") from error
                    except SetupError:
                        raise
                    except pin_errors:
                        raise
                    except (pkcs11.exceptions.DeviceRemoved, pkcs11.exceptions.TokenNotPresent,
                            pkcs11.exceptions.PinLocked) as error:
                        raise SetupError("Smart card unavailable or PIN rejected.") from error
                    except Exception as error:
                        failed += 1
                        # The detailed backend error is only printed in debug mode.
                        reason = str(error) if isinstance(error, (OSError, FileError)) else type(error).__name__
                        if isinstance(error, BackendError):
                            reason = "OpenSSL could not sign the file."
                        log_error(f"{source_path}: {reason}", error if reason != str(error) else None)
                    else:
                        signed += 1
                        if args.debug:
                            feedback(diagnostic(f"Signed {source_path} → {destination}", pin), file=sys.stderr)
    except (Exception, KeyboardInterrupt) as error:
        stopped = True
        if saved_pin_in_use and isinstance(error, (PinRejected, *pin_errors)):
            try:
                pin_store.forget()
                log_error("Saved PIN removed after rejection. Run again to enter the PIN manually.")
            except SetupError as removal_error:
                log_error(str(removal_error))
        message = {
            "PinIncorrect": "Smart card PIN rejected.",
            "PinInvalid": "Smart card PIN rejected.",
            "PinLenRange": "Smart card PIN rejected.",
            "PinLocked": "Smart card PIN locked.",
            "DeviceRemoved": "Smart card removed.",
            "TokenNotPresent": "Smart card not found.",
            "KeyboardInterrupt": "Signing cancelled.",
        }.get(type(error).__name__, type(error).__name__)
        if isinstance(error, (SetupError, OSError)):
            message = str(error)
        log_error(message, error)

    report(signed, skipped, failed)
    if stopped:
        return 1 if signed or failed else 2
    if failed:
        return 1
    return 0 if signed else 3


def stamp_coordinate(value):
    try:
        number = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError("stamp coordinates must be numbers") from None
    if not math.isfinite(number) or number < 0:
        raise argparse.ArgumentTypeError("stamp coordinates must be finite and nonnegative")
    return number


def stamp_page_number(value):
    try:
        number = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("stamp page must be a positive integer") from None
    if number < 1:
        raise argparse.ArgumentTypeError("stamp page must be a positive integer")
    return number


def run_cli(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--format", choices=("pades", "cades"),
                        help="signature format (default: pades)")
    parser.add_argument("--stamp-page", type=stamp_page_number, metavar="NUMBER",
                        help="one-based stamp page number, overriding stamp-page (PAdES only)")
    parser.add_argument("--stamp-position", nargs=2, type=stamp_coordinate, metavar=("X", "Y"),
                        help="stamp top-left coordinates from the visible page top-left in points (PAdES only)")
    parser.add_argument("--debug", action="store_true", help="show verbose diagnostics before and after smart-card login")
    actions = parser.add_mutually_exclusive_group()
    for flag, help_text in (
        ("extract", "extract embedded content from P7M files without overwriting outputs or verifying signatures"),
        ("card-info", "authenticate with the PIN and read card information as JSON (read-only)"),
        ("change-pin", "change the selected card's user PIN"),
        ("forget-pin", "remove the selected card's saved PIN without signing"),
    ):
        actions.add_argument("--" + flag, action="store_true", help=help_text)
    parser.add_argument("--slot", type=int, help="PKCS#11 slot ID for card management")
    parser.add_argument("--agent-only", action="store_true",
                        help="require a per-user password agent for PIN prompts; never use the terminal")
    parser.add_argument("--no-keyring", action="store_true",
                        help="do not read or save PINs in the keyring")
    parser.add_argument("paths", nargs="*", type=Path, metavar="FILE")
    args = parser.parse_args(argv)
    _agent_only.set(args.agent_only)
    if args.agent_only and args.forget_pin:
        parser.error("--agent-only cannot be combined with --forget-pin")
    if args.extract:
        for option in ("format", "stamp_page", "stamp_position", "slot", "no_keyring", "agent_only"):
            if getattr(args, option) is not None and getattr(args, option) is not False:
                parser.error(f"--{option.replace('_', '-')} cannot be combined with --extract")
        if not args.paths:
            parser.error("--extract requires at least one FILE")
        return run_extraction(args)
    args.format = args.format or "pades"
    management = args.card_info or args.change_pin
    for option in ("stamp-position", "stamp-page"):
        if getattr(args, option.replace("-", "_")) is not None and (args.format != "pades" or management or args.forget_pin):
            parser.error(f"--{option} requires PAdES signing")
    if args.slot is not None and not management:
        parser.error("--slot requires --card-info or --change-pin")
    if args.forget_pin and args.no_keyring:
        parser.error("--forget-pin cannot be combined with --no-keyring")
    if management or args.forget_pin:
        if args.paths:
            parser.error("card management does not accept input files")
        return manage_card(args) if management else forget_pin()
    if not args.paths:
        parser.error("at least one FILE or a card management action is required")
    return run_batch(args)


def main(argv=None):
    collected = UserFeedback()
    token = _current_feedback.set(collected)
    agent_token = _agent_only.set(False)
    status = None
    try:
        status = run_cli(argv)
        return status
    except SystemExit as error:
        if error.code:
            status = error.code
            collected.messages.append("Invalid command line. See terminal output.\n")
        raise
    finally:
        _current_feedback.reset(token)
        _agent_only.reset(agent_token)
        if status is not None:
            try:
                notify_feedback(collected.report(), status)
            except (Exception, KeyboardInterrupt):
                # Desktop integration must never change the operation's result.
                pass


if __name__ == "__main__":
    sys.exit(main())
