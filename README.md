# LiteSign

LiteSign signs files on Linux with a physical smart card. It uses pyHanko for
PAdES and OpenSSL for attached CAdES signatures and co-signatures. It also
extracts embedded documents from P7M files without a smart card.

## Install

For a per-user installation with Nautilus integration, run from this project
folder as your regular desktop user (not with `sudo`):

```sh
./install.sh
```

Python 3.11 or later, Bash, Python virtual-environment support, and access to the
Python package index (or a populated pip cache) are required. The installer
prompts for the path to your smartcard's PKCS#11 module. The file must exist and
be readable; it is not loaded and no PIN or card login is requested during
installation. On reinstall, press Enter to retain the existing module path.
The path is stored as an absolute path. Existing TOML settings and comments are
preserved; new configurations use LiteSign's defaults.

The installer creates a private virtual environment, installs the Python
dependencies, and installs these files (respecting absolute XDG overrides):

| Component | Default location |
| --- | --- |
| Application, icon and virtual environment | `~/.local/share/litesign/` |
| CLI launcher | `~/.local/bin/litesign` |
| Nautilus scripts | `~/.local/share/nautilus/scripts/` |
| Configuration | `~/.config/litesign/config.toml` |

The installed CLI is `litesign`; add `~/.local/bin` to your shell's `PATH` if
necessary. The application is copied into its own installation, so the original
project folder is not required afterward. Vendor middleware is not copied.
TOMLKit is included in `requirements.txt` and preserves configuration formatting during installation.

Reinstalling builds a new virtual environment at its permanent path before
switching the launcher. Failed setup leaves the previous installation usable.
Unrelated or modified launcher/script files are never replaced. Previous
successful application versions are retained until uninstall.

To uninstall, run either the project's `./uninstall.sh` or the installed copy:

```sh
~/.local/share/litesign/current/uninstall.sh
```

With a custom `XDG_DATA_HOME`, use the corresponding path instead. Uninstall
removes the managed application versions, CLI launcher and Nautilus scripts.
It preserves configuration, keyring entries, documents, temporary logs, unrelated
scripts and user-modified launcher/script files. No system packages are installed
or removed by these scripts.

For development without installation:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
```

Install your card vendor's PKCS#11 middleware or OpenSC if it supports your card.
A PC/SC reader may also require the `pcscd` service. Configure the path to the
middleware's shared library, for example `/usr/lib64/opensc-pkcs11.so` on some
Fedora installations. The path depends on your distribution and middleware.

PAdES uses an available system sans font and falls back to Pillow’s built-in
sans font, which covers fewer characters. For CAdES, install OpenSSL 3 and
[pkcs11-provider](https://github.com/openssl-projects/pkcs11-provider), often
packaged as `pkcs11-provider`. If the provider is installed in a custom
directory, point `OPENSSL_MODULES` to the directory containing its `pkcs11.so`.

## Use

For signing, insert the smart card. Running from a terminal works without a
graphical password agent.

```sh
python litesign.py -- report.pdf annex.pdf
python litesign.py --format cades -- report.pdf data.csv
python litesign.py --format cades -- report-signed.pdf.p7m
python litesign.py --debug -- report.pdf
python litesign.py --stamp-position 36 72 -- report.pdf
python litesign.py --stamp-page 2 --stamp-position 36 72 -- report.pdf
```

PAdES is the default when you omit `--format`. LiteSign processes paths in the order given. It prompts for the PIN without
echo and uses the first eligible signing certificate on the first initialized
token exposed by the configured driver. Certificates outside their validity
period are skipped using the current system time. If no eligible, currently valid
certificate remains, signing stops with an error. Use one signing card at a time.
Local paths and mounted shares exposed as Linux paths are accepted.

| Input | Format | Output |
| --- | --- | --- |
| `report.pdf` | PAdES | `report-signed.pdf` |
| `report-signed.pdf` | PAdES | `report-signed-signed.pdf` |
| `report.pdf` | CAdES | `report-signed.pdf.p7m` |
| `report-signed.pdf.p7m` | CAdES | `report-signed-signed.pdf.p7m` |

Signatures are written to a temporary file in the output directory, flushed
and synced, then atomically moved into place after signing succeeds. Failures
before replacement preserve any existing output and remove the temporary file.
Existing output access permissions are preserved; new outputs are readable and
writable only by the current user. The output directory must be writable.
If you pass `report.pdf` followed by `report-signed.pdf`, the second operation
signs the file just written by the first operation. LiteSign refuses an output
symlink or an output that aliases the current input.

PAdES skips paths without a `.pdf` extension, ignoring case. CAdES treats an
existing `.p7m` as an attached DER CMS envelope and adds a parallel signature
to it. Co-signing requires an existing SHA-256, SHA-384, SHA-512 or SHA-224
signer with a message digest attribute. Before co-signing, LiteSign checks the
attached payload against every existing message digest using these supported
algorithms and rejects mismatches or ambiguous digest attributes before opening
the output. This checks payload integrity, not existing signatures or certificate
trust. New envelopes use SHA-256; co-signatures reuse a supported existing digest
algorithm.
PAdES uses the basic B-B profile. CAdES uses OpenSSL's `-cades` signed
certificate attribute. Trusted timestamps and long-term validation are
outside the scope of this release.

If PAdES processing encounters a PDF parsing error, LiteSign automatically tries
once to rasterize the document with Ghostscript (`gs`) and sign the resulting PDF
with the same stamp settings. Install Ghostscript with your distribution's package
manager to enable this fallback. Pages become 300 dpi color images with lossless
compression; searchable text and interactive features are lost, and file size may
increase. LiteSign reports the conversion in its usual feedback. The original is
unchanged and temporary conversion files are removed. Conversion stops after
120 seconds. Already-signed PDFs, or PDFs whose signatures cannot be checked,
are not rasterized. Other errors do not trigger conversion.

## Nautilus scripts

After installation, select files in GNOME Files and choose an entry from the
**Scripts** context submenu:

| Script | Operation |
| --- | --- |
| `Sign as pdf` | PAdES signing; non-PDF paths are skipped. |
| `Sign as p7m` | CAdES signing; existing `.p7m` files receive a parallel signature. |
| `Extract p7m` | Extract one envelope layer; existing output paths are always refused. |

Each script passes the entire selection to LiteSign in one batch. Spaces,
quotes, Unicode, newlines and leading hyphens in filenames are preserved.
Select files in a local folder or a mounted location exposed as filesystem
paths. An empty selection or a remote selection without local paths fails.
Directories are not processed recursively.

No terminal is opened. The signing scripts use `--agent-only`: when PIN entry
is required, `systemd-ask-password` must be available with a running per-user
password agent (systemd 257 or later). LiteSign explicitly requests that agent
with `--no-tty --user`. Missing helpers, failed/cancelled requests, and timeouts
stop signing without terminal fallback or automatic retry. An absent agent may
only be detected when the 90-second request timeout expires. A usable saved
keyring PIN avoids prompting. The scripts cannot establish agent availability
merely by finding the helper executable.

Extraction does not need a smartcard, PIN agent, or smartcard configuration.
Results use LiteSign's notifications and temporary logs, without notification
actions or automatic file opening. Install `notify-send` and ensure your desktop
notification service works so feedback is visible when launched from Nautilus.
Ordinary CLI use retains its terminal PIN fallback unless `--agent-only` is set.

## Extract P7M content

```sh
python litesign.py --extract -- document.pdf.p7m other.xml.p7m
```

Extraction accepts attached CMS SignedData in binary DER or PEM encoding
(`CMS` or `PKCS7` labels). It removes the final `.p7m` extension, ignoring case,
and writes the embedded bytes unchanged beside the input: `document.pdf.p7m`
becomes `document.pdf`. An empty embedded document is valid. It extracts only
one layer: `document.pdf.p7m.p7m` becomes `document.pdf.p7m`.

**Existing outputs are always refused. There is no overwrite option.** This
includes directories, symlinks, and outputs created concurrently. Extraction
publishes a completed temporary file atomically using a hard link; the output
filesystem must support hard links. New files have owner-only read/write
permissions, and failed extraction cleans up the temporary file.

No smart card, PIN, keyring, OpenSSL executable, or configuration file is needed.
Extraction does not read or create configuration. Signing, stamp, and card
options cannot be combined with `--extract`; `--debug` remains available.

Extraction does not verify signatures, certificate validity, or certificate
trust. Success is reported as extraction with `Signatures not verified.`
Malformed or encrypted envelopes and detached signatures are rejected. A failed
file does not prevent later files from being processed; paths without a `.p7m`
extension are skipped. The final summary reports extracted, skipped, and failed
counts.

## PIN prompts and desktop feedback

When `systemd-ask-password` is installed, LiteSign uses it for PIN entry with
input echo disabled and a 90-second timeout. This applies to signing, card
information, and all three prompts when changing a PIN. Its output is captured
privately; LiteSign does not enable systemd password caching or use systemd's
inherited password credentials. The existing Python keyring behavior is unchanged.

If the command is absent, LiteSign uses the terminal password prompt unless
`--agent-only` was specified. Once a
systemd prompt has started, cancellation or failure stops the operation without
retrying through another prompt. Without a terminal, a compatible password agent
must be running; installing `systemd-ask-password` alone does not guarantee a
graphical dialog. Per-user password agents require systemd 257 or later.

When `notify-send` is available, LiteSign sends one final desktop notification
for signing, extraction, or card management. Terminal stdout/stderr and exit
codes are preserved, including the JSON output from `--card-info`. Notifications
require a working desktop notification service; delivery failures do not affect
the operation's result. Notification delivery has a three-second timeout.

Reports longer than 300 characters or four lines are saved to a unique
`litesign-*.log` file in Python's temporary directory, normally `/tmp` (or the
usable directory selected by `TMPDIR`). Logs are readable and writable only by
the current user. The notification shows a short result and the log path; the
same path is printed to stderr. PINs and their URI-encoded forms are redacted,
and password-helper output is never included in reports.

There are no notification actions, automatic file openers, or background
helpers. LiteSign leaves completed logs available for manual inspection and
relies on system temporary-file cleanup; cleanup timing depends on the system.
No log is created when `notify-send` is absent. If a log cannot be written,
terminal output remains available.

## Configure

LiteSign creates `${XDG_CONFIG_HOME:-$HOME/.config}/litesign/config.toml` on
the first invocation that needs configuration. Set `[smartcard].module` to the
PKCS#11 shared library path before signing or running card-management commands.
If the setting is missing, empty, or whitespace-only, LiteSign stops with exit
code `2` and reports the configuration file to edit. It never prompts for the
module path or saves it automatically. Relative paths are resolved against the
configuration directory, and the configured driver file must exist.
The PIN is entered at run time unless a saved PIN is available.

```toml
[smartcard]
module = "/path/to/vendor-pkcs11.so"
remember-pin = false

[pades.stamp]
stamp-page = "last"
stamp-vertical-position = "bottom"
stamp-horizontal-position = "right"
icon-path = "@bundled"
location = ""
reason = ""
```

- `stamp-page` accepts `"first"`, `"last"` or an unquoted positive integer such as
  `2`. If a PDF has fewer pages than requested, the batch stops before signing
  that file or replacing its output; previously completed outputs remain.
- `stamp-vertical-position` accepts `"top"`, `"center"` or `"bottom"`.
  `stamp-horizontal-position` accepts `"left"`, `"center"` or `"right"`.
- `icon-path = "@bundled"` uses the pen icon in `assets/icon.png` beside the
  script. Set `icon-path = ""` to omit the icon, or set a custom PNG path.
  Relative custom paths are resolved against the config directory. Existing
  icon settings are preserved.
- The stamp shows the reason first, then the signer. The final line shows
  the location and local signing date and time. When set, the reason and
  location appear without labels and are also stored in the PDF signature
  metadata.
  Placement uses the displayed page, including rotation and cropping.
  Repeated signatures may overlap.

Use `--stamp-page NUMBER` to override `stamp-page` without changing the
configuration. The command-line option accepts only a positive, one-based integer;
`first` and `last` are available only in the configuration. The override applies
to each PDF in the batch.

Use `--stamp-position X Y` to override both placement settings for the invocation
without changing the configuration. Coordinates locate the stamp's top-left
corner relative to the visible page's top-left, after cropping and rotation.
X increases rightward and Y downward. Values are in PDF points (normally 1/72
inch); fractional values are accepted. The page is selected by
`stamp-page` or its command-line override. Both options are available only for
PAdES signing, and placement is checked against the selected page.

Automatic placement retains its 12-point margin. Custom placement can touch the
page edges, but the entire stamp must fit. Negative or non-finite coordinates
are rejected. If placement exceeds the page boundaries after calculating the
actual stamp dimensions, the batch stops with an error before signing that file
or replacing its output. Previously completed outputs remain. LiteSign does not
move or shrink the stamp to make it fit.

The configuration keys are now `stamp-page`, `stamp-horizontal-position` and
`stamp-vertical-position`; previous names have no compatibility aliases.

The [assets directory](assets/README.md) also has space for local vendor
middleware. Install the middleware according to the vendor's instructions.

## Remember the card PIN

Set `remember-pin = true` in `[smartcard]` to save and reuse the PIN with the
Python [`keyring`](https://keyring.readthedocs.io/en/stable/) library. The setting
defaults to `false`, including for existing configurations that omit it.

LiteSign supports the library's Secret Service backend (such as GNOME Keyring)
and KWallet backends. A running desktop keyring and session D-Bus are required;
unlocking the keyring may display a desktop prompt. KWallet may also require
your distribution's `dbus-python` package. Unsupported backends, including
plaintext file stores, are not used. If the keyring cannot be initialized or
read, LiteSign prompts for the PIN and skips storage for that run. A storage
failure is reported without failing an otherwise successful signing operation.

The PIN is stored only after card authentication and signing-certificate selection
succeed. Entries are separate for each card, identified by manufacturer, model
and serial number, and shared by PAdES and CAdES. Cards without a usable identity
fall back to manual entry; duplicate identities among detected cards are rejected
when keyring use is enabled. The PIN is never written to the TOML configuration.

A rejected saved PIN is removed and the batch stops without retrying. Run again
to enter the corrected PIN. If removal fails, use `--no-keyring` until you can
remove the stale entry. Card removal and unrelated signing errors do not erase
saved PINs. PIN warning flags require manual entry, and a locked card stops the
batch before login. Some cards do not report warning flags.

```sh
python litesign.py --no-keyring -- report.pdf
python litesign.py --forget-pin
```

`--no-keyring` bypasses both reading and writing saved PINs for that invocation.
`--forget-pin` removes the inserted card's saved PIN without logging into the card
or signing files. It works even with `remember-pin = false` and requires no file
arguments. Disabling `remember-pin` alone leaves saved entries in the keyring.

Saving a PIN makes it available to the desktop session. Applications running as
your user may access an unlocked keyring; the physical card is still required
for signing. See the [GNOME keyring security model](https://wiki.gnome.org/Projects/GnomeKeyring/SecurityFAQ).

## Card information and PIN management

```sh
python litesign.py --card-info
python litesign.py --card-info --slot 7
python litesign.py --change-pin --slot 7
```

`--card-info` prompts for the user PIN, authenticates, and prints JSON for the
selected card using a read-only session.
It reports reader and driver information, token identity and versions, status
and PIN warning flags, mechanisms, visible certificates and key metadata.
Binary identifiers are hexadecimal. Certificates include their subject, issuer,
serial, validity dates, SHA-256 fingerprint, public-key details and usage.
Expired certificates remain visible; date status is not a trust or revocation
check. Unreadable attributes are reported individually as unavailable, so they
do not hide the other fields. Private key material is never requested.

Inspection always authenticates in a read-only session and never accesses the
keyring. It prompts for the user PIN once and does not change the PIN or card
objects. Authentication may update the card's login/retry status; a rejected PIN
is never retried automatically. If authentication fails, inspection stops without
falling back to unauthenticated output. The driver may withhold information even
after login. Exact retry counts, PIN length limits, memory statistics and the
card clock are not exposed by the Python interface. Unset warning flags do not
guarantee that retries remain.

Card inspection and PIN changes require an explicit `--slot` when
multiple tokens are present. The command lists available slot IDs and labels
before prompting, so you can rerun it with the desired slot. A physical card can
expose several logical tokens with different PINs;
select the token documented by its vendor. The selected identity is displayed
before prompting and checked again afterward. No signing certificate is required.
These commands do not accept files. Close other card applications before changing
a PIN, and do not run signing or management concurrently for the same card.

`--change-pin` prompts for the current PIN and the new PIN twice, without echo.
It opens a read/write session authenticated as the normal user, then calls
PKCS#11 `C_SetPIN` with the current and new PIN. The middleware enforces PIN
length and character policies. A failed login stops before `C_SetPIN`.

Activation, token initialization and creation of an initial user PIN are not
supported. Changes require an already initialized token and user PIN. PIN
management through a reader's protected authentication path is also unsupported.
Locked user PINs stop login and ordinary PIN changes before submission;
low-attempt user PIN flags produce a warning.
Credentials are never retried automatically or included in backend diagnostics,
even with `--debug`.

Before a mutation, LiteSign writes a non-secret invalidation marker under
`invalid-pins/` beside its configuration. This prevents reuse of an old saved
PIN after an interrupted operation or an unavailable keyring. If writing the
marker fails, the card operation does not start. After a successful change,
`remember-pin = true` saves the new PIN and clears the marker, unless
`--no-keyring` is set. A storage failure is reported separately from the card's
successful change and leaves saved PIN reuse disabled. Otherwise, the next
signing invocation prompts for the current PIN; successful authentication and
storage re-enable reuse. `--forget-pin` also clears the marker after removing
the saved credential. Do not manually remove these markers while old PINs remain
in the keyring. Markers contain no PIN.

## Results

The batch summary goes to stdout. File errors and verbose `--debug`
diagnostics go to stderr. Before asking for the PIN, debug mode reports the
runtime, configuration, signing mode, dependencies, driver and detected
tokens. It also checks the OpenSSL providers before login in CAdES mode.
After login it reports signing progress and sanitizes backend errors. Keyring
failures use generic messages to avoid exposing credentials in diagnostics.

| Exit code | Meaning |
| --- | --- |
| `0` | At least one file signed or extracted and none failed, or card management completed (keyring save warnings do not change this status). |
| `1` | At least one file failed, signing or extraction was interrupted after some files completed, or a PIN changed but session cleanup failed. |
| `2` | Command-line, configuration, dependency or card error prevented signing or extraction, or card management failed. After a device error during mutation, check the card state before repeating the operation. |
| `3` | All inputs were skipped. |

## Tests

```sh
python -m pip install pytest -r requirements.txt
python -m pytest
```

Automated tests use software signatures and mocked cards/keyrings; they do not
access desktop credentials, change real card PINs, or require SoftHSM. Management
tests cover token selection, blocked credentials, secret-safe errors,
partial metadata, and stale-keyring prevention. Physical-card compatibility must
be checked against the selected middleware; the automated suite cannot establish
that a particular card supports PIN changes. Extraction tests cover binary and
PEM payloads, nested envelopes, malformed inputs, and refusal to overwrite files,
including concurrent destination creation. Desktop tests mock password and
notification utilities; they do not display real prompts or notifications.
Installer tests use isolated directories and simulated package installation;
they cover rollback, configuration preservation, uninstall ownership and exact
Nautilus filename handling.

For physical-card acceptance, sign a PDF twice, sign a binary file in CAdES,
and co-sign the resulting envelope. Verify the outputs with your usual
signature validator.

## License

[GNU General Public License, version 3](LICENSE).
