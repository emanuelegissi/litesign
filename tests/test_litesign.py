import os
from pathlib import Path

import pytest

import litesign as ls


@pytest.mark.parametrize(("name", "mode", "expected"), [
    ("a.PDF", "pades", "a-signed.PDF"),
    ("a-signed.pdf", "pades", "a-signed-signed.pdf"),
    ("a.tar.gz", "cades", "a.tar-signed.gz.p7m"),
    ("a.pdf.p7m", "cades", "a-signed.pdf.p7m"),
    ("a.p7m", "cades", "a-signed.p7m"),
    ("a", "cades", "a-signed.p7m"),
])
def test_output_name(name, mode, expected):
    assert ls.output_path(Path(name), mode) == Path(expected)


@pytest.mark.parametrize("page", ['"first"', '"last"', "2"])
def test_config_page(tmp_path, page):
    config = tmp_path / "config.toml"
    config.write_text(f'[pades.stamp]\nstamp-page={page}\nicon-path="icon.png"\n')
    _, stamp = ls.load_config(config, "pades")
    assert stamp["stamp-page"] == (int(page) if page.isdigit() else page.strip('"'))
    assert stamp["icon-path"] == tmp_path / "icon.png"


@pytest.mark.parametrize("page", ["0", "-1", "true", '"2"', '"middle"'])
def test_invalid_page(tmp_path, page):
    config = tmp_path / "config.toml"
    config.write_text(f"[pades.stamp]\nstamp-page={page}\n")
    with pytest.raises(ls.SetupError, match="positive integer"):
        ls.load_config(config, "pades")


@pytest.mark.parametrize("horizontal,x", [("left", 22), ("center", 65), ("right", 108)])
@pytest.mark.parametrize("vertical,y", [("bottom", 32), ("center", 65), ("top", 98)])
def test_all_stamp_positions(horizontal, x, vertical, y):
    assert ls.stamp_box((10, 20, 150, 130), 0, 30, 20, horizontal, vertical) == (
        x, y, x + 30, y + 20
    )


@pytest.mark.parametrize("rotation,expected", [
    (90, (118, 88, 138, 118)), (180, (22, 98, 52, 118)), (270, (22, 32, 42, 62)),
])
def test_rotated_stamp_box(rotation, expected):
    assert ls.stamp_box((10, 20, 150, 130), rotation, 30, 20, "right", "bottom") == expected


def test_redact_pin():
    message = "123-456; 123%2D456; %31%32%33%2d%34%35%36"
    assert ls.diagnostic(message, "123-456") == "[redacted]; [redacted]; [redacted]"


def test_output_alias_keeps_current_input(tmp_path):
    source = tmp_path / "doc.pdf"
    destination = tmp_path / "doc-signed.pdf"
    source.write_bytes(b"original")
    os.link(source, destination)
    with source.open("rb") as original, pytest.raises(ls.FileError, match="current input"):
        with ls.open_output(destination, original):
            pytest.fail("An aliased input was opened for writing")
    assert source.read_bytes() == b"original"


@pytest.mark.parametrize("existing_output", [False, True])
@pytest.mark.parametrize("error_type", [RuntimeError, KeyboardInterrupt])
def test_failed_output_is_not_published(tmp_path, existing_output, error_type):
    source = tmp_path / "doc.pdf"
    destination = tmp_path / "doc-signed.pdf"
    source.write_bytes(b"original")
    if existing_output:
        destination.write_bytes(b"old output")
    before = set(tmp_path.iterdir())
    with source.open("rb") as original, pytest.raises(error_type):
        with ls.open_output(destination, original) as output:
            output.write(b"partial")
            raise error_type("test failure")
    if existing_output:
        assert destination.read_bytes() == b"old output"
    else:
        assert not destination.exists()
    assert source.read_bytes() == b"original"
    assert set(tmp_path.iterdir()) == before


@pytest.fixture
def configured_driver(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    config = tmp_path / "litesign/config.toml"
    config.parent.mkdir()
    module = tmp_path / "driver.so"
    module.touch()
    config.write_text(ls.DEFAULT_CONFIG.replace('module = ""', f'module = "{module}"'))
    return config


def test_all_skipped_with_configured_driver(configured_driver, capsys):
    assert ls.main(["a.txt", "b.png"]) == 3
    assert capsys.readouterr().out == "No files signed · 2 skipped.\n"
    assert configured_driver.is_file()


def test_missing_input_is_failed(configured_driver, capsys):
    assert ls.main(["--format", "pades", "missing.pdf", "b.txt"]) == 1
    result = capsys.readouterr()
    assert "1 skipped · 1 failed" in result.out
    assert "missing.pdf" in result.err


def test_icon(tmp_path):
    from PIL import Image

    config = tmp_path / "config.toml"
    _, stamp = ls.load_config(config, "pades")
    assert 'icon-path = "@bundled"' in config.read_text()
    assert stamp["icon-path"] == Path(ls.__file__).parent / "assets" / "icon.png"
    _, icon = ls.prepare_stamp(stamp)
    assert icon.size == (63, 128)

    config.write_text(config.read_text().replace('"@bundled"', '""'))
    _, stamp = ls.load_config(config, "pades")
    _, icon = ls.prepare_stamp(stamp)
    assert icon is None
    stamp["icon-path"] = tmp_path / "icon.png"
    with pytest.raises(ls.SetupError, match="readable PNG"):
        ls.prepare_stamp(stamp)
    Image.new("RGBA", (96, 48)).save(stamp["icon-path"])
    _, icon = ls.prepare_stamp(stamp)
    assert icon.size == (96, 48)


def test_resolving_configured_module_preserves_settings(tmp_path):
    config = tmp_path / "config.toml"
    config.write_text('# My settings\n[smartcard]\nmodule="vendor driver.so"\n[pades.stamp]\nreason="Approvazione"\n')
    original = config.read_bytes()
    module = tmp_path / "vendor driver.so"
    module.touch()
    stored, stamp = ls.load_config(config, "pades")
    assert ls.resolve_module(config, stored["module"]) == module
    assert stamp["reason"] == "Approvazione"
    assert config.read_bytes() == original


def test_no_card_reports_before_pin_prompt(tmp_path, monkeypatch, capsys):
    config = tmp_path / "litesign/config.toml"
    config.parent.mkdir()
    module = tmp_path / "pkcs11.so"
    module.touch()
    config.write_text(ls.DEFAULT_CONFIG.replace('module = ""', f'module = "{module}"'))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))

    def absent(_, debug=None, **kwargs):
        raise ls.SetupError("Smart card not found.")

    monkeypatch.setattr(ls, "find_token", absent)
    monkeypatch.setattr(ls, "prompt_pin", lambda: pytest.fail("Unexpected PIN prompt"))
    source = tmp_path / "doc.pdf"
    source.touch()
    assert ls.main(["--format", "pades", str(source)]) == 2
    assert capsys.readouterr().err == "Smart card not found.\n"


def test_stamp_renders_without_system_fonts(tmp_path, monkeypatch):
    from PIL import ImageFont

    truetype = ImageFont.truetype

    def bundled_only(font, *args, **kwargs):
        if isinstance(font, str):
            raise OSError("No system fonts installed")
        return truetype(font, *args, **kwargs)

    monkeypatch.setattr(ImageFont, "truetype", bundled_only)
    _, stamp = ls.load_config(tmp_path / "config.toml", "pades")
    font, icon = ls.prepare_stamp(stamp)
    assert font.getname()[0] == "Aileron"
    image = ls.stamp_art(font, icon, stamp, "René Rossi", "2026-11-06")
    assert image.width > 48
    assert image.height > 48


@pytest.mark.parametrize(("reason", "location", "expected"), [
    ("Approved", "Genova", ["Approved", "René Rossi", "Genova, 2026-11-06 12:30 CET"]),
    ("", "Comando Provinciale di Genova\nSede Centrale",
     ["René Rossi", "Comando Provinciale di Genova Sede Centrale, 2026-11-06 12:30 CET"]),
    ("", " ", ["René Rossi", "2026-11-06 12:30 CET"]),
])
def test_stamp_line_order_and_labels(tmp_path, monkeypatch, reason, location, expected):
    from PIL import ImageDraw

    drawn = []
    monkeypatch.setattr(ImageDraw.ImageDraw, "text", lambda self, xy, text, **kw: drawn.append(text))
    _, stamp = ls.load_config(tmp_path / "config.toml", "pades")
    stamp.update(reason=reason, location=location)
    font, icon = ls.prepare_stamp(stamp)
    ls.stamp_art(font, icon, stamp, "René Rossi", "2026-11-06 12:30 CET")
    assert drawn == expected


def test_rounded_stamp_has_transparent_corners(tmp_path):
    _, stamp = ls.load_config(tmp_path / "config.toml", "pades")
    font, icon = ls.prepare_stamp(stamp)
    image = ls.stamp_art(font, icon, stamp, "René Rossi", "2026-11-06 12:30 CET")
    width, height = image.size
    for point in ((0, 0), (width - 1, 0), (0, height - 1), (width - 1, height - 1)):
        assert image.getpixel(point)[3] == 0
    assert image.getpixel((width // 2, 0)) == (171, 178, 185, 255)
    assert image.getpixel((width // 2, 5)) == (255, 255, 255, 255)


@pytest.mark.parametrize("existing_output", [False, True])
def test_output_is_replaced_only_after_success(tmp_path, existing_output):
    source = tmp_path / "input.pdf"
    destination = tmp_path / "output.pdf"
    source.write_bytes(b"original")
    if existing_output:
        destination.write_bytes(b"old output")
        destination.chmod(0o640)
    previous = destination.open("rb") if existing_output else None
    try:
        with source.open("rb") as original, ls.open_output(destination, original) as output:
            output.write(b"complete signature")
            output.flush()
            if existing_output:
                assert destination.read_bytes() == b"old output"
            else:
                assert not destination.exists()
        assert destination.read_bytes() == b"complete signature"
        assert destination.stat().st_mode & 0o777 == (0o640 if existing_output else 0o600)
        if previous is not None:
            assert previous.read() == b"old output"
    finally:
        if previous is not None:
            previous.close()
    assert source.read_bytes() == b"original"
    assert set(tmp_path.iterdir()) == {source, destination}


@pytest.mark.parametrize("operation", ["fsync", "replace"])
def test_output_commit_failure_preserves_previous_output(tmp_path, monkeypatch, operation):
    source = tmp_path / "input.pdf"
    destination = tmp_path / "output.pdf"
    source.write_bytes(b"original")
    destination.write_bytes(b"old output")

    def fail(*args, **kwargs):
        raise OSError("simulated commit failure")

    monkeypatch.setattr(ls.os, operation, fail)
    with source.open("rb") as original, pytest.raises(OSError, match="simulated commit failure"):
        with ls.open_output(destination, original) as output:
            output.write(b"complete signature")
    assert destination.read_bytes() == b"old output"
    assert source.read_bytes() == b"original"
    assert set(tmp_path.iterdir()) == {source, destination}


@pytest.mark.parametrize("target_exists", [False, True])
def test_output_symlink_is_rejected(tmp_path, target_exists):
    source = tmp_path / "input.pdf"
    target = tmp_path / "target.pdf"
    destination = tmp_path / "output.pdf"
    source.write_bytes(b"original")
    if target_exists:
        target.write_bytes(b"target")
    destination.symlink_to(target)
    before = set(tmp_path.iterdir())
    with source.open("rb") as original, pytest.raises(ls.FileError, match="symlink"):
        with ls.open_output(destination, original):
            pytest.fail("A symlink output was accepted")
    assert destination.is_symlink()
    assert target.read_bytes() == b"target" if target_exists else not target.exists()
    assert set(tmp_path.iterdir()) == before


@pytest.mark.parametrize("link_type", ["symlink", "hardlink"])
def test_output_alias_created_during_signing_is_rejected(tmp_path, link_type):
    source = tmp_path / "input.pdf"
    destination = tmp_path / "output.pdf"
    source.write_bytes(b"original")
    with source.open("rb") as original, pytest.raises(ls.FileError):
        with ls.open_output(destination, original) as output:
            output.write(b"complete signature")
            if link_type == "symlink":
                destination.symlink_to(source)
            else:
                os.link(source, destination)
    assert source.read_bytes() == b"original"
    assert destination.read_bytes() == b"original"
    assert set(tmp_path.iterdir()) == {source, destination}


@pytest.mark.parametrize("kind", ["directory", "fifo"])
def test_nonregular_output_is_rejected(tmp_path, kind):
    source = tmp_path / "input.pdf"
    destination = tmp_path / "output.pdf"
    source.write_bytes(b"original")
    if kind == "directory":
        destination.mkdir()
    else:
        os.mkfifo(destination)
    with source.open("rb") as original, pytest.raises(ls.FileError, match="regular file"):
        with ls.open_output(destination, original):
            pytest.fail("A nonregular output was accepted")
    assert source.read_bytes() == b"original"
    assert set(tmp_path.iterdir()) == {source, destination}


@pytest.mark.parametrize('reason', ['Firmato digitalmente', '', 'A long signing reason that wraps over several lines in this stamp'])
@pytest.mark.parametrize('icon_size', [(20, 50), (100, 30)])
def test_stamp_centers_icon_and_text_at_matching_heights(tmp_path, reason, icon_size):
    from PIL import Image

    _, stamp = ls.load_config(tmp_path / 'config.toml', 'pades')
    stamp.update(reason=reason, location='Sassari')
    font, _ = ls.prepare_stamp(stamp)
    # Transparent padding must not affect the visible icon's alignment.
    icon = Image.new('RGBA', (icon_size[0] + 20, icon_size[1] + 20))
    icon.paste((0, 0, 0, 255), (10, 10, icon_size[0] + 10, icon_size[1] + 10))
    original = icon.tobytes()
    result = ls.stamp_art(font, icon, stamp, 'EMANUELE GISSI', '2026-11-09 08:54 CET')

    def color_bounds(color):
        mask = Image.new('L', result.size)
        pixels = result.load()
        mask.putdata([255 if pixels[x, y] == color else 0
                      for y in range(result.height) for x in range(result.width)])
        return mask.getbbox()

    left, top, right, bottom = color_bounds((0, 0, 0, 255))
    text_left, text_top, _, text_bottom = color_bounds((39, 49, 58, 255))
    assert abs((bottom - top) - (text_bottom - text_top)) <= 2
    assert abs(top + bottom - result.height) <= 2
    assert abs(text_top + text_bottom - result.height) <= 2
    assert abs(left - (text_left - right)) <= 4
    assert icon.tobytes() == original
