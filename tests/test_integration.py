"""PDF page-selection tests that run without a smart card."""

import pytest

import litesign as ls


def make_pdf(path):
    from pyhanko.pdf_utils import generic as pdf
    from pyhanko.pdf_utils.writer import PageObject, PdfFileWriter

    writer = PdfFileWriter()
    for _ in range(2):
        contents = writer.add_object(pdf.StreamObject(stream_data=b""))
        writer.insert_page(PageObject(contents, (0, 0, 600, 800)))
    second, _ = writer.find_page_for_modification(1)
    second = second.get_object()
    second[pdf.pdf_name("/Rotate")] = pdf.NumberObject(90)
    second[pdf.pdf_name("/CropBox")] = pdf.ArrayObject(
        [pdf.NumberObject(n) for n in (20, 30, 580, 770)]
    )
    with path.open("wb") as output:
        writer.write(output)


@pytest.mark.parametrize(("selector", "expected"), [
    ("first", (0, (0, 0, 600, 800), 0)),
    ("last", (-1, (20, 30, 580, 770), 90)),
    (2, (1, (20, 30, 580, 770), 90)),
])
def test_pdf_page_selection(tmp_path, selector, expected):
    from pyhanko.pdf_utils.reader import PdfFileReader

    source = tmp_path / "doc.pdf"
    make_pdf(source)
    with source.open("rb") as stream:
        assert ls.find_page(PdfFileReader(stream), selector) == expected
