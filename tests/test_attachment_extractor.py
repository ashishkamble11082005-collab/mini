"""
Unit tests for AttachmentExtractor module.
Tests PDF, inline image with Content-ID, zero-byte attachment, spoofed extension (.pdf that's really an .exe), size cap filter, save_to disk extraction, and functional entrypoint.
"""

import email
from pathlib import Path
from email_parser.attachment_extractor import AttachmentExtractor, check_magic_mismatch, parse_attachments


def test_attachment_extractor_pdf():
    ae = AttachmentExtractor()
    eml = (
        "Content-Type: multipart/mixed; boundary=\"BOUND\"\r\n\r\n"
        "--BOUND\r\n"
        "Content-Type: application/pdf; name=\"doc.pdf\"\r\n"
        "Content-Disposition: attachment; filename=\"doc.pdf\"\r\n"
        "Content-Transfer-Encoding: base64\r\n\r\n"
        "JVBERi0xLjQKJSDl4uXzCg=="
        "\r\n--BOUND--"
    )
    msg = email.message_from_string(eml)
    errors = []
    atts = ae.extract(msg, errors)

    assert len(atts) == 1
    assert atts[0].filename == "doc.pdf"
    assert atts[0].content_size_bytes > 0
    assert atts[0].md5_hash != ""
    assert atts[0].sha256_hash != ""


def test_attachment_extractor_inline_image():
    ae = AttachmentExtractor()
    eml = (
        "Content-Type: multipart/related; boundary=\"BOUND\"\r\n\r\n"
        "--BOUND\r\n"
        "Content-Type: image/png\r\n"
        "Content-Disposition: inline\r\n"
        "Content-ID: <cid_image_001>\r\n"
        "Content-Transfer-Encoding: base64\r\n\r\n"
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="
        "\r\n--BOUND--"
    )
    msg = email.message_from_string(eml)
    errors = []
    atts = ae.extract(msg, errors)

    assert len(atts) == 1
    assert atts[0].is_inline is True
    assert atts[0].content_id == "cid_image_001"


def test_attachment_extractor_zero_byte():
    ae = AttachmentExtractor()
    eml = (
        "Content-Type: multipart/mixed; boundary=\"BOUND\"\r\n\r\n"
        "--BOUND\r\n"
        "Content-Type: text/plain; name=\"empty.txt\"\r\n"
        "Content-Disposition: attachment; filename=\"empty.txt\"\r\n\r\n"
        "\r\n--BOUND--"
    )
    msg = email.message_from_string(eml)
    errors = []
    atts = ae.extract(msg, errors)

    assert len(atts) == 1
    assert atts[0].filename == "empty.txt"
    assert atts[0].content_size_bytes == 0


def test_attachment_extractor_spoofed_extension():
    png_magic_bytes = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15c4"
    mismatch, detected_mime = check_magic_mismatch(png_magic_bytes, "document.pdf", "application/pdf")
    assert mismatch is True
    assert detected_mime == "image/png"


def test_attachment_extractor_size_cap():
    ae = AttachmentExtractor(max_attachment_size_mb=0.001)
    eml = (
        "Content-Type: multipart/mixed; boundary=\"BOUND\"\r\n\r\n"
        "--BOUND\r\n"
        "Content-Type: application/octet-stream; name=\"large.bin\"\r\n"
        "Content-Disposition: attachment; filename=\"large.bin\"\r\n\r\n"
        + ("A" * 5000) +
        "\r\n--BOUND--"
    )
    msg = email.message_from_string(eml)
    errors = []
    atts = ae.extract(msg, errors)

    assert len(atts) == 1
    assert atts[0].md5_hash == ""
    assert any("exceeds configured cap" in err for err in atts[0].parsing_errors)


def test_attachment_extractor_save_to_disk(tmp_path):
    target_dir = tmp_path / "extracted_attachments"
    ae = AttachmentExtractor(save_to=target_dir)

    eml = (
        "Content-Type: multipart/mixed; boundary=\"BOUND\"\r\n\r\n"
        "--BOUND\r\n"
        "Content-Type: text/plain; name=\"save_me.txt\"\r\n"
        "Content-Disposition: attachment; filename=\"save_me.txt\"\r\n\r\n"
        "Extracted to disk content"
        "\r\n--BOUND--"
    )
    msg = email.message_from_string(eml)
    errors = []
    atts = ae.extract(msg, errors)

    assert len(atts) == 1
    files_created = list(target_dir.glob("*save_me.txt"))
    assert len(files_created) == 1
    assert files_created[0].read_text() == "Extracted to disk content"


def test_parse_attachments_functional():
    eml = (
        "Content-Type: multipart/mixed; boundary=\"BOUND\"\r\n\r\n"
        "--BOUND\r\n"
        "Content-Type: text/plain; name=\"func.txt\"\r\n"
        "Content-Disposition: attachment; filename=\"func.txt\"\r\n\r\n"
        "Functional payload"
        "\r\n--BOUND--"
    )
    msg = email.message_from_string(eml)
    errors = []
    atts = parse_attachments(msg, errors)
    assert len(atts) == 1
    assert atts[0].filename == "func.txt"
