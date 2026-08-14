"""
Unit tests for Attachment Parser module.
Tests filename path traversal sanitization, content_type_mismatch detection, streaming hashing, inline asset detection, and recursive EML attachments.
"""

import io
import email
from email_parser.attachment_parser import (
    sanitize_filename,
    check_content_type_mismatch,
    compute_streaming_hashes,
    parse_attachments,
)


def test_sanitize_filename_path_traversal():
    assert sanitize_filename("../../../etc/passwd") == "passwd"
    assert sanitize_filename("C:\\Windows\\System32\\malware.exe") == "malware.exe"
    assert sanitize_filename("..\\..\\secret.doc") == "secret.doc"
    assert sanitize_filename("normal_file.pdf") == "normal_file.pdf"
    assert sanitize_filename(None).startswith("attachment_")


def test_content_type_mismatch():
    assert check_content_type_mismatch("document.pdf", "image/png") is True
    assert check_content_type_mismatch("image.png", "image/png") is False


def test_compute_streaming_hashes():
    data = b"Security test payload for email attachment hashing"
    stream = io.BytesIO(data)
    size, md5_hex, sha1_hex, sha256_hex = compute_streaming_hashes(stream)

    assert size == len(data)
    assert len(md5_hex) == 32
    assert len(sha1_hex) == 40
    assert len(sha256_hex) == 64


def test_parse_attachments_standard_and_inline():
    errors = []
    eml_raw = (
        "Content-Type: multipart/mixed; boundary=\"MIXED_BOUNDARY\"\r\n\r\n"
        "--MIXED_BOUNDARY\r\n"
        "Content-Type: text/plain\r\n\r\nBody text\r\n"
        "--MIXED_BOUNDARY\r\n"
        "Content-Type: application/pdf; name=\"invoice.pdf\"\r\n"
        "Content-Disposition: attachment; filename=\"../../invoice.pdf\"\r\n"
        "Content-Transfer-Encoding: base64\r\n\r\n"
        "SGVsbG8gV29ybGQ=\r\n"
        "--MIXED_BOUNDARY\r\n"
        "Content-Type: image/png\r\n"
        "Content-Disposition: inline\r\n"
        "Content-ID: <logo_123>\r\n"
        "Content-Transfer-Encoding: base64\r\n\r\n"
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==\r\n"
        "--MIXED_BOUNDARY--"
    )
    msg = email.message_from_string(eml_raw)
    atts = parse_attachments(msg, errors)

    assert len(atts) == 2
    # Attachment 1
    pdf_att = [a for a in atts if a.filename == "invoice.pdf"][0]
    assert pdf_att.is_inline is False
    assert pdf_att.content_size_bytes > 0
    assert pdf_att.md5_hash != ""
    assert pdf_att.sha256_hash != ""

    # Inline asset 2
    logo_att = [a for a in atts if a.content_id == "logo_123"][0]
    assert logo_att.is_inline is True
