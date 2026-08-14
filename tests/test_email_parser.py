"""
Integration unit tests for EmailParser orchestrator.
Verifies end-to-end parsing pipeline against ParsedEmailResult contract, exception resilience, parse_duration_ms tracking, and malformed inputs.
"""

import io
import pytest
from pathlib import Path
from email_parser import EmailParser, ParsedEmailResult


@pytest.fixture
def parser():
    return EmailParser(max_recursion_depth=3)


def test_parse_bytes_valid_email(parser):
    eml_raw = (
        "From: sender@example.com\r\n"
        "To: recipient@example.com\r\n"
        "Subject: Integration Test\r\n"
        "Date: Thu, 13 Aug 2026 12:00:00 +0000\r\n"
        "Content-Type: text/plain\r\n\r\n"
        "Hello World Pipeline"
    ).encode("utf-8")

    res = parser.parse_bytes(eml_raw)
    assert isinstance(res, ParsedEmailResult)
    assert res.headers.subject == "Integration Test"
    assert res.headers.sender.address == "sender@example.com"
    assert res.body_text == "Hello World Pipeline"
    assert res.parse_duration_ms >= 0.0
    assert res.raw_size_bytes == len(eml_raw)
    assert len(res.parsing_errors) == 0


def test_parse_bytes_zero_length(parser):
    res = parser.parse_bytes(b"")
    assert isinstance(res, ParsedEmailResult)
    assert res.raw_size_bytes == 0
    assert len(res.parsing_errors) > 0
    assert "empty or zero-length" in res.parsing_errors[0]


def test_parse_bytes_garbage_data(parser):
    garbage = b"\x00\x01\x02\xfe\xff\x80\x90\x00\x00" * 100
    res = parser.parse_bytes(garbage)
    assert isinstance(res, ParsedEmailResult)
    assert res.raw_size_bytes == len(garbage)
    assert isinstance(res.parsing_errors, list)


def test_parse_file_non_existent(parser):
    res = parser.parse_file("non_existent_file_path_12345.eml")
    assert isinstance(res, ParsedEmailResult)
    assert len(res.parsing_errors) > 0
    assert "File not found" in res.parsing_errors[0]


def test_parse_file_existing(parser, tmp_path):
    file_path = tmp_path / "test.eml"
    eml_content = (
        "From: Alice <alice@test.com>\r\n"
        "To: Bob <bob@test.com>\r\n"
        "Subject: File Test\r\n\r\n"
        "File body content"
    ).encode("utf-8")
    file_path.write_bytes(eml_content)

    res = parser.parse_file(file_path)
    assert isinstance(res, ParsedEmailResult)
    assert res.headers.subject == "File Test"
    assert res.headers.sender.name == "Alice"


def test_parse_stream(parser):
    eml_bytes = b"Subject: Stream Test\r\n\r\nStream Body Content"
    stream = io.BytesIO(eml_bytes)

    res = parser.parse_stream(stream)
    assert isinstance(res, ParsedEmailResult)
    assert res.headers.subject == "Stream Test"
    assert res.body_text == "Stream Body Content"


def test_embedded_eml_recursion_limit(parser):
    inner_eml = (
        "From: inner@test.com\r\n"
        "Subject: Inner Email\r\n\r\nInner Content"
    )

    outer_eml = (
        "From: outer@test.com\r\n"
        "Subject: Outer Email\r\n"
        "Content-Type: multipart/mixed; boundary=\"OUTER_BOUND\"\r\n\r\n"
        "--OUTER_BOUND\r\n"
        "Content-Type: message/rfc822\r\n"
        "Content-Disposition: attachment; filename=\"nested.eml\"\r\n\r\n"
        + inner_eml + "\r\n"
        "--OUTER_BOUND--"
    ).encode("utf-8")

    res = parser.parse_bytes(outer_eml)
    assert isinstance(res, ParsedEmailResult)
    assert res.headers.subject == "Outer Email"
    assert len(res.attachments) == 1
    assert res.attachments[0].filename == "nested.eml"
