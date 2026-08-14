"""
End-to-end integration tests for EmailParser orchestrator across fixtures.
"""

import pytest
from pathlib import Path
from email_parser import EmailParser, ParsedEmailResult


@pytest.fixture
def parser():
    return EmailParser()


def test_e2e_plain_text_fixture(parser, fixtures_dir):
    eml_path = fixtures_dir / "plain_text.eml"
    result = parser.parse_file(eml_path)

    assert isinstance(result, ParsedEmailResult)
    assert result.headers.subject == "Plain Text Email Test"
    assert result.headers.sender.address == "alice@example.com"
    assert result.body_text is not None
    assert "simple plain text body" in result.body_text
    assert len(result.urls) >= 1
    assert result.parse_duration_ms > 0.0


def test_e2e_multipart_html_fixture(parser, fixtures_dir):
    eml_path = fixtures_dir / "multipart_html.eml"
    result = parser.parse_file(eml_path)

    assert isinstance(result, ParsedEmailResult)
    assert result.headers.subject == "News Alert: Security"
    assert result.body_html is not None
    assert len(result.urls) >= 1


def test_e2e_attachment_fixture(parser, fixtures_dir):
    eml_path = fixtures_dir / "attachment.eml"
    result = parser.parse_file(eml_path)

    assert isinstance(result, ParsedEmailResult)
    assert result.headers.subject == "Important Document Attached"
    assert len(result.attachments) == 1
    att = result.attachments[0]
    assert att.filename == "Report.pdf"
    assert att.content_size_bytes > 0
    assert len(att.sha256_hash) == 64


def test_e2e_phishing_defanged_fixture(parser, fixtures_dir):
    eml_path = fixtures_dir / "phishing_defanged.eml"
    result = parser.parse_file(eml_path)

    assert isinstance(result, ParsedEmailResult)
    defanged_urls = [u for u in result.urls if u.was_defanged]
    assert len(defanged_urls) >= 1
    assert any(u.is_ip_address for u in result.urls)


def test_e2e_malformed_corrupt_fixture(parser, fixtures_dir):
    eml_path = fixtures_dir / "malformed_corrupt.eml"
    result = parser.parse_file(eml_path)

    assert isinstance(result, ParsedEmailResult)
    # Never crashes, captures warnings/errors in parsing_errors list
    assert isinstance(result.parsing_errors, list)
