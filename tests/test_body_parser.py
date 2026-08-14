"""
Unit tests for Body Parser module.
Tests MIME body extraction, multi-encoding fallbacks, BeautifulSoup HTML parsing, ExtractedURL extraction & defanging/IP checks, and hidden CSS text detection.
"""

import email
from email_parser.body_parser import parse_body, is_obfuscated_url, detect_hidden_text, check_was_defanged, check_is_ip_address
from bs4 import BeautifulSoup


def test_url_defanged_check():
    assert check_was_defanged("hxxps://malicious[.]site/login") is True
    assert check_was_defanged("https://normal-site.com") is False


def test_url_is_ip_address_check():
    assert check_is_ip_address("192.168.1.1", "http://192.168.1.1/admin") is True
    assert check_is_ip_address("0x7f000001", "http://0x7f000001/phish") is True
    assert check_is_ip_address("example.com", "http://example.com/welcome") is False


def test_url_obfuscation_zero_width_chars():
    obfuscated_url = "http://pay\u200bpal.com/login"
    assert is_obfuscated_url(obfuscated_url) is True


def test_url_obfuscation_hex_ip():
    hex_url = "http://0x7f000001/phish"
    assert is_obfuscated_url(hex_url) is True


def test_url_obfuscation_at_trickery():
    at_url = "http://google.com@attacker-site.com/login"
    assert is_obfuscated_url(at_url) is True


def test_url_obfuscation_anchor_mismatch():
    dest_url = "https://evil-phish.com/reset"
    anchor = "https://paypal.com/security"
    assert is_obfuscated_url(dest_url, anchor_text=anchor) is True


def test_detect_hidden_text_css():
    html_content = """
    <html>
        <body>
            <p>Normal text</p>
            <span style="display: none;">Hidden phishing keyword</span>
            <div style="font-size: 0px;">Zero font hidden text</div>
            <div style="color: #ffffff; background-color: #ffffff;">White text on white background</div>
        </body>
    </html>
    """
    soup = BeautifulSoup(html_content, "html.parser")
    assert detect_hidden_text(soup) is True


def test_parse_body_multipart_html_and_text():
    errors = []
    eml_raw = (
        "Content-Type: multipart/alternative; boundary=\"BOUNDARY\"\r\n\r\n"
        "--BOUNDARY\r\n"
        "Content-Type: text/plain; charset=\"iso-8859-1\"\r\n\r\n"
        "Please visit http://example.com/welcome\r\n"
        "--BOUNDARY\r\n"
        "Content-Type: text/html; charset=\"utf-8\"\r\n\r\n"
        "<html><body><a href=\"https://secure-login.com\" style=\"display:none\">Click Here</a></body></html>\r\n"
        "--BOUNDARY--"
    )
    msg = email.message_from_string(eml_raw)
    body = parse_body(msg, errors)

    assert body.plain_text is not None
    assert "http://example.com/welcome" in body.plain_text
    assert body.html_raw is not None
    assert body.hidden_text_detected is True
    assert len(body.urls) >= 2
    assert "iso-8859-1" in body.charsets_detected or "utf-8" in body.charsets_detected


def test_parse_body_corrupted_encoding():
    errors = []
    msg = email.message.Message()
    msg.set_type("text/plain")
    msg.set_param("charset", "utf-8")
    msg.set_payload(b"Hello \xff\xfe World Invalid Bytes")

    body = parse_body(msg, errors)
    assert body.plain_text is not None
    assert "Hello" in body.plain_text
    assert len(errors) == 0
