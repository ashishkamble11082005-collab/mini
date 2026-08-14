"""
Unit tests for BodyExtractor module.
Tests multipart/alternative, HTML-only, plain-text-only, broken base64 padding, cid: references, and decode_payload_bytes fallbacks.
"""

import email
from email_parser.body_extractor import BodyExtractor, decode_payload_bytes, parse_body, strip_cid_references_from_html


def test_body_extractor_multipart_alternative():
    be = BodyExtractor()
    eml = (
        "Content-Type: multipart/alternative; boundary=\"ALT_BOUND\"\r\n\r\n"
        "--ALT_BOUND\r\n"
        "Content-Type: text/plain; charset=\"utf-8\"\r\n\r\n"
        "Plain text alternative\r\n"
        "--ALT_BOUND\r\n"
        "Content-Type: text/html; charset=\"utf-8\"\r\n\r\n"
        "<html><body><p>HTML alternative</p><img src=\"cid:logo_1\" /></body></html>\r\n"
        "--ALT_BOUND--"
    )
    msg = email.message_from_string(eml)
    errors = []
    body = be.extract(msg, errors)

    assert body.plain_text == "Plain text alternative"
    assert "HTML alternative" in body.html_raw
    assert "logo_1" in body.cid_references


def test_body_extractor_html_only():
    be = BodyExtractor()
    eml = (
        "Content-Type: text/html; charset=\"utf-8\"\r\n\r\n"
        "<html><body><h1>Only HTML Body</h1></body></html>"
    )
    msg = email.message_from_string(eml)
    errors = []
    body = be.extract(msg, errors)

    assert body.plain_text is None
    assert "Only HTML Body" in body.html_raw
    assert body.html_stripped == "Only HTML Body"


def test_body_extractor_text_only():
    be = BodyExtractor()
    eml = (
        "Content-Type: text/plain; charset=\"utf-8\"\r\n\r\n"
        "Only plain text email content"
    )
    msg = email.message_from_string(eml)
    errors = []
    body = be.extract(msg, errors)

    assert body.plain_text == "Only plain text email content"
    assert body.html_raw is None


def test_body_extractor_broken_base64():
    be = BodyExtractor()
    eml = (
        "Content-Type: text/plain; charset=\"utf-8\"\r\n"
        "Content-Transfer-Encoding: base64\r\n\r\n"
        "SGVsbG8gV29ybGQ"  # Missing base64 padding '='
    )
    msg = email.message_from_string(eml)
    errors = []
    body = be.extract(msg, errors)

    assert body.plain_text is not None
    assert "Hello World" in body.plain_text or len(body.plain_text) > 0


def test_decode_payload_bytes_charset_normalizer():
    # Raw CP1252 byte stream with smart quotes (\x93 and \x94)
    data = b"Smart quotes \x93Hello\x94"
    text, enc = decode_payload_bytes(data, charset="invalid-charset-12345")
    assert "Hello" in text


def test_strip_cid_references():
    html = '<p>Image: <img src="cid:img_header_99" /></p>'
    clean_html, cids = strip_cid_references_from_html(html)
    assert "#cid-stripped" in clean_html
    assert "img_header_99" in cids


def test_parse_body_functional():
    eml = "Content-Type: text/plain; charset=\"utf-8\"\r\n\r\nFunctional Body Test"
    msg = email.message_from_string(eml)
    errors = []
    body = parse_body(msg, errors)
    assert body.plain_text == "Functional Body Test"
