"""
Unit tests for HeaderParser module.
Tests missing Date, malformed From, non-ASCII Subject, multimap raw_headers, dateutil fallbacks, Received hops, and Auth-Results.
"""

import email
from email_parser.header_parser import (
    HeaderParser,
    decode_header_value,
    parse_headers,
)


def test_header_parser_valid():
    hp = HeaderParser()
    raw = (
        "From: Alice <alice@example.com>\r\n"
        "To: Bob <bob@example.com>\r\n"
        "Subject: =?UTF-8?B?TmV3cyBBbGVydA==?=\r\n"
        "Date: Thu, 13 Aug 2026 12:00:00 +0000\r\n"
        "Received: from server1 by server2; Thu, 13 Aug 2026 11:59:00 +0000\r\n"
        "Received: from client by server1; Thu, 13 Aug 2026 11:58:00 +0000\r\n\r\n"
        "Body"
    ).encode("utf-8")

    errors = []
    hdr = hp.parse(raw, errors)

    assert hdr.subject == "News Alert"
    assert hdr.sender.address == "alice@example.com"
    assert hdr.date is not None
    assert len(hdr.raw_headers["received"]) == 2


def test_header_parser_missing_date():
    hp = HeaderParser()
    raw = (
        "From: Alice <alice@example.com>\r\n"
        "Subject: Missing Date Header\r\n\r\nBody"
    ).encode("utf-8")

    errors = []
    hdr = hp.parse(raw, errors)

    assert hdr.subject == "Missing Date Header"
    assert hdr.date is None
    assert len(errors) == 0


def test_header_parser_malformed_from():
    hp = HeaderParser()
    raw = (
        "From: =?INVALID?Q?Broken_Name <broken-addr\r\n"
        "Subject: Malformed From Test\r\n\r\nBody"
    ).encode("utf-8")

    errors = []
    hdr = hp.parse(raw, errors)

    assert hdr.subject == "Malformed From Test"
    assert hdr.sender is not None
    assert isinstance(errors, list)


def test_header_parser_non_ascii_subject():
    hp = HeaderParser()
    raw = (
        "From: sender@domain.com\r\n"
        "Subject: =?UTF-8?Q?S=c3=a9curit=c3=a9_Alert?=\r\n\r\nBody"
    ).encode("utf-8")

    errors = []
    hdr = hp.parse(raw, errors)

    assert hdr.subject == "Sécurité Alert"


def test_header_parser_dateutil_fallback():
    hp = HeaderParser()
    errors = []
    # ISO date string instead of standard RFC 2822 date
    raw_date = "2026-08-13 14:30:00"
    iso = hp.parse_date_to_iso(raw_date, errors)
    assert iso is not None
    assert "2026-08-13T14:30:00" in iso


def test_header_parser_auth_results():
    hp = HeaderParser()
    eml_raw = (
        "Authentication-Results: mx.google.com; spf=pass dkim=pass dmarc=fail\r\n"
        "Received-SPF: pass (google.com: domain of sender@example.com designates 1.2.3.4)\r\n"
        "DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=s1; h=from:to:subject; bh=xyz=; b=sig1=\r\n"
        "DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=thirdparty.com; s=s2; h=from:to; bh=abc=; b=sig2=\r\n"
        "Subject: Auth Test\r\n\r\nBody"
    )
    msg = email.message_from_string(eml_raw)
    errors = []
    hdr = hp.parse(msg, errors)

    assert hdr.auth_results.spf_result == "pass"
    assert hdr.auth_results.dkim_result == "pass"
    assert hdr.auth_results.dmarc_result == "fail"

    # Verify dedicated raw dkim_signatures extraction for independent RSA cryptographic verification
    assert len(hdr.dkim_signatures) == 2
    assert "d=example.com" in hdr.dkim_signatures[0]
    assert "d=thirdparty.com" in hdr.dkim_signatures[1]


def test_header_parser_invalid_source():
    hp = HeaderParser()
    errors = []
    hdr = hp.parse(12345, errors)  # Invalid int source
    assert hdr.subject is None
    assert len(errors) == 1


def test_decode_header_value_edge_cases():
    assert decode_header_value(None) is None
    assert decode_header_value("") is None
    assert decode_header_value("Plain Text Header") == "Plain Text Header"


def test_parse_headers_functional():
    eml_raw = "From: <user@test.com>\r\nSubject: Functional Test\r\n\r\n"
    msg = email.message_from_string(eml_raw)
    errors = []
    hdr = parse_headers(msg, errors)
    assert hdr.subject == "Functional Test"
