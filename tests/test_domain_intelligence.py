from threat_intelligence.domain_intelligence import analyze_domain


def test_clean_domain():
    result = analyze_domain("example.com")

    assert result["status"] == "ANALYZED"
    assert result["risk"] == "NO_FINDINGS"
    assert result["domain"] == "example.com"


def test_ip_address():
    result = analyze_domain("192.168.1.50")

    assert result["status"] == "IP_ADDRESS"
    assert result["risk"] == "MEDIUM"


def test_invalid_domain_structure():
    result = analyze_domain("localhost")

    assert result["status"] == "ANALYZED"
    assert result["risk"] == "MEDIUM"

    finding_types = {
        finding["type"]
        for finding in result["findings"]
    }

    assert "invalid_domain_structure" in finding_types


def test_excessive_label_length():
    domain = "a" * 64 + ".com"

    result = analyze_domain(domain)

    finding_types = {
        finding["type"]
        for finding in result["findings"]
    }

    assert "excessive_label_length" in finding_types


def test_dns_information_present():
    result = analyze_domain("example.com")

    assert "dns" in result
    assert "a" in result["dns"]
    assert "aaaa" in result["dns"]
    assert "mx" in result["dns"]
    assert "nameservers" in result["dns"]

from unittest.mock import patch


def test_dns_records_are_collected():
    fake_dns = {
        "a": ["192.0.2.1"],
        "aaaa": ["2001:db8::1"],
        "mx": ["mail.example.com"],
        "nameservers": ["ns1.example.com"],
    }

    with patch(
        "threat_intelligence.domain_intelligence._resolve_dns",
        return_value=fake_dns,
    ):
        result = analyze_domain("example.com")

    assert result["dns"]["a"] == ["192.0.2.1"]
    assert result["dns"]["aaaa"] == ["2001:db8::1"]
    assert result["dns"]["mx"] == ["mail.example.com"]
    assert result["dns"]["nameservers"] == ["ns1.example.com"]


def test_dns_resolution_failure_is_reported():
    fake_dns = {
        "a": [],
        "aaaa": [],
        "mx": [],
        "nameservers": [],
    }

    with patch(
        "threat_intelligence.domain_intelligence._resolve_dns",
        return_value=fake_dns,
    ):
        result = analyze_domain("nonexistent.example")

    finding_types = {
        finding["type"]
        for finding in result["findings"]
    }

    assert "dns_resolution_failed" in finding_types
    assert result["risk"] == "MEDIUM"