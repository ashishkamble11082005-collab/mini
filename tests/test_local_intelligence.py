from threat_intelligence.local_url_intelligence import analyze_url_locally
from threat_intelligence.local_attachment_intelligence import analyze_attachment_locally


def test_ip_url():
    result = analyze_url_locally("http://192.168.1.50/admin")

    assert result["risk"] == "MEDIUM"
    assert any(
        finding["type"] == "ip_address_url"
        for finding in result["findings"]
    )


def test_suspicious_login_url():
    result = analyze_url_locally(
        "https://secure-login.phish-domain.com/verify"
    )

    assert result["risk"] == "MEDIUM"
    assert any(
        finding["type"] == "suspicious_keyword"
        for finding in result["findings"]
    )


def test_clean_url():
    result = analyze_url_locally("https://example.com")

    assert result["risk"] == "NO_FINDINGS"
    assert result["findings"] == []


def test_dangerous_attachment():
    result = analyze_attachment_locally(
        "invoice.pdf.exe",
        "application/octet-stream",
    )

    assert result["risk"] == "HIGH"
    assert any(
        finding["type"] == "dangerous_file_extension"
        for finding in result["findings"]
    )


def test_double_extension():
    result = analyze_attachment_locally(
        "invoice.pdf.exe",
        "application/octet-stream",
    )

    assert any(
        finding["type"] == "double_extension"
        for finding in result["findings"]
    )