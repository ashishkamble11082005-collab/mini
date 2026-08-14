"""
Unit tests for URLExtractor module.
Tests defanged URLs, IP-literal URLs, <a href> vs plaintext, IDN homograph / punycode domains,
and hypothesis property-based tests for defanging normalizer.
"""

from hypothesis import given, strategies as st
from email_parser.url_extractor import URLExtractor, normalize_defanged_url, extract_urls
from email_parser.schemas import BodyData


def test_url_extractor_defanged_normalization():
    norm_url, was_defanged = normalize_defanged_url("hxxps://malicious-site[.]com/login")
    assert norm_url == "https://malicious-site.com/login"
    assert was_defanged is True

    norm_url2, was_defanged2 = normalize_defanged_url("http://phish-site(dot)org/reset")
    assert norm_url2 == "http://phish-site.org/reset"
    assert was_defanged2 is True

    norm_url3, was_defanged3 = normalize_defanged_url("fxps://site[:]/path")
    assert norm_url3 == "https://site:/path"
    assert was_defanged3 is True


def test_url_extractor_ip_literal():
    ue = URLExtractor()
    body = BodyData(plain_text="Check server http://192.168.1.100/status and http://0x7f000001/phish")
    errors = []
    urls = ue.extract_from_body(body, errors)

    assert len(urls) >= 2
    ip_urls = [u for u in urls if u.is_ip_address]
    assert len(ip_urls) >= 1


def test_url_extractor_html_vs_plaintext():
    ue = URLExtractor()
    html_content = '<a href="https://example.com/click">Click Here</a><img src="https://img.example.com/banner.png" alt="Banner" />'
    plain_content = "Visit https://example.com/click or https://other.com/text"
    body = BodyData(plain_text=plain_content, html_raw=html_content)
    errors = []
    urls = ue.extract_from_body(body, errors)

    example_url = [u for u in urls if "example.com/click" in u.url][0]
    assert example_url.occurrence_count >= 2
    assert example_url.anchor_text == "Click Here"


def test_url_extractor_idn_homograph():
    ue = URLExtractor()
    body = BodyData(plain_text="Punycode domain link http://xn--e1afmkfd.xn--p1ai/path")
    errors = []
    urls = ue.extract_from_body(body, errors)

    assert len(urls) == 1
    assert urls[0].domain is not None


def test_extract_urls_functional():
    body = BodyData(plain_text="Visit http://test.org")
    errors = []
    urls = extract_urls(body, errors)
    assert len(urls) == 1
    assert urls[0].url == "http://test.org"


# Hypothesis Property-Based Test for normalize_defanged_url
@given(st.text(min_size=1, max_size=100))
def test_hypothesis_normalize_defanged_url(random_text):
    # Ensure normalize_defanged_url never raises exception on arbitrary string inputs
    norm_url, was_defanged = normalize_defanged_url(random_text)
    assert isinstance(norm_url, str)
    assert isinstance(was_defanged, bool)
