"""
Unit tests for mini.ai_detector.feature_engineering module.
"""

import math
import numpy as np
from ai_detector.feature_engineering import FeatureExtractor
from ai_detector.config import FEATURE_NAMES, URGENCY_KEYWORDS
from email_parser.schemas import (
    ParsedEmailResult,
    HeaderData,
    AuthResults,
    HopInfo,
    ExtractedURL,
    AttachmentMetadata,
)


def test_compute_shannon_entropy():
    extractor = FeatureExtractor()

    # Empty text -> 0.0
    assert extractor.compute_shannon_entropy("") == 0.0
    assert extractor.compute_shannon_entropy(None) == 0.0

    # Single repeated char -> 0.0
    assert extractor.compute_shannon_entropy("aaaaa") == 0.0

    # Equal distribution: 2 unique chars "ab" -> - (0.5 * log2(0.5) * 2) = 1.0
    assert math.isclose(extractor.compute_shannon_entropy("ab"), 1.0)


def test_extract_vector_none_input():
    extractor = FeatureExtractor()
    vector, summary = extractor.extract_vector(None)

    assert isinstance(vector, np.ndarray)
    assert vector.shape == (16,)
    assert vector.dtype == np.float32
    assert len(summary) == 16
    assert np.all(vector == 0.0)


def test_extract_vector_empty_parsed_email():
    extractor = FeatureExtractor()
    parsed = ParsedEmailResult()
    vector, summary = extractor.extract_vector(parsed)

    assert vector.shape == (16,)
    assert vector.dtype == np.float32
    assert summary["body_char_count"] == 0.0
    assert summary["body_entropy"] == 0.0
    assert summary["uppercase_ratio"] == 0.0
    assert summary["html_to_text_ratio"] == 0.0


def test_extract_vector_full_featured_email():
    extractor = FeatureExtractor()

    headers = HeaderData(
        subject="URGENT: Password Reset & Verify Account Immediately",
        auth_results=AuthResults(spf_result="pass", dkim_result="pass", dmarc_result="fail"),
        hops=[
            HopInfo(hop_number=1, delay_seconds=1.2),
            HopInfo(hop_number=2, delay_seconds=5.4),
        ],
    )

    urls = [
        ExtractedURL(url="http://192.168.1.1/admin", is_ip_address=True),
        ExtractedURL(url="hxxp://malicious[.]com", was_defanged=True),
        ExtractedURL(
            url="http://phishing-site.ru/login",
            anchor_text="http://paypal.com",
            domain="phishing-site.ru",
        ),
    ]

    attachments = [
        AttachmentMetadata(filename="invoice.pdf.exe", content_type_mismatch=True)
    ]

    parsed = ParsedEmailResult(
        headers=headers,
        body_text="PLEASE RESET YOUR PASSWORD IMMEDIATELY. URGENT WIRE TRANSFER REQUIRED.",
        body_html="<html><body><p>PLEASE RESET YOUR PASSWORD IMMEDIATELY.</p></body></html>",
        urls=urls,
        attachments=attachments,
    )

    vector, summary = extractor.extract_vector(parsed)

    assert vector.shape == (16,)
    assert vector.dtype == np.float32

    # Check extracted values
    assert summary["spf_pass"] == 1.0
    assert summary["dkim_pass"] == 1.0
    assert summary["dmarc_pass"] == 0.0
    assert summary["hop_count"] == 2.0
    assert summary["max_hop_delay_sec"] == 5.4
    assert summary["url_count"] == 3.0
    assert summary["ip_literal_count"] == 1.0
    assert summary["defanged_url_count"] == 1.0
    assert summary["mismatched_anchor_count"] == 1.0
    assert summary["attachment_count"] == 1.0
    assert summary["mime_mismatch_detected"] == 1.0
    assert summary["urgency_word_count"] >= 3.0


def test_mismatched_anchor_detection():
    extractor = FeatureExtractor()

    # Valid anchor matching target
    valid_url = ExtractedURL(
        url="https://bank.com/login",
        anchor_text="https://bank.com",
        domain="bank.com",
    )
    assert not extractor._is_mismatched_anchor(valid_url)

    # Mismatched anchor text domain
    phish_url = ExtractedURL(
        url="https://evil-hacker.com/login",
        anchor_text="https://secure.paypal.com",
        domain="evil-hacker.com",
    )
    assert extractor._is_mismatched_anchor(phish_url)
