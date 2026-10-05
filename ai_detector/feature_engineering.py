"""
Feature Engineering Module for AI Detection Subsystem.

Transforms ParsedEmailResult from the upstream parsing pipeline into a 16-element
float32 numpy array feature vector aligned with FEATURE_NAMES.
"""

import math
import re
from collections import Counter
from typing import Optional
from urllib.parse import urlparse

import numpy as np

from ai_detector.config import FEATURE_NAMES, URGENCY_KEYWORDS
from email_parser.schemas import ParsedEmailResult, ExtractedURL


class FeatureExtractor:
    """Transforms ParsedEmailResult into numerical feature vectors for model inference."""

    @staticmethod
    def compute_shannon_entropy(text: str) -> float:
        """
        Calculates Shannon Entropy H(X) = -sum(p(x) * log2(p(x))) for character distribution.

        Args:
            text: Input string payload.

        Returns:
            Shannon entropy as a float value. Returns 0.0 for empty strings.
        """
        if not text or not isinstance(text, str):
            return 0.0

        length = len(text)
        if length == 0:
            return 0.0

        counts = Counter(text)
        entropy = 0.0
        for count in counts.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)

        return float(entropy)

    @staticmethod
    def _is_mismatched_anchor(url_obj: ExtractedURL) -> bool:
        """Helper to detect if anchor text URL/domain mismatches target URL netloc/domain."""
        if not url_obj:
            return False

        anchor_text = getattr(url_obj, "anchor_text", None)
        if not anchor_text or not isinstance(anchor_text, str):
            return False

        anchor = anchor_text.strip().lower()
        if not anchor:
            return False

        actual_url = getattr(url_obj, "url", "") or ""
        if not actual_url or not isinstance(actual_url, str):
            return False

        # Extract actual host from target URL
        if "://" not in actual_url:
            parsed_actual = urlparse("http://" + actual_url)
        else:
            parsed_actual = urlparse(actual_url)
        actual_host = (parsed_actual.netloc or parsed_actual.path or "").split(":")[0].lower()
        actual_domain = (getattr(url_obj, "domain", None) or "").lower()

        if not actual_host and not actual_domain:
            return False

        # Check if anchor text contains a domain or URL pattern
        anchor_host: Optional[str] = None
        if "http://" in anchor or "https://" in anchor or "www." in anchor:
            url_match = re.search(r'(?:https?://|www\.)[^\s<>"\'()]+', anchor)
            if url_match:
                raw_match = url_match.group(0)
                if not raw_match.startswith("http"):
                    raw_match = "http://" + raw_match
                parsed_anchor = urlparse(raw_match)
                anchor_host = (parsed_anchor.netloc or "").split(":")[0].lower()
        else:
            domain_match = re.search(r'\b([a-z0-9-]+\.[a-z]{2,})\b', anchor)
            if domain_match:
                anchor_host = domain_match.group(1).lower()

        if anchor_host and actual_host:
            if anchor_host != actual_host:
                # Allow subdomain relationships or matching root domain
                if actual_domain and (anchor_host == actual_domain or anchor_host.endswith("." + actual_domain)):
                    return False
                if actual_host == anchor_host or actual_host.endswith("." + anchor_host):
                    return False
                return True

        return False

    def extract_vector(
        self, parsed: Optional[ParsedEmailResult]
    ) -> tuple[np.ndarray, dict[str, float]]:
        """
        Safely extracts all 16 metrics from ParsedEmailResult with defensive fallbacks.

        Args:
            parsed: Upstream ParsedEmailResult instance or None.

        Returns:
            Tuple of (numpy float32 array of shape (16,), dictionary mapping feature name to float value).
        """
        features_dict: dict[str, float] = {}

        if parsed is None or not isinstance(parsed, ParsedEmailResult):
            # Impute default zero vector
            for name in FEATURE_NAMES:
                features_dict[name] = 0.0
            vector = np.zeros((len(FEATURE_NAMES),), dtype=np.float32)
            return vector, features_dict

        # Safely resolve sub-components
        headers = getattr(parsed, "headers", None)
        auth = getattr(headers, "auth_results", None) if headers else None

        # 1. Authentication Pass Flags
        spf_res = (getattr(auth, "spf_result", None) or "").lower()
        features_dict["spf_pass"] = 1.0 if spf_res == "pass" else 0.0

        dkim_res = (getattr(auth, "dkim_result", None) or "").lower()
        features_dict["dkim_pass"] = 1.0 if dkim_res == "pass" else 0.0

        dmarc_res = (getattr(auth, "dmarc_result", None) or "").lower()
        features_dict["dmarc_pass"] = 1.0 if dmarc_res == "pass" else 0.0

        # 2. Hop Chain Metrics
        hops = getattr(headers, "hops", None) if headers else None
        if hops and isinstance(hops, list):
            features_dict["hop_count"] = float(len(hops))
            delays = [
                float(getattr(h, "delay_seconds", 0.0))
                for h in hops
                if getattr(h, "delay_seconds", None) is not None
            ]
            features_dict["max_hop_delay_sec"] = max(0.0, max(delays, default=0.0))
        else:
            features_dict["hop_count"] = 0.0
            features_dict["max_hop_delay_sec"] = 0.0

        # 3. Body Text Features
        body_text = getattr(parsed, "body_text", None) or ""
        body_html = getattr(parsed, "body_html", None) or ""

        features_dict["body_char_count"] = float(len(body_text))
        features_dict["body_entropy"] = self.compute_shannon_entropy(body_text)

        upper_count = sum(1 for c in body_text if c.isupper())
        features_dict["uppercase_ratio"] = float(upper_count) / float(max(1, len(body_text)))

        # 4. Urgency Keyword Count
        subject = (getattr(headers, "subject", None) or "") if headers else ""
        combined_text = (body_text + " " + subject).lower()
        urgency_count = 0
        for kw in URGENCY_KEYWORDS:
            if kw and isinstance(kw, str):
                urgency_count += combined_text.count(kw.lower())
        features_dict["urgency_word_count"] = float(urgency_count)

        # 5. HTML to Text Ratio
        features_dict["html_to_text_ratio"] = float(len(body_html)) / float(max(1, len(body_text)))

        # 6. URL & IOC Features
        urls = getattr(parsed, "urls", None)
        if urls and isinstance(urls, list):
            features_dict["url_count"] = float(len(urls))
            features_dict["ip_literal_count"] = float(
                sum(1 for u in urls if getattr(u, "is_ip_address", False))
            )
            features_dict["defanged_url_count"] = float(
                sum(1 for u in urls if getattr(u, "was_defanged", False))
            )
            features_dict["mismatched_anchor_count"] = float(
                sum(1 for u in urls if self._is_mismatched_anchor(u))
            )
        else:
            features_dict["url_count"] = 0.0
            features_dict["ip_literal_count"] = 0.0
            features_dict["defanged_url_count"] = 0.0
            features_dict["mismatched_anchor_count"] = 0.0

        # 7. Attachment Features
        attachments = getattr(parsed, "attachments", None)
        if attachments and isinstance(attachments, list):
            features_dict["attachment_count"] = float(len(attachments))
            mismatch_found = any(
                getattr(att, "content_type_mismatch", False) for att in attachments
            )
            features_dict["mime_mismatch_detected"] = 1.0 if mismatch_found else 0.0
        else:
            features_dict["attachment_count"] = 0.0
            features_dict["mime_mismatch_detected"] = 0.0

        # Build ordered numpy array matching FEATURE_NAMES sequence
        vector_vals = [features_dict[name] for name in FEATURE_NAMES]
        vector = np.array(vector_vals, dtype=np.float32)

        return vector, features_dict
