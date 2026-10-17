"""
Body parser module adapter re-exporting BodyExtractor and security helper functions.
"""

import re
import urllib.parse
import email.message
from typing import Optional
from bs4 import BeautifulSoup  # type: ignore # pyrefly: ignore [missing-import]
from email_parser.schemas import BodyData
from email_parser.body_extractor import BodyExtractor, decode_payload_bytes
from email_parser.url_extractor import URLExtractor, normalize_defanged_url, is_ip_host, ZERO_WIDTH_CHARS, HEX_OCTAL_IP_REGEX


def parse_body(msg: email.message.Message, parsing_errors: list[str]) -> BodyData:
    """Extracts body content and populates extracted URLs."""
    extractor = BodyExtractor()
    body_data = extractor.extract(msg, parsing_errors)
    url_extractor = URLExtractor()
    body_data.urls = url_extractor.extract_from_body(body_data, parsing_errors)
    return body_data


def check_was_defanged(url: str) -> bool:
    """Checks if a URL exhibited defanged format."""
    _, was_defanged = normalize_defanged_url(url)
    return was_defanged


def check_is_ip_address(domain: Optional[str], url: str) -> bool:
    """Checks if a domain/URL targets an IP address literal."""
    return is_ip_host(domain, url)


def is_obfuscated_url(url: str, anchor_text: Optional[str] = None) -> bool:
    """Checks if a URL exhibits phishing obfuscation signatures."""
    if ZERO_WIDTH_CHARS.search(url) or HEX_OCTAL_IP_REGEX.search(url):
        return True

    parsed = urllib.parse.urlparse(url)
    if parsed.username or "@" in (parsed.netloc or ""):
        return True

    if anchor_text:
        anchor_clean = anchor_text.strip()
        if anchor_clean.startswith("http://") or anchor_clean.startswith("https://"):
            try:
                anchor_host = urllib.parse.urlparse(anchor_clean).netloc.lower()
                dest_host = parsed.netloc.lower()
                if anchor_host and dest_host and anchor_host != dest_host:
                    return True
            except Exception:
                pass
    return False


def detect_hidden_text(soup: BeautifulSoup) -> bool:
    """Scans BeautifulSoup HTML object for hidden CSS text trickery."""
    hidden_style_pattern = re.compile(
        r"display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|font-size\s*:\s*1px|opacity\s*:\s*0",
        re.IGNORECASE,
    )
    for tag in soup.find_all(True, style=True):
        if hidden_style_pattern.search(tag["style"]):
            if tag.get_text(strip=True):
                return True

    color_pattern = re.compile(r"color\s*:\s*(#fff|#ffffff|white);?\s*background(?:-color)?\s*:\s*(#fff|#ffffff|white)", re.IGNORECASE)
    for tag in soup.find_all(True, style=True):
        if color_pattern.search(tag["style"]):
            if tag.get_text(strip=True):
                return True

    return False


__all__ = [
    "BodyExtractor",
    "parse_body",
    "decode_payload_bytes",
    "check_was_defanged",
    "check_is_ip_address",
    "is_obfuscated_url",
    "detect_hidden_text",
]
