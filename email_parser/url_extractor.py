"""
URL Extractor Module for Email Processing & Parsing.

Provides URLExtractor class using regex + BeautifulSoup DOM scanning,
tldextract domain parsing, defanged URL normalization (hxxp, [.], (dot)),
IP-literal detection, IDN homograph / punycode support, and occurrence counting.
"""

import re
import logging
import urllib.parse
import tldextract  # type: ignore # pyrefly: ignore [missing-import]
from typing import Optional
from bs4 import BeautifulSoup  # type: ignore # pyrefly: ignore [missing-import]

from email_parser.schemas import ExtractedURL, BodyData

logger = logging.getLogger(__name__)

# Patterns for normal and defanged URLs
URL_REGEX = re.compile(
    r"(?:https?|hxxps?|fxps?|ftp)://[a-zA-Z0-9.\-\[\]\(\)]+(?::[0-9]+)?(?:/[^\s<>'\"`\(\)]*)?",
    re.IGNORECASE,
)
ZERO_WIDTH_CHARS = re.compile(r"[\u200b\u200c\u200d\ufeff\u00ad\u200e\u200f]")
IPV4_REGEX = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
IPV6_REGEX = re.compile(r"^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::1$")
HEX_OCTAL_IP_REGEX = re.compile(r"https?://(?:0x[0-9a-fA-F]+|[0-9]{8,11})\b", re.IGNORECASE)
CSS_URL_REGEX = re.compile(r"url\s*\(\s*['\"]?(https?://[^'\"]+)['\"]?\s*\)", re.IGNORECASE)


def normalize_defanged_url(raw_url: str) -> tuple[str, bool]:
    """
    Detects and refangs defanged URLs (e.g., hxxp -> http, [.] -> ., (dot) -> .).

    Args:
        raw_url: Raw candidate URL string.

    Returns:
        Tuple of (normalized_valid_url, was_defanged: bool).
    """
    was_defanged = False
    url = raw_url.strip()

    # Scheme defanging
    if url.lower().startswith("hxxps://"):
        url = "https://" + url[8:]
        was_defanged = True
    elif url.lower().startswith("hxxp://"):
        url = "http://" + url[7:]
        was_defanged = True
    elif url.lower().startswith("fxps://"):
        url = "https://" + url[7:]
        was_defanged = True
    elif url.lower().startswith("fxp://"):
        url = "http://" + url[6:]
        was_defanged = True

    # Host/domain dot defanging
    if "[.]" in url:
        url = url.replace("[.]", ".")
        was_defanged = True
    if "(.)" in url:
        url = url.replace("(.)", ".")
        was_defanged = True
    if "[:]" in url:
        url = url.replace("[:]", ":")
        was_defanged = True
    if "(:)" in url:
        url = url.replace("(:)", ":")
        was_defanged = True
    if re.search(r"\b\(dot\)\b", url, re.IGNORECASE):
        url = re.sub(r"\b\(dot\)\b", ".", url, flags=re.IGNORECASE)
        was_defanged = True

    return url, was_defanged


def is_ip_host(domain: Optional[str], url: str) -> bool:
    """Checks if domain/host is an IP address literal (IPv4, IPv6, Hex/Octal)."""
    if HEX_OCTAL_IP_REGEX.search(url):
        return True
    if not domain:
        return False
    clean_domain = domain.strip("[]")
    if IPV4_REGEX.match(clean_domain) or IPV6_REGEX.match(clean_domain):
        return True
    return False


class URLExtractor:
    """
    URL and IOC Extractor scanning plain text and HTML DOMs.
    Normalizes defanged URLs, parses domains via tldextract, and tracks occurrence counts.
    """

    def __init__(self):
        self.tld_extractor = tldextract.TLDExtract(include_psl_private_domains=True)

    def extract_from_body(self, body_data: BodyData, parsing_errors: list[str]) -> list[ExtractedURL]:
        """
        Extracts, normalizes, and aggregates all URLs from BodyData.

        Args:
            body_data: BodyData container.
            parsing_errors: Error tracking list.

        Returns:
            List of ExtractedURL objects.
        """
        url_map: dict[str, ExtractedURL] = {}

        def process_candidate(raw_url: str, anchor_text: Optional[str] = None, source: str = "plain_text"):
            if not raw_url or raw_url.startswith("data:"):
                return

            try:
                # Clean zero-width space characters
                cleaned = ZERO_WIDTH_CHARS.sub("", raw_url).strip()
                normalized_url, was_defanged = normalize_defanged_url(cleaned)

                # Ensure valid URL structure
                parsed = urllib.parse.urlparse(normalized_url)
                if not parsed.scheme or not parsed.netloc:
                    # Try adding http:// if netloc missing
                    if not parsed.scheme and "://" not in normalized_url:
                        normalized_url = "http://" + normalized_url
                        parsed = urllib.parse.urlparse(normalized_url)

                if not parsed.netloc:
                    return

                key = normalized_url.lower()

                if key in url_map:
                    url_map[key].occurrence_count += 1
                    if anchor_text and not url_map[key].anchor_text:
                        url_map[key].anchor_text = anchor_text.strip()
                else:
                    # Domain extraction via tldextract
                    ext = self.tld_extractor(normalized_url)
                    domain = ext.fqdn or parsed.netloc.lower()

                    # Check IDN homograph / punycode
                    if domain.startswith("xn--"):
                        try:
                            domain = domain.encode("ascii").decode("idna")
                        except Exception:
                            pass

                    is_ip = is_ip_host(domain, normalized_url)
                    obfuscated = ZERO_WIDTH_CHARS.search(raw_url) is not None or HEX_OCTAL_IP_REGEX.search(normalized_url) is not None

                    url_map[key] = ExtractedURL(
                        url=normalized_url,
                        domain=domain,
                        scheme=parsed.scheme.lower(),
                        is_ip_address=is_ip,
                        was_defanged=was_defanged,
                        occurrence_count=1,
                        anchor_text=anchor_text.strip() if anchor_text else None,
                        is_obfuscated=obfuscated,
                        source=source,
                    )

            except Exception as e:
                err_msg = f"Skipped malformed URL '{raw_url}': {e}"
                logger.warning(err_msg)
                parsing_errors.append(err_msg)

        # 1. DOM extraction from raw HTML
        if body_data.html_raw:
            try:
                soup = BeautifulSoup(body_data.html_raw, "html.parser")
                for a_tag in soup.find_all("a", href=True):
                    process_candidate(a_tag["href"], anchor_text=a_tag.get_text(), source="html_href")
                for img_tag in soup.find_all("img", src=True):
                    process_candidate(img_tag["src"], anchor_text=img_tag.get("alt"), source="html_img_src")
                for script_tag in soup.find_all("script", src=True):
                    process_candidate(script_tag["src"], source="html_script_src")
                for iframe_tag in soup.find_all("iframe", src=True):
                    process_candidate(iframe_tag["src"], source="html_iframe_src")
                for form_tag in soup.find_all("form", action=True):
                    process_candidate(form_tag["action"], source="html_form_action")
                for style_tag in soup.find_all("style"):
                    if style_tag.string:
                        for m in CSS_URL_REGEX.finditer(style_tag.string):
                            process_candidate(m.group(1), source="html_css_tag")
            except Exception as e:
                err_msg = f"Error scanning HTML DOM for URLs: {e}"
                logger.warning(err_msg)
                parsing_errors.append(err_msg)

        # 2. Plain text regex scanning
        text_sources = []
        if body_data.plain_text:
            text_sources.append(body_data.plain_text)
        if body_data.html_stripped:
            text_sources.append(body_data.html_stripped)

        for text in text_sources:
            for match in URL_REGEX.finditer(text):
                process_candidate(match.group(0), source="plain_text")

        return list(url_map.values())


# Functional entrypoint
def extract_urls(body_data: BodyData, parsing_errors: list[str]) -> list[ExtractedURL]:
    extractor = URLExtractor()
    return extractor.extract_from_body(body_data, parsing_errors)
