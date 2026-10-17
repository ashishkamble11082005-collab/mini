"""
Body Extractor Module for Email Processing & Parsing.

Provides BodyExtractor class to recursively walk MIME multipart trees (multipart/alternative,
multipart/mixed, multipart/related), decode base64/quoted-printable payloads via get_content() with fallbacks,
resolve missing/corrupted charsets via charset-normalizer, and strip/preserve cid: inline-image references.
"""

import re
import logging
import email.message
from typing import Optional
from bs4 import BeautifulSoup  # type: ignore # pyrefly: ignore [missing-import]

from email_parser.schemas import BodyData

logger = logging.getLogger(__name__)

CID_SRC_REGEX = re.compile(r"src=['\"]cid:([^'\"]+)['\"]", re.IGNORECASE)
CID_URL_REGEX = re.compile(r"cid:([^\s'\"`>]+)", re.IGNORECASE)


def decode_payload_bytes(payload: bytes, charset: Optional[str] = None) -> tuple[str, str]:
    """
    Decodes raw payload bytes trying declared charset, utf-8, charset-normalizer, or common fallbacks.

    Args:
        payload: Raw bytes payload.
        charset: Declared MIME charset string.

    Returns:
        Tuple of (decoded_string, encoding_name).
    """
    if charset:
        enc_clean = charset.lower().strip('"\'')
        try:
            return payload.decode(enc_clean), enc_clean
        except (UnicodeDecodeError, LookupError):
            pass

    try:
        return payload.decode("utf-8"), "utf-8"
    except UnicodeDecodeError:
        pass

    # Charset-normalizer recovery
    try:
        from charset_normalizer import from_bytes  # type: ignore # pyrefly: ignore [missing-import]
        results = from_bytes(payload)
        best = results.best()
        if best and best.encoding:
            return str(best), best.encoding
    except Exception:
        pass

    for enc in ["iso-8859-1", "windows-1252", "latin1"]:
        try:
            return payload.decode(enc), enc
        except (UnicodeDecodeError, LookupError):
            continue

    return payload.decode("utf-8", errors="replace"), "utf-8-replace"


def strip_cid_references_from_html(raw_html: str) -> tuple[str, list[str]]:
    """
    Strips inline cid: image references from HTML src attributes while collecting content-ids.

    Args:
        raw_html: Raw HTML string.

    Returns:
        Tuple of (cleaned_html, list_of_cid_references).
    """
    cid_list: set[str] = set()

    for match in CID_URL_REGEX.finditer(raw_html):
        cid_list.add(match.group(1).strip("<> "))

    cleaned_html = CID_SRC_REGEX.sub("src=\"#cid-stripped\"", raw_html)
    return cleaned_html, sorted(list(cid_list))


class BodyExtractor:
    """
    MIME Body Walker class recursively extracting top-level text/plain and text/html bodies,
    handling base64/quoted-printable decoding, charset-normalizer recovery, and cid: reference preservation.
    """

    def extract(self, msg: email.message.Message, parsing_errors: list[str]) -> BodyData:
        """
        Recursively walks MIME tree and extracts best body components into BodyData.

        Args:
            msg: email.message.Message instance.
            parsing_errors: Target error list.

        Returns:
            BodyData instance.
        """
        body_data = BodyData()
        plain_text_parts: list[str] = []
        html_parts: list[str] = []
        charsets: set[str] = set()
        cid_refs: set[str] = set()

        try:
            # 1. Prefer stdlib get_body for clean top-level part extraction when available
            plain_part = None
            html_part = None

            if hasattr(msg, "get_body"):
                try:
                    plain_part = msg.get_body(prefertype="plain")
                    html_part = msg.get_body(prefertype="html")
                except Exception:
                    plain_part, html_part = None, None

            if plain_part is not None or html_part is not None:
                parts_to_process = []
                if plain_part and str(plain_part.get("Content-Disposition", "")).lower() != "attachment":
                    parts_to_process.append(plain_part)
                if html_part and str(html_part.get("Content-Disposition", "")).lower() != "attachment" and html_part != plain_part:
                    parts_to_process.append(html_part)
            else:
                # Walk MIME parts recursively if get_body did not yield parts
                parts_to_process = [
                    p for p in msg.walk()
                    if not p.is_multipart() and "attachment" not in str(p.get("Content-Disposition", "")).lower()
                ]

            for part in parts_to_process:
                content_type = part.get_content_type().lower()
                charset = part.get_content_charset()

                payload = None
                try:
                    payload = part.get_content() if hasattr(part, "get_content") else None
                except Exception:
                    payload = None

                if not payload or not isinstance(payload, str):
                    raw_bytes = part.get_payload(decode=True)
                    if raw_bytes and isinstance(raw_bytes, bytes):
                        text_str, enc_used = decode_payload_bytes(raw_bytes, charset)
                        charsets.add(enc_used)
                        payload = text_str
                    elif isinstance(part.get_payload(), str):
                        payload = part.get_payload()

                if not payload or not isinstance(payload, str):
                    continue

                if content_type == "text/plain" and payload not in plain_text_parts:
                    plain_text_parts.append(payload)
                elif content_type == "text/html" and payload not in html_parts:
                    html_parts.append(payload)

        except Exception as e:
            err_msg = f"Error walking MIME tree for body: {e}"
            logger.warning(err_msg)
            parsing_errors.append(err_msg)

        if plain_text_parts:
            body_data.plain_text = "\n".join(plain_text_parts)

        if html_parts:
            raw_html = "\n".join(html_parts)
            body_data.html_raw = raw_html

            # Strip cid: references from HTML while preserving CIDs in cid_references list
            cleaned_html, extracted_cids = strip_cid_references_from_html(raw_html)
            cid_refs.update(extracted_cids)

            try:
                soup = BeautifulSoup(raw_html, "html.parser")
                body_data.html_stripped = soup.get_text(separator=" ", strip=True)

                # Detect hidden CSS text
                hidden_style_pattern = re.compile(
                    r"display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|font-size\s*:\s*1px|opacity\s*:\s*0",
                    re.IGNORECASE,
                )
                for tag in soup.find_all(True, style=True):
                    if hidden_style_pattern.search(tag["style"]):
                        if tag.get_text(strip=True):
                            body_data.hidden_text_detected = True
                            break

                # Collect CIDs from img src attributes
                for img in soup.find_all("img", src=True):
                    src = img["src"]
                    if src.lower().startswith("cid:"):
                        cid_refs.add(src[4:].strip("<> "))

            except Exception as e:
                err_msg = f"Error parsing HTML body with BeautifulSoup: {e}"
                logger.warning(err_msg)
                parsing_errors.append(err_msg)
                body_data.html_stripped = re.sub(r"<[^>]+>", " ", raw_html).strip()

        body_data.cid_references = sorted(list(cid_refs))
        body_data.charsets_detected = sorted(list(charsets))
        return body_data


# Functional entrypoint
def parse_body(msg: email.message.Message, parsing_errors: list[str]) -> BodyData:
    extractor = BodyExtractor()
    return extractor.extract(msg, parsing_errors)
