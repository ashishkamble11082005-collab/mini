"""
Header Parser Module for Email Processing & Parsing.

Provides HeaderParser class using email.parser.BytesParser(policy=email.policy.default),
RFC 2047 decoding with charset-normalizer fallback, safe date parsing, Received hop parsing,
Authentication-Results parsing, raw DKIM-Signature header extraction, and multi-value header multimap capture.
"""

import re
import logging
import email.parser
import email.policy
import email.header
import email.utils
from pathlib import Path
from datetime import datetime, timezone
from typing import Union, Optional
from dateutil import parser as dateutil_parser

from email_parser.schemas import HeaderData, EmailAddress, HopInfo, AuthResults

logger = logging.getLogger(__name__)

IPV4_PATTERN = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
IPV6_PATTERN = re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:)*:[0-9a-fA-F]{1,4}\b")
FROM_HOST_PATTERN = re.compile(r"\bfrom\s+([^\s\(\)]+)", re.IGNORECASE)
BY_HOST_PATTERN = re.compile(r"\bby\s+([^\s\(\)]+)", re.IGNORECASE)
WITH_PROTO_PATTERN = re.compile(r"\bwith\s+([^\s\(\)]+)", re.IGNORECASE)


def decode_header_value(raw_val: Optional[str]) -> Optional[str]:
    """
    Decodes an RFC 2047 encoded header value with charset-normalizer fallback.

    Args:
        raw_val: Raw header string value.

    Returns:
        Decoded unicode string or safe fallback.
    """
    if not raw_val:
        return None

    try:
        decoded_chunks = []
        for content, encoding in email.header.decode_header(raw_val):
            if isinstance(content, bytes):
                enc = encoding or "utf-8"
                try:
                    decoded_chunks.append(content.decode(enc, errors="strict"))
                except (UnicodeDecodeError, LookupError):
                    try:
                        from charset_normalizer import from_bytes
                        res = from_bytes(content).best()
                        if res:
                            decoded_chunks.append(str(res))
                        else:
                            decoded_chunks.append(content.decode("utf-8", errors="replace"))
                    except Exception:
                        decoded_chunks.append(content.decode("utf-8", errors="replace"))
            elif isinstance(content, str):
                decoded_chunks.append(content)
        return "".join(decoded_chunks).strip()
    except Exception as e:
        logger.warning(f"Error decoding header value '{raw_val}': {e}")
        return str(raw_val).strip()


class HeaderParser:
    """
    Class responsible for parsing RFC headers from raw email bytes or file objects into HeaderData.
    """

    def __init__(self):
        self.bytes_parser = email.parser.BytesParser(policy=email.policy.default)

    def parse_email_address(self, raw_str: Optional[str]) -> Optional[EmailAddress]:
        """Parses a display name and email address pair."""
        if not raw_str:
            return None
        decoded = decode_header_value(raw_str) or ""
        cleaned_str = re.sub(r"[\r\n\t]", " ", decoded).strip()
        pairs = email.utils.getaddresses([cleaned_str])
        if pairs:
            name, addr = pairs[0]
            clean_name = re.sub(r"\s+", " ", name).strip() if name else None
            clean_addr = re.sub(r"\s+", "", addr).strip() if addr else None
            return EmailAddress(
                name=clean_name if clean_name else None,
                address=clean_addr if clean_addr else None,
                raw=decoded,
            )
        return EmailAddress(raw=decoded)

    def parse_email_addresses(self, raw_headers: list[str]) -> list[EmailAddress]:
        """Parses a list of header strings into EmailAddress models."""
        addresses: list[EmailAddress] = []
        for raw in raw_headers:
            if not raw:
                continue
            decoded = decode_header_value(raw) or ""
            cleaned_str = re.sub(r"[\r\n\t]", " ", decoded).strip()
            pairs = email.utils.getaddresses([cleaned_str])
            for name, addr in pairs:
                clean_name = re.sub(r"\s+", " ", name).strip() if name else None
                clean_addr = re.sub(r"\s+", "", addr).strip() if addr else None
                addresses.append(
                    EmailAddress(
                        name=clean_name if clean_name else None,
                        address=clean_addr if clean_addr else None,
                        raw=decoded,
                    )
                )
        return addresses

    def parse_date_to_iso(self, raw_date: Optional[str], parsing_errors: list[str]) -> Optional[str]:
        """Safely normalizes raw date header to ISO 8601 string without raising."""
        if not raw_date:
            return None
        try:
            dt = email.utils.parsedate_to_datetime(raw_date)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.isoformat()
        except Exception as e1:
            try:
                dt = dateutil_parser.parse(raw_date)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt.isoformat()
            except Exception as e2:
                err_msg = f"Failed to parse date header '{raw_date}': {e1} / {e2}"
                logger.warning(err_msg)
                parsing_errors.append(err_msg)
                return None

    def parse_received_hops(self, received_headers: list[str], parsing_errors: list[str]) -> list[HopInfo]:
        """Parses Received headers into ordered HopInfo models (hop 1 is initial sender)."""
        hops_raw = list(reversed(received_headers))
        parsed_hops: list[HopInfo] = []
        hop_dt_list: list[Optional[datetime]] = []

        for idx, raw in enumerate(hops_raw, start=1):
            try:
                from_match = FROM_HOST_PATTERN.search(raw)
                by_match = BY_HOST_PATTERN.search(raw)
                with_match = WITH_PROTO_PATTERN.search(raw)

                from_host = from_match.group(1) if from_match else None
                by_host = by_match.group(1) if by_match else None
                with_proto = with_match.group(1) if with_match else None

                ip_addr = None
                v4_matches = IPV4_PATTERN.findall(raw)
                if v4_matches:
                    ip_addr = v4_matches[0]
                else:
                    v6_matches = IPV6_PATTERN.findall(raw)
                    if v6_matches:
                        ip_addr = v6_matches[0]

                hop_dt = None
                timestamp_iso = None
                if ";" in raw:
                    date_part = raw.split(";", 1)[1].strip()
                    try:
                        hop_dt = email.utils.parsedate_to_datetime(date_part)
                    except Exception:
                        try:
                            hop_dt = dateutil_parser.parse(date_part)
                        except Exception:
                            hop_dt = None

                if hop_dt:
                    if hop_dt.tzinfo is None:
                        hop_dt = hop_dt.replace(tzinfo=timezone.utc)
                    timestamp_iso = hop_dt.isoformat()

                hop_dt_list.append(hop_dt)

                parsed_hops.append(
                    HopInfo(
                        hop_number=idx,
                        from_host=from_host,
                        by_host=by_host,
                        with_protocol=with_proto,
                        timestamp_iso=timestamp_iso,
                        delay_seconds=None,
                        ip_address=ip_addr,
                    )
                )
            except Exception as e:
                err_msg = f"Error parsing Received hop header #{idx}: {e}"
                logger.warning(err_msg)
                parsing_errors.append(err_msg)

        for i in range(len(parsed_hops)):
            if i > 0 and hop_dt_list[i] is not None and hop_dt_list[i - 1] is not None:
                try:
                    diff = (hop_dt_list[i] - hop_dt_list[i - 1]).total_seconds()
                    parsed_hops[i].delay_seconds = round(diff, 2)
                except Exception:
                    pass

        return parsed_hops

    def parse_auth_results(self, msg: email.message.Message, parsing_errors: list[str]) -> AuthResults:
        """Parses Authentication-Results and Received-SPF headers."""
        auth = AuthResults()
        raw_auth = msg.get_all("Authentication-Results", [])
        raw_spf = msg.get_all("Received-SPF", [])

        combined_auth_str = " ".join([decode_header_value(str(h)) or "" for h in (raw_auth + raw_spf)])
        if not combined_auth_str.strip():
            return auth

        auth.raw_header = combined_auth_str

        try:
            spf_match = re.search(r"spf=(pass|fail|softfail|neutral|none|temperror|permerror)", combined_auth_str, re.IGNORECASE)
            if spf_match:
                auth.spf_result = spf_match.group(1).lower()

            dkim_match = re.search(r"dkim=(pass|fail|neutral|none|policy|temperror|permerror)", combined_auth_str, re.IGNORECASE)
            if dkim_match:
                auth.dkim_result = dkim_match.group(1).lower()

            dmarc_match = re.search(r"dmarc=(pass|fail|bestguesspass|none)", combined_auth_str, re.IGNORECASE)
            if dmarc_match:
                auth.dmarc_result = dmarc_match.group(1).lower()
        except Exception as e:
            err_msg = f"Error parsing Authentication-Results header: {e}"
            logger.warning(err_msg)
            parsing_errors.append(err_msg)

        return auth

    def parse(self, source: Union[bytes, str, Path], parsing_errors: list[str]) -> HeaderData:
        """
        Parses headers from raw bytes or file path into HeaderData contract.

        Args:
            source: Raw bytes or file path string/Path.
            parsing_errors: Target error list.

        Returns:
            HeaderData instance.
        """
        header_data = HeaderData()

        try:
            if isinstance(source, (str, Path)):
                with open(source, "rb") as f:
                    msg = self.bytes_parser.parse(f)
            elif isinstance(source, bytes):
                msg = self.bytes_parser.parsebytes(source)
            elif hasattr(source, "get_all"):
                msg = source
            else:
                parsing_errors.append("Invalid header source provided.")
                return header_data
        except Exception as e:
            err_msg = f"BytesParser failed to ingest header source: {e}"
            logger.warning(err_msg)
            parsing_errors.append(err_msg)
            return header_data

        # Subject
        try:
            header_data.subject = decode_header_value(msg.get("Subject"))
        except Exception as e:
            parsing_errors.append(f"Error parsing Subject header: {e}")

        # Message-ID
        try:
            header_data.message_id = decode_header_value(msg.get("Message-ID"))
        except Exception as e:
            parsing_errors.append(f"Error parsing Message-ID header: {e}")

        # Return-Path
        try:
            header_data.return_path = decode_header_value(msg.get("Return-Path"))
        except Exception as e:
            parsing_errors.append(f"Error parsing Return-Path header: {e}")

        # Date
        try:
            raw_date = msg.get("Date")
            header_data.date = self.parse_date_to_iso(raw_date, parsing_errors)
        except Exception as e:
            parsing_errors.append(f"Error parsing Date header: {e}")

        # Sender (From)
        try:
            if msg.get("From"):
                header_data.sender = self.parse_email_address(msg.get("From"))
        except Exception as e:
            parsing_errors.append(f"Error parsing From header: {e}")

        # Receiver (To, Cc, Bcc combined)
        try:
            to_addrs = self.parse_email_addresses([str(h) for h in msg.get_all("To", [])])
            cc_addrs = self.parse_email_addresses([str(h) for h in msg.get_all("Cc", [])])
            bcc_addrs = self.parse_email_addresses([str(h) for h in msg.get_all("Bcc", [])])
            header_data.receiver = to_addrs + cc_addrs + bcc_addrs
        except Exception as e:
            parsing_errors.append(f"Error parsing Receiver headers: {e}")

        # Multimap raw_headers: preserves all repeated headers as a list of strings
        try:
            raw_map: dict[str, list[str]] = {}
            for key in dict.fromkeys([k.lower() for k in msg.keys()]):
                vals = msg.get_all(key, [])
                decoded_vals = [decode_header_value(str(v)) or "" for v in vals if v is not None]
                raw_map[key] = decoded_vals
            header_data.raw_headers = raw_map
        except Exception as e:
            parsing_errors.append(f"Error constructing raw_headers multimap: {e}")

        # Dedicated raw DKIM-Signature headers collection for independent cryptographic verification
        try:
            dkim_raw_list = msg.get_all("DKIM-Signature", [])
            header_data.dkim_signatures = [
                decode_header_value(str(h)) or str(h)
                for h in dkim_raw_list
                if h is not None
            ]
        except Exception as e:
            parsing_errors.append(f"Error extracting DKIM-Signature headers: {e}")

        # Received Hops
        try:
            received_list = [str(h) for h in msg.get_all("Received", [])]
            if received_list:
                header_data.hops = self.parse_received_hops(received_list, parsing_errors)
        except Exception as e:
            parsing_errors.append(f"Error parsing Received headers: {e}")

        # Auth Results (upstream server authentication evaluation)
        try:
            header_data.auth_results = self.parse_auth_results(msg, parsing_errors)
        except Exception as e:
            parsing_errors.append(f"Error parsing Authentication-Results: {e}")

        return header_data


# Functional convenience entrypoint
def parse_headers(msg: email.message.Message, parsing_errors: list[str]) -> HeaderData:
    parser = HeaderParser()
    return parser.parse(msg, parsing_errors)
