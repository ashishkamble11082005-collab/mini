"""
Authentication Data Extractor for ShieldMail.

This module creates an independent parsed representation of the
original email bytes for authentication analysis.

It does NOT perform SPF, DKIM, or DMARC verification.

The original raw message bytes are treated as the source of truth.
The authentication path parses those bytes independently from the
normal email-analysis parser.
"""

from typing import Optional
import email.message
from email import policy
from email.parser import BytesParser

from pydantic import BaseModel, Field, ConfigDict


class AuthenticationContext(BaseModel):
    """
    Authentication-related evidence used by SPF, DKIM, and DMARC.

    Message-derived information comes from the original email.

    SMTP transport information is optional and can be supplied by
    the live gateway.
    """

    model_config = ConfigDict(extra="ignore")

    # =========================================================
    # Message identity
    # =========================================================

    from_address: Optional[str] = None
    from_domain: Optional[str] = None
    return_path: Optional[str] = None

    # =========================================================
    # DKIM
    # =========================================================

    dkim_signatures: list[str] = Field(
        default_factory=list
    )

    raw_headers: list[str] = Field(
        default_factory=list
    )

    raw_headers_map: dict[str, list[str]] = Field(
    default_factory=dict
)

    raw_body: bytes = b""

    # =========================================================
    # Existing authentication evidence
    # =========================================================

    authentication_results: list[str] = Field(
        default_factory=list
    )

    received_headers: list[str] = Field(
        default_factory=list
    )

    # =========================================================
    # SMTP transport information
    # =========================================================

    sender_ip: Optional[str] = None
    helo: Optional[str] = None
    envelope_from: Optional[str] = None
    envelope_from_domain: Optional[str] = None
    envelope_to: list[str] = Field(
        default_factory=list
    )


class AuthenticationExtractor:
    """
    Extracts authentication-related information from an email.

    The extractor creates its own email.message.Message from the
    supplied raw bytes. This prevents authentication processing from
    depending on the normal email-analysis Message object.
    """

    def __init__(self):
        self.bytes_parser = BytesParser(
            policy=policy.default
        )
    @staticmethod
    def _extract_domain(
        address: Optional[str]
    ) -> Optional[str]:
        """
        Extract a domain from an email-address-like value.

        Supports:
            alice@example.com
            <alice@example.com>
            Alice <alice@example.com>

        Returns:
            Lowercase domain or None.
        """

        if not address:
            return None

        try:
            value = str(address).strip()

            if value.startswith("<") and value.endswith(">"):
                value = value[1:-1].strip()

            elif "<" in value and ">" in value:
                value = value.split("<", 1)[1]
                value = value.split(">", 1)[0].strip()

            if "@" not in value:
                return None

            domain = value.rsplit("@", 1)[1].strip().lower()

            return domain or None

        except Exception:
            return None
    def extract_from_bytes(
        self,
        raw_bytes: bytes,
        sender_ip: Optional[str] = None,
        helo: Optional[str] = None,
        envelope_from: Optional[str] = None,
        envelope_to: Optional[list[str]] = None,
    ) -> AuthenticationContext:
        """
        Parse raw email bytes independently and extract
        authentication-relevant information.

        Args:
            raw_bytes:
                Original email bytes.

            sender_ip:
                SMTP connecting sender IP when available.

            helo:
                SMTP HELO/EHLO identity when available.

            envelope_from:
                SMTP MAIL FROM value when available.

            envelope_to:
                SMTP RCPT TO values when available.

        Returns:
            AuthenticationContext containing extracted evidence.
        """

        context = AuthenticationContext(
            sender_ip=sender_ip,
            helo=helo,
            envelope_from=envelope_from,
            envelope_from_domain=self._extract_domain(
                envelope_from
            ),
            envelope_to=envelope_to or [],
        )

        if not raw_bytes:
            return context

        try:
            msg = self.bytes_parser.parsebytes(
                raw_bytes
            )
        except Exception:
            return context

        return self.extract(
            msg,
            raw_message=raw_bytes,
            context=context,
        )

    def extract(
        self,
        msg: email.message.Message,
        raw_message: Optional[bytes] = None,
        context: Optional[AuthenticationContext] = None,
    ) -> AuthenticationContext:
        """
        Extract authentication data from an already parsed
        Message object.

        This method is primarily an internal/helper interface.
        extract_from_bytes() should normally be used by callers.
        """

        if context is None:
            context = AuthenticationContext()

        # =====================================================
        # From
        # =====================================================

        try:
            from_header = msg.get("From")

            if from_header:
                context.from_address = str(
                    from_header
                )

                address = str(from_header)

                if "<" in address and ">" in address:
                    address = address.split(
                        "<",
                        1
                    )[1].split(
                        ">",
                        1
                    )[0]

                if "@" in address:
                    context.from_domain = (
                        address.rsplit("@", 1)[1]
                        .strip()
                        .lower()
                    )

        except Exception:
            pass

        # =====================================================
        # Return-Path
        # =====================================================

        try:
            return_path = msg.get("Return-Path")

            if return_path:
                context.return_path = str(
                    return_path
                )

        except Exception:
            pass

        # =====================================================
        # DKIM-Signature
        # =====================================================

        try:
            dkim_headers = msg.get_all(
                "DKIM-Signature",
                []
            )

            context.dkim_signatures = [
                str(value)
                for value in dkim_headers
            ]

        except Exception:
            context.dkim_signatures = []

        # =====================================================
        # Authentication-Results
        # =====================================================

        try:
            auth_headers = msg.get_all(
                "Authentication-Results",
                []
            )

            context.authentication_results = [
                str(value)
                for value in auth_headers
            ]

        except Exception:
            context.authentication_results = []

        # =====================================================
        # Received headers
        # =====================================================

        try:
            received_headers = msg.get_all(
                "Received",
                []
            )

            context.received_headers = [
                str(value)
                for value in received_headers
            ]

        except Exception:
            context.received_headers = []

        # =====================================================
        # Preserve ordered raw headers
        # =====================================================

        try:
            context.raw_headers = [
                f"{key}: {value}"
                for key, value in msg.raw_items()
            ]

        except Exception:
            context.raw_headers = []

        try:
            context.raw_headers_map = (
        self._build_raw_headers_map(msg)
    )
        except Exception:
            context.raw_headers_map = {}   

        # =====================================================
        # Preserve original body bytes
        # =====================================================

        if raw_message is not None:
            try:
                separator = b"\r\n\r\n"

                position = raw_message.find(
                    separator
                )

                if position != -1:
                    context.raw_body = raw_message[
                        position + len(separator):
                    ]

                else:
                    separator = b"\n\n"

                    position = raw_message.find(
                        separator
                    )

                    if position != -1:
                        context.raw_body = raw_message[
                            position + len(separator):
                        ]

            except Exception:
                context.raw_body = b""

        return context
    @staticmethod
    def _build_raw_headers_map(
    msg: email.message.Message
) -> dict[str, list[str]]:
        headers_map: dict[str, list[str]] = {}

        for key, value in msg.raw_items():
            normalized_key = key.strip().lower()

            if not normalized_key:
             continue

            headers_map.setdefault(
            normalized_key,
            []
        ).append(str(value))

        return headers_map

def extract_authentication_context(
    raw_bytes: bytes,
    sender_ip: Optional[str] = None,
    helo: Optional[str] = None,
    envelope_from: Optional[str] = None,
    envelope_to: Optional[list[str]] = None,
) -> AuthenticationContext:
    """
    Functional entry point for authentication extraction.
    """

    extractor = AuthenticationExtractor()

    return extractor.extract_from_bytes(
        raw_bytes=raw_bytes,
        sender_ip=sender_ip,
        helo=helo,
        envelope_from=envelope_from,
        envelope_to=envelope_to,
    )