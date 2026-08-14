"""
Data Contracts and Pydantic v2 Schemas for Email Parsing Pipeline.

Defines HeaderData, AttachmentMetadata, ExtractedURL, BodyData, and ParsedEmailResult.
All fields feature safe defaults and comprehensive docstrings.
"""

from typing import Optional
from datetime import datetime, timezone
from pydantic import BaseModel, Field, ConfigDict  # type: ignore # pyrefly: ignore [missing-import]


class EmailAddress(BaseModel):
    """Represents a parsed email address with optional display name."""
    model_config = ConfigDict(extra="ignore")

    name: Optional[str] = None
    address: Optional[str] = None
    raw: str = ""


class HopInfo(BaseModel):
    """Represents a single routing hop parsed from Received headers."""
    model_config = ConfigDict(extra="ignore")

    hop_number: int
    from_host: Optional[str] = None
    by_host: Optional[str] = None
    with_protocol: Optional[str] = None
    timestamp_iso: Optional[str] = None
    delay_seconds: Optional[float] = None
    ip_address: Optional[str] = None


class AuthResults(BaseModel):
    """Represents authentication verification status parsed from Authentication-Results header."""
    model_config = ConfigDict(extra="ignore")

    spf_result: Optional[str] = None
    dkim_result: Optional[str] = None
    dmarc_result: Optional[str] = None
    raw_header: Optional[str] = None


class HeaderData(BaseModel):
    """
    Aggregated parsed email headers contract.
    
    Attributes:
        sender: Parsed sender email address object (from From header).
        receiver: List of recipient email addresses parsed from To, Cc, and Bcc headers.
        subject: Email subject string.
        date: ISO 8601 normalized datetime string (nullable).
        message_id: Unique Message-ID header string.
        return_path: Return-Path header string.
        raw_headers: Multimap dictionary mapping lowercased header names to list of raw header values.
        dkim_signatures: Dedicated list of raw DKIM-Signature header strings for independent cryptographic verification.
        hops: Parsed routing hop chain.
        auth_results: SPF, DKIM, and DMARC verification results from Authentication-Results.
    """
    model_config = ConfigDict(extra="ignore")

    sender: Optional[EmailAddress] = None
    receiver: list[EmailAddress] = Field(default_factory=list)
    subject: Optional[str] = None
    date: Optional[str] = None
    message_id: Optional[str] = None
    return_path: Optional[str] = None
    raw_headers: dict[str, list[str]] = Field(default_factory=dict)
    dkim_signatures: list[str] = Field(default_factory=list)
    hops: list[HopInfo] = Field(default_factory=list)
    auth_results: AuthResults = Field(default_factory=AuthResults)


class AttachmentMetadata(BaseModel):
    """
    Metadata and cryptographic hashes for extracted email attachments.
    """
    model_config = ConfigDict(extra="ignore")

    attachment_id: str = ""
    filename: str = ""
    content_type: str = "application/octet-stream"
    content_type_mismatch: bool = False
    content_size_bytes: int = 0
    md5_hash: str = ""
    sha1_hash: str = ""
    sha256_hash: str = ""
    content_id: Optional[str] = None
    is_inline: bool = False
    parsing_errors: list[str] = Field(default_factory=list)


class ExtractedURL(BaseModel):
    """
    Metadata for extracted URLs and Indicators of Compromise (IOCs).
    """
    model_config = ConfigDict(extra="ignore")

    url: str
    domain: Optional[str] = None
    scheme: Optional[str] = None
    is_ip_address: bool = False
    was_defanged: bool = False
    occurrence_count: int = 1
    anchor_text: Optional[str] = None
    is_obfuscated: bool = False
    source: str = "plain_text"


class BodyData(BaseModel):
    """Intermediate body extractor data structure."""
    model_config = ConfigDict(extra="ignore")

    plain_text: Optional[str] = None
    html_raw: Optional[str] = None
    html_stripped: Optional[str] = None
    cid_references: list[str] = Field(default_factory=list)
    urls: list[ExtractedURL] = Field(default_factory=list)
    hidden_text_detected: bool = False
    charsets_detected: list[str] = Field(default_factory=list)


class ParsedEmailResult(BaseModel):
    """
    Top-level output schema for email parsing pipeline execution.
    """
    model_config = ConfigDict(extra="ignore")

    headers: HeaderData = Field(default_factory=HeaderData)
    body_text: Optional[str] = None
    body_html: Optional[str] = None
    urls: list[ExtractedURL] = Field(default_factory=list)
    attachments: list[AttachmentMetadata] = Field(default_factory=list)
    parsing_errors: list[str] = Field(default_factory=list)
    parse_duration_ms: float = 0.0
    raw_size_bytes: int = 0
    parsed_at_iso: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


# Backward-compatibility alias mappings
EmailAnalysisResult = ParsedEmailResult
AttachmentData = AttachmentMetadata
URLEntry = ExtractedURL
