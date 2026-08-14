"""
Email Processing & Parsing Module.

Security-adjacent email parsing library designed to ingest standard, malformed, or malicious .eml files
without ever raising unhandled exceptions.
"""

from email_parser.parser import EmailParser
from email_parser.schemas import (
    HeaderData,
    AttachmentMetadata,
    ExtractedURL,
    ParsedEmailResult,
    EmailAddress,
    HopInfo,
    AuthResults,
    # Backward compatibility aliases
    EmailAnalysisResult,
    AttachmentData,
    URLEntry,
)

__all__ = [
    "EmailParser",
    "HeaderData",
    "AttachmentMetadata",
    "ExtractedURL",
    "ParsedEmailResult",
    "EmailAddress",
    "HopInfo",
    "AuthResults",
    "EmailAnalysisResult",
    "AttachmentData",
    "URLEntry",
]
