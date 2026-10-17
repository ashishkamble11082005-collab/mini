"""
Models package adapter re-exporting Pydantic v2 schemas from schemas.py.
"""

from email_parser.schemas import (
    EmailAddress,
    HopInfo,
    AuthResults,
    HeaderData,
    AttachmentMetadata,
    ExtractedURL,
    ParsedEmailResult,
    # Aliases
    EmailAnalysisResult,
    AttachmentData,
    URLEntry,
)

__all__ = [
    "EmailAddress",
    "HopInfo",
    "AuthResults",
    "HeaderData",
    "AttachmentMetadata",
    "ExtractedURL",
    "ParsedEmailResult",
    "EmailAnalysisResult",
    "AttachmentData",
    "URLEntry",
]
