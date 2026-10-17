"""
Attachment parser adapter re-exporting AttachmentExtractor from attachment_extractor.py.
"""

import mimetypes
from email_parser.attachment_extractor import (
    AttachmentExtractor,
    parse_attachments,
    sanitize_filename,
    check_magic_mismatch,
)

def check_content_type_mismatch(filename: str, declared_content_type: str) -> bool:
    if not filename or "." not in filename:
        return False
    guessed_type, _ = mimetypes.guess_type(filename)
    if not guessed_type:
        return False
    guessed_main = guessed_type.split("/")[0].lower()
    declared_main = declared_content_type.split("/")[0].lower()
    return guessed_main != declared_main and declared_content_type.lower() != "application/octet-stream"

def compute_streaming_hashes(stream):
    ae = AttachmentExtractor()
    return ae.compute_streaming_hashes(stream)

__all__ = [
    "AttachmentExtractor",
    "parse_attachments",
    "sanitize_filename",
    "check_magic_mismatch",
    "check_content_type_mismatch",
    "compute_streaming_hashes",
]
