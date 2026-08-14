"""
Attachment Extractor Module for Email Processing & Parsing.

Provides AttachmentExtractor class to detect, sanitize, hash (MD5/SHA256 streaming),
magic-bytes cross-check (filetype), size-cap filter, and optionally extract attachments to disk.
"""

import io
import re
import os
import uuid
import hashlib
import logging
import filetype  # type: ignore # pyrefly: ignore [missing-import]
import email.message
from pathlib import Path
from typing import Optional, Union, TYPE_CHECKING

from email_parser.schemas import AttachmentMetadata
from email_parser.header_parser import decode_header_value

if TYPE_CHECKING:
    from email_parser.parser import EmailParser

logger = logging.getLogger(__name__)

CHUNK_SIZE = 65536  # 64 KB streaming buffer chunk size


def sanitize_filename(raw_filename: Optional[str], default_ext: str = ".dat") -> str:
    """
    Sanitizes candidate attachment filename to prevent directory traversal and null byte attacks.

    Args:
        raw_filename: Raw extracted filename string.
        default_ext: Fallback extension.

    Returns:
        Clean, safe filename string.
    """
    if not raw_filename:
        return f"attachment_{uuid.uuid4().hex[:8]}{default_ext}"

    filename = decode_header_value(raw_filename) or ""
    filename = re.sub(r"[\x00-\x1f\x7f-\x9f]", "", filename)
    filename = os.path.basename(filename.replace("\\", "/"))
    filename = re.sub(r"^\.+", "", filename).strip()

    if not filename:
        return f"attachment_{uuid.uuid4().hex[:8]}{default_ext}"

    return filename


def check_magic_mismatch(payload: bytes, filename: str, declared_type: str) -> tuple[bool, Optional[str]]:
    """
    Cross-checks declared Content-Type against payload magic bytes using filetype library.

    Args:
        payload: Binary content bytes.
        filename: Sanitized filename.
        declared_type: Declared MIME Content-Type header.

    Returns:
        Tuple of (content_type_mismatch: bool, detected_mime: str | None).
    """
    if not payload:
        return False, None

    try:
        kind = filetype.guess(payload[:2048])
        if not kind:
            return False, None

        detected_mime = kind.mime.lower()
        declared_mime = declared_type.split(";")[0].strip().lower()

        if declared_mime == "application/octet-stream":
            return False, detected_mime

        declared_main = declared_mime.split("/")[0]
        detected_main = detected_mime.split("/")[0]

        if declared_main != detected_main:
            return True, detected_mime

        # Specific executable spoofing check (e.g. extension .pdf with application/x-executable or application/x-dosexec)
        if "executable" in detected_mime or "dosexec" in detected_mime:
            if not declared_mime.endswith("executable") and not declared_mime.endswith("dosexec"):
                return True, detected_mime

    except Exception as e:
        logger.warning(f"Magic bytes inspection error: {e}")

    return False, None


class AttachmentExtractor:
    """
    Attachment extraction engine with streaming hashing, magic bytes checking, size capping, and disk export.
    """

    def __init__(self, max_attachment_size_mb: float = 25.0, save_to: Optional[Union[str, Path]] = None):
        """
        Initializes AttachmentExtractor.

        Args:
            max_attachment_size_mb: Max allowed attachment size in MB for hashing.
            save_to: Optional directory path to extract attachments on request.
        """
        self.max_attachment_size_bytes = int(max_attachment_size_mb * 1024 * 1024)
        self.save_to = Path(save_to) if save_to else None

        if self.save_to:
            self.save_to.mkdir(parents=True, exist_ok=True)

    def compute_streaming_hashes(self, stream: io.BufferedIOBase) -> tuple[int, str, str, str]:
        """Reads stream in 64KB chunks to calculate size and hashes."""
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()
        size_bytes = 0

        while True:
            chunk = stream.read(CHUNK_SIZE)
            if not chunk:
                break
            size_bytes += len(chunk)
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)

        return size_bytes, md5.hexdigest(), sha1.hexdigest(), sha256.hexdigest()

    def process_part(
        self,
        part: email.message.Message,
        attachment_idx: int,
        parsing_errors: list[str],
        parent_parser: Optional["EmailParser"] = None,
        current_depth: int = 0,
    ) -> Optional[AttachmentMetadata]:
        """Processes a single MIME attachment part."""
        att_errors: list[str] = []

        try:
            content_disposition = str(part.get("Content-Disposition", "")).lower()
            content_type = part.get_content_type().lower()
            content_id = part.get("Content-ID")

            if content_id:
                content_id = content_id.strip("<> ")

            is_inline = "inline" in content_disposition or bool(content_id)

            raw_filename = part.get_filename()
            if not raw_filename and "name=" in content_type:
                for param in content_type.split(";"):
                    if "name=" in param.lower():
                        raw_filename = param.split("=", 1)[1].strip('"\' ')

            filename = sanitize_filename(raw_filename)
            payload = part.get_payload(decode=True)

            if payload is None:
                sub_payload = part.get_payload()
                if isinstance(sub_payload, list) and len(sub_payload) > 0:
                    item = sub_payload[0]
                    if hasattr(item, "as_bytes"):
                        payload = item.as_bytes()
                    elif isinstance(item, bytes):
                        payload = item
                    elif isinstance(item, str):
                        payload = item.encode("utf-8")
                elif hasattr(sub_payload, "as_bytes"):
                    payload = sub_payload.as_bytes()
                elif isinstance(sub_payload, bytes):
                    payload = sub_payload
                elif isinstance(sub_payload, str):
                    payload = sub_payload.encode("utf-8")

            if payload is None:
                att_errors.append("Attachment payload could not be extracted or is empty.")
                payload = b""

            if isinstance(payload, str):
                payload = payload.encode("utf-8")

            raw_len = len(payload)
            mismatch, detected_mime = check_magic_mismatch(payload, filename, content_type)
            if mismatch:
                att_errors.append(f"Content-Type mismatch: declared '{content_type}', detected '{detected_mime}'.")

            attachment_id = f"att_{attachment_idx}_{uuid.uuid4().hex[:6]}"

            # Enforce max_attachment_size_mb cap
            if raw_len > self.max_attachment_size_bytes:
                att_errors.append(
                    f"Attachment size ({raw_len} bytes) exceeds configured cap of {self.max_attachment_size_bytes} bytes. Hashing skipped."
                )
                md5_hex, sha1_hex, sha256_hex = "", "", ""
            else:
                stream = io.BytesIO(payload)
                _, md5_hex, sha1_hex, sha256_hex = self.compute_streaming_hashes(stream)

            # Optional disk extraction on request
            if self.save_to and payload:
                try:
                    target_file = self.save_to / f"{attachment_id}_{filename}"
                    with open(target_file, "wb") as f_out:
                        f_out.write(payload)
                except Exception as save_err:
                    att_errors.append(f"Failed to save attachment to disk: {save_err}")

            # Handle embedded EML recursive parsing if configured
            if content_type == "message/rfc822" and parent_parser and payload:
                if current_depth < parent_parser.max_recursion_depth:
                    try:
                        sub_result = parent_parser.parse_bytes(payload, current_depth=current_depth + 1)
                        if sub_result.parsing_errors:
                            att_errors.extend([f"[Embedded EML] {err}" for err in sub_result.parsing_errors])
                    except Exception as sub_err:
                        err_msg = f"Failed to recursively parse embedded EML attachment: {sub_err}"
                        logger.warning(err_msg)
                        att_errors.append(err_msg)
                else:
                    att_errors.append(f"Maximum recursion depth ({parent_parser.max_recursion_depth}) reached for embedded EML.")

            return AttachmentMetadata(
                attachment_id=attachment_id,
                filename=filename,
                content_type=content_type,
                content_type_mismatch=mismatch,
                content_size_bytes=raw_len,
                md5_hash=md5_hex,
                sha1_hash=sha1_hex,
                sha256_hash=sha256_hex,
                content_id=content_id,
                is_inline=is_inline,
                parsing_errors=att_errors,
            )

        except Exception as e:
            err_msg = f"Error processing attachment part #{attachment_idx}: {e}"
            logger.warning(err_msg)
            parsing_errors.append(err_msg)
            return None

    def extract(
        self,
        msg: email.message.Message,
        parsing_errors: list[str],
        parent_parser: Optional["EmailParser"] = None,
        current_depth: int = 0,
    ) -> list[AttachmentMetadata]:
        """Iterates over MIME parts and extracts all attachment metadata objects."""
        attachments: list[AttachmentMetadata] = []
        attachment_counter = 1

        try:
            for part in msg.walk():
                content_type = part.get_content_type().lower()
                if part.is_multipart() and content_type != "message/rfc822":
                    continue

                content_disposition = str(part.get("Content-Disposition", "")).lower()
                filename = part.get_filename()
                content_id = part.get("Content-ID")

                is_attachment = (
                    "attachment" in content_disposition
                    or bool(filename)
                    or (content_type not in ["text/plain", "text/html"] and "inline" in content_disposition)
                    or (content_type not in ["text/plain", "text/html"] and bool(content_id))
                    or content_type == "message/rfc822"
                )

                if is_attachment:
                    att_data = self.process_part(
                        part=part,
                        attachment_idx=attachment_counter,
                        parsing_errors=parsing_errors,
                        parent_parser=parent_parser,
                        current_depth=current_depth,
                    )
                    if att_data:
                        attachments.append(att_data)
                        attachment_counter += 1

        except Exception as e:
            err_msg = f"Error walking MIME message parts for attachments: {e}"
            logger.warning(err_msg)
            parsing_errors.append(err_msg)

        return attachments


# Functional alias
def parse_attachments(
    msg: email.message.Message,
    parsing_errors: list[str],
    parent_parser: Optional["EmailParser"] = None,
    current_depth: int = 0,
) -> list[AttachmentMetadata]:
    extractor = AttachmentExtractor()
    return extractor.extract(msg, parsing_errors, parent_parser=parent_parser, current_depth=current_depth)
