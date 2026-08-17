"""
Core Orchestrator Module for Email Processing & Parsing.

Provides EmailParser class executing HeaderParser -> BodyExtractor -> AttachmentExtractor -> URLExtractor
with isolated try/except stage boundaries, error aggregation, parse_duration_ms tracking,
and CLI entry point (`python -m email_parser.parser sample.eml --json`).
"""

import sys
import time
import json
import logging
import argparse
from pathlib import Path
from typing import BinaryIO, Union
from datetime import datetime, timezone
from email_parser.authentication_extractor import AuthenticationExtractor
from email_parser.schemas import ParsedEmailResult, HeaderData, BodyData
from email_parser.header_parser import HeaderParser
from email_parser.body_extractor import BodyExtractor
from email_parser.attachment_extractor import AttachmentExtractor
from email_parser.url_extractor import URLExtractor

logger = logging.getLogger(__name__)


class EmailParser:
    """
    Production-grade Email Parser orchestrator. Runs header, body, attachment, and URL extraction
    stages in sequence with isolated exception boundaries.
    """

    def __init__(
        self,
        max_recursion_depth: int = 3,
        max_attachment_size_mb: float = 25.0,
        save_attachments_to: Union[str, Path, None] = None,
    ):
        """
        Initializes EmailParser orchestrator.

        Args:
            max_recursion_depth: Max depth for recursive embedded EML parsing.
            max_attachment_size_mb: Attachment hashing size cap in MB.
            save_attachments_to: Optional filesystem directory path to save attachments.
        """
        self.max_recursion_depth = max_recursion_depth
        self.header_parser = HeaderParser()
        self.authentication_extractor = AuthenticationExtractor()
        self.body_extractor = BodyExtractor()
        self.attachment_extractor = AttachmentExtractor(
            max_attachment_size_mb=max_attachment_size_mb, save_to=save_attachments_to
        )
        self.url_extractor = URLExtractor()

    def parse_bytes(self, raw_bytes: bytes, current_depth: int = 0) -> ParsedEmailResult:
        """
        Parses raw .eml bytes into ParsedEmailResult.

        Args:
            raw_bytes: Raw email byte payload.
            current_depth: Embedded email recursion level.

        Returns:
            ParsedEmailResult contract instance.
        """
        start_time = time.perf_counter()
        parsing_errors: list[str] = []
        raw_size = len(raw_bytes) if raw_bytes else 0

        if not raw_bytes:
            parsing_errors.append("Input email byte array is empty or zero-length.")
            duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
            return ParsedEmailResult(
                headers=HeaderData(),
                body_text=None,
                body_html=None,
                urls=[],
                attachments=[],
                parsing_errors=parsing_errors,
                parse_duration_ms=duration_ms,
                raw_size_bytes=raw_size,
                parsed_at_iso=datetime.now(timezone.utc).isoformat(),
            )

        msg = None
        authentication_context = None

        try:
         msg = self.header_parser.bytes_parser.parsebytes(raw_bytes)
        except Exception as e:
         err_msg = f"BytesParser failed to ingest bytes: {e}"
         logger.warning(err_msg)
         parsing_errors.append(err_msg)


        try:
         authentication_context = (
         self.authentication_extractor.extract_from_bytes(
            raw_bytes
        )
    )
        except Exception as e:
         err_msg = f"Authentication extraction stage failed: {e}"
         logger.error(err_msg, exc_info=True)
         parsing_errors.append(err_msg)

        # STAGE 1: Header Parsing
        header_data = HeaderData()
        if msg is not None:
            try:
                header_data = self.header_parser.parse(msg, parsing_errors)
            except Exception as e:
                err_msg = f"Unhandled exception during header parsing stage: {e}"
                logger.error(err_msg, exc_info=True)
                parsing_errors.append(err_msg)

        # STAGE 2: Body Extraction
        body_data = BodyData()
        if msg is not None:
            try:
                body_data = self.body_extractor.extract(msg, parsing_errors)
            except Exception as e:
                err_msg = f"Unhandled exception during body extraction stage: {e}"
                logger.error(err_msg, exc_info=True)
                parsing_errors.append(err_msg)

        # STAGE 3: Attachment Hashing & Extraction
        attachments_data = []
        if msg is not None:
            try:
                attachments_data = self.attachment_extractor.extract(
                    msg=msg,
                    parsing_errors=parsing_errors,
                    parent_parser=self,
                    current_depth=current_depth,
                )
            except Exception as e:
                err_msg = f"Unhandled exception during attachment extraction stage: {e}"
                logger.error(err_msg, exc_info=True)
                parsing_errors.append(err_msg)

        # STAGE 4: URL & IOC Extraction
        urls_data = []
        try:
            urls_data = self.url_extractor.extract_from_body(body_data, parsing_errors)
        except Exception as e:
            err_msg = f"Unhandled exception during URL extraction stage: {e}"
            logger.error(err_msg, exc_info=True)
            parsing_errors.append(err_msg)

        duration_ms = round((time.perf_counter() - start_time) * 1000, 2)

        return ParsedEmailResult(
            headers=header_data,
            body_text=body_data.plain_text,
            body_html=body_data.html_raw,
            urls=urls_data,
            attachments=attachments_data,
            parsing_errors=parsing_errors,
            parse_duration_ms=duration_ms,
            raw_size_bytes=raw_size,
            parsed_at_iso=datetime.now(timezone.utc).isoformat(),
        )

    def parse_file(self, file_path: Union[str, Path]) -> ParsedEmailResult:
        """
        Parses an .eml file from filesystem path.

        Args:
            file_path: Path to .eml file.

        Returns:
            ParsedEmailResult instance.
        """
        start_time = time.perf_counter()
        parsing_errors: list[str] = []
        path_obj = Path(file_path)

        if not path_obj.exists():
            err_msg = f"File not found at path: {file_path}"
            logger.warning(err_msg)
            parsing_errors.append(err_msg)
            duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
            return ParsedEmailResult(
                headers=HeaderData(),
                body_text=None,
                body_html=None,
                urls=[],
                attachments=[],
                parsing_errors=parsing_errors,
                parse_duration_ms=duration_ms,
                raw_size_bytes=0,
                parsed_at_iso=datetime.now(timezone.utc).isoformat(),
            )

        try:
            with open(path_obj, "rb") as f:
                content = f.read()
            res = self.parse_bytes(content)
            res.parsing_errors.extend(parsing_errors)
            return res
        except Exception as e:
            err_msg = f"Failed to read file '{file_path}': {e}"
            logger.error(err_msg)
            parsing_errors.append(err_msg)
            duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
            return ParsedEmailResult(
                headers=HeaderData(),
                body_text=None,
                body_html=None,
                urls=[],
                attachments=[],
                parsing_errors=parsing_errors,
                parse_duration_ms=duration_ms,
                raw_size_bytes=0,
                parsed_at_iso=datetime.now(timezone.utc).isoformat(),
            )

    def parse_stream(self, stream: BinaryIO) -> ParsedEmailResult:
        """Parses an open binary stream."""
        start_time = time.perf_counter()
        parsing_errors: list[str] = []
        try:
            content = stream.read()
            return self.parse_bytes(content)
        except Exception as e:
            err_msg = f"Failed to read from binary stream: {e}"
            logger.error(err_msg)
            parsing_errors.append(err_msg)
            duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
            return ParsedEmailResult(
                headers=HeaderData(),
                body_text=None,
                body_html=None,
                urls=[],
                attachments=[],
                parsing_errors=parsing_errors,
                parse_duration_ms=duration_ms,
                raw_size_bytes=0,
                parsed_at_iso=datetime.now(timezone.utc).isoformat(),
            )


def main():
    """CLI entrypoint: python -m email_parser.parser sample.eml --json"""
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except Exception:
            pass

    arg_parser = argparse.ArgumentParser(description="Ingest and parse .eml files into ParsedEmailResult JSON.")
    arg_parser.add_argument("file", help="Path to .eml file to parse")
    arg_parser.add_argument("--json", action="store_true", help="Output pretty-printed JSON")
    args = arg_parser.parse_args()

    parser = EmailParser()
    result = parser.parse_file(args.file)

    if args.json:
        print(result.model_dump_json(indent=2))
    else:
        print(f"Parsed {args.file} in {result.parse_duration_ms} ms with {len(result.parsing_errors)} errors.")


if __name__ == "__main__":
    main()
