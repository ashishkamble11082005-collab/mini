# Email Processing & Parsing Module

A production-grade, security-adjacent email ingestion and parsing module built with Python 3.10+ and Pydantic v2. Designed to process raw, malformed, or malicious `.eml` files cleanly without ever crashing or raising unhandled exceptions.

## Features

- **Schema Validation**: Pydantic v2 data contracts (`HeaderData`, `AttachmentMetadata`, `ExtractedURL`, `ParsedEmailResult`).
- **Header Parsing**: RFC 2047 encoded-word decoding, RFC 2822 date normalization (ISO 8601), Received hop chain parsing with delay metrics, and raw_headers multimap dictionary.
- **Body Extraction**: Recursive MIME walker supporting base64/quoted-printable payloads, charset auto-detection via `charset-normalizer`, HTML text stripping, and `cid:` inline asset reference preservation.
- **Attachment Extraction**: Content-Disposition and Content-ID entity resolution, path traversal filename sanitization, magic bytes MIME cross-checking (`filetype`), streaming MD5/SHA256 checksums, configurable `max_attachment_size_mb` cap, and optional `save_to` disk extraction.
- **URL & IOC Extraction**: Text regex + HTML DOM URL discovery, defanged URL normalization (`hxxp://`, `[.]`, `(dot)`), `tldextract` domain parsing, IP-literal recognition, IDN homograph support, and occurrence counting.
- **Fault-Tolerant Orchestrator**: Multi-stage `EmailParser` with isolated `try/except` boundaries, `parse_duration_ms` tracking, error aggregation, and a rich CLI (`python parser.py sample.eml --json`).

## Quick Start

### Installation

```bash
pip install -r requirements.txt
```

### Usage

```python
from email_parser import EmailParser

parser = EmailParser()
result = parser.parse_file("sample.eml")

print(f"Subject: {result.headers.subject}")
print(f"Sender: {result.headers.sender.address}")
print(f"Duration: {result.parse_duration_ms} ms")
print(f"Errors: {result.parsing_errors}")
```

### CLI

```bash
python -m email_parser.parser sample.eml --json
```

### Running Tests

```bash
pytest -v
```
