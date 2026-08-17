from email import policy
from email.parser import BytesParser

from authentication_extractor import (
    AuthenticationExtractor
)


email_data = (
    b"From: Alice <alice@example.com>\r\n"
    b"To: Bob <bob@example.net>\r\n"
    b"Return-Path: <alice@example.com>\r\n"
    b"DKIM-Signature: v=1; a=rsa-sha256; d=example.com; "
    b"s=selector1; h=from:to; bh=TEST; b=SIGNATURE\r\n"
    b"Authentication-Results: mx.example.com; "
    b"spf=pass; dkim=pass\r\n"
    b"Received: from mail.example.com (192.0.2.10)\r\n"
    b"    by mx.example.net;\r\n"
    b"    Mon, 17 Aug 2026 10:00:00 +0000\r\n"
    b"Subject: ShieldMail Test\r\n"
    b"\r\n"
    b"Hello ShieldMail!\r\n"
)


# =============================================================
# Normal parser representation
# =============================================================

normal_msg = BytesParser(
    policy=policy.default
).parsebytes(email_data)


# =============================================================
# Authentication representation
# =============================================================

extractor = AuthenticationExtractor()

auth_result = extractor.extract_from_bytes(
    raw_bytes=email_data,
    sender_ip="192.0.2.10",
    helo="mail.example.com",
    envelope_from="<alice@example.com>",
    envelope_to=["bob@example.net"],
)


print("=" * 60)
print("APPROACH B AUTHENTICATION EXTRACTOR TEST")
print("=" * 60)

print("From:")
print(auth_result.from_address)

print("From domain:")
print(auth_result.from_domain)

print("Return-Path:")
print(auth_result.return_path)

print("DKIM signatures:")

for signature in auth_result.dkim_signatures:
    print(signature)

print("Authentication-Results:")

for auth in auth_result.authentication_results:
    print(auth)

print("Received headers:")

for received in auth_result.received_headers:
    print(received)

print("=" * 60)
print("RAW HEADERS")

for header in auth_result.raw_headers:
    print(repr(header))

print("=" * 60)
print("RAW HEADERS MAP")

for header_name, values in auth_result.raw_headers_map.items():
    print(f"{header_name!r}: {values!r}")

print("=" * 60)
print("RAW BODY")
print(repr(auth_result.raw_body))

print("=" * 60)
print("TRANSPORT DATA")

print("Sender IP:", auth_result.sender_ip)
print("HELO:", auth_result.helo)
print("Envelope From:", auth_result.envelope_from)
print(
    "Envelope From Domain:",
    auth_result.envelope_from_domain
)
print("Envelope To:", auth_result.envelope_to)

print("=" * 60)

# =============================================================
# Verify both representations were created independently
# =============================================================

print("NORMAL PARSER CREATED:", normal_msg is not None)
print("AUTHENTICATION DATA CREATED:", auth_result is not None)

print("=" * 60)
print("FULL AUTHENTICATION CONTEXT")
print(auth_result.model_dump())


print("=" * 60)
print("INDEPENDENCE TEST")

# Modify ONLY the normal parser's Message object.
normal_msg.replace_header(
    "Subject",
    "MODIFIED BY NORMAL PARSER"
)

print("Normal parser Subject:")
print(normal_msg.get("Subject"))

print()
print("Authentication raw Subject:")

for header in auth_result.raw_headers:
    if header.lower().startswith("subject:"):
        print(header)

print()
print("Authentication raw body:")
print(repr(auth_result.raw_body))