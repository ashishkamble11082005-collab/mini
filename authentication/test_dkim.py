from authentication.dkim import parse_dkim_signature, get_dkim_public_key, remove_dkim_signature_value, verify_dkim, verify_dkim_signature
import base64
from authentication.dkim import (
    canonicalize_body,
    calculate_body_hash,
    verify_body_hash
)
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from authentication.dkim import (
    canonicalize_header,
    get_signed_headers
)
from authentication.dkim import verify_rsa_signature
from authentication.dkim import parse_rsa_public_key

def encode_der_length(length: int):
    """
    Encode an integer length using DER rules.
    """

    if length < 128:
        return bytes([length])

    raw = length.to_bytes(
        (length.bit_length() + 7) // 8,
        "big"
    )

    return bytes([0x80 | len(raw)]) + raw

def encode_der_integer(value: int):
    """
    Encode an integer as a DER INTEGER.
    """

    raw = value.to_bytes(
        (value.bit_length() + 7) // 8,
        "big"
    )

    if not raw:
        raw = b"\x00"

    # DER INTEGER is signed.
    # Add a leading zero if the highest bit is set
    # so the value remains positive.
    if raw[0] & 0x80:
        raw = b"\x00" + raw

    return (
        b"\x02"
        + encode_der_length(len(raw))
        + raw
    )

def encode_dkim_rsa_public_key(public_key):
    """
    Convert an RSA public key into the Base64
    representation used by DKIM p=.
    """

    numbers = public_key.public_numbers()

    modulus = encode_der_integer(
        numbers.n
    )

    exponent = encode_der_integer(
        numbers.e
    )

    sequence = modulus + exponent

    der = (
        b"\x30"
        + encode_der_length(len(sequence))
        + sequence
    )

    return base64.b64encode(
        der
    ).decode("ascii")

def run_controlled_dkim_test(
    signature_header,
    raw_headers,
    body,
    public_key
):
    import authentication.dkim  as dkim

    original_lookup = dkim.get_dkim_public_key

    public_key_b64 = encode_dkim_rsa_public_key(
        public_key
    )

    def controlled_lookup(domain, selector):
        return {
            "found": True,
            "domain": domain,
            "selector": selector,
            "record": f"v=DKIM1; k=rsa; p={public_key_b64}",
            "key_type": "rsa",
            "public_key": public_key_b64,
            "tags": {
                "v": "DKIM1",
                "k": "rsa",
                "p": public_key_b64
            },
            "reason": "Controlled test public key"
        }

    try:
        dkim.get_dkim_public_key = controlled_lookup

        return dkim.verify_dkim(
            signature_header=signature_header,
            raw_headers=raw_headers,
            body=body
        )

    finally:
        dkim.get_dkim_public_key = original_lookup


tests = [

    {
        "name": "Valid DKIM signature",
        "header": (
            "DKIM-Signature: "
            "v=1; "
            "a=rsa-sha256; "
            "d=example.com; "
            "s=selector1; "
            "c=relaxed/relaxed; "
            "h=from:to:subject:date; "
            "bh=BODY_HASH; "
            "b=SIGNATURE"
        )
    },

    {
        "name": "Missing selector",
        "header": (
            "DKIM-Signature: "
            "v=1; "
            "a=rsa-sha256; "
            "d=example.com; "
            "h=from:to:subject; "
            "bh=BODY_HASH; "
            "b=SIGNATURE"
        )
    },

    {
        "name": "Missing domain",
        "header": (
            "DKIM-Signature: "
            "v=1; "
            "a=rsa-sha256; "
            "s=selector1; "
            "h=from:to:subject; "
            "bh=BODY_HASH; "
            "b=SIGNATURE"
        )
    },

    {
        "name": "Empty header",
        "header": ""
    }
]


for test in tests:

    print("=" * 60)
    print(test["name"])

    result = parse_dkim_signature(
        test["header"]
    )

    print(result)


print("=" * 60)
print("DKIM PUBLIC KEY TEST")

domain = "spotify.com"
selector = "s1"
result = get_dkim_public_key(
    domain,
    selector
)

print(result)



# ============================================================
# Controlled DKIM public-key test
# ============================================================

fake_keys = {
    ("test.com", "selector1"):
        "v=DKIM1; k=rsa; p=TEST_PUBLIC_KEY"
}


def fake_key_lookup(domain, selector):

    print(
        f"DNS lookup: "
        f"{selector}._domainkey.{domain}"
    )

    return fake_keys.get((domain, selector))


print("=" * 60)
print("DKIM CONTROLLED PUBLIC KEY TEST")

result = get_dkim_public_key(
    domain="test.com",
    selector="selector1",
    key_lookup=fake_key_lookup
)

print(result)


fake_keys[("test.com", "empty")] = (
    "v=DKIM1; k=rsa; p="
)

print("=" * 60)
print("DKIM EMPTY PUBLIC KEY TEST")

result = get_dkim_public_key(
    domain="test.com",
    selector="empty",
    key_lookup=fake_key_lookup
)

print(result)

print("=" * 60)
print("DKIM MISSING PUBLIC KEY TEST")

result = get_dkim_public_key(
    domain="test.com",
    selector="missing",
    key_lookup=fake_key_lookup
)

print(result)

print("=" * 60)
print("DKIM RSA PUBLIC KEY ROUND-TRIP TEST")

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

original_public_key = private_key.public_key()

dkim_p_value = encode_dkim_rsa_public_key(
    original_public_key
)

print(
    "Generated p= value:",
    dkim_p_value[:80] + "..."
)

decoded_public_key = parse_rsa_public_key(
    dkim_p_value
)

original_numbers = (
    original_public_key.public_numbers()
)

decoded_numbers = (
    decoded_public_key.public_numbers()
)

print(
    "Modulus matches:",
    original_numbers.n == decoded_numbers.n
)

print(
    "Exponent matches:",
    original_numbers.e == decoded_numbers.e
)


print("=" * 60)
print("DKIM RSA SIGNATURE VERIFICATION TEST")

message = (
    b"ShieldMail DKIM test message"
)

signature = private_key.sign(
    message,
    padding.PKCS1v15(),
    hashes.SHA256()
)

result = verify_rsa_signature(
    original_public_key,
    message,
    signature
)

print(
    "Correct message:",
    result
)

tampered_message = (
    b"ShieldMail DKIM modified message"
)

result = verify_rsa_signature(
    original_public_key,
    tampered_message,
    signature
)

print(
    "Modified message:",
    result
)

wrong_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

wrong_public_key = (
    wrong_private_key.public_key()
)

result = verify_rsa_signature(
    wrong_public_key,
    message,
    signature
)

print(
    "Wrong public key:",
    result
)

print("=" * 60)
print("DKIM SIMPLE BODY CANONICALIZATION TEST")

body = "Hello ShieldMail!\r\n"

canonicalized = canonicalize_body(
    body,
    "simple"
)

print(
    "Canonicalized:",
    repr(canonicalized)
)

body_with_blank_lines = (
    "Hello ShieldMail!\r\n"
    "\r\n"
    "\r\n"
)

canonicalized = canonicalize_body(
    body_with_blank_lines,
    "simple"
)

print(
    "Trailing blank lines removed:",
    repr(canonicalized)
)

print("=" * 60)
print("DKIM RELAXED BODY CANONICALIZATION TEST")

body = (
    "Hello    ShieldMail!  \r\n"
    "This\tis\ta\ttest.   \r\n"
)

canonicalized = canonicalize_body(
    body,
    "relaxed"
)

print(
    "Canonicalized:",
    repr(canonicalized)
)

print("=" * 60)
print("DKIM BODY HASH TEST")

body = (
    "Hello ShieldMail!\r\n"
    "This is a phishing detection test.\r\n"
)

expected_hash = calculate_body_hash(
    body,
    "relaxed"
)

print(
    "Expected body hash:",
    expected_hash
)

result = verify_body_hash(
    body,
    expected_hash,
    "relaxed"
)

print(
    "Correct body:",
    result
)

tampered_body = (
    "Hello ShieldMail!\r\n"
    "This is a legitimate email.\r\n"
)

result = verify_body_hash(
    tampered_body,
    expected_hash,
    "relaxed"
)

print(
    "Modified body:",
    result
)

equivalent_body = (
    "Hello   ShieldMail!   \r\n"
    "This is   a phishing detection test.\t\r\n"
)

result = verify_body_hash(
    equivalent_body,
    expected_hash,
    "relaxed"
)

print(
    "Whitespace-only modification:",
    result
)

print("=" * 60)
print("DKIM HEADER CANONICALIZATION TEST")

print(
    "Simple:",
    repr(
        canonicalize_header(
            "Subject",
            "  Hello   ShieldMail  ",
            "simple"
        )
    )
)

print(
    "Relaxed:",
    repr(
        canonicalize_header(
            "Subject",
            "  Hello   ShieldMail  ",
            "relaxed"
        )
    )
)

print("=" * 60)
print("DKIM REPEATED HEADER TEST")

raw_headers = {
    "from": [
        "Alice <alice@example.com>"
    ],
    "received": [
        "from server1.example.com",
        "from server2.example.com",
        "from server3.example.com"
    ],
    "subject": [
        "ShieldMail test"
    ]
}

result = get_signed_headers(
    raw_headers,
    "received:received:from",
    "relaxed"
)

for header in result:
    print(repr(header))





print("=" * 60)
print("DKIM b= REMOVAL TEST")

signature_header = (
    "DKIM-Signature: "
    "v=1; "
    "a=rsa-sha256; "
    "d=example.com; "
    "s=selector1; "
    "h=from:to:subject; "
    "bh=BODYHASH; "
    "b=SIGNATUREDATA"
)

result = remove_dkim_signature_value(
    signature_header
)

print(result)

print("=" * 60)
print("DKIM SIGNING DATA TEST")

raw_headers = {
    "from": [
        "Alice <alice@example.com>"
    ],
    "to": [
        "Bob <bob@example.net>"
    ],
    "subject": [
        "ShieldMail Test"
    ]
}

signature_header = (
    "DKIM-Signature: "
    "v=1; "
    "a=rsa-sha256; "
    "d=example.com; "
    "s=selector1; "
    "h=from:to:subject; "
    "bh=BODYHASH; "
    "b=SIGNATUREDATA"
)
from authentication.dkim import build_dkim_signing_data
signing_data = build_dkim_signing_data(
    raw_headers=raw_headers,
    signature_header=signature_header,
    signed_header_names="from:to:subject",
    header_canonicalization="relaxed"
)

print(
    signing_data.decode("utf-8")
)


print("=" * 60)
print("DKIM ACTUAL SIGNATURE TEST")

signing_data = (
    b"from:Alice <alice@example.com>\r\n"
    b"to:Bob <bob@example.net>\r\n"
    b"subject:ShieldMail Test\r\n"
)

signature_bytes = private_key.sign(
    signing_data,
    padding.PKCS1v15(),
    hashes.SHA256()
)

signature_b64 = base64.b64encode(
    signature_bytes
).decode("ascii")

result = verify_dkim_signature(
    public_key=original_public_key,
    signing_data=signing_data,
    signature=signature_b64,
    algorithm="rsa-sha256"
)

print(
    "Correct signature:",
    result
)

tampered_data = (
    b"from:Alice <alice@example.com>\r\n"
    b"to:Bob <bob@example.net>\r\n"
    b"subject:THIS WAS CHANGED\r\n"
)

result = verify_dkim_signature(
    public_key=original_public_key,
    signing_data=tampered_data,
    signature=signature_b64,
    algorithm="rsa-sha256"
)

print(
    "Tampered signing data:",
    result
)

result = verify_dkim_signature(
    public_key=original_public_key,
    signing_data=signing_data,
    signature="THIS_IS_NOT_VALID_BASE64!!!",
    algorithm="rsa-sha256"
)

print(
    "Invalid Base64 signature:",
    result
)

result = verify_dkim_signature(
    public_key=original_public_key,
    signing_data=signing_data,
    signature=signature_b64,
    algorithm="rsa-sha1"
)

print(
    "Unsupported algorithm:",
    result
)


print("=" * 60)
print("MISSING h= TEST")

result = parse_dkim_signature(
    "v=1; a=rsa-sha256; d=example.com; s=selector1; "
    "bh=BODYHASH; b=SIGNATURE"
)

print(result)

print("=" * 60)
print("MISSING bh= TEST")

result = parse_dkim_signature(
    "v=1; a=rsa-sha256; d=example.com; s=selector1; "
    "h=from:to:subject; b=SIGNATURE"
)

print(result)

print("=" * 60)
print("MISSING b= TEST")

result = parse_dkim_signature(
    "v=1; a=rsa-sha256; d=example.com; s=selector1; "
    "h=from:to:subject; bh=BODYHASH"
)

print(result)

print("=" * 60)
print("DUPLICATE TAG TEST")

result = parse_dkim_signature(
    "v=1; a=rsa-sha256; "
    "d=example.com; d=evil.com; "
    "s=selector1; "
    "h=from:to; "
    "bh=BODYHASH; "
    "b=SIGNATURE"
)

print(result)

print("=" * 60)
print("DKIM WHITESPACE TEST")

result = parse_dkim_signature(
    "v=1; "
    "a=rsa-sha256; "
    "d=example.com; "
    "s=selector1; "
    "h=from:to; "
    "bh=BODY HASH; "
    "b=SIGNATURE DATA"
)

print(result)

print("=" * 60)
print("COMPLETE DKIM CONTROLLED VERIFICATION TEST")

raw_headers = {
    "from": [
        "Alice <alice@example.com>"
    ],
    "to": [
        "Bob <bob@example.net>"
    ],
    "subject": [
        "ShieldMail Test"
    ]
}

body = (
    "Hello ShieldMail!\r\n"
    "This is a controlled DKIM test.\r\n"
)

# Calculate the real body hash.
body_hash = calculate_body_hash(
    body,
    "relaxed"
)

print("Body hash generated:")
print(body_hash)

# Construct DKIM-Signature without the b= value.
signature_header_without_b = (
    "DKIM-Signature: "
    "v=1; "
    "a=rsa-sha256; "
    "d=example.com; "
    "s=selector1; "
    "c=relaxed/relaxed; "
    "h=from:to:subject; "
    f"bh={body_hash}; "
    "b="
)

# Build the exact data that DKIM signs.
signing_data = build_dkim_signing_data(
    raw_headers=raw_headers,
    signature_header=signature_header_without_b,
    signed_header_names="from:to:subject",
    header_canonicalization="relaxed"
)

print("Signing data generated:")
print(signing_data.decode("utf-8"))

# Sign using the RSA private key generated earlier
# in test_dkim.py.
signature_bytes = private_key.sign(
    signing_data,
    padding.PKCS1v15(),
    hashes.SHA256()
)

signature_b64 = base64.b64encode(
    signature_bytes
).decode("ascii")

print("RSA signature generated.")
print("Signature length:", len(signature_b64))

# Build the final DKIM-Signature header.
signature_header = (
    "DKIM-Signature: "
    "v=1; "
    "a=rsa-sha256; "
    "d=example.com; "
    "s=selector1; "
    "c=relaxed/relaxed; "
    "h=from:to:subject; "
    f"bh={body_hash}; "
    f"b={signature_b64}"
)

print("Complete DKIM-Signature generated.")
print("Running verify_dkim...")

result = run_controlled_dkim_test(
    signature_header=signature_header,
    raw_headers=raw_headers,
    body=body,
    public_key=original_public_key
)

print("Controlled verification result:")
print(result)
