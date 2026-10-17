from .dns_utils import resolve_dkim_key
import base64
import hashlib
import re
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def parse_dkim_signature(signature_header: str):
    """
    Parse a DKIM-Signature header.

    Returns:
        dict: Parsed DKIM parameters.
    """

    if not signature_header:
        return {
            "valid": False,
            "reason": "DKIM-Signature header is missing"
        }

    # Remove the header name if it was supplied.
    if ":" in signature_header:
        header_name, header_value = signature_header.split(
            ":",
            1
        )

        if header_name.strip().lower() == "dkim-signature":
            signature_header = header_value.strip()

    tags = {}

    # DKIM tags are separated by semicolons.
    for part in signature_header.split(";"):

        part = part.strip()

        if not part:
            continue

        if "=" not in part:
            return {
                "valid": False,
                "reason": f"Malformed DKIM tag: {part}"
            }

        key, value = part.split("=", 1)

        key = key.strip()
        value = value.strip()

        if not key:
            return {
                "valid": False,
                "reason": "DKIM tag name is empty"
            }

        # Duplicate DKIM tags are not accepted.
        if key in tags:
            return {
                "valid": False,
                "reason": f"Duplicate DKIM tag: {key}",
                "tags": tags
            }

        tags[key] = value

    # Required DKIM tags needed for actual verification.
    required_tags = [
        "v",
        "a",
        "d",
        "s",
        "h",
        "bh",
        "b"
    ]

    missing_tags = [
        tag for tag in required_tags
        if tag not in tags
    ]

    if missing_tags:
        return {
            "valid": False,
            "reason": (
                "Missing required DKIM tag(s): "
                + ", ".join(missing_tags)
            ),
            "tags": tags
        }

    # DKIM version must currently be 1.
    if tags["v"] != "1":
        return {
            "valid": False,
            "reason": f"Unsupported DKIM version: {tags['v']}",
            "tags": tags
        }

    # We currently implement RSA-SHA256.
    algorithm = tags["a"].lower()

    if algorithm != "rsa-sha256":
        return {
            "valid": False,
            "reason": f"Unsupported DKIM algorithm: {tags['a']}",
            "tags": tags
        }

    # Canonicalization defaults to simple/simple.
    canonicalization = tags.get(
        "c",
        "simple/simple"
    )

    # Validate the canonicalization format.
    canonical_parts = canonicalization.split("/")

    if len(canonical_parts) == 1:
        header_canonicalization = canonical_parts[0]
        body_canonicalization = "simple"
    elif len(canonical_parts) == 2:
        header_canonicalization = canonical_parts[0]
        body_canonicalization = canonical_parts[1]
    else:
        return {
            "valid": False,
            "reason": (
                "Invalid DKIM canonicalization: "
                + canonicalization
            ),
            "tags": tags
        }

    supported_modes = {
        "simple",
        "relaxed"
    }

    if (
        header_canonicalization not in supported_modes
        or body_canonicalization not in supported_modes
    ):
        return {
            "valid": False,
            "reason": (
                "Unsupported DKIM canonicalization: "
                + canonicalization
            ),
            "tags": tags
        }

    # b= and bh= values may contain folding whitespace.
    # Keep all other values untouched.
    body_hash = "".join(
        tags["bh"].split()
    )

    signature = "".join(
        tags["b"].split()
    )

    if not body_hash:
        return {
            "valid": False,
            "reason": "DKIM body hash (bh=) is empty",
            "tags": tags
        }

    if not signature:
        return {
            "valid": False,
            "reason": "DKIM signature (b=) is empty",
            "tags": tags
        }

    return {
        "valid": True,
        "version": tags["v"],
        "algorithm": tags["a"],
        "domain": tags["d"],
        "selector": tags["s"],
        "canonicalization": canonicalization,
        "header_canonicalization": header_canonicalization,
        "body_canonicalization": body_canonicalization,
        "signed_headers": tags["h"],
        "body_hash": body_hash,
        "signature": signature,
        "tags": tags
    }

def get_dkim_public_key(
    domain: str,
    selector: str,
    key_lookup=None
):
    """
    Retrieve and validate a DKIM public-key record.
    """

    if key_lookup is None:
        key_lookup = resolve_dkim_key

    try:
        record = key_lookup(domain, selector)

    except Exception as exc:
        return {
            "found": False,
            "domain": domain,
            "selector": selector,
            "record": None,
            "public_key": None,
            "reason": (
                f"DNS error while retrieving DKIM key: {exc}"
            )
        }

    # ... keep the rest of your existing validation

    if record is None:
        return {
            "found": False,
            "domain": domain,
            "selector": selector,
            "record": None,
            "public_key": None,
            "reason": "DKIM public key not found"
        }

    tags = {}

    for part in record.split(";"):

        part = part.strip()

        if not part or "=" not in part:
            continue

        key, value = part.split("=", 1)

        tags[key.strip()] = value.strip()

    public_key = tags.get("p", "")
    key_type = tags.get("k", "rsa").lower()

    if not public_key:
        return {
            "found": False,
            "domain": domain,
            "selector": selector,
            "record": record,
            "key_type": key_type,
            "public_key": None,
            "tags": tags,
            "reason": "DKIM record exists but contains no public key"
        }

    if key_type not in {"rsa", "ed25519"}:
        return {
            "found": False,
            "domain": domain,
            "selector": selector,
            "record": record,
            "key_type": key_type,
            "public_key": public_key,
            "tags": tags,
            "reason": f"Unsupported DKIM key type: {key_type}"
        }

    return {
        "found": True,
        "domain": domain,
        "selector": selector,
        "record": record,
        "key_type": key_type,
        "public_key": public_key,
        "tags": tags,
        "reason": "DKIM public key retrieved successfully"
    }

def read_der_length(data: bytes, offset: int):
    """
    Read a DER length field.

    Returns:
        tuple[int, int]:
            Parsed length and the next offset.
    """

    if offset >= len(data):
        raise ValueError("Unexpected end of DER data")

    first_byte = data[offset]
    offset += 1

    # Short-form length
    if first_byte < 128:
        return first_byte, offset

    # Long-form length
    number_of_bytes = first_byte & 0x7F

    if number_of_bytes == 0:
        raise ValueError("Indefinite DER length is not allowed")

    if offset + number_of_bytes > len(data):
        raise ValueError("Incomplete DER length")

    length = int.from_bytes(
        data[offset:offset + number_of_bytes],
        "big"
    )

    offset += number_of_bytes

    return length, offset

def read_der_integer(data: bytes, offset: int):
    """
    Read a DER INTEGER.

    Returns:
        tuple[int, int]:
            Integer value and next offset.
    """

    if offset >= len(data):
        raise ValueError("Unexpected end of DER data")

    if data[offset] != 0x02:
        raise ValueError("Expected DER INTEGER")

    offset += 1

    length, offset = read_der_length(
        data,
        offset
    )

    if length <= 0:
        raise ValueError("DER INTEGER cannot be empty")

    if offset + length > len(data):
        raise ValueError("DER INTEGER extends beyond input")

    raw_value = data[
        offset:offset + length
    ]

    offset += length

    value = int.from_bytes(
        raw_value,
        "big",
        signed=False
    )

    return value, offset

def parse_rsa_public_key(public_key: str):
    """Decode and validate a DKIM RSA public key from its Base64 p= value."""
    import base64
    import binascii

    if not public_key:
        raise ValueError("DKIM public key is empty")

    try:
        key_data = base64.b64decode(
            "".join(public_key.split()),
            validate=True,
        )
    except (binascii.Error, ValueError) as exc:
        raise ValueError("Invalid Base64 DKIM public key") from exc

    if not key_data:
        raise ValueError("Decoded DKIM public key is empty")

    try:
        key = serialization.load_der_public_key(key_data)
    except (ValueError, TypeError) as exc:
        raise ValueError("Invalid DER-encoded DKIM public key") from exc

    if not isinstance(key, rsa.RSAPublicKey):
        raise ValueError("DKIM public key is not an RSA key")

    return key

def verify_rsa_signature(
    public_key,
    data: bytes,
    signature: bytes
):
    """
    Verify an RSA-SHA256 signature.

    Returns:
        bool: True when the signature is valid,
              otherwise False.
    """

    try:
        public_key.verify(
            signature,
            data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )

        return True

    except Exception:
        return False


def canonicalize_body(body, mode: str = "simple") -> bytes:
    """Apply DKIM simple or relaxed body canonicalization."""

    if body is None:
        body = b""

    if isinstance(body, str):
        body = body.encode("utf-8")

    if not isinstance(body, bytes):
        raise TypeError("Body must be str, bytes, or None")

    mode = mode.lower().strip()
    if mode not in {"simple", "relaxed"}:
        raise ValueError(
            f"Unsupported body canonicalization mode: {mode}"
        )

    # Normalize line endings to CRLF.
    body = body.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    body = body.replace(b"\n", b"\r\n")

    if mode == "relaxed":
        # Match dkimpy's reference operations.
        body = re.sub(rb"[ \t]+\r\n", b"\r\n", body)
        body = re.sub(rb"[ \t]+", b" ", body)

    # Match dkimpy's trailing-line handling.
    end = None
    while body.endswith(b"\r\n", 0, end):
        if end is None:
            end = -2
        else:
            end -= 2

    if end is None:
        return body + b"\r\n"

    end += 2
    if end == 0:
        return body

    return body[:end]


def calculate_body_hash(
    body,
    mode: str = "simple"
) -> str:
    """
    Calculate the Base64-encoded SHA-256 hash
    of the DKIM-canonicalized body.
    """

    canonicalized_body = canonicalize_body(
        body,
        mode
    )


    digest = hashlib.sha256(
        canonicalized_body
    ).digest()

    return base64.b64encode(
        digest
    ).decode("ascii")

def verify_body_hash(
    body,
    expected_hash: str,
    mode: str = "simple"
):
    """
    Compare the calculated DKIM body hash
    with the bh= value from DKIM-Signature.

    Returns:
        dict containing verification result.
    """

    if not expected_hash:
        return {
            "status": "FAIL",
            "reason": "DKIM body hash (bh=) is missing"
        }

    try:
        calculated_hash = calculate_body_hash(
            body,
            mode
        )

    except Exception as exc:
        return {
            "status": "ERROR",
            "reason": f"Body hash calculation failed: {exc}"
        }

    if calculated_hash == expected_hash:
        return {
            "status": "PASS",
            "calculated_hash": calculated_hash,
            "expected_hash": expected_hash,
            "reason": "Body hash matches"
        }



    return {
        "status": "FAIL",
        "calculated_hash": calculated_hash,
        "expected_hash": expected_hash,
        "reason": "Body hash does not match"
    }

def canonicalize_header(
    field_name: str,
    field_value: str,
    mode: str = "simple"
) -> str:
    """
    Apply DKIM header canonicalization.

    Supported modes:
        simple
        relaxed
    """

    if field_name is None:
        raise ValueError("Header field name is required")

    if field_value is None:
        field_value = ""

    mode = mode.lower().strip()

    if mode not in {"simple", "relaxed"}:
        raise ValueError(
            f"Unsupported header canonicalization mode: {mode}"
        )

    if mode == "simple":
        return f"{field_name}:{field_value}"

    # Relaxed:
    # 1. Lowercase the field name.
    # 2. Unfold continuation whitespace.
    # 3. Convert WSP runs to a single SP.
    # 4. Remove WSP immediately before/after the colon.
    # 5. Remove WSP at the beginning/end of the value.

    field_name = field_name.lower()

    # Header values reaching this function should already be unfolded,
    # but normalize any remaining folding just in case.
    field_value = re.sub(
        r"\r\n[ \t]+",
        " ",
        field_value
    )

    field_value = re.sub(
        r"[ \t]+",
        " ",
        field_value
    )

    field_value = field_value.strip()

    return f"{field_name}:{field_value}"


def get_signed_headers(raw_headers, signed_header_names, mode="simple"):
    """Select existing headers in DKIM h= order, matching dkimpy behavior."""
    available = {
        name.lower(): list(values)
        for name, values in raw_headers.items()
    }

    header_names = [
        name.strip().lower()
        for name in signed_header_names.split(":")
        if name.strip()
    ]

    canonicalized = []

    for name in header_names:
        values = available.get(name, [])

        if not values:
            continue

        # DKIM selects the last remaining occurrence of each header.
        value = values.pop()
        canonicalized.append(
            canonicalize_header(name, value, mode) + "\r\n"
        )

    return canonicalized



def remove_dkim_signature_value(
    signature_header: str
) -> str:
    """
    Remove the value of the b= tag from a DKIM-Signature header.

    The b= tag itself remains present.
    """

    if not signature_header:
        raise ValueError(
            "DKIM-Signature header is empty"
        )

    # Locate b= case-insensitively.
    match = re.search(
        r"(?i)(^|;[ \t]*)(b[ \t]*=[ \t]*)",
        signature_header
    )

    if not match:
        raise ValueError(
            "DKIM-Signature header does not contain b="
        )

    value_start = match.end()

    # The b= value extends until the next semicolon
    # or the end of the header.
    value_end_match = re.search(
        r";",
        signature_header[value_start:]
    )

    if value_end_match:
        value_end = (
            value_start
            + value_end_match.start()
        )
    else:
        value_end = len(signature_header)

    return (
        signature_header[:value_start]
        + signature_header[value_end:]
    )

def build_dkim_signing_data(
    raw_headers: dict[str, list[str]],
    signature_header: str,
    signed_header_names: str,
    header_canonicalization: str = "simple"
) -> bytes:
    """
    Build the byte sequence covered by a DKIM signature.

    The sequence consists of the canonicalized headers listed
    in h= followed by the canonicalized DKIM-Signature header
    with its b= value removed.
    """

    signed_headers = get_signed_headers(
        raw_headers,
        signed_header_names,
        header_canonicalization
    )



    signature_without_b = (
        remove_dkim_signature_value(
            signature_header
        )
    )

    # If the header was supplied with the field name,
    # split it so canonicalization can handle it correctly.
    if ":" not in signature_without_b:
        raise ValueError(
            "Invalid DKIM-Signature header"
        )

    field_name, field_value = (
        signature_without_b.split(":", 1)
    )


    canonicalized_signature = canonicalize_header(
    field_name,
    field_value,
    header_canonicalization
)


    return (
        "".join(signed_headers)
        + canonicalized_signature
    ).encode("utf-8")

def decode_dkim_signature(signature: str) -> bytes:
    """
    Decode the Base64 value from the DKIM b= tag.
    DKIM permits folding whitespace inside the value,
    so whitespace is removed before decoding.
    """

    if not signature:
        raise ValueError("DKIM signature b= value is empty")

    cleaned = re.sub(r"\s+", "", signature)

    try:
        return base64.b64decode(
            cleaned,
            validate=True
        )
    except Exception as exc:
        raise ValueError(
            "Invalid Base64 DKIM signature"
        ) from exc

def verify_dkim_signature(
    public_key,
    signing_data: bytes,
    signature: str,
    algorithm: str = "rsa-sha256"
):
    """
    Verify a DKIM cryptographic signature.

    Currently supports:
        rsa-sha256
    """

    algorithm = algorithm.lower().strip()

    if algorithm != "rsa-sha256":
        return {
            "status": "ERROR",
            "reason": f"Unsupported DKIM algorithm: {algorithm}"
        }

    try:
        signature_bytes = decode_dkim_signature(
            signature
        )

    except ValueError as exc:
        return {
            "status": "ERROR",
            "reason": str(exc)
        }

    try:
        public_key.verify(
            signature_bytes,
            signing_data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )

        return {
            "status": "PASS",
            "algorithm": algorithm,
            "reason": "DKIM cryptographic signature verified"
        }

    except Exception:
        return {
            "status": "FAIL",
            "algorithm": algorithm,
            "reason": "DKIM cryptographic signature verification failed"
        }

def verify_dkim(
    signature_header: str,
    raw_headers: dict[str, list[str]],
    body
):
    """
    Perform complete DKIM verification.

    Verification flow:
        1. Parse DKIM-Signature
        2. Retrieve public key from DNS
        3. Verify body hash (bh=)
        4. Build DKIM signing data
        5. Verify cryptographic signature (b=)

    Returns:
        dict: Structured DKIM verification result.
    """

    # ---------------------------------------------------------
    # STEP 1: Parse DKIM-Signature
    # ---------------------------------------------------------

    parsed = parse_dkim_signature(
        signature_header
    )

    if not parsed.get("valid"):
        return {
            "status": "ERROR",
            "reason": parsed.get(
                "reason",
                "Invalid DKIM-Signature"
            ),
            "domain": parsed.get("domain"),
            "selector": parsed.get("selector")
        }

    domain = parsed["domain"]
    selector = parsed["selector"]
    algorithm = parsed["algorithm"]
    canonicalization = parsed["canonicalization"]

    header_canonicalization = parsed[
        "header_canonicalization"
    ]

    body_canonicalization = parsed[
        "body_canonicalization"
    ]

    # ---------------------------------------------------------
    # STEP 2: Get DKIM public key from DNS
    # ---------------------------------------------------------

    try:
        dns_result = get_dkim_public_key(
            domain,
            selector
        )

    except Exception as exc:
        return {
            "status": "ERROR",
            "domain": domain,
            "selector": selector,
            "algorithm": algorithm,
            "canonicalization": canonicalization,
            "reason": f"DKIM DNS lookup failed: {exc}"
        }

    if not dns_result.get("found"):
        return {
            "status": "NONE",
            "domain": domain,
            "selector": selector,
            "algorithm": algorithm,
            "canonicalization": canonicalization,
            "reason": dns_result.get(
                "reason",
                "DKIM public key not found"
            )
        }

    public_key_value = dns_result.get(
        "public_key"
    )

    if not public_key_value:
        return {
            "status": "NONE",
            "domain": domain,
            "selector": selector,
            "algorithm": algorithm,
            "canonicalization": canonicalization,
            "reason": "DKIM public key is empty"
        }

    # ---------------------------------------------------------
    # STEP 3: Parse RSA public key
    # ---------------------------------------------------------

    try:
        public_key = parse_rsa_public_key(
            public_key_value
        )

    except Exception as exc:
        return {
            "status": "ERROR",
            "domain": domain,
            "selector": selector,
            "algorithm": algorithm,
            "canonicalization": canonicalization,
            "reason": f"Invalid DKIM public key: {exc}"
        }

    # ---------------------------------------------------------
    # STEP 4: Verify body hash (bh=)
    # ---------------------------------------------------------

    body_result = verify_body_hash(
        body=body,
        expected_hash=parsed["body_hash"],
        mode=body_canonicalization
    )

    if body_result["status"] != "PASS":
        return {
            "status": "FAIL",
            "domain": domain,
            "selector": selector,
            "algorithm": algorithm,
            "canonicalization": canonicalization,
            "body_hash_status": body_result["status"],
            "signature_status": None,
            "reason": body_result["reason"]
        }

    # ---------------------------------------------------------
    # STEP 5: Build DKIM signing data
    # ---------------------------------------------------------

    try:
        signing_data = build_dkim_signing_data(
            raw_headers=raw_headers,
            signature_header=f"DKIM-Signature: {signature_header}",
            signed_header_names=parsed[
                "signed_headers"
            ],
            header_canonicalization=(
                header_canonicalization
            )
        )

    except Exception as exc:
        return {
            "status": "ERROR",
            "domain": domain,
            "selector": selector,
            "algorithm": algorithm,
            "canonicalization": canonicalization,
            "body_hash_status": "PASS",
            "signature_status": None,
            "reason": (
                "Failed to build DKIM signing data: "
                f"{exc}"
            )
        }

    # ---------------------------------------------------------
    # STEP 6: Verify b= cryptographic signature
    # ---------------------------------------------------------

    signature_result = verify_dkim_signature(
        public_key=public_key,
        signing_data=signing_data,
        signature=parsed["signature"],
        algorithm=algorithm
    )

    if signature_result["status"] != "PASS":
        return {
            "status": "FAIL",
            "domain": domain,
            "selector": selector,
            "algorithm": algorithm,
            "canonicalization": canonicalization,
            "body_hash_status": "PASS",
            "signature_status": signature_result[
                "status"
            ],
            "reason": signature_result["reason"]
        }

    # ---------------------------------------------------------
    # STEP 7: Everything passed
    # ---------------------------------------------------------

    return {
        "status": "PASS",
        "domain": domain,
        "selector": selector,
        "algorithm": algorithm,
        "canonicalization": canonicalization,
        "body_hash_status": "PASS",
        "signature_status": "PASS",
        "reason": (
            "DKIM body hash and cryptographic "
            "signature verified"
        )
    }
