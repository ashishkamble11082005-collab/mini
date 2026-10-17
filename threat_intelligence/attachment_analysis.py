import hashlib
from typing import Optional
from .virustotal import VirusTotalClient, VirusTotalError


def hash_attachment(data: bytes) -> dict[str, str]:
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("Attachment data must be bytes")
    raw = bytes(data)
    return {"md5": hashlib.md5(raw).hexdigest(),
            "sha1": hashlib.sha1(raw).hexdigest(),
            "sha256": hashlib.sha256(raw).hexdigest()}


def analyze_attachment(data: bytes, filename: Optional[str],
                       content_type: Optional[str],
                       client: VirusTotalClient) -> dict:
    hashes = hash_attachment(data)
    result = {"filename": filename, "content_type": content_type,
              "size": len(data), "hashes": hashes}
    try:
        vt = client.get_file_report(hashes["sha256"])
    except VirusTotalError as exc:
        vt = {"status": "UNAVAILABLE", "sha256": hashes["sha256"],
              "reason": str(exc)}
    result["virustotal"] = vt
    if vt.get("status") == "FOUND":
        result["risk"] = ("MALICIOUS" if vt.get("malicious")
                           else "SUSPICIOUS" if vt.get("suspicious")
                           else "NO_MALICIOUS_DETECTION")
    elif vt.get("status") == "NOT_FOUND":
        result["risk"] = "UNKNOWN"
    else:
        result["risk"] = "UNAVAILABLE"
    return result
