from urllib.parse import urlsplit, urlunsplit
from .virustotal import VirusTotalClient, VirusTotalError


def normalize_url(url: str) -> str:
    value = (url or "").strip()
    if not value:
        return ""
    parts = urlsplit(value)
    if not parts.scheme and not parts.netloc:
        parts = urlsplit("http://" + value)
    scheme = parts.scheme.lower()
    hostname = (parts.hostname or "").lower()
    if not hostname:
        return value
    netloc = hostname
    if parts.port is not None:
        default = {"http": 80, "https": 443}.get(scheme)
        if parts.port != default:
            netloc = f"{netloc}:{parts.port}"
    return urlunsplit((scheme, netloc, parts.path or "", parts.query or "", ""))


def analyze_url(url: str, client: VirusTotalClient) -> dict:
    normalized = normalize_url(url)
    if not normalized:
        return {"status": "INVALID", "url": url,
                "reason": "URL is empty or could not be normalized"}
    try:
        result = client.get_url_report(normalized)
    except VirusTotalError as exc:
        return {"status": "UNAVAILABLE", "url": normalized, "reason": str(exc)}
    result["normalized_url"] = normalized
    if result.get("status") == "FOUND":
        stats = result.get("stats", {})
        result["risk"] = (
            "MALICIOUS" if stats.get("malicious", 0) > 0
            else "SUSPICIOUS" if stats.get("suspicious", 0) > 0
            else "NO_MALICIOUS_DETECTION"
        )
    elif result.get("status") == "NOT_FOUND":
        result["risk"] = "UNKNOWN"
    return result
