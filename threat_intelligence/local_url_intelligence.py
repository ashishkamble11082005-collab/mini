from __future__ import annotations

import ipaddress
import re
from urllib.parse import unquote, urlsplit
import unicodedata
from difflib import SequenceMatcher
SUSPICIOUS_KEYWORDS = {
    "login",
    "signin",
    "verify",
    "verification",
    "account",
    "password",
    "credential",
    "secure",
    "update",
    "confirm",
    "bank",
    "wallet",
    "payment",
    "invoice",
    "reset",
}


SUSPICIOUS_TLDS = {
    "zip",
    "mov",
    "click",
    "top",
    "xyz",
    "tk",
    "ml",
    "ga",
    "cf",
    "gq",
}

SUSPICIOUS_PORTS = {
    21,
    22,
    23,
    25,
    110,
    135,
    139,
    445,
    1433,
    3306,
    3389,
    5900,
}

BRAND_DOMAINS = {
    "paypal": {"paypal.com"},
    "microsoft": {"microsoft.com", "live.com", "office.com"},
    "google": {"google.com", "gmail.com"},
    "apple": {"apple.com", "icloud.com"},
    "amazon": {"amazon.com"},
    "facebook": {"facebook.com", "meta.com"},
    "instagram": {"instagram.com"},
    "linkedin": {"linkedin.com"},
    "netflix": {"netflix.com"},
    "github": {"github.com"},
}
BRAND_SIMILARITY_THRESHOLD = 0.85
MAX_URL_LENGTH = 2048

def _detect_brand_impersonation(hostname: str) -> list[dict]:
    findings = []

    labels = hostname.split(".")
    registered_domain = ".".join(labels[-2:]) if len(labels) >= 2 else hostname

    for brand, legitimate_domains in BRAND_DOMAINS.items():
        if brand not in hostname:
            continue

        if any(
            hostname == domain or hostname.endswith("." + domain)
            for domain in legitimate_domains
        ):
            continue

        findings.append({
            "type": "brand_impersonation",
            "severity": "HIGH",
            "brand": brand,
            "reason": (
                f"Hostname contains the brand name '{brand}' "
                f"but does not belong to a known legitimate {brand} domain"
            ),
        })

    return findings

def _normalize_brand_candidate(value: str) -> str:
    translation = str.maketrans({
        "0": "o",
        "1": "l",
        "3": "e",
        "4": "a",
        "5": "s",
        "7": "t",
        "8": "b",
        "9": "g",
    })

    return value.lower().translate(translation)


def _detect_typosquatting(hostname: str) -> list[dict]:
    findings = []

    labels = [
        label
        for label in hostname.split(".")
        if label
    ]

    for brand, legitimate_domains in BRAND_DOMAINS.items():
        for label in labels:
            normalized_label = _normalize_brand_candidate(label)

            # Direct similarity against the complete label.
            similarity = SequenceMatcher(
                None,
                normalized_label,
                brand,
            ).ratio()

            # Also inspect hyphen-separated components.
            components = [
                component
                for component in normalized_label.split("-")
                if component
            ]

            component_similarity = max(
                (
                    SequenceMatcher(None, component, brand).ratio()
                    for component in components
                ),
                default=0.0,
            )

            best_similarity = max(
                similarity,
                component_similarity,
            )

            if best_similarity < BRAND_SIMILARITY_THRESHOLD:
                continue

            legitimate_domain = any(
                hostname == domain or
                hostname.endswith("." + domain)
                for domain in legitimate_domains
            )

            if legitimate_domain:
                continue

            if label == brand:
                continue

            findings.append({
                "type": "possible_typosquatting",
                "severity": "HIGH",
                "brand": brand,
                "similarity": round(best_similarity, 3),
                "matched_label": label,
                "normalized_label": normalized_label,
                "reason": (
                    f"Hostname label '{label}' closely resembles "
                    f"the brand name '{brand}'"
                ),
            })

            break

    return findings

def _detect_obfuscated_ip(hostname: str) -> bool:
    if not hostname:
        return False

    # Decimal IPv4 representation, e.g. 3232235777
    if hostname.isdigit():
        try:
            value = int(hostname)

            if 0 <= value <= 0xFFFFFFFF:
                ipaddress.IPv4Address(value)
                return True
        except ValueError:
            pass

    # Hexadecimal IPv4 representation, e.g. 0xC0A80132
    if hostname.lower().startswith("0x"):
        try:
            value = int(hostname, 16)

            if 0 <= value <= 0xFFFFFFFF:
                ipaddress.IPv4Address(value)
                return True
        except ValueError:
            pass

    return False

def _has_confusable_characters(hostname: str) -> bool:
    for character in hostname:
        if ord(character) > 127:
            normalized = unicodedata.normalize("NFKC", character)

            if normalized == character:
                return True

    return False


def analyze_url_locally(url: str) -> dict:
    findings = []

    value = (url or "").strip()

    if not value:
        return {
            "status": "INVALID",
            "risk": "UNKNOWN",
            "findings": [],
        }

    parts = urlsplit(value)

    hostname = (parts.hostname or "").lower()

        # Brand impersonation
    findings.extend(_detect_brand_impersonation(hostname))
    findings.extend(_detect_typosquatting(hostname))
        # Percent-encoded URL content
    decoded_value = unquote(value)

    if decoded_value != value:
        findings.append({
            "type": "percent_encoded_url",
            "severity": "MEDIUM",
            "reason": "URL contains percent-encoded characters that may obscure its actual content",
        })

    if not hostname:
        return {
            "status": "INVALID",
            "risk": "UNKNOWN",
            "findings": [],
        }

    # IP address URL
    try:
        ip = ipaddress.ip_address(hostname)

        findings.append({
            "type": "ip_address_url",
            "severity": "MEDIUM",
            "reason": f"URL uses an IP address instead of a domain name: {ip}",
        })
    except ValueError:
        pass

        # Obfuscated IPv4 representation
    if _detect_obfuscated_ip(hostname):
        findings.append({
            "type": "obfuscated_ip_url",
            "severity": "HIGH",
            "reason": "URL hostname uses an obfuscated numeric representation of an IPv4 address",
        })

    # HTTP instead of HTTPS
    if parts.scheme.lower() == "http":
        findings.append({
            "type": "insecure_http",
            "severity": "LOW",
            "reason": "URL uses HTTP instead of HTTPS",
        })

        # Unusual / sensitive port
    try:
        port = parts.port

        if port in SUSPICIOUS_PORTS:
            findings.append({
                "type": "suspicious_port",
                "severity": "MEDIUM",
                "reason": f"URL uses a port commonly associated with network or administrative services: {port}",
            })

    except ValueError:
        findings.append({
            "type": "invalid_port",
            "severity": "MEDIUM",
            "reason": "URL contains an invalid port number",
        })

    # Punycode / IDN
    if "xn--" in hostname:
        findings.append({
            "type": "punycode_domain",
            "severity": "MEDIUM",
            "reason": "Domain contains punycode/IDN encoding",
        })

        # Unicode / confusable characters
    if _has_confusable_characters(hostname):
        findings.append({
            "type": "unicode_confusable_domain",
            "severity": "MEDIUM",
            "reason": "Domain contains non-ASCII characters that may visually resemble characters from another script",
        })

    # Suspicious keywords
    lowered_url = value.lower()

    matched_keywords = sorted(
        keyword
        for keyword in SUSPICIOUS_KEYWORDS
        if keyword in lowered_url
    )

    if matched_keywords:
        findings.append({
            "type": "suspicious_keyword",
            "severity": "MEDIUM",
            "keywords": matched_keywords,
            "reason": "URL contains keywords commonly associated with account or credential actions",
        })

    # Excessive subdomains
    labels = hostname.split(".")

    if len(labels) >= 5:
        findings.append({
            "type": "excessive_subdomains",
            "severity": "MEDIUM",
            "reason": "URL contains an unusually large number of domain labels",
        })

    # Suspicious TLD
    if "." in hostname:
        tld = hostname.rsplit(".", 1)[-1]

        if tld in SUSPICIOUS_TLDS:
            findings.append({
                "type": "suspicious_tld",
                "severity": "LOW",
                "reason": f"Domain uses the .{tld} TLD",
            })

        # Excessively long URL
    if len(value) > MAX_URL_LENGTH:
        findings.append({
            "type": "long_url",
            "severity": "LOW",
            "reason": "URL is unusually long and may contain excessive or obfuscated data",
        })

    # Very long hostname
    if len(hostname) > 80:
        findings.append({
            "type": "long_hostname",
            "severity": "LOW",
            "reason": "Hostname is unusually long",
        })

    # @ symbol can obscure the actual destination
    if "@" in value:
        findings.append({
            "type": "userinfo_in_url",
            "severity": "HIGH",
            "reason": "URL contains user-information syntax that can obscure the destination",
        })

    # Determine local risk
    severity_rank = {
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 3,
    }

    highest = max(
        (severity_rank[f["severity"]] for f in findings),
        default=0,
    )

    risk = {
        0: "NO_FINDINGS",
        1: "LOW",
        2: "MEDIUM",
        3: "HIGH",
    }[highest]

    return {
        "status": "ANALYZED",
        "risk": risk,
        "hostname": hostname,
        "findings": findings,
    }