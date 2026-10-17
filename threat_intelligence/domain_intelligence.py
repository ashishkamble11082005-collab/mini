from __future__ import annotations
import ipaddress
import dns.resolver

def _resolve_dns(domain: str) -> dict:
    result = {
        "a": [],
        "aaaa": [],
        "mx": [],
        "nameservers": [],
    }

    record_types = {
        "a": "A",
        "aaaa": "AAAA",
        "mx": "MX",
        "nameservers": "NS",
    }

    for key, record_type in record_types.items():
        try:
            answers = dns.resolver.resolve(
                domain,
                record_type,
                lifetime=3,
            )

            for answer in answers:
                if record_type == "MX":
                    value = str(answer.exchange).rstrip(".")
                else:
                    value = str(answer).rstrip(".")

                if value not in result[key]:
                    result[key].append(value)

        except (
            dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer,
            dns.resolver.NoNameservers,
            dns.resolver.LifetimeTimeout,
        ):
            pass

    return result

def analyze_domain(domain: str) -> dict:
    value = (domain or "").strip().lower()

    if not value:
        return {
            "status": "INVALID",
            "risk": "UNKNOWN",
            "findings": [],
        }

    findings = []

    try:
        ipaddress.ip_address(value)

        return {
            "status": "IP_ADDRESS",
            "risk": "MEDIUM",
            "domain": value,
            "findings": [
                {
                    "type": "ip_address_domain",
                    "severity": "MEDIUM",
                    "reason": "Value is an IP address rather than a domain name",
                }
            ],
        }

    except ValueError:
        pass

    labels = value.split(".")

    if len(labels) < 2:
        findings.append({
        "type": "invalid_domain_structure",
        "severity": "MEDIUM",
        "reason": "Domain does not contain the expected hierarchical structure",
    })

    if len(value) > 253:
        findings.append({
        "type": "excessive_domain_length",
        "severity": "LOW",
        "reason": "Domain exceeds the maximum length defined for DNS names",
    })

    if any(len(label) > 63 for label in labels):
        findings.append({
        "type": "excessive_label_length",
        "severity": "LOW",
        "reason": "Domain contains a label exceeding the maximum DNS label length",
    })

    if value.startswith(".") or value.endswith("."):
        findings.append({
        "type": "malformed_domain",
        "severity": "MEDIUM",
        "reason": "Domain contains an invalid leading or trailing dot",
    })

    if not any(len(label) > 63 for label in labels):
        dns = _resolve_dns(value)
    else:
        dns = {
        "a": [],
        "aaaa": [],
        "mx": [],
        "nameservers": [],
    }

    if len(value) > 253:
        findings.append({
            "type": "excessive_domain_length",
            "severity": "LOW",
            "reason": "Domain exceeds the maximum length defined for DNS names",
        })

    if any(len(label) > 63 for label in labels):
        findings.append({
            "type": "excessive_label_length",
            "severity": "LOW",
            "reason": "Domain contains a label exceeding the maximum DNS label length",
        })

    if value.startswith(".") or value.endswith("."):
        findings.append({
            "type": "malformed_domain",
            "severity": "MEDIUM",
            "reason": "Domain contains an invalid leading or trailing dot",
        })

    if not dns["a"] and not dns["aaaa"]:
        findings.append({
            "type": "dns_resolution_failed",
            "severity": "MEDIUM",
            "reason": "Domain did not resolve to an IPv4 or IPv6 address",
        })

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
        "domain": value,
        "dns": dns,
        "findings": findings,
    }